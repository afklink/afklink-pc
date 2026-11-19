//! Session admission by viewer device keys (protocol spec rev 3, §2–§11): the decisions, and
//! only the decisions. [`Admission`] takes each event of the orchestrator's main loop — a
//! `session_request`, a first offer, a re-offer, a session's end, the pairing panel and its
//! requests, the PC's switch, a key removed, sleep — and answers what to do: the verdict (§11.1),
//! whether the session is admitted in this mode, the `ks` message for the viewer (§3.7), the
//! journal events, the session's identity and role **from the key record** for a signed session
//! (§3.4 step 10), and the change the trust list needs ([`AdmitOp`]).
//!
//! It never awaits and never touches a file: the list is read through [`Trusted`] (no I/O) and a
//! change goes to [`Trusted::admit`], the trust list's queue (removals first, one change in
//! flight, staged again at its turn); its end comes back as a [`Landed`] that the orchestrator
//! hands to [`Admission::landed`]. A session whose admission needs a change is admitted only when
//! the change is installed (§3.4 step 9); a failed or slow write refuses it
//! (`key_list_damaged:write_failed`).
//!
//! # Modes
//!
//! Strict («Доверенные устройства» on): admitted only by steps 1–9 of §3.4. Observe (off): every
//! step runs and grounds are applied (the list grows toward strict), the verdict is reported, and
//! admission follows `is_bound` as today — except `fingerprint_changed` and
//! `key_list_damaged:write_failed`. A damaged list cannot say the mode; its mode file can
//! ([`TrustStore::damaged_mode`]): when it says observe, every offer is
//! `key_list_damaged:read_failed` and admitted by `is_bound` as in observe (adds and recoveries
//! stay refused); otherwise — missing, unusable or strict — it is strict (the store's fail-closed
//! rule) and every offer is refused `key_list_damaged:read_failed`.
//!
//! # The window rule (§3.4 «Органы доверия», §10.1)
//!
//! One mechanism, [`Trusted`]'s window token: every session or pending session that is not signed
//! by a confirmed owner key counts ([`Trusted::sync_live`], [`Admission::counting`]); its start
//! moves the token on. A pending session counts until its offer is decided (spec:
//! «ожидающий Pending — любой из них в любой момент»); one signed by a confirmed owner key stops
//! counting once admitted (the exemption). The pairing panel records the token when it opens; a
//! key accepted there is confirmed only if [`Trusted::window_clean`] still holds at «Разрешить».
//!
//! # Threads
//!
//! Everything here runs on the orchestrator's main loop, synchronously, with no lock and no wait.
//! The worst case of one first offer: the limits' pass over the `proof` JSON (≤ 16 KB), one ECDSA
//! verify of the key card, one of the offer, then per ground (≤ 4) at most three ECDSA verifies
//! (grant + invitation, or the recovery) or one Ed25519 verify (the attestation), and one dry run
//! of the store's rules ([`TrustStore::check_add`]: one clone of the list, O(list)). About ten
//! signature checks and four list clones, a few milliseconds at the list's limits; the token
//! bucket bounds it to 20 offers a second.
//!
//! # Logs
//!
//! `debug` for every decision and refusal with its step; `info` for a session's verdict; `warn`
//! for `identity_mismatch` and a full bucket (once a minute). Never a nonce, a signature, a proof,
//! initData or a full `key_id` (`kid=` 8 characters).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use afklink_protocol::{BindingRole, OwnerRequestState};
use serde_json::Value;

use crate::trusted::{DeviceAttempt, DeviceRef, Trusted};
use crate::viewer_keys::nonce::{NonceBatch, NonceBook};
use crate::viewer_keys::proof::{
    ground_id, verify_first_use, AdmitEntry, Endorse, Grant, InviteSig, KeyReg, OfferProof,
    RecoverGround, MAX_VIEWER_KEY_BYTES,
};
use crate::viewer_keys::sdp::viewer_fingerprint;
use crate::viewer_keys::wire::{b64url_array, FINGERPRINT_LEN, NONCE_PC_LEN};
use crate::viewer_keys::{
    AddOutcome, Attempt, AttemptNoted, AttestationError, ClientKind, Ground, Invite, KeyId,
    KeyState, Lookup, NewKey, Person, PersonKeys, Platform, RecoverOutcome, Recovery, Removal,
    SnapshotPerson, Staged, StoreError, TelegramIdentity, TelegramVerifier, TrustStore, ViewerKey,
};

mod party;
#[cfg(test)]
mod tests;

pub use party::PartyAnswer;

/// Offers with a proof checked per second, and the bucket's depth (spec §3.4).
pub const VERIFY_RATE_PER_S: u32 = 20;
/// `grant.issued_at − invite.issued_at` at most (spec §7: 24 h + 1 h).
pub const INVITE_GRANT_WINDOW_MS: i128 = 25 * 3_600_000;
/// … and at least.
pub const INVITE_GRANT_SKEW_MS: i128 = -3_600_000;
/// `first_use_probe` at most once an hour per person and key (spec §9) …
const PROBE_PER_KEY_MS: u64 = 3_600_000;
/// … and at most three a day per person.
const PROBE_PER_DAY: usize = 3;
const DAY_MS: u64 = 24 * 3_600_000;
/// `recover_attempt` at most once an hour per person (spec §8.4).
const RECOVER_ATTEMPT_MS: u64 = 3_600_000;
/// `party_device_limit` at most once an hour per person (process §7).
const PARTY_LIMIT_MS: u64 = 3_600_000;
/// A full bucket's `warn` at most once a minute.
const BUSY_WARN_MS: u64 = 60_000;
/// Another device's new attempt (§10.2) journaled at most three times a day per person (spec §9's
/// bound for the same notice).
const ATTEMPTS_JOURNALED_PER_DAY: usize = 3;
/// How long a `pc_allow` key waits for `BindingAdded` at most (spec §5: until the request's
/// expiry): the owner's time to answer and a margin, from «Разрешить».
pub const PC_ALLOW_WAIT: Duration = Duration::from_millis(
    afklink_protocol::OWNER_REQUEST_TTL_MS + crate::owner_request::EXPIRY_GRACE_MS.unsigned_abs(),
);
/// The most `pair_request`s kept waiting for their answer at once (§5: the server may send new
/// `request_id`s without end, with the panel closed too). Over it the one that came first is
/// forgotten, its key with it: «Разрешить» on it then binds without a key.
pub const PAIR_WAITING_MAX: usize = 32;
/// How long a `pair_request` waits for its answer here at most: the server's lifetime of a request
/// (`PAIR_CONFIRM_TIMEOUT_MS`) and a margin for its repeat after a reconnect. Its answer, a cancel
/// or this, whichever comes first, ends it.
pub const PAIR_WAIT: Duration =
    Duration::from_millis(afklink_protocol::PAIR_CONFIRM_TIMEOUT_MS + 60_000);

// --- Verdicts -----------------------------------------------------------------------------------

/// A session's verdict (spec §11.1): `signed`, `unsigned`, `key_unconfirmed`, or a reason of §11
/// with its `ended_detail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub code: &'static str,
    pub detail: Option<&'static str>,
}

impl Verdict {
    pub const SIGNED: Self = Self::of("signed");
    pub const UNSIGNED: Self = Self::of("unsigned");
    pub const KEY_UNCONFIRMED: Self = Self::of("key_unconfirmed");
    pub const KEY_UNKNOWN: Self = Self::of("key_unknown");
    pub const KEY_REVOKED: Self = Self::of("key_revoked");
    pub const FINGERPRINT_CHANGED: Self = Self::of("fingerprint_changed");
    /// Not a verdict: the end reason of a session observe mode refuses because its person is not
    /// bound (`unbound`, as before keys) — never a success verdict as a reason (§11).
    pub const UNBOUND: Self = Self::of("unbound");

    const fn of(code: &'static str) -> Self {
        Self { code, detail: None }
    }

    const fn with(code: &'static str, detail: &'static str) -> Self {
        Self {
            code,
            detail: Some(detail),
        }
    }

    pub const fn proof_invalid(detail: &'static str) -> Self {
        Self::with("proof_invalid", detail)
    }

    pub const fn admit_refused(detail: &'static str) -> Self {
        Self::with("admit_refused", detail)
    }

    pub const fn nonce_stale(detail: &'static str) -> Self {
        Self::with("nonce_stale", detail)
    }

    pub const fn key_list_damaged(detail: &'static str) -> Self {
        Self::with("key_list_damaged", detail)
    }

    pub const fn key_required(detail: &'static str) -> Self {
        Self::with("key_required", detail)
    }

    /// The offer's signature verified and the key is in the list (confirmed or not).
    pub fn is_signed(&self) -> bool {
        *self == Self::SIGNED || *self == Self::KEY_UNCONFIRMED
    }
}

/// The PC's switch as the admission reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Observe,
    Strict,
}

impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Strict => "strict",
        }
    }
}

/// The `ks` DataChannel message (spec §3.7), sent once the `input` channel opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ks {
    pub kid: KeyId,
    pub verdict: Verdict,
    /// The ground that added the key now (`endorse`, `grant`, `recover`, `first_use`, `party`).
    pub admit: Option<&'static str>,
    pub mode: Mode,
}

impl Ks {
    /// The JSON of the message: `{"t":"ks","kid",…}`.
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("t".into(), "ks".into());
        m.insert("kid".into(), self.kid.as_str().into());
        m.insert("verdict".into(), self.verdict.code.into());
        if let Some(d) = self.verdict.detail {
            m.insert("detail".into(), d.into());
        }
        if let Some(a) = self.admit {
            m.insert("admit".into(), a.into());
        }
        m.insert("mode".into(), self.mode.as_str().into());
        Value::Object(m)
    }
}

/// Who a session is and with what role. For a signed session — the key record's (§3.4 step 10);
/// otherwise the server's word, as today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub telegram_user_id: i64,
    pub role: BindingRole,
    pub first_name: Option<String>,
    pub username: Option<String>,
    /// Taken from the key record (a signed session): server messages never change it.
    pub from_record: bool,
}

/// A journal event of an admission (the orchestrator writes it with the names it has).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalEvent {
    /// A key was added (after the write): its ground (`pair`, `endorse`, `grant`, `first_use`,
    /// `party`).
    KeyAdded {
        ground: &'static str,
        key_id: KeyId,
        telegram_user_id: i64,
        role: BindingRole,
        unconfirmed: bool,
        /// `endorse.by` / `grant.by`: the device that vouched.
        by: Option<KeyId>,
        /// A `grant` or a party's grant for a guest this PC has already (spec §7
        /// «Новое устройство уже привязанного гостя»): the key joined that guest, no new person —
        /// the orchestrator words it «Новое устройство гостя <имя>», not «Новый гость».
        guest_new_device: bool,
    },
    /// A same-device recovery replaced keys (after the write).
    KeyReplaced {
        key_id: KeyId,
        telegram_user_id: i64,
        replaced: Vec<KeyId>,
    },
    /// Someone with this Telegram account tried to recover a device with a wrong recovery
    /// signature (§8.4 step 3; at most once an hour per person).
    RecoverAttempt { telegram_user_id: i64 },
    /// A device of a person who already has a `first_use` key tried to get in (§9; rate limited).
    FirstUseProbe {
        telegram_user_id: i64,
        key_id: KeyId,
        kind: Option<String>,
        platform: Option<String>,
    },
    /// A party member's device was refused `limit`: the list is full for it (process §7; at most
    /// once an hour per person). The person at the PC is told which party's guest it was.
    PartyDeviceLimit {
        telegram_user_id: i64,
        party_id: crate::viewer_keys::GroundId,
    },
}

impl JournalEvent {
    /// The vectors' name of the event.
    pub fn name(&self) -> String {
        match self {
            Self::KeyAdded { ground, .. } => format!("key_added:{ground}"),
            Self::KeyReplaced { .. } => "key_replaced".into(),
            Self::RecoverAttempt { .. } => "recover_attempt".into(),
            Self::FirstUseProbe { .. } => "first_use_probe".into(),
            Self::PartyDeviceLimit { .. } => "party_device_limit".into(),
        }
    }
}

// --- Store changes ------------------------------------------------------------------------------

/// A same-device recovery, owned, to stage at the queue's turn.
#[derive(Debug, Clone)]
pub struct RecoverChange {
    pub rpk: ViewerKey,
    pub attested: TelegramIdentity,
    pub device_id: String,
    pub session_id: String,
    pub nonce_pc: [u8; NONCE_PC_LEN],
    pub rsig: Vec<u8>,
    pub new_key: ViewerKey,
    pub kind: ClientKind,
    pub platform: Platform,
}

impl RecoverChange {
    fn recovery(&self) -> Recovery<'_> {
        Recovery {
            rpk: &self.rpk,
            attested: &self.attested,
            device_id: &self.device_id,
            session_id: &self.session_id,
            nonce_pc: self.nonce_pc,
            rsig: &self.rsig,
            new_key: self.new_key.clone(),
            kind: self.kind.clone(),
            platform: self.platform.clone(),
        }
    }
}

/// A key to add, on its ground.
#[derive(Debug, Clone)]
pub struct AddChange {
    pub new: NewKey,
    pub ground: Ground,
    /// §10: a `pair` on the server's word — `pc_allow` + `BindingAdded` (§5, unconfirmed),
    /// never a press at the PC.
    pub server_word: bool,
    /// For a `pair` at the PC, what its press saw.
    pub press: Option<PressSeen>,
}

/// What a «Разрешить» at the PC saw at its press.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PressSeen {
    /// §5: the role the press named, matched against the derived one at the press. Read again
    /// at the write ([`Trusted::pair_role`]): another derived role then — the PC's owner changed
    /// in between — cancels the press whole (`role_changed`). `None`: no role to keep.
    pub role: Option<BindingRole>,
}

impl AddChange {
    /// A `pair` at the PC (not the server's word) — its person, and what its press saw.
    pub fn pc_press(&self) -> Option<(i64, PressSeen)> {
        match &self.ground {
            Ground::Pair { person, .. } if !self.server_word => {
                Some((person.telegram_user_id, self.press.unwrap_or_default()))
            }
            _ => None,
        }
    }
}

impl StoreOp {
    /// An add of `new` on `ground`.
    pub fn add(new: NewKey, ground: Ground) -> Self {
        Self::Add(Box::new(AddChange {
            new,
            ground,
            server_word: false,
            press: None,
        }))
    }

    /// An add of `new` on a `pair` at the PC whose press saw `press`.
    pub fn add_at_press(new: NewKey, ground: Ground, press: PressSeen) -> Self {
        Self::Add(Box::new(AddChange {
            new,
            ground,
            server_word: false,
            press: Some(press),
        }))
    }

    /// An add of `new` on a `pair` the server's word brought (`pc_allow` + `BindingAdded`).
    pub fn add_on_server_word(new: NewKey, ground: Ground) -> Self {
        Self::Add(Box::new(AddChange {
            new,
            ground,
            server_word: true,
            press: None,
        }))
    }
}

/// A change of the trust list an admission needs, for [`Trusted::admit`].
#[derive(Debug, Clone)]
pub enum StoreOp {
    /// A key on a ground (`pair`, `endorse`, `grant`, `first_use`, `pc_allow` → `BindingAdded`).
    Add(Box<AddChange>),
    /// A same-device recovery.
    Recover(Box<RecoverChange>),
    /// `last_used_at` of a key that connected (written only when due, §3.4 step 9).
    Touch { key_id: KeyId },
    /// The `first_use` snapshot (§9), from the first `agent_ready`'s bindings.
    FirstUseSnapshot { people: Vec<SnapshotPerson> },
    /// The list's notes (§10, §10.2, §7: attempts, the grant token) when memory's are not
    /// in the file yet.
    Notes,
}

impl StoreOp {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Add(_) => "admit_add",
            Self::Recover(_) => "admit_recover",
            Self::Touch { .. } => "admit_touch",
            Self::FirstUseSnapshot { .. } => "admit_snapshot",
            Self::Notes => "admit_notes",
        }
    }

    /// Stage the change on `store` (no I/O): the store decides every rule again. `Ok(None)`:
    /// nothing to write (a touch not due, a snapshot taken already).
    pub fn stage(
        &self,
        store: &mut TrustStore,
        now_unix_ms: i64,
    ) -> Result<Option<StagedChange>, StoreError> {
        match self {
            Self::Add(a) => store
                .stage_add(a.new.clone(), a.ground.clone(), now_unix_ms)
                .map(|s| Some(StagedChange::Add(s))),
            Self::Recover(r) => store
                .stage_recover(r.recovery(), now_unix_ms)
                .map(|s| Some(StagedChange::Recover(s))),
            Self::Touch { key_id } => store
                .stage_touch(key_id, now_unix_ms)
                .map(|s| s.map(StagedChange::Unit)),
            Self::FirstUseSnapshot { people } => store
                .stage_first_use_snapshot(people.clone(), now_unix_ms)
                .map(|s| s.map(StagedChange::Unit)),
            Self::Notes => store.stage_flush().map(|s| s.map(StagedChange::Unit)),
        }
    }
}

/// A staged admission change.
pub enum StagedChange {
    Unit(Staged<()>),
    Add(Staged<AddOutcome>),
    Recover(Staged<RecoverOutcome>),
}

/// A change with its ticket: [`Admission::landed`] matches the result by it.
#[derive(Debug, Clone)]
pub struct AdmitOp {
    pub ticket: u64,
    pub op: StoreOp,
}

/// What an installed admission change did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandedOutcome {
    Unit,
    Added(AddOutcome),
    Recovered(RecoverOutcome),
}

/// An admission change's end, from [`Trusted::take_landed`].
#[derive(Debug, Clone)]
pub struct Landed {
    pub ticket: u64,
    /// The write outlived its limit: the session stops waiting; the final result follows.
    pub slow: bool,
    pub result: Result<LandedOutcome, StoreError>,
}

// --- Inputs and answers -------------------------------------------------------------------------

/// A `session_request` (spec §2.2, §3.4 step 10), as the agent got it.
#[derive(Debug, Clone)]
pub struct SessionRequest<'a> {
    pub session_id: &'a str,
    /// The server's word.
    pub telegram_user_id: i64,
    /// The server's word (`role_of`).
    pub role: BindingRole,
    pub first_name: Option<&'a str>,
    pub username: Option<&'a str>,
    /// `session_request.nonce_pc`, as on the wire (for the accounting only).
    pub nonce_pc: Option<&'a str>,
}

/// What to do with a `session_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestDecision {
    /// A repeated `session_request` of a known session: `warn`, ignored (spec §2.6).
    pub ignored: bool,
    /// Send a new nonce batch (spec §2.2 (c): no `nonce_pc`, or one of the newest batch; the
    /// caller rate-limits to one per 2 s).
    pub want_batch: bool,
}

/// A first offer.
#[derive(Debug, Clone)]
pub struct FirstOffer<'a> {
    pub session_id: &'a str,
    pub sdp: &'a str,
    pub proof: Option<&'a Value>,
    /// Today's binding check (observe mode admits by it).
    pub is_bound: bool,
}

/// Whether and when a session goes on.
#[derive(Debug, Clone)]
pub enum Outcome {
    Admit,
    Refuse,
    /// Hand the change to [`Trusted::admit`]; admitted or refused at [`Admission::landed`].
    AfterWrite(Box<AdmitOp>),
}

/// The decision on a first offer.
#[derive(Debug, Clone)]
pub struct OfferDecision {
    pub verdict: Verdict,
    /// The ground that adds the key with this offer.
    pub admit: Option<&'static str>,
    pub mode: Mode,
    pub outcome: Outcome,
    /// For the `input` channel once it opens (only for an admitted session).
    pub ks: Option<Ks>,
    /// The session's identity and role (when admitted or waiting for the write).
    pub identity: Option<SessionIdentity>,
    /// Journal events now (the key's own come at [`Admission::landed`]).
    pub journal: Vec<JournalEvent>,
    /// `identity_mismatch` (logged at `warn` already).
    pub warn: Option<&'static str>,
    /// The rule that refused first, where the contract's vectors name one (`why`): `other_key`
    /// for a returning key whose card describes another key (§10), the card's own reason when it
    /// does not verify; an invitation's rule; [`OWNER_ON_PC`] for a `grant_role` whose cause is
    /// the person being an owner on this PC. `None` elsewhere (logged with each refusal).
    pub why: Option<&'static str>,
    /// A `last_used_at` note for [`Trusted::admit`] (no answer awaited).
    pub touch: Option<AdmitOp>,
    /// Another device that tried to get in as a bound person and was refused after the offer's
    /// signature verified (§10.2): kept on the list's notes already (the window's attempts); here
    /// only when the list took it as a new attempt and within the day's bound — the orchestrator
    /// journals it.
    pub attempts: Vec<DeviceAttempt>,
}

impl OfferDecision {
    /// Admitted now (false while waiting for the write).
    pub fn admitted(&self) -> bool {
        matches!(self.outcome, Outcome::Admit)
    }
}

/// What a landed change means.
#[derive(Debug, Clone, Default)]
pub struct LandedDecision {
    /// The session that waited for it, if it still exists: `Some((session_id, admitted,
    /// verdict))` — the final verdict, from the landed record (or the store's refusal). Never a
    /// success verdict when not admitted. `None` for a session already answered (`slow`) or
    /// gone (ended meanwhile): nothing to end twice.
    pub session: Option<(String, bool, Verdict)>,
    /// For an admitted waiting session: its `ks` rebuilt from the final result (replaces the one
    /// of the offer).
    pub ks: Option<Ks>,
    /// For an admitted waiting session: the key that signed it as the final result has it —
    /// `None` when the key did not land (observe admitted it by the binding).
    pub kid: Option<KeyId>,
    /// For an admitted waiting session: its identity and role now (the record's, or the
    /// server's word when the key did not land).
    pub identity: Option<SessionIdentity>,
    pub journal: Vec<JournalEvent>,
    /// Sessions of keys a recovery replaced: end them (`key_revoked`).
    pub end_sessions: Vec<EndSession>,
    /// A pairing's key: `(key_id, unconfirmed, rpk stored)`.
    pub pair_key: Option<(KeyId, bool, bool)>,
    /// The rule that refused the waiting session's key at the list (the vectors' `why`).
    pub why: Option<&'static str>,
    /// §10.2: the offer whose key the list refused at the queue's turn is another
    /// device's new attempt: journal it ([`Admission::journal_bound`] applied), as
    /// [`OfferDecision::attempts`].
    pub attempts: Vec<DeviceAttempt>,
}

/// A re-offer's decision (spec §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reoffer {
    Continue,
    End(Verdict),
}

/// A session to end, with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndSession {
    pub session_id: String,
    pub verdict: Verdict,
}

/// A control of trust on the PC that remote input may reach (spec §3.4 «Органы доверия»).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustControl {
    /// The pairing panel and «Привязать».
    PairingPanel,
    /// «Разрешить» in a pairing window.
    PairAllow,
    /// «Доверенные устройства» and its window.
    StrictToggle,
    /// The list: «Отключить устройство», «Подтвердить», «Удалить».
    ListEdit,
}

/// A `pair_request` (spec §5).
#[derive(Debug, Clone)]
pub struct PairRequest<'a> {
    pub request_id: &'a str,
    pub telegram_user_id: i64,
    pub first_name: Option<&'a str>,
    pub username: Option<&'a str>,
    pub viewer_key: Option<&'a Value>,
}

/// What happened to a `pair_request`'s key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerKeyOutcome {
    Accepted,
    IgnoredNoPanel,
    IgnoredWindowUsed,
    /// The same `request_id` again while it waits (§5): the first wins — its person and its key
    /// (or none); the repeat's key is not taken and spends no window.
    IgnoredRepeat,
    Invalid,
    Absent,
}

impl ViewerKeyOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::IgnoredNoPanel => "ignored_no_panel",
            Self::IgnoredWindowUsed => "ignored_window_used",
            Self::IgnoredRepeat => "ignored_repeat",
            Self::Invalid => "invalid",
            Self::Absent => "absent",
        }
    }
}

/// §10 `owner_changed`: the role a binding has after it — the account named is the owner, every
/// other a guest; `None`, the PC has no owner. The agent's list and the admission's copy both
/// take it.
pub fn role_after_owner_changed(telegram_user_id: i64, owner: Option<i64>) -> BindingRole {
    if Some(telegram_user_id) == owner {
        BindingRole::Owner
    } else {
        BindingRole::Guest
    }
}

/// One owner at most: the role another binding keeps when one comes in with `added` — a new
/// owner leaves no other (the server never lists two; this keeps the PC from reading two in
/// between). The agent's list and the admission's copy both take it.
pub fn role_beside_added(
    added: Option<BindingRole>,
    other: Option<BindingRole>,
) -> Option<BindingRole> {
    if added == Some(BindingRole::Owner) && other == Some(BindingRole::Owner) {
        Some(BindingRole::Guest)
    } else {
        other
    }
}

/// «Разрешить»'s decision for the key.
#[derive(Debug, Clone, Default)]
pub struct PairAllowDecision {
    /// The key to add (through [`Trusted::admit`]); its result at [`Admission::landed`].
    pub op: Option<AdmitOp>,
    pub key_id: Option<KeyId>,
    pub unconfirmed: bool,
    /// Why no key is written (`key_unconfirmed` in strict mode, `admit_refused:limit`, …).
    pub refused: Option<Verdict>,
    /// `rpk_conflict`: the key goes in without its recovery key; `key_other_person`: the key is
    /// at another person (active or removed) — not written, the binding goes ahead.
    pub warn: Option<&'static str>,
    /// §5: an owner on this PC and the press had no second step «Это моё устройство» — nothing
    /// changes, the request still waits, no answer goes to the server.
    pub second_step_required: bool,
    /// No such request waits here (answered, cancelled, past its bound — also when the
    /// bound passed after the caller's own check — or forgotten at the bound): nothing is
    /// decided and no answer goes to the server.
    pub not_waiting: bool,
    /// §5: the PC has an owner and the press named another role than the one derived for the
    /// person (the window showed a reading that moved since): nothing changes — no key, no
    /// answer to the server, the request still waits and the window reads the role again.
    pub role_refused: bool,
}

// --- State --------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Signed {
    key_id: KeyId,
    nonce_pc: [u8; NONCE_PC_LEN],
}

#[derive(Debug, Clone)]
struct Sess {
    /// Decided (admitted); `false` while pending or waiting for a write.
    live: bool,
    /// Counts against the window: anything but a live session signed by a confirmed owner key.
    counts: bool,
    server: SessionIdentity,
    identity: SessionIdentity,
    verdict: Verdict,
    signed: Option<Signed>,
    /// Remembered from the first offer (§3.5): `None` when it had no usable one.
    fp: Option<[u8; FINGERPRINT_LEN]>,
    had_offer: bool,
    /// `session_request` carried a `nonce_pc` (§3.4 step 2: `no_nonce` or `no_proof`).
    had_nonce: bool,
    /// The ticket of the write this session's first offer waits for: a landing answers this
    /// session only by this ticket — never one of an earlier session that had the same id.
    waiting: Option<u64>,
}

#[derive(Debug, Clone)]
struct PairKey {
    reg: KeyReg,
    person: Person,
    /// The pairing panel's token when it opened (§3.4: the window runs from there).
    token: u64,
    /// A `pc_allow` key: forgotten after this (§5, the request's expiry).
    until: Option<Instant>,
}

/// What «Разрешить» on a pairing request writes, read as the press reads it (§5): the window says
/// from this whether the press lets the person connect ([`Self::connects`]), and the press takes
/// the same reading ([`Admission::pair_allow`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairPlan {
    /// No key held for the request: the binding alone.
    NoKey,
    /// Via `pc_allow`: the key waits for `BindingAdded` — strict forgets it, observe adds it as
    /// a guest's, unconfirmed ([`Admission::binding_added`]). `lands`: what
    /// that add does with the key, read now by the same check ([`key_landing`]).
    PcAllow { lands: KeyLanding },
    /// Via `pc_allow` for an owner on this PC: the key is not taken at all (it would land a
    /// guest's), so the press gives him nothing he asked for, in either mode.
    OwnerPcAllow,
    /// The key goes to the list, confirmed or not.
    Writes { unconfirmed: bool },
    /// The same key is listed for this same person already and nothing is written: the record
    /// stays as it is. `works` — it admits as a confirmed key would; otherwise it waits for
    /// «Подтвердить» in «Доступ» (unconfirmed).
    Already { works: bool },
    /// The list refuses the key: the binding alone. `tainted` — the opening was not clean (strict
    /// writes no unconfirmed key, a removed key comes back only confirmed); otherwise `cause`.
    Refused { tainted: bool, cause: KeyRefusal },
    /// §5: the PC has an owner and the press carries another role than the one derived for the
    /// person (an owner on this PC: the owner's; anyone else: a guest's) — nothing changes, the
    /// request still waits (`role`).
    Role,
}

/// What the list does with a pairing's key ([`key_landing`]): writes it, holds it for this same
/// person already (`works`: it admits as a confirmed key would), or refuses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLanding {
    Writes,
    Already { works: bool },
    Refused(KeyRefusal),
}

/// The role a `pc_allow` key is added with at `BindingAdded`, and its confirmedness (§5, §10.1).
const PC_ALLOW_ADD: (BindingRole, bool) = (BindingRole::Guest, true);

/// The list's check of a pairing's key (`check_add`, no write) — the one the press reads, the
/// window reads, and `BindingAdded` reads for a `pc_allow` key. The person's own listed record is
/// `Already` (leaving, its removal decided, is a refusal: removed for every rule).
fn key_landing(
    store: &TrustStore,
    key: &PairKey,
    role: BindingRole,
    unconfirmed: bool,
) -> KeyLanding {
    match store.check_add(&key.reg.new_key(), &pair_ground(key, role, unconfirmed), 0) {
        Ok(_) => KeyLanding::Writes,
        Err(StoreError::OtherPerson(_)) => KeyLanding::Refused(KeyRefusal::OtherPerson),
        Err(StoreError::Full(_)) => KeyLanding::Refused(KeyRefusal::Full),
        Err(StoreError::AlreadyActive(kid)) => match store.listed(&kid) {
            Some(l) if l.state == KeyState::Works => KeyLanding::Already {
                works: !l.record.unconfirmed,
            },
            _ => KeyLanding::Refused(KeyRefusal::Unavailable),
        },
        Err(_) => KeyLanding::Refused(KeyRefusal::Unavailable),
    }
}

/// A pairing's ground: its request's person, the role, confirmed or not.
fn pair_ground(key: &PairKey, role: BindingRole, unconfirmed: bool) -> Ground {
    Ground::Pair {
        person: key.person.clone(),
        role,
        unconfirmed,
    }
}

/// §5: the role a press at the PC may name for `person`, or `None` when it is chosen at the PC —
/// derived when the PC has an owner ([`Trusted::pair_role`]); via `pc_allow`, which never gives
/// owner rights, a guest's on a PC with no owner at all. One rule for every press.
pub fn press_role(trusted: &Trusted, person: i64, via_pc_allow: bool) -> Option<BindingRole> {
    trusted
        .pair_role(person)
        .or(via_pc_allow.then_some(BindingRole::Guest))
}

/// §5: «Разрешить» needs the owner's second step «Это моё устройство»: the person is an owner on
/// this PC and the press writes a key (no key, a listed one or a refused one: nothing to consent
/// to). The window's reading and the press both ask this.
pub fn needs_owner_step(trusted: &Trusted, person: i64, plan: PairPlan) -> bool {
    trusted.pair_role(person) == Some(BindingRole::Owner) && matches!(plan, PairPlan::Writes { .. })
}

/// Why the list refuses a pairing's key on a clean opening ([`PairPlan::Refused`]): each has its
/// own line in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    /// Active or removed at another person (`key_other_person`).
    OtherPerson,
    /// The list holds as many keys as it may.
    Full,
    /// The list is damaged, unreadable or busy, or the key cannot go in as it stands (its own
    /// record not admitting): the «Доступ» section says what and how.
    Unavailable,
}

impl KeyRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OtherPerson => "other_person",
            Self::Full => "full",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What «Разрешить» on a pairing request gives the person ([`PairPlan::gives`]): the window offers
/// it only where [`Self::connects`] and otherwise says why — never a press that cannot let them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairGives {
    /// They can connect after it: a key of theirs that admits lands, or observe admits by the
    /// binding.
    Connects,
    /// They can connect after it by the same key, listed for them already: nothing is written.
    Added,
    /// Strict, and the request carries no usable key.
    NoKey,
    /// A session stands in the way: strict, and a session that is not a confirmed owner's ran
    /// since the panel opened; or a guest's session is live, so the press goes via `pc_allow`
    /// (strict forgets its key, and an owner on this PC never has it taken, either mode). The
    /// plan (`refused_tainted`, `pc_allow`, `owner_pc_allow`) and the device line tell them apart.
    Session,
    /// Strict, and the key is active or removed at another person.
    OtherPerson,
    /// Strict, and the list takes no key now: full, or it cannot take it
    /// ([`KeyRefusal::Unavailable`]). The plan (`refused_full`, `refused_unavailable`, `role`)
    /// and the device line tell them apart.
    ListClosed,
    /// Strict, and the same key is listed for the person but admits nothing until «Подтвердить»
    /// in «Доступ» (unconfirmed).
    ListedWaiting,
}

/// What «Разрешить» on a pairing request does to the DEVICE ([`PairPlan::device`]): the window's
/// device line, true in either mode. Whether the person can connect is [`PairGives`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairDevice {
    /// Nothing to say of a device: no key is taken (`pc_allow` for an owner, strict `pc_allow`),
    /// or the press is not this reading's.
    None,
    /// The key goes in, confirmed (`again`: a key removed earlier comes back).
    Trusted { again: bool },
    /// The key goes in unconfirmed (`again` as above).
    Unconfirmed { again: bool },
    /// No usable key with the request.
    NoKey,
    /// The opening was not clean and the list takes no key from it.
    NotTrusted,
    /// The same key is listed for the person and works: nothing changes.
    Added,
    /// The same key is listed for the person and waits for «Подтвердить» in «Доступ».
    ListedWaiting,
    /// Not written: the key is another person's.
    OtherPerson,
    /// Not written: the list is full.
    ListFull,
    /// Not written: the list cannot take it now.
    ListUnavailable,
}

impl PairDevice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Trusted { again: false } => "trusted",
            Self::Trusted { again: true } => "again",
            Self::Unconfirmed { again: false } => "unconfirmed",
            Self::Unconfirmed { again: true } => "unconfirmed_again",
            Self::NoKey => "no_key",
            Self::NotTrusted => "not_trusted",
            Self::Added => "added",
            Self::ListedWaiting => "listed_waiting",
            Self::OtherPerson => "other_person",
            Self::ListFull => "list_full",
            Self::ListUnavailable => "list_unavailable",
        }
    }
}

impl PairGives {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connects => "connects",
            Self::Added => "added",
            Self::NoKey => "no_key",
            Self::Session => "session",
            Self::OtherPerson => "other_person",
            Self::ListClosed => "list_closed",
            Self::ListedWaiting => "listed_waiting",
        }
    }

    /// The press lets the person connect: the window offers «Разрешить» exactly then (the one
    /// reading; the window's DTO carries it as `allow_connects`).
    pub const fn connects(self) -> bool {
        matches!(self, Self::Connects | Self::Added)
    }
}

impl PairPlan {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoKey => "no_key",
            Self::PcAllow { .. } => "pc_allow",
            Self::OwnerPcAllow => "owner_pc_allow",
            Self::Writes { unconfirmed: false } => "writes",
            Self::Writes { unconfirmed: true } => "writes_unconfirmed",
            Self::Already { works: true } => "already",
            Self::Already { works: false } => "already_waiting",
            Self::Refused { tainted: true, .. } => "refused_tainted",
            Self::Refused { cause, .. } => match cause {
                KeyRefusal::OtherPerson => "refused_other_person",
                KeyRefusal::Full => "refused_full",
                KeyRefusal::Unavailable => "refused_unavailable",
            },
            Self::Role => "role",
        }
    }

    /// What the press gives the person, by the admission's own rule for their next session:
    /// strict admits only a working confirmed key of theirs; observe admits a bound person
    /// whatever their key — unsigned or an unknown key all go by `is_bound` — so in observe every
    /// press that binds connects. Not offered all the same: an owner's `pc_allow` (his key is not
    /// taken, nothing he asked for).
    pub fn gives(self, strict: bool) -> PairGives {
        match (strict, self) {
            (_, Self::OwnerPcAllow) => PairGives::Session,
            // Strict writes only a confirmed key: the list refuses an unconfirmed one (`Refused`).
            (true, Self::Writes { .. }) => PairGives::Connects,
            (_, Self::Already { works: true }) => PairGives::Added,
            (true, Self::Already { works: false }) => PairGives::ListedWaiting,
            (true, Self::NoKey) => PairGives::NoKey,
            (true, Self::PcAllow { .. } | Self::Refused { tainted: true, .. }) => {
                PairGives::Session
            }
            (true, Self::Refused { cause, .. }) => match cause {
                KeyRefusal::OtherPerson => PairGives::OtherPerson,
                KeyRefusal::Full | KeyRefusal::Unavailable => PairGives::ListClosed,
            },
            // The window reads the derived role, so this is a press's own reading only.
            (true, Self::Role) => PairGives::ListClosed,
            (false, _) => PairGives::Connects,
        }
    }

    /// What the press does to the device, in either mode: `again` — the key is a removed one
    /// coming back. Never a promise for a key not written.
    pub fn device(self, strict: bool, again: bool) -> PairDevice {
        match self {
            Self::NoKey => PairDevice::NoKey,
            // Strict forgets a `pc_allow` key; observe adds it as a guest's, unconfirmed.
            Self::PcAllow { .. } if strict => PairDevice::None,
            // Observe: what `BindingAdded` does with the key — the promise only for a write.
            Self::PcAllow { lands } => match lands {
                KeyLanding::Writes => PairDevice::Unconfirmed { again },
                KeyLanding::Already { works: true } => PairDevice::Added,
                KeyLanding::Already { works: false } => PairDevice::ListedWaiting,
                KeyLanding::Refused(cause) => cause.device(),
            },
            Self::OwnerPcAllow | Self::Role => PairDevice::None,
            Self::Writes { unconfirmed: false } => PairDevice::Trusted { again },
            Self::Writes { unconfirmed: true } => PairDevice::Unconfirmed { again },
            Self::Already { works: true } => PairDevice::Added,
            Self::Already { works: false } => PairDevice::ListedWaiting,
            Self::Refused { tainted: true, .. } => PairDevice::NotTrusted,
            Self::Refused { cause, .. } => cause.device(),
        }
    }
}

impl KeyRefusal {
    /// The device line of a refused key.
    const fn device(self) -> PairDevice {
        match self {
            Self::OtherPerson => PairDevice::OtherPerson,
            Self::Full => PairDevice::ListFull,
            Self::Unavailable => PairDevice::ListUnavailable,
        }
    }
}

/// A `pair_request` waiting for its answer (§5). The first under its id wins: its person and its
/// key (or its lack of one) stay until the answer, a cancel or [`PAIR_WAIT`].
#[derive(Debug, Clone)]
struct PairWait {
    person: Person,
    key: Option<PairKey>,
    /// Arrival order, for [`PAIR_WAITING_MAX`].
    seq: u64,
    until: Instant,
}

#[derive(Debug, Clone)]
enum Waiting {
    /// A first offer waits for its key's write.
    Offer {
        session_id: String,
        is_bound: bool,
        mode: Mode,
        ks: Ks,
        by: Option<KeyId>,
    },
    /// «Разрешить» or `BindingAdded`.
    Pair,
}

/// Another device's attempt held while its offer waits for the key's write: the entry the
/// list would note (the server's person and role, the key, its kind and platform and recovery
/// key, the PC's clock at the offer) and the offer's monotonic time for the journal's day bound.
#[derive(Debug, Clone)]
struct HeldAttempt {
    draft: Attempt,
    now_ms: u64,
}

#[derive(Debug, Clone)]
struct Awaiting {
    waiting: Waiting,
    /// The session heard `slow` already, or ended ([`Admission::session_ended`]): the landing
    /// answers no session.
    answered: bool,
    /// §10.2, a first offer's: the attempt it is if the list refuses its key at the
    /// queue's turn — what the attempt needs, taken from the verified card (never the card),
    /// kept until the list's final word ([`Admission::landed`]).
    attempt: Option<HeldAttempt>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at_ms: u64,
}

/// What a ground gave (§3.4 step 8).
struct Candidate {
    op: StoreOp,
    ground: &'static str,
    uid: i64,
    role: BindingRole,
    unconfirmed: bool,
    by: Option<KeyId>,
}

/// Why a ground gave nothing.
enum Fail {
    Verdict(Verdict),
    /// A refusal of this ground whose rule the vectors name (`why`): an invitation's (§7); a
    /// `grant_role` whose cause is «owner on this PC» ([`OWNER_ON_PC`], §10.2).
    Why(Verdict, &'static str),
    /// Not a refusal of this ground: the whole offer stops here (`key_unconfirmed` in strict,
    /// `key_revoked`, a damaged list).
    Stop(Verdict),
}

/// The admission engine. One per orchestrator, on its main loop.
pub struct Admission {
    device_id: String,
    verifier: TelegramVerifier,
    book: NonceBook,
    bucket: Bucket,
    busy_warned_ms: Option<u64>,
    sessions: HashMap<String, Sess>,
    /// The pairing panel: open since the token, and whether its one key was taken.
    panel: Option<(u64, bool)>,
    /// Every `pair_request` waiting for its answer, with or without a key, by request id
    /// (bounded: [`PAIR_WAITING_MAX`], [`PAIR_WAIT`]).
    pairs: HashMap<String, PairWait>,
    pair_seq: u64,
    /// The request on screen ([`Self::pair_shown`]), never forgotten at the bound.
    pair_shown: Option<String>,
    /// For tests: the request a guard ([`Self::pair_still_waiting`]) found waiting reaches its
    /// bound right after it — the deadline crossed between the guard and the consume.
    #[cfg(test)]
    pub(crate) lapse_after_guard: bool,
    /// `pc_allow` keys waiting for `BindingAdded` (observe mode, §5): by request id.
    pc_allow: HashMap<String, PairKey>,
    probes_key: HashMap<(i64, KeyId), u64>,
    probes_day: HashMap<i64, VecDeque<u64>>,
    recover_journal: HashMap<i64, u64>,
    /// When a party member's device past the list's limit was last told, per person.
    party_limit_told: HashMap<i64, u64>,
    /// Other devices' attempts journaled per person in the last day.
    attempts_day: HashMap<i64, VecDeque<u64>>,
    next_ticket: u64,
    awaiting: HashMap<u64, Awaiting>,
    /// Live or pending sessions of the orchestrator's that this engine does not know (they count
    /// against the window): as [`Self::window_live`] last saw them.
    unknown_live: AtomicUsize,
    /// The PC's bindings as the server last said them (`agent_ready.bindings`, `binding_added`,
    /// `binding_removed`): who the PC knows (§10) and whose attempts count (§10.2). The server's
    /// word: never a role given to a key.
    bindings: HashMap<i64, BindingRole>,
    /// The valid card of the offer being decided when its key is unknown (no record, no
    /// tombstone): a refusal then may be an attempt (§10.2).
    attempt_reg: Option<KeyReg>,
    /// A test's wall clock: `Some(t0)` reads `t0 + now_ms` (the vectors' `pc_clock_at_0_ms`).
    wall_at_0: Option<i64>,
    /// The vectors' offer being decided, with the request it carries: neither Pending nor live
    /// while its checks run (the reference's table), so it counts against no window.
    #[cfg(test)]
    pub(crate) quiet: Option<String>,
}

/// The mode the admission decides in now: the PC's switch («Доверенные устройства») while the list
/// reads; a damaged list's mode file ([`TrustStore::damaged_mode`]) when it says observe; strict
/// otherwise (no list, a damaged one whose mode file says strict or nothing). The one reading of the
/// mode: the decisions, the orchestrator's checks and the mode a `session_end` reports all ask it.
pub(crate) fn mode_of(store: Option<&TrustStore>) -> Mode {
    match store.map(|s| (s.switches(), s.damaged_mode())) {
        Some((Ok(s), _)) if !s.trusted_devices_mode => Mode::Observe,
        // A damaged list whose mode file says observe (the store's «mode file»).
        Some((Err(_), Some(false))) => Mode::Observe,
        _ => Mode::Strict,
    }
}

/// The guards of a person's removal (§10): never the owner by the bindings, nor a holder of a
/// working owner-role key — not touched at all — nor a person the PC does not know. Whether the
/// removal touches anything of theirs.
pub(crate) fn removal_touches(
    store: &TrustStore,
    telegram_user_id: i64,
    bound: Option<BindingRole>,
    by: Removal,
) -> bool {
    let owner_key = store
        .person_keys(telegram_user_id)
        .as_ref()
        .is_ok_and(PersonKeys::owner_by_keys);
    let known = store.knows_person(telegram_user_id, bound.is_some());
    let owner_by_binding = bound == Some(BindingRole::Owner);
    if owner_by_binding || owner_key || !known {
        tracing::debug!(
            user_id = telegram_user_id,
            by = ?by,
            owner_by_binding,
            owner_key,
            known,
            "admission: a person removed: nothing of theirs is touched (the owner, a working \
             owner-role key, or a person the PC does not know)"
        );
        return false;
    }
    true
}

impl Admission {
    /// `device_id`: this PC's own (config.json). `verifier`: Telegram's, for recoveries
    /// ([`TelegramVerifier::production`] in every shipped build).
    pub fn new(device_id: String, verifier: TelegramVerifier) -> Self {
        Self {
            device_id,
            verifier,
            book: NonceBook::new(),
            bucket: Bucket {
                tokens: f64::from(VERIFY_RATE_PER_S),
                at_ms: 0,
            },
            busy_warned_ms: None,
            sessions: HashMap::new(),
            panel: None,
            pairs: HashMap::new(),
            pair_seq: 0,
            pair_shown: None,
            #[cfg(test)]
            lapse_after_guard: false,
            pc_allow: HashMap::new(),
            probes_key: HashMap::new(),
            probes_day: HashMap::new(),
            recover_journal: HashMap::new(),
            party_limit_told: HashMap::new(),
            attempts_day: HashMap::new(),
            next_ticket: 1,
            awaiting: HashMap::new(),
            unknown_live: AtomicUsize::new(0),
            bindings: HashMap::new(),
            attempt_reg: None,
            wall_at_0: None,
            #[cfg(test)]
            quiet: None,
        }
    }

    /// A test's wall clock: the PC's clock reads `at_0 + now_ms` (monotonic) from now on.
    #[cfg(test)]
    pub(crate) fn set_wall_clock(&mut self, at_0: i64) {
        self.wall_at_0 = Some(at_0);
    }

    /// The PC's wall clock now (unix ms; a test's when set), for a removal's `T` decided outside
    /// the engine (the window's «Удалить человека», §10).
    pub fn wall_now(&self, now_ms: u64) -> i64 {
        self.wall_ms(now_ms)
    }

    /// The PC's wall clock (unix ms) for the list's times: removals' `T`, attempts (§10).
    fn wall_ms(&self, now_ms: u64) -> i64 {
        match self.wall_at_0 {
            Some(t0) => t0.saturating_add(i64::try_from(now_ms).unwrap_or(i64::MAX)),
            None => crate::journal::now_ms(),
        }
    }

    // --- Bindings (the server's word, §10, §10.2) -------------------------------------------

    /// The whole binding list as it stands now (the agent's, after every binding message): kept
    /// here, and its owners told to the trust list ([`Trusted::set_bound_owners`]) — «owner on
    /// this PC» and the derived pairing role read them, so both move in one call.
    pub fn set_bindings(
        &mut self,
        trusted: &mut Trusted,
        bindings: impl IntoIterator<Item = (i64, BindingRole)>,
    ) {
        self.bindings = bindings.into_iter().collect();
        tracing::debug!(
            bound = self.bindings.len(),
            "admission: the PC's bindings (the server's word)"
        );
        self.tell_owners(trusted);
    }

    /// One binding added (`binding_added`) or its role changed, by the agent list's own rule
    /// ([`role_beside_added`]: a new owner leaves no other).
    pub fn note_binding(
        &mut self,
        trusted: &mut Trusted,
        telegram_user_id: i64,
        role: BindingRole,
    ) {
        tracing::debug!(
            user_id = telegram_user_id,
            role = role.as_str(),
            "admission: a binding noted (the server's word)"
        );
        for (uid, other) in &mut self.bindings {
            let kept = role_beside_added(Some(role), Some(*other)).unwrap_or(*other);
            if kept != *other {
                tracing::debug!(
                    user_id = *uid,
                    "admission: a new owner's binding leaves this one a guest"
                );
                *other = kept;
            }
        }
        self.bindings.insert(telegram_user_id, role);
        self.tell_owners(trusted);
    }

    /// The bindings' owners, to the trust list.
    fn tell_owners(&self, trusted: &mut Trusted) {
        trusted.set_bound_owners(
            self.bindings
                .iter()
                .filter(|(_, r)| **r == BindingRole::Owner)
                .map(|(u, _)| *u),
        );
    }

    /// A binding's role as the server said it.
    pub fn bound_role(&self, telegram_user_id: i64) -> Option<BindingRole> {
        self.bindings.get(&telegram_user_id).copied()
    }

    /// A write of the notes alone when memory's are not in the file (`why` for the log): staged
    /// at its turn, it writes nothing if a write before it carried them.
    fn queue_notes(&mut self, trusted: &mut Trusted, why: &'static str) {
        let unsaved = trusted
            .store_for_notes()
            .is_some_and(|store| store.notes_unsaved());
        tracing::debug!(
            why,
            unsaved,
            "admission: the notes {}",
            if unsaved {
                "are not in the file: a write of them queued"
            } else {
                "are in the file: nothing queued"
            }
        );
        if unsaved {
            let ticket = self.ticket();
            trusted.admit(AdmitOp {
                ticket,
                op: StoreOp::Notes,
            });
        }
    }

    /// A person's removal (§10): `binding_removed` on the server (`by` `server`) or «Отвязать» at
    /// the PC (`pc`) — the person's guest-role keys ([`Trusted::guest_removed_on_server`] /
    /// [`Trusted::untrust_guest`]; owner-role keys stay), and when any leave, the one shared step
    /// of a removal (their attempts go, the grant token is replaced). Decided in memory, once,
    /// before anything is staged; the untrust's op is a write of that memory. Never for the
    /// owner (by the bindings, before this call took a `binding_removed` out of them), nor a
    /// holder of a working owner-role key — not touched at all: their keys, guest-role too, their
    /// attempts and the grant token stay — nor a person the PC does not know. While the list is
    /// damaged nothing changes (§10 «Повреждённый список»). Whether their keys were decided.
    pub fn remove_person(
        &mut self,
        trusted: &mut Trusted,
        telegram_user_id: i64,
        bound: Option<BindingRole>,
        by: Removal,
        live: usize,
    ) -> bool {
        let Some(store) = trusted.store() else {
            tracing::debug!(
                user_id = telegram_user_id,
                by = ?by,
                "admission: a person removed; no list here"
            );
            return false;
        };
        if !removal_touches(store, telegram_user_id, bound, by) {
            return false;
        }
        match by {
            Removal::Server => trusted.guest_removed_on_server(telegram_user_id, live),
            Removal::Pc => trusted.untrust_guest(telegram_user_id, live),
        }
        tracing::debug!(
            user_id = telegram_user_id,
            by = ?by,
            "admission: a person's removal decided in memory (guest keys denied); one write takes \
             it"
        );
        true
    }

    fn ticket(&mut self) -> u64 {
        let t = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1);
        t
    }

    /// The sessions and pending sessions this engine knows that count against the window
    /// (§3.4): every one but a live session signed by a confirmed owner key. Not the window's
    /// number by itself: see [`Self::window_live`].
    pub fn counting(&self) -> usize {
        self.sessions
            .iter()
            .filter(|(id, s)| s.counts && !self.is_quiet(id))
            .count()
    }

    #[cfg(test)]
    fn is_quiet(&self, session_id: &str) -> bool {
        self.quiet.as_deref() == Some(session_id)
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self, reason = "the test build's twin reads the engine")]
    fn is_quiet(&self, _session_id: &str) -> bool {
        false
    }

    /// [`Self::counting`] without one session: the vectors' table, where the offer being decided
    /// is neither Pending nor live while its checks run.
    #[cfg(test)]
    pub(crate) fn counting_except(&self, session_id: &str) -> usize {
        self.sessions
            .iter()
            .filter(|(id, s)| s.counts && id.as_str() != session_id)
            .count()
    }

    /// **The** window count (§3.4, §10.1), one source for the orchestrator's
    /// `trusted.sync_live` and for this engine's own: `live` — every session and pending session
    /// the orchestrator has now (its `pending` and `sessions` ids) — counts unless this engine
    /// knows it as a live session signed by a confirmed owner key; a session this engine does
    /// not know counts. Sessions this engine still holds that the orchestrator does not list now
    /// count until their end is told ([`Self::session_ended`]): the safe side. Remembers the
    /// unknown ones, so this engine's own updates of the window between two calls say the same
    /// number and the window token moves once per change.
    pub fn window_live<'a>(&self, live: impl IntoIterator<Item = &'a str>) -> usize {
        let unknown = live
            .into_iter()
            .filter(|id| !self.sessions.contains_key(*id))
            .count();
        let was = self.unknown_live.swap(unknown, Ordering::Relaxed);
        if was != unknown {
            tracing::debug!(
                was,
                unknown,
                "admission: sessions the admission does not know (they count against the window)"
            );
        }
        self.counting() + unknown
    }

    /// The window count as last known ([`Self::window_live`]'s rule, without a new list).
    fn window_count(&self) -> usize {
        self.counting() + self.unknown_live.load(Ordering::Relaxed)
    }

    fn sync(&self, trusted: &mut Trusted) {
        trusted.sync_live(self.window_count());
    }

    // --- Nonces ---------------------------------------------------------------------------------

    /// A new batch for the server (`session_nonces`, spec §2.2), issued at `now_ms` (monotonic).
    pub fn new_nonce_batch(&mut self, now_ms: u64) -> Option<NonceBatch> {
        self.book.new_batch(now_ms)
    }

    /// Record a batch issued at `issued_ms` (the vectors' and tests' batches).
    pub fn insert_nonce_batch(&mut self, issued_ms: u64, nonces: Vec<[u8; NONCE_PC_LEN]>) {
        self.book.insert(issued_ms, nonces);
    }

    /// Resume from sleep (spec §2.2): the book is cleared and a new batch is due at once.
    pub fn resumed_from_sleep(&mut self, now_ms: u64) -> Option<NonceBatch> {
        self.book.clear();
        self.book.new_batch(now_ms)
    }

    // --- Sessions -------------------------------------------------------------------------------

    /// A `session_request`: the session is pending and counts against the window.
    pub fn session_requested(
        &mut self,
        trusted: &mut Trusted,
        req: &SessionRequest<'_>,
    ) -> RequestDecision {
        if self.sessions.contains_key(req.session_id) {
            tracing::warn!(
                session = req.session_id,
                "admission: a repeated session_request of a known session; ignored"
            );
            return RequestDecision {
                ignored: true,
                want_batch: false,
            };
        }
        let nonce = req.nonce_pc.and_then(b64url_array::<NONCE_PC_LEN>);
        let want_batch = nonce.is_none_or(|n| self.book.in_newest_batch(&n));
        let server = SessionIdentity {
            telegram_user_id: req.telegram_user_id,
            role: req.role,
            first_name: req.first_name.map(str::to_string),
            username: req.username.map(str::to_string),
            from_record: false,
        };
        tracing::debug!(
            session = req.session_id,
            user_id = req.telegram_user_id,
            role = req.role.as_str(),
            nonce = nonce.is_some(),
            want_batch,
            "admission: session requested; pending (counts against the window)"
        );
        self.sessions.insert(
            req.session_id.to_string(),
            Sess {
                live: false,
                counts: true,
                identity: server.clone(),
                server,
                verdict: Verdict::UNSIGNED,
                signed: None,
                fp: None,
                had_offer: false,
                had_nonce: req.nonce_pc.is_some(),
                waiting: None,
            },
        );
        if !self.is_quiet(req.session_id) {
            trusted.session_began("pending", req.session_id);
        }
        self.sync(trusted);
        RequestDecision {
            ignored: false,
            want_batch,
        }
    }

    /// A session ended (or its pending request was dropped).
    /// A session's write still in flight is detached from it: when it lands, its key's own
    /// events stand, but it answers no session — not a later one the server gives the same id.
    pub fn session_ended(&mut self, trusted: &mut Trusted, session_id: &str) {
        if self.sessions.remove(session_id).is_some() {
            tracing::debug!(session = session_id, "admission: session ended");
        }
        for (ticket, aw) in &mut self.awaiting {
            if let (
                Waiting::Offer {
                    session_id: sid, ..
                },
                false,
            ) = (&aw.waiting, aw.answered)
            {
                if sid == session_id {
                    aw.answered = true;
                    tracing::debug!(
                        session = session_id,
                        ticket = *ticket,
                        "admission: the ended session's write is still in flight; detached \
                         (it answers no session when it lands)"
                    );
                }
            }
        }
        self.sync(trusted);
    }

    /// Whether `session_id` is the session that waits for the write `ticket` (not an earlier
    /// session that had the same id).
    fn waits_for(&self, session_id: &str, ticket: u64) -> bool {
        self.sessions
            .get(session_id)
            .is_some_and(|s| s.waiting == Some(ticket))
    }

    fn take_bucket(&mut self, now_ms: u64) -> bool {
        let rate = f64::from(VERIFY_RATE_PER_S);
        let elapsed = now_ms.saturating_sub(self.bucket.at_ms) as f64 / 1000.0;
        self.bucket.tokens = (self.bucket.tokens + elapsed * rate).min(rate);
        self.bucket.at_ms = self.bucket.at_ms.max(now_ms);
        if self.bucket.tokens >= 1.0 {
            self.bucket.tokens -= 1.0;
            return true;
        }
        if self
            .busy_warned_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= BUSY_WARN_MS)
        {
            self.busy_warned_ms = Some(now_ms);
            tracing::warn!(
                rate = VERIFY_RATE_PER_S,
                "admission: more offers with a proof than the PC checks per second; refused busy \
                 (warned once a minute)"
            );
        }
        false
    }

    /// The first offer of a session (spec §3.4): steps 1–10, synchronously. `now_ms` — monotonic
    /// (the nonce book's clock); `now_unix_ms` — for the list's display times.
    pub fn first_offer(
        &mut self,
        trusted: &mut Trusted,
        offer: &FirstOffer<'_>,
        now_ms: u64,
    ) -> OfferDecision {
        let sid = offer.session_id;
        let mode = mode_of(trusted.store());
        let fp = viewer_fingerprint(offer.sdp).ok();
        let Some(sess) = self.sessions.get(sid).cloned() else {
            tracing::warn!(
                session = sid,
                "admission: a first offer without a session_request; refused"
            );
            return OfferDecision {
                mode,
                ..refusal(Verdict::nonce_stale("no_nonce"))
            };
        };
        if sess.had_offer {
            // §2.6/§3.5: a session has one first offer. The orchestrator asks [`Self::offered`]
            // and sends any other through [`Self::reoffer`]; one that still comes here is never
            // decided again (no second verdict, nothing of the first overwritten) and ends the
            // session: the safe side of a duplicate nobody routed.
            let r = self.reoffer(sid, offer.sdp, offer.proof);
            let verdict = match r {
                Reoffer::End(v) => v,
                Reoffer::Continue => Verdict::FINGERPRINT_CHANGED,
            };
            // not-a-key-name: a verdict's protocol code (`.code`), never a key
            tracing::warn!(
                session = sid,
                reoffer = ?r,
                verdict = verdict.code,
                detail = verdict.detail.unwrap_or("-"),
                "admission: a second first offer of a session not routed as a re-offer; never \
                 decided again: the session ends"
            );
            self.sessions.remove(sid);
            self.sync(trusted);
            return OfferDecision {
                mode,
                ..refusal(verdict)
            };
        }
        self.attempt_reg = None;
        let (mut decision, spent_nonce) = self.decide(trusted, offer, &sess, mode, fp, now_ms);
        let attempt = self.after_decide(trusted, &decision, &sess.server, now_ms);
        // The notes the decision left (an attempt) reach the file with the next write: the touch
        // carries them; with no touch, a write of the notes alone.
        if decision.touch.is_none() && trusted.store().is_some_and(TrustStore::notes_unsaved) {
            tracing::debug!(
                session = sid,
                "admission: the list's notes changed; a write queued"
            );
            decision.touch = Some(AdmitOp {
                ticket: self.ticket(),
                op: StoreOp::Notes,
            });
        }
        decision.attempts = attempt
            .and_then(|a| self.journal_bound(a, now_ms))
            .into_iter()
            .collect();
        // Remember what the re-offers check (§3.5), whatever the verdict.
        let admitted_or_waiting = !matches!(decision.outcome, Outcome::Refuse);
        if let Some(s) = self.sessions.get_mut(sid) {
            s.had_offer = true;
            s.fp = fp;
            s.verdict = decision.verdict;
            if let Some(identity) = &decision.identity {
                s.identity = identity.clone();
            }
            if let (true, Some(ks), Some(nonce_pc)) =
                (decision.verdict.is_signed(), &decision.ks, spent_nonce)
            {
                s.signed = Some(Signed {
                    key_id: ks.kid.clone(),
                    nonce_pc,
                });
            }
            if let Outcome::AfterWrite(op) = &decision.outcome {
                s.waiting = Some(op.ticket);
            }
            if matches!(decision.outcome, Outcome::Admit) {
                s.live = true;
                s.counts = !(decision.verdict == Verdict::SIGNED
                    && s.identity.role == BindingRole::Owner
                    && s.identity.from_record);
            }
        }
        if !admitted_or_waiting {
            self.sessions.remove(sid);
        }
        self.sync(trusted);
        // not-a-key-name: a verdict's protocol code (`.code`), never a key
        tracing::info!(
            session = sid,
            verdict = decision.verdict.code,
            detail = decision.verdict.detail.unwrap_or("-"),
            admit = decision.admit.unwrap_or("-"),
            mode = mode.as_str(),
            outcome = match decision.outcome {
                Outcome::Admit => "admit",
                Outcome::Refuse => "refuse",
                Outcome::AfterWrite(_) => "after_write",
            },
            "admission: first offer decided"
        );
        if !admitted_or_waiting {
            decision.ks = None;
            decision.identity = None;
            decision.verdict = end_reason(decision.verdict, mode);
        }
        decision
    }

    /// What a decision leaves on the list's notes (§10.2), in memory: another device's attempt
    /// when the offer verified for a key the PC does not know, with a valid card, and was refused
    /// `key_unknown` or `admit_refused` for a person in the bindings —
    /// either mode. The window hears of the attempt ([`Trusted::attempt_noted`]); a new one is
    /// returned for the journal. An offer whose key goes to the queue is held until the list's
    /// word ([`Self::landed`]).
    fn after_decide(
        &mut self,
        trusted: &mut Trusted,
        decision: &OfferDecision,
        server: &SessionIdentity,
        now_ms: u64,
    ) -> Option<DeviceAttempt> {
        let wall = self.wall_ms(now_ms);
        let reg = self.attempt_reg.take();
        trusted.store_for_notes()?;
        let reg = reg?;
        let draft = Attempt {
            telegram_user_id: server.telegram_user_id,
            role: server.role,
            key: reg.key,
            kind: reg.kind,
            platform: reg.platform,
            rpk: reg.rpk,
            first_at: wall,
            last_at: wall,
            count: 1,
        };
        // The key goes to the list's queue; the list's word at its turn decides whether
        // this offer is an attempt — held until then.
        if let Outcome::AfterWrite(op) = &decision.outcome {
            if let Some(Awaiting {
                waiting: Waiting::Offer { .. },
                attempt,
                ..
            }) = self.awaiting.get_mut(&op.ticket)
            {
                // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
                tracing::debug!(
                    user_id = draft.telegram_user_id,
                    kid = %draft.key_id().short(),
                    ticket = op.ticket,
                    "admission: an unknown key's write waits: an attempt only if the list \
                     refuses it at its turn (held until then)"
                );
                *attempt = Some(HeldAttempt { draft, now_ms });
            }
            return None;
        }
        if !counts_as_attempt(decision.verdict) {
            return None;
        }
        self.note_device_attempt(trusted, draft, decision.verdict)
    }

    /// Note another device's attempt (§10.2) refused `verdict` ([`counts_as_attempt`]) on the
    /// list's notes, in memory, when its person is in the bindings; the window hears of it
    /// ([`Trusted::attempt_noted`]). A new one is returned for the journal.
    fn note_device_attempt(
        &mut self,
        trusted: &mut Trusted,
        draft: Attempt,
        verdict: Verdict,
    ) -> Option<DeviceAttempt> {
        let uid = draft.telegram_user_id;
        let kid = draft.key_id().clone();
        if !self.bindings.contains_key(&uid) {
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                user_id = uid,
                kid = %kid.short(),
                "admission: a refused new device of a person not in the bindings: no attempt"
            );
            return None;
        }
        let wall = draft.last_at;
        let device = DeviceRef {
            kind: draft.kind.clone(),
            platform: draft.platform.clone(),
        };
        let noted = trusted
            .store_for_notes()
            .map(|store| store.note_attempt_how(draft, wall));
        let new = noted == Some(AttemptNoted::New);
        trusted.attempt_noted(uid, &kid, new, wall);
        // §10.2: an attempt not recorded (all 64 places traced, this person not) is journaled as
        // usual, within the day's bound; a repeat or no attempt is not.
        let journal = new || noted == Some(AttemptNoted::NotRecorded);
        tracing::debug!(
            user_id = uid,
            kid = %kid.short(),
            noted = ?noted,
            journal,
            "admission: another device's attempt"
        );
        if !journal {
            return None;
        }
        // The refusal as the journal names it: `key_unknown`, or `admit_refused`'s detail.
        let reason = if verdict == Verdict::KEY_UNKNOWN {
            "key_unknown"
        } else {
            verdict.detail.unwrap_or(verdict.code)
        };
        Some(DeviceAttempt {
            telegram_user_id: uid,
            reason,
            key_id: kid,
            device: Some(device),
            at_ms: wall,
        })
    }

    /// Whether `session_id` has had its first offer — decided and admitted, or waiting for its
    /// key's write (§2.6). Any other offer of it is a re-offer: [`Self::reoffer`] (the
    /// orchestrator drops it on `Continue` while the session waits for its write, and ends the
    /// session on `End`), never [`Self::first_offer`] again.
    pub fn offered(&self, session_id: &str) -> bool {
        self.sessions.get(session_id).is_some_and(|s| s.had_offer)
    }

    /// Whether to journal another device's new attempt (the list took it as new): within
    /// [`ATTEMPTS_JOURNALED_PER_DAY`] for the person.
    fn journal_bound(&mut self, attempt: DeviceAttempt, now_ms: u64) -> Option<DeviceAttempt> {
        let uid = attempt.telegram_user_id;
        for day in self.attempts_day.values_mut() {
            while day
                .front()
                .is_some_and(|at| now_ms.saturating_sub(*at) >= DAY_MS)
            {
                day.pop_front();
            }
        }
        self.attempts_day.retain(|_, day| !day.is_empty());
        let day = self.attempts_day.entry(uid).or_default();
        let journal = day.len() < ATTEMPTS_JOURNALED_PER_DAY;
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            user_id = uid,
            reason = attempt.reason,
            kid = %attempt.key_id.short(),
            today = day.len(),
            "admission: another device tried to get in as this person: {}",
            if journal { "journaled" } else { "kept for the window, not journaled (a day's bound)" }
        );
        if !journal {
            return None;
        }
        day.push_back(now_ms);
        Some(attempt)
    }
}

/// The reason a refused offer ends with: its verdict, but never a success verdict — observe mode
/// refuses those only for an unbound person (`unbound`, as before keys).
fn end_reason(verdict: Verdict, mode: Mode) -> Verdict {
    let success = verdict == Verdict::SIGNED
        || verdict == Verdict::UNSIGNED
        || (mode == Mode::Observe && verdict == Verdict::KEY_UNCONFIRMED);
    if success {
        // not-a-key-name: a verdict's protocol code (`.code`), never a key
        tracing::debug!(
            verdict = verdict.code,
            mode = mode.as_str(),
            "admission: refused with a success verdict (observe, not bound): ends unbound"
        );
        Verdict::UNBOUND
    } else {
        verdict
    }
}

/// A refused offer with nothing else to say. Its `mode` is a placeholder: every caller sets the
/// mode it read from the list (`OfferDecision { mode, ..refusal(v) }`).
fn refusal(verdict: Verdict) -> OfferDecision {
    OfferDecision {
        verdict,
        admit: None,
        mode: Mode::Strict,
        outcome: Outcome::Refuse,
        ks: None,
        identity: None,
        journal: Vec::new(),
        warn: None,
        why: None,
        touch: None,
        attempts: Vec::new(),
    }
}

/// An offer decided without a key record behind it (unsigned, or refused): strict refuses;
/// observe admits by `is_bound` with the server's identity, and tells the viewer the verdict when
/// it named a key.
fn without_record(
    verdict: Verdict,
    mode: Mode,
    is_bound: bool,
    kid: Option<&KeyId>,
    server: &SessionIdentity,
) -> OfferDecision {
    let observe = mode == Mode::Observe;
    let admitted = observe && is_bound;
    // not-a-key-name: a verdict's protocol code (`.code`), never a key
    tracing::debug!(
        verdict = verdict.code,
        detail = verdict.detail.unwrap_or("-"),
        mode = mode.as_str(),
        is_bound,
        admitted,
        "admission: no key record admits this offer; {}",
        if observe {
            "observe mode admits by the binding"
        } else {
            "strict mode refuses"
        }
    );
    OfferDecision {
        verdict,
        admit: None,
        mode,
        outcome: if admitted {
            Outcome::Admit
        } else {
            Outcome::Refuse
        },
        ks: kid.filter(|_| admitted).map(|kid| Ks {
            kid: kid.clone(),
            verdict,
            admit: None,
            mode,
        }),
        identity: admitted.then(|| server.clone()),
        journal: Vec::new(),
        warn: None,
        why: None,
        touch: None,
        attempts: Vec::new(),
    }
}

/// The ground-specific code of a store refusal (spec §6.5, §7, §8.4, §9, §10).
/// §10.2: the refusals of a verified offer with a valid card for an unknown key that make it
/// another device's attempt: `key_unknown`, or `admit_refused`.
fn counts_as_attempt(v: Verdict) -> bool {
    v == Verdict::KEY_UNKNOWN || v.code == "admit_refused"
}

fn store_fail(e: &StoreError, ground: &'static str) -> Fail {
    let refused = |d| Fail::Verdict(Verdict::admit_refused(d));
    match e {
        StoreError::KeyUnconfirmed => Fail::Stop(Verdict::KEY_UNCONFIRMED),
        // §10 «Одно правило возврата»: an endorse that returns nothing (issued before the removal,
        // or another person's) is this ground's refusal: the next ground in `admit` is tried.
        StoreError::Removed { .. } if ground == "endorse" => Fail::Verdict(Verdict::KEY_REVOKED),
        StoreError::Removed { .. } => Fail::Stop(Verdict::KEY_REVOKED),
        StoreError::Full(_) => refused("limit"),
        StoreError::RpkConflict => refused("rpk_conflict"),
        StoreError::Spent(_) if ground == "grant" || ground == "party" => refused("grant_spent"),
        StoreError::PartyLeader => refused("party_leader"),
        StoreError::Spent(_) => refused("endorse_spent"),
        StoreError::InviteSpent(_) => refused("invite_spent"),
        StoreError::InviteIdMismatch => Fail::Why(Verdict::admit_refused("invite_bad"), "binding"),
        StoreError::InviteNotOwner => Fail::Why(Verdict::admit_refused("invite_bad"), "by"),
        StoreError::InviteOwnerMismatch => refused("invite_owner_mismatch"),
        StoreError::InviteMissing => refused("invite_missing"),
        StoreError::NotOwner => refused("grant_not_owner"),
        // The list's `grant_role` is only ever «the person is an owner on this PC» (a grant naming
        // a role other than guest never reaches it: the admission's own check refuses it).
        StoreError::GrantRole => Fail::Why(Verdict::admit_refused("grant_role"), OWNER_ON_PC),
        StoreError::GrantStale => refused("grant_stale"),
        StoreError::SignerUnknown(_) => refused("endorse_signer_unknown"),
        StoreError::SignerRemoved(_) => refused("endorse_signer_revoked"),
        StoreError::FirstUseClosed(_) | StoreError::FirstUseAgain => refused("first_use_closed"),
        StoreError::RecoverNoRecord => refused("recover_no_record"),
        StoreError::RecoverBadSig => refused("recover_bad_sig"),
        StoreError::RecoverAttestation => refused("attest_bad"),
        StoreError::Invalid(_) if ground == "grant" || ground == "party" => {
            refused("grant_malformed")
        }
        StoreError::Invalid(_) | StoreError::AlreadyActive(_) => refused("key_reg_bad"),
        _ => Fail::Stop(Verdict::key_list_damaged("read_failed")),
    }
}

/// The `why` of a `grant_role` whose cause is «owner on this PC» (§10.2: an owner-role key of
/// the person, or the owner by the bindings) — not a grant naming a role other than guest. Both
/// are `admit_refused:grant_role` outside; only the first is no ground on a removed key.
const OWNER_ON_PC: &str = "owner_on_pc";

/// §3.4 step 8, §10 «Повтор основания для удалённого ключа»: the one list of refusals that are no
/// ground on a key with a removed record — any refusal of an `endorse`; of a `grant`, the paper
/// already used or its author not an active owner (`grant_spent`, `invite_spent`,
/// `grant_not_owner`) and `grant_role` for «owner on this PC» ([`OWNER_ON_PC`]). Such a refusal
/// is never the offer's reason (the next ground is tried; nothing else → `key_revoked`), at the
/// check and at the write alike. Every other grant refusal keeps its reason (`grant_stale` first
/// of all); a stop stays a stop. On a key with no removed record the caller never asks.
fn no_ground_on_removed(ground: &str, fail: &Fail) -> bool {
    match (ground, fail) {
        ("endorse", Fail::Verdict(_) | Fail::Why(..)) => true,
        ("grant", Fail::Verdict(v)) => {
            v.code == "admit_refused"
                && matches!(
                    v.detail,
                    Some("grant_spent" | "invite_spent" | "grant_not_owner")
                )
        }
        // Party spec §5.2: of a party's grant, the paper used already, a signer the PC does not
        // take as the party's leader, and `grant_role` for «owner on this PC».
        ("party", Fail::Verdict(v)) => {
            v.code == "admit_refused" && matches!(v.detail, Some("grant_spent" | "party_leader"))
        }
        ("grant" | "party", Fail::Why(v, why)) => {
            v.code == "admit_refused" && v.detail == Some("grant_role") && *why == OWNER_ON_PC
        }
        _ => false,
    }
}

/// [`store_fail`] for a change refused at the queue's turn (the write decides every rule again):
/// a ground refused for a reason from the «no ground» list ([`no_ground_on_removed`]) while its
/// key has a removed record NOW — removed during the check, or since — is `key_revoked`, whatever
/// the ground's own cause (kept in the debug line). Every other refusal keeps its code; a stop (a
/// damaged list, strict mode's `key_unconfirmed`) stays a stop.
fn write_refusal(
    e: &StoreError,
    ground: &'static str,
    store: Option<&TrustStore>,
    kid: &KeyId,
) -> Fail {
    let fail = store_fail(e, ground);
    let on_removed = no_ground_on_removed(ground, &fail)
        && store.is_some_and(|s| matches!(s.lookup(kid), Lookup::Removed(_)));
    if !on_removed {
        return fail;
    }
    tracing::debug!(
        kid = %kid.short(),
        ground,
        reason = e.as_str(),
        error = %e,
        "admission: the ground refused at its write for a reason from the «no ground» list, on a \
         key with a removed record now: no ground there, key_revoked"
    );
    Fail::Verdict(Verdict::KEY_REVOKED)
}

/// §10 «Одно правило возврата»: the grounds that may lift a `pc` or `server` removal — a grant
/// (with a new invitation) and an endorse (of the same person's trusted device), tried in the
/// order of `admit`; `recover` and `first_use` never lift one.
/// Party spec §5.2: a party's grant lifts only the server's removal, never one at the PC nor a
/// replacement (the leader's app would issue it back by itself).
fn lifts_a_removal(entry: &AdmitEntry, origin: &crate::viewer_keys::Origin) -> bool {
    use crate::viewer_keys::Origin;
    match entry {
        AdmitEntry::Grant { .. } | AdmitEntry::Endorse(_) => {
            matches!(origin, Origin::Pc | Origin::Server)
        }
        AdmitEntry::Party(_) => matches!(origin, Origin::Server),
        AdmitEntry::Recover(_) | AdmitEntry::FirstUse(_) => false,
    }
}

/// What the grounds of one offer share.
struct GroundCtx<'a> {
    /// For «owner on this PC» ([`Trusted::owner_on_pc`]); its list is `store`.
    trusted: &'a Trusted,
    store: &'a TrustStore,
    proof: &'a OfferProof,
    reg: Option<&'a KeyReg>,
    session_id: &'a str,
    mode: Mode,
    now_ms: u64,
}

impl Admission {
    #[allow(
        clippy::too_many_lines,
        reason = "the ten steps of §3.4 in their order, one place to read them"
    )]
    fn decide(
        &mut self,
        trusted: &Trusted,
        offer: &FirstOffer<'_>,
        sess: &Sess,
        mode: Mode,
        fp: Option<[u8; FINGERPRINT_LEN]>,
        now_ms: u64,
    ) -> (OfferDecision, Option<[u8; NONCE_PC_LEN]>) {
        let sid = offer.session_id;
        let server = &sess.server;
        let plain = |v: Verdict, kid: Option<&KeyId>| {
            (without_record(v, mode, offer.is_bound, kid, server), None)
        };
        // 1. The list reads.
        let Some(store) = trusted.store().filter(|s| !s.is_damaged()) else {
            tracing::debug!(
                session = sid,
                "admission: step 1: the list is damaged or absent"
            );
            return plain(Verdict::key_list_damaged("read_failed"), None);
        };
        // 2. A proof at all.
        let Some(proof_value) = offer.proof else {
            let v = if mode == Mode::Observe {
                Verdict::UNSIGNED
            } else if sess.had_nonce {
                Verdict::key_required("no_proof")
            } else {
                Verdict::nonce_stale("no_nonce")
            };
            // not-a-key-name: a verdict's protocol code (`.code`), never a key
            tracing::debug!(
                session = sid,
                had_nonce = sess.had_nonce,
                verdict = v.code,
                "admission: step 2: no proof"
            );
            return plain(v, None);
        };
        // The bucket: one token per offer that reaches step 3, before any parsing.
        if !self.take_bucket(now_ms) {
            return plain(Verdict::proof_invalid("busy"), None);
        }
        // 3. Parse, limits first.
        let proof = match OfferProof::parse(proof_value) {
            Ok(p) => p,
            Err(why) => {
                tracing::debug!(session = sid, why, "admission: step 3: proof malformed");
                return plain(Verdict::proof_invalid("malformed"), None);
            }
        };
        let kid = proof.key_id.clone();
        // 4. The fingerprint.
        let Some(fp) = fp else {
            tracing::debug!(session = sid, kid = %kid.short(), "admission: step 4: fp_bad");
            return plain(Verdict::proof_invalid("fp_bad"), Some(&kid));
        };
        // 5. The nonce.
        if let Err(e) = self.book.check(&proof.nonce_pc, now_ms) {
            tracing::debug!(
                session = sid,
                kid = %kid.short(),
                detail = e.detail(),
                "admission: step 5: nonce refused"
            );
            return plain(Verdict::nonce_stale(e.detail()), Some(&kid));
        }
        // 6. The verifying SPKI: the record's (active or removed), else the card's.
        let lookup = store.lookup(&kid);
        let mut reg: Option<KeyReg> = None;
        let verifying = match &lookup {
            Lookup::Active(r) | Lookup::PendingRemoval(r) => r.key.clone(),
            Lookup::Removed(t) => t.key.clone(),
            Lookup::StoreDamaged => {
                return plain(Verdict::key_list_damaged("read_failed"), Some(&kid));
            }
            Lookup::Unknown => match &proof.key_reg {
                None => {
                    tracing::debug!(
                        session = sid,
                        kid = %kid.short(),
                        "admission: step 6: unknown key, no card"
                    );
                    return plain(Verdict::KEY_UNKNOWN, Some(&kid));
                }
                Some(v) => match KeyReg::parse_verify(v) {
                    Ok(r) => {
                        let key = r.key.clone();
                        self.attempt_reg = Some(r.clone());
                        reg = Some(r);
                        key
                    }
                    Err(why) => {
                        tracing::debug!(
                            session = sid,
                            kid = %kid.short(),
                            why,
                            "admission: step 6: key card refused"
                        );
                        return plain(Verdict::admit_refused("key_reg_bad"), Some(&kid));
                    }
                },
            },
        };
        if verifying.key_id() != &kid {
            tracing::debug!(
                session = sid,
                kid = %kid.short(),
                card = %verifying.key_id().short(),
                "admission: step 6: the card is another key"
            );
            return plain(Verdict::proof_invalid("key_mismatch"), Some(&kid));
        }
        // 7. The offer's signature, with this PC's own device_id.
        if !proof.verify(&verifying, sid, &self.device_id, &fp) {
            tracing::debug!(session = sid, kid = %kid.short(), "admission: step 7: bad_sig");
            return plain(Verdict::proof_invalid("bad_sig"), Some(&kid));
        }
        tracing::debug!(
            session = sid,
            kid = %kid.short(),
            "admission: step 7: the offer's signature verifies"
        );
        // 8. The record, or the grounds.
        let mut journal = Vec::new();
        match lookup {
            Lookup::Active(r) => {
                let verdict = if r.unconfirmed {
                    Verdict::KEY_UNCONFIRMED
                } else {
                    Verdict::SIGNED
                };
                let identity = SessionIdentity {
                    telegram_user_id: r.person.telegram_user_id,
                    role: r.role,
                    first_name: r.person.first_name.clone(),
                    username: r.person.username.clone(),
                    from_record: true,
                };
                let admitted = match mode {
                    Mode::Strict => !r.unconfirmed,
                    Mode::Observe => offer.is_bound,
                };
                tracing::debug!(
                    session = sid,
                    kid = %kid.short(),
                    unconfirmed = r.unconfirmed,
                    role = r.role.as_str(),
                    admitted,
                    "admission: step 8: an active key"
                );
                if !admitted {
                    return (
                        OfferDecision {
                            mode,
                            ..refusal(verdict)
                        },
                        None,
                    );
                }
                // 9. Commit: spend the nonce, note the use.
                self.book.spend(&proof.nonce_pc, sid);
                let warn = self.mismatch(server, &identity, sid);
                let touch = AdmitOp {
                    ticket: self.ticket(),
                    op: StoreOp::Touch {
                        key_id: kid.clone(),
                    },
                };
                return (
                    OfferDecision {
                        verdict,
                        admit: None,
                        mode,
                        outcome: Outcome::Admit,
                        ks: Some(Ks {
                            kid: kid.clone(),
                            verdict,
                            admit: None,
                            mode,
                        }),
                        identity: Some(identity),
                        journal,
                        warn,
                        why: None,
                        touch: Some(touch),
                        attempts: Vec::new(),
                    },
                    Some(proof.nonce_pc),
                );
            }
            Lookup::PendingRemoval(_) => {
                tracing::debug!(session = sid, kid = %kid.short(), "admission: step 8: removal pending");
                return plain(Verdict::KEY_REVOKED, Some(&kid));
            }
            Lookup::Removed(t) => {
                // One return rule (§10): `pc` and `server` — a grant or an endorse may lift it
                // (decided with the ground: its own checks, then the person); `replaced` — only
                // a pairing at the PC. `recover` and `first_use` lift nothing.
                let lifters = proof
                    .admit
                    .iter()
                    .filter(|e| lifts_a_removal(e, &t.origin))
                    .count();
                tracing::debug!(
                    session = sid,
                    kid = %kid.short(),
                    origin = t.origin.as_str(),
                    grounds = proof.admit.len(),
                    lifters,
                    "admission: step 8: a removed key"
                );
                if lifters == 0 {
                    return plain(Verdict::KEY_REVOKED, Some(&kid));
                }
                // §10: the card must describe this same key (the SPKI stays the record's).
                let card = proof.key_reg.as_ref().map(KeyReg::parse_verify);
                let why = match card {
                    Some(Ok(r)) if r.key.key_id() == &kid => {
                        reg = Some(r);
                        None
                    }
                    Some(Ok(_)) => Some("other_key"),
                    Some(Err(why)) => Some(why),
                    None => Some("missing"),
                };
                if let Some(why) = why {
                    tracing::debug!(
                        session = sid,
                        kid = %kid.short(),
                        why,
                        "admission: step 8: a returning key needs its own valid card"
                    );
                    let (mut d, nonce) = plain(Verdict::admit_refused("key_reg_bad"), Some(&kid));
                    d.why = Some(why);
                    return (d, nonce);
                }
            }
            Lookup::Unknown => {}
            Lookup::StoreDamaged => {
                return plain(Verdict::key_list_damaged("read_failed"), Some(&kid));
            }
        }
        // The grounds, in order: the first that gives a candidate wins.
        let ctx = GroundCtx {
            trusted,
            store,
            proof: &proof,
            reg: reg.as_ref(),
            session_id: sid,
            mode,
            now_ms,
        };
        let removed_origin = match store.lookup(&kid) {
            Lookup::Removed(t) => Some(t.origin.clone()),
            _ => None,
        };
        let removed = removed_origin.is_some();
        let mut first_fail: Option<(Verdict, Option<&'static str>)> = None;
        // §3.4 step 8, §10 «Повтор основания для удалённого ключа»: on a removed key a refusal
        // from the «no ground» list ([`no_ground_on_removed`]: any endorse's; a spent or orphaned
        // grant's) is never the offer's reason.
        let mut no_grounds = 0usize;
        let mut candidate = None;
        for entry in &proof.admit {
            if removed_origin
                .as_ref()
                .is_some_and(|o| !lifts_a_removal(entry, o))
            {
                tracing::debug!(
                    session = sid,
                    kid = %kid.short(),
                    ground = entry.kind(),
                    "admission: step 8: a removed key: this ground lifts no removal, skipped"
                );
                continue;
            }
            match self.ground(&ctx, entry, &mut journal) {
                Ok(c) => {
                    candidate = Some(c);
                    break;
                }
                Err(f @ (Fail::Verdict(_) | Fail::Why(..))) => {
                    let no_ground = removed && no_ground_on_removed(entry.kind(), &f);
                    let (v, why) = match f {
                        Fail::Why(v, why) => (v, Some(why)),
                        Fail::Verdict(v) | Fail::Stop(v) => (v, None),
                    };
                    // not-a-key-name: a verdict's protocol code (`.code`), never a key
                    tracing::debug!(
                        session = sid,
                        kid = %kid.short(),
                        ground = entry.kind(),
                        verdict = v.code,
                        detail = v.detail.unwrap_or("-"),
                        why = why.unwrap_or("-"),
                        "admission: step 8: ground refused{}",
                        if no_ground {
                            " (a removed key: a refusal from the «no ground» list — any \
                             endorse's, a spent or orphaned grant's — is no ground, not the \
                             offer's reason)"
                        } else {
                            ""
                        }
                    );
                    if no_ground {
                        no_grounds += 1;
                    } else if first_fail.is_none() {
                        first_fail = Some((v, why));
                    }
                }
                Err(Fail::Stop(v)) => {
                    // not-a-key-name: a verdict's protocol code (`.code`), never a key
                    tracing::debug!(
                        session = sid,
                        kid = %kid.short(),
                        ground = entry.kind(),
                        verdict = v.code,
                        "admission: step 8: ground stops the offer"
                    );
                    let mut d = without_record(v, mode, offer.is_bound, Some(&kid), server);
                    d.journal = journal;
                    return (d, None);
                }
            }
        }
        let Some(c) = candidate else {
            // A removed key that nothing returned: the first refusal not from the «no ground»
            // list (a grant's that keeps its reason), else `key_revoked` — whatever the order in
            // `admit`.
            let (v, why) = first_fail.unwrap_or(if removed {
                (Verdict::KEY_REVOKED, None)
            } else {
                (Verdict::KEY_UNKNOWN, None)
            });
            if removed {
                // not-a-key-name: a verdict's protocol code (`.code`), never a key
                tracing::debug!(
                    session = sid,
                    kid = %kid.short(),
                    no_grounds,
                    verdict = v.code,
                    detail = v.detail.unwrap_or("-"),
                    "admission: step 8: a removed key: nothing returns it"
                );
            }
            let mut d = without_record(v, mode, offer.is_bound, Some(&kid), server);
            d.journal = journal;
            d.why = why;
            // §10.2: another device's attempt, if any, is noted after the decision
            // (`after_decide`), on the verdict.
            return (d, None);
        };
        // 9. Commit: spend the nonce; the candidate goes to the list's queue; the session waits.
        self.book.spend(&proof.nonce_pc, sid);
        let verdict = if c.unconfirmed {
            Verdict::KEY_UNCONFIRMED
        } else {
            Verdict::SIGNED
        };
        let identity = SessionIdentity {
            telegram_user_id: c.uid,
            role: c.role,
            first_name: None,
            username: None,
            from_record: true,
        };
        let warn = self.mismatch(server, &identity, sid);
        let ks = Ks {
            kid: kid.clone(),
            verdict,
            admit: Some(c.ground),
            mode,
        };
        let ticket = self.ticket();
        self.awaiting.insert(
            ticket,
            Awaiting {
                waiting: Waiting::Offer {
                    session_id: sid.to_string(),
                    is_bound: offer.is_bound,
                    mode,
                    ks: ks.clone(),
                    by: c.by.clone(),
                },
                answered: false,
                attempt: None,
            },
        );
        tracing::debug!(
            session = sid,
            kid = %kid.short(),
            ground = c.ground,
            user_id = c.uid,
            role = c.role.as_str(),
            unconfirmed = c.unconfirmed,
            ticket,
            "admission: step 9: a candidate; the session waits for its write"
        );
        (
            OfferDecision {
                verdict,
                admit: Some(c.ground),
                mode,
                outcome: Outcome::AfterWrite(Box::new(AdmitOp { ticket, op: c.op })),
                ks: Some(ks),
                identity: Some(identity),
                journal,
                warn,
                why: None,
                touch: None,
                attempts: Vec::new(),
            },
            Some(proof.nonce_pc),
        )
    }

    /// §3.4 step 10: a signed session's person is the record's; a different word of the server
    /// is `identity_mismatch`.
    fn mismatch(
        &self,
        server: &SessionIdentity,
        record: &SessionIdentity,
        sid: &str,
    ) -> Option<&'static str> {
        (server.telegram_user_id != record.telegram_user_id).then(|| {
            tracing::warn!(
                session = sid,
                server_user_id = server.telegram_user_id,
                record_user_id = record.telegram_user_id,
                "admission: identity_mismatch: the server names another person than the key's \
                 record; the record's person and role are the session's"
            );
            "identity_mismatch"
        })
    }

    fn ground(
        &mut self,
        ctx: &GroundCtx<'_>,
        entry: &AdmitEntry,
        journal: &mut Vec<JournalEvent>,
    ) -> Result<Candidate, Fail> {
        let refused = |d| Fail::Verdict(Verdict::admit_refused(d));
        // Every ground adds the card's key: the card was checked at step 6 (or for a returning
        // key at step 8).
        let Some(reg) = ctx.reg else {
            return Err(refused("key_reg_bad"));
        };
        let new = reg.new_key();
        let kid = &ctx.proof.key_id;
        match entry {
            AdmitEntry::Endorse(v) => {
                let e = Endorse::parse(v).map_err(|why| {
                    tracing::debug!(why, "admission: endorse malformed");
                    refused("endorse_malformed")
                })?;
                if &e.key_id != kid {
                    return Err(refused("endorse_key_mismatch"));
                }
                let by_key = match ctx.store.lookup(&e.by) {
                    Lookup::Active(r) => r.key.clone(),
                    Lookup::PendingRemoval(_) | Lookup::Removed(_) => {
                        return Err(refused("endorse_signer_revoked"));
                    }
                    Lookup::Unknown => return Err(refused("endorse_signer_unknown")),
                    Lookup::StoreDamaged => {
                        return Err(Fail::Stop(Verdict::key_list_damaged("read_failed")));
                    }
                };
                let endorse_id = e.ground_id();
                if ctx
                    .store
                    .spent()
                    .is_ok_and(|(endorse, _, _)| endorse.contains(&endorse_id))
                {
                    return Err(refused("endorse_spent"));
                }
                if !e.verify(&by_key) {
                    return Err(refused("endorse_bad_sig"));
                }
                let ground = Ground::Endorse {
                    by: e.by.clone(),
                    endorse_id,
                    issued_at: e.issued_at,
                };
                let out = ctx.store.check_add(&new, &ground, 0).map_err(|err| {
                    tracing::debug!(
                        kid = %kid.short(),
                        by = %e.by.short(),
                        reason = err.as_str(),
                        error = %err,
                        "admission: the list refuses the endorse's key"
                    );
                    store_fail(&err, "endorse")
                })?;
                tracing::debug!(
                    kid = %kid.short(),
                    by = %e.by.short(),
                    user_id = out.telegram_user_id,
                    role = out.role.as_str(),
                    unconfirmed = out.unconfirmed,
                    known_person = out.known_person,
                    lifted = out.lifted.unwrap_or("-"),
                    "admission: the endorse gives a candidate{}",
                    if out.lifted.is_some() {
                        " (its write would lift the key's removal)"
                    } else {
                        ""
                    }
                );
                Ok(Candidate {
                    op: StoreOp::add(new, ground),
                    ground: "endorse",
                    uid: out.telegram_user_id,
                    role: out.role,
                    unconfirmed: out.unconfirmed,
                    by: Some(e.by),
                })
            }
            AdmitEntry::Grant { grant, invite } => self.grant(ctx, &new, grant, invite.as_ref()),
            AdmitEntry::Party(grant) => self.party(ctx, &new, grant, journal),
            AdmitEntry::Recover(m) => {
                let Some(rpk) = reg.rpk.clone() else {
                    return Err(refused("recover_malformed"));
                };
                let r = RecoverGround::parse(m).map_err(|why| {
                    tracing::debug!(why, "admission: recovery malformed");
                    refused("recover_malformed")
                })?;
                let attested = self
                    .verifier
                    .verify_attestation(&r.init_data, kid)
                    .map_err(|e| match e {
                        AttestationError::HasHash => refused("attest_has_hash"),
                        _ => refused("attest_bad"),
                    })?;
                let change = RecoverChange {
                    rpk,
                    attested: attested.clone(),
                    device_id: self.device_id.clone(),
                    session_id: ctx.session_id.to_string(),
                    nonce_pc: ctx.proof.nonce_pc,
                    rsig: r.rsig.to_vec(),
                    new_key: reg.key.clone(),
                    kind: reg.kind.clone(),
                    platform: reg.platform.clone(),
                };
                match ctx.store.check_recover(change.recovery(), 0) {
                    Ok(out) => Ok(Candidate {
                        op: StoreOp::Recover(Box::new(change)),
                        ground: "recover",
                        uid: out.telegram_user_id,
                        role: out.role,
                        unconfirmed: out.unconfirmed,
                        by: None,
                    }),
                    Err(e) => {
                        if e == StoreError::RecoverBadSig {
                            let uid = attested.user_id();
                            let due = self.recover_journal.get(&uid).is_none_or(|at| {
                                ctx.now_ms.saturating_sub(*at) >= RECOVER_ATTEMPT_MS
                            });
                            tracing::debug!(
                                user_id = uid,
                                journal = due,
                                "admission: recovery signature refused after a valid attestation"
                            );
                            if due {
                                self.recover_journal.insert(uid, ctx.now_ms);
                                journal.push(JournalEvent::RecoverAttempt {
                                    telegram_user_id: uid,
                                });
                            }
                        }
                        Err(store_fail(&e, "recover"))
                    }
                }
            }
            AdmitEntry::FirstUse(m) => {
                let uid = verify_first_use(m, &self.device_id, &reg.key).map_err(|why| {
                    tracing::debug!(why, "admission: first_use signature refused");
                    refused("first_use_bad_sig")
                })?;
                let ground = Ground::FirstUse {
                    telegram_user_id: uid,
                };
                match ctx.store.check_add(&new, &ground, 0) {
                    Ok(out) => Ok(Candidate {
                        op: StoreOp::add(new, ground),
                        ground: "first_use",
                        uid: out.telegram_user_id,
                        role: out.role,
                        unconfirmed: out.unconfirmed,
                        by: None,
                    }),
                    Err(e) => {
                        if e == StoreError::FirstUseAgain {
                            self.probe(uid, reg, ctx.now_ms, journal);
                        }
                        Err(store_fail(&e, "first_use"))
                    }
                }
            }
        }
    }

    /// §9: a `first_use_probe` at most once an hour per person and key, three a day per person.
    fn probe(&mut self, uid: i64, reg: &KeyReg, now_ms: u64, journal: &mut Vec<JournalEvent>) {
        let key = (uid, reg.key.key_id().clone());
        let per_key = self
            .probes_key
            .get(&key)
            .is_none_or(|at| now_ms.saturating_sub(*at) >= PROBE_PER_KEY_MS);
        let day = self.probes_day.entry(uid).or_default();
        while day
            .front()
            .is_some_and(|at| now_ms.saturating_sub(*at) >= DAY_MS)
        {
            day.pop_front();
        }
        let per_day = day.len() < PROBE_PER_DAY;
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            user_id = uid,
            kid = %reg.key.key_id().short(),
            per_key,
            today = day.len(),
            "admission: first_use_closed with a first_use key already: probe {}",
            if per_key && per_day { "journaled" } else { "rate-limited" }
        );
        if per_key && per_day {
            day.push_back(now_ms);
            self.probes_key.insert(key, now_ms);
            journal.push(JournalEvent::FirstUseProbe {
                telegram_user_id: uid,
                key_id: reg.key.key_id().clone(),
                kind: Some(reg.kind.as_str().to_string()),
                platform: Some(reg.platform.as_str().to_string()),
            });
        }
    }

    /// `grant` with its invitation (spec §7), in the order of grant.json.
    fn grant(
        &mut self,
        ctx: &GroundCtx<'_>,
        new: &NewKey,
        grant: &Value,
        invite: Option<&Value>,
    ) -> Result<Candidate, Fail> {
        let refused = |d| Fail::Verdict(Verdict::admit_refused(d));
        let g = Grant::parse(grant).map_err(|why| {
            tracing::debug!(why, "admission: grant malformed");
            refused("grant_malformed")
        })?;
        if g.device_id != self.device_id {
            return Err(refused("grant_device"));
        }
        if g.key_id != ctx.proof.key_id {
            return Err(refused("grant_key_mismatch"));
        }
        let owner_key = |id: &KeyId| match ctx.store.lookup(id) {
            Lookup::Active(r) if r.role == BindingRole::Owner => Some(r),
            _ => None,
        };
        let granter = owner_key(&g.by).ok_or_else(|| refused("grant_not_owner"))?;
        if g.role != "guest" {
            // A form error: keeps its reason on a removed key too (no `why`). The role is the
            // sender's text: only its length is logged.
            tracing::debug!(
                role_len = g.role.len(),
                "admission: the grant names a role other than guest: grant_role"
            );
            return Err(refused("grant_role"));
        }
        let grant_id = ground_id(&g.grant_id);
        if ctx
            .store
            .spent()
            .is_ok_and(|(_, grants, _)| grants.contains(&grant_id))
        {
            return Err(refused("grant_spent"));
        }
        // Deliberately the strict side: a grant naming a person with any owner-role record still
        // listed, working or not (`listed_owner`), is refused — that removal may yet be undone.
        // §10.2: and an owner on this PC with no such record — the owner by the bindings, keys
        // or none (a guest grant never touches the owner).
        let grantee_owner = ctx
            .store
            .person_keys(g.telegram_user_id)
            .is_ok_and(|k| !k.listed_owner.is_empty())
            || ctx.trusted.owner_on_pc(g.telegram_user_id);
        if grantee_owner {
            tracing::debug!(
                user_id = g.telegram_user_id,
                "admission: the grant's person is an owner on this PC: grant_role ({OWNER_ON_PC})"
            );
            return Err(Fail::Why(Verdict::admit_refused("grant_role"), OWNER_ON_PC));
        }
        if !g.verify(&granter.key) {
            return Err(refused("grant_bad_sig"));
        }
        // §7 «Токен выдачи»: the grant's last own check, before the invitation's — a removal the
        // PC learned of since the owner signed it replaced the token.
        if ctx.store.grant_token_current(&g.grant_token).is_err() {
            tracing::debug!(
                kid = %ctx.proof.key_id.short(),
                by = %g.by.short(),
                "admission: the grant carries another grant token than the PC's current one: \
                 grant_stale"
            );
            return Err(refused("grant_stale"));
        }
        let invite = match invite.map(InviteSig::parse) {
            None if ctx.mode == Mode::Strict => return Err(refused("invite_missing")),
            None => {
                tracing::debug!(
                    "admission: a grant without an invitation (observe): the key is unconfirmed"
                );
                None
            }
            Some(Err(why)) => {
                tracing::debug!(why, "admission: invitation malformed");
                return Err(refused("invite_missing"));
            }
            Some(Ok(inv)) => {
                let inviter = owner_key(&inv.by);
                let bad = inv.device_id != self.device_id
                    || g.inv_id != Some(inv.inv_id)
                    || inviter.is_none_or(|r| !inv.verify(&r.key));
                if bad {
                    return Err(refused("invite_bad"));
                }
                if inviter.map(|r| r.person.telegram_user_id)
                    != Some(granter.person.telegram_user_id)
                {
                    return Err(refused("invite_owner_mismatch"));
                }
                let skew = i128::from(g.issued_at) - i128::from(inv.issued_at);
                if !(INVITE_GRANT_SKEW_MS..=INVITE_GRANT_WINDOW_MS).contains(&skew) {
                    tracing::debug!(skew_ms = %skew, "admission: invitation out of the grant's window");
                    return Err(refused("invite_expired"));
                }
                Some(Invite {
                    inv_id: ground_id(&inv.inv_id),
                    by: inv.by,
                })
            }
        };
        let ground = Ground::Grant {
            by: g.by.clone(),
            grant_id,
            inv_id: g.inv_id.as_ref().map(ground_id),
            invite,
            person: Person {
                telegram_user_id: g.telegram_user_id,
                first_name: g.name.clone(),
                username: g.username.clone(),
            },
            token: g.grant_token,
        };
        let out = ctx.store.check_add(new, &ground, 0).map_err(|e| {
            tracing::debug!(
                user_id = g.telegram_user_id,
                reason = e.as_str(),
                error = %e,
                "admission: the list refuses the grant's key"
            );
            store_fail(&e, "grant")
        })?;
        tracing::debug!(
            user_id = out.telegram_user_id,
            known_guest = out.known_person,
            lifted = out.lifted.unwrap_or("-"),
            "admission: the grant gives a candidate ({})",
            if out.known_person {
                "a new device of a guest this PC has"
            } else {
                "a new guest"
            }
        );
        Ok(Candidate {
            op: StoreOp::add(new.clone(), ground),
            ground: "grant",
            uid: out.telegram_user_id,
            role: out.role,
            unconfirmed: out.unconfirmed,
            by: Some(g.by),
        })
    }
}

impl Admission {
    // --- After the first offer --------------------------------------------------------------

    /// A re-offer in a live session (spec §3.5): checked before `Renegotiate`. On `End`, end the
    /// session with that verdict (and call [`Self::session_ended`]).
    pub fn reoffer(&self, session_id: &str, sdp: &str, proof: Option<&Value>) -> Reoffer {
        let Some(s) = self.sessions.get(session_id) else {
            tracing::warn!(
                session = session_id,
                "admission: a re-offer of an unknown session"
            );
            return Reoffer::End(Verdict::FINGERPRINT_CHANGED);
        };
        let fp = viewer_fingerprint(sdp).ok();
        if fp.is_none() || fp != s.fp {
            tracing::debug!(
                session = session_id,
                usable = fp.is_some(),
                remembered = s.fp.is_some(),
                "admission: re-offer: the fingerprint is not the session's; fingerprint_changed"
            );
            return Reoffer::End(Verdict::FINGERPRINT_CHANGED);
        }
        match (&s.signed, proof) {
            (Some(signed), Some(p)) => {
                let same = OfferProof::parse(p)
                    .is_ok_and(|p| p.key_id == signed.key_id && p.nonce_pc == signed.nonce_pc);
                if !same {
                    tracing::debug!(
                        session = session_id,
                        kid = %signed.key_id.short(),
                        "admission: re-offer: another proof in a signed session; proof_mismatch"
                    );
                    return Reoffer::End(Verdict::proof_invalid("proof_mismatch"));
                }
            }
            (None, Some(_)) => tracing::debug!(
                session = session_id,
                "admission: re-offer: a proof in an unsigned session is ignored"
            ),
            _ => {}
        }
        tracing::debug!(session = session_id, "admission: re-offer: continue");
        Reoffer::Continue
    }

    /// The session's state: `(signed, verdict, identity)`.
    pub fn session(&self, session_id: &str) -> Option<(bool, Verdict, &SessionIdentity)> {
        self.sessions
            .get(session_id)
            .map(|s| (s.signed.is_some(), s.verdict, &s.identity))
    }

    /// An admission change ended ([`Trusted::take_landed`]). For a first offer that waited for
    /// it: the session's final verdict, `ks`, key and identity come from **what landed** — the
    /// record's `unconfirmed`, person and role, or the store's refusal at the queue's turn — never
    /// from the offer's guess (§3.4 step 9). A session ended meanwhile gets no answer.
    /// Whether `ticket` is a pairing's key write still waited for (a «Разрешить» press,
    /// or `pc_allow`'s `binding_added`) — asked before [`Self::landed`] takes it.
    pub fn is_pair_write(&self, ticket: u64) -> bool {
        self.awaiting
            .get(&ticket)
            .is_some_and(|aw| matches!(aw.waiting, Waiting::Pair))
    }

    pub fn landed(&mut self, trusted: &mut Trusted, landed: Landed) -> LandedDecision {
        let mut out = LandedDecision::default();
        let Landed {
            ticket,
            slow,
            result,
        } = landed;
        let Some(aw) = self.awaiting.get_mut(&ticket) else {
            tracing::debug!(
                ticket,
                "admission: a landed change nobody waits for (a touch)"
            );
            return out;
        };
        if slow {
            if let (Waiting::Offer { session_id, .. }, false) = (&aw.waiting, aw.answered) {
                aw.answered = true;
                let sid = session_id.clone();
                if self.waits_for(&sid, ticket) {
                    self.sessions.remove(&sid);
                    tracing::warn!(
                        session = %sid,
                        ticket,
                        "admission: the key's write outlived its limit; the session is refused \
                         key_list_damaged:write_failed (the write lands later)"
                    );
                    out.session = Some((sid, false, Verdict::key_list_damaged("write_failed")));
                    self.sync(trusted);
                } else {
                    tracing::debug!(
                        session = %sid,
                        ticket,
                        "admission: the key's write outlived its limit; its session is gone \
                         already (nothing to answer)"
                    );
                }
            }
            return out;
        }
        let Some(aw) = self.awaiting.remove(&ticket) else {
            return out;
        };
        let ground = match &aw.waiting {
            Waiting::Offer { ks, .. } => ks.admit.unwrap_or("pair"),
            Waiting::Pair => "pair",
        };
        // What landed: the key's record (`key_id`, person, role, unconfirmed), if any.
        let mut landed_key: Option<(KeyId, i64, BindingRole, bool)> = None;
        match &result {
            Ok(outcome) => {
                let by = match &aw.waiting {
                    Waiting::Offer { by, .. } => by.clone(),
                    Waiting::Pair => None,
                };
                match outcome {
                    LandedOutcome::Added(a) => {
                        let guest_new_device =
                            (ground == "grant" || ground == "party") && a.known_person;
                        tracing::debug!(
                            ticket,
                            kid = %a.key_id.short(),
                            ground,
                            user_id = a.telegram_user_id,
                            unconfirmed = a.unconfirmed,
                            guest_new_device,
                            "admission: a key landed; journal {}",
                            if guest_new_device {
                                "a known guest's new device"
                            } else {
                                "a new key"
                            }
                        );
                        out.journal.push(JournalEvent::KeyAdded {
                            ground,
                            key_id: a.key_id.clone(),
                            telegram_user_id: a.telegram_user_id,
                            role: a.role,
                            unconfirmed: a.unconfirmed,
                            by,
                            guest_new_device,
                        });
                        if matches!(aw.waiting, Waiting::Pair) {
                            out.pair_key = Some((a.key_id.clone(), a.unconfirmed, !a.rpk_dropped));
                        }
                        landed_key =
                            Some((a.key_id.clone(), a.telegram_user_id, a.role, a.unconfirmed));
                    }
                    LandedOutcome::Recovered(r) => {
                        out.journal.push(JournalEvent::KeyReplaced {
                            key_id: r.new_key_id.clone(),
                            telegram_user_id: r.telegram_user_id,
                            replaced: r.replaced.clone(),
                        });
                        out.end_sessions = self.keys_removed(trusted, &r.replaced);
                        landed_key = Some((
                            r.new_key_id.clone(),
                            r.telegram_user_id,
                            r.role,
                            r.unconfirmed,
                        ));
                    }
                    LandedOutcome::Unit => {}
                }
            }
            Err(e) => tracing::debug!(
                ticket,
                reason = e.as_str(),
                "admission: the key's change was not installed ({e})"
            ),
        }
        if let (Some(held), Err(e)) = (&aw.attempt, &result) {
            self.held_attempt_landed(&mut out, trusted, held, e, ground);
        }
        if let (
            Waiting::Offer {
                session_id,
                is_bound,
                mode,
                ks,
                ..
            },
            false,
        ) = (&aw.waiting, aw.answered)
        {
            if self.waits_for(session_id, ticket) {
                self.offer_landed(
                    &mut out,
                    trusted,
                    session_id,
                    (*mode, *is_bound),
                    ks,
                    landed_key,
                    result.as_ref().err(),
                );
            } else {
                tracing::debug!(
                    session = %session_id,
                    ticket,
                    known = self.sessions.contains_key(session_id),
                    "admission: the key's change landed after its session ended (or for an \
                     earlier session of the same id); nothing to answer (the key's own events \
                     stand)"
                );
            }
        }
        self.sync(trusted);
        out
    }

    /// §10.2: an offer's key refused at the queue's turn (`error`) is another device's
    /// attempt as a refusal at the decision is — when the list's rule refused it and the refusal
    /// counts ([`counts_as_attempt`]); a failed write or a key active meanwhile is none. Noted, the notes queued for a write, a new one journaled (`out.attempts`).
    fn held_attempt_landed(
        &mut self,
        out: &mut LandedDecision,
        trusted: &mut Trusted,
        held: &HeldAttempt,
        error: &StoreError,
        ground: &'static str,
    ) {
        let refusal = write_refusal(error, ground, trusted.store(), held.draft.key_id());
        let verdict = match (error, refusal) {
            (StoreError::AlreadyActive(_), _) | (_, Fail::Stop(_)) => None,
            (_, Fail::Verdict(v) | Fail::Why(v, _)) => Some(v),
        };
        let counts = verdict.is_some_and(counts_as_attempt);
        // not-a-key-name: `kid` (a device key's short id) and a verdict's protocol code (`.code`)
        tracing::debug!(
            user_id = held.draft.telegram_user_id,
            kid = %held.draft.key_id().short(),
            reason = error.as_str(),
            verdict = verdict.map_or("-", |v| v.code),
            detail = verdict.and_then(|v| v.detail).unwrap_or("-"),
            counts,
            "admission: the held attempt's key refused at the queue's turn: {}",
            if counts { "another device's attempt" } else { "no attempt" }
        );
        let Some(v) = verdict.filter(|_| counts) else {
            return;
        };
        let attempt = self.note_device_attempt(trusted, held.draft.clone(), v);
        self.queue_notes(trusted, "an attempt refused at the queue's turn");
        out.attempts
            .extend(attempt.and_then(|a| self.journal_bound(a, held.now_ms)));
    }

    /// The session that waited for a landed change, still known: its final result.
    #[allow(
        clippy::too_many_arguments,
        reason = "one waiting session's parts, read once from its entry"
    )]
    fn offer_landed(
        &mut self,
        out: &mut LandedDecision,
        trusted: &Trusted,
        session_id: &str,
        (mode, is_bound): (Mode, bool),
        ks: &Ks,
        landed_key: Option<(KeyId, i64, BindingRole, bool)>,
        error: Option<&StoreError>,
    ) {
        // §10: decided on the state after the last wait — the mode as it is now (a switch to
        // strict meanwhile admits nothing).
        let decided_in = mode;
        let mode = mode_of(trusted.store());
        if mode != decided_in {
            tracing::debug!(
                session = session_id,
                decided_in = decided_in.as_str(),
                now = mode.as_str(),
                "admission: the mode changed while the key's change was queued; decided on the \
                 mode now"
            );
        }
        // §10: the key became active meanwhile (another ground, «Разрешить»): no second record —
        // the existing one decides, as step 8 would; the ground is not used (nothing spent).
        let existing = match error {
            Some(StoreError::AlreadyActive(k)) if *k == ks.kid => trusted.store().and_then(|st| {
                let Lookup::Active(r) = st.lookup(k) else {
                    return None;
                };
                Some((
                    r.key_id().clone(),
                    r.person.telegram_user_id,
                    r.role,
                    r.unconfirmed,
                ))
            }),
            _ => None,
        };
        if let Some((kid, uid, role, unconfirmed)) = existing {
            tracing::debug!(
                session = session_id,
                kid = %kid.short(),
                user_id = uid,
                unconfirmed,
                "admission: the key became active while its change was queued; the existing \
                 record decides"
            );
            return self.offer_landed(
                out,
                trusted,
                session_id,
                (mode, is_bound),
                &Ks {
                    admit: None,
                    ..ks.clone()
                },
                Some((kid, uid, role, unconfirmed)),
                None,
            );
        }
        let (verdict, admitted, record) = match (&landed_key, error) {
            (Some((kid, uid, role, unconfirmed)), _) => {
                let verdict = if *unconfirmed {
                    Verdict::KEY_UNCONFIRMED
                } else {
                    Verdict::SIGNED
                };
                // Strict never writes an unconfirmed key (the store refuses it); were one to land,
                // it would not admit.
                let admitted = match mode {
                    Mode::Strict => !*unconfirmed,
                    Mode::Observe => is_bound,
                };
                (verdict, admitted, Some((kid.clone(), *uid, *role)))
            }
            (None, Some(e)) => {
                // A rule the list decides again at the queue's turn (it changed meanwhile) is a
                // verdict; anything else is a failed write (§3.4 step 9).
                let verdict =
                    match write_refusal(e, ks.admit.unwrap_or(""), trusted.store(), &ks.kid) {
                        Fail::Verdict(v) => v,
                        Fail::Why(v, why) => {
                            out.why = Some(why);
                            v
                        }
                        Fail::Stop(v) if v.code != "key_list_damaged" => v,
                        Fail::Stop(_) => Verdict::key_list_damaged("write_failed"),
                    };
                let admitted =
                    verdict.code != "key_list_damaged" && mode == Mode::Observe && is_bound;
                (verdict, admitted, None)
            }
            (None, None) => {
                tracing::warn!(
                    session = session_id,
                    "admission: a waiting session's change landed with no key; refused \
                     key_list_damaged:write_failed"
                );
                (Verdict::key_list_damaged("write_failed"), false, None)
            }
        };
        if !admitted {
            self.sessions.remove(session_id);
            let reason = end_reason(verdict, mode);
            // not-a-key-name: a verdict's protocol code (`.code`), never a key
            tracing::debug!(
                session = session_id,
                verdict = verdict.code,
                reason = reason.code,
                detail = reason.detail.unwrap_or("-"),
                mode = mode.as_str(),
                "admission: the key's change landed; the session is refused"
            );
            out.session = Some((session_id.to_string(), false, reason));
            return;
        }
        let Some(s) = self.sessions.get_mut(session_id) else {
            return;
        };
        s.live = true;
        s.verdict = verdict;
        match &record {
            Some((kid, uid, role)) => {
                let names = trusted.store().and_then(|st| st.listed(kid)).map(|l| {
                    (
                        l.record.person.first_name.clone(),
                        l.record.person.username.clone(),
                    )
                });
                let (first_name, username) = names.unwrap_or((None, None));
                s.identity = SessionIdentity {
                    telegram_user_id: *uid,
                    role: *role,
                    first_name,
                    username,
                    from_record: true,
                };
                if let Some(signed) = &mut s.signed {
                    signed.key_id = kid.clone();
                }
                out.kid = Some(kid.clone());
                out.ks = Some(Ks {
                    kid: kid.clone(),
                    verdict,
                    admit: ks.admit,
                    mode,
                });
            }
            None => {
                // Observe admitted it by the binding; the key is not in the list: the server's
                // word, and the viewer hears the refusal's verdict (no key of its signs here).
                s.signed = None;
                s.identity = s.server.clone();
                out.ks = Some(Ks {
                    kid: ks.kid.clone(),
                    verdict,
                    admit: None,
                    mode,
                });
            }
        }
        s.counts = !(s.verdict == Verdict::SIGNED
            && s.identity.role == BindingRole::Owner
            && s.identity.from_record);
        // not-a-key-name: a verdict's protocol code (`.code`), never a key
        tracing::debug!(
            session = session_id,
            verdict = verdict.code,
            detail = verdict.detail.unwrap_or("-"),
            keyed = record.is_some(),
            user_id = s.identity.telegram_user_id,
            role = s.identity.role.as_str(),
            counts = s.counts,
            mode = mode.as_str(),
            "admission: the key's change landed; the session goes on with the final result"
        );
        out.identity = Some(s.identity.clone());
        out.session = Some((session_id.to_string(), true, verdict));
    }

    /// Keys left the list (removed at the PC or by the server, replaced by a recovery): the
    /// sessions they signed end `key_revoked`.
    pub fn keys_removed(&mut self, trusted: &mut Trusted, key_ids: &[KeyId]) -> Vec<EndSession> {
        let ending: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.signed
                    .as_ref()
                    .is_some_and(|g| key_ids.contains(&g.key_id))
            })
            .map(|(id, _)| id.clone())
            .collect();
        let mut out = Vec::new();
        for id in ending {
            self.sessions.remove(&id);
            tracing::debug!(session = %id, "admission: the session's key was removed; ending it");
            out.push(EndSession {
                session_id: id,
                verdict: Verdict::KEY_REVOKED,
            });
        }
        out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        self.sync(trusted);
        out
    }

    /// The PC's switch changed (after the store installed it). Turning strict mode on ends every
    /// session whose verdict is not `signed` (spec §10): `key_unconfirmed` for a session of an
    /// unconfirmed key, `key_required` for any other; then every Pending request (a
    /// `session_request` with no offer yet), `key_required` — its offer would be decided in strict
    /// mode, but meanwhile it holds the trust windows (§3.4). Sessions first, then the requests,
    /// each by id.
    pub fn mode_changed(&mut self, trusted: &mut Trusted, strict: bool) -> Vec<EndSession> {
        let mut out = Vec::new();
        let mut pending = Vec::new();
        if strict {
            let ending: Vec<(String, Verdict, bool)> = self
                .sessions
                .iter()
                .filter(|(_, s)| !s.had_offer || s.verdict != Verdict::SIGNED)
                .map(|(id, s)| {
                    // `key_required` has one detail in the contract (`no_proof`): a Pending
                    // request has given none either.
                    let v = if s.had_offer && s.verdict == Verdict::KEY_UNCONFIRMED {
                        Verdict::KEY_UNCONFIRMED
                    } else {
                        Verdict::key_required("no_proof")
                    };
                    (id.clone(), v, s.had_offer)
                })
                .collect();
            for (id, verdict, had_offer) in ending {
                self.sessions.remove(&id);
                let e = EndSession {
                    session_id: id,
                    verdict,
                };
                if had_offer {
                    out.push(e);
                } else {
                    pending.push(e);
                }
            }
            out.sort_by(|a, b| a.session_id.cmp(&b.session_id));
            pending.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        }
        tracing::debug!(
            strict,
            ended = out.len(),
            pending_ended = pending.len(),
            "admission: the PC's switch changed{}",
            if pending.is_empty() {
                ""
            } else {
                "; Pending requests end key_required"
            }
        );
        out.extend(pending);
        self.sync(trusted);
        out
    }

    /// `owner_changed` from the server (§10): the binding roles are rewritten
    /// ([`role_after_owner_changed`]: the account named is the owner, every other a guest; `None`
    /// — the PC has no owner) and their owners told to the trust list. Sessions: it moves only
    /// those without a key record (unsigned, observe mode); a signed session keeps its record's
    /// role (§3.4 step 10). Every session's role after it.
    pub fn owner_changed(
        &mut self,
        trusted: &mut Trusted,
        owner: Option<i64>,
    ) -> Vec<(String, BindingRole)> {
        let mut moved = 0usize;
        for (uid, role) in &mut self.bindings {
            let now = role_after_owner_changed(*uid, owner);
            if now != *role {
                moved += 1;
                *role = now;
            }
        }
        tracing::debug!(
            owner = owner.unwrap_or(0),
            moved,
            bound = self.bindings.len(),
            "admission: owner_changed rewrites the binding roles ({})",
            if owner.is_some() {
                "the account named is the owner, every other a guest"
            } else {
                "no owner: every binding a guest"
            }
        );
        self.tell_owners(trusted);
        let mut out = Vec::new();
        for (id, s) in &mut self.sessions {
            if !s.identity.from_record {
                let role = role_after_owner_changed(s.identity.telegram_user_id, owner);
                if role != s.identity.role {
                    tracing::debug!(
                        session = %id,
                        role = role.as_str(),
                        "admission: owner_changed moves an unsigned session's role"
                    );
                }
                s.identity.role = role;
                s.server.role = role;
            }
            out.push((id.clone(), s.identity.role));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Whether remote input of `session_id` may reach `control` (spec §3.4 «Органы доверия»):
    /// only a live session signed by a confirmed owner key; the switch and the list also only
    /// while no other session counts against the window.
    pub fn remote_input(&self, session_id: &str, control: TrustControl) -> bool {
        let exempt = self
            .sessions
            .get(session_id)
            .is_some_and(|s| s.live && !s.counts);
        let clean = self.counting() == 0;
        let accepted = match control {
            TrustControl::PairingPanel | TrustControl::PairAllow => exempt,
            TrustControl::StrictToggle | TrustControl::ListEdit => exempt && clean,
        };
        tracing::debug!(
            session = session_id,
            control = ?control,
            exempt,
            clean,
            accepted,
            "admission: remote input to a trust control"
        );
        accepted
    }

    // --- Pairing at the PC (§5) ----------------------------------------------------------------

    /// The pairing panel opened (it records the window token) or closed.
    pub fn pairing_panel(&mut self, trusted: &Trusted, open: bool) {
        self.panel = open.then(|| (trusted.window_token(), false));
        tracing::debug!(
            open,
            token = trusted.window_token(),
            clean = trusted.counting() == 0,
            "admission: pairing panel"
        );
    }

    /// A `pair_request` (§5). Every request is kept by its id with its person, with or without a
    /// key, until its answer, a cancel or [`PAIR_WAIT`]: «Разрешить» on it still binds the person.
    /// Its key is taken only while the panel is open, one per opening. The first under an id
    /// wins: a repeat while it waits (the server repeats waiting requests on reconnect) changes
    /// nothing — neither its person nor its key (or its lack of one) — and answers `absent`,
    /// `ignored_no_panel` or `ignored_window_used` as usual, else `ignored_repeat`: its key is not
    /// taken and spends no window.
    pub fn pair_request(&mut self, req: &PairRequest<'_>) -> ViewerKeyOutcome {
        let now = Instant::now();
        self.expire_pairs(now);
        let first = self
            .pairs
            .get(req.request_id)
            .map(|w| (w.person.telegram_user_id, w.key.is_some()));
        let mut taken: Option<PairKey> = None;
        let outcome = match (req.viewer_key, &mut self.panel) {
            (None, _) => ViewerKeyOutcome::Absent,
            (Some(_), None) => ViewerKeyOutcome::IgnoredNoPanel,
            (Some(_), Some((_, true))) => ViewerKeyOutcome::IgnoredWindowUsed,
            (Some(_), Some(_)) if first.is_some() => ViewerKeyOutcome::IgnoredRepeat,
            (Some(v), Some((token, window_taken))) => {
                let size = crate::viewer_keys::proof::compact_len(v);
                let reg = if size > MAX_VIEWER_KEY_BYTES {
                    Err("size")
                } else {
                    KeyReg::parse_verify(v)
                };
                match reg {
                    Ok(reg) => {
                        *window_taken = true;
                        taken = Some(PairKey {
                            reg,
                            person: Person {
                                telegram_user_id: req.telegram_user_id,
                                first_name: req.first_name.map(str::to_string),
                                username: req.username.map(str::to_string),
                            },
                            token: *token,
                            until: None,
                        });
                        ViewerKeyOutcome::Accepted
                    }
                    Err(why) => {
                        tracing::debug!(why, "admission: pair_request: viewer_key refused");
                        ViewerKeyOutcome::Invalid
                    }
                }
            }
        };
        if let Some((first_user_id, first_key)) = first {
            if outcome == ViewerKeyOutcome::IgnoredRepeat {
                tracing::debug!(
                    request = req.request_id,
                    first_user_id,
                    user_id = req.telegram_user_id,
                    first_key,
                    "admission: pair_request: viewer_key ignored: repeat (the first wins)"
                );
            } else {
                tracing::debug!(
                    request = req.request_id,
                    first_user_id,
                    user_id = req.telegram_user_id,
                    first_key,
                    viewer_key = outcome.as_str(),
                    "admission: pair_request again under a waiting id: nothing changes (the first \
                     wins)"
                );
            }
            return outcome;
        }
        if self.pairs.len() >= PAIR_WAITING_MAX {
            // Never the request on screen.
            let shown = self.pair_shown.as_deref();
            let oldest = self
                .pairs
                .iter()
                .filter(|(id, _)| Some(id.as_str()) != shown)
                .min_by_key(|(_, w)| w.seq)
                .map(|(id, w)| (id.clone(), w.key.is_some()));
            if let Some((id, had_key)) = oldest {
                self.pairs.remove(&id);
                tracing::debug!(
                    request = %id,
                    had_key,
                    max = PAIR_WAITING_MAX,
                    shown = shown.unwrap_or("-"),
                    "admission: waiting pair_requests at their bound: the first that came (not \
                     the one on screen) is forgotten"
                );
            }
        }
        self.pair_seq += 1;
        self.pairs.insert(
            req.request_id.to_string(),
            PairWait {
                person: Person {
                    telegram_user_id: req.telegram_user_id,
                    first_name: req.first_name.map(str::to_string),
                    username: req.username.map(str::to_string),
                },
                key: taken,
                seq: self.pair_seq,
                until: now.checked_add(PAIR_WAIT).unwrap_or(now),
            },
        );
        tracing::debug!(
            request = req.request_id,
            user_id = req.telegram_user_id,
            viewer_key = outcome.as_str(),
            waiting = self.pairs.len(),
            "admission: pair_request"
        );
        outcome
    }

    /// The request on screen (the orchestrator's `pending_pair`), never forgotten at
    /// [`PAIR_WAITING_MAX`].
    pub fn pair_shown(&mut self, request_id: Option<&str>) {
        if self.pair_shown.as_deref() != request_id {
            tracing::debug!(
                request = request_id.unwrap_or("-"),
                was = self.pair_shown.as_deref().unwrap_or("-"),
                "admission: the request on screen (kept at the waiting bound)"
            );
            self.pair_shown = request_id.map(str::to_string);
        }
    }

    /// Whether `request_id` still waits for its answer (not answered, cancelled, past
    /// [`PAIR_WAIT`] or forgotten at [`PAIR_WAITING_MAX`]). An answer for one that does not is
    /// refused: nothing goes to the server.
    pub fn pair_still_waiting(&mut self, request_id: &str) -> bool {
        self.expire_pairs(Instant::now());
        let waiting = self.pairs.contains_key(request_id);
        tracing::debug!(
            request = request_id,
            waiting,
            shown = self.pair_shown.as_deref().unwrap_or("-"),
            "admission: an answer: {}",
            if waiting {
                "the request waits"
            } else {
                "no such request waits (answered, cancelled, expired or forgotten at the bound)"
            }
        );
        #[cfg(test)]
        if self.lapse_after_guard {
            if let Some(w) = self.pairs.get_mut(request_id) {
                w.until = Instant::now();
            }
        }
        waiting
    }

    /// Whether a `pair_request` under `request_id` now repeats one that still waits (§5:
    /// the server re-sends waiting requests on a reconnect) — those past [`PAIR_WAIT`] forgotten
    /// first, as [`Self::pair_request`] does. Asked before it.
    pub fn pair_repeat(&mut self, request_id: &str) -> bool {
        self.expire_pairs(Instant::now());
        let repeat = self.pairs.contains_key(request_id);
        tracing::debug!(
            request = request_id,
            repeat,
            "admission: pair_request: {}",
            if repeat {
                "a repeat of a request that still waits"
            } else {
                "no request under this id waits (new, or the earlier one ended)"
            }
        );
        repeat
    }

    /// The person and the key a waiting `pair_request` holds (§5: the first under its id): what
    /// «Разрешить» on it decides by. `None` when no such request waits.
    /// What «Разрешить» on `request_id` would write now ([`PairPlan`]), `role` the role it
    /// gives; `None` when no such request waits (the press then sends nothing).
    pub fn pair_plan(
        &self,
        trusted: &Trusted,
        request_id: &str,
        role: BindingRole,
        via_pc_allow: bool,
    ) -> Option<PairPlan> {
        let waiting = self.pairs.get(request_id)?;
        Some(Self::plan_key(
            trusted,
            waiting.person.telegram_user_id,
            waiting.key.as_ref(),
            role,
            via_pc_allow,
        ))
    }

    /// The one reading of what a pairing's key does on «Разрешить»: the press
    /// ([`Self::pair_allow`], [`Self::pair_key`]'s own check is this same `check_add`) and the
    /// window ([`Self::pair_plan`]) both take it. `person`: the request's (the first under its id).
    fn plan_key(
        trusted: &Trusted,
        person: i64,
        key: Option<&PairKey>,
        role: BindingRole,
        via_pc_allow: bool,
    ) -> PairPlan {
        // §5: a press naming another role than the one the PC derives for the PERSON changes
        // nothing — with a key or without one, `pc_allow` included ([`press_role`]).
        if press_role(trusted, person, via_pc_allow).is_some_and(|derived| derived != role) {
            return PairPlan::Role;
        }
        let Some(key) = key else {
            return PairPlan::NoKey;
        };
        if via_pc_allow {
            // §5: an owner on this PC never gets a guest key, which `BindingAdded` would give.
            if trusted.owner_on_pc(person) {
                return PairPlan::OwnerPcAllow;
            }
            let (role, unconfirmed) = PC_ALLOW_ADD;
            let lands = trusted
                .store()
                .map_or(KeyLanding::Refused(KeyRefusal::Unavailable), |s| {
                    key_landing(s, key, role, unconfirmed)
                });
            return PairPlan::PcAllow { lands };
        }
        let Some(store) = trusted.store() else {
            return PairPlan::Refused {
                tainted: false,
                cause: KeyRefusal::Unavailable,
            };
        };
        let unconfirmed = !trusted.window_clean(key.token);
        match key_landing(store, key, role, unconfirmed) {
            KeyLanding::Writes => PairPlan::Writes { unconfirmed },
            // The key is this same person's (another person's is `OtherPerson`) and the owner's
            // lift of his own guest-role record is a write: it admits as its record does.
            KeyLanding::Already { works } => PairPlan::Already { works },
            KeyLanding::Refused(cause) => PairPlan::Refused {
                tainted: unconfirmed,
                cause,
            },
        }
    }

    pub fn pair_waiting(&self, request_id: &str) -> Option<(&Person, Option<&KeyReg>)> {
        self.pairs
            .get(request_id)
            .map(|w| (&w.person, w.key.as_ref().map(|k| &k.reg)))
    }

    /// Forget waiting `pair_request`s past [`PAIR_WAIT`].
    fn expire_pairs(&mut self, now: Instant) {
        self.pairs.retain(|id, w| {
            let keep = now < w.until;
            if !keep {
                // not-a-key-name: `had_key`, a viewer device key held or not, never a keyboard key
                tracing::debug!(
                    request = %id,
                    user_id = w.person.telegram_user_id,
                    had_key = w.key.is_some(),
                    "admission: a pair_request waited past its bound with no answer; forgotten"
                );
            }
            keep
        });
    }

    /// A pairing request ended without «Разрешить» (cancelled, refused, expired): it is
    /// forgotten with its key, and so is a `pc_allow` key waiting for `BindingAdded`.
    pub fn pair_cancelled(&mut self, request_id: &str) {
        let had_request = self.pairs.remove(request_id);
        let had_pc_allow = self.pc_allow.remove(request_id).is_some();
        // Whether the request held a device's card (its viewer key and key_reg).
        let had_card = had_request.as_ref().is_some_and(|w| w.key.is_some());
        tracing::debug!(
            request = request_id,
            was_waiting = had_request.is_some(),
            had_card,
            had_pc_allow,
            "admission: pairing request ended"
        );
    }

    /// «Разрешить» at the PC (`pair_response`), or `pc_allow` (a non-owner's session asked the
    /// owner): the request's key, if it had one. `shown_user_id`: the person the window shows for
    /// it (the engine's own record of the request decides). `second_step`: the owner's
    /// «Это моё устройство» (§5).
    pub fn pair_allow(
        &mut self,
        trusted: &Trusted,
        request_id: &str,
        shown_user_id: Option<i64>,
        role: BindingRole,
        via_pc_allow: bool,
        second_step: bool,
    ) -> PairAllowDecision {
        self.expire_pairs(Instant::now());
        let first_user_id = self
            .pairs
            .get(request_id)
            .map(|w| w.person.telegram_user_id);
        if let (Some(first), Some(shown)) = (first_user_id, shown_user_id) {
            if first != shown {
                tracing::warn!(
                    request = request_id,
                    first_user_id = first,
                    shown_user_id = shown,
                    "admission: allow: the window shows another person than the request's first; \
                     the request's own decides"
                );
            }
        }
        // §5: the press names the role the window showed. Derived otherwise now — read first, as
        // the steps below are the derived role's — nothing changes: no key, no answer, the
        // request still waits and the window reads the role again.
        // The role is the person's: checked with a key or without one, `pc_allow` included. The
        // plan is read once for the press: nothing below changes its inputs.
        let plan = self.pairs.get(request_id).map(|w| {
            Self::plan_key(
                trusted,
                w.person.telegram_user_id,
                w.key.as_ref(),
                role,
                via_pc_allow,
            )
        });
        let role_moved = (plan == Some(PairPlan::Role))
            .then(|| self.pairs.get(request_id))
            .flatten()
            .map(|w| w.key.as_ref().map(|k| k.reg.key.key_id().clone()));
        if let Some(kid) = role_moved {
            let derived = first_user_id.and_then(|uid| press_role(trusted, uid, via_pc_allow));
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                request = request_id,
                kid = %kid.as_ref().map_or("-", |k| k.short()),
                derived = derived.map_or("-", BindingRole::as_str),
                pressed = role.as_str(),
                via_pc_allow,
                "admission: allow refused role: the press names another role than the one \
                 derived for the person; nothing changes, the request still waits"
            );
            return PairAllowDecision {
                key_id: kid,
                role_refused: true,
                ..PairAllowDecision::default()
            };
        }
        // §5: an owner on this PC gets his key only with the explicit second step
        // «Это моё устройство» ([`needs_owner_step`]). Without it nothing changes.
        let owner_step = first_user_id
            .zip(plan)
            .is_some_and(|(uid, plan)| needs_owner_step(trusted, uid, plan));
        if owner_step && !second_step {
            tracing::debug!(
                request = request_id,
                "admission: allow: an owner on this PC without the second step «Это моё \
                 устройство»: nothing changes, the request still waits"
            );
            return PairAllowDecision {
                second_step_required: true,
                ..PairAllowDecision::default()
            };
        }
        let (Some(waiting), Some(plan)) = (self.pairs.remove(request_id), plan) else {
            // Never «the binding goes ahead» for a request gone (its bound may have passed
            // after the caller's guard).
            tracing::debug!(
                request = request_id,
                "admission: allow refused not_waiting: no such request waits here (answered, \
                 cancelled, expired or forgotten); no answer goes"
            );
            return PairAllowDecision {
                not_waiting: true,
                ..PairAllowDecision::default()
            };
        };
        let Some(key) = waiting.key else {
            tracing::debug!(
                request = request_id,
                user_id = waiting.person.telegram_user_id,
                "admission: allow: the request had no key; the binding goes ahead, nothing written"
            );
            return PairAllowDecision::default();
        };
        if plan == PairPlan::OwnerPcAllow {
            // §5: an owner on this PC never gets a guest key, and `BindingAdded` would
            // give one: the key is not taken; the binding goes as today.
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                request = request_id,
                kid = %key.reg.key.key_id().short(),
                "admission: pc_allow from an owner on this PC: the key is not taken (it would \
                 land a guest's); the binding goes ahead"
            );
            return PairAllowDecision::default();
        }
        if matches!(plan, PairPlan::PcAllow { .. }) {
            // §5: the key waits for the server's BindingAdded (observe only; decided there) until
            // the request's expiry, the owner's decline or `PairCancelled`.
            self.expire_pc_allow(Instant::now());
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                request = request_id,
                kid = %key.reg.key.key_id().short(),
                wait_s = PC_ALLOW_WAIT.as_secs(),
                "admission: pc_allow: the key waits for BindingAdded"
            );
            self.pc_allow.insert(
                request_id.to_string(),
                PairKey {
                    until: Instant::now().checked_add(PC_ALLOW_WAIT),
                    ..key
                },
            );
            return PairAllowDecision::default();
        }
        let unconfirmed = !trusted.window_clean(key.token);
        // Matched against the derived role just above (`plan_key`), read again at the write.
        let press = PressSeen { role: Some(role) };
        self.pair_key(trusted, key, role, unconfirmed, Some(press))
    }

    /// `BindingAdded` after `pc_allow` (§5): strict mode does not activate it, nor does the
    /// person being an owner on this PC with the binding applied (the caller applies it first:
    /// [`Self::note_binding`], or the agent's list through [`Self::set_bindings`]); observe adds
    /// it as a guest's, unconfirmed.
    pub fn binding_added(&mut self, trusted: &Trusted, telegram_user_id: i64) -> PairAllowDecision {
        self.expire_pc_allow(Instant::now());
        let Some(request_id) = self
            .pc_allow
            .iter()
            .find(|(_, k)| k.person.telegram_user_id == telegram_user_id)
            .map(|(id, _)| id.clone())
        else {
            return PairAllowDecision::default();
        };
        let Some(key) = self.pc_allow.remove(&request_id) else {
            return PairAllowDecision::default();
        };
        if mode_of(trusted.store()) == Mode::Strict {
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                user_id = telegram_user_id,
                kid = %key.reg.key.key_id().short(),
                "admission: BindingAdded after pc_allow in strict mode: the key is forgotten"
            );
            return PairAllowDecision::default();
        }
        // §5: read again here, with this binding applied (the caller applies it first): an owner
        // on this PC never gets the guest key `pc_allow` would land.
        if trusted.owner_on_pc(telegram_user_id) {
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                user_id = telegram_user_id,
                kid = %key.reg.key.key_id().short(),
                "admission: BindingAdded after pc_allow for an owner on this PC: the key is \
                 forgotten, not activated (it would land a guest's)"
            );
            return PairAllowDecision::default();
        }
        let (role, unconfirmed) = PC_ALLOW_ADD;
        self.pair_key(trusted, key, role, unconfirmed, None)
    }

    /// A binding removed (`binding_removed`): the person leaves the bindings.
    pub fn forget_binding(
        &mut self,
        trusted: &mut Trusted,
        telegram_user_id: i64,
    ) -> Option<BindingRole> {
        let was = self.bindings.remove(&telegram_user_id);
        tracing::debug!(
            user_id = telegram_user_id,
            was = was.map_or("-", BindingRole::as_str),
            "admission: a binding removed (the server's word)"
        );
        self.tell_owners(trusted);
        was
    }

    /// The owner's answer to a `pc_allow` (`owner_request_state` of kind `pc_allow`, spec §5):
    /// declined, expired, cancelled or refused — the waiting key is forgotten (`BindingAdded` after that
    /// adds nothing); pending — its expiry, when sooner than the agent's own bound, is the
    /// key's; confirmed — the key waits for `BindingAdded` as before. `request_id` names the
    /// pairing request; without one, the person's waiting keys. `expires_in`: the request's
    /// time left (pending). Call it for every such message: cheap, and expired keys go too.
    pub fn pc_allow_state(
        &mut self,
        request_id: Option<&str>,
        telegram_user_id: i64,
        state: OwnerRequestState,
        expires_in: Option<Duration>,
    ) {
        let now = Instant::now();
        self.expire_pc_allow(now);
        let ids: Vec<String> = self
            .pc_allow
            .iter()
            .filter(|(id, k)| match request_id {
                Some(r) => id.as_str() == r,
                None => k.person.telegram_user_id == telegram_user_id,
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            match state {
                OwnerRequestState::Pending | OwnerRequestState::Confirmed => {
                    let Some(k) = self.pc_allow.get_mut(&id) else {
                        continue;
                    };
                    if let Some(at) = expires_in.and_then(|d| now.checked_add(d)) {
                        if k.until.is_none_or(|u| at < u) {
                            k.until = Some(at);
                        }
                    }
                    tracing::debug!(
                        request = %id,
                        user_id = telegram_user_id,
                        state = state.as_str(),
                        left_s = k.until.map_or(0, |u| u.saturating_duration_since(now).as_secs()),
                        "admission: pc_allow: the key still waits for BindingAdded"
                    );
                }
                _ => {
                    self.pc_allow.remove(&id);
                    tracing::debug!(
                        request = %id,
                        user_id = telegram_user_id,
                        state = state.as_str(),
                        "admission: pc_allow: the owner did not allow it; the key is forgotten"
                    );
                }
            }
        }
    }

    /// Forget `pc_allow` keys past their request's expiry (§5).
    fn expire_pc_allow(&mut self, now: Instant) {
        self.pc_allow.retain(|id, k| {
            let keep = k.until.is_none_or(|u| now < u);
            if !keep {
                // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
                tracing::debug!(
                    request = %id,
                    kid = %k.reg.key.key_id().short(),
                    "admission: pc_allow: the request expired with no BindingAdded; the key is \
                     forgotten"
                );
            }
            keep
        });
    }

    /// A test's clock: every waiting `pair_request`'s expiry moved `by` earlier.
    #[cfg(test)]
    fn age_pairs(&mut self, by: Duration) {
        for w in self.pairs.values_mut() {
            w.until = w.until.checked_sub(by).unwrap_or(w.until);
        }
    }

    /// A test's clock: every waiting `pc_allow` key's expiry moved `by` earlier.
    #[cfg(test)]
    fn age_pc_allow(&mut self, by: Duration) {
        for k in self.pc_allow.values_mut() {
            k.until = k.until.and_then(|u| u.checked_sub(by));
        }
    }

    /// The key of a «Разрешить»: `press` — at the PC, what its press saw; `None` — the
    /// server's word (`pc_allow` + `BindingAdded`).
    fn pair_key(
        &mut self,
        trusted: &Trusted,
        key: PairKey,
        role: BindingRole,
        unconfirmed: bool,
        press: Option<PressSeen>,
    ) -> PairAllowDecision {
        let server_word = press.is_none();
        let kid = key.reg.key.key_id().clone();
        let mut out = PairAllowDecision {
            key_id: Some(kid.clone()),
            unconfirmed,
            ..PairAllowDecision::default()
        };
        let Some(store) = trusted.store() else {
            out.refused = Some(Verdict::key_list_damaged("read_failed"));
            return out;
        };
        let new = key.reg.new_key();
        let ground = pair_ground(&key, role, unconfirmed);
        match store.check_add(&new, &ground, 0) {
            Ok(a) => {
                if a.rpk_dropped {
                    out.warn = Some("rpk_conflict");
                }
                let ticket = self.ticket();
                self.awaiting.insert(
                    ticket,
                    Awaiting {
                        waiting: Waiting::Pair,
                        answered: false,
                        attempt: None,
                    },
                );
                tracing::debug!(
                    kid = %kid.short(),
                    role = role.as_str(),
                    unconfirmed,
                    server_word,
                    rpk_dropped = a.rpk_dropped,
                    ticket,
                    "admission: allow: the key goes to the list"
                );
                out.op = Some(AdmitOp {
                    ticket,
                    op: match press {
                        None => StoreOp::add_on_server_word(new, ground),
                        Some(p) => StoreOp::add_at_press(new, ground, p),
                    },
                });
            }
            Err(StoreError::OtherPerson(_)) => {
                // §5, §10.2: the key is at another person (active or removed): not written, the
                // record or tombstone untouched; the binding goes ahead as today.
                tracing::warn!(
                    kid = %kid.short(),
                    server_word,
                    "admission: allow: the key is at another person; not written (key_other_person)"
                );
                out.warn = Some("key_other_person");
            }
            Err(StoreError::AlreadyActive(_)) => {
                // Another person's key is `OtherPerson` above: this is the person's own record,
                // which admits (or not) as it stands; nothing is written, the binding goes ahead.
                tracing::debug!(
                    kid = %kid.short(),
                    server_word,
                    "admission: allow: the key is this person's listed record already; not written"
                );
            }
            Err(e) => {
                let v = match store_fail(&e, "pair") {
                    Fail::Verdict(v) | Fail::Why(v, _) | Fail::Stop(v) => v,
                };
                // not-a-key-name: a verdict's protocol code (`.code`), never a key
                tracing::debug!(
                    kid = %kid.short(),
                    reason = e.as_str(),
                    error = %e,
                    verdict = v.code,
                    "admission: allow: the key is not written"
                );
                out.refused = Some(v);
            }
        }
        out
    }

    /// The `first_use` snapshot (§9) from the first `agent_ready`'s bindings, for
    /// [`Trusted::admit`] (the store takes it once).
    pub fn first_use_snapshot(&mut self, people: Vec<SnapshotPerson>) -> AdmitOp {
        AdmitOp {
            ticket: self.ticket(),
            op: StoreOp::FirstUseSnapshot { people },
        }
    }
}
