//! The PC's trusted devices on the orchestrator's main loop: the one [`TrustStore`] of the process,
//! its change queue, the read-only view the window reads, and the window token (protocol spec
//! §3.4 «Органы доверия», §10, §10.1, §14; design §3.2).
//!
//! # The queue
//!
//! Every change goes through the store's three steps (`crate::viewer_keys`, «Saving: stage, write,
//! install»): staged here, synchronously, on the main loop; written on the blocking pool
//! ([`WRITE_LIMIT`] to answer); installed (or abandoned) back here when the write's result comes in
//! as an internal event ([`TrustedDone`], through the session-signal channel of the orchestrator).
//!
//! - **One change in flight**; the rest wait in order (a removal's own change queues ahead of
//!   adds, switches and confirms, so it is written sooner — not what keeps it).
//! - **A removal is decided once, at the press** (§10.1 «Нажатие решает сразу»), in memory,
//!   before anything is queued: its keys are denied and carried (`deny_carried`;
//!   [`TrustStore::deny_tree_now`] for «Удалить», [`TrustStore::deny_person_tree_now`] for
//!   «Удалить человека»), so they count as removed at once. A server's removal of a guest
//!   (`UntrustGuest`) is denied and carried alike.
//! - **Every write is a snapshot of memory**: whatever change is staged, it writes the carried
//!   removals (`pending_by`) and the
//!   notes (the grant token, attempts, the stored binding list) as memory has them (`crate::viewer_keys`,
//!   «Removals do not wait»). So the first write that lands takes every removal decided before it was staged —
//!   a removal's own change is only one such write (a write of memory: «Удалить»,
//!   «Удалить человека» and a guest's untrust stage nothing else), and one that failed is
//!   superseded by the next that lands, whichever change it is.
//! - A write that outlives [`WRITE_LIMIT`] answers its caller `slow`; its handle is kept and
//!   awaited in the background, and the result is installed (or abandoned) when it lands.
//! - Retries on what the store calls retryable (`Busy`, `NeedsReopen` after a reopen,
//!   `ChangedOnDisk`, `StaleBase` after a reopen, a write error), at most [`MAX_ATTEMPTS`]; then
//!   `write_failed`. Any other refusal undenies what the removal denied (and so withdraws its
//!   carry).
//! - **A removal's write that ran out of attempts is parked** while its keys stay denied, and
//!   queued again after the next installed change and on the timer ([`PARKED_RETRY`]), so the
//!   carry always has a write to ride. The retry writes memory as it is then and decides
//!   nothing again: a later decision at the PC («Разрешить», «Подтвердить») stands over it.
//! - **A list that turns damaged loses what no write took yet** (§10 «Повреждённый список»), as
//!   a restart before the write would: the store drops its carries, upgrades and notes, and
//!   every queued or parked change but a repair (`Reopen`, `Restore`, `Reset`) is answered
//!   `damaged` and dropped. Nothing replays after the repair; the binding list's rule runs then.
//! - After each install, abandon and reopen, [`TrustStore::pending_without_removal`]: a key that
//!   joined as a descendant of a denied one — carried by the store with its root's origin as it
//!   joined, the origin memory holds for that root — gets a removal of its own with that origin.
//!   No origin of a decided removal is kept here: the store's carry is the one place.
//! - A reopen (`reopen_load`, plus the backup's check for the window) runs on the blocking pool too.
//!
//! What admission adds later fits here as more [`OpKind`]s (an add on a ground, a recovery, a touch,
//! the `first_use` snapshot): the queue, the retries and the view do not change.
//!
//! # The binding list's rule (§10 «Сверка со списком сервера: одно правило»)
//!
//! A person the PC knows (keys, removed keys, attempts, or the stored last binding list), whom the
//! current list does not name and who holds no working owner-role key, keeps no undecided
//! guest-role key; the holder of a working owner-role key is not touched at all.
//! [`Trusted::bring_to_rule`] is the one decision point that brings the list to it
//! ([`TrustStore::bring_to_rule`] the one inference): after a connection's `agent_ready`, after
//! every binding message (the orchestrator calls it), after every installed change (a repair's
//! landing included) and on the tick when a skipped person's grace ends. The current list is
//! this connection's `agent_ready` list and the binding messages since; from a link loss until the
//! next `agent_ready` there is none, and nothing is decided. One run's guest keys' removals (origin
//! `server`), notes and stored list go in one write; a second run changes nothing. The people it
//! took reach the orchestrator through [`Trusted::take_ruled`]: their sessions and pending requests
//! end. An explicit `binding_removed` keeps its own rules (`crate::admission`) and is followed by
//! the rule.
//!
//! # The window token (§3.4, §10.1)
//!
//! An epoch bumped whenever a session or a pending session starts that is not signed by a
//! confirmed owner key — today every one, since none is signed yet ([`Trusted::session_began`]) —
//! and `clean`: no such session live or pending now ([`Trusted::sync_live`]). «Подтвердить» and
//! turning «Доверенные устройства» on are refused `session` unless `clean` holds when the change is
//! staged and the window's token is the epoch now.
//!
//! # Threads
//!
//! [`Trusted`] lives on the orchestrator's main loop (one tokio task); everything it does there is
//! in memory: staging (a clone of the list and its checks, O(list)), installing, building the view
//! (O(active keys × list) for the dependents' walk: a few thousand steps for a full list). The
//! store's file I/O — a write, a reopen's load, the backup's check — runs in `spawn_blocking`; a
//! small async task awaits it with [`WRITE_LIMIT`] and sends the result back through the
//! orchestrator's channel. No lock is taken here; the store takes its own write lock on the
//! blocking thread only. The window reads the view through a `watch` channel and never waits on
//! the main loop's write.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_protocol::BindingRole;
use tokio::sync::{mpsc, oneshot, watch};

use crate::admission::{AdmitOp, Landed, LandedOutcome, StagedChange, StoreOp};
use crate::journal::{Journal, Kind, TrustedDevice as JournalDevice};
use crate::viewer_keys::{
    AddOutcome, ClientKind, DamageKind, Ground, GroundId, KeyId, KeyRecord, KeySource, Lookup,
    NewKey, OwnerDevice, Person, Platform, RecoverOutcome, Removal, ReopenLoad, Staged, StoreError,
    TreeRemoval, TrustStore, WriteFailed, Written,
};

/// How long a write (or a reopen's load) may take before its caller is answered `slow` (spec
/// §3.4 step 9: 2 s). It goes on in the background and lands when the disk answers.
pub const WRITE_LIMIT: Duration = Duration::from_secs(2);

/// How long the window waits for an answer: the write's limit and a margin for the queue's hop.
pub const REPLY_LIMIT: Duration = Duration::from_secs(3);

/// The most tries of one change on a retryable error before it is `write_failed`.
pub const MAX_ATTEMPTS: u32 = 3;

/// The window token's first epoch.
const FIRST_EPOCH: u64 = 1;

/// How often parked removals are tried again on their own (besides after every saved change):
/// the orchestrator's tick calls [`Trusted::tick`].
pub const PARKED_RETRY: Duration = Duration::from_secs(60);

/// The same device's attempt again moves its time in the list's notes without a new view until
/// the shown one is this old ([`Trusted::attempt_noted`]): the window says «Последняя: …» about
/// right, and a device that keeps trying cannot make the window republish on every offer.
const ATTEMPT_REPUBLISH_MS: i64 = 60_000;

// --- What the window asks, and what it hears ---------------------------------------------------

/// A change the window asks for (`AgentCommand::Trusted`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedAsk {
    /// «Доверенные устройства» on (needs `token` and a clean window) or off (always).
    SetMode { on: bool, token: Option<u64> },
    /// «Удалить»: the key and every active key that descends from it, origin `pc`. A person left
    /// with no working owner-role key whom the current list does not name is the rule's after the
    /// install (§10 «Сверка со списком сервера», [`Trusted::bring_to_rule`]).
    Remove { key_id: KeyId },
    /// «Удалить человека» (§10, §10.2): every key of the person with all its descendants, origin
    /// `pc`, their attempts gone and the grant token replaced — in one write; decided at the
    /// press. Never for the owner (by the bindings or by the PC's keys): `owner`.
    RemovePerson { telegram_user_id: i64 },
    /// «Подтвердить»: clear the key's `unconfirmed` mark; needs a clean window (one press: the
    /// person's decision, attempts or not).
    Confirm { key_id: KeyId, token: u64 },
    /// «Разрешить» on another device's attempt (§10.2): its key joins at the PC as the person's,
    /// with the role of the person's own keys here (none: guest) — a pairing at the PC. Needs the
    /// window's explicit second step (`second_step`, «Это моё устройство») when the person is the
    /// owner (by the server's bindings or by the PC's keys). `token`: the dialog's window token; a
    /// session since it opened (a taint) writes nothing in either mode (`tainted`, the attempt
    /// stays). `role` — the role the window showed (the owner's with «Это моё устройство», else a guest's): another
    /// one derived at the press or at the write is refused `role` ([`Trusted::owner_on_pc`]).
    AttemptAllow {
        telegram_user_id: i64,
        key_id: KeyId,
        token: u64,
        second_step: bool,
        role: BindingRole,
    },
    /// «Скрыть»: the attempt goes from the list (decided at the press, written with the notes).
    /// Needs a clean window, as «Подтвердить».
    AttemptHide {
        telegram_user_id: i64,
        key_id: KeyId,
        token: u64,
    },
    /// A repair at the PC (a restore needs a clean window and the token its dialog opened with).
    Repair(RepairAction),
    /// «Убрать ПК из пати» (party spec §6): the PC leaves the party, decided at the press
    /// ([`TrustStore::leave_party_now`]) — the delegation goes, the party's keys and their walk
    /// leave `server`, the grant token is replaced; one write carries it. The server hears of it
    /// by `party_state`. The answer is how many keys left; `not_found` when the PC is not in it.
    PartyLeave {
        party_id: crate::viewer_keys::GroundId,
    },
}

impl TrustedAsk {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SetMode { on: true, .. } => "mode_on",
            Self::SetMode { on: false, .. } => "mode_off",
            Self::Remove { .. } => "remove",
            Self::RemovePerson { .. } => "remove_person",
            Self::Confirm { .. } => "confirm",
            Self::AttemptAllow { .. } => "attempt_allow",
            Self::AttemptHide { .. } => "attempt_hide",
            Self::Repair(RepairAction::Reopen) => "reopen",
            Self::Repair(RepairAction::Restore { .. }) => "restore",
            Self::Repair(RepairAction::Reset) => "reset",
            Self::PartyLeave { .. } => "party_leave",
        }
    }
}

/// The PC's answer to a join or a leave (party spec §4.2), sent once the write that holds its
/// decision landed ([`Trusted::take_party_acks`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyAck {
    pub party_id: String,
    pub op: afklink_protocol::PartyAckOp,
    pub result: afklink_protocol::PartyAckResult,
}

/// What «Восстановить» / «Очистить список» / reading the file again do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairAction {
    /// Read the file again (allowed on a healthy store too).
    Reopen,
    /// Take the backup over a damaged file, keeping the switch the window shows. `token`: the
    /// window token as the dialog opened (as for confirm and mode-on) — a session that came and
    /// went since refuses it with `session`.
    Restore { token: u64 },
    /// Empty a damaged list, keeping the switch the window shows.
    Reset,
}

/// Why the window's change was refused (the IPC's error codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustedError {
    #[error("a session other than a confirmed owner's went on since the window opened")]
    Session,
    #[error("the trusted devices list is damaged")]
    Damaged,
    #[error("the list was written by a newer agent")]
    NewerVersion,
    #[error("the list is full")]
    Full,
    #[error("the key or the person is not in the list")]
    NotFound,
    #[error("the list could not be written")]
    WriteFailed,
    #[error("the write outlived its limit; it lands in the background")]
    Slow,
    #[error("another change is in flight")]
    Busy,
    #[error("refused")]
    Refused,
    /// «Удалить человека» for the owner (by the server's bindings or by the PC's keys): never.
    #[error("the owner is never removed as a person")]
    Owner,
    /// «Разрешить» for the owner without the window's explicit second step (§10.2).
    #[error("the explicit second step is needed")]
    SecondStep,
    /// «Разрешить» after a session went on since the dialog opened, in either mode: nothing is
    /// written, the attempt stays (§10.2).
    #[error("a session went on since the dialog opened; nothing written")]
    Tainted,
    /// «Разрешить» on an attempt older than 30 days (§10.2): it went.
    #[error("the attempt is older than 30 days")]
    Expired,
    /// «Разрешить» on an attempt whose key is in the list already.
    #[error("the device is in the list already")]
    Added,
    /// «Разрешить» on an attempt whose key is active or removed at another person (§10.2,
    /// `key_other_person`): nothing written, the attempt stays («Скрыть» removes it).
    #[error("the device is in the list at another person")]
    OtherPerson,
    /// «Включить» with no device of the owner's own that admits in strict mode (§10.2): a key that
    /// works, has the owner's role and is confirmed ([`TrustStore::has_owner_device`]). Turning
    /// the mode on then would shut the owner out.
    #[error("no confirmed owner device: the owner could not connect in strict mode")]
    NoOwnerDevice,
    /// «Разрешить» on an attempt whose press named another role than the one derived for the
    /// person — at the press, or again at the write (§10.2, «владелец на этом ПК»): nothing
    /// written, the attempt stays.
    #[error("the press named another role than the person's on this PC")]
    Role,
}

impl TrustedError {
    /// The code the window gets.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Damaged => "damaged",
            Self::NewerVersion => "newer_version",
            Self::Full => "full",
            Self::NotFound => "not_found",
            Self::WriteFailed => "write_failed",
            Self::Slow => "slow",
            Self::Busy => "busy",
            Self::Refused => "refused",
            Self::Owner => "owner",
            Self::SecondStep => "second_step",
            Self::Tainted => "tainted",
            Self::Expired => "expired",
            Self::Added => "added",
            Self::OtherPerson => "key_other_person",
            Self::NoOwnerDevice => "no_owner_device",
            Self::Role => "role",
        }
    }

    /// The code for a store refusal that a retry cannot change (or that ran out of retries).
    pub(crate) fn of(e: &StoreError) -> Self {
        match e {
            StoreError::Damaged => Self::Damaged,
            StoreError::NewerVersion => Self::NewerVersion,
            StoreError::Full(_) => Self::Full,
            StoreError::NotFound(_) | StoreError::Removed { .. } => Self::NotFound,
            StoreError::Write(_)
            | StoreError::ChangedOnDisk
            | StoreError::StaleBase
            | StoreError::NeedsReopen => Self::WriteFailed,
            StoreError::Busy => Self::Busy,
            StoreError::AlreadyActive(_) => Self::Added,
            StoreError::OtherPerson(_) => Self::OtherPerson,
            _ => Self::Refused,
        }
    }
}

/// The answer: how many keys a removal took; 0 for the other changes.
pub type TrustedReply = Result<u32, TrustedError>;

/// A change from the window, with where its answer goes.
#[derive(Debug)]
pub struct TrustedRequest {
    pub ask: TrustedAsk,
    pub reply: oneshot::Sender<TrustedReply>,
}

/// Send `ask` to the orchestrator through `commands` and wait at most [`REPLY_LIMIT`] for the
/// answer: `slow` past it (the change goes on), `refused` when the agent is gone. For an async
/// caller (the window's commands); the wait is a channel's, never a thread's.
pub async fn ask(
    commands: &mpsc::UnboundedSender<crate::AgentCommand>,
    ask: TrustedAsk,
) -> TrustedReply {
    let what = ask.as_str();
    let (reply, answer) = oneshot::channel();
    if commands
        .send(crate::AgentCommand::Trusted(TrustedRequest { ask, reply }))
        .is_err()
    {
        tracing::warn!(
            ask = what,
            "trusted devices: the agent has stopped; refused"
        );
        return Err(TrustedError::Refused);
    }
    match tokio::time::timeout(REPLY_LIMIT, answer).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(_)) => {
            tracing::warn!(
                ask = what,
                "trusted devices: the orchestrator dropped the request unanswered; refused"
            );
            Err(TrustedError::Refused)
        }
        Err(_) => {
            tracing::warn!(
                ask = what,
                limit_ms = REPLY_LIMIT.as_millis() as u64,
                "trusted devices: no answer within the limit (the orchestrator is busy or the \
                 write is slow); answered slow"
            );
            Err(TrustedError::Slow)
        }
    }
}

// --- The view ---------------------------------------------------------------------------------

/// What the window reads (`get_trusted`): published after every install, reopen and repair, and
/// whenever the window token or `clean` changes, with `rev` bumped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedView {
    /// Bumped at every publish: the window reloads the view when it changes (`trusted_rev`).
    pub rev: u64,
    /// `None`: the list is healthy.
    pub damage: Option<TrustedDamage>,
    /// The switch as stored; while damaged, the one the admission decides by — the mode file's
    /// (`TrustStore::damaged_mode`), `true` (strict) when it says nothing or there is no list.
    pub trusted_mode: bool,
    /// Every person with an active key, people in the order of their first key.
    pub people: Vec<TrustedPerson>,
    /// The `first_use` snapshot's people who never had a key here.
    pub waiting: Vec<i64>,
    /// Where the owner's own device stands for the switch ([`TrustStore::owner_device`], §10.2):
    /// the window offers «Включить» only at [`OwnerDevice::Ready`] and says what to do otherwise
    /// (add a device, or confirm one); turning the mode off is never held by it.
    pub owner_device: OwnerDevice,
    /// No session other than a confirmed owner's is live or pending now.
    pub clean: bool,
    /// The window token: the epoch now.
    pub token: u64,
    /// A list-wide limit is reached: new keys are refused until some are removed.
    pub full: bool,
    /// The parties the PC is in (party spec §3.1), in join order: the window's party cards.
    pub parties: Vec<TrustedParty>,
}

/// A party the PC is in, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedParty {
    pub party_id: GroundId,
    /// The party's name as the join signed it, cleaned as a person's name is.
    pub party: String,
    /// The leader as the join named him (names cleaned).
    pub leader: Person,
}

/// What is wrong with the list, and what the PC can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedDamage {
    pub kind: DamageKind,
    /// The backup passes every check and the damage is one a restore may replace.
    pub can_restore: bool,
    /// A reset is allowed (not for an unreadable file nor a newer version's).
    pub can_reset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPerson {
    pub telegram_user_id: i64,
    /// From the person's latest key record.
    pub first_name: Option<String>,
    pub username: Option<String>,
    pub devices: Vec<TrustedDeviceView>,
    /// Devices this PC does not know that tried to get in as this person (spec §10.2): the list's
    /// stored attempts (they outlive a restart), newest last, at most
    /// [`crate::viewer_keys::ATTEMPTS_PER_PERSON`]: «Подтвердить» warns while any is here.
    pub attempts: Vec<TrustedAttempt>,
    /// What «Разрешить» on their attempt gives: the owner's role for an owner on this PC
    /// ([`TrustStore::owner_here`]: a working owner-role key, or the owner by the bindings), a
    /// guest's otherwise.
    pub role: BindingRole,
    /// «Разрешить» needs the owner's explicit second step («Это моё устройство»): the press gives
    /// the owner's role.
    pub needs_second_step: bool,
}

/// Another device's attempt as the list keeps it (spec §10.2: [`crate::viewer_keys::Attempt`]),
/// for the window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAttempt {
    pub key_id: KeyId,
    /// The device as its key card names it.
    pub device: DeviceRef,
    /// How many times it tried.
    pub count: u32,
    /// The PC's clock (unix ms): its first and its latest try.
    pub first_at_ms: i64,
    pub last_at_ms: i64,
}

/// Another device tried to get in as a person and was refused after its offer's signature
/// verified (spec §10.2), for the journal: the admission makes one when the list keeps a new
/// attempt ([`crate::viewer_keys::TrustStore::note_attempt`]), within a day's bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAttempt {
    pub telegram_user_id: i64,
    /// The refusal: `key_unknown`, or `admit_refused`'s detail (`first_use_closed`,
    /// `recover_bad_sig`, …).
    pub reason: &'static str,
    /// The device's key (shown as its first 8 characters only).
    pub key_id: KeyId,
    /// The device as its key card names it.
    pub device: Option<DeviceRef>,
    /// The PC's clock (unix ms), for the window.
    pub at_ms: i64,
}

/// A device as far as its name goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRef {
    pub kind: ClientKind,
    pub platform: Platform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDeviceView {
    pub key_id: KeyId,
    pub device: DeviceRef,
    pub role: BindingRole,
    /// How it got in, as the list names it (`pair`, `endorse`, `grant`, `recover`, `first_use`,
    /// `party`).
    pub source: &'static str,
    /// `party`: the party whose leader's grant let it in.
    pub party: Option<GroundId>,
    /// `endorse.by` / `grant.by` while that key is still active.
    pub by: Option<DeviceRef>,
    /// `endorse.by` / `grant.by`, whether or not it is still in the list.
    pub by_key_id: Option<KeyId>,
    pub unconfirmed: bool,
    /// Active keys that «Удалить» on this one takes too.
    pub dependents: usize,
    pub added_at: i64,
    pub last_used_at: Option<i64>,
    /// A session of this key is live: always false until admission is wired (no session is signed
    /// yet).
    pub in_session: bool,
}

// --- Internal events --------------------------------------------------------------------------

/// A blocking job's result, back on the main loop ([`Trusted::on_done`]).
pub struct TrustedDone {
    job: u64,
    finished: Finished,
}

impl TrustedDone {
    /// Its name, for the orchestrator's step (`crate::step_watch`).
    pub fn kind(&self) -> &'static str {
        match self.finished {
            Finished::Wrote(_) => "trusted_written",
            Finished::Reopened { .. } => "trusted_reopened",
            Finished::Slow => "trusted_slow",
            Finished::Lost(_) => "trusted_lost",
        }
    }
}

enum Finished {
    Wrote(Wrote),
    Reopened {
        load: ReopenLoad,
        restorable: bool,
    },
    /// The job outlived [`WRITE_LIMIT`]: its caller hears `slow`; the job goes on.
    Slow,
    /// The blocking thread failed (a panic): whatever it carried is lost.
    Lost(String),
}

/// Where the orchestrator takes a [`TrustedDone`] in: its session-signal channel.
pub type Notify = Arc<dyn Fn(TrustedDone) + Send + Sync>;

/// A staged change of any outcome type.
enum Change {
    Unit(Staged<()>),
    Keys(Staged<Vec<KeyId>>),
    /// An admission's add (`crate::admission`).
    Add(Staged<AddOutcome>),
    /// An admission's same-device recovery.
    Recover(Staged<RecoverOutcome>),
}

enum Wrote {
    Unit(Result<Written<()>, WriteFailed<()>>),
    Keys(Result<Written<Vec<KeyId>>, WriteFailed<Vec<KeyId>>>),
    Add(Result<Written<AddOutcome>, WriteFailed<AddOutcome>>),
    Recover(Result<Written<RecoverOutcome>, WriteFailed<RecoverOutcome>>),
}

impl Change {
    fn write(self) -> Wrote {
        match self {
            Self::Unit(s) => Wrote::Unit(s.write()),
            Self::Keys(s) => Wrote::Keys(s.write()),
            Self::Add(s) => Wrote::Add(s.write()),
            Self::Recover(s) => Wrote::Recover(s.write()),
        }
    }
}

impl From<StagedChange> for Change {
    fn from(c: StagedChange) -> Self {
        match c {
            StagedChange::Unit(s) => Self::Unit(s),
            StagedChange::Add(s) => Self::Add(s),
            StagedChange::Recover(s) => Self::Recover(s),
        }
    }
}

// --- The queue ---------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpKind {
    SetMode {
        on: bool,
        token: Option<u64>,
    },
    Confirm {
        key_id: KeyId,
        token: u64,
    },
    /// «Разрешить» on an attempt: decided again at the stage ([`Trusted::stage_attempt_allow`]).
    /// `role`: the role the press named, derived again at the stage.
    AttemptAllow {
        uid: i64,
        key_id: KeyId,
        token: u64,
        second_step: bool,
        role: BindingRole,
    },
    /// The list's notes as memory has them (a hidden attempt): one write, or
    /// none when they are in the file already. `count`: the answer.
    Notes {
        what: &'static str,
    },
    /// «Удалить» at the PC: the key's tree, decided at the press
    /// ([`TrustStore::deny_tree_now`]); its stage is a write of memory.
    RemoveTree(KeyId),
    /// «Удалить человека» at the PC: the person's walk, decided at the press
    /// ([`press_remove_person`]); its stage is a write of memory.
    RemovePerson {
        uid: i64,
    },
    /// One key: an inherited pending removal. Staged on its own (a `server` one of an owner-role
    /// key is refused and withdrawn), and only while memory still decides it.
    RemoveKey {
        key_id: KeyId,
        by: Removal,
    },
    /// A guest unbound — at the PC (`by` `pc`) or on the server (`server`, spec §10): the
    /// person's guest-role keys, decided when it is queued ([`Trusted::untrust_guest`]); its
    /// stage is a write of memory (the keys and the notes).
    UntrustGuest {
        uid: i64,
        by: Removal,
    },
    Restore {
        token: u64,
    },
    Reset,
    Reopen,
    /// A party's join or leave (party spec §4.3), decided in memory when it came: its stage is a
    /// write of memory, a removal's class (queued first, parked when it cannot be saved). `ack`:
    /// the server's answer, taken once it lands ([`Trusted::take_party_acks`]); `None` for a
    /// leave at the PC.
    Party {
        ack: Option<PartyAck>,
    },
    /// An admission's change (`crate::admission`): its payload waits in `Trusted::admit_ops`.
    /// Not a removal; never gated by the window rule (the admission decided it).
    Admit {
        ticket: u64,
        what: &'static str,
    },
}

impl OpKind {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::SetMode { on: true, .. } => "mode_on",
            Self::SetMode { on: false, .. } => "mode_off",
            Self::Confirm { .. } => "confirm",
            Self::AttemptAllow { .. } => "attempt_allow",
            Self::Notes { what, .. } => what,
            Self::RemoveTree(_) => "remove_tree",
            Self::RemovePerson { .. } => "remove_person",
            Self::RemoveKey { .. } => "remove_key",
            Self::UntrustGuest {
                by: Removal::Pc, ..
            } => "untrust_guest",
            Self::UntrustGuest {
                by: Removal::Server,
                ..
            } => "server_removes_guest",
            Self::Restore { .. } => "restore",
            Self::Reset => "reset",
            Self::Reopen => "reopen",
            Self::Party { ack: Some(a) } => a.op.as_str(),
            Self::Party { ack: None } => "party_leave_at_pc",
            Self::Admit { what, .. } => what,
        }
    }

    /// The answer of a change whose outcome is `()`: one key for a single removal, else 0.
    const fn unit_count(&self) -> u32 {
        match self {
            Self::RemoveKey { .. } => 1,
            _ => 0,
        }
    }

    const fn is_removal(&self) -> bool {
        matches!(
            self,
            Self::RemoveTree(_)
                | Self::RemovePerson { .. }
                | Self::RemoveKey { .. }
                | Self::UntrustGuest { .. }
                | Self::Party { .. }
        )
    }

    /// A repair of a damaged list: the only changes a damaged list keeps.
    const fn is_repair(&self) -> bool {
        matches!(self, Self::Reopen | Self::Restore { .. } | Self::Reset)
    }
}

struct Op {
    kind: OpKind,
    /// The window's answer; `None` for the queue's own changes (an inherited removal, a guest's
    /// keys at an unbind) and once answered (`slow`).
    reply: Option<oneshot::Sender<TrustedReply>>,
    attempts: u32,
    /// The keys this removal denied at once.
    denied: Vec<KeyId>,
}

impl Op {
    fn new(kind: OpKind, reply: Option<oneshot::Sender<TrustedReply>>) -> Self {
        Self {
            kind,
            reply,
            attempts: 0,
            denied: Vec::new(),
        }
    }

    /// Whether this op is about `key_id` already (it denied it, or it removes it), so its write
    /// takes the key and no removal of its own is queued for it. A key that inherited a pending
    /// removal since (it joined as a descendant, [`TrustStore::pending_without_removal`]) is no
    /// op's decision: it gets a removal of its own from [`Trusted::after_change`].
    fn covers(&self, key_id: &KeyId) -> bool {
        self.denied.contains(key_id)
            || matches!(&self.kind, OpKind::RemoveTree(k) | OpKind::RemoveKey { key_id: k, .. } if k == key_id)
    }

    /// The answer of a change that wrote memory (or found it written): a removal's is what its
    /// decision denied; else [`OpKind::unit_count`].
    fn count(&self) -> u32 {
        match self.kind {
            OpKind::RemoveTree(_)
            | OpKind::RemovePerson { .. }
            | OpKind::UntrustGuest { .. }
            | OpKind::Party { .. } => u32::try_from(self.denied.len()).unwrap_or(u32::MAX),
            _ => self.kind.unit_count(),
        }
    }

    fn answer(&mut self, reply: TrustedReply) {
        let what = self.kind.as_str();
        match self.reply.take() {
            Some(tx) => {
                tracing::debug!(
                    op = what,
                    outcome = reply.map_or_else(|e| e.as_str(), |_| "ok"),
                    removed = reply.unwrap_or(0),
                    "trusted devices: answered"
                );
                if tx.send(reply).is_err() {
                    tracing::debug!(
                        op = what,
                        "trusted devices: the window stopped waiting for the answer"
                    );
                }
            }
            None => tracing::debug!(
                op = what,
                outcome = reply.map_or_else(|e| e.as_str(), |_| "ok"),
                "trusted devices: done (nobody waits for the answer)"
            ),
        }
    }
}

/// A window's change refused before anything is queued: the refusal goes to the window, and one
/// the window stopped waiting for is logged, never lost silently.
fn refuse(reply: oneshot::Sender<TrustedReply>, what: &'static str, refusal: TrustedError) {
    if reply.send(Err(refusal)).is_err() {
        tracing::debug!(
            ask = what,
            refusal = refusal.as_str(),
            "trusted devices: refused; the window stopped waiting for the answer"
        );
    }
}

/// Deny `ids` at once and make every later write carry their removal (origin of `by`, at the
/// press): «Нажатие решает сразу» (§10.1) for every removal path — a parked write is superseded
/// by the next one that lands, whatever change it is.
fn deny_carried(store: &mut TrustStore, ids: &[KeyId], by: Removal) {
    store.deny_now(ids);
    store.carry_removal(ids, by, crate::journal::now_ms());
}

/// «Удалить человека» at the press (§10, §10.2), in memory, before anything is queued: refused
/// `owner` for the owner (by the server's bindings, `bound`; by the latest known list,
/// `owner_by_list`; or by the PC's own keys), `damaged` when the list is (nothing can be checked).
/// Otherwise their walk is denied at once ([`TrustStore::deny_person_tree_now`], tombstones at
/// `now_ms`; their attempts go and the grant token is replaced), every later write carrying it —
/// also for a person the PC holds nothing of (their attempts aged out, or never known): accepted,
/// nothing denied, the token replaced all the same (vector `removal_press_replaces_the_token`).
/// The denied `key_id`s. The contract vectors' harness
/// decides «Удалить человека» through this one too.
pub(crate) fn press_remove_person(
    store: &mut TrustStore,
    uid: i64,
    bound: Option<BindingRole>,
    owner_by_list: bool,
    now_ms: i64,
) -> Result<TreeRemoval, TrustedError> {
    // The owner guard is a working owner-role key (§10 «Действующий ключ»): one whose removal
    // is decided guards nobody, as for the server's unbind.
    // Removing more is the strict side.
    let (owner_key, owner_key_leaving) = match store.person_keys(uid) {
        Ok(k) => (k.owner_by_keys(), k.owner_keys_not_working()),
        Err(e) => {
            tracing::debug!(
                telegram_user_id = uid,
                "trusted devices: remove person refused damaged ({e}): the list cannot say who \
                 they are"
            );
            return Err(TrustedError::of(&e));
        }
    };
    let owner_by_binding = bound == Some(BindingRole::Owner);
    if owner_by_binding || owner_by_list || owner_key {
        tracing::debug!(
            telegram_user_id = uid,
            owner_by_binding,
            owner_by_list,
            owner_key,
            "trusted devices: remove person refused owner (the owner is never removed as a person)"
        );
        return Err(TrustedError::Owner);
    }
    if owner_key_leaving {
        tracing::debug!(
            telegram_user_id = uid,
            "trusted devices: remove person: no owner-role key of theirs works (each leaving) — \
             no owner guard"
        );
    }
    let tree = store.deny_person_tree_now(uid, now_ms);
    tracing::info!(
        telegram_user_id = uid,
        kids = %short_list(&tree.removed),
        "trusted devices: a person removed at the PC: their walk denied at once; one write \
         carries it"
    );
    Ok(tree)
}

/// «Разрешить» on another device's attempt (§10.2), checked at the press and again at the stage:
/// the list reads (`damaged`); the attempt is there (its key active for the person already:
/// `added`; else `not_found`) and its last try is at most 30 days before the PC's clock (the
/// store's one rule, [`TrustStore::attempts`]; `expired` otherwise, and it goes);
/// the press names the role derived for the person now — the owner's for an owner on this PC
/// (`owner_here`, [`Trusted::owner_on_pc`] read by the caller), a guest's for anyone else, never
/// the server's word alone (`role` otherwise); the window gave the owner's explicit second step
/// when the person is an owner on this PC or has any owner-role record (`second_step`).
pub(crate) fn attempt_allow_check(
    store: &mut TrustStore,
    uid: i64,
    key_id: &KeyId,
    second_step: bool,
    (owner_here, pressed): (bool, BindingRole),
) -> Result<(), TrustedError> {
    // Deliberately the strict side: any owner-role record of the person still listed, working
    // or not (`listed_owner`), asks the second step — its removal may yet be refused and undone.
    let owner_key = match store.person_keys(uid) {
        Ok(keys) => !keys.listed_owner.is_empty(),
        Err(e) => {
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                telegram_user_id = uid,
                kid = %key_id.short(),
                "trusted devices: allow refused ({e}): the list cannot be read"
            );
            return Err(TrustedError::of(&e));
        }
    };
    let expired = store.expired_attempt_age(uid, key_id);
    match (store.attempt(uid, key_id), expired) {
        (None, Some(age)) => {
            store.prune_attempts(store.wall_now());
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                telegram_user_id = uid,
                kid = %key_id.short(),
                age_ms = age,
                "trusted devices: allow refused expired (the attempt is older than 30 days; it \
                 went)"
            );
            return Err(TrustedError::Expired);
        }
        (Some(_), _) => {}
        (None, None) => {
            let added = matches!(
                store.lookup(key_id),
                Lookup::Active(r) if r.person.telegram_user_id == uid
            );
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::debug!(
                telegram_user_id = uid,
                kid = %key_id.short(),
                added,
                "trusted devices: allow refused: no such attempt ({})",
                if added { "the device is in the list" } else { "it went" }
            );
            return Err(if added {
                TrustedError::Added
            } else {
                TrustedError::NotFound
            });
        }
    }
    // §10.2: the role the press named is the one the window showed; derived otherwise now (the
    // bindings or the keys moved since it rendered) — nothing written, the window reads again.
    let derived = if owner_here {
        BindingRole::Owner
    } else {
        BindingRole::Guest
    };
    if derived != pressed {
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            telegram_user_id = uid,
            kid = %key_id.short(),
            pressed = pressed.as_str(),
            derived = derived.as_str(),
            "trusted devices: allow refused role: the press named another role than the \
             person's on this PC now; nothing written, the attempt stays"
        );
        return Err(TrustedError::Role);
    }
    let needs = owner_here || owner_key;
    // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
    tracing::debug!(
        telegram_user_id = uid,
        kid = %key_id.short(),
        owner_here,
        owner_key,
        needs_second_step = needs,
        second_step,
        "trusted devices: allow {}",
        if needs && !second_step {
            "refused second_step"
        } else {
            "may go on"
        }
    );
    if needs && !second_step {
        return Err(TrustedError::SecondStep);
    }
    Ok(())
}

/// A device leaving the list, for its journal entry once the removal is installed.
struct Untrusted {
    uid: i64,
    first_name: Option<String>,
    username: Option<String>,
    device: JournalDevice,
}

enum Flight {
    Idle,
    Writing {
        job: u64,
        op: Op,
        started: Instant,
        untrusted: Vec<Untrusted>,
    },
    Reopening {
        job: u64,
        /// The window's «reopen», or `None` for the queue's own (after `NeedsReopen`).
        op: Option<Op>,
        started: Instant,
    },
}

/// What a stage did with an op.
enum Staging {
    /// A job runs; the queue waits for it.
    Started,
    /// Done at once (nothing to write, or refused): the next op may go.
    Done,
}

/// The trusted devices on the main loop. One per orchestrator.
pub struct Trusted {
    store: Option<TrustStore>,
    queue: VecDeque<Op>,
    parked: Vec<Op>,
    flight: Flight,
    /// A reopen is due before the next stage (`NeedsReopen`, `StaleBase`, a lost write).
    reopen_wanted: bool,
    view: watch::Sender<Arc<TrustedView>>,
    rev: u64,
    epoch: u64,
    /// Sessions and pending sessions that count against the window, as last told.
    live: usize,
    /// The backup passes every check (read on the blocking pool with every reopen, and at attach).
    backup_restorable: bool,
    notify: Notify,
    next_job: u64,
    write_limit: Duration,
    /// When the parked removals were last parked or tried again ([`Self::tick`]).
    parked_at: Option<Instant>,
    /// The PC's wall time (unix ms) after which the published view shows an attempt that no
    /// longer counts (§10.2: 30 days) — [`Self::tick`] publishes again then. Set at every publish.
    attempts_age_out_at: Option<i64>,
    /// The admission's changes waiting or in flight, by ticket ([`Self::admit`]).
    admit_ops: HashMap<u64, StoreOp>,
    /// The admission's changes that ended, for [`Self::take_landed`].
    landed: Vec<Landed>,
    /// The party answers whose write landed, for [`Self::take_party_acks`].
    party_acks: Vec<PartyAck>,
    /// The people the server's bindings name the owner ([`Self::set_bound_owners`]): read only by
    /// «owner on this PC» ([`Self::owner_on_pc`]), «the PC has an owner» ([`Self::pair_role`])
    /// and the owner guard of «Удалить человека» ([`press_remove_person`]).
    bound_owners: std::collections::BTreeSet<i64>,
    /// §10 «Текущий список»: everyone the server's bindings name on **this connection**, with
    /// their role — its `agent_ready`'s list ([`Self::agent_ready`]) and every binding message
    /// since ([`Self::set_bound_people`]); `None` before it and from a link loss
    /// ([`Self::forget_bound_people`]): the rule runs against no other list
    /// ([`Self::bring_to_rule`]). Not the store's stored last list, which outlives link losses
    /// and restarts and only tells whom the PC knows.
    bound_people: Option<BTreeMap<i64, BindingRole>>,
    /// The people the rule took since the orchestrator last asked ([`Self::take_ruled`]): their
    /// sessions and pending requests end.
    ruled: BTreeSet<i64>,
    /// The rule denied keys since then: their sessions end by the orchestrator's sweep.
    ruled_keys: bool,
    /// The PC's wall time when the grace of a person the rule skipped ends: the tick runs the
    /// rule again then ([`Self::tick`]).
    rule_due_at: Option<i64>,
    /// A test's wall clock moved on right after the view is built, before the age-out
    /// deadline is computed (the clock crossing 30 days between the two).
    #[cfg(test)]
    cross_after_view: Option<i64>,
    /// A test's hold on the blocking jobs: each waits for one `()` before it runs.
    #[cfg(test)]
    gate: Option<Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>>,
    /// A test's panic in the next blocking job, before it runs (a lost job).
    #[cfg(test)]
    panic_next: bool,
}

impl Trusted {
    /// No store yet (the CLI and tests keep none): the view says unreadable and every change is
    /// refused. `notify` takes the blocking jobs' results back to the main loop.
    pub fn new(notify: Notify) -> (Self, watch::Receiver<Arc<TrustedView>>) {
        let (view, rx) = watch::channel(Arc::new(TrustedView {
            rev: 0,
            damage: Some(TrustedDamage {
                kind: DamageKind::Unreadable,
                can_restore: false,
                can_reset: false,
            }),
            // No list: strict, as `build_view` says it.
            trusted_mode: true,
            people: Vec::new(),
            waiting: Vec::new(),
            owner_device: OwnerDevice::Missing,
            clean: true,
            token: FIRST_EPOCH,
            full: false,
            parties: Vec::new(),
        }));
        (
            Self {
                store: None,
                queue: VecDeque::new(),
                parked: Vec::new(),
                flight: Flight::Idle,
                reopen_wanted: false,
                view,
                rev: 0,
                epoch: FIRST_EPOCH,
                live: 0,
                backup_restorable: false,
                notify,
                next_job: 1,
                write_limit: WRITE_LIMIT,
                parked_at: None,
                attempts_age_out_at: None,
                admit_ops: HashMap::new(),
                landed: Vec::new(),
                party_acks: Vec::new(),
                bound_owners: std::collections::BTreeSet::new(),
                bound_people: None,
                ruled: BTreeSet::new(),
                ruled_keys: false,
                rule_due_at: None,
                #[cfg(test)]
                cross_after_view: None,
                #[cfg(test)]
                gate: None,
                #[cfg(test)]
                panic_next: false,
            },
            rx,
        )
    }

    /// Take `store` as the orchestrator's (opened beside config.json at start). On a damaged store
    /// the backup is checked here, for the window's «Восстановить»: **blocking file I/O**, for the
    /// start, where config.json is read — never on the async runtime.
    pub fn attach(&mut self, store: TrustStore) {
        self.backup_restorable =
            store.is_damaged() && TrustStore::backup_restorable(&store.paths());
        tracing::info!(
            damaged = store.damage().map_or("no", |d| d.kind.as_str()),
            backup_restorable = self.backup_restorable,
            "trusted devices: the list is the orchestrator's"
        );
        self.store = Some(store);
        self.publish("attached");
    }

    /// The people the server's bindings name the owner, as they stand now (`agent_ready`,
    /// `binding_added`/`removed`, `owner_changed`): «Разрешить» for one of them needs the
    /// second step (§10.2). The view is published when they change.
    pub fn set_bound_owners(&mut self, owners: impl IntoIterator<Item = i64>) {
        let owners: std::collections::BTreeSet<i64> = owners.into_iter().collect();
        if owners == self.bound_owners {
            return;
        }
        tracing::debug!(
            owners = owners.len(),
            "trusted devices: the bound owners changed (the second step of «Разрешить»)"
        );
        self.bound_owners = owners;
        self.publish("bound owners");
    }

    /// §5, §10.2 «Владелец на этом ПК» ([`TrustStore::owner_here`]) against the bound owners as
    /// they stand now. No list: nobody.
    pub fn owner_on_pc(&self, telegram_user_id: i64) -> bool {
        self.store.as_ref().is_some_and(|s| {
            s.owner_here(
                telegram_user_id,
                self.bound_owners.contains(&telegram_user_id),
            )
        })
    }

    /// §5, §7, §10.2: what an admission's change must still meet at its stage beyond the list's own
    /// rules (`StoreOp::stage`) — the server's bindings live here, not in the list, and may move
    /// while the change waits (a `binding_added` or `owner_changed` during its checks):
    /// - a pairing at the PC keeps the role its press named: derived otherwise now, the press is
    ///   cancelled whole (`role_changed`; the agent's held answer goes as a decline);
    /// - a grant never lands for an owner on this PC, the owner by the bindings included
    ///   (`grant_role`: a guest grant never touches the owner).
    pub fn admit_stage_check(&self, op: &StoreOp) -> Result<(), StoreError> {
        let StoreOp::Add(a) = op else {
            return Ok(());
        };
        if let Some((uid, pressed)) = a
            .pc_press()
            .and_then(|(uid, seen)| seen.role.map(|r| (uid, r)))
        {
            let derived = self.pair_role(uid);
            if derived.is_some_and(|d| d != pressed) {
                tracing::debug!(
                    telegram_user_id = uid,
                    pressed = pressed.as_str(),
                    derived = derived.map_or("-", BindingRole::as_str),
                    "trusted devices: a pairing's write: the role derived now is not the one its \
                     press named; cancelled whole (role_changed)"
                );
                return Err(StoreError::RoleChanged);
            }
        }
        // §5: the server's word (`pc_allow` + `BindingAdded`) lands a guest's key, which an owner
        // on this PC never gets — read again here, as an `owner_changed` may have come while it
        // waited behind another write.
        if let Ground::Pair { person, .. } = &a.ground {
            if a.server_word && self.owner_on_pc(person.telegram_user_id) {
                tracing::debug!(
                    telegram_user_id = person.telegram_user_id,
                    by_bindings = self.bound_owners.contains(&person.telegram_user_id),
                    "trusted devices: a pc_allow key's write: its person is an owner on this PC \
                     now; not written (role_changed)"
                );
                return Err(StoreError::RoleChanged);
            }
        }
        if let Ground::Grant { person, .. } | Ground::Party { person, .. } = &a.ground {
            if self.owner_on_pc(person.telegram_user_id) {
                tracing::debug!(
                    telegram_user_id = person.telegram_user_id,
                    by_bindings = self.bound_owners.contains(&person.telegram_user_id),
                    "trusted devices: a grant's write: its person is an owner on this PC now; \
                     refused grant_role"
                );
                return Err(StoreError::GrantRole);
            }
        }
        Ok(())
    }

    /// §5: the key role a pairing at the PC gives this person — derived when the PC has an
    /// owner ([`TrustStore::has_owner`]): an owner on this PC gets the owner's, anyone else a
    /// guest's. `None`: the PC has no owner, the role is the one chosen at the PC.
    pub fn pair_role(&self, telegram_user_id: i64) -> Option<BindingRole> {
        let store = self.store.as_ref()?;
        if !store.has_owner(!self.bound_owners.is_empty()) {
            return None;
        }
        Some(if self.owner_on_pc(telegram_user_id) {
            BindingRole::Owner
        } else {
            BindingRole::Guest
        })
    }

    /// §10 «Текущий список»: a connection's `agent_ready` came with `bindings` (by user id and
    /// role): from now on they are this connection's list, followed by every binding message
    /// ([`Self::set_bound_people`]) until the link goes ([`Self::forget_bound_people`]). The rule
    /// is the caller's next step ([`Self::bring_to_rule`]).
    pub fn agent_ready(&mut self, bindings: impl IntoIterator<Item = (i64, BindingRole)>) {
        let list: BTreeMap<i64, BindingRole> = bindings.into_iter().collect();
        tracing::debug!(
            bound = list.len(),
            had = self.bound_people.as_ref().map(BTreeMap::len),
            "trusted devices: agent_ready: this connection's binding list (the rule's current list)"
        );
        self.bound_people = Some(list);
    }

    /// §10: the link to the server is gone (`why`): there is no current list until the next
    /// `agent_ready` — the server may bind someone meanwhile — so the rule does not run.
    pub fn forget_bound_people(&mut self, why: &str) {
        if self.bound_people.take().is_some() {
            tracing::debug!(
                why,
                "trusted devices: this connection's binding list forgotten (the rule waits for \
                 the next agent_ready)"
            );
        }
    }

    /// ONE write of what the rule decided in memory (`what` names it), unless a write of the notes
    /// is queued already: any write carries memory as it is then — the notes, the stored list and
    /// the carried removals of `denied`, which that op then covers (no removal of their own is
    /// queued for them meanwhile).
    fn queue_notes_write(&mut self, why: &str, what: &'static str, denied: Vec<KeyId>) {
        let queued = self
            .queue
            .iter_mut()
            .find(|o| matches!(o.kind, OpKind::Notes { .. }));
        tracing::debug!(
            why,
            what,
            already_queued = queued.is_some(),
            denied = denied.len(),
            "trusted devices: memory is not in the file; a write of it {}",
            if queued.is_some() {
                "is queued already"
            } else {
                "queued"
            }
        );
        match queued {
            Some(o) => {
                for id in denied {
                    if !o.denied.contains(&id) {
                        o.denied.push(id);
                    }
                }
            }
            None => {
                self.enqueue(Op {
                    denied,
                    ..Op::new(OpKind::Notes { what }, None)
                });
                self.pump();
            }
        }
    }

    /// The rule's current list as a binding message left it (`agent_ready`'s list and every
    /// `binding_added`/`removed`, `owner_changed` since). Before this connection's `agent_ready`
    /// (or after its link went) there is none, and a binding message makes none.
    pub fn set_bound_people(&mut self, people: impl IntoIterator<Item = (i64, BindingRole)>) {
        let Some(current) = self.bound_people.as_mut() else {
            tracing::debug!(
                "trusted devices: bindings with no agent_ready on this connection (or after its \
                 link went): no current list made of them"
            );
            return;
        };
        let people: BTreeMap<i64, BindingRole> = people.into_iter().collect();
        if *current != people {
            tracing::debug!(
                bound = people.len(),
                was = current.len(),
                "trusted devices: the current binding list changed"
            );
            *current = people;
        }
    }

    /// §10 «Сверка со списком сервера: одно правило» — **the one decision point**: brings the list
    /// to the rule against this connection's current list ([`TrustStore::bring_to_rule`], the
    /// only place that infers a removal from it), `why` the trigger: an `agent_ready`, a binding
    /// message, an installed change, a repair's landing, the grace's end on the tick. Nothing
    /// without a list attached, without a current list, or while the list is damaged or needs a
    /// reopen. A run that changed memory queues ONE write of it (any write is a snapshot: the
    /// notes, the guest keys' tombstones and the stored list together). The people it took are
    /// kept for the orchestrator ([`Self::take_ruled`]): their sessions and pending requests end.
    /// Running it again changes nothing.
    pub fn bring_to_rule(&mut self, why: &str) {
        let (Some(store), Some(named)) = (self.store.as_mut(), self.bound_people.as_ref()) else {
            tracing::debug!(
                why,
                store = self.store.is_some(),
                current_list = self.bound_people.is_some(),
                "trusted devices: the binding list's rule not run (no list here, or no current \
                 binding list: no agent_ready on this connection yet, or the link is down)"
            );
            return;
        };
        let now = store.wall_now();
        let run = match store.bring_to_rule(named, now) {
            Ok(run) => run,
            Err(e) => {
                tracing::debug!(
                    why,
                    reason = e.as_str(),
                    "trusted devices: the binding list's rule not run now ({e}); it runs once \
                     the list reads again"
                );
                return;
            }
        };
        if self.rule_due_at != run.due_at {
            tracing::debug!(
                why,
                due_at = ?run.due_at,
                "trusted devices: the rule runs again on the tick when a skipped person's grace \
                 ends"
            );
            self.rule_due_at = run.due_at;
        }
        self.ruled.extend(run.ended.iter().copied());
        self.ruled_keys |= !run.denied.is_empty();
        if !run.changed() {
            tracing::trace!(
                why,
                "trusted devices: the binding list's rule: nothing to change"
            );
            return;
        }
        tracing::debug!(
            why,
            taken = run.ended.len(),
            denied = run.denied.len(),
            rotated = run.rotated,
            list_noted = run.list_noted,
            "trusted devices: the binding list's rule changed memory; one write of it queued"
        );
        self.queue_notes_write(why, "rule", run.denied);
        self.publish("the rule");
    }

    /// The people the rule took since the last call (their sessions end `unbound`, their pending
    /// requests are dropped) and whether it denied any key (the keys' sessions end by the sweep).
    pub fn take_ruled(&mut self) -> (Vec<i64>, bool) {
        (
            std::mem::take(&mut self.ruled).into_iter().collect(),
            std::mem::take(&mut self.ruled_keys),
        )
    }

    /// A party's join or leave decided in memory (party spec §4.3): one write of memory queued,
    /// a removal's class; `denied` the keys a leave denied (the op covers them). `ack` goes to
    /// [`Self::take_party_acks`] once a write that holds the decision landed — or at once when
    /// the file holds it already.
    pub fn party_write(&mut self, ack: Option<PartyAck>, denied: Vec<KeyId>) {
        tracing::debug!(
            ack = ?ack,
            denied = %short_list(&denied),
            "trusted devices: a party's decision; its write of memory queued"
        );
        self.enqueue(Op {
            denied,
            ..Op::new(OpKind::Party { ack }, None)
        });
        self.pump();
    }

    /// The party answers whose write landed since the last call, in order.
    pub fn take_party_acks(&mut self) -> Vec<PartyAck> {
        std::mem::take(&mut self.party_acks)
    }

    /// A party's write landed (or found the file holding it): its answer is due.
    fn party_landed(&mut self, op: &Op) {
        if let OpKind::Party { ack: Some(ack) } = &op.kind {
            tracing::debug!(ack = ?ack, "trusted devices: a party's write landed; its answer is due");
            self.party_acks.push(ack.clone());
        }
    }

    /// Whether a store is attached.
    pub fn has_store(&self) -> bool {
        self.store.is_some()
    }

    /// How long a write's caller waits for its result before it hears `slow` ([`WRITE_LIMIT`]
    /// in the product). The agent holds «Разрешить»'s answer for as long.
    pub(crate) fn write_limit(&self) -> Duration {
        self.write_limit
    }

    /// An agent-level test's limit before a write answers `slow` (a loaded machine starts a
    /// blocking job seconds late); the product's [`WRITE_LIMIT`] is unchanged.
    #[cfg(test)]
    pub(crate) fn set_write_limit(&mut self, limit: Duration) {
        self.write_limit = limit;
    }

    /// Every file job of an agent-level test waits for `release` (a send, or its drop) —
    /// a loaded machine, played.
    #[cfg(test)]
    pub(crate) fn gate_jobs(&mut self, release: std::sync::mpsc::Receiver<()>) {
        self.gate = Some(Arc::new(std::sync::Mutex::new(release)));
    }

    /// The list, read-only (the admission decides over it; no I/O).
    pub fn store(&self) -> Option<&TrustStore> {
        self.store.as_ref()
    }

    /// The list for its notes only (spec §10, §10.2, §7: attempts, the grant token, the
    /// stored binding list): memory changes with no I/O that decide at once, allowed while a change is in
    /// flight; every later write carries them. Never a `stage_*` through this.
    pub(crate) fn store_for_notes(&mut self) -> Option<&mut TrustStore> {
        self.store.as_mut()
    }

    /// The list for a test that applies changes synchronously (the admission's table test).
    #[cfg(test)]
    pub(crate) fn store_mut(&mut self) -> Option<&mut TrustStore> {
        self.store.as_mut()
    }

    /// The window token now: what a window (the pairing panel, «Подтвердить», mode-on) records
    /// when it opens.
    pub fn window_token(&self) -> u64 {
        self.epoch
    }

    /// Whether a window opened with `token` is still clean: no session other than one signed by a
    /// confirmed owner key since it opened (every such start moves the epoch on, §3.4), and none
    /// now. The one rule for the pairing panel, «Подтвердить» and mode-on.
    pub fn window_clean(&self, token: u64) -> bool {
        self.live == 0 && token == self.epoch
    }

    /// How many sessions count against the window now (as last told).
    pub fn counting(&self) -> usize {
        self.live
    }

    // --- The admission's changes ----------------------------------------------------------------

    /// Queue an admission's change (`crate::admission`): after the removals, staged at its turn
    /// (the store decides again then), written on the blocking pool, installed here. Its end —
    /// installed, refused, or past [`WRITE_LIMIT`] (`slow`, the write goes on and lands later) —
    /// comes out of [`Self::take_landed`], which the orchestrator reads after [`Self::on_done`].
    pub fn admit(&mut self, op: AdmitOp) {
        let AdmitOp { ticket, op } = op;
        let what = op.as_str();
        tracing::debug!(
            ticket,
            op = what,
            queued = self.queue.len(),
            "trusted devices: the admission's change queued"
        );
        if self.store.is_none() {
            self.landed.push(Landed {
                ticket,
                slow: false,
                result: Err(StoreError::Damaged),
            });
            return;
        }
        self.admit_ops.insert(ticket, op);
        self.enqueue(Op::new(OpKind::Admit { ticket, what }, None));
        self.pump();
    }

    /// The admission's changes that ended since the last call.
    pub fn take_landed(&mut self) -> Vec<Landed> {
        std::mem::take(&mut self.landed)
    }

    fn admit_landed(&mut self, ticket: u64, result: Result<LandedOutcome, StoreError>) {
        self.admit_ops.remove(&ticket);
        tracing::debug!(
            ticket,
            outcome = result.as_ref().map_or_else(|e| e.as_str(), |_| "installed"),
            "trusted devices: the admission's change ended"
        );
        self.landed.push(Landed {
            ticket,
            slow: false,
            result,
        });
    }

    // --- Other devices' attempts (spec §10.2) ---------------------------------------------------

    /// The admission noted another device's attempt on the list's notes
    /// ([`TrustStore::note_attempt`], in memory; the next write carries it): the window is
    /// published for a new one (`new`), and for the same device again only once the time the
    /// window shows is [`ATTEMPT_REPUBLISH_MS`] old — a device that keeps trying does not make it
    /// republish on every offer (its count and time are in the notes all the same, and the next
    /// view shows them).
    pub fn attempt_noted(&mut self, telegram_user_id: i64, key_id: &KeyId, new: bool, now_ms: i64) {
        let shown = self
            .view
            .borrow()
            .people
            .iter()
            .find(|p| p.telegram_user_id == telegram_user_id)
            .and_then(|p| p.attempts.iter().find(|a| &a.key_id == key_id))
            .map(|a| a.last_at_ms);
        // A repeat the window does not show (an attempt that went meanwhile) changes no view.
        let republish =
            new || shown.is_some_and(|at| now_ms.saturating_sub(at) >= ATTEMPT_REPUBLISH_MS);
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            user_id = telegram_user_id,
            kid = %key_id.short(),
            new,
            shown_at = ?shown,
            republish,
            "trusted devices: another device's attempt noted on the list; {}",
            if republish { "the window is published" } else { "the shown time stands a while" }
        );
        if republish {
            self.publish("another device's attempt");
        }
    }

    /// A person's attempts that still count (spec §10.2: [`TrustStore::attempts`], the last try
    /// at most 30 days before the PC's clock), newest last.
    pub fn attempts_of(&self, telegram_user_id: i64) -> Vec<TrustedAttempt> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        self.attempts_of_at(telegram_user_id, store.wall_now())
    }

    /// [`Self::attempts_of`] at one reading of the PC's wall clock (`now_ms`).
    fn attempts_of_at(&self, telegram_user_id: i64, now_ms: i64) -> Vec<TrustedAttempt> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let mut out: Vec<TrustedAttempt> = store
            .attempts_at(now_ms)
            .iter()
            .filter(|a| a.telegram_user_id == telegram_user_id)
            .map(|a| TrustedAttempt {
                key_id: a.key_id().clone(),
                device: DeviceRef {
                    kind: a.kind.clone(),
                    platform: a.platform.clone(),
                },
                count: a.count,
                first_at_ms: a.first_at,
                last_at_ms: a.last_at,
            })
            .collect();
        out.sort_by_key(|a| a.last_at_ms);
        out
    }

    // --- The window token ---------------------------------------------------------------------

    /// A session or a pending session started (`what`: which, `session`: its id) that is not signed
    /// by a confirmed owner key — today every one. **Admission's seam:** a session signed by a
    /// confirmed owner key (§3.4 «Органы доверия») does not call this, and does not count in
    /// [`Self::sync_live`].
    pub fn session_began(&mut self, what: &'static str, session: &str) {
        self.epoch = self.epoch.wrapping_add(1);
        self.live = self.live.saturating_add(1);
        tracing::debug!(
            what,
            session,
            epoch = self.epoch,
            "trusted devices: a session not signed by a confirmed owner began; the window token \
             moves on (confirm and mode-on refused for a window opened before it)"
        );
        self.publish("a session began");
    }

    /// How many sessions and pending sessions count against the window now (`clean` is zero).
    /// Any change of that number — a start, an end, clean ↔ not clean — moves the window token on,
    /// so a token read while a session was on (or before any change since) never passes later.
    /// **Admission's seam:** count only those not signed by a confirmed owner key.
    pub fn sync_live(&mut self, live: usize) {
        if live == self.live {
            return;
        }
        let was = self.live;
        self.live = live;
        self.epoch = self.epoch.wrapping_add(1);
        tracing::debug!(
            was,
            live,
            clean = live == 0,
            epoch = self.epoch,
            "trusted devices: the sessions counting against the window changed; the window token \
             moves on"
        );
        self.publish("sessions changed");
    }

    /// The orchestrator's tick: parked removals are tried again every [`PARKED_RETRY`], whether or
    /// not another change was saved meanwhile. Cheap when nothing is parked. The view is also
    /// published again once an attempt it shows ages past 30 days ([`Self::age_out_attempts`]).
    pub fn tick(&mut self, now: Instant) {
        self.age_out_attempts();
        self.rule_on_tick();
        if self.parked.is_empty() {
            return;
        }
        let due = self
            .parked_at
            .is_none_or(|at| now.saturating_duration_since(at) >= PARKED_RETRY);
        if !due {
            return;
        }
        tracing::debug!(
            parked = self.parked.len(),
            "trusted devices: parked removals tried again on the timer"
        );
        self.parked_at = Some(now);
        self.unpark();
        self.pump();
    }

    /// §10 «Запас»: the rule again once the grace of a person it skipped has ended (the PC's wall
    /// clock past `rule_due_at`). One comparison otherwise.
    fn rule_on_tick(&mut self) {
        let Some(due) = self.rule_due_at else {
            return;
        };
        let Some(now) = self.store.as_ref().map(TrustStore::wall_now) else {
            return;
        };
        if now < due {
            return;
        }
        tracing::debug!(
            due_at = due,
            now,
            "trusted devices: a skipped person's grace ended: the rule runs again"
        );
        self.rule_due_at = None;
        self.bring_to_rule("the grace ended (tick)");
    }

    /// §10.2 «Попытка старше 30 дней не показывается»: the view is built from the attempts
    /// that count at its publish; with nothing else happening it would keep one past its 30 days.
    /// On the orchestrator's tick (no thread or timer of its own): once the PC's wall clock passes
    /// the earliest shown attempt's age-out, the view is published again — built, as always, from
    /// the attempts that count ([`TrustStore::attempts`]); memory's notes are left as they are
    /// (the next note prunes them). Cheap otherwise: one comparison with the wall clock.
    fn age_out_attempts(&mut self) {
        let Some(at) = self.attempts_age_out_at else {
            return;
        };
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let now_ms = store.wall_now();
        if now_ms <= at {
            return;
        }
        tracing::debug!(
            age_out_at = at,
            now_ms,
            "trusted devices: an attempt shown in the view is older than 30 days now; the view is \
             published again without it"
        );
        self.publish("an attempt aged out");
    }

    /// Confirm, mode-on and restore: `clean` now and the window's token is the epoch.
    /// §10.2: strict mode goes on only over the owner's own confirmed device — at the press and
    /// again at the stage, as the window token. Turning it off is never held by this.
    fn owner_device_held(&self, what: &'static str) -> Result<(), TrustedError> {
        let Some(store) = self.store.as_ref() else {
            return Err(TrustedError::Refused);
        };
        // A list that does not read says so at its stage (`damaged`), not this.
        if store.is_damaged() {
            return Ok(());
        }
        let device = store.owner_device();
        if device == OwnerDevice::Ready {
            return Ok(());
        }
        tracing::debug!(
            op = what,
            owner_device = device.as_str(),
            "trusted devices: refused no_owner_device (no working, confirmed owner-role key: strict \
             mode would shut the owner out)"
        );
        Err(TrustedError::NoOwnerDevice)
    }

    fn window_open(&self, token: Option<u64>, what: &'static str) -> Result<(), TrustedError> {
        if self.live == 0 && token == Some(self.epoch) {
            return Ok(());
        }
        tracing::debug!(
            op = what,
            live = self.live,
            token = ?token,
            epoch = self.epoch,
            "trusted devices: refused session (a session went on since the window opened, or \
             one is live or pending now)"
        );
        Err(TrustedError::Session)
    }

    // --- Commands -----------------------------------------------------------------------------

    /// The window's change. `live`: the sessions and pending sessions that count against the
    /// window now. Answers through the request's channel, now or when the change lands.
    pub fn command(&mut self, req: TrustedRequest, live: usize) {
        self.command_at(req, live, None);
    }

    /// [`Self::command`] with what the PC knows beside the list: `bound`, the server's binding
    /// role of the person a «Удалить человека» names (`None`: not bound, or another ask).
    pub fn command_at(&mut self, req: TrustedRequest, live: usize, bound: Option<BindingRole>) {
        self.sync_live(live);
        let TrustedRequest { ask, reply } = req;
        let what = ask.as_str();
        // «Разрешить» for an owner on this PC gives the owner's role, with the second step.
        let owner_here = match &ask {
            TrustedAsk::AttemptAllow {
                telegram_user_id, ..
            } => self.owner_on_pc(*telegram_user_id),
            _ => false,
        };
        let Some(store) = self.store.as_mut() else {
            tracing::debug!(
                ask = what,
                "trusted devices: refused, this agent keeps no list"
            );
            refuse(reply, what, TrustedError::Refused);
            return;
        };
        tracing::debug!(
            ask = what,
            queued = self.queue.len(),
            in_flight = !matches!(self.flight, Flight::Idle),
            "trusted devices: the window asks"
        );
        // §3.4 «Органы доверия»: while any live or pending session is not
        // signed by a confirmed owner key, every trust command of the window is refused, for the
        // person at the PC too. The queue's own changes (a guest's untrust, parked retries, the
        // admission's changes) are not gated.
        if self.live > 0 {
            tracing::debug!(
                ask = what,
                live = self.live,
                "trusted devices: refused session (a session not signed by a confirmed owner key \
                 is live or pending)"
            );
            refuse(reply, what, TrustedError::Session);
            return;
        }
        let op = match ask {
            TrustedAsk::SetMode { on: true, token } => {
                if let Err(e) = self
                    .window_open(token, what)
                    .and_then(|()| self.owner_device_held(what))
                {
                    refuse(reply, what, e);
                    return;
                }
                Op::new(OpKind::SetMode { on: true, token }, Some(reply))
            }
            TrustedAsk::SetMode { on: false, .. } => Op::new(
                OpKind::SetMode {
                    on: false,
                    token: None,
                },
                Some(reply),
            ),
            TrustedAsk::Confirm { key_id, token } => {
                if let Err(e) = self.window_open(Some(token), what) {
                    refuse(reply, what, e);
                    return;
                }
                Op::new(OpKind::Confirm { key_id, token }, Some(reply))
            }
            TrustedAsk::AttemptAllow {
                telegram_user_id: uid,
                key_id,
                token,
                second_step,
                role,
            } => {
                // A taint (a session since the dialog opened) is decided at the stage: nothing
                // is written in either mode.
                let pressed = (owner_here, role);
                if let Err(e) = attempt_allow_check(store, uid, &key_id, second_step, pressed) {
                    refuse(reply, what, e);
                    return;
                }
                Op::new(
                    OpKind::AttemptAllow {
                        uid,
                        key_id,
                        token,
                        second_step,
                        role,
                    },
                    Some(reply),
                )
            }
            TrustedAsk::AttemptHide {
                telegram_user_id: uid,
                key_id,
                token,
            } => {
                if let Err(e) = self.window_open(Some(token), what) {
                    refuse(reply, what, e);
                    return;
                }
                let Some(store) = self.store.as_mut() else {
                    refuse(reply, what, TrustedError::Refused);
                    return;
                };
                let refused = if store.is_damaged() {
                    Some(TrustedError::Damaged)
                } else if !store.drop_attempt(uid, &key_id) {
                    Some(TrustedError::NotFound)
                } else {
                    None
                };
                // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
                tracing::debug!(
                    telegram_user_id = uid,
                    kid = %key_id.short(),
                    outcome = refused.map_or("hidden", TrustedError::as_str),
                    "trusted devices: «Скрыть» on an attempt (decided now; the notes' write follows)"
                );
                if let Some(e) = refused {
                    refuse(reply, what, e);
                    return;
                }
                self.publish("attempt hidden");
                Op::new(
                    OpKind::Notes {
                        what: "attempt_hide",
                    },
                    Some(reply),
                )
            }
            TrustedAsk::Remove { key_id } => {
                // Decided here, once (§10.1): refused `damaged` (§10 «Повреждённый список»: a
                // damaged list is changed by nothing; repair it first) and `not_found` (a key the
                // list does not know at all has no tree), with nothing denied.
                let denied = match store.deny_tree_now(&key_id, crate::journal::now_ms()) {
                    Ok(tree) => tree.removed,
                    Err(e) => {
                        let refusal = TrustedError::of(&e);
                        tracing::debug!(
                            kid = %key_id.short(),
                            refusal = refusal.as_str(),
                            "trusted devices: remove refused ({e})"
                        );
                        refuse(reply, what, refusal);
                        return;
                    }
                };
                Op {
                    denied,
                    ..Op::new(OpKind::RemoveTree(key_id), Some(reply))
                }
            }
            TrustedAsk::RemovePerson { telegram_user_id } => {
                // §10 «владельца это не трогает никогда»: with the owner's keys all
                // leaving (no keys guard), the latest known list still guards them — the
                // bound owners, and before this connection's `agent_ready` (a fresh start: the
                // admission has no binding yet) the stored last known list. Refusing more is
                // only availability: the window offers «Удалить человека» again after it.
                let by_bound_owners = self.bound_owners.contains(&telegram_user_id);
                let by_stored_list = self.bound_people.is_none()
                    && store.last_bindings().is_some_and(|list| {
                        list.iter().any(|b| {
                            b.telegram_user_id == telegram_user_id && b.role == BindingRole::Owner
                        })
                    });
                if by_bound_owners || by_stored_list {
                    tracing::debug!(
                        telegram_user_id,
                        by_bound_owners,
                        by_stored_list,
                        bound = ?bound,
                        "trusted devices: remove person: the latest known list names them the owner"
                    );
                }
                match press_remove_person(
                    store,
                    telegram_user_id,
                    bound,
                    by_bound_owners || by_stored_list,
                    crate::journal::now_ms(),
                ) {
                    Ok(TreeRemoval { removed: denied }) => Op {
                        denied,
                        ..Op::new(
                            OpKind::RemovePerson {
                                uid: telegram_user_id,
                            },
                            Some(reply),
                        )
                    },
                    Err(e) => {
                        refuse(reply, what, e);
                        return;
                    }
                }
            }
            TrustedAsk::PartyLeave { party_id } => {
                // Decided here, once (party spec §6): `damaged` on a list that cannot be read,
                // `not_found` when the PC is not in that party, with nothing changed.
                let why = "«Убрать ПК из пати» at the PC";
                match store.leave_party_now(
                    &party_id,
                    crate::viewer_keys::PartyLeaveBy::Pc,
                    why,
                    crate::journal::now_ms(),
                ) {
                    Ok(Some(denied)) => Op {
                        denied,
                        ..Op::new(OpKind::Party { ack: None }, Some(reply))
                    },
                    Ok(None) => {
                        refuse(reply, what, TrustedError::NotFound);
                        return;
                    }
                    Err(e) => {
                        tracing::debug!(party = %party_id, "trusted devices: party leave refused ({e})");
                        refuse(reply, what, TrustedError::of(&e));
                        return;
                    }
                }
            }
            TrustedAsk::Repair(RepairAction::Reopen) => Op::new(OpKind::Reopen, Some(reply)),
            TrustedAsk::Repair(RepairAction::Restore { token }) => {
                if let Err(e) = self.window_open(Some(token), what) {
                    refuse(reply, what, e);
                    return;
                }
                Op::new(OpKind::Restore { token }, Some(reply))
            }
            TrustedAsk::Repair(RepairAction::Reset) => Op::new(OpKind::Reset, Some(reply)),
        };
        self.enqueue(op);
        self.pump();
    }

    /// A guest unbound at the PC («Отвязать», spec §10: `pc` — a person removed at the PC): the
    /// person's **guest-role** keys leave the list, origin `pc`, denied and carried at once; the
    /// queued change is a write of memory. Keys whose role is owner's stay: the key's role is the
    /// list's, and an owner's keys leave only through the window's «Удалить». A damaged list
    /// changes nothing (§10 «Повреждённый список»: after the repair the binding list's rule takes
    /// the person, `server`).
    pub fn untrust_guest(&mut self, telegram_user_id: i64, live: usize) {
        self.untrust_guest_by(telegram_user_id, Removal::Pc, live);
    }

    /// A guest's binding removed on the server (`BindingRemoved`, spec §10 table, origin
    /// `server`; the owner removing a guest in the Mini App comes this way too): the person's
    /// **guest-role** keys are denied at once and leave the list as tombstones `server` — which a
    /// new `grant` of the owner on a **new** invitation (§7), or «Разрешить» at the PC, lifts.
    /// Owner-role keys never (design §8; the store refuses it too). The queue's own change: not
    /// gated by the window rule; decided here once, its write is a write of memory; a damaged list
    /// changes nothing. Their live sessions end at the orchestrator's sweep (`key_revoked`).
    pub fn guest_removed_on_server(&mut self, telegram_user_id: i64, live: usize) {
        self.untrust_guest_by(telegram_user_id, Removal::Server, live);
    }

    fn untrust_guest_by(&mut self, telegram_user_id: i64, by: Removal, live: usize) {
        self.sync_live(live);
        if self.store.is_none() {
            tracing::debug!(
                telegram_user_id,
                by = ?by,
                "trusted devices: a guest unbound; this agent keeps no list, nothing to remove"
            );
            return;
        }
        self.queue_untrust_guest(telegram_user_id, by);
        self.pump();
    }

    /// [`Self::untrust_guest_by`]'s decision and queueing, without starting the queue. The
    /// caller pumps.
    fn queue_untrust_guest(&mut self, telegram_user_id: i64, by: Removal) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        // §10 «Повреждённый список»: a damaged list changes nothing and remembers nothing — the
        // server's unbind and one at the PC alike (that one went to the server) — and no waiting
        // change is touched first. Once the list is repaired, the binding list's rule takes
        // whoever the current list does not name (`server`). Decided here once, in memory: the
        // guest-role keys denied and carried.
        let decided = store.deny_guest_keys_now(telegram_user_id, by, crate::journal::now_ms());
        let (guest_keys, owner_keys) = match decided {
            Ok(keys) => keys,
            Err(e) => {
                tracing::debug!(
                    telegram_user_id,
                    by = ?by,
                    "trusted devices: a guest unbound while the list is unusable ({e}): nothing \
                     changed or kept; the rule decides after the repair"
                );
                return;
            }
        };
        // An admission's key of theirs may be on its way into the list (queued, retried, or being
        // written) — not listed yet, so it is not among the keys below: a grant dies by the token
        // replaced here (checked at its install, [`Self::landed_again`]); a key that descends
        // from a key denied here leaves with it at the install ([`TrustStore::settle_pending`]).
        //
        // One untrust of a person waiting at a time (queued or parked): another unbind of them
        // only joins it — a flood of `BindingRemoved` keeps the queue bounded. The origin is the
        // store's carry: the PC's never gives way to the server's ([`TrustStore::carry_removal`]).
        let waiting = self.queue.iter().chain(self.parked.iter()).position(
            |o| matches!(o.kind, OpKind::UntrustGuest { uid, .. } if uid == telegram_user_id),
        );
        let op = Op::new(
            OpKind::UntrustGuest {
                uid: telegram_user_id,
                by,
            },
            None,
        );
        if guest_keys.is_empty() {
            // Nothing of theirs to remove: memory unsaved for another reason still rides this
            // op's write of memory; one that changed nothing writes nothing.
            let unsaved = store.notes_unsaved();
            let queued = unsaved && waiting.is_none();
            tracing::debug!(
                telegram_user_id,
                admission_changes = self.admit_ops.len(),
                unsaved,
                queued,
                "trusted devices: a guest unbound with no guest key in the list; nothing to remove \
                 now{}",
                if queued {
                    "; the removal's write of memory queued"
                } else {
                    ""
                }
            );
            if queued {
                self.enqueue(op);
            }
            return;
        }
        // not-a-key-name: `keys` is a count of access keys, not a pressed key
        tracing::info!(
            telegram_user_id,
            keys = guest_keys.len(),
            owner_keys_stay = owner_keys,
            by = ?by,
            merged = waiting.is_some(),
            "trusted devices: a guest unbound ({}); their guest keys are denied and carried (their \
             owner-role keys stay), and a write of memory queued",
            match by {
                Removal::Pc => "at the PC, origin pc",
                Removal::Server => "on the server, origin server",
            }
        );
        match waiting {
            Some(at) => {
                let queued = self.queue.len();
                let o = if at < queued {
                    &mut self.queue[at]
                } else {
                    &mut self.parked[at - queued]
                };
                for id in guest_keys {
                    if !o.denied.contains(&id) {
                        o.denied.push(id);
                    }
                }
            }
            None => self.enqueue(Op {
                denied: guest_keys,
                ..op
            }),
        }
    }

    /// An admission's change installed — decided again after its last wait (§7, §10): a key
    /// whose removal was decided during its write is refused `key_revoked`; a grant whose grant
    /// token a removal (any removal press at the PC included) replaced during its write is
    /// stale — the key is denied at once and leaves `server`: a removal of its own (or their
    /// untrust waiting takes it), carried by every later write; the admission hears
    /// `grant_stale`, as the stage would have said. Otherwise the outcome as it is.
    fn landed_again(
        &mut self,
        ticket: u64,
        outcome: LandedOutcome,
    ) -> Result<LandedOutcome, StoreError> {
        let (uid, kid) = match &outcome {
            LandedOutcome::Added(a) => (a.telegram_user_id, a.key_id.clone()),
            LandedOutcome::Recovered(r) => (r.telegram_user_id, r.new_key_id.clone()),
            LandedOutcome::Unit => return Ok(outcome),
        };
        let Some(store) = self.store.as_mut() else {
            return Ok(outcome);
        };
        // A key that leaves at its own install — it descends from a key whose removal was decided
        // during its write ([`TrustStore::settle_pending`]) — is refused as removed (`key_revoked`).
        if let Some(origin) = store.removal_decided(&kid) {
            tracing::info!(
                ticket,
                telegram_user_id = uid,
                kid = %kid.short(),
                origin,
                "trusted devices: an admission's key landed whose removal was decided during its \
                 write (it descends from a removed key); refused key_revoked"
            );
            return Err(StoreError::Removed {
                key_id: kid,
                origin,
            });
        }
        // §7: a grant is decided by the token at its install too — a removal during its write
        // replaced it: stale.
        let stale_grant = match self.admit_ops.get(&ticket) {
            Some(StoreOp::Add(a)) => match &a.ground {
                Ground::Grant { token, .. } | Ground::Party { token, .. } => {
                    store.grant_token_current(token).is_err()
                }
                _ => false,
            },
            _ => false,
        };
        if !stale_grant {
            return Ok(outcome);
        }
        let (by, refusal) = (Removal::Server, StoreError::GrantStale);
        deny_carried(store, std::slice::from_ref(&kid), by);
        // Their untrust still waiting writes it with memory (it covers the key now); otherwise the
        // key's own removal is queued by `after_change` (a denied key with no removal), with this
        // origin.
        let joined = self
            .queue
            .iter_mut()
            .chain(self.parked.iter_mut())
            .find(|o| matches!(o.kind, OpKind::UntrustGuest { uid: u, .. } if u == uid))
            .map(|o| {
                if !o.denied.contains(&kid) {
                    o.denied.push(kid.clone());
                }
            })
            .is_some();
        tracing::info!(
            ticket,
            telegram_user_id = uid,
            kid = %kid.short(),
            reason = refusal.as_str(),
            joined_untrust = joined,
            "trusted devices: an admission's grant landed after a removal replaced its grant \
             token; denied at once, its removal follows (server)"
        );
        Err(refusal)
    }

    /// Keep a removal whose write cannot be saved now; its keys stay denied. Tried again after the
    /// next saved change, and on the timer ([`Self::tick`]).
    fn park(&mut self, op: Op) {
        if self.parked.is_empty() {
            self.parked_at = Some(Instant::now());
        }
        self.parked.push(op);
    }

    /// Queue `op`: a removal after the removals already waiting, before everything else.
    fn enqueue(&mut self, op: Op) {
        if op.kind.is_removal() {
            let at = self
                .queue
                .iter()
                .position(|o| !o.kind.is_removal())
                .unwrap_or(self.queue.len());
            self.queue.insert(at, op);
        } else {
            self.queue.push_back(op);
        }
    }

    /// Back at the head of its class, for a retry.
    fn requeue_front(&mut self, op: Op) {
        if op.kind.is_removal() {
            self.queue.push_front(op);
        } else {
            let at = self
                .queue
                .iter()
                .position(|o| !o.kind.is_removal())
                .unwrap_or(self.queue.len());
            self.queue.insert(at, op);
        }
    }

    fn busy(&self) -> bool {
        !matches!(self.flight, Flight::Idle)
    }

    /// Nothing in flight and nothing queued (the admission's tests drive the queue).
    #[cfg(test)]
    pub(crate) fn settled(&self) -> bool {
        !self.busy() && self.queue.is_empty()
    }

    /// Start what can start: a due reopen, else the next op.
    fn pump(&mut self) {
        while !self.busy() {
            if self.reopen_wanted {
                self.reopen_wanted = false;
                self.start_reopen(None);
                return;
            }
            let Some(op) = self.queue.pop_front() else {
                return;
            };
            if let Staging::Started = self.stage(op) {
                return;
            }
        }
    }

    fn stage(&mut self, mut op: Op) -> Staging {
        if let OpKind::Reopen = op.kind {
            self.start_reopen(Some(op));
            return Staging::Started;
        }
        // The window's rule again at the stage: a session may have begun while the op waited.
        let token = match &op.kind {
            OpKind::SetMode {
                on: true, token, ..
            } => Some(*token),
            OpKind::Confirm { token, .. } | OpKind::Restore { token } => Some(Some(*token)),
            _ => None,
        };
        if let Some(token) = token {
            if let Err(e) = self.window_open(token, op.kind.as_str()) {
                op.answer(Err(e));
                return Staging::Done;
            }
        }
        // A removal decided since the press may have taken the owner's last such device.
        if matches!(op.kind, OpKind::SetMode { on: true, .. }) {
            if let Err(e) = self.owner_device_held(op.kind.as_str()) {
                op.answer(Err(e));
                return Staging::Done;
            }
        }
        if let OpKind::AttemptAllow {
            uid,
            ref key_id,
            token,
            second_step,
            role,
        } = op.kind
        {
            let key_id = key_id.clone();
            return self.stage_attempt_allow(op, uid, key_id, token, (second_step, role));
        }
        // The bindings' part of an admission's rules, read again at its write.
        if let OpKind::Admit { ticket, .. } = op.kind {
            let checked = self
                .admit_ops
                .get(&ticket)
                .map_or(Ok(()), |payload| self.admit_stage_check(payload));
            if let Err(e) = checked {
                self.retry_or_fail(op, &e);
                return Staging::Done;
            }
        }
        let Some(store) = self.store.as_mut() else {
            op.answer(Err(TrustedError::Refused));
            return Staging::Done;
        };
        // A repair only on a list damaged now: a reset or a restore of a healthy one (the window's
        // dialog opened while it was damaged, a reopen fixed it since) would wipe or roll it back.
        if matches!(op.kind, OpKind::Reset | OpKind::Restore { .. }) && !store.is_damaged() {
            tracing::debug!(
                op = op.kind.as_str(),
                "trusted devices: refused, the list is not damaged (a repair only mends a damaged \
                 one)"
            );
            op.answer(Err(TrustedError::Refused));
            return Staging::Done;
        }
        let now = crate::journal::now_ms();
        if let OpKind::Admit { ticket, .. } = op.kind {
            let Some(payload) = self.admit_ops.get(&ticket) else {
                tracing::warn!(
                    ticket,
                    "trusted devices: an admission's change without payload"
                );
                return Staging::Done;
            };
            return match payload.stage(store, now) {
                Ok(Some(change)) => self.launch(op, change.into()),
                Ok(None) => {
                    self.admit_landed(ticket, Ok(LandedOutcome::Unit));
                    Staging::Done
                }
                Err(e) => {
                    self.retry_or_fail(op, &e);
                    Staging::Done
                }
            };
        }
        let staged: Result<Option<Change>, StoreError> = match &op.kind {
            OpKind::SetMode { on, .. } => store
                .stage_set_trusted_devices_mode(*on)
                .map(|s| s.map(Change::Unit)),
            OpKind::Confirm { key_id, .. } => {
                store.stage_confirm(key_id).map(|s| s.map(Change::Unit))
            }
            // Decided at the press (or when queued) and carried: the write is a write of memory
            // at every stage alike, so a retry decides nothing again — memory as it is then, with
            // every later decision at the PC in it.
            OpKind::RemoveTree(_)
            | OpKind::RemovePerson { .. }
            | OpKind::UntrustGuest { .. }
            | OpKind::Party { .. }
            | OpKind::Notes { .. } => store.stage_flush().map(|s| s.map(Change::Unit)),
            // Its own stage (a `server` removal of an owner-role key is refused and withdrawn),
            // and only while memory still decides it: a removal that landed, or was withdrawn,
            // leaves nothing to write — a key added back since is a later decision's.
            OpKind::RemoveKey { key_id, by } => {
                if store.removal_decided(key_id).is_some() {
                    store
                        .stage_remove(key_id, *by, now)
                        .map(|s| Some(Change::Unit(s)))
                } else {
                    // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
                    tracing::debug!(
                        kid = %key_id.short(),
                        by = ?by,
                        "trusted devices: one key's removal is decided no more (landed, or \
                         withdrawn): nothing to write"
                    );
                    Ok(None)
                }
            }
            OpKind::Restore { .. } => store
                .stage_restore_from_backup(now)
                .map(|s| Some(Change::Unit(s))),
            // A person a reset left with no working owner-role key is the rule's after the install
            // (§10 «Сверка со списком сервера»).
            OpKind::Reset => store
                .stage_reset_to_empty(now)
                .map(|s| Some(Change::Keys(s))),
            OpKind::Reopen | OpKind::Admit { .. } | OpKind::AttemptAllow { .. } => {
                unreachable_reopen()
            }
        };
        match staged {
            // Nothing left to write: memory is on disk (an earlier write carried it all).
            Ok(None) => {
                tracing::debug!(
                    op = op.kind.as_str(),
                    attempt = op.attempts + 1,
                    "trusted devices: nothing to write (so already)"
                );
                self.party_landed(&op);
                let n = op.count();
                op.answer(Ok(n));
                Staging::Done
            }
            Ok(Some(change)) => self.launch(op, change),
            Err(e) => {
                self.retry_or_fail(op, &e);
                Staging::Done
            }
        }
    }

    /// «Разрешить» at its stage (§10.2) — at every stage, a retry's included: the press's checks
    /// again ([`attempt_allow_check`], the bindings as they stand now), then the taint: a session
    /// since the dialog opened (`token` other than the epoch) or one now means nothing is written,
    /// in either mode (`tainted`, the attempt stays). Otherwise the attempt's key joins confirmed
    /// as a pairing at the PC — the person as their latest key names them, the role derived for
    /// them here (the attempt goes with it at the install).
    fn stage_attempt_allow(
        &mut self,
        mut op: Op,
        uid: i64,
        key_id: KeyId,
        token: u64,
        (second_step, pressed): (bool, BindingRole),
    ) -> Staging {
        let tainted = self.live > 0 || token != self.epoch;
        // Read before the list is taken for the write; nothing below changes the person's keys
        // before the key is staged.
        let owner_here = self.owner_on_pc(uid);
        let (live, epoch) = (self.live, self.epoch);
        let Some(store) = self.store.as_mut() else {
            op.answer(Err(TrustedError::Refused));
            return Staging::Done;
        };
        // The role read again here: one derived otherwise than at the press cancels it (`role`).
        let check = attempt_allow_check(store, uid, &key_id, second_step, (owner_here, pressed));
        if let Err(e) = check {
            op.answer(Err(e));
            return Staging::Done;
        }
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            telegram_user_id = uid,
            kid = %key_id.short(),
            tainted,
            live,
            token,
            epoch,
            "trusted devices: allow at its stage: {}",
            if tainted {
                "a session since the dialog opened: nothing written (the attempt stays)"
            } else {
                "a clean window: the key joins confirmed"
            }
        );
        if tainted {
            op.answer(Err(TrustedError::Tainted));
            return Staging::Done;
        }
        let Some(attempt) = store.attempt(uid, &key_id).cloned() else {
            op.answer(Err(TrustedError::NotFound));
            return Staging::Done;
        };
        // §5: an owner on this PC (a working owner-role key, or the owner by the bindings) gets
        // only the owner's role — never a new guest key; anyone else a guest's. The name may come
        // from any listed record of theirs.
        tracing::debug!(
            telegram_user_id = uid,
            owner_here,
            "trusted devices: allow: the key gets the {} role",
            if owner_here { "owner's" } else { "guest's" }
        );
        let (person, role) = match store.person_keys(uid) {
            Ok(keys) => {
                if keys.owner_keys_not_working() {
                    // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
                    tracing::debug!(
                        telegram_user_id = uid,
                        kid = %key_id.short(),
                        owner_records = keys.listed_owner.len(),
                        "trusted devices: allow: owner-role keys that do not work give no role"
                    );
                }
                (
                    store.person_names(uid).cloned(),
                    if owner_here {
                        BindingRole::Owner
                    } else {
                        BindingRole::Guest
                    },
                )
            }
            Err(_) => (None, BindingRole::Guest),
        };
        let person = person.unwrap_or(Person {
            telegram_user_id: uid,
            first_name: None,
            username: None,
        });
        let new = NewKey {
            key: attempt.key,
            rpk: attempt.rpk,
            kind: attempt.kind,
            platform: attempt.platform,
        };
        let ground = Ground::Pair {
            person,
            role,
            unconfirmed: false,
        };
        match store.stage_add(new, ground, crate::journal::now_ms()) {
            Ok(staged) => self.launch(op, Change::Add(staged)),
            Err(e) => {
                self.retry_or_fail(op, &e);
                Staging::Done
            }
        }
    }

    /// A staged change goes to the blocking pool as the change in flight.
    fn launch(&mut self, op: Op, change: Change) -> Staging {
        let untrusted = self.leaving(&op);
        let job = self.next_job();
        tracing::debug!(
            op = op.kind.as_str(),
            job,
            attempt = op.attempts + 1,
            leaving = untrusted.len(),
            "trusted devices: staged; writing on the blocking pool"
        );
        self.flight = Flight::Writing {
            job,
            op,
            started: Instant::now(),
            untrusted,
        };
        self.spawn(job, move || Finished::Wrote(change.write()));
        Staging::Started
    }

    /// The active keys a staged removal takes, as the journal will name them (read before the
    /// install, while the store still has their records).
    fn leaving(&self, op: &Op) -> Vec<Untrusted> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        let ids: Vec<KeyId> = match &op.kind {
            OpKind::RemoveKey { key_id, .. } => vec![key_id.clone()],
            _ => Vec::new(),
        };
        // «Нажатие решает сразу»: every ordinary write carries the pending removals — a removal's
        // own (a write of memory) and other presses' alike; a removal is journaled once, by the
        // write that takes it to the disk, whichever change that is (a restore or a reset of a
        // damaged list carries nothing).
        let carried = if matches!(op.kind, OpKind::Restore { .. } | OpKind::Reset) {
            Vec::new()
        } else {
            store.carried_now()
        };
        let mut ids = ids;
        let own = ids.len();
        for id in carried {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        if ids.len() > own {
            tracing::debug!(
                op = op.kind.as_str(),
                own,
                carried = %short_list(&ids[own..]),
                "trusted devices: the write carries pending removals; journaled with it"
            );
        }
        if ids.is_empty() {
            return Vec::new();
        }
        ids.iter()
            .filter_map(|id| store.listed(id))
            .map(|l| l.record)
            .map(|r| Untrusted {
                uid: r.person.telegram_user_id,
                first_name: r.person.first_name.clone(),
                username: r.person.username.clone(),
                device: JournalDevice {
                    kind: r.kind.as_str().to_string(),
                    platform: r.platform.as_str().to_string(),
                    source: r.source.as_str().to_string(),
                },
            })
            .collect()
    }

    fn next_job(&mut self) -> u64 {
        let job = self.next_job;
        self.next_job = self.next_job.wrapping_add(1);
        job
    }

    /// Run `work` on the blocking pool; its result (and `slow` past the limit) comes back through
    /// `notify`. The async task that waits holds no lock and blocks no worker.
    fn spawn(&mut self, job: u64, work: impl FnOnce() -> Finished + Send + 'static) {
        let notify = Arc::clone(&self.notify);
        let limit = self.write_limit;
        #[cfg(test)]
        let gate = self.gate.clone();
        #[cfg(test)]
        let panic_now = std::mem::take(&mut self.panic_next);
        let work = move || {
            #[cfg(test)]
            if let Some(gate) = gate {
                let _ = crate::sync::lock(&gate).recv_timeout(Duration::from_secs(10));
            }
            #[cfg(test)]
            #[allow(clippy::panic, reason = "a test's lost job")]
            if panic_now {
                panic!("a test's file job panics before it runs");
            }
            work()
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            // No runtime (never in the agent): here, now; the result is taken in like any other.
            tracing::warn!(
                job,
                "trusted devices: no async runtime; the job runs in place"
            );
            notify(TrustedDone {
                job,
                finished: work(),
            });
            return;
        };
        runtime.spawn(async move {
            let started = Instant::now();
            let mut handle = tokio::task::spawn_blocking(work);
            let joined = match tokio::time::timeout(limit, &mut handle).await {
                Ok(joined) => joined,
                Err(_) => {
                    tracing::warn!(
                        job,
                        limit_ms = limit.as_millis() as u64,
                        "trusted devices: the file job outlived its limit; its caller hears slow, \
                         and it lands when the disk answers"
                    );
                    notify(TrustedDone {
                        job,
                        finished: Finished::Slow,
                    });
                    let joined = handle.await;
                    tracing::info!(
                        job,
                        took_ms = started.elapsed().as_millis() as u64,
                        "trusted devices: the slow file job ended"
                    );
                    joined
                }
            };
            let finished = joined.unwrap_or_else(|e| Finished::Lost(e.to_string()));
            notify(TrustedDone { job, finished });
        });
    }

    fn start_reopen(&mut self, op: Option<Op>) {
        let Some(store) = &self.store else {
            if let Some(mut op) = op {
                op.answer(Err(TrustedError::Refused));
            }
            return;
        };
        let paths = store.paths();
        let job = self.next_job();
        tracing::debug!(
            job,
            asked = op.is_some(),
            "trusted devices: reopening the list on the blocking pool"
        );
        self.flight = Flight::Reopening {
            job,
            op,
            started: Instant::now(),
        };
        self.spawn(job, move || {
            let load = TrustStore::reopen_load(&paths);
            let restorable = TrustStore::backup_restorable(&paths);
            Finished::Reopened { load, restorable }
        });
    }

    // --- Results ------------------------------------------------------------------------------

    /// A blocking job's result, on the main loop.
    pub fn on_done(&mut self, done: TrustedDone, live: usize, journal: Option<&Journal>) {
        self.sync_live(live);
        let TrustedDone { job, finished } = done;
        let current = match &self.flight {
            Flight::Writing { job: j, .. } | Flight::Reopening { job: j, .. } => Some(*j),
            Flight::Idle => None,
        };
        if current != Some(job) {
            tracing::warn!(
                job,
                current = ?current,
                "trusted devices: a result for a job that is not the one in flight; dropped"
            );
            return;
        }
        match finished {
            Finished::Slow => {
                if let Flight::Writing {
                    op:
                        Op {
                            kind: OpKind::Admit { ticket, .. },
                            ..
                        },
                    ..
                } = &self.flight
                {
                    // The session stops waiting (spec §3.4 step 9); the write lands later.
                    self.landed.push(Landed {
                        ticket: *ticket,
                        slow: true,
                        result: Err(StoreError::Write("slow".to_string())),
                    });
                }
                match &mut self.flight {
                    Flight::Writing { op, .. } => op.answer(Err(TrustedError::Slow)),
                    Flight::Reopening { op: Some(op), .. } => op.answer(Err(TrustedError::Slow)),
                    _ => {}
                }
                return;
            }
            Finished::Lost(why) => {
                let flight = std::mem::replace(&mut self.flight, Flight::Idle);
                tracing::error!(
                    job,
                    "trusted devices: the file job's thread failed ({why}); the change is lost, \
                     the list is read again"
                );
                self.reopen_wanted = true;
                match flight {
                    Flight::Writing { op, .. } => self.retry_or_fail(op, &StoreError::NeedsReopen),
                    Flight::Reopening {
                        op: Some(mut op), ..
                    } => {
                        op.answer(Err(TrustedError::WriteFailed));
                    }
                    _ => {}
                }
            }
            Finished::Wrote(wrote) => {
                let Flight::Writing {
                    op,
                    started,
                    untrusted,
                    ..
                } = std::mem::replace(&mut self.flight, Flight::Idle)
                else {
                    return;
                };
                self.take_written(op, wrote, started, untrusted, journal);
            }
            Finished::Reopened { load, restorable } => {
                let Flight::Reopening { op, started, .. } =
                    std::mem::replace(&mut self.flight, Flight::Idle)
                else {
                    return;
                };
                self.take_reopen(op, load, restorable, started);
            }
        }
        self.after_change();
        self.pump();
    }

    fn take_written(
        &mut self,
        mut op: Op,
        wrote: Wrote,
        started: Instant,
        untrusted: Vec<Untrusted>,
        journal: Option<&Journal>,
    ) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let took_ms = started.elapsed().as_millis() as u64;
        let mut outcome = LandedOutcome::Unit;
        let installed: Result<u32, StoreError> = match wrote {
            Wrote::Unit(Ok(w)) => store.install(w).map(|()| op.count()).map_err(|n| n.error),
            Wrote::Keys(Ok(w)) => store
                .install(w)
                .map(|ids| u32::try_from(ids.len()).unwrap_or(u32::MAX))
                .map_err(|n| n.error),
            Wrote::Add(Ok(w)) => store
                .install(w)
                .map(|o| {
                    outcome = LandedOutcome::Added(o);
                    0
                })
                .map_err(|n| n.error),
            Wrote::Recover(Ok(w)) => store
                .install(w)
                .map(|o| {
                    let replaced = u32::try_from(o.replaced.len()).unwrap_or(u32::MAX);
                    outcome = LandedOutcome::Recovered(o);
                    replaced
                })
                .map_err(|n| n.error),
            Wrote::Unit(Err(f)) => Err(abandoned(store, f)),
            Wrote::Keys(Err(f)) => Err(abandoned(store, f)),
            Wrote::Add(Err(f)) => Err(abandoned(store, f)),
            Wrote::Recover(Err(f)) => Err(abandoned(store, f)),
        };
        match installed {
            Ok(removed) => {
                if let OpKind::Admit { ticket, .. } = op.kind {
                    let landed = self
                        .landed_again(ticket, std::mem::replace(&mut outcome, LandedOutcome::Unit));
                    self.admit_landed(ticket, landed);
                }
                tracing::info!(
                    op = op.kind.as_str(),
                    removed,
                    took_ms,
                    "trusted devices: change installed"
                );
                if let OpKind::Restore { .. } | OpKind::Reset = op.kind {
                    self.backup_restorable = false;
                }
                if let (OpKind::AttemptAllow { key_id, .. }, LandedOutcome::Added(o)) =
                    (&op.kind, &outcome)
                {
                    self.journal_allowed(key_id, o, journal);
                }
                self.journal_installed(&op.kind, untrusted, journal);
                self.party_landed(&op);
                op.answer(Ok(removed));
                // The disk takes writes: what was parked tries again.
                self.unpark();
                self.publish(op.kind.as_str());
            }
            Err(e) => {
                tracing::debug!(
                    op = op.kind.as_str(),
                    reason = e.as_str(),
                    took_ms,
                    "trusted devices: change not installed ({e})"
                );
                // An abandon after `ChangedOnDisk` reloaded the list.
                self.publish("not installed");
                self.retry_or_fail(op, &e);
            }
        }
    }

    fn take_reopen(
        &mut self,
        op: Option<Op>,
        load: ReopenLoad,
        restorable: bool,
        started: Instant,
    ) {
        let Some(store) = self.store.as_mut() else {
            return;
        };
        let reloaded = store.take_reopen(load);
        self.backup_restorable = restorable;
        tracing::info!(
            took_ms = started.elapsed().as_millis() as u64,
            damaged = store.damage().map_or("no", |d| d.kind.as_str()),
            left = reloaded.left_active.len(),
            joined = reloaded.joined_active.len(),
            changed = reloaded.changed.len(),
            inherited_pending = reloaded.inherited_pending.len(),
            stale = reloaded.needs_reopen,
            backup_restorable = restorable,
            "trusted devices: the list read again (no session is signed yet, so none ends for a \
             key that left)"
        );
        let damaged = store.is_damaged();
        if reloaded.needs_reopen {
            self.reopen_wanted = true;
        }
        self.publish("reopened");
        if let Some(mut op) = op {
            if reloaded.needs_reopen {
                // Read again first; the window hears when that one lands.
                self.requeue_front(op);
            } else {
                op.answer(Ok(0));
                if damaged {
                    tracing::debug!(
                        parked = self.parked.len(),
                        "trusted devices: the reopen read a damaged list; parked removals are not \
                         tried again (the damage drops them)"
                    );
                } else {
                    self.unpark();
                }
            }
        }
    }

    /// §10 «Повреждённый список»: the list is damaged, so what waits is lost with memory, as at a
    /// restart before the write — every queued and parked change but a repair (`Reopen`,
    /// `Restore`, `Reset`) is answered `damaged` and dropped (an admission's hears it as its
    /// landing). Nothing of it replays after the repair: the binding list's rule decides then.
    fn drop_waiting(&mut self) {
        let (kept, dropped): (Vec<Op>, Vec<Op>) = std::mem::take(&mut self.queue)
            .into_iter()
            .chain(std::mem::take(&mut self.parked))
            .partition(|o| o.kind.is_repair());
        self.queue = kept.into();
        self.parked_at = None;
        if dropped.is_empty() {
            tracing::debug!(
                repairs_kept = self.queue.len(),
                "trusted devices: the list is damaged; nothing waits to be dropped"
            );
            return;
        }
        tracing::warn!(
            dropped = dropped.len(),
            removals = dropped.iter().filter(|o| o.kind.is_removal()).count(),
            repairs_kept = self.queue.len(),
            "trusted devices: the list is damaged: the waiting changes are answered damaged and \
             dropped (nothing replays after the repair)"
        );
        for mut op in dropped {
            tracing::debug!(
                op = op.kind.as_str(),
                kids = %short_list(&op.denied),
                "trusted devices: dropped, the list is damaged"
            );
            match op.kind {
                OpKind::Admit { ticket, .. } => self.admit_landed(ticket, Err(StoreError::Damaged)),
                _ => op.answer(Err(TrustedError::Damaged)),
            }
        }
    }

    /// After every install, abandon and reopen: a due reopen; on a damaged list the waiting
    /// changes go ([`Self::drop_waiting`]); the keys that inherited a pending removal get one of
    /// their own; the binding list's rule.
    fn after_change(&mut self) {
        let Some(store) = &self.store else {
            return;
        };
        if store.needs_reopen() {
            self.reopen_wanted = true;
        }
        if store.is_damaged() {
            self.drop_waiting();
            return;
        }
        let pending = store.pending_without_removal();
        let mut queued = Vec::new();
        for p in pending {
            let covered = self.queue.iter().any(|o| o.covers(&p.key_id))
                || self.parked.iter().any(|o| o.covers(&p.key_id))
                || matches!(&self.flight, Flight::Writing { op, .. } if op.covers(&p.key_id));
            if covered {
                continue;
            }
            // The origin is memory's (the key's carry, its root's for an inherited one): this
            // queue only makes sure a write takes it.
            let by = p.by;
            tracing::debug!(
                kid = %p.key_id.short(),
                from = p.inherited_from.as_ref().map_or("-", KeyId::short),
                by = ?by,
                "trusted devices: a key denied with no removal queued; its removal queued"
            );
            queued.push(Op {
                denied: vec![p.key_id.clone()],
                ..Op::new(
                    OpKind::RemoveKey {
                        key_id: p.key_id,
                        by,
                    },
                    None,
                )
            });
        }
        // Carried with that origin — nothing new for a key memory carries already (an inherited
        // one is from its join): any later write that lands takes them.
        if let Some(store) = self.store.as_mut() {
            for op in &queued {
                if let OpKind::RemoveKey { key_id, by } = &op.kind {
                    store.carry_removal(
                        std::slice::from_ref(key_id),
                        *by,
                        crate::journal::now_ms(),
                    );
                }
            }
        }
        for op in queued {
            self.enqueue(op);
        }
        // §10 «Сверка со списком сервера»: after every installed change — a repair's landing
        // included — the list is brought to the rule by the current list.
        self.bring_to_rule("a change landed");
    }

    /// A refusal at the stage or the write: retry (a reopen first when the store asks for one),
    /// park a removal whose write ran out of attempts, or answer (and drop).
    fn retry_or_fail(&mut self, mut op: Op, e: &StoreError) {
        let retryable = matches!(
            e,
            StoreError::Busy
                | StoreError::Write(_)
                | StoreError::ChangedOnDisk
                | StoreError::NeedsReopen
                | StoreError::StaleBase
        );
        if matches!(e, StoreError::NeedsReopen | StoreError::StaleBase) {
            self.reopen_wanted = true;
        }
        // §10 «Повреждённый список»: a list found damaged under this change (its abandon read the
        // file again) is what holds now — a change but a repair is answered `damaged` and
        // dropped, never retried, parked or answered `write_failed`: its decision went with
        // memory, and what waits goes too ([`Self::drop_waiting`]).
        if !op.kind.is_repair() && self.store.as_ref().is_some_and(TrustStore::is_damaged) {
            tracing::debug!(
                op = op.kind.as_str(),
                reason = e.as_str(),
                attempt = op.attempts + 1,
                "trusted devices: the list is damaged now ({e}); answered damaged and dropped"
            );
            match op.kind {
                OpKind::Admit { ticket, .. } => self.admit_landed(ticket, Err(StoreError::Damaged)),
                _ => op.answer(Err(TrustedError::Damaged)),
            }
            return;
        }
        if retryable && op.attempts + 1 < MAX_ATTEMPTS {
            op.attempts += 1;
            tracing::debug!(
                op = op.kind.as_str(),
                reason = e.as_str(),
                attempt = op.attempts,
                max = MAX_ATTEMPTS,
                reopen_first = self.reopen_wanted,
                "trusted devices: retryable refusal; tried again"
            );
            self.requeue_front(op);
            return;
        }
        if let OpKind::Admit { ticket, .. } = op.kind {
            self.admit_landed(ticket, Err(e.clone()));
            return;
        }
        let code = if retryable {
            TrustedError::WriteFailed
        } else {
            TrustedError::of(e)
        };
        let removal = op.kind.is_removal();
        // A removal's write that ran out of attempts waits: its keys stay denied and the carry
        // needs a write to ride; the window still hears why. Not a damaged list's: memory lost
        // the decision with it (§10 «Повреждённый список»), so the op is answered and dropped.
        if removal && retryable {
            tracing::warn!(
                op = op.kind.as_str(),
                reason = e.as_str(),
                attempts = op.attempts + 1,
                kids = %short_list(&op.denied),
                "trusted devices: a removal could not be saved; its keys stay denied and its write \
                 of memory is tried again after the next saved change, and every minute"
            );
            op.answer(Err(code));
            op.attempts = 0;
            self.park(op);
            return;
        }
        // not-a-key-name: `code` is the window's refusal code (session, damaged, …)
        tracing::debug!(
            op = op.kind.as_str(),
            reason = e.as_str(),
            code = code.as_str(),
            "trusted devices: refused ({e}); the change is dropped"
        );
        if removal && !op.denied.is_empty() {
            // Not the keys another waiting removal still takes: they stay denied for it.
            let free: Vec<KeyId> = op
                .denied
                .iter()
                .filter(|id| {
                    !self.queue.iter().any(|o| o.covers(id))
                        && !self.parked.iter().any(|o| o.covers(id))
                })
                .cloned()
                .collect();
            if free.len() != op.denied.len() {
                tracing::debug!(
                    kept = op.denied.len() - free.len(),
                    "trusted devices: undeny skips keys another waiting removal takes"
                );
            }
            if let Some(store) = self.store.as_mut() {
                store.undeny(&free);
            }
        }
        op.answer(Err(code));
    }

    /// Queue the parked removals again. Each is a write of memory as it is now ([`Self::stage`]):
    /// it decides nothing again — no key is denied — so a decision
    /// made at the PC since stands, and one whose memory a landed write took finds nothing to do.
    fn unpark(&mut self) {
        if self.parked.is_empty() {
            return;
        }
        tracing::debug!(
            parked = self.parked.len(),
            "trusted devices: parked removals queued again (each writes memory as it is now; \
             nothing is decided again)"
        );
        self.parked_at = Some(Instant::now());
        for op in std::mem::take(&mut self.parked) {
            self.enqueue(op);
        }
    }

    /// «Разрешить» installed: «Новое устройство» in the journal, «Разрешено на ПК» (source
    /// `pair`), a known guest's new device when the person had keys here. No toast: the person
    /// at the PC did it.
    fn journal_allowed(&self, key_id: &KeyId, added: &AddOutcome, journal: Option<&Journal>) {
        let Some(journal) = journal else {
            return;
        };
        let Some(Lookup::Active(r)) = self.store.as_ref().map(|s| s.lookup(key_id)) else {
            // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
            tracing::warn!(
                kid = %key_id.short(),
                "trusted devices: the allowed key is not active after its install; not journaled"
            );
            return;
        };
        let name = crate::person_name(
            r.person.telegram_user_id,
            r.person.first_name.as_deref(),
            r.person.username.as_deref(),
        );
        let guest_new_device = added.known_person && added.role == BindingRole::Guest;
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            kid = %key_id.short(),
            unconfirmed = added.unconfirmed,
            guest_new_device,
            "trusted devices: allowed at the PC; journaled"
        );
        journal.device_added(
            crate::journal::Person {
                user: r.person.telegram_user_id,
                name: &name.text,
                username: r.person.username.as_deref(),
            },
            JournalDevice {
                kind: r.kind.as_str().to_string(),
                platform: r.platform.as_str().to_string(),
                source: r.source.as_str().to_string(),
            },
            None,
            guest_new_device,
            crate::journal::now_ms(),
        );
    }

    fn journal_installed(
        &self,
        kind: &OpKind,
        untrusted: Vec<Untrusted>,
        journal: Option<&Journal>,
    ) {
        let Some(journal) = journal else {
            return;
        };
        let now = crate::journal::now_ms();
        if let OpKind::SetMode { on, .. } = kind {
            journal.trusted_event(
                if *on {
                    Kind::TrustedOn
                } else {
                    Kind::TrustedOff
                },
                None,
                None,
                now,
            );
        }
        // The keys this write took off the list: its own removal's and every other press's it
        // carried (journaled once, here, when they reach the disk).
        for u in untrusted {
            let name = crate::person_name(u.uid, u.first_name.as_deref(), u.username.as_deref());
            journal.trusted_event(
                Kind::DeviceUntrusted,
                Some(crate::journal::Person {
                    user: u.uid,
                    name: &name.text,
                    username: u.username.as_deref(),
                }),
                Some(u.device),
                now,
            );
        }
    }

    // --- The view -----------------------------------------------------------------------------

    fn publish(&mut self, why: &str) {
        self.rev = self.rev.wrapping_add(1);
        // One reading of the wall clock for the view's attempts and their age-out
        // deadline — an attempt crossing its 30 days between two readings would be shown with no
        // deadline to take it out.
        let now_ms = self.store.as_ref().map(TrustStore::wall_now);
        let view = self.build_view(now_ms.unwrap_or(0));
        #[cfg(test)]
        if let (Some(t), Some(store)) = (self.cross_after_view.take(), self.store.as_mut()) {
            store.set_wall_now(t);
        }
        self.attempts_age_out_at = self
            .store
            .as_ref()
            .zip(now_ms)
            .and_then(|(store, now_ms)| store.attempts_age_out_at(now_ms));
        // not-a-key-name: `keys` is a count of access keys in the list, not a pressed key
        tracing::debug!(
            why,
            rev = view.rev,
            damaged = view.damage.map_or("no", |d| d.kind.as_str()),
            people = view.people.len(),
            keys = view.people.iter().map(|p| p.devices.len()).sum::<usize>(),
            waiting = view.waiting.len(),
            parties = view.parties.len(),
            clean = view.clean,
            token = view.token,
            full = view.full,
            trusted_mode = view.trusted_mode,
            owner_device = view.owner_device.as_str(),
            age_out_at = ?self.attempts_age_out_at,
            "trusted devices: view published"
        );
        self.view.send_replace(Arc::new(view));
    }

    /// The view at the wall-clock reading `now_ms` (the attempts that count at it).
    fn build_view(&self, now_ms: i64) -> TrustedView {
        let mut view = TrustedView {
            rev: self.rev,
            damage: None,
            trusted_mode: false,
            people: Vec::new(),
            waiting: Vec::new(),
            owner_device: OwnerDevice::Missing,
            clean: self.live == 0,
            token: self.epoch,
            full: false,
            parties: Vec::new(),
        };
        let Some(store) = &self.store else {
            view.damage = Some(TrustedDamage {
                kind: DamageKind::Unreadable,
                can_restore: false,
                can_reset: false,
            });
            // No list: the admission is strict (`Agent::admission_strict`), and so is the window.
            view.trusted_mode = true;
            return view;
        };
        if let Some(d) = store.damage() {
            let repairable = !matches!(d.kind, DamageKind::Unreadable | DamageKind::NewerVersion);
            view.damage = Some(TrustedDamage {
                kind: d.kind,
                can_restore: repairable && self.backup_restorable,
                can_reset: repairable,
            });
            // The switch the admission decides by while damaged: the mode file's, strict when it
            // says nothing (missing or unusable) — so the window's «Доступ» says what admits.
            let mode = store.damaged_mode();
            view.trusted_mode = mode.unwrap_or(true);
            tracing::trace!(
                mode_file = match mode {
                    Some(true) => "strict",
                    Some(false) => "observe",
                    None => "none (strict)",
                },
                "trusted devices: a damaged list's switch for the view"
            );
            return view;
        }
        // Strict mode before admission: storing the switch is all it does. Nothing reads it to
        // admit or refuse yet — admission (§3.4 «Строгий режим») wires it, and turning it on then
        // also ends every live and pending session that is not signed (§10).
        view.trusted_mode = store
            .switches()
            .map(|s| s.trusted_devices_mode)
            .unwrap_or(false);
        let dependents = store.dependents().unwrap_or_default();
        let device_ref = |r: &KeyRecord| DeviceRef {
            kind: r.kind.clone(),
            platform: r.platform.clone(),
        };
        // Every listed record shows until the write that takes it lands (a leaving one too).
        let people = store.listed_people().unwrap_or_default();
        for (uid, records) in &people {
            let uid = *uid;
            let latest = records.iter().map(|l| l.record).max_by_key(|r| r.added_at);
            // The role shown is the one a press gives: the owner's for an owner on this PC
            // ([`Self::owner_on_pc`]). The second step stays on the strict side (any
            // owner-role record), as the press checks it.
            let owner_here = self.owner_on_pc(uid);
            let owner_record = records.iter().any(|l| l.record.role == BindingRole::Owner);
            let attempts = self.attempts_of_at(uid, now_ms);
            let devices = records
                .iter()
                .map(|l| l.record)
                .map(|r| {
                    let signer = store.signed_by(r.key_id()).ok().flatten();
                    TrustedDeviceView {
                        key_id: r.key_id().clone(),
                        device: device_ref(r),
                        role: r.role,
                        source: r.source.as_str(),
                        party: match &r.source {
                            KeySource::Party { party_id, .. } => Some(party_id.clone()),
                            _ => None,
                        },
                        by: signer.and_then(|(_, l)| l).map(|l| device_ref(l.record)),
                        by_key_id: signer.map(|(by, _)| by.clone()),
                        unconfirmed: r.unconfirmed,
                        dependents: dependents.get(r.key_id()).copied().unwrap_or(0),
                        added_at: r.added_at,
                        last_used_at: r.last_used_at,
                        in_session: false,
                    }
                })
                .collect();
            view.people.push(TrustedPerson {
                telegram_user_id: uid,
                first_name: latest.and_then(|r| r.person.first_name.clone()),
                username: latest.and_then(|r| r.person.username.clone()),
                devices,
                attempts,
                role: if owner_here {
                    BindingRole::Owner
                } else {
                    BindingRole::Guest
                },
                needs_second_step: owner_here || owner_record,
            });
        }
        // People with attempts and no key here (a removed guest trying again, a new device of a
        // person the PC never had a key of): after the people with keys, in the attempts' order.
        // Named by the server's bindings in the window; their role here is the one a press
        // gives: the owner's for the owner by the bindings.
        let mut attempt_only: Vec<i64> = Vec::new();
        for a in store.attempts_at(now_ms) {
            let uid = a.telegram_user_id;
            if !people.iter().any(|(p, _)| *p == uid) && !attempt_only.contains(&uid) {
                attempt_only.push(uid);
            }
        }
        for uid in attempt_only {
            let owner_here = self.owner_on_pc(uid);
            let attempts = self.attempts_of_at(uid, now_ms);
            view.people.push(TrustedPerson {
                telegram_user_id: uid,
                first_name: None,
                username: None,
                devices: Vec::new(),
                attempts,
                role: if owner_here {
                    BindingRole::Owner
                } else {
                    BindingRole::Guest
                },
                needs_second_step: owner_here,
            });
        }
        view.waiting = store.snapshot_people_without_keys().unwrap_or_default();
        view.owner_device = store.owner_device();
        view.full = store.full().ok().flatten().is_some();
        let delegations = store.delegations().unwrap_or_else(|e| {
            tracing::debug!(
                reason = e.as_str(),
                "trusted devices: the parties do not read ({e}); the window shows none"
            );
            &[]
        });
        view.parties = delegations
            .iter()
            .map(|d| TrustedParty {
                party_id: d.party_id.clone(),
                party: crate::person_name::clean_name(&d.party).trim().to_owned(),
                leader: d.leader.clone(),
            })
            .collect();
        view
    }
}

/// End a failed write: abandon it (an abandon after `ChangedOnDisk` reloads the file) and say
/// what the reload changed. The write's error.
fn abandoned<T>(store: &mut TrustStore, failed: WriteFailed<T>) -> StoreError {
    let error = failed.error().clone();
    match store.abandon(failed) {
        Some(reloaded) => tracing::info!(
            reason = error.as_str(),
            left = reloaded.left_active.len(),
            joined = reloaded.joined_active.len(),
            changed = reloaded.changed.len(),
            damaged = reloaded.damaged,
            "trusted devices: a write failed and the list was read again (no session is signed \
             yet, so none ends for a key that left)"
        ),
        None => tracing::debug!(
            reason = error.as_str(),
            "trusted devices: a write failed; the list is as it was"
        ),
    }
    error
}

/// `Reopen` never reaches the stage's match (it starts a reopen first).
fn unreachable_reopen() -> Result<Option<Change>, StoreError> {
    Err(StoreError::Invalid("reopen is not a staged change".into()))
}

fn short_list(ids: &[KeyId]) -> String {
    ids.iter().map(KeyId::short).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests;
