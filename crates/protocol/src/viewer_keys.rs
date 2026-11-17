//! Viewer device keys, milestone 1, on the wire: the agent's side of the contract's
//! `viewer-keys.ts` (constants, vocabularies, strict base64url) and `viewer-keys-wire.ts` (the shapes
//! and the limits on the opaque values). Spec: `docs/design/viewer-device-keys-protocol.md` rev 3 in
//! the umbrella.
//!
//! What is here is form only. The messages that carry device keys are in [`crate::agent_ws`]
//! (`session_nonces`, `agent_ready.nonce_pool`, `session_request.nonce_pc`, `sdp.proof`,
//! `pair_request.viewer_key`, `pair_response.key_id`), the DataChannel's `ks` is [`KeyStatus`] (an
//! [`crate::AgentDataMessage`] variant) and the summary's `key_*` fields are on
//! [`crate::metrics::AgentSessionSummary`]. Hashing, signatures, the nonce book, the key list and
//! every decision of the spec's §3.4 belong to `afklink_core`: nothing here verifies anything.
//!
//! ## Opaque values and their limits (§1.2)
//!
//! `sdp.proof` and `pair_request.viewer_key` arrive as `serde_json::Value`: a field the agent could
//! not parse must cost a verdict, never the frame (a frame that does not parse is dropped whole, and
//! the offer or the prompt with it). The server is the attacker here, so the agent holds them to the
//! spec's limits itself, **before** any parsing of their fields or any cryptography:
//! [`check_proof_wire`] and [`check_viewer_key_wire`]. Over a limit is `proof_invalid:malformed`
//! (`admit_refused:key_reg_bad` for a `viewer_key`) — the caller's decision, not this module's.
//!
//! One case is not protected, as for `session_request.quality_profile`: JSON that `serde_json` cannot
//! hold as a `Value` at all — nesting past its recursion limit (128), a number out of `f64` range —
//! fails the whole message's parse (the message enums are internally tagged, so serde buffers the
//! whole message first). The server holds both values to [`PROOF_MAX_DEPTH`] before it relays them
//! (`proofWireSchema`, `viewerKeyWireSchema`), so only a server that is not ours sends one, and then
//! the offer is lost, not trusted.
//!
//! ## Logs (§1.4)
//!
//! Nothing here logs. A caller never logs `nonce_pc`, a `proof` (whole or its signatures),
//! `attest.init_data` or a DTLS fingerprint; a `key_id` only as its first [`KEY_ID_LOG_CHARS`]
//! characters ([`key_id_for_log`]).
//!
//! Held to the contract by `tests/viewer_keys.rs` (constants, vocabularies, the `ks` schema, the
//! base64url vectors) and by the golden fixtures (`tests/fixtures.rs`).

use std::fmt;
use std::io;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::metrics::{is_end_detail_code, InvalidField};

/* --- constants (§12, `viewer-keys.ts`) ------------------------------------------------------- */

/// `nonce_pc`: 16 bytes from the PC's CSPRNG (§2.2).
pub const NONCE_BYTES: usize = 16;
/// Nonces per `session_nonces` batch, all different.
pub const NONCE_BATCH: usize = 4;
/// The PC sends a new batch this often while its socket lives.
pub const NONCE_ROTATE_MS: u64 = 60_000;
/// A refill asked by `session_request` (§2.2 (c)): at most once per this window, deferred, not lost.
pub const NONCE_REFILL_MIN_MS: u64 = 2_000;
/// The server hands out a batch's nonces only while the batch is at most this old (its clock).
pub const NONCE_SERVE_MS: u64 = 100_000;
/// A nonce is valid at most this long after its batch was issued, inclusive (the PC's clock).
pub const NONCE_TTL_MS: u64 = 180_000;
/// The PC's nonce book remembers batches this long, so an expired nonce is told from a foreign one.
pub const NONCE_BOOK_KEEP_MS: u64 = 360_000;
/// Batches the book holds at most; past it the oldest go (with a `warn`).
pub const NONCE_BOOK_MAX_BATCHES: usize = 192;
/// `grant.issued_at - invite.issued_at` at most (§7): the invite's 24 h plus 1 h of clock skew.
pub const INVITE_GRANT_WINDOW_MS: u64 = 90_000_000;
/// The clock skew allowed between two of the owner's devices in an invite and its grant: the
/// difference above may be negative down to minus this.
pub const INVITE_GRANT_SKEW_MS: u64 = 3_600_000;
/// Bases (`proof.admit`) in one proof at most.
pub const ADMIT_MAX: usize = 4;
/// Active keys per person on one PC.
pub const KEYS_PER_PERSON: usize = 16;
/// All keys on one PC.
pub const KEYS_MAX: usize = 256;
/// Revoked keys and spent ids, each list.
pub const REVOKED_MAX: usize = 4096;
/// `proof` at most, as compact JSON in UTF-8 (`serde_json::to_vec`; the contract: `JSON.stringify`).
pub const PROOF_MAX_BYTES: usize = 16_384;
/// JSON nesting of a `proof` (and of a `viewer_key`) at most; the object itself is level 1.
pub const PROOF_MAX_DEPTH: usize = 8;
/// `pair_request.viewer_key` (a `key_reg`) at most, compact JSON in UTF-8.
pub const VIEWER_KEY_MAX_BYTES: usize = 1_024;
/// `attest.init_data` at most, UTF-8 bytes.
pub const ATTEST_INIT_DATA_MAX_BYTES: usize = 4_096;
/// Offers whose signatures the PC checks per second at most (§3.4, a token bucket); past it `busy`.
pub const VERIFY_RATE_PER_S: u32 = 20;
/// `proof.v`, `endorse.v`, `invite_sig.v`, `grant.v`.
pub const VIEWER_KEYS_VERSION: u32 = 1;
/// A `key_id` in a log: its first characters only (§1.4).
pub const KEY_ID_LOG_CHARS: usize = 8;
/// The Mini App's launch parameter for recovery's attestation (§8.2): `k_<key_id>`.
pub const RECOVER_START_PARAM_PREFIX: &str = "k_";

/// Sizes of the binary values (§1.2, `VIEWER_KEY_BYTES`), in bytes; on the wire
/// [`b64url_len`] characters.
pub mod bytes {
    /// `key_id`.
    pub const KEY_ID: usize = 32;
    /// A DTLS fingerprint (`fp_viewer`).
    pub const FINGERPRINT: usize = 32;
    /// `nonce_pc`, `nonce_n`, `nonce_o`, the secret `s`.
    pub const NONCE: usize = 16;
    /// `endorse_id`, `grant_id`, `inv_id`, a non-empty `grant_token`.
    pub const ID: usize = 16;
    /// `spki`, `rpk`.
    pub const SPKI: usize = 91;
    /// An ECDSA P-256 signature `r || s` (IEEE P1363), not DER.
    pub const SIGNATURE: usize = 64;
    /// HMAC-SHA-256 and SHA-256.
    pub const HMAC: usize = 32;
}

/* --- vocabularies -------------------------------------------------------------------------- */

/// The nine `session_end` reasons of device keys (§11, `KEY_END_REASONS`), all in the contract's
/// `SESSION_END_REASONS`. The agent sends them with `detail.ended_detail` from [`Self::details`].
/// In observe mode only `fingerprint_changed` and `key_list_damaged:write_failed` end a session; the
/// rest are the verdict in [`KeyStatus`] and the summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEndReason {
    /// `nonce_pc` missing or not valid; the viewer reconnects once by itself.
    NonceStale,
    /// Strict mode, a nonce was given and no `proof` came.
    KeyRequired,
    /// The PC does not know the key and no base came with it.
    KeyUnknown,
    /// Strict mode, the key is marked unconfirmed (§10.1).
    KeyUnconfirmed,
    /// A base for a new key was refused; `ended_detail` names which check.
    AdmitRefused,
    /// The key was removed from the PC.
    KeyRevoked,
    /// The signature did not hold.
    ProofInvalid,
    /// A re-offer in a live session carried another DTLS fingerprint.
    FingerprintChanged,
    /// The PC's key list could not be read or written.
    KeyListDamaged,
}

impl KeyEndReason {
    /// Every reason, in the contract's order.
    pub const ALL: [Self; 9] = [
        Self::NonceStale,
        Self::KeyRequired,
        Self::KeyUnknown,
        Self::KeyUnconfirmed,
        Self::AdmitRefused,
        Self::KeyRevoked,
        Self::ProofInvalid,
        Self::FingerprintChanged,
        Self::KeyListDamaged,
    ];

    /// The wire word (`session_end.reason`, `ks.verdict`, `summary.key_verdict`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonceStale => "nonce_stale",
            Self::KeyRequired => "key_required",
            Self::KeyUnknown => "key_unknown",
            Self::KeyUnconfirmed => "key_unconfirmed",
            Self::AdmitRefused => "admit_refused",
            Self::KeyRevoked => "key_revoked",
            Self::ProofInvalid => "proof_invalid",
            Self::FingerprintChanged => "fingerprint_changed",
            Self::KeyListDamaged => "key_list_damaged",
        }
    }

    /// The reason's `ended_detail` words (`SESSION_END_DETAILS` in the contract's `metrics.ts`), in
    /// the contract's order; empty for the four that have none.
    pub const fn details(self) -> &'static [&'static str] {
        match self {
            Self::NonceStale => &ended_detail::NONCE_STALE,
            Self::KeyRequired => &ended_detail::KEY_REQUIRED,
            Self::AdmitRefused => &ended_detail::ADMIT_REFUSED,
            Self::ProofInvalid => &ended_detail::PROOF_INVALID,
            Self::KeyListDamaged => &ended_detail::KEY_LIST_DAMAGED,
            Self::KeyUnknown
            | Self::KeyUnconfirmed
            | Self::KeyRevoked
            | Self::FingerprintChanged => &[],
        }
    }
}

impl fmt::Display for KeyEndReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `ended_detail` of the device-key reasons (`SESSION_END_DETAILS` in the contract's `metrics.ts`),
/// the agent's to send; the server holds each to its reason's list before it relays it to the viewer.
pub mod ended_detail {
    /// `nonce_stale`.
    pub const NONCE_STALE: [&str; 4] = ["no_nonce", "nonce_unknown", "nonce_expired", "nonce_used"];
    /// `key_required`.
    pub const KEY_REQUIRED: [&str; 1] = ["no_proof"];
    /// `admit_refused`: which check refused the base.
    pub const ADMIT_REFUSED: [&str; 29] = [
        "key_reg_bad",
        "limit",
        "rpk_conflict",
        "invite_missing",
        "invite_bad",
        "invite_spent",
        "invite_expired",
        "invite_owner_mismatch",
        "endorse_malformed",
        "endorse_key_mismatch",
        "endorse_signer_unknown",
        "endorse_signer_revoked",
        "endorse_spent",
        "endorse_bad_sig",
        "grant_malformed",
        "grant_key_mismatch",
        "grant_not_owner",
        "grant_role",
        "grant_spent",
        "grant_device",
        "grant_bad_sig",
        "grant_stale",
        "attest_bad",
        "attest_has_hash",
        "recover_malformed",
        "recover_no_record",
        "recover_bad_sig",
        "first_use_closed",
        "first_use_bad_sig",
    ];
    /// `proof_invalid`.
    pub const PROOF_INVALID: [&str; 6] = [
        "malformed",
        "fp_bad",
        "key_mismatch",
        "bad_sig",
        "proof_mismatch",
        "busy",
    ];
    /// `key_list_damaged`.
    pub const KEY_LIST_DAMAGED: [&str; 2] = ["read_failed", "write_failed"];
}

/// `ks.verdict` (§3.7, `KS_VERDICTS`): the key is active and confirmed on this PC, or a reason of
/// §11 (observe mode only: in strict mode a refused session has no channel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KsVerdict {
    Signed,
    NonceStale,
    KeyRequired,
    KeyUnknown,
    KeyUnconfirmed,
    AdmitRefused,
    KeyRevoked,
    ProofInvalid,
    FingerprintChanged,
    KeyListDamaged,
}

impl KsVerdict {
    /// Every verdict, in the contract's order: `signed`, then [`KeyEndReason::ALL`].
    pub const ALL: [Self; 10] = [
        Self::Signed,
        Self::NonceStale,
        Self::KeyRequired,
        Self::KeyUnknown,
        Self::KeyUnconfirmed,
        Self::AdmitRefused,
        Self::KeyRevoked,
        Self::ProofInvalid,
        Self::FingerprintChanged,
        Self::KeyListDamaged,
    ];

    /// The wire word; also `summary.key_verdict`.
    pub const fn as_str(self) -> &'static str {
        match self.reason() {
            None => "signed",
            Some(r) => r.as_str(),
        }
    }

    /// The reason, for every verdict but `signed`.
    pub const fn reason(self) -> Option<KeyEndReason> {
        Some(match self {
            Self::Signed => return None,
            Self::NonceStale => KeyEndReason::NonceStale,
            Self::KeyRequired => KeyEndReason::KeyRequired,
            Self::KeyUnknown => KeyEndReason::KeyUnknown,
            Self::KeyUnconfirmed => KeyEndReason::KeyUnconfirmed,
            Self::AdmitRefused => KeyEndReason::AdmitRefused,
            Self::KeyRevoked => KeyEndReason::KeyRevoked,
            Self::ProofInvalid => KeyEndReason::ProofInvalid,
            Self::FingerprintChanged => KeyEndReason::FingerprintChanged,
            Self::KeyListDamaged => KeyEndReason::KeyListDamaged,
        })
    }
}

impl From<KeyEndReason> for KsVerdict {
    fn from(r: KeyEndReason) -> Self {
        match r {
            KeyEndReason::NonceStale => Self::NonceStale,
            KeyEndReason::KeyRequired => Self::KeyRequired,
            KeyEndReason::KeyUnknown => Self::KeyUnknown,
            KeyEndReason::KeyUnconfirmed => Self::KeyUnconfirmed,
            KeyEndReason::AdmitRefused => Self::AdmitRefused,
            KeyEndReason::KeyRevoked => Self::KeyRevoked,
            KeyEndReason::ProofInvalid => Self::ProofInvalid,
            KeyEndReason::FingerprintChanged => Self::FingerprintChanged,
            KeyEndReason::KeyListDamaged => Self::KeyListDamaged,
        }
    }
}

/// `summary.key_verdict` of a session whose offer carried no `proof` (§11.1, `KEY_VERDICTS`); every
/// other verdict is a [`KsVerdict`]'s word.
pub const KEY_VERDICT_UNSIGNED: &str = "unsigned";

/// What added a key (`ks.admit`, `summary.key_admit`; `KEY_ADMITS`): «Разрешить» at the PC, or a
/// base the proof carried (`KEY_ADMIT_KINDS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAdmit {
    Pair,
    Endorse,
    Grant,
    Recover,
    FirstUse,
}

impl KeyAdmit {
    /// Every admit, in the contract's order.
    pub const ALL: [Self; 5] = [
        Self::Pair,
        Self::Endorse,
        Self::Grant,
        Self::Recover,
        Self::FirstUse,
    ];

    /// The wire word; also `summary.key_admit`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::Endorse => "endorse",
            Self::Grant => "grant",
            Self::Recover => "recover",
            Self::FirstUse => "first_use",
        }
    }

    /// The `proof.admit[].kind` this is (`KEY_ADMIT_KINDS`): every admit but `pair`. A `kind` this
    /// build does not know is skipped by the caller, never an error (§1.2).
    pub fn from_admit_kind(kind: &str) -> Option<Self> {
        match kind {
            "endorse" => Some(Self::Endorse),
            "grant" => Some(Self::Grant),
            "recover" => Some(Self::Recover),
            "first_use" => Some(Self::FirstUse),
            _ => None,
        }
    }
}

/// The PC's mode (`ks.mode`, `summary.key_mode`; `KEY_MODES`): watch only, or
/// «Доверенные устройства» on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMode {
    Observe,
    Strict,
}

impl KeyMode {
    /// Every mode, in the contract's order.
    pub const ALL: [Self; 2] = [Self::Observe, Self::Strict];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Strict => "strict",
        }
    }
}

/// What a device says it is (§4, `key_reg.kind`; `DEVICE_KINDS`): a claim for display only.
pub const DEVICE_KINDS: [&str; 3] = ["telegram", "telegram_desktop", "browser"];

/// `key_reg.platform` (§4, `DEVICE_PLATFORMS`).
pub const DEVICE_PLATFORMS: [&str; 7] = [
    "iphone", "ipad", "android", "mac", "windows", "linux", "unknown",
];

/// The longest `kind` and `platform` (`DEVICE_DESC_PATTERN`).
pub const DEVICE_DESC_MAX: usize = 24;

/// The form of `key_reg.kind` and `key_reg.platform` (`DEVICE_DESC_PATTERN`: `^[a-z0-9_]{1,24}$`).
/// A well-formed value off its list (a newer client) is signed and stored as sent, and displayed as
/// `unknown`.
pub fn is_device_desc(s: &str) -> bool {
    (1..=DEVICE_DESC_MAX).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/* --- strict base64url (§1.2) --------------------------------------------------------------- */

/// Characters of `bytes` bytes as base64url without padding.
pub const fn b64url_len(bytes: usize) -> usize {
    (bytes * 4).div_ceil(3)
}

fn b64url_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Strict base64url of exactly `bytes` bytes (§1.2, `b64urlDecodeStrict`): only `A–Z a–z 0–9 - _`,
/// no `=`, exactly [`b64url_len`] characters, the last character's unused low bits zero (so encoding
/// the result again gives the same string). `None` for anything else.
pub fn b64url_decode(s: &str, bytes: usize) -> Option<Vec<u8>> {
    let text = s.as_bytes();
    if text.len() != b64url_len(bytes) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in text {
        acc = (acc << 6) | u32::from(b64url_value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Truncation intended: the byte that just completed.
            out.push(((acc >> bits) & 0xff) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    // What is left are the last character's unused bits: zero, or the string is not canonical.
    (acc == 0 && out.len() == bytes).then_some(out)
}

/// [`b64url_decode`] succeeds: the form check alone.
pub fn is_b64url(s: &str, bytes: usize) -> bool {
    b64url_decode(s, bytes).is_some()
}

/// A grant token's form (§7 «Токен выдачи»): `""` (a PC that has none), or [`bytes::ID`] bytes in
/// strict base64url.
pub fn is_grant_token(s: &str) -> bool {
    s.is_empty() || is_b64url(s, bytes::ID)
}

/// A `key_id` as a log may carry it (§1.4): its first [`KEY_ID_LOG_CHARS`] characters, or `"-"` for
/// one that is not a `key_id`'s form (never the raw value).
pub fn key_id_for_log(key_id: &str) -> &str {
    if is_b64url(key_id, bytes::KEY_ID) {
        &key_id[..KEY_ID_LOG_CHARS]
    } else {
        "-"
    }
}

/// `session_nonces.nonces` as the contract takes it (`nonceBatchSchema`): [`NONCE_BATCH`] nonces,
/// each strict base64url of [`NONCE_BYTES`], all different. The agent makes its own; this is the
/// check before one goes out.
pub fn is_nonce_batch(nonces: &[String]) -> bool {
    nonces.len() == NONCE_BATCH
        && nonces.iter().all(|n| is_b64url(n, NONCE_BYTES))
        && nonces
            .iter()
            .enumerate()
            .all(|(i, n)| !nonces[..i].contains(n))
}

/* --- `ks`: what the PC decided, to the viewer (§3.7) -------------------------------------------- */

/// What the PC decided about the viewer's device key (`ks`, `keyStatusSchema`): agent → viewer on
/// the `input` channel, once, when the channel opened after the first offer — only to a session whose
/// offer carried a `proof`. For the viewer's interface only (milestone 1 has no PC signature): the
/// viewer marks «this PC took me» by it and drops no base over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStatus {
    /// The key it judged (`proof.key_id`): 43 characters of strict base64url.
    pub kid: String,
    pub verdict: KsVerdict,
    /// The reason's `ended_detail`, when it has one (`END_DETAIL_CODE_PATTERN`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The base that added the key now; absent when none did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admit: Option<KeyAdmit>,
    pub mode: KeyMode,
}

impl KeyStatus {
    /// The fields an enum cannot hold to the contract (`kid`'s form, `detail`'s pattern); the first
    /// that fails is named. The viewer refuses a `ks` that fails (its schema is strict), so the agent
    /// checks before it sends and sends none rather than one that would be dropped.
    pub fn check(&self) -> Result<(), InvalidField> {
        if !is_b64url(&self.kid, bytes::KEY_ID) {
            return Err(InvalidField { field: "ks.kid" });
        }
        if self
            .detail
            .as_deref()
            .is_some_and(|d| !is_end_detail_code(d))
        {
            return Err(InvalidField { field: "ks.detail" });
        }
        Ok(())
    }
}

/* --- limits on the opaque values (§1.2) ---------------------------------------------------- */

/// Why an opaque value broke the spec's limits (§1.2). For the log: what the agent refused, never
/// what the value held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireLimit {
    /// Not a JSON object.
    NotObject,
    /// Nested deeper than [`PROOF_MAX_DEPTH`] (the object itself is level 1).
    TooDeep,
    /// Over its size as compact JSON.
    TooLarge,
    /// `proof.admit` present and not an array.
    AdmitNotArray,
    /// `proof.admit` has more than [`ADMIT_MAX`] entries.
    TooManyAdmits,
}

impl WireLimit {
    /// A short word for the log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotObject => "not_object",
            Self::TooDeep => "too_deep",
            Self::TooLarge => "too_large",
            Self::AdmitNotArray => "admit_not_array",
            Self::TooManyAdmits => "too_many_admits",
        }
    }
}

impl fmt::Display for WireLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for WireLimit {}

/// JSON nesting of `value` (`jsonDepth`): an object or an array is 1 + its deepest child, anything
/// else 0. Stops counting past `cap` (returns at most `cap + 1`), so a deep value costs neither stack
/// nor time beyond the cap.
pub fn json_depth(value: &Value, cap: usize) -> usize {
    fn deepest<'a>(children: impl Iterator<Item = &'a Value>, cap: usize) -> usize {
        let mut deepest = 0;
        for child in children {
            deepest = deepest.max(json_depth(child, cap - 1));
            if deepest >= cap {
                break;
            }
        }
        deepest
    }
    match value {
        Value::Array(_) | Value::Object(_) if cap == 0 => 1,
        Value::Array(items) => 1 + deepest(items.iter(), cap),
        Value::Object(map) => 1 + deepest(map.values(), cap),
        _ => 0,
    }
}

/// Counts what `serde_json` writes and stops once it passes `cap`.
struct CappedCount {
    n: usize,
    cap: usize,
}

impl io::Write for CappedCount {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.n = self.n.saturating_add(buf.len());
        if self.n > self.cap {
            return Err(io::Error::other("over the cap"));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `value`'s size as compact JSON in UTF-8 (`serde_json::to_vec(value).len()`), or `None` once it
/// passes `cap`: counted as it is written, never allocated, and the writing stops at the cap.
///
/// The contract measures `JSON.stringify`. The two agree byte for byte on strings, integers, `true`,
/// `false` and `null`, which is everything a well-formed `proof` or `key_reg` holds; they differ on a
/// fraction or an exponent (`1.0` is `1.0` here and `1` there), so a value made of such numbers may
/// be judged a few bytes apart by the server and by the agent near the bound.
pub fn compact_len_within(value: &Value, cap: usize) -> Option<usize> {
    let mut count = CappedCount { n: 0, cap };
    serde_json::to_writer(&mut count, value).ok()?;
    Some(count.n)
}

fn check_opaque(value: &Value, max_bytes: usize) -> Result<(), WireLimit> {
    if !value.is_object() {
        return Err(WireLimit::NotObject);
    }
    // Depth first, as the contract does: a deep value is refused before it is serialized at all.
    if json_depth(value, PROOF_MAX_DEPTH) > PROOF_MAX_DEPTH {
        return Err(WireLimit::TooDeep);
    }
    if compact_len_within(value, max_bytes).is_none() {
        return Err(WireLimit::TooLarge);
    }
    Ok(())
}

/// `sdp.proof` within the spec's limits (§1.2, `proofWireSchema`): an object, at most
/// [`PROOF_MAX_DEPTH`] deep, at most [`PROOF_MAX_BYTES`] as compact JSON, and its `admit`, when
/// present, an array of at most [`ADMIT_MAX`]. Nothing else is looked at: the fields and the
/// signatures are the verifier's. A failure is `proof_invalid:malformed`, decided by the caller
/// without any cryptography.
pub fn check_proof_wire(proof: &Value) -> Result<(), WireLimit> {
    check_opaque(proof, PROOF_MAX_BYTES)?;
    match proof.get("admit") {
        None => Ok(()),
        Some(Value::Array(admit)) if admit.len() <= ADMIT_MAX => Ok(()),
        Some(Value::Array(_)) => Err(WireLimit::TooManyAdmits),
        Some(_) => Err(WireLimit::AdmitNotArray),
    }
}

/// `pair_request.viewer_key` within the spec's limits (§1.2, `viewerKeyWireSchema`): an object, at
/// most [`PROOF_MAX_DEPTH`] deep and [`VIEWER_KEY_MAX_BYTES`] as compact JSON. A failure costs the
/// key (`admit_refused:key_reg_bad`), never the prompt.
pub fn check_viewer_key_wire(viewer_key: &Value) -> Result<(), WireLimit> {
    check_opaque(viewer_key, VIEWER_KEY_MAX_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `n` levels of nesting: an object at the top, arrays below.
    fn nested(n: usize) -> Value {
        let mut v = json!(1);
        for _ in 1..n {
            v = json!([v]);
        }
        if n == 0 {
            v
        } else {
            json!({ "x": v })
        }
    }

    #[test]
    fn depth_counts_containers_and_stops_at_the_cap() {
        assert_eq!(json_depth(&json!(1), 8), 0);
        assert_eq!(json_depth(&json!({}), 8), 1);
        assert_eq!(json_depth(&json!({"a": [1, {"b": null}]}), 8), 3);
        for n in 1..=12 {
            let v = nested(n);
            assert_eq!(json_depth(&v, 64), n, "{n}");
            assert_eq!(json_depth(&v, 8), n.min(9), "{n}");
        }
        // A cap of 0 still tells a container from a scalar.
        assert_eq!(json_depth(&json!([]), 0), 1);
        assert_eq!(json_depth(&json!("s"), 0), 0);
    }

    #[test]
    fn a_proof_at_depth_eight_passes_and_at_nine_does_not() {
        assert_eq!(check_proof_wire(&nested(8)), Ok(()));
        assert_eq!(check_proof_wire(&nested(9)), Err(WireLimit::TooDeep));
        assert_eq!(check_viewer_key_wire(&nested(9)), Err(WireLimit::TooDeep));
    }

    #[test]
    fn size_is_compact_json_and_the_bound_is_inclusive() {
        let pad = |len: usize| {
            // `{"p":"…"}`: 8 bytes around the string.
            json!({ "p": "a".repeat(len - 8) })
        };
        let exact = pad(PROOF_MAX_BYTES);
        assert_eq!(
            serde_json::to_vec(&exact).expect("serializes").len(),
            PROOF_MAX_BYTES
        );
        assert_eq!(
            compact_len_within(&exact, PROOF_MAX_BYTES),
            Some(PROOF_MAX_BYTES)
        );
        assert_eq!(check_proof_wire(&exact), Ok(()));
        assert_eq!(
            check_proof_wire(&pad(PROOF_MAX_BYTES + 1)),
            Err(WireLimit::TooLarge)
        );
        assert_eq!(check_viewer_key_wire(&pad(VIEWER_KEY_MAX_BYTES)), Ok(()));
        assert_eq!(
            check_viewer_key_wire(&pad(VIEWER_KEY_MAX_BYTES + 1)),
            Err(WireLimit::TooLarge)
        );
        // Multibyte text counts in UTF-8 bytes, as the contract's `TextEncoder` does.
        assert_eq!(
            compact_len_within(&json!({ "p": "ж" }), 100),
            Some(r#"{"p":"ж"}"#.len())
        );
        assert_eq!(compact_len_within(&json!({ "p": "ж" }), 9), None);
    }

    #[test]
    fn a_proof_is_an_object_with_at_most_four_admits() {
        assert_eq!(check_proof_wire(&json!([])), Err(WireLimit::NotObject));
        assert_eq!(check_proof_wire(&json!("p")), Err(WireLimit::NotObject));
        assert_eq!(check_proof_wire(&json!(null)), Err(WireLimit::NotObject));
        assert_eq!(check_viewer_key_wire(&json!([])), Err(WireLimit::NotObject));
        let admits = |n: usize| json!({ "v": 1, "admit": vec![json!({"kind": "x"}); n] });
        assert_eq!(check_proof_wire(&admits(0)), Ok(()));
        assert_eq!(check_proof_wire(&admits(ADMIT_MAX)), Ok(()));
        assert_eq!(
            check_proof_wire(&admits(ADMIT_MAX + 1)),
            Err(WireLimit::TooManyAdmits)
        );
        assert_eq!(
            check_proof_wire(&json!({ "admit": {} })),
            Err(WireLimit::AdmitNotArray)
        );
        assert_eq!(
            check_proof_wire(&json!({ "admit": null })),
            Err(WireLimit::AdmitNotArray)
        );
        // Unknown fields are not looked at.
        assert_eq!(check_proof_wire(&json!({ "future": [1, 2] })), Ok(()));
    }

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64url_len(16), 22);
        assert_eq!(b64url_len(32), 43);
        assert_eq!(b64url_len(64), 86);
        assert_eq!(b64url_len(91), 122);
        assert_eq!(
            b64url_decode("AAECAwQFBgcICQoLDA0ODw", 16),
            Some((0u8..16).collect())
        );
        assert!(b64url_decode("AAECAwQFBgcICQoLDA0ODw=", 16).is_none());
        assert!(b64url_decode("AAECAwQFBgcICQoLDA0OD", 16).is_none());
        assert!(
            b64url_decode("AAECAwQFBgcICQoLDA0ODx", 16).is_none(),
            "tail bits"
        );
        assert!(b64url_decode("AAECAwQFBgcICQoLDA0OD+", 16).is_none());
        assert!(b64url_decode("AAECAwQFBgcICQoLDA0OD/", 16).is_none());
        assert!(b64url_decode("AAECAwQFBgcICQoLDA0OD ", 16).is_none());
        // Non-ASCII of the right byte length is not a character of the alphabet.
        assert!(b64url_decode("AAECAwQFBgcICQoLDA0Oжw", 16).is_none());
    }

    #[test]
    fn a_key_id_is_logged_by_its_prefix_only() {
        let kid = "xv1LLFMXsnHJBfPauS-3_i4H3u1HUxe7Uo7ybLFvEi8";
        assert_eq!(key_id_for_log(kid), "xv1LLFMX");
        assert_eq!(key_id_for_log("secret-ish"), "-");
        assert_eq!(key_id_for_log(""), "-");
    }

    #[test]
    fn a_nonce_batch_is_four_different_nonces() {
        let n = |c: char| format!("{}A", c.to_string().repeat(21));
        let good: Vec<String> = ['A', 'B', 'C', 'D'].map(n).to_vec();
        assert!(is_nonce_batch(&good));
        assert!(!is_nonce_batch(&good[..3]));
        let mut five = good.clone();
        five.push(n('E'));
        assert!(!is_nonce_batch(&five));
        let mut twice = good.clone();
        twice[3] = twice[0].clone();
        assert!(!is_nonce_batch(&twice));
        let mut bad = good;
        bad[2] = "short".into();
        assert!(!is_nonce_batch(&bad));
    }

    #[test]
    fn verdicts_are_signed_and_the_reasons() {
        assert_eq!(KsVerdict::ALL[0].as_str(), "signed");
        assert_eq!(KsVerdict::Signed.reason(), None);
        for (v, r) in KsVerdict::ALL[1..].iter().zip(KeyEndReason::ALL) {
            assert_eq!(v.reason(), Some(r));
            assert_eq!(KsVerdict::from(r), *v);
            assert_eq!(v.as_str(), r.as_str());
            assert_eq!(
                serde_json::to_value(v).expect("serializes"),
                json!(r.as_str())
            );
        }
        for r in KeyEndReason::ALL {
            assert!(r.details().iter().all(|d| is_end_detail_code(d)), "{r}");
        }
        for a in KeyAdmit::ALL {
            assert_eq!(
                serde_json::to_value(a).expect("serializes"),
                json!(a.as_str())
            );
            assert_eq!(
                KeyAdmit::from_admit_kind(a.as_str()),
                (a != KeyAdmit::Pair).then_some(a)
            );
        }
        assert_eq!(KeyAdmit::from_admit_kind("future_kind"), None);
        for m in KeyMode::ALL {
            assert_eq!(
                serde_json::to_value(m).expect("serializes"),
                json!(m.as_str())
            );
        }
    }

    #[test]
    fn a_key_status_is_checked_before_it_goes() {
        let ks = KeyStatus {
            kid: "xv1LLFMXsnHJBfPauS-3_i4H3u1HUxe7Uo7ybLFvEi8".into(),
            verdict: KsVerdict::AdmitRefused,
            detail: Some("endorse_signer_revoked".into()),
            admit: None,
            mode: KeyMode::Observe,
        };
        assert_eq!(ks.check(), Ok(()));
        let bad_kid = KeyStatus {
            kid: "xv1LLFMX".into(),
            ..ks.clone()
        };
        assert_eq!(bad_kid.check(), Err(InvalidField { field: "ks.kid" }));
        let bad_detail = KeyStatus {
            detail: Some("Not A Code".into()),
            ..ks
        };
        assert_eq!(bad_detail.check(), Err(InvalidField { field: "ks.detail" }));
    }

    #[test]
    fn device_descriptions_have_the_contracts_form() {
        for d in DEVICE_KINDS.iter().chain(&DEVICE_PLATFORMS) {
            assert!(is_device_desc(d), "{d}");
        }
        assert!(is_device_desc(&"a".repeat(24)));
        assert!(!is_device_desc(&"a".repeat(25)));
        assert!(!is_device_desc(""));
        assert!(!is_device_desc("iPhone"));
        assert!(!is_device_desc("айфон"));
    }
}
