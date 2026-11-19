//! The PC's own trust in viewers' device keys: the list of keys this PC lets in, and the checks over
//! bytes the session admission will call (design `docs/design/viewer-device-keys.md` §3, §3.1, §3.2,
//! §9.1, milestone 1 in §18).
//!
//! What is here, and only this — no wire format, no admission, no window:
//!
//! - [`ViewerKey`] and [`KeyId`] (`key`): a viewer's ECDSA P-256 public key, taken only as the
//!   canonical 91-byte SPKI with its point checked on the curve, its `key_id`, and the check of a
//!   64-byte `r‖s` signature over whatever bytes the protocol spec says are signed;
//! - [`TelegramVerifier`] (`telegram`): Telegram's Ed25519 signature on a Mini App's initData
//!   (Bot API 8.0, third-party validation) and the rule `start_param == "k_" + key_id` that ties a
//!   key to the Telegram account it was born in;
//! - [`TrustStore`] (`store`): `viewer_keys.json` beside `config.json` — the keys (each with the
//!   public half of its device's recovery key, when it has one, and its `unconfirmed` mark), the
//!   removed ones (with their SPKI), the spent `endorse_id`/`grant_id`/`inv_id`s, the `first_use`
//!   snapshot and the PC's switch (protocol spec §10, §10.1) — which fails closed, and the rules
//!   every add, removal and recovery must pass. Every change is staged (pure), written (blocking)
//!   and installed ([`Staged`], [`Written`]);
//! - `wire`: `LP(…)`, strict base64url and every signed message (spec §1.1, §1.2, §3.1, §4, §6.5,
//!   §7, §8.3, §9);
//! - `proof`: `offer_proof` with its limits (§1.2), the key card (`key_reg`, §4) and the grounds of
//!   `proof.admit` (`endorse`, `grant` with its invitation, recovery, `first_use`), parsed and
//!   checked over bytes;
//! - `sdp`: the viewer's DTLS fingerprint in its offer (§3.3);
//! - `nonce`: the nonce book (§2.2).
//!
//! The decisions over all of this — the session admission of §3.4–§11 — are `crate::admission`.
//!
//! Same-device recovery (protocol spec §8, always on): each device and Telegram account has a
//! separate ECDSA P-256 recovery key; the PC keeps only its public key (`rpk`, a canonical SPKI
//! checked like a device key) and [`TrustStore::stage_recover`] builds the recovery message itself
//! and checks the recovery signature, for the key Telegram attested only. Nothing secret is kept
//! on the PC.
//!
//! # Constants
//!
//! Every domain-separation string and prefix is below, in one place: the `key_id` and
//! `start_param` ones, both the design's (§3, §3.1).
//!
//! # Threads
//!
//! Nothing here spawns or waits on another thread. The crypto is pure and fast (one ECDSA or
//! Ed25519 verify, microseconds). [`TrustStore`]'s `stage_*`, `install`, `abandon`, `deny_now`
//! and queries do no I/O; [`Staged::write`], the store's opening, `reopen` and its plain
//! (all-in-one) mutations do synchronous file I/O on the caller's thread: on the Tauri async runtime, through `spawn_blocking`
//! (`docs/project-rules.md`, «Потоки и замки»), without holding a lock across the wait. The one
//! lock, process-wide, is taken inside [`Staged::write`] around its file steps only.
//!
//! # Logs
//!
//! `debug` for every decision and refusal with its reason; `info` when the store is created or
//! changed; `error` for a damaged store and for a build without the bot id. Never a full initData, a
//! signature, nor SPKI bytes; a key is named by the first 8 characters of its `key_id` only
//! ([`KeyId::short`], spec §1.4), in log lines, error texts and damage details.

mod key;
pub mod nonce;
pub mod proof;
pub mod sdp;
mod store;
mod telegram;
pub mod wire;

pub use key::{
    KeyError, KeyId, SigError, ViewerKey, KEY_ID_LEN, KEY_ID_SHORT_LEN, SIGNATURE_LEN, SPKI_LEN,
};
pub use store::{
    Abandon, AddOutcome, Attempt, AttemptNoted, ClientKind, Damage, DamageKind, Delegation,
    FirstUseSnapshot, Ground, GroundId, Invite, Joined, KeyRecord, KeySource, KeyState,
    KnownBinding, Limit, Listed, Lookup, NewKey, NotInstalled, Notes, Origin, OwnerDevice,
    PartyLeaveBy, PendingKey, Person, PersonKeys, Platform, RecoverOutcome, Recovery, Reloaded,
    Removal, ReopenLoad, RuleRun, SnapshotPerson, Staged, StoreError, StorePaths, SwitchState,
    Tombstone, TreeRemoval, TrustStore, WriteFailed, Written, ATTEMPTS_MAX, ATTEMPTS_PER_PERSON,
    ATTEMPT_KEEP_MS, BACKUP_FILE_NAME, DAMAGED_FILE_PREFIX, FILE_NAME, FORMAT_VERSION,
    GROUND_ID_LEN, LAST_BINDINGS_MAX, LAST_USED_WRITE_AFTER_MS, MAX_ACTIVE_KEYS, MAX_DELEGATIONS,
    MAX_KEYS_PER_PERSON, MAX_SNAPSHOT_PEOPLE, MAX_SPENT, MAX_TOMBSTONES, MAX_TOMBSTONES_AT_PC,
    MAX_USER_ID, MODE_FILE_NAME, NAME_MAX_CHARS, PARTY_FORMAT_VERSION, TAG_MAX_LEN,
    UNBOUND_KEY_GRACE_MS,
};
pub use telegram::{
    AttestationError, TelegramEnvironment, TelegramIdentity, TelegramVerifier, BOT_ID_VAR,
    MAX_INIT_DATA_LEN, PRODUCTION_KEY_HEX, PROD_TG_BOT_ID,
};
pub use wire::GrantToken;

/// What `key_id` hashes before the SPKI (§3): `key_id = base64url(SHA-256(this ‖ SPKI))`.
pub const VIEWER_KEY_DOMAIN: &[u8] = b"AFKLINK-VIEWER-KEY-V1\0";

/// What a key's Telegram attestation carries in `start_param` before its `key_id` (§3.1).
pub const START_PARAM_PREFIX: &str = "k_";

/// SHA-256 over the concatenation of `parts`, through aws-lc-rs.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for part in parts {
        ctx.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}
