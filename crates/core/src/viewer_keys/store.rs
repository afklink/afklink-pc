//! The PC's list of trusted viewer keys (protocol spec §10, §10.1, design §3.2):
//! `viewer_keys.json` beside `config.json`, with `viewer_keys.json.bak` the version before the
//! last change.
//!
//! # What it holds
//!
//! - active keys ([`KeyRecord`]): the SPKI (its `key_id` recomputed at every load), the person
//!   (`telegram_user_id`, display names), the key's role, the client `kind` and device `platform`
//!   from `key_reg` (display only), the public recovery key `rpk`, how the key got in
//!   ([`KeySource`]), the `unconfirmed` mark (§10.1) and two display times;
//! - removed keys ([`Tombstone`]): the SPKI (an admission checks a removed key's offer signature
//!   before it says «revoked», §3.4 step 6), the person, where the removal came from ([`Origin`])
//!   and how the key had got in (its signers stay links of the chain, §10.1);
//! - spent grounds: every `endorse_id`, `grant_id` and `inv_id` a key was added by, kept after the
//!   key is removed and after a reset at the PC, so a replayed `endorse`, `grant` or invitation is
//!   useless;
//! - the switch «Доверенные устройства» ([`SwitchState`]); same-device recovery has no switch;
//! - the `first_use` snapshot (§9): people and roles, taken once.
//!
//! # Rules a change must pass (step 8 of §3.4 calls these, so none can be skipped)
//!
//! - a removed `key_id` comes back only as its origin allows (§10): `pc`/`replaced` — only through
//!   `pair` (at the PC); `server` — through `pair`, or a `grant` **with** an unspent invitation
//!   whose person is the removed key's; everything else is refused ([`StoreError::Removed`]);
//! - `endorse`: `by` is active; the new key takes `by`'s person and role, whatever the caller says;
//! - `grant`: `by` is an active owner's key, the person is not an owner here, and the grant's
//!   `inv_id` (§7: it is always in `g`) is unspent; with an invitation, `invite.inv_id` is the
//!   grant's and `invite.by` is an active owner's key of the same person as `by`; without one,
//!   only in observe mode and the key is unconfirmed. Every grant spends its `grant_id` **and** its
//!   `inv_id`, with or without the invitation (so an old request cannot come back with one);
//! - `first_use`: observe mode; the person in the snapshot, with no active and no removed key; the
//!   person and role from the snapshot ([`StoreError::FirstUseAgain`] when the person already has a
//!   `first_use` key — the admission journals that);
//! - recovery ([`TrustStore::stage_recover`]): all checks of §8.4 in one operation, the recovery
//!   message built here;
//! - the server removes guests' keys only ([`StoreError::ServerRemovesOwner`]);
//! - a recovery key already on another person's key: refused ([`StoreError::RpkConflict`]), except
//!   for a pairing at the PC, which adds the key without it (§4);
//! - limits ([`Limit`]): ≤ 16 active keys per person, ≤ 256 active, ≤ 4096 tombstones and ≤ 4096
//!   spent grounds (the three id sets together; spec §10: the two lists each have their limit). A
//!   full list refuses new keys; removal always works; nothing is evicted. A recovery is a
//!   replacement, not a new key: it needs room only among the tombstones.
//! - a **confirmed** pairing at the PC — [`Ground::Pair`] with `unconfirmed: false`, a person's
//!   own action there with no other session that could have pressed it (§3.4) — is **not** held
//!   by the tombstone limit (spec §10: removals and actions at the PC are not blocked), so a flood
//!   of tombstones on the server's word cannot lock the PC owner out; only a ceiling far beyond
//!   anything the server's grounds can reach ([`MAX_TOMBSTONES_AT_PC`], which bounds the file)
//!   holds it. A marked pairing (`unconfirmed: true`: `pc_allow`, or a window with another
//!   session) keeps [`MAX_TOMBSTONES`] like every other ground.
//!
//! # `unconfirmed` (§10.1)
//!
//! A key is unconfirmed when it got in on the server's word: every `first_use` key, a `grant`
//! without an invitation, a `pair` the caller marks so (the §3.4 window rule and the `pc_allow` →
//! `BindingAdded` path are the admission's to decide), and any key whose signer (`endorse.by`,
//! `grant.by`, `invite.by`) is unconfirmed itself; a recovery is unconfirmed when any record it
//! replaces is. In strict mode a key that would be unconfirmed is not added at all
//! ([`StoreError::KeyUnconfirmed`]). Only the PC clears the mark ([`TrustStore::stage_confirm`],
//! one key at a time) and removes a key with every key that descends from it
//! ([`TrustStore::deny_tree_now`]; a descendant the server had removed stays as it was).
//! [`TrustStore::deny_guest_keys_now`] takes the
//! guest-role keys of an unbound person.
//!
//! # Fails closed
//!
//! A primary file that cannot be read or parsed, that breaks an invariant, that says a newer
//! `version`, or that is missing while a backup exists makes the store [`Damage`]d: logged at
//! `error`, every admission-side query answers «deny» ([`Lookup::StoreDamaged`], and
//! [`TrustStore::switches`] is an error, so «mode off» cannot be read from a damaged list — only
//! from the mode file, below), and
//! every ordinary change is refused. Then: [`TrustStore::reopen`] (an unreadable file may be
//! transient), and the two at-PC actions, both of which first keep the damaged file as
//! `viewer_keys.json.damaged-<unix_ms>`: [`TrustStore::stage_restore_from_backup`] (only a backup
//! that passes every check; not for [`DamageKind::Unreadable`] nor [`DamageKind::NewerVersion`])
//! and [`TrustStore::stage_reset_to_empty`] (not for an unreadable file nor a newer version's —
//! upgrade instead of wiping; the backup's tombstones, spent ids and snapshot carried over, its
//! active keys turned into tombstones `pc`). Both keep the switch the window shows — the damaged
//! store's effective one ([`TrustStore::damaged_mode`]), strict when the mode file is missing or
//! unusable — in the list and the mode file; a restore never takes the backup's switch. No primary
//! and no backup is a first run: an empty store, written at its first change.
//!
//! # The mode file
//!
//! [`MODE_FILE_NAME`] beside the list holds only the switch (`{"version":1,
//! "trusted_devices_mode":…}`), so a damaged list with the switch **off** does not lock everyone
//! out: [`TrustStore::damaged_mode`] says what the file says, and the admission then observes
//! (admits by the binding, as with the switch off) instead of refusing every offer. Adds,
//! recoveries and every other change stay refused while damaged. A missing or unusable mode file
//! beside a damaged list is strict (refuse, as before). Every write orders it so that it can only
//! be **stricter** than the list, never laxer: a list that turns strict has «strict» written to
//! the mode file first (when it cannot be, the file is removed — missing reads as strict — and
//! when that fails too, a change that turns the switch on or a repair is refused); a list that
//! turns observe is written first, then the mode file. A healthy list always wins over a mode
//! file that disagrees (`warn`); the mode file is rewritten at the next write and at
//! [`TrustStore::open_in`] / [`TrustStore::reopen`] (under the write lock, only while the list on
//! disk is still the one loaded). Read only on blocking threads: opens, reopens and a write's own
//! reload.
//!
//! # Saving: stage, write, install (spec §14)
//!
//! Every change is three steps, so the decision can be made synchronously on the agent's main loop
//! and the file written on a blocking thread:
//!
//! 1. `stage_*` (`&mut self`, no I/O): every rule above, then the next list — a [`Staged`] that
//!    remembers the bytes it was built on (shared, not copied). A refusal is an `Err` here. The
//!    stage costs the decision (scans of the keys and tombstones) and one clone of the list, both
//!    O(list); the serializing and the load check of the new bytes (O(list) too, and the costly
//!    part: every SPKI is re-validated) are the write's.
//! 2. [`Staged::write`] (blocking file I/O; owns everything it needs, no `&TrustStore`):
//!    serializes the new list and checks that its bytes would load (the same checks as a load);
//!    then, under one process-wide lock, re-reads the primary and refuses
//!    ([`StoreError::ChangedOnDisk`]) when it is not the bytes the change was built on, copies those
//!    to the backup and writes the new primary whole (`crate::config::write_whole`: temporary file,
//!    flush, rename). Run it in `spawn_blocking`, with the caller's own time limit (2 s, §3.4 step
//!    9). A failure is a [`WriteFailed`], which carries the change back for [`TrustStore::abandon`].
//! 3. [`TrustStore::install`] (never I/O): takes the written list as the store's. When the store
//!    was reopened meanwhile, the change still counts if the disk as the store read it holds the
//!    written bytes, or the bytes the write's locked re-read proved it replaced; otherwise the
//!    install fails with [`StoreError::StaleBase`] ([`NotInstalled`], carrying the outcome) and
//!    the store needs a reopen.
//!
//! **One change in flight.** From a successful `stage_*` (one that returns a change to write)
//! until its [`TrustStore::install`] or [`TrustStore::abandon`], every other `stage_*` is refused
//! [`StoreError::Busy`] — a `stage_touch` too, when it decides to write (it still notes the use in
//! memory). So no change can be staged on a base an unfinished write may still replace, and a
//! write that outlives its caller's time limit can never land after a later change and undo it
//! (a PC's removal, say). **The caller's duty**: when its time limit fires, it keeps the
//! `spawn_blocking` handle, awaits it in the background and then calls `install` with the
//! [`Written`] or `abandon` with the [`WriteFailed`] (or with a [`Staged`] it decides not to write
//! at all). A change lost instead — any of the three dropped, its write panicked, the handle
//! dropped — is seen at the next stage: each carries a token the store holds only weakly, so a
//! dead token means no write of it is running any more. Then `error`, the change in flight is
//! ended and the store refuses every stage [`StoreError::NeedsReopen`] (memory may be behind the
//! disk) until [`TrustStore::reopen`] (blocking: `spawn_blocking`). A reopen alone does not end a
//! live change in flight — only `install`/`abandon` do.
//!
//! **Removals do not wait: every write is a snapshot of memory** (spec §10.1
//! «Нажатие решает сразу»). A removal is decided at the press, in memory (allowed while busy or
//! needing a reopen): [`TrustStore::deny_now`] makes its keys count as removed at once —
//! [`TrustStore::lookup`] answers [`Lookup::PendingRemoval`], they sign no endorse, grant or
//! invitation and are no recovery's candidate, and a key that joins later as their descendant
//! (an in-flight endorse or recovery) is pending too; [`TrustStore::carry_removal`] notes the
//! removal's origin and time (`pending_by`; a `pc` one is never replaced by a `server` one).
//! [`TrustStore::deny_tree_now`] («Удалить»), [`TrustStore::deny_person_tree_now`]
//! («Удалить человека») and [`TrustStore::deny_guest_keys_now`] (a guest unbound) are those
//! decisions: they do both for exactly the keys the removal takes (the tombstones on a walk stay
//! as they are); their own write is a write of memory ([`TrustStore::stage_flush`]). The notes (the grant token, attempts, the stored binding list) are
//! memory's as well; the token is replaced with the removal's own decision
//! ([`TrustStore::rotate_grant_token`]). Every change staged from then on, **whatever it is**, is
//! written as memory has it: the carried keys as tombstones of their origin (a `server` carry
//! never takes an owner-role key) and memory's notes. So the
//! first write that lands takes every decided removal to the disk, and a removal's own
//! change is only one such write: when it fails, the next write that lands supersedes it. A
//! staged removal (`stage_remove`, a healthy `stage_reset_to_empty`) denies its keys the same way
//! at the stage. **The admission's duty:** deny and carry first, then queue a change that writes
//! (its own removal) and retry it on the retryable errors — [`StoreError::Busy`],
//! [`StoreError::NeedsReopen`] (after the reopen), [`StoreError::Write`],
//! [`StoreError::ChangedOnDisk`], [`StoreError::StaleBase`] — so the carry is never left without
//! a write to ride; a retry writes memory as it is and decides nothing again. A list that turns
//! damaged drops every decision no write took yet (the carries, the notes),
//! as a restart before the write would (§10 «Повреждённый список»): nothing replays after the
//! repair. On any other refusal ([`StoreError::ServerRemovesOwner`],
//! [`StoreError::NotFound`], [`StoreError::Removed`], …) a retry cannot help: it calls
//! [`TrustStore::undeny`] for the keys it denied, which withdraws their carry too (`undeny` leaves
//! alone the keys the change in flight removes). A key that inherits the mark as it joins is
//! denied and carried with its root's origin — the origin memory decided for that root, kept in
//! its carry only (a later removal of another origin never changes it): after every install,
//! abandon and reopen the admission reads [`TrustStore::pending_without_removal`] (also
//! [`Reloaded::inherited_pending`]) and queues a removal for each key there with the origin it
//! names (`PendingKey::by`) — so the mark reaches the file.
//!
//! **Reloads say what changed.** [`TrustStore::abandon`] after [`StoreError::ChangedOnDisk`]
//! and [`TrustStore::reopen`] return [`Reloaded`]: the keys that left the active list (end their
//! sessions), those that joined it (journal them) and those whose person, role or mark changed.
//! An install or abandon that cannot apply changes nothing in memory and asks for a reopen,
//! whose [`Reloaded`] the admission must read — not just the error. A reopen whose load is stale
//! (the store changed after [`TrustStore::reopen_load`]) is not taken either:
//! [`Reloaded::needs_reopen`], load again.
//!
//! Only an installed change takes effect in memory. The plain methods ([`TrustStore::add`],
//! [`TrustStore::recover`], …) run the three steps in a row, for tests, the CLI and callers already
//! on a blocking thread.
//!
//! The one exception is `last_used_at` ([`TrustStore::stage_touch`]): it is noted in memory at
//! every connection, at once, and staged for writing only when the file has no value for that key
//! or one ten minutes old or older (spec §3.4 step 9) — otherwise it goes out with the next change of any kind. It is for
//! display only; an install keeps the later of the written and the in-memory value.
//!
//! **One `TrustStore` per process**, owned by one place. Within the process the write lock makes
//! re-read + backup + primary one step, so two writes on one base can never both land (whichever
//! comes second finds the file changed). Another process or a hand edit is caught by the re-read,
//! but there is no lock across processes.
//!
//! # Threads
//!
//! `stage_*`, `install`, `abandon` (after [`StoreError::ChangedOnDisk`] it takes the file as the
//! write's own thread loaded it), `deny_now` and the queries do no I/O and no waiting: call them
//! where the store lives (the main loop). [`Staged::write`], [`TrustStore::open_default`],
//! [`TrustStore::reopen`] and the plain methods do synchronous file I/O on the
//! caller's thread: on the Tauri async runtime, through `spawn_blocking`. The one lock,
//! process-wide, is taken only inside [`Staged::write`] (on the blocking thread) around the file
//! steps of a write, never while waiting on another thread or task.
//!
//! # Logs
//!
//! A key is named by the first 8 characters of its `key_id` only (`kid=AbCd1234`, §1.4), in log
//! lines, error texts and damage details alike.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use afklink_protocol::BindingRole;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::wire::{recover_message, GrantToken, NONCE_PC_LEN};
use super::{KeyId, TelegramIdentity, ViewerKey, SPKI_LEN};
use crate::person_name::clean_name;

/// The list's file, in the data directory beside `config.json`.
pub const FILE_NAME: &str = "viewer_keys.json";
/// The list as it was before the last change.
pub const BACKUP_FILE_NAME: &str = "viewer_keys.json.bak";
/// What a damaged primary is kept as by a repair at the PC, before `<unix_ms>`.
pub const DAMAGED_FILE_PREFIX: &str = "viewer_keys.json.damaged-";
/// The mode file beside the list: only the switch, so a damaged list can still say the mode
/// (module docs, «The mode file»).
pub const MODE_FILE_NAME: &str = "viewer_keys.mode";
/// The mode file's format.
const MODE_FORMAT_VERSION: u32 = 1;
/// The largest mode file read (it holds a few dozen bytes).
const MAX_MODE_BYTES: u64 = 4096;
/// The one file format this build writes and reads: every field, the grant token among them, is
/// always there. Any other version is damage — a newer one [`DamageKind::NewerVersion`] (deny,
/// and no reset that would wipe what a newer build wrote), an older or unknown one
/// [`DamageKind::BadVersion`].
pub const FORMAT_VERSION: u32 = 3;
/// §10: the most bindings the last binding list the PC knew keeps
/// ([`TrustStore::note_last_bindings`]); the parser refuses more.
pub const LAST_BINDINGS_MAX: usize = 4096;
/// §10 «Сверка со списком сервера», «Запас»: a person with a key written less than this before the
/// PC's clock (`added_at`; a time ahead of the clock does not count) is not taken for removed
/// because the current binding list does not name them — their `pair_response` may have been lost
/// in a break, their `binding_added` not arrived ([`TrustStore::bring_to_rule`]). An explicit
/// `binding_removed` ignores it.
pub const UNBOUND_KEY_GRACE_MS: i64 = 600_000;
/// §10.2: an attempt lives this long from its last try.
pub const ATTEMPT_KEEP_MS: i64 = 30 * 86_400_000;
/// §10.2: the most attempts of one person, and in all.
pub const ATTEMPTS_PER_PERSON: usize = 4;
pub const ATTEMPTS_MAX: usize = 64;
/// The most active keys.
pub const MAX_ACTIVE_KEYS: usize = 256;
/// The most active keys of one person.
pub const MAX_KEYS_PER_PERSON: usize = 16;
/// The most tombstones a new key may find on any ground but `pair` (removals may go past it: they
/// always work).
pub const MAX_TOMBSTONES: usize = 4096;
/// The most tombstones a confirmed pairing at the PC (`Ground::Pair` with `unconfirmed: false`)
/// may find: the file's own bound, twice what the server's
/// grounds can ever fill (they stop at [`MAX_TOMBSTONES`]), so only thousands of the PC owner's own
/// pair-and-remove rounds could reach it. A file holds at most this many tombstones plus
/// [`MAX_ACTIVE_KEYS`] (the keys a removal may turn into tombstones on top).
pub const MAX_TOMBSTONES_AT_PC: usize = 2 * MAX_TOMBSTONES;
/// The most spent grounds (`endorse_id`, `grant_id` and `inv_id` together).
pub const MAX_SPENT: usize = 4096;
/// The most people in the `first_use` snapshot (a PC's bindings are tens; the server supplies the
/// list).
pub const MAX_SNAPSHOT_PEOPLE: usize = 256;
/// The longest display name kept, in characters.
pub const NAME_MAX_CHARS: usize = 64;
/// The largest Telegram user id taken: 2^53 − 1 (spec §8.2).
pub const MAX_USER_ID: i64 = (1 << 53) - 1;
/// How old the stored `last_used_at` must be before a connection writes a new one.
pub const LAST_USED_WRITE_AFTER_MS: i64 = 10 * 60 * 1000;
/// An `endorse_id` / `grant_id` / `inv_id`: 16 bytes in base64url without padding.
pub const GROUND_ID_LEN: usize = 22;
/// The largest file read or written: a full list (256 keys, 8448 tombstones with their SPKIs and
/// sources, 4096 spent ids, the snapshot — about 6 MB) stays well under it.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

// --- Values -----------------------------------------------------------------------------------

/// An `endorse_id`, `grant_id` or `inv_id` (spec §6.5, §7): opaque, exactly 22 base64url
/// characters that decode to 16 bytes and are their canonical spelling.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroundId(String);

impl GroundId {
    /// Parse strictly; `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != GROUND_ID_LEN
            || !text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        // The engine refuses non-zero trailing bits; the re-encoding says so again.
        let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
        let bytes = <[u8; 16]>::try_from(bytes.as_slice()).ok()?;
        (URL_SAFE_NO_PAD.encode(bytes) == text).then(|| Self(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroundId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for GroundId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroundId({})", self.0)
    }
}

impl Serialize for GroundId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// Only what [`GroundId::parse`] accepts.
impl<'de> Deserialize<'de> for GroundId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| serde::de::Error::custom("not a canonical ground id"))
    }
}

/// Whose key it is. `telegram_user_id` is the identity; the names are for display only (cleaned,
/// at most [`NAME_MAX_CHARS`] characters, absent rather than empty).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Person {
    pub telegram_user_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// The longest `kind` / `platform` value.
pub const TAG_MAX_LEN: usize = 24;

/// Whether `s` is a well-formed `kind` / `platform` value: `[a-z0-9_]{1,24}`.
fn tag_ok(s: &str) -> bool {
    (1..=TAG_MAX_LEN).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

macro_rules! display_tag {
    ($(#[$doc:meta])* $name:ident, $what:literal, [$($known:literal),+ $(,)?]) => {
        $(#[$doc])*
        ///
        /// **Display only**: never an authorization input, never taken from the server's word (it
        /// comes from the viewer's signed `key_reg`). Any well-formed value is kept as is (a newer
        /// client may send one this build does not know; the window shows it as unknown).
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// The values this build knows.
            pub const KNOWN: &'static [&'static str] = &[$($known),+];

            /// Take `s` if it is `[a-z0-9_]{1,24}`; `None` otherwise.
            pub fn parse(s: &str) -> Option<Self> {
                tag_ok(s).then(|| Self(s.to_string()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Whether this build knows the value.
            pub fn is_known(&self) -> bool {
                Self::KNOWN.contains(&self.0.as_str())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        /// Only what `parse` accepts.
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::parse(&text)
                    .ok_or_else(|| serde::de::Error::custom(concat!("not a well-formed ", $what)))
            }
        }
    };
}

display_tag!(
    /// Which client made the key (`kind` in `key_reg`).
    ClientKind,
    "kind",
    ["telegram", "telegram_desktop", "browser"]
);

display_tag!(
    /// The device's platform (`platform` in `key_reg`).
    Platform,
    "platform",
    ["iphone", "ipad", "android", "mac", "windows", "linux", "unknown"]
);

/// The owner's signed invitation a `grant` came with (spec §7): its id and the owner's key that
/// signed it. The caller has checked the invitation's signature, `device_id` and the time window;
/// the store checks that `inv_id` is the grant's and checks `by`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub inv_id: GroundId,
    pub by: KeyId,
}

/// How a key got into the list (spec §10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeySource {
    /// «Разрешить» at this PC.
    Pair,
    /// Endorsed by another active key of the same person.
    Endorse { by: KeyId, endorse_id: GroundId },
    /// A guest let in by an owner's key: the grant's `inv_id` when it has one (§7, spent with the
    /// add; `null` only on a grant without a signed invitation); `invite_by` — the key that signed
    /// the invitation, when the grant came with one.
    Grant {
        by: KeyId,
        grant_id: GroundId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        inv_id: Option<GroundId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invite_by: Option<KeyId>,
    },
    /// The same device after it lost its key (§8.4): every record it replaced, and the ancestry
    /// edges of those records (their `parents`, deduplicated): the record carries them itself, so
    /// they survive whatever later happens to the replaced records' tombstones (§10.1 «inherits
    /// the edges», spec §10 `source.parents`). Always written, `[]` too; a record without it does
    /// not load (damage).
    Recover {
        replaced: Vec<KeyId>,
        parents: Vec<KeyId>,
    },
    /// The person's first key on the server's word, from the snapshot (§9).
    FirstUse,
}

impl KeySource {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::Endorse { .. } => "endorse",
            Self::Grant { .. } => "grant",
            Self::Recover { .. } => "recover",
            Self::FirstUse => "first_use",
        }
    }

    /// The keys this one descends from (§10.1): `endorse.by`, `grant.by`, `invite.by`, and for a
    /// recovery the edges of the records it replaced (stored in the record itself), deduplicated.
    /// Not the replaced records: a recovery is not their descendant, it takes their place — see
    /// [`Self::replaced`].
    pub fn parents(&self) -> Vec<&KeyId> {
        let mut out: Vec<&KeyId> = match self {
            Self::Pair | Self::FirstUse => Vec::new(),
            Self::Endorse { by, .. } => vec![by],
            Self::Grant { by, invite_by, .. } => {
                let mut out = vec![by];
                if let Some(invite_by) = invite_by {
                    out.push(invite_by);
                }
                out
            }
            Self::Recover { parents, .. } => parents.iter().collect(),
        };
        let mut seen = HashSet::new();
        out.retain(|k| seen.insert(*k));
        out
    }

    /// The records a recovery replaced (none for any other source): the §10.1 walk goes on to
    /// them, so a recovery inherits their descendants.
    pub fn replaced(&self) -> &[KeyId] {
        match self {
            Self::Recover { replaced, .. } => replaced,
            _ => &[],
        }
    }
}

/// Where a removal came from (spec §10), which decides what can bring the key back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Origin {
    /// «Удалить», a person removed at the PC, or a reset: `pair`, or an owner's `grant` with a new
    /// invitation for the same person, brings it back (one return rule, spec §10).
    Pc,
    /// Replaced by a same-device recovery: only `pair` brings it back.
    Replaced { new_key_id: KeyId },
    /// The server removed a guest's binding: `pair`, or an owner's `grant` with a new invitation
    /// for the same person, brings it back (as for `pc`: one return rule).
    Server,
}

impl Origin {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pc => "pc",
            Self::Replaced { .. } => "replaced",
            Self::Server => "server",
        }
    }
}

/// Who removes a key through [`TrustStore::stage_remove`] (a replacement goes through
/// [`TrustStore::stage_recover`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// At this PC.
    Pc,
    /// The server (`binding_removed` of a guest): refused for an owner's key.
    Server,
}

/// A removed key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tombstone {
    /// The key itself: an admission checks a removed key's offer signature with it (§3.4 step 6)
    /// before it says the key is revoked. Its `key_id` is recomputed from the SPKI at every load.
    pub key: ViewerKey,
    pub telegram_user_id: i64,
    pub origin: Origin,
    /// The spec's `removed_at` (§10 «Удалённые ключи»): unix milliseconds, the PC's clock, when
    /// this removed record was written (every origin); a later walk through it never changes it.
    /// A returning `endorse` must be issued after it (§10 «Одно правило возврата»).
    pub at: i64,
    /// How the key had got in: its signers stay links of the chain (§10.1).
    pub source: KeySource,
}

impl Tombstone {
    pub fn key_id(&self) -> &KeyId {
        self.key.key_id()
    }

    pub fn spki(&self) -> &[u8; SPKI_LEN] {
        self.key.spki()
    }
}

/// An active key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRecord {
    pub key: ViewerKey,
    pub person: Person,
    pub role: BindingRole,
    /// The device's recovery key (`rpk`, §8.1), when it has one. Public; nothing secret is kept.
    pub rpk: Option<ViewerKey>,
    /// Display only (see [`ClientKind`]).
    pub kind: ClientKind,
    /// Display only (see [`Platform`]).
    pub platform: Platform,
    pub source: KeySource,
    /// §10.1: the key got in on the server's word; no strict-mode admission, no trust organs.
    pub unconfirmed: bool,
    /// Unix milliseconds, the PC's clock; display only.
    pub added_at: i64,
    /// Unix milliseconds, the PC's clock; display only (see [`TrustStore::stage_touch`]).
    pub last_used_at: Option<i64>,
}

impl KeyRecord {
    pub fn key_id(&self) -> &KeyId {
        self.key.key_id()
    }

    fn tombstone(&self, origin: Origin, at: i64) -> Tombstone {
        Tombstone {
            key: self.key.clone(),
            telegram_user_id: self.person.telegram_user_id,
            origin,
            at,
            source: self.source.clone(),
        }
    }
}

/// The key a new record is for, as its `key_reg` describes it (the caller has checked the card's
/// signature).
#[derive(Debug, Clone)]
pub struct NewKey {
    pub key: ViewerKey,
    pub rpk: Option<ViewerKey>,
    pub kind: ClientKind,
    pub platform: Platform,
}

/// A listed record as the PC decides on it now (§10 «Действующий ключ»): its removal decided, else
/// it works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// A working key: it admits, signs (`endorse.by`, `grant.by`, `invite.by`) and counts as an
    /// owner key.
    Works,
    /// Its removal is decided (denied at once, carried by every later write): listed until the
    /// write that takes it lands.
    Leaving,
}

/// A record in the list with its [`KeyState`] ([`TrustStore::listed`],
/// [`TrustStore::listed_people`]): how the window and the journal read a record, so nothing
/// outside the store reads one without its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listed<'a> {
    pub record: &'a KeyRecord,
    pub state: KeyState,
}

/// Where the owner's own device stands for the strict switch ([`TrustStore::owner_device`], §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerDevice {
    /// A working, confirmed owner-role key: the switch may go on.
    Ready,
    /// Working owner-role keys, every one unconfirmed: «Подтвердить» one first.
    Unconfirmed,
    /// No working owner-role key: a device of the owner's added at the PC first.
    Missing,
}

impl OwnerDevice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unconfirmed => "needs_confirm",
            Self::Missing => "needs_device",
        }
    }
}

/// One person's listed keys by role, read with their [`KeyState`] ([`TrustStore::person_keys`]),
/// each in the order they were added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersonKeys {
    /// Working owner-role keys: an owner by the PC's keys. The owner guard of every removal and
    /// the role a press gives read these.
    pub working_owner: Vec<KeyId>,
    /// Working guest-role keys.
    pub working_guest: Vec<KeyId>,
    /// Every owner-role record in the list, working or not: only the deliberately strict reads
    /// (a grant naming an owner, the second step of «Разрешить») and the staging of a removal
    /// that must not take an owner-role record read these.
    pub listed_owner: Vec<KeyId>,
    /// Every guest-role record in the list, working or not (what a removal of the person takes).
    pub listed_guest: Vec<KeyId>,
}

impl PersonKeys {
    /// An owner by the PC's keys: a working owner-role key.
    pub fn owner_by_keys(&self) -> bool {
        !self.working_owner.is_empty()
    }

    /// Owner-role records listed, none of them working (each leaving).
    pub fn owner_keys_not_working(&self) -> bool {
        self.working_owner.is_empty() && !self.listed_owner.is_empty()
    }

    /// Every record of the person in the list, owner-role first.
    pub fn listed(&self) -> impl Iterator<Item = &KeyId> {
        self.listed_owner.iter().chain(&self.listed_guest)
    }
}

/// What one run of the binding list's rule changed in memory ([`TrustStore::bring_to_rule`], §10
/// «Сверка со списком сервера: одно правило»); the next write carries all of it (one snapshot).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleRun {
    /// The people it took (not named, no working owner-role key): all their sessions and pending
    /// requests end.
    pub ended: Vec<i64>,
    /// The guest-role keys whose removal (origin `server`) it decided now: denied and carried.
    pub denied: Vec<KeyId>,
    /// The grant token was replaced (§7 «Токен выдачи»): someone's guest keys left, or someone
    /// left the stored last binding list.
    pub rotated: bool,
    /// The stored last binding list changed.
    pub list_noted: bool,
    /// The PC's wall time (unix ms) when the grace of a person it skipped ends: run again then.
    pub due_at: Option<i64>,
}

impl RuleRun {
    /// Whether memory changed (a write of it is due).
    pub fn changed(&self) -> bool {
        !self.denied.is_empty() || self.rotated || self.list_noted
    }
}

/// On what ground a key is added ([`TrustStore::stage_add`]); the store, not the caller, decides
/// the person and role wherever the ground carries them.
#[derive(Debug, Clone)]
pub enum Ground {
    /// «Разрешить» at the PC: the person and role the PC chose. `unconfirmed` is the admission's
    /// call (§3.4: a session other than a confirmed owner's during the window; §5: `pc_allow` →
    /// `BindingAdded`).
    Pair {
        person: Person,
        role: BindingRole,
        unconfirmed: bool,
    },
    /// The caller has checked the signature under `by`'s SPKI. `issued_at`: the endorse's own
    /// (unix ms, the signing device's clock) — read only when it would return a removed key (§10
    /// «Одно правило возврата»: it must be later than the removed record's time).
    Endorse {
        by: KeyId,
        endorse_id: GroundId,
        issued_at: u64,
    },
    /// The caller has checked the grant's signature, `device_id`, `key_id` and `role == "guest"`,
    /// and — when `invite` is given — the invitation's signature, `device_id` and time window
    /// (§7); `person` and `inv_id` are the grant's (`inv_id`, when the grant has one, is spent,
    /// with or without `invite`; with an invitation, `invite.inv_id` must equal it, so a grant
    /// with `inv_id: None` and an invitation is refused).
    Grant {
        by: KeyId,
        grant_id: GroundId,
        inv_id: Option<GroundId>,
        invite: Option<Invite>,
        person: Person,
        /// The PC's grant token the grant carries (§7 «Токен выдачи»): checked against the
        /// current one at the stage, as at the first decision.
        token: GrantToken,
    },
    /// The caller has checked the key's signature over `uid`.
    FirstUse { telegram_user_id: i64 },
}

impl Ground {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pair { .. } => "pair",
            Self::Endorse { .. } => "endorse",
            Self::Grant { .. } => "grant",
            Self::FirstUse { .. } => "first_use",
        }
    }
}

/// What an add did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddOutcome {
    pub key_id: KeyId,
    pub telegram_user_id: i64,
    pub role: BindingRole,
    pub unconfirmed: bool,
    /// A pairing whose `rpk` is already another person's key's: the key was added without it (§4).
    pub rpk_dropped: bool,
    /// The origin of the tombstone the add lifted, if any.
    pub lifted: Option<&'static str>,
    /// The person already had a live key here before this add: the key joins that person (a
    /// guest's new device on a `grant`, spec §7 «Новое устройство уже привязанного гостя»), not a
    /// new one. Keys whose removal is pending do not count.
    pub known_person: bool,
}

/// A same-device recovery (spec §8.3–8.4) to check and stage as one operation.
#[derive(Debug, Clone)]
pub struct Recovery<'a> {
    /// `key_reg.rpk` of the new key.
    pub rpk: &'a ViewerKey,
    /// Telegram's attestation, from [`super::TelegramVerifier::verify_attestation`]: it must be
    /// for `new_key` ([`TelegramIdentity::attested_key`]).
    pub attested: &'a TelegramIdentity,
    /// This PC's own `device_id`.
    pub device_id: &'a str,
    /// The session's id, as on the wire.
    pub session_id: &'a str,
    /// The session's `nonce_pc`, raw.
    pub nonce_pc: [u8; NONCE_PC_LEN],
    /// `rsig`, as decoded.
    pub rsig: &'a [u8],
    pub new_key: ViewerKey,
    /// From the new `key_reg`.
    pub kind: ClientKind,
    /// From the new `key_reg`.
    pub platform: Platform,
}

/// What a removal at the PC decided ([`TrustStore::deny_tree_now`],
/// [`TrustStore::deny_person_tree_now`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeRemoval {
    /// The listed keys it denied, the root first when it is listed: their live sessions must
    /// end.
    pub removed: Vec<KeyId>,
}

/// What a recovery did. The live sessions of every `replaced` key must end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverOutcome {
    pub new_key_id: KeyId,
    pub telegram_user_id: i64,
    pub role: BindingRole,
    pub unconfirmed: bool,
    pub replaced: Vec<KeyId>,
}

/// One person of the `first_use` snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPerson {
    pub person: Person,
    pub role: BindingRole,
}

/// The people and roles of the bindings at the first `agent_ready` of a build with keys (§9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstUseSnapshot {
    /// Unix milliseconds, the PC's clock.
    pub taken_at: i64,
    pub people: Vec<SnapshotPerson>,
}

/// The PC's switch. Same-device recovery is always on and has none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwitchState {
    /// «Доверенные устройства»: only keys in the list get in. Off by default.
    pub trusted_devices_mode: bool,
}

/// What the list says of a `key_id`, with the verdict ([`KeyState`]): only [`Lookup::Active`]
/// admits and signs. For every listed one the record's SPKI checks the offer's signature first
/// (§3.4 step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// A working key ([`KeyState::Works`]).
    Active(&'a KeyRecord),
    /// Listed, but its removal is decided ([`TrustStore::deny_now`]): deny, as for a removed key.
    PendingRemoval(&'a KeyRecord),
    /// Removed: [`Tombstone::key`] is the SPKI to check the offer's signature with.
    Removed(&'a Tombstone),
    Unknown,
    /// The store is damaged: deny, whatever the switch.
    StoreDamaged,
}

/// What is wrong with the primary file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DamageKind {
    /// It (or the directory) could not be read: possibly transient ([`TrustStore::reopen`]).
    Unreadable,
    /// Larger than any list could be.
    TooLarge,
    /// Not JSON, or not of the expected shape.
    NotParsable,
    /// No usable `version`.
    BadVersion,
    /// A `version` newer than this build knows.
    NewerVersion,
    /// It parses but breaks an invariant.
    Invariant,
    /// Missing while the backup exists.
    PrimaryMissing,
}

impl DamageKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreadable => "unreadable",
            Self::TooLarge => "too_large",
            Self::NotParsable => "not_parsable",
            Self::BadVersion => "bad_version",
            Self::NewerVersion => "newer_version",
            Self::Invariant => "invariant",
            Self::PrimaryMissing => "primary_missing",
        }
    }
}

/// Why the store is damaged: the kind, and a detail for the log and the window (never a key's
/// bytes, a full `key_id` or a name from the file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Damage {
    pub kind: DamageKind,
    pub detail: String,
}

impl Damage {
    fn new(kind: DamageKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.detail)
    }
}

/// Which limit a new key hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    PerPerson,
    Active,
    Tombstones,
    Spent,
}

impl Limit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerPerson => "per_person",
            Self::Active => "active",
            Self::Tombstones => "tombstones",
            Self::Spent => "spent",
        }
    }
}

/// Why a change or a query was refused. The texts name keys by 8 characters only.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error(
        "the trusted-keys file is damaged; only reopening, restoring the backup or resetting works"
    )]
    Damaged,
    #[error("the store is not damaged: nothing to restore")]
    NotDamaged,
    #[error(
        "the trusted-keys file could not be read, which may pass: reopen instead of repairing"
    )]
    Unreadable,
    #[error(
        "the trusted-keys file is of a newer version: an older backup is not restored over it"
    )]
    NewerVersion,
    #[error("the trusted-keys file changed on disk since this store read it; reloaded, try again")]
    ChangedOnDisk,
    #[error("the store changed after this change was staged; reloaded from the file")]
    StaleBase,
    #[error("another change to the trusted-keys file is not finished yet; try again after it")]
    Busy,
    #[error("the trusted-keys store may be behind its file: reopen it first")]
    NeedsReopen,
    #[error("not this store's change in flight")]
    NotInFlight,
    #[error("key {} was removed ({origin}) and this ground cannot bring it back", .key_id.short())]
    Removed { key_id: KeyId, origin: &'static str },
    #[error("key {} is already in the list", .0.short())]
    AlreadyActive(KeyId),
    /// A pairing at the PC (§5, §10.2 «Разрешить», `pc_allow` + `BindingAdded`) of a key that is
    /// active or removed at another person: never written, nothing touched (`key_other_person`).
    #[error("key {} is at another person (active or removed)", .0.short())]
    OtherPerson(KeyId),
    #[error("key {} is not in the list", .0.short())]
    NotFound(KeyId),
    #[error("the list is full ({})", .0.as_str())]
    Full(Limit),
    #[error("ground {0} is spent")]
    Spent(GroundId),
    #[error("invitation {0} is spent")]
    InviteSpent(GroundId),
    /// The admission reports it as `invite_bad` (§7: `inv_id == grant.inv_id`).
    #[error("the invitation is for another inv_id than the grant's")]
    InviteIdMismatch,
    #[error("the signing key {} is not in the list", .0.short())]
    SignerUnknown(KeyId),
    #[error("the signing key {} was removed", .0.short())]
    SignerRemoved(KeyId),
    #[error("the granting key is not an active owner's")]
    NotOwner,
    #[error("the person of the grant is an owner on this PC")]
    GrantRole,
    /// §7 «Токен выдачи»: the grant carries another token than the PC's current one.
    #[error("the grant was signed over an older grant token")]
    GrantStale,
    #[error("a grant without a signed invitation: refused in trusted devices mode")]
    InviteMissing,
    #[error("the invitation's signing key is not an active owner's")]
    InviteNotOwner,
    #[error("the invitation and the grant are signed by different people")]
    InviteOwnerMismatch,
    #[error("the key would be unconfirmed, and trusted devices mode is on")]
    KeyUnconfirmed,
    #[error("the recovery key is already on another person's key")]
    RpkConflict,
    #[error("the server never removes an owner's key")]
    ServerRemovesOwner,
    /// §5: a pairing at the PC whose derived role at the write is not the one its press named.
    #[error("the role derived now is not the one the press named")]
    RoleChanged,
    #[error("first_use is closed: {0}")]
    FirstUseClosed(&'static str),
    #[error("first_use is closed: the person already has a first_use key")]
    FirstUseAgain,
    #[error("recovery: no active key of the attested person with this recovery key")]
    RecoverNoRecord,
    #[error("recovery: Telegram attested another key than the new one")]
    RecoverAttestation,
    #[error("recovery: the recovery signature does not verify")]
    RecoverBadSig,
    #[error("not valid: {0}")]
    Invalid(String),
    #[error("the backup cannot be used ({0})")]
    BackupUnusable(String),
    #[error("not saved: {0}")]
    Write(String),
}

impl StoreError {
    /// A stable name for log fields.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Damaged => "damaged",
            Self::NotDamaged => "not_damaged",
            Self::Unreadable => "unreadable",
            Self::NewerVersion => "newer_version",
            Self::ChangedOnDisk => "changed_on_disk",
            Self::StaleBase => "stale_base",
            Self::Busy => "busy",
            Self::NeedsReopen => "needs_reopen",
            Self::NotInFlight => "not_in_flight",
            Self::Removed { .. } => "removed",
            Self::AlreadyActive(_) => "already_active",
            Self::OtherPerson(_) => "other_person",
            Self::NotFound(_) => "not_found",
            Self::Full(_) => "full",
            Self::Spent(_) => "spent",
            Self::InviteSpent(_) => "invite_spent",
            Self::InviteIdMismatch => "invite_id_mismatch",
            Self::SignerUnknown(_) => "signer_unknown",
            Self::SignerRemoved(_) => "signer_removed",
            Self::NotOwner => "not_owner",
            Self::GrantRole => "grant_role",
            Self::GrantStale => "grant_stale",
            Self::InviteMissing => "invite_missing",
            Self::InviteNotOwner => "invite_not_owner",
            Self::InviteOwnerMismatch => "invite_owner_mismatch",
            Self::KeyUnconfirmed => "key_unconfirmed",
            Self::RpkConflict => "rpk_conflict",
            Self::ServerRemovesOwner => "server_removes_owner",
            Self::RoleChanged => "role_changed",
            Self::FirstUseClosed(_) => "first_use_closed",
            Self::FirstUseAgain => "first_use_again",
            Self::RecoverNoRecord => "recover_no_record",
            Self::RecoverAttestation => "recover_attestation",
            Self::RecoverBadSig => "recover_bad_sig",
            Self::Invalid(_) => "invalid",
            Self::BackupUnusable(_) => "backup_unusable",
            Self::Write(_) => "write",
        }
    }
}

// --- The list in memory -----------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrustList {
    switches: SwitchState,
    keys: Vec<KeyRecord>,
    tombstones: Vec<Tombstone>,
    spent_endorse: BTreeSet<GroundId>,
    spent_grant: BTreeSet<GroundId>,
    spent_invite: BTreeSet<GroundId>,
    snapshot: Option<FirstUseSnapshot>,
    /// Memory decides (spec §10.1 «Нажатие решает сразу»): changed in memory at once, written
    /// with the next write of any change ([`Notes`]). Boxed: the list sits unboxed in
    /// `State::Ready` and `Plan::Commit`, beside small variants (`clippy::large_enum_variant`).
    notes: Box<Notes>,
}

/// §10 «ПК знает человека»: one binding of the stored last binding list — the person and the role
/// the server's list gave them. Stored with the notes, replaced by the current list in the rule's
/// own write ([`TrustStore::bring_to_rule`]), so a person only bound here is still known when a
/// later list (of this run or the next) leaves them out. Not the current list of a
/// connection (the trusted queue's, `None` after a link loss): this one survives link losses and
/// restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownBinding {
    pub telegram_user_id: i64,
    pub role: BindingRole,
}

/// Another device's attempt (spec §10.2): an offer whose signature verified, with a valid card,
/// for a key the PC does not know, refused; one per (person, key). Times on the PC's clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub telegram_user_id: i64,
    /// The server's word (`session_request`): shown, never given («Разрешить» takes the role of
    /// the person's keys on the PC).
    pub role: BindingRole,
    pub key: ViewerKey,
    pub kind: ClientKind,
    pub platform: Platform,
    pub rpk: Option<ViewerKey>,
    pub first_at: i64,
    pub last_at: i64,
    pub count: u32,
}

impl Attempt {
    pub fn key_id(&self) -> &KeyId {
        self.key.key_id()
    }
}

/// The list's notes: the grant token (§7 «Токен выдачи»), the attempts (§10.2) and the stored last
/// binding list (§10). In memory they decide at once and every write carries them as they are then
/// (a snapshot), so no write loses an earlier note and a parked write is overtaken by the next one
/// safely.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes {
    grant_token: GrantToken,
    attempts: Vec<Attempt>,
    /// The stored last binding list, by user id ([`KnownBinding`]); `None`: none stored (a first
    /// run, a file older than it, a reset) — the rule then knows people by their traces alone.
    last_bindings: Option<Vec<KnownBinding>>,
}

impl Notes {
    /// Memory's notes (`mine`) kept over a reload of the file's (`self`), against `base`: the
    /// notes as memory last knew the disk to hold them (written or read). The grant token:
    /// memory's when memory replaced it since `base` (it was never sent), else the file's.
    fn merge_from(&mut self, mine: &Self, base: &Self) {
        // The file's attempts that memory dropped since the last write (a removal took them) are
        // not the file's to bring back: three ways against the last write.
        let file_attempts = self.attempts.len();
        self.attempts.retain(|a| {
            let same =
                |x: &Attempt| x.telegram_user_id == a.telegram_user_id && x.key_id() == a.key_id();
            mine.attempts.iter().any(same) || !base.attempts.iter().any(same)
        });
        let dropped = file_attempts - self.attempts.len();
        if dropped > 0 {
            tracing::debug!(
                dropped,
                kept = self.attempts.len(),
                "viewer keys: the file's attempts that memory dropped since the last write (a \
                 removal took them) are not brought back by the reload"
            );
        }
        if mine.grant_token != base.grant_token {
            tracing::debug!(
                file_moved = self.grant_token != base.grant_token,
                "viewer keys: memory's grant token kept over the file's (replaced in memory since \
                 the last write; never sent)"
            );
            self.grant_token = mine.grant_token;
        } else if self.grant_token != base.grant_token {
            tracing::debug!(
                "viewer keys: the file's grant token taken (another writer replaced it; memory \
                 kept the one last written)"
            );
        }
        // Memory's binding list is the later one (the file only had what memory wrote).
        if mine.last_bindings.is_some() && mine.last_bindings != self.last_bindings {
            tracing::debug!(
                file = self.last_bindings.as_ref().map(Vec::len),
                memory = mine.last_bindings.as_ref().map(Vec::len),
                "viewer keys: memory's last known binding list kept over the file's"
            );
            self.last_bindings.clone_from(&mine.last_bindings);
        }
        // One entry per (person, key), the fresher of the two — the later last try (its
        // role and card), the higher count, the earlier first try; memory's own attempts after
        // the file's. The caps are the caller's ([`TrustStore::keep_notes`]): it knows the trace.
        let (mut freshened, mut added) = (0usize, 0usize);
        for a in &mine.attempts {
            match self
                .attempts
                .iter_mut()
                .find(|x| x.telegram_user_id == a.telegram_user_id && x.key_id() == a.key_id())
            {
                Some(x) => {
                    if *x == *a {
                        continue;
                    }
                    let (first_at, count) = (x.first_at.min(a.first_at), x.count.max(a.count));
                    if a.last_at > x.last_at {
                        *x = a.clone();
                    }
                    x.first_at = first_at;
                    x.count = count;
                    freshened += 1;
                }
                None => {
                    self.attempts.push(a.clone());
                    added += 1;
                }
            }
        }
        if freshened > 0 || added > 0 {
            tracing::debug!(
                freshened,
                added,
                total = self.attempts.len(),
                "viewer keys: memory's attempts merged over the file's (per person and key, the \
                 fresher of each)"
            );
        }
    }

    /// A fresh grant token in place of the current one (§7 «Токен выдачи»): the one place the token
    /// is replaced — memory's ([`TrustStore::rotate_grant_token`]) and a repaired list's, which
    /// memory does not have. `why` is logged, never the value.
    fn new_grant_token(&mut self, why: &str) {
        let was_none = self.grant_token.is_empty();
        self.grant_token = GrantToken::fresh(self.grant_token);
        tracing::info!(
            why,
            was_none,
            "viewer keys: the grant token replaced (every grant signed before is refused \
             grant_stale; the server hears the new one once it is written)"
        );
    }
}

/// §10.2: an attempt counts while its last try is at most [`ATTEMPT_KEEP_MS`] before `now_ms`
/// (the PC's wall clock) — the one rule every reader of the attempts goes by.
fn attempt_counts(a: &Attempt, now_ms: i64) -> bool {
    now_ms.saturating_sub(a.last_at) <= ATTEMPT_KEEP_MS
}

/// What [`TrustStore::note_attempt_how`] did with another device's attempt (§10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptNoted {
    /// A new entry.
    New,
    /// The stored entry counted again (its last try moved).
    Repeated,
    /// Not recorded: the newcomer was itself the oldest last try over a cap
    /// ([`evict_attempts`]; a clock set back). The journal goes as usual.
    NotRecorded,
    /// No attempt: out of range, a key in the list or removed, or no healthy list.
    Ignored,
}

/// §10.2: the caps after a new attempt (`newcomer`: its person and key) was pushed last, or over a
/// merged list (`None`, [`TrustStore::keep_notes`]), by age only: a person over
/// [`ATTEMPTS_PER_PERSON`] loses their oldest last try, and the list over [`ATTEMPTS_MAX`] its
/// oldest last try, whoever's it is. Whether the newcomer stays (`true` with no newcomer).
fn evict_attempts(attempts: &mut Vec<Attempt>, newcomer: Option<(i64, &KeyId)>) -> bool {
    let is_new =
        |a: &Attempt| newcomer.is_some_and(|(u, k)| a.telegram_user_id == u && a.key_id() == k);
    let oldest = |attempts: &[Attempt], pick: &dyn Fn(&Attempt) -> bool| {
        attempts
            .iter()
            .enumerate()
            .filter(|(_, a)| pick(a))
            .min_by_key(|(_, a)| a.last_at)
            .map(|(i, _)| i)
    };
    // The people the per-person cap may concern: the newcomer's, or everyone in a merged list.
    let mut over: Vec<i64> = match newcomer {
        Some((uid, _)) => vec![uid],
        None => attempts.iter().map(|a| a.telegram_user_id).collect(),
    };
    over.sort_unstable();
    over.dedup();
    for uid in over {
        while attempts
            .iter()
            .filter(|a| a.telegram_user_id == uid)
            .count()
            > ATTEMPTS_PER_PERSON
        {
            let Some(i) = oldest(attempts, &|a| a.telegram_user_id == uid) else {
                break;
            };
            let a = attempts.remove(i);
            tracing::debug!(
                kid = %a.key_id().short(),
                user_id = uid,
                last_at = a.last_at,
                cap = ATTEMPTS_PER_PERSON,
                merged = newcomer.is_none(),
                "viewer keys: the person's oldest attempt evicted (the per-person cap)"
            );
        }
    }
    while attempts.len() > ATTEMPTS_MAX {
        let Some(i) = oldest(attempts, &|_| true) else {
            break;
        };
        let a = attempts.remove(i);
        tracing::debug!(
            kid = %a.key_id().short(),
            user_id = a.telegram_user_id,
            last_at = a.last_at,
            cap = ATTEMPTS_MAX,
            merged = newcomer.is_none(),
            "viewer keys: the oldest attempt evicted (the cap in all)"
        );
    }
    newcomer.is_none() || attempts.iter().any(is_new)
}

/// §10.2: a key that entered the list (pairing or any ground) drops only the SAME person's
/// attempts with it — for a ground, the ground's person, the record's. Another person's attempt
/// with the same key stays (the server, replaying that person's `key_reg` under another name,
/// would otherwise erase a real attempt with one «Разрешить»), and so does every attempt of a
/// removed key. Kept state-wise: an attempt is never noted for a key in the list, so (person,
/// key) with the key active at that person is exactly one that entered. How many went.
fn drop_entered_attempts(list: &mut TrustList, what: &str) -> usize {
    if list.notes.attempts.is_empty() {
        return 0;
    }
    let entered: HashSet<(i64, &KeyId)> = list
        .keys
        .iter()
        .map(|r| (r.person.telegram_user_id, r.key_id()))
        .collect();
    let before = list.notes.attempts.len();
    let mut gone = Vec::new();
    list.notes.attempts.retain(|a| {
        let drop = entered.contains(&(a.telegram_user_id, a.key_id()));
        if drop {
            gone.push((a.telegram_user_id, a.key_id().short().to_owned()));
        }
        !drop
    });
    let others = list
        .notes
        .attempts
        .iter()
        .filter(|a| list.keys.iter().any(|r| r.key_id() == a.key_id()))
        .count();
    if !gone.is_empty() || others > 0 {
        tracing::debug!(
            what,
            dropped = ?gone,
            kept_of_another_persons_key = others,
            "viewer keys: attempts of keys in the list: the same person's go, another person's \
             stay"
        );
    }
    before - list.notes.attempts.len()
}

/// The §10.1 walk's edges ([`TrustList::walk_index`]): parent → children (by `parents`), and a
/// recovery → the records it replaced.
struct WalkIndex<'a> {
    children: HashMap<&'a KeyId, Vec<&'a KeyId>>,
    replaced: HashMap<&'a KeyId, &'a [KeyId]>,
}

impl<'a> WalkIndex<'a> {
    /// Breadth first from `root` (first): children, then a recovery's replaced records.
    fn walk(&self, root: &'a KeyId) -> Vec<&'a KeyId> {
        self.walk_many(&[root])
    }

    /// [`Self::walk`] from several roots at once (in their order).
    fn walk_many(&self, roots: &[&'a KeyId]) -> Vec<&'a KeyId> {
        let mut seen: HashSet<&KeyId> = HashSet::new();
        let mut queue: VecDeque<&KeyId> =
            roots.iter().copied().filter(|r| seen.insert(r)).collect();
        let mut out = Vec::new();
        while let Some(id) = queue.pop_front() {
            out.push(id);
            let children = self.children.get(id).map(Vec::as_slice).unwrap_or_default();
            let replaced = self.replaced.get(id).copied().unwrap_or_default();
            for next in children.iter().copied().chain(replaced) {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        out
    }
}

impl TrustList {
    fn find(&self, key_id: &KeyId) -> Option<usize> {
        self.keys.iter().position(|r| r.key_id() == key_id)
    }

    fn active(&self, key_id: &KeyId) -> Option<&KeyRecord> {
        self.find(key_id).map(|i| &self.keys[i])
    }

    fn tombstone(&self, key_id: &KeyId) -> Option<&Tombstone> {
        self.tombstones.iter().find(|t| t.key_id() == key_id)
    }

    fn keys_of(&self, uid: i64) -> impl Iterator<Item = &KeyRecord> {
        self.keys
            .iter()
            .filter(move |r| r.person.telegram_user_id == uid)
    }

    fn spent_count(&self) -> usize {
        self.spent_endorse.len() + self.spent_grant.len() + self.spent_invite.len()
    }

    /// Room for one more key of `uid` (after any tombstone the add lifts) that spends `spends`
    /// ground ids. A confirmed pairing at the PC (`at_pc`) is held by [`MAX_TOMBSTONES_AT_PC`]
    /// instead of [`MAX_TOMBSTONES`] (spec §10: actions at the PC are not blocked by what the
    /// server filled).
    fn room_for_new(&self, uid: i64, spends: usize, at_pc: bool) -> Result<(), StoreError> {
        let tombstone_limit = if at_pc {
            MAX_TOMBSTONES_AT_PC
        } else {
            MAX_TOMBSTONES
        };
        let full = if self.keys.len() >= MAX_ACTIVE_KEYS {
            Some(Limit::Active)
        } else if self.keys_of(uid).count() >= MAX_KEYS_PER_PERSON {
            Some(Limit::PerPerson)
        } else if self.tombstones.len() >= tombstone_limit {
            Some(Limit::Tombstones)
        } else if self.spent_count() + spends > MAX_SPENT {
            Some(Limit::Spent)
        } else {
            None
        };
        match full {
            Some(limit) => {
                // Read by every plan (the request window's every turn): trace; the write's
                // refusal says the limit ("add refused", `full`).
                tracing::trace!(
                    limit = limit.as_str(),
                    active = self.keys.len(),
                    of_person = self.keys_of(uid).count(),
                    tombstones = self.tombstones.len(),
                    tombstone_limit,
                    at_pc,
                    spent = self.spent_count(),
                    spends,
                    "viewer keys: no room for a new key"
                );
                Err(StoreError::Full(limit))
            }
            None => Ok(()),
        }
    }

    /// The `first_use` person and role for `uid` (§9), or why not.
    fn first_use_person(&self, uid: i64) -> Result<SnapshotPerson, StoreError> {
        // Before the mode: in both modes the admission journals a second first_use.
        if self
            .keys_of(uid)
            .any(|r| matches!(r.source, KeySource::FirstUse))
        {
            return Err(StoreError::FirstUseAgain);
        }
        if self.switches.trusted_devices_mode {
            return Err(StoreError::FirstUseClosed("trusted devices mode is on"));
        }
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or(StoreError::FirstUseClosed("no snapshot taken yet"))?;
        let entry = snapshot
            .people
            .iter()
            .find(|p| p.person.telegram_user_id == uid)
            .ok_or(StoreError::FirstUseClosed(
                "the person is not in the snapshot",
            ))?;
        if self.keys_of(uid).next().is_some() {
            return Err(StoreError::FirstUseClosed("the person has a key"));
        }
        if self.tombstones.iter().any(|t| t.telegram_user_id == uid) {
            return Err(StoreError::FirstUseClosed("the person has a removed key"));
        }
        Ok(entry.clone())
    }

    /// The §10.1 walk's edges over every record and tombstone (a removed or replaced record keeps
    /// its source, so the walk goes through inactive links).
    fn walk_index(&self) -> WalkIndex<'_> {
        let mut children: HashMap<&KeyId, Vec<&KeyId>> = HashMap::new();
        let mut replaced: HashMap<&KeyId, &[KeyId]> = HashMap::new();
        let nodes = self
            .keys
            .iter()
            .map(|r| (r.key_id(), &r.source))
            .chain(self.tombstones.iter().map(|t| (t.key_id(), &t.source)));
        for (id, source) in nodes {
            for parent in source.parents() {
                children.entry(parent).or_default().push(id);
            }
            if !source.replaced().is_empty() {
                replaced.insert(id, source.replaced());
            }
        }
        WalkIndex { children, replaced }
    }

    /// `root` and every key, active or removed, that the §10.1 walk reaches from it, `root`
    /// first, then breadth first: the keys whose `endorse.by`, `grant.by`, `invite.by` or
    /// recovery `parents` name a key on the way, and from a recovery on to the records it
    /// replaced (it inherits their descendants). Removed keys are links too (their sources are
    /// kept): a key endorsed by a removed key that `root` had endorsed still descends from `root`.
    fn descendants(&self, root: &KeyId) -> Vec<KeyId> {
        self.walk_index().walk(root).into_iter().cloned().collect()
    }

    /// What «Удалить» on `root` takes (§10.1): the active keys of its tree, the root first when it
    /// is active, and the whole tree (active and removed). [`StoreError::NotFound`] for a key the
    /// list does not know at all.
    fn tree_of(&self, root: &KeyId) -> Result<(Vec<KeyId>, Vec<KeyId>), StoreError> {
        if self.find(root).is_none() && self.tombstone(root).is_none() {
            return Err(StoreError::NotFound(root.clone()));
        }
        let tree = self.descendants(root);
        let active: Vec<KeyId> = tree
            .iter()
            .filter(|id| self.find(id).is_some())
            .cloned()
            .collect();
        Ok((active, tree))
    }

    /// What «Удалить человека» at the PC takes (§10.2): the roots (the person's active keys, then
    /// their tombstones), the walk from all of them (active and removed), and the active keys on
    /// it in walk order.
    fn person_walk(&self, telegram_user_id: i64) -> (Vec<KeyId>, Vec<KeyId>, Vec<KeyId>) {
        let roots: Vec<KeyId> = self
            .keys_of(telegram_user_id)
            .map(|r| r.key_id().clone())
            .chain(
                self.tombstones
                    .iter()
                    .filter(|t| t.telegram_user_id == telegram_user_id)
                    .map(|t| t.key_id().clone()),
            )
            .collect();
        let index = self.walk_index();
        let refs: Vec<&KeyId> = roots.iter().collect();
        let walk: Vec<KeyId> = index.walk_many(&refs).into_iter().cloned().collect();
        let removed: Vec<KeyId> = walk
            .iter()
            .filter(|id| self.find(id).is_some())
            .cloned()
            .collect();
        (roots, walk, removed)
    }

    /// The active keys as (key_id → person, role, mark), for [`Reloaded`].
    fn active_view(&self) -> HashMap<KeyId, (i64, BindingRole, bool)> {
        self.keys
            .iter()
            .map(|r| {
                (
                    r.key_id().clone(),
                    (r.person.telegram_user_id, r.role, r.unconfirmed),
                )
            })
            .collect()
    }
}

/// What a reload of the file changed in the active list (see the module docs): end the sessions
/// of `left_active`, journal `joined_active`, re-check the sessions of `changed`.
#[must_use = "a reload may have removed keys whose sessions must end"]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reloaded {
    /// Active before, not active now (removed, replaced, or the store is damaged now).
    pub left_active: Vec<KeyId>,
    /// Active now, not before.
    pub joined_active: Vec<KeyId>,
    /// Active before and now, with another person, role or `unconfirmed` mark.
    pub changed: Vec<KeyId>,
    /// The file did not load: the store is damaged now (every key denied).
    pub damaged: bool,
    /// Keys that joined as descendants of a key whose removal is pending and inherited the mark
    /// ([`TrustStore::pending_without_removal`]): each needs a removal staged.
    pub inherited_pending: Vec<KeyId>,
    /// [`TrustStore::take_reopen`] did not take the load (stale, or another store's): nothing
    /// changed, the store needs a reopen with a fresh load.
    pub needs_reopen: bool,
}

impl Reloaded {
    /// Whether the active list is what it was.
    pub fn is_empty(&self) -> bool {
        self.left_active.is_empty()
            && self.joined_active.is_empty()
            && self.changed.is_empty()
            && !self.damaged
    }

    fn between(
        before: &HashMap<KeyId, (i64, BindingRole, bool)>,
        after: Option<&HashMap<KeyId, (i64, BindingRole, bool)>>,
    ) -> Self {
        let empty = HashMap::new();
        let now = after.unwrap_or(&empty);
        let mut left_active: Vec<KeyId> = before
            .keys()
            .filter(|k| !now.contains_key(*k))
            .cloned()
            .collect();
        let mut joined_active: Vec<KeyId> = now
            .keys()
            .filter(|k| !before.contains_key(*k))
            .cloned()
            .collect();
        let mut changed: Vec<KeyId> = now
            .iter()
            .filter(|(k, v)| before.get(*k).is_some_and(|b| b != *v))
            .map(|(k, _)| k.clone())
            .collect();
        left_active.sort();
        joined_active.sort();
        changed.sort();
        Self {
            left_active,
            joined_active,
            changed,
            damaged: after.is_none(),
            inherited_pending: Vec::new(),
            needs_reopen: false,
        }
    }
}

/// An install that could not apply ([`TrustStore::install`]): why, the outcome the change was
/// staged with (what it would have done), and what memory changed meanwhile.
///
/// **The admission reads `reloaded` and [`TrustStore::needs_reopen`], not just `error`**: an
/// install never does I/O, so `reloaded` is empty and, with [`StoreError::StaleBase`], the store
/// needs a reopen — whose own [`Reloaded`] says which keys left (end their sessions) and joined.
#[derive(Debug)]
pub struct NotInstalled<T> {
    pub error: StoreError,
    pub outcome: T,
    pub reloaded: Reloaded,
}

#[derive(Debug)]
enum State {
    Ready(TrustList),
    Damaged(Damage),
}

/// Where the store was opened, for [`TrustStore::reopen`].
#[derive(Debug, Clone, Copy)]
enum Opened {
    Default,
    /// [`TrustStore::open_in`]: the paths already held.
    Dir,
}

// --- Staged changes ---------------------------------------------------------------------------

/// The primary's bytes, shared between the store and its staged changes (a stage keeps the base
/// without copying it).
type Bytes = Arc<Vec<u8>>;

/// What [`Staged::write`] will do.
#[derive(Debug)]
enum Plan {
    /// An ordinary change: `next`, serialized in the write, replaces `base`, which goes to the
    /// backup.
    Commit {
        next: TrustList,
        /// The primary's bytes the change was built on; `None` when there was no primary.
        base: Option<Bytes>,
        /// The base list's switch: a change that turns it on is refused when the mode file
        /// cannot be made strict first.
        base_strict: bool,
    },
    /// Reset of a damaged store at the PC (the backup is read in the write).
    ResetDamaged {
        now_ms: i64,
        /// The damaged primary as this store loaded it (`None`: there was none): the write
        /// refuses [`StoreError::ChangedOnDisk`] unless the file still holds exactly that.
        expect: Option<Bytes>,
        /// The switch the repaired list keeps: the damaged store's effective one
        /// ([`TrustStore::damaged_mode`], strict when it says nothing).
        strict: bool,
    },
    /// Restore of the backup over a damaged store at the PC.
    Restore {
        now_ms: i64,
        /// As for [`Plan::ResetDamaged`].
        expect: Option<Bytes>,
        /// As for [`Plan::ResetDamaged`]: never the backup's own switch.
        strict: bool,
    },
}

/// Tickets of changes in flight, unique in the process (so a [`Written`] from another store
/// instance is never taken for this one's).
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);

/// The one lock of this module: held by [`Staged::write`], on its blocking thread, around the
/// file steps of a write (re-read + backup + primary; a repair's keep + read + primary), so two
/// writes in this process can never interleave there. Never held while waiting on another thread
/// or task.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Take [`WRITE_LOCK`], with a line when another write holds it. A poisoned lock (a write that
/// panicked) is taken all the same: the files are checked by the re-read, not by the lock's state.
fn write_lock(what: &str) -> MutexGuard<'static, ()> {
    match WRITE_LOCK.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(p)) => {
            tracing::warn!(
                change = what,
                "viewer keys: the write lock was poisoned; taken"
            );
            p.into_inner()
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            tracing::debug!(
                change = what,
                "viewer keys: another write of the file is under way; waiting for it"
            );
            WRITE_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}

/// A test's pause inside a write, between the re-read check and the backup (see the tests).
#[cfg(test)]
type PauseHook = Arc<dyn Fn() + Send + Sync>;

/// A change decided and not yet written (see the module docs: stage, write, install). Owns
/// everything [`Staged::write`] needs, so it can go to a blocking thread. While it (or what its
/// write returns) is not installed or abandoned, the store stages nothing else.
#[must_use = "a staged change does nothing until it is written and installed, or abandoned"]
pub struct Staged<T> {
    plan: Plan,
    /// The store's generation the change was built on ([`TrustStore::install`] checks it).
    generation: u64,
    /// Which change in flight this is ([`TrustStore::install`], [`TrustStore::abandon`]).
    ticket: u64,
    /// The change is alive while this (moved on into [`Written`] / [`WriteFailed`]) is: the
    /// store keeps only a `Weak`, so a change dropped anywhere is seen as lost.
    token: Arc<()>,
    primary: PathBuf,
    backup: PathBuf,
    what: String,
    outcome: T,
    #[cfg(test)]
    pause: Option<PauseHook>,
}

impl<T> fmt::Debug for Staged<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Staged")
            .field("what", &self.what)
            .field("generation", &self.generation)
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

/// A written change, for [`TrustStore::install`].
#[must_use = "a written change takes effect in memory only when installed"]
pub struct Written<T> {
    next: TrustList,
    bytes: Bytes,
    /// For an ordinary change: the primary's bytes the locked re-read found before this write
    /// (`None` inside: no primary). `None` for a repair, which proves no base.
    base: Option<Option<Bytes>>,
    generation: u64,
    ticket: u64,
    /// Keeps the change alive for the store's `Weak` (see [`Staged`]).
    _token: Arc<()>,
    what: String,
    outcome: T,
}

impl<T> Written<T> {
    /// What the change will report once installed.
    pub fn outcome(&self) -> &T {
        &self.outcome
    }
}

impl<T> fmt::Debug for Written<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Written")
            .field("what", &self.what)
            .field("generation", &self.generation)
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

/// A write that failed: the error, and the change, for [`TrustStore::abandon`] (which ends it and,
/// after [`StoreError::ChangedOnDisk`], reloads the file).
#[must_use = "a failed write keeps the store busy until it is abandoned"]
pub struct WriteFailed<T>(Box<Failure<T>>);

/// The inside of a [`WriteFailed`] (boxed: an `Err` stays small).
struct Failure<T> {
    error: StoreError,
    ticket: u64,
    what: String,
    outcome: T,
    generation: u64,
    token: Arc<()>,
    /// After [`StoreError::ChangedOnDisk`]: the file as the write's thread loaded it right after,
    /// so [`TrustStore::abandon`] reloads without I/O on the caller's thread.
    fresh: Option<Loaded>,
}

impl<T> WriteFailed<T> {
    pub fn error(&self) -> &StoreError {
        &self.0.error
    }

    /// What the change would have reported.
    pub fn outcome(&self) -> &T {
        &self.0.outcome
    }
}

impl<T> fmt::Debug for WriteFailed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteFailed")
            .field("error", &self.0.error)
            .field("what", &self.0.what)
            .field("ticket", &self.0.ticket)
            .finish_non_exhaustive()
    }
}

mod sealed {
    /// What [`super::TrustStore::abandon`] needs of a change in flight.
    pub struct Parts {
        pub(super) ticket: u64,
        /// The generation the change was built on.
        pub(super) generation: u64,
        /// Kept until the abandon is over.
        pub(super) _token: std::sync::Arc<()>,
        pub(super) what: String,
        /// The write's error; `None` for a change never written.
        pub(super) error: Option<super::StoreError>,
        /// The file as loaded after [`super::StoreError::ChangedOnDisk`].
        pub(super) fresh: Option<super::Loaded>,
    }

    pub trait Sealed {
        fn into_parts(self) -> Parts;
    }
}

/// A change in flight that will not be installed: a [`Staged`] the caller decided not to write,
/// or a [`WriteFailed`].
pub trait Abandon: sealed::Sealed {}

impl<T> sealed::Sealed for Staged<T> {
    fn into_parts(self) -> sealed::Parts {
        sealed::Parts {
            ticket: self.ticket,
            generation: self.generation,
            _token: self.token,
            what: self.what,
            error: None,
            fresh: None,
        }
    }
}

impl<T> Abandon for Staged<T> {}

impl<T> sealed::Sealed for WriteFailed<T> {
    fn into_parts(self) -> sealed::Parts {
        let Failure {
            error,
            ticket,
            what,
            generation,
            token,
            fresh,
            ..
        } = *self.0;
        sealed::Parts {
            ticket,
            generation,
            _token: token,
            what,
            error: Some(error),
            fresh,
        }
    }
}

impl<T> Abandon for WriteFailed<T> {}

impl<T> Staged<T> {
    /// What the change will report once installed.
    pub fn outcome(&self) -> &T {
        &self.outcome
    }

    /// A test's pause inside the write, between the re-read check and the backup.
    #[cfg(test)]
    fn with_pause(mut self, pause: PauseHook) -> Self {
        self.pause = Some(pause);
        self
    }

    /// Write the change (blocking file I/O; see the module docs). Nothing here touches the store
    /// in memory: on success hand the result to [`TrustStore::install`], on failure to
    /// [`TrustStore::abandon`].
    pub fn write(self) -> Result<Written<T>, WriteFailed<T>> {
        let Self {
            plan,
            generation,
            ticket,
            token,
            primary,
            backup,
            what,
            outcome,
            #[cfg(test)]
            pause,
        } = self;
        #[cfg(not(test))]
        let pause = ();
        let result = match plan {
            Plan::Commit {
                next,
                base,
                base_strict,
            } => write_commit(
                &primary,
                &backup,
                &next,
                base.as_ref(),
                base_strict,
                &what,
                &pause,
            )
            .map(|bytes| (next, bytes, Some(base))),
            Plan::ResetDamaged {
                now_ms,
                expect,
                strict,
            } => reset_damaged_files(&primary, &backup, now_ms, expect.as_ref(), strict, &what)
                .map(|(next, bytes)| (next, bytes, None)),
            Plan::Restore {
                now_ms,
                expect,
                strict,
            } => restore_files(&primary, &backup, now_ms, expect.as_ref(), strict, &what)
                .map(|(next, bytes)| (next, bytes, None)),
        };
        match result {
            Ok((next, bytes, base)) => {
                tracing::debug!(
                    bytes = bytes.len(),
                    change = %what,
                    ticket,
                    "viewer keys: written, to be installed"
                );
                Ok(Written {
                    next,
                    bytes: Arc::new(bytes),
                    base,
                    generation,
                    ticket,
                    _token: token,
                    what,
                    outcome,
                })
            }
            Err(error) => {
                tracing::debug!(
                    reason = error.as_str(),
                    change = %what,
                    ticket,
                    "viewer keys: not written, to be abandoned ({error})"
                );
                // Another writer changed the file: load it here, on the blocking thread, for the
                // abandon's reload.
                let fresh = (error == StoreError::ChangedOnDisk).then(|| load(&primary, &backup));
                Err(WriteFailed(Box::new(Failure {
                    error,
                    ticket,
                    what,
                    outcome,
                    generation,
                    token,
                    fresh,
                })))
            }
        }
    }
}

/// The checks before a write: the new list fits a file and would load.
fn check_writable(bytes: &[u8]) -> Result<(), StoreError> {
    if bytes.len() as u64 > MAX_FILE_BYTES {
        tracing::warn!(
            bytes = bytes.len(),
            "viewer keys: not saved, the list would be larger than a file is read"
        );
        return Err(StoreError::Invalid(format!(
            "the list would be {} bytes",
            bytes.len()
        )));
    }
    if let Err(damage) = parse_list(bytes) {
        tracing::debug!(damage = %damage, "viewer keys: not saved, the new list would not load");
        return Err(StoreError::Invalid(damage.to_string()));
    }
    Ok(())
}

/// The test pause of a write, or nothing.
#[cfg(test)]
type Pause = Option<PauseHook>;
#[cfg(not(test))]
type Pause = ();

/// An ordinary change's write: the bytes and their checks (no lock), then under [`WRITE_LOCK`]
/// the re-read against `base`, the mode file when it turns strict, the backup, the primary, the
/// mode file when it turns observe. The new bytes on success.
fn write_commit(
    primary: &Path,
    backup: &Path,
    next: &TrustList,
    base: Option<&Bytes>,
    base_strict: bool,
    what: &str,
    #[cfg_attr(not(test), allow(unused_variables))] pause: &Pause,
) -> Result<Vec<u8>, StoreError> {
    let bytes = serialize(next)?;
    check_writable(&bytes)?;
    let _guard = write_lock(what);
    match read_bounded(primary) {
        Ok(on_disk) if on_disk.as_deref() == base.map(|b| b.as_slice()) => {}
        Ok(_) => {
            tracing::warn!(
                path = %primary.display(),
                change = what,
                "viewer keys: the file changed on disk since this store read or wrote it \
                 (another writer); the change is refused and the file is to be reloaded"
            );
            return Err(StoreError::ChangedOnDisk);
        }
        Err(e) => {
            tracing::debug!("viewer keys: not saved, the file could not be re-read: {e}");
            return Err(StoreError::Write(e));
        }
    }
    #[cfg(test)]
    if let Some(pause) = pause {
        pause();
    }
    let next_strict = next.switches.trusted_devices_mode;
    let side = read_mode(primary);
    // Turning the switch on must not leave the mode file at observe; any other change only
    // fixes a stale mode file on the way, and never fails for it.
    mode_before(
        primary,
        &side,
        next_strict,
        next_strict && !base_strict,
        what,
    )?;
    if let Some(current) = base {
        if let Err(e) = crate::config::write_whole(backup, current) {
            tracing::debug!("viewer keys: backup not written, nothing changed: {e:#}");
            return Err(StoreError::Write(format!("backup: {e:#}")));
        }
    }
    if let Err(e) = crate::config::write_whole(primary, &bytes) {
        tracing::debug!("viewer keys: list not written, nothing changed: {e:#}");
        return Err(StoreError::Write(format!("{e:#}")));
    }
    mode_after(primary, &side, next_strict, what);
    Ok(bytes)
}

/// What the mode file says ([`MODE_FILE_NAME`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Side {
    Missing,
    /// It could not be read, or is not a mode file of this format (the reason, for the log).
    Unusable(String),
    /// Its `trusted_devices_mode`.
    Says(bool),
}

impl Side {
    /// The switch it gives a damaged list: `None` (strict) unless it is readable.
    fn says(&self) -> Option<bool> {
        match self {
            Self::Says(on) => Some(*on),
            Self::Missing | Self::Unusable(_) => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Missing => "missing".into(),
            Self::Unusable(why) => format!("unusable ({why})"),
            Self::Says(true) => "strict".into(),
            Self::Says(false) => "observe".into(),
        }
    }
}

/// The mode file of the list at `primary`.
fn mode_path(primary: &Path) -> PathBuf {
    primary.with_file_name(MODE_FILE_NAME)
}

/// The mode file's content, fields in this order.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeFile {
    version: u32,
    trusted_devices_mode: bool,
}

/// The mode file of the list at `primary`, as read now (blocking).
fn read_mode(primary: &Path) -> Side {
    let path = mode_path(primary);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Side::Missing,
        Err(e) => return Side::Unusable(format!("open: {e}")),
    };
    let mut bytes = Vec::new();
    if let Err(e) = file.take(MAX_MODE_BYTES + 1).read_to_end(&mut bytes) {
        return Side::Unusable(format!("read: {e}"));
    }
    if bytes.len() as u64 > MAX_MODE_BYTES {
        return Side::Unusable(format!("more than {MAX_MODE_BYTES} bytes"));
    }
    match serde_json::from_slice::<ModeFile>(&bytes) {
        Ok(m) if m.version == MODE_FORMAT_VERSION => Side::Says(m.trusted_devices_mode),
        Ok(m) => Side::Unusable(format!("version {}", m.version)),
        // The kind and place only, as for the list.
        Err(e) => Side::Unusable(format!(
            "{:?} at line {} column {}",
            e.classify(),
            e.line(),
            e.column()
        )),
    }
}

/// Write the mode file of the list at `primary` whole (blocking).
fn write_mode(primary: &Path, strict: bool) -> Result<(), String> {
    let bytes = serde_json::to_vec(&ModeFile {
        version: MODE_FORMAT_VERSION,
        trusted_devices_mode: strict,
    })
    .map_err(|e| format!("serialize: {e}"))?;
    crate::config::write_whole(&mode_path(primary), &bytes).map_err(|e| format!("{e:#}"))
}

/// Before the list is written, under [`WRITE_LOCK`]: a list that will be strict gets «strict» in
/// the mode file first, unless it already says so — a crash or a failed list write after this
/// leaves the mode file stricter than the list, never laxer. When the write fails, the mode file
/// is removed (missing reads as strict). When that fails too: `required` (the change turns the
/// switch on, or a repair) refuses the change; otherwise `warn` and go on (the mode file was
/// already stale before this change; the next write or open tries again).
fn mode_before(
    primary: &Path,
    side: &Side,
    next_strict: bool,
    required: bool,
    what: &str,
) -> Result<(), StoreError> {
    if !next_strict || *side == Side::Says(true) {
        return Ok(());
    }
    let Err(write_error) = write_mode(primary, true) else {
        tracing::debug!(
            change = what,
            was = %side.describe(),
            "viewer keys: mode file set to strict before the list"
        );
        return Ok(());
    };
    let path = mode_path(primary);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::warn!(
                change = what,
                "viewer keys: mode file not written ({write_error}); removed instead (a missing \
                 one reads as strict)"
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                change = what,
                "viewer keys: mode file not written ({write_error}); there is none (reads as \
                 strict)"
            );
            Ok(())
        }
        Err(remove_error) if required => {
            tracing::warn!(
                change = what,
                was = %side.describe(),
                "viewer keys: not saved: the mode file can be neither set to strict \
                 ({write_error}) nor removed ({remove_error}); nothing changed"
            );
            Err(StoreError::Write(format!("mode file: {write_error}")))
        }
        Err(remove_error) => {
            tracing::warn!(
                change = what,
                was = %side.describe(),
                "viewer keys: the mode file can be neither set to strict ({write_error}) nor \
                 removed ({remove_error}); the list is saved all the same (the change does not \
                 turn the switch on); tried again at the next write or open"
            );
            Ok(())
        }
    }
}

/// After the list is written, under [`WRITE_LOCK`]: a list that is now observe gets «observe» in
/// the mode file, unless it already says so. A failure is only a `warn`: the mode file stays
/// strict, missing or unusable — all strict for a damaged list — and the next write or open
/// tries again.
fn mode_after(primary: &Path, side: &Side, next_strict: bool, what: &str) {
    if next_strict || *side == Side::Says(false) {
        return;
    }
    match write_mode(primary, false) {
        Ok(()) => tracing::debug!(
            change = what,
            was = %side.describe(),
            "viewer keys: mode file set to observe after the list"
        ),
        Err(e) => tracing::warn!(
            change = what,
            was = %side.describe(),
            "viewer keys: the list is saved, the mode file not set to observe ({e}); a damaged \
             list would be strict until the next write or open"
        ),
    }
}

/// At an open or reopen (blocking), for a healthy list whose mode file is missing, unusable or
/// says the other mode (an upgrade, a crash between the two files, a failed mode write): write
/// what the list says — under [`WRITE_LOCK`], and only while the primary still holds the bytes
/// loaded (a write meanwhile has set the mode file itself). Updates `loaded.side` when written.
fn mode_at_open(primary: &Path, loaded: &mut Loaded) {
    let Ok(Some((list, bytes))) = &loaded.list else {
        return;
    };
    let strict = list.switches.trusted_devices_mode;
    if loaded.side == Side::Says(strict) {
        return;
    }
    let _guard = write_lock("mode file at open");
    match read_bounded(primary) {
        Ok(Some(now)) if now == *bytes => {}
        other => {
            tracing::debug!(
                changed = other.is_ok(),
                "viewer keys: mode file not synced at open: the list changed or could not be \
                 re-read meanwhile (left to that write or the next open)"
            );
            return;
        }
    }
    let side = read_mode(primary);
    if side == Side::Says(strict) {
        loaded.side = side;
        return;
    }
    match write_mode(primary, strict) {
        Ok(()) => {
            tracing::info!(
                was = %side.describe(),
                now = if strict { "strict" } else { "observe" },
                "viewer keys: mode file synced with the list at open"
            );
            loaded.side = Side::Says(strict);
        }
        Err(e) => tracing::warn!(
            was = %side.describe(),
            "viewer keys: mode file not synced with the list at open ({e}); tried again at the \
             next write or open"
        ),
    }
}

/// Under [`WRITE_LOCK`], before a repair overwrites the primary: the file must still be the
/// damaged one this store loaded (`expect`; `None`: there was no primary). Another process — the
/// CLI opens the store too — may have repaired or replaced it, or written a newer version, since:
/// then [`StoreError::ChangedOnDisk`] (the write's thread loads the file for the abandon).
fn still_damaged_as_loaded(
    primary: &Path,
    expect: Option<&Bytes>,
    what: &str,
) -> Result<(), StoreError> {
    match read_bounded(primary) {
        Ok(on_disk) if on_disk.as_deref() == expect.map(|b| b.as_slice()) => {
            tracing::debug!(
                change = what,
                primary = if expect.is_some() {
                    "the damaged bytes"
                } else {
                    "none"
                },
                "viewer keys: repair: the primary is still as this store loaded it"
            );
            Ok(())
        }
        Ok(on_disk) => {
            tracing::warn!(
                path = %primary.display(),
                change = what,
                loaded = expect.map_or(0, |b| b.len()),
                now = on_disk.as_ref().map_or(0, Vec::len),
                now_exists = on_disk.is_some(),
                "viewer keys: repair refused: the file changed on disk since this store loaded \
                 it damaged (another process repaired or replaced it); it is to be reloaded"
            );
            Err(StoreError::ChangedOnDisk)
        }
        Err(e) => {
            tracing::debug!(
                change = what,
                "viewer keys: repair not saved, the file could not be re-read: {e}"
            );
            Err(StoreError::Write(e))
        }
    }
}

/// The reset of a damaged store: keep the damaged primary, carry over what the backup can give,
/// write the new primary (the backup is left as it is). All under [`WRITE_LOCK`], and only while
/// the primary is still the damaged file this store loaded (`expect`).
fn reset_damaged_files(
    primary: &Path,
    backup: &Path,
    now_ms: i64,
    expect: Option<&Bytes>,
    strict: bool,
    what: &str,
) -> Result<(TrustList, Vec<u8>), StoreError> {
    let _guard = write_lock(what);
    still_damaged_as_loaded(primary, expect, what)?;
    // Read the backup before anything is touched: a newer build's backup is an upgrade's to
    // read, not a reset's to throw away.
    let carried = match read_list(backup) {
        Ok(found) => found.map(|(list, _)| list),
        Err(damage) if damage.kind == DamageKind::NewerVersion => {
            tracing::debug!(
                damage = %damage,
                "viewer keys: reset refused: the backup is of a newer version (upgrade instead)"
            );
            return Err(StoreError::NewerVersion);
        }
        Err(damage) => {
            tracing::debug!(
                damage = %damage,
                "viewer keys: reset: the backup is unusable; nothing carried over"
            );
            None
        }
    };
    let kept = keep_damaged(primary, now_ms)?;
    // The switch stays as the window showed it («Переключатель … останется как есть»): the damaged
    // store's effective one, strict when its mode file said nothing.
    let switches = SwitchState {
        trusted_devices_mode: strict,
    };
    // A person the reset leaves with no working owner-role key is the binding list's rule's once
    // the reset lands (§10 «Сверка со списком сервера», [`TrustStore::bring_to_rule`]).
    let (next, from_backup) = match carried {
        Some(b) => {
            // The backup's active keys become tombstones `pc`: whoever had a key keeps first_use
            // closed, and a key comes back by a pairing at the PC or a new invited grant.
            let mut tombstones = b.tombstones;
            tombstones.extend(b.keys.iter().map(|r| r.tombstone(Origin::Pc, now_ms)));
            let carried_keys = b.keys.len();
            (
                TrustList {
                    switches,
                    keys: Vec::new(),
                    tombstones,
                    spent_endorse: b.spent_endorse,
                    spent_grant: b.spent_grant,
                    spent_invite: b.spent_invite,
                    snapshot: b.snapshot,
                    // The removed people stay (§10); the backup's attempts too (pruned on read).
                    notes: b.notes,
                },
                Some(carried_keys),
            )
        }
        None => (
            TrustList {
                switches,
                ..TrustList::default()
            },
            None,
        ),
    };
    let mut next = next;
    // §7 «Токен выдачи»: a reset replaces the token in its own write (never `""` after it).
    next.notes.new_grant_token("a damaged store reset");
    let bytes = serialize(&next)?;
    check_writable(&bytes)?;
    // Strict: the mode file says so before the list (refused when it cannot); observe: after it.
    let side = read_mode(primary);
    mode_before(primary, &side, strict, true, what)?;
    // The damaged primary does not go to the backup.
    if let Err(e) = crate::config::write_whole(primary, &bytes) {
        tracing::debug!("viewer keys: reset not saved: {e:#}");
        return Err(StoreError::Write(format!("{e:#}")));
    }
    mode_after(primary, &side, strict, what);
    tracing::debug!(
        strict,
        kept = kept
            .as_ref()
            .map_or_else(|| "-".to_string(), |p| p.display().to_string()),
        backup_keys_removed = from_backup.map_or_else(|| "-".to_string(), |n| n.to_string()),
        tombstones = next.tombstones.len(),
        spent = next.spent_count(),
        snapshot = next.snapshot.is_some(),
        "viewer keys: damaged store reset written"
    );
    Ok((next, bytes))
}

/// The restore of the backup over a damaged store: the backup must pass every check; the damaged
/// primary is kept first. All under [`WRITE_LOCK`], and only while the primary is still the
/// damaged file this store loaded (`expect`).
fn restore_files(
    primary: &Path,
    backup: &Path,
    now_ms: i64,
    expect: Option<&Bytes>,
    strict: bool,
    what: &str,
) -> Result<(TrustList, Vec<u8>), StoreError> {
    let _guard = write_lock(what);
    still_damaged_as_loaded(primary, expect, what)?;
    let mut list = match read_list(backup) {
        Ok(Some((list, _))) => list,
        Ok(None) => {
            tracing::debug!(path = %backup.display(), "viewer keys: restore refused (no backup)");
            return Err(StoreError::BackupUnusable("there is no backup".into()));
        }
        Err(damage) => {
            tracing::debug!(
                path = %backup.display(),
                damage = %damage,
                "viewer keys: restore refused (the backup is damaged too)"
            );
            return Err(StoreError::BackupUnusable(damage.to_string()));
        }
    };
    // The switch stays as the window showed it («Переключатель … останется как есть»), never the
    // backup's: a backup that says observe must not open a strict PC.
    let backup_strict = list.switches.trusted_devices_mode;
    list.switches.trusted_devices_mode = strict;
    // A removal decided before the damage and not yet written is lost with memory and does not
    // replay; the binding list's rule runs after the install (§10 «Повреждённый список»). The
    // grant token is replaced in this same write (§7 «Токен выдачи»): a grant signed over the
    // backup's is refused `grant_stale`. So the backup is always written again, never copied.
    list.notes.new_grant_token("a restore from the backup");
    let bytes = serialize(&list)?;
    check_writable(&bytes)?;
    tracing::debug!(
        strict,
        backup_strict,
        "viewer keys: restore keeps the effective switch, not the backup's"
    );
    let kept = keep_damaged(primary, now_ms)?;
    let side = read_mode(primary);
    mode_before(primary, &side, strict, true, what)?;
    if let Err(e) = crate::config::write_whole(primary, &bytes) {
        tracing::debug!("viewer keys: restore not saved: {e:#}");
        return Err(StoreError::Write(format!("{e:#}")));
    }
    mode_after(primary, &side, strict, what);
    tracing::debug!(
        kept = kept
            .as_ref()
            .map_or_else(|| "-".to_string(), |p| p.display().to_string()),
        active = list.keys.len(),
        tombstones = list.tombstones.len(),
        "viewer keys: backup restored over the damaged file"
    );
    Ok((list, bytes))
}

/// A damaged store's mode file as the log says it ([`TrustStore::damaged_mode`]).
fn describe_damaged_mode(mode: Option<bool>) -> &'static str {
    match mode {
        Some(true) => "strict",
        Some(false) => "observe",
        None => "none or unusable, strict",
    }
}

/// Keep the damaged primary under a new name (a hard link, else a copy); `None` when there is
/// none. The primary itself stays until it is replaced whole: never a moment without one.
fn keep_damaged(primary: &Path, now_ms: i64) -> Result<Option<PathBuf>, StoreError> {
    match std::fs::symlink_metadata(primary) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let dir = primary.parent().unwrap_or_else(|| Path::new("."));
    for n in 0..100u32 {
        let name = if n == 0 {
            format!("{DAMAGED_FILE_PREFIX}{now_ms}")
        } else {
            format!("{DAMAGED_FILE_PREFIX}{now_ms}-{n}")
        };
        let target = dir.join(name);
        match std::fs::hard_link(primary, &target) {
            Ok(()) => return Ok(Some(target)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(link_error) => {
                if target.exists() {
                    continue;
                }
                tracing::debug!(
                    "viewer keys: the damaged file not hard-linked ({link_error}); copying"
                );
                return match std::fs::copy(primary, &target) {
                    Ok(_) => Ok(Some(target)),
                    Err(e) => {
                        tracing::debug!("viewer keys: the damaged file not kept: {e}");
                        Err(StoreError::Write(format!(
                            "the damaged file could not be kept: {e}"
                        )))
                    }
                };
            }
        }
    }
    tracing::debug!("viewer keys: no free name to keep the damaged file under");
    Err(StoreError::Write(
        "no free name to keep the damaged file under".into(),
    ))
}

// --- The store --------------------------------------------------------------------------------

/// The trusted-keys store. See the module docs; one per process.
#[derive(Debug)]
pub struct TrustStore {
    primary: PathBuf,
    backup: PathBuf,
    opened: Opened,
    state: State,
    /// The primary's bytes as this instance last loaded or wrote them; `None` when there was no
    /// primary (a first run) or the store is damaged.
    disk: Option<Bytes>,
    /// `last_used_at` per key as the primary has it.
    stored_last_used: HashMap<KeyId, i64>,
    /// Bumped at every load and every install (not at a memory-only `last_used_at` note): a
    /// staged change installs as staged only on the generation it was built on.
    generation: u64,
    /// The change in flight (staged, not yet installed or abandoned).
    in_flight: Option<Flight>,
    /// This instance, unique in the process ([`StorePaths`]).
    instance: u64,
    /// Memory may be behind the disk (a change was lost in flight, or an install or abandon
    /// could not apply after a reopen): every stage is refused [`StoreError::NeedsReopen`] until
    /// [`TrustStore::reopen`].
    needs_reopen: bool,
    /// Keys whose removal is decided and not yet installed ([`TrustStore::deny_now`]):
    /// [`Lookup::PendingRemoval`]. Memory only.
    /// Each pending key with the key the admission denied directly that it inherited the mark
    /// from (`None`: denied directly).
    pending_removal: HashMap<KeyId, Option<KeyId>>,
    /// «Нажатие решает сразу»: pending removals with the origin and time of their press
    /// ([`Self::carry_removal`]): every write staged from now on writes them removed (a
    /// snapshot of memory), so a parked removal is superseded by the next write that lands.
    /// An entry goes once the key is no longer active in the list.
    pending_by: HashMap<KeyId, (Origin, i64)>,
    /// While damaged: the switch the mode file gave at the load (`None`: missing or unusable,
    /// strict). `None` while healthy ([`Self::damaged_mode`]).
    damaged_mode: Option<bool>,
    /// While damaged: the primary as the load read it — `Some(None)`: there was none,
    /// `Some(Some(bytes))`: its (damaged) bytes; `None`: not read (unreadable) or healthy. A
    /// repair writes only over exactly that ([`StoreError::ChangedOnDisk`] otherwise).
    damaged_raw: Option<Option<Bytes>>,
    /// The notes as the primary holds them (loaded or last written): memory's differ until the
    /// next write ([`TrustStore::notes_unsaved`]).
    saved_notes: Notes,
    /// A test's wall clock ([`Self::wall_now`]): the vectors' PC clock, not the machine's.
    #[cfg(test)]
    test_wall: Option<i64>,
}

/// Where a store reads and writes ([`TrustStore::paths`]), for [`TrustStore::reopen_load`] on a
/// blocking thread.
#[derive(Debug, Clone)]
pub struct StorePaths {
    primary: PathBuf,
    backup: PathBuf,
    opened: Opened,
    /// The store these are of, and its generation when they were taken: a load is taken only by
    /// that store, still on that generation.
    instance: u64,
    generation: u64,
}

/// What [`TrustStore::reopen_load`] read, for [`TrustStore::take_reopen`].
#[must_use = "a reopen takes effect only through take_reopen"]
pub struct ReopenLoad {
    /// The paths it was asked for (the store's), and those it read (a default store's data
    /// directory is resolved again).
    asked: StorePaths,
    primary: PathBuf,
    backup: PathBuf,
    loaded: Loaded,
}

impl fmt::Debug for ReopenLoad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReopenLoad")
            .field("primary", &self.primary)
            .field("damaged", &self.loaded.list.as_ref().err().map(|d| d.kind))
            .field("mode_file", &self.loaded.side)
            .finish_non_exhaustive()
    }
}

/// The change in flight: its ticket, and a `Weak` to its token (dead once every [`Staged`],
/// [`Written`] or [`WriteFailed`] of it is dropped).
#[derive(Debug)]
struct Flight {
    ticket: u64,
    alive: std::sync::Weak<()>,
    /// The active keys this change removes (a removal stage's outcome).
    removes: Vec<KeyId>,
}

/// A key whose removal is pending and not yet staged ([`TrustStore::pending_without_removal`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingKey {
    pub key_id: KeyId,
    /// The key the admission denied directly whose mark this one inherited; `None` when the
    /// admission denied this one itself.
    pub inherited_from: Option<KeyId>,
    /// The origin its removal is written with: its carry's ([`TrustStore::carry_removal`]; a key
    /// that inherits a pending removal is carried with its root's origin as it joins), `pc` for
    /// a key no carry names (the date line's side: a removal decided here).
    pub by: Removal,
}

impl TrustStore {
    /// Open the store in the agent's data directory. A directory that cannot be made is a damaged
    /// store (deny), not a missing one. Blocking file I/O.
    pub fn open_default() -> Self {
        match crate::paths::afklink_dir() {
            Ok(dir) => Self::open_at(&dir, Opened::Default, 0),
            Err(e) => {
                let damage = Damage::new(DamageKind::Unreadable, format!("data directory: {e:#}"));
                tracing::error!(
                    damage = %damage,
                    "viewer keys: the store is damaged; every viewer key is denied until it is \
                     reopened, restored or reset at the PC"
                );
                // The paths the directory would have, so an at-PC action later writes there (or
                // fails), never into the current directory.
                let dir = crate::paths::dir_override()
                    .map_or_else(crate::paths::default_dir, Path::to_path_buf);
                Self {
                    primary: dir.join(FILE_NAME),
                    backup: dir.join(BACKUP_FILE_NAME),
                    opened: Opened::Default,
                    state: State::Damaged(damage),
                    disk: None,
                    stored_last_used: HashMap::new(),
                    generation: 1,
                    in_flight: None,
                    instance: NEXT_TICKET.fetch_add(1, Ordering::Relaxed),
                    needs_reopen: false,
                    pending_removal: HashMap::new(),
                    pending_by: HashMap::new(),
                    damaged_mode: None,
                    damaged_raw: None,
                    saved_notes: Notes::default(),
                    #[cfg(test)]
                    test_wall: None,
                }
            }
        }
    }

    /// Open the store in `dir` ([`FILE_NAME`], [`BACKUP_FILE_NAME`]). Blocking file I/O.
    pub fn open_in(dir: &Path) -> Self {
        Self::open_at(dir, Opened::Dir, 0)
    }

    fn open_at(dir: &Path, opened: Opened, generation: u64) -> Self {
        let mut store = Self {
            primary: dir.join(FILE_NAME),
            backup: dir.join(BACKUP_FILE_NAME),
            opened,
            state: State::Ready(TrustList::default()),
            disk: None,
            stored_last_used: HashMap::new(),
            generation,
            in_flight: None,
            instance: NEXT_TICKET.fetch_add(1, Ordering::Relaxed),
            needs_reopen: false,
            pending_removal: HashMap::new(),
            pending_by: HashMap::new(),
            damaged_mode: None,
            damaged_raw: None,
            saved_notes: Notes::default(),
            #[cfg(test)]
            test_wall: None,
        };
        store.load_from_disk();
        store
    }

    /// Run the load again (after [`DamageKind::Unreadable`], which may have been transient, after
    /// [`StoreError::NeedsReopen`], or to pick up a change made elsewhere), whatever the state;
    /// what memory held is dropped, the pending removals stay (pruned by the new list). A live
    /// change in flight stays in flight (its write may still be running); a lost one is ended.
    /// Blocking file I/O: [`Self::reopen_load`] then [`Self::take_reopen`], for callers already on a
    /// blocking thread.
    pub fn reopen(&mut self) -> Reloaded {
        let loaded = Self::reopen_load(&self.paths());
        self.take_reopen(loaded)
    }

    /// Where this store reads and writes, for [`Self::reopen_load`] on another thread.
    pub fn paths(&self) -> StorePaths {
        StorePaths {
            primary: self.primary.clone(),
            backup: self.backup.clone(),
            opened: self.opened,
            instance: self.instance,
            generation: self.generation,
        }
    }

    /// The reopen's file I/O, on any thread (blocking: `spawn_blocking`): the data directory
    /// resolved again for a store opened by [`Self::open_default`], then the load. Hand the result
    /// to [`Self::take_reopen`] on the store's own thread.
    pub fn reopen_load(paths: &StorePaths) -> ReopenLoad {
        let (primary, backup, mut loaded) = match paths.opened {
            Opened::Dir => (
                paths.primary.clone(),
                paths.backup.clone(),
                load(&paths.primary, &paths.backup),
            ),
            Opened::Default => match crate::paths::afklink_dir() {
                Ok(dir) => {
                    let primary = dir.join(FILE_NAME);
                    let backup = dir.join(BACKUP_FILE_NAME);
                    let loaded = load(&primary, &backup);
                    (primary, backup, loaded)
                }
                Err(e) => (
                    paths.primary.clone(),
                    paths.backup.clone(),
                    Loaded {
                        list: Err(Damage::new(
                            DamageKind::Unreadable,
                            format!("data directory: {e:#}"),
                        )),
                        // No directory, no mode file: strict.
                        side: Side::Unusable("data directory".into()),
                        raw: None,
                    },
                ),
            },
        };
        mode_at_open(&primary, &mut loaded);
        ReopenLoad {
            asked: paths.clone(),
            primary,
            backup,
            loaded,
        }
    }

    /// Take a [`Self::reopen_load`] as the store's state (no I/O) and say what changed.
    pub fn take_reopen(&mut self, reopen: ReopenLoad) -> Reloaded {
        let was = self.damage().map(|d| d.kind.as_str());
        let before = self.active_view().unwrap_or_default();
        let was_needing = self.needs_reopen;
        let ReopenLoad {
            asked,
            primary,
            backup,
            loaded,
        } = reopen;
        if asked.instance != self.instance
            || asked.generation != self.generation
            || asked.primary != self.primary
            || asked.backup != self.backup
        {
            // Read before the store changed (an install, another reopen) or for another store:
            // taking it would roll memory back. Load again.
            self.needs_reopen = true;
            tracing::warn!(
                loaded_on = asked.generation,
                now = self.generation,
                same_store = asked.instance == self.instance,
                "viewer keys: a reopen's load is stale or not this store's; not taken, load again"
            );
            return Reloaded {
                needs_reopen: true,
                ..Reloaded::default()
            };
        }
        self.primary = primary;
        self.backup = backup;
        let mine = self.notes().cloned();
        let base = self.saved_notes.clone();
        self.take_load(loaded);
        self.keep_notes("a reopen", mine, &base);
        let inherited_pending = self.settle_pending(|id| before.contains_key(id));
        if self
            .in_flight
            .as_ref()
            .is_some_and(|f| f.alive.strong_count() == 0)
        {
            let lost = self.in_flight.take().map_or(0, |f| f.ticket);
            tracing::error!(
                ticket = lost,
                "viewer keys: the change in flight was lost (dropped without install or \
                 abandon); ended by the reopen"
            );
        }
        self.needs_reopen = false;
        let reloaded = Reloaded {
            inherited_pending,
            ..Reloaded::between(&before, self.active_view().as_ref())
        };
        tracing::info!(
            was_damaged = was.unwrap_or("no"),
            now_damaged = self.damage().map_or("no", |d| d.kind.as_str()),
            was_needing_reopen = was_needing,
            left = %short_list(&reloaded.left_active),
            joined = %short_list(&reloaded.joined_active),
            changed = %short_list(&reloaded.changed),
            in_flight = self.in_flight.is_some(),
            pending_removal = self.pending_removal.len(),
            "viewer keys: reopened"
        );
        reloaded
    }

    /// Whether `key_id`'s removal is decided and not yet on disk — denied at once
    /// ([`Self::deny_now`]) or carried by every write ([`Self::carry_removal`]) — with the
    /// origin it will be written with (`pending`: denied, its removal's origin not decided here).
    /// Every rule reads such a key as removed (a pending removal wins over the raw list).
    pub fn removal_decided(&self, key_id: &KeyId) -> Option<&'static str> {
        match self.pending_by.get(key_id) {
            Some((origin, _)) => Some(origin.as_str()),
            None => self
                .pending_removal
                .contains_key(key_id)
                .then_some("pending"),
        }
    }

    /// The verdict on a listed record (§10 «Действующий ключ»): its removal decided
    /// ([`Self::deny_now`], [`Self::carry_removal`]), else it works. Every reading of a record — [`Self::lookup`], [`Self::listed`],
    /// [`Self::person_keys`], the signer checks, the binding list's rule — goes through it.
    fn state_of(&self, r: &KeyRecord) -> KeyState {
        if self.removal_pending(r) {
            KeyState::Leaving
        } else {
            KeyState::Works
        }
    }

    /// §10 «Действующий ключ»: only such a key admits, signs and counts as an owner key.
    fn works(&self, r: &KeyRecord) -> bool {
        self.state_of(r) == KeyState::Works
    }

    /// Whether `r`'s removal is decided (denied, carried by every later write).
    fn removal_pending(&self, r: &KeyRecord) -> bool {
        self.pending_removal.contains_key(r.key_id()) || self.pending_by.contains_key(r.key_id())
    }

    /// A signer's record (`endorse.by`, `grant.by`, `invite.by`): `None` when it is not listed or
    /// its removal is decided (the signer counts as removed, §10).
    fn signer<'a>(&self, list: &'a TrustList, key_id: &KeyId) -> Option<&'a KeyRecord> {
        list.active(key_id).filter(|r| self.works(r))
    }

    /// Deny `key_ids` at once, before their removal is staged or while it waits behind a change
    /// in flight or a needed reopen (memory only; always allowed): [`Self::lookup`] answers
    /// [`Lookup::PendingRemoval`] for them from now on, and they sign nothing and recover nothing
    /// (a pending removal is a removal for every rule). An id leaves the set when the store's list
    /// does not have it active — its removal installed, or came in by a reload — or by
    /// [`Self::undeny`]. A key that joins the list (an install or a reload) as a descendant of a
    /// pending key — endorsed, granted or invited by it, or recovering it — is pending too.
    pub fn deny_now(&mut self, key_ids: &[KeyId]) {
        for id in key_ids {
            self.pending_removal.insert(id.clone(), None);
        }
        tracing::debug!(
            kids = %short_list(key_ids),
            pending = self.pending_removal.len(),
            busy = self.in_flight.is_some(),
            needs_reopen = self.needs_reopen,
            "viewer keys: denied at once, removal pending"
        );
    }

    /// «Удалить» at the PC (§10.1 «Нажатие решает сразу»), decided here once, in memory: the key
    /// and every key that descends from it — through `endorse.by`, `grant.by`, `invite.by` and
    /// recoveries, transitively — denied at once and carried by every later write as tombstones
    /// `pc` (at `now_ms`); the tombstones on the walk stay as they are (their origin too). The
    /// root may be removed already: its descendants are walked all the same. The grant token is
    /// replaced with the press (§7 «Смена»: every removal press at the PC, even one whose walk
    /// only goes through tombstones), so a grant signed before it is `grant_stale`. A single
    /// key's removal is no removal of the person: their attempts stay. Memory only, allowed while
    /// busy or needing a reopen; the write that takes it is any write of memory
    /// ([`Self::stage_flush`]). Refused, with nothing denied and the token kept, on a damaged list
    /// ([`StoreError::Damaged`]: a damaged list is changed by nothing) and for a key the list does
    /// not know at all ([`StoreError::NotFound`]).
    pub fn deny_tree_now(&mut self, root: &KeyId, now_ms: i64) -> Result<TreeRemoval, StoreError> {
        let found = self.ready().and_then(|list| list.tree_of(root));
        let (removed, walk) = found.inspect_err(|e| {
            tracing::debug!(
                kid = %root.short(),
                reason = e.as_str(),
                "viewer keys: «Удалить» refused ({e}); nothing denied"
            );
        })?;
        tracing::debug!(
            kid = %root.short(),
            root_active = removed.first() == Some(root),
            walk = walk.len(),
            kids = %short_list(&removed),
            "viewer keys: «Удалить» at the PC: the tree denied at once"
        );
        self.deny_now(&removed);
        self.carry_removal(&removed, Removal::Pc, now_ms);
        self.rotate_grant_token("«Удалить» at the PC");
        Ok(TreeRemoval { removed })
    }

    /// «Нажатие решает сразу» (spec §10.1): `key_ids`, denied already ([`Self::deny_now`]), are
    /// written removed (origin of `by`, at `now_ms`) by every write staged from now on, whatever
    /// change it is — not only by their own removal's write, which may fail and park. Memory
    /// only, allowed while busy or needing a reopen.
    pub fn carry_removal(&mut self, key_ids: &[KeyId], by: Removal, now_ms: i64) {
        let origin = match by {
            Removal::Pc => Origin::Pc,
            Removal::Server => Origin::Server,
        };
        // Design §8: the PC never applies an owner's removal from the server — a `server` carry
        // of an owner-role record is withdrawn here, where it is made, with the key's denial:
        // no write would take it, and one left in memory would make every write stage for it.
        let owner_role = |id: &KeyId| {
            self.ready()
                .ok()
                .and_then(|list| list.active(id))
                .is_some_and(|r| r.role == BindingRole::Owner)
        };
        let withdrawn: Vec<KeyId> = key_ids
            .iter()
            .filter(|id| {
                origin == Origin::Server
                    && owner_role(id)
                    && !matches!(self.pending_by.get(*id), Some((Origin::Pc, _)))
            })
            .cloned()
            .collect();
        if !withdrawn.is_empty() {
            tracing::warn!(
                kids = %short_list(&withdrawn),
                "viewer keys: a server removal of owner-role keys is not carried; withdrawn, the \
                 keys stay"
            );
            self.undeny(&withdrawn);
        }
        for id in key_ids.iter().filter(|id| !withdrawn.contains(id)) {
            match self.pending_by.get_mut(id) {
                // The PC's removal is the stronger one: a server's never takes its place; the
                // first press of the same origin keeps its time.
                Some(was) if was.0 == Origin::Pc || was.0 == origin => {}
                Some(was) => *was = (origin.clone(), now_ms),
                None => {
                    self.pending_by.insert(id.clone(), (origin.clone(), now_ms));
                }
            }
        }
        if !key_ids.is_empty() {
            tracing::debug!(
                kids = %short_list(key_ids),
                origin = origin.as_str(),
                carried = self.pending_by.len(),
                "viewer keys: pending removals every write carries from now on"
            );
        }
    }

    /// «Нажатие решает сразу» for «Удалить человека» at the PC (§10.1, §10.2): the walk starts at
    /// the person's active keys, then their tombstones, as «Удалить» from each
    /// ([`Self::deny_tree_now`]) — its active keys, in walk order, denied at once and carried by
    /// every later write (origin `pc`, at `now_ms`); the tombstones on it stay as they are. Then
    /// the one shared step of a removal ([`Self::person_removed`]: the token, the attempts). Memory only,
    /// allowed while busy or needing a reopen; a damaged store denies nothing (it denies
    /// everything anyway).
    pub fn deny_person_tree_now(&mut self, telegram_user_id: i64, now_ms: i64) -> TreeRemoval {
        let (ids, walk) = match &self.state {
            State::Ready(list) => {
                let (_, walk, removed) = list.person_walk(telegram_user_id);
                (removed, walk)
            }
            State::Damaged(_) => (Vec::new(), Vec::new()),
        };
        tracing::debug!(
            user_id = telegram_user_id,
            walk = walk.len(),
            kids = %short_list(&ids),
            "viewer keys: a person removed at the PC: their walk denied at once"
        );
        self.deny_now(&ids);
        self.carry_removal(&ids, Removal::Pc, now_ms);
        self.person_removed(telegram_user_id, "a person removed at the PC");
        TreeRemoval { removed: ids }
    }

    /// A guest unbound (spec §10: on the server, `by` `server`; at the PC, `pc`), the keys' part:
    /// the person's **guest-role** keys denied at once
    /// and carried by every later write (origin of `by`, at `now_ms`). Owner-role keys stay: the
    /// key's role is the list's, and an owner's keys leave only through «Удалить» (design §8).
    /// The denied `key_id`s in list order, and how many owner-role keys of theirs stay. Memory
    /// only, allowed while busy or needing a reopen; refused on a list that cannot be read, with
    /// nothing denied (§10 «Повреждённый список»).
    pub fn deny_guest_keys_now(
        &mut self,
        telegram_user_id: i64,
        by: Removal,
        now_ms: i64,
    ) -> Result<(Vec<KeyId>, usize), StoreError> {
        let keys = self.person_keys(telegram_user_id)?;
        let guest = keys.listed_guest;
        let owner_keys = keys.listed_owner.len();
        tracing::debug!(
            user_id = telegram_user_id,
            by = ?by,
            kids = %short_list(&guest),
            owner_keys_stay = owner_keys,
            "viewer keys: a guest unbound: their guest-role keys denied at once"
        );
        if !guest.is_empty() {
            self.deny_now(&guest);
            self.carry_removal(&guest, by, now_ms);
            self.person_removed(telegram_user_id, "a removed person's guest keys leave");
        }
        Ok((guest, owner_keys))
    }

    /// The active keys among the pending removals that every write staged now carries removed
    /// ([`Self::carry_removal`]), sorted: a write that lands takes them to the disk, whichever
    /// change it is (the journal names them once, at that write).
    pub fn carried_now(&self) -> Vec<KeyId> {
        let State::Ready(list) = &self.state else {
            return Vec::new();
        };
        let mut ids: Vec<KeyId> = self
            .pending_by
            .keys()
            .filter(|id| list.find(id).is_some())
            .cloned()
            .collect();
        ids.sort();
        ids
    }

    /// Take `key_ids` out of the pending removals: for a removal the store refused for a reason a
    /// retry cannot change (see the module docs, «Removals do not wait»).
    pub fn undeny(&mut self, key_ids: &[KeyId]) {
        let removing: HashSet<KeyId> = self
            .in_flight
            .as_ref()
            .filter(|f| f.alive.strong_count() > 0)
            .map(|f| f.removes.iter().cloned().collect())
            .unwrap_or_default();
        let mut kept = Vec::new();
        for id in key_ids {
            if removing.contains(id) {
                kept.push(id.clone());
            } else {
                self.pending_removal.remove(id);
                // No later write carries a withdrawn removal.
                self.pending_by.remove(id);
            }
        }
        if !kept.is_empty() {
            tracing::debug!(
                kids = %short_list(&kept),
                "viewer keys: undeny skipped: the change in flight removes these keys"
            );
        }
        tracing::debug!(
            kids = %short_list(key_ids),
            pending = self.pending_removal.len(),
            "viewer keys: pending removal withdrawn"
        );
    }

    /// After the list changed (an install or a load): a key that joined it — active now, not
    /// before — and descends from a pending key (its `endorse.by`, `grant.by`, `invite_by` or a
    /// record it replaced) is pending too, through the joined keys transitively; then every id
    /// the list does not have active leaves the set (a damaged store holds none: its load dropped
    /// them, [`Self::take_load`]).
    /// The keys that inherited the mark in this step are returned (see
    /// [`Self::pending_without_removal`]).
    fn settle_pending(&mut self, was_active: impl Fn(&KeyId) -> bool) -> Vec<KeyId> {
        let State::Ready(list) = &self.state else {
            return Vec::new();
        };
        let mut inherited = Vec::new();
        let mut inherit_carry: Vec<(KeyId, Removal)> = Vec::new();
        loop {
            let more: Vec<(KeyId, KeyId)> = list
                .keys
                .iter()
                .filter(|r| {
                    !was_active(r.key_id()) && !self.pending_removal.contains_key(r.key_id())
                })
                .filter_map(|r| {
                    // Its signers, and for a recovery the records it replaced too.
                    let parent = r
                        .source
                        .parents()
                        .into_iter()
                        .chain(r.source.replaced())
                        .find(|p| self.pending_removal.contains_key(*p))?;
                    // The key the admission denied directly, up the chain.
                    let root = self
                        .pending_removal
                        .get(parent)
                        .cloned()
                        .flatten()
                        .unwrap_or_else(|| parent.clone());
                    Some((r.key_id().clone(), root))
                })
                .collect();
            if more.is_empty() {
                break;
            }
            for (id, root) in more {
                // Its root's removal as memory decided it — the origin in the root's carry, the
                // only place it is kept: a later removal of another origin never changes it.
                if let Some((origin, _)) = self.pending_by.get(&root) {
                    inherit_carry.push((id.clone(), removal_of(origin)));
                }
                self.pending_removal.insert(id.clone(), Some(root));
                inherited.push(id);
            }
        }
        if !inherited.is_empty() {
            tracing::warn!(
                kids = %short_list(&inherited),
                "viewer keys: keys that joined as descendants of a key whose removal is pending: \
                 pending too"
            );
        }
        self.pending_by.retain(|id, _| list.find(id).is_some());
        let before = self.pending_removal.len();
        self.pending_removal.retain(|id, _| list.find(id).is_some());
        if self.pending_removal.len() != before {
            tracing::debug!(
                cleared = before - self.pending_removal.len(),
                still_pending = self.pending_removal.len(),
                "viewer keys: pending removals cleared (no longer active)"
            );
        }
        // Carried like their root's removal from now on: any later write that lands takes them.
        let now_ms = self.wall_now();
        for (id, by) in inherit_carry {
            self.carry_removal(std::slice::from_ref(&id), by, now_ms);
        }
        inherited
    }

    /// The pending keys still active in the list that no change in flight removes: every one
    /// needs a removal staged. `inherited_from` is the key the admission denied directly whose mark
    /// the key inherited (it joined as its descendant, [`Self::deny_now`]); `None` for a key the
    /// admission denied itself. `by` is the origin memory holds for its removal: an inherited key
    /// is carried with its root's as it joins ([`Self::settle_pending`]), so the admission
    /// decides no origin. **The admission's duty:** it queues the key's removal with `by`,
    /// retried like any removal; it reads this after every install, abandon and reopen.
    pub fn pending_without_removal(&self) -> Vec<PendingKey> {
        let State::Ready(list) = &self.state else {
            return Vec::new();
        };
        let removing: HashSet<&KeyId> = self
            .in_flight
            .as_ref()
            .filter(|f| f.alive.strong_count() > 0)
            .map(|f| f.removes.iter().collect())
            .unwrap_or_default();
        let mut out: Vec<PendingKey> = self
            .pending_removal
            .iter()
            .filter(|(id, _)| list.find(id).is_some() && !removing.contains(id))
            .map(|(id, from)| PendingKey {
                key_id: id.clone(),
                inherited_from: from.clone(),
                by: self
                    .pending_by
                    .get(id)
                    .map_or(Removal::Pc, |(origin, _)| removal_of(origin)),
            })
            .collect();
        out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        out
    }
    /// Whether memory may be behind the disk: stages are refused until [`Self::reopen`].
    pub fn needs_reopen(&self) -> bool {
        self.needs_reopen
    }

    /// The active keys, `None` when damaged (for [`Reloaded`]).
    fn active_view(&self) -> Option<HashMap<KeyId, (i64, BindingRole, bool)>> {
        match &self.state {
            State::Ready(list) => Some(list.active_view()),
            State::Damaged(_) => None,
        }
    }

    /// Take `loaded` as the store's state and say what changed (no I/O).
    fn reload_with(&mut self, why: &str, loaded: Loaded) -> Reloaded {
        let before = self.active_view().unwrap_or_default();
        let mine = self.notes().cloned();
        let base = self.saved_notes.clone();
        self.take_load(loaded);
        self.keep_notes(why, mine, &base);
        let inherited_pending = self.settle_pending(|id| before.contains_key(id));
        let reloaded = Reloaded {
            inherited_pending,
            ..Reloaded::between(&before, self.active_view().as_ref())
        };
        tracing::info!(
            why,
            left = %short_list(&reloaded.left_active),
            joined = %short_list(&reloaded.joined_active),
            changed = %short_list(&reloaded.changed),
            damaged = reloaded.damaged,
            "viewer keys: reloaded the file"
        );
        reloaded
    }

    /// The people with an active key, while the list reads (none while damaged).
    fn keyed_people(&self) -> HashSet<i64> {
        self.ready().map_or_else(
            |_| HashSet::new(),
            |l| l.keys.iter().map(|k| k.person.telegram_user_id).collect(),
        )
    }

    /// Memory's notes before a reload or reopen (`mine`; `None`: the list was damaged) are
    /// decisions (spec §10.1 «Нажатие решает сразу»): onto a list that reads, three ways against
    /// the notes as memory last knew the disk to hold them (`base`, [`Notes::merge_from`]). A list
    /// that turned damaged keeps nothing of them (§10 «Повреждённый список»): they are lost as at
    /// a restart before the write, the removals not yet written with them ([`Self::take_load`]);
    /// after the repair the binding list's rule runs by the current list.
    fn keep_notes(&mut self, why: &str, mine: Option<Notes>, base: &Notes) {
        let Some(mine) = mine else {
            return;
        };
        match &mut self.state {
            State::Ready(list) => {
                if mine != *list.notes {
                    list.notes.merge_from(&mine, base);
                    // The merge may hold more than the caps (the file's attempts beside the
                    // ones memory evicted them for) — the parser would refuse every next write.
                    // First the attempts of keys the file has entered at their person (they
                    // take no place), then the caps as at a note over what is left — an entered
                    // one never pushes a real attempt out.
                    let before = list.notes.attempts.len();
                    let entered = drop_entered_attempts(list, "a reload's merged notes");
                    let _ = evict_attempts(&mut list.notes.attempts, None);
                    tracing::debug!(
                        why,
                        before,
                        after = list.notes.attempts.len(),
                        entered,
                        "viewer keys: the merged attempts held to the caps"
                    );
                    tracing::debug!(
                        why,
                        attempts = list.notes.attempts.len(),
                        unsaved = *list.notes != self.saved_notes,
                        "viewer keys: memory's notes kept over the reload (three ways against the \
                         last write); written with the next change"
                    );
                }
            }
            State::Damaged(_) => {
                tracing::warn!(
                    why,
                    last_bindings = ?mine.last_bindings.as_ref().map(Vec::len),
                    attempts = mine.attempts.len(),
                    "viewer keys: the list turned damaged under a reload: memory's notes are not \
                     kept (lost as at a restart before the write; the binding list's rule runs \
                     after the repair)"
                );
            }
        }
    }

    fn load_from_disk(&mut self) {
        let mut loaded = load(&self.primary, &self.backup);
        mode_at_open(&self.primary, &mut loaded);
        self.take_load(loaded);
    }

    /// Take a load's result as the store's state (no I/O).
    fn take_load(&mut self, loaded: Loaded) {
        self.generation = self.generation.wrapping_add(1);
        let Loaded { list, side, raw } = loaded;
        // Set again below only for a damaged list.
        self.damaged_mode = None;
        self.damaged_raw = None;
        match list {
            Ok(Some((list, bytes))) => {
                let strict = list.switches.trusted_devices_mode;
                if side != Side::Says(strict) {
                    tracing::warn!(
                        list = if strict { "strict" } else { "observe" },
                        mode_file = %side.describe(),
                        "viewer keys: the mode file disagrees with the healthy list; the list \
                         wins (the mode file is set at the next write or open)"
                    );
                }
                tracing::debug!(
                    path = %self.primary.display(),
                    active = list.keys.len(),
                    unconfirmed = list.keys.iter().filter(|r| r.unconfirmed).count(),
                    tombstones = list.tombstones.len(),
                    spent = list.spent_count(),
                    snapshot = list.snapshot.as_ref().map_or(0, |s| s.people.len()),
                    trusted_devices_mode = list.switches.trusted_devices_mode,
                    "viewer keys: loaded"
                );
                self.stored_last_used = stored_last_used(&list);
                self.saved_notes = (*list.notes).clone();
                self.disk = Some(Arc::new(bytes));
                self.state = State::Ready(list);
            }
            Ok(None) => {
                tracing::info!(
                    path = %self.primary.display(),
                    "viewer keys: no list yet (first run): an empty one, written at its first change"
                );
                self.stored_last_used.clear();
                self.saved_notes = Notes::default();
                self.disk = None;
                self.state = State::Ready(TrustList::default());
            }
            Err(damage) => {
                self.damaged_mode = side.says();
                tracing::error!(
                    path = %self.primary.display(),
                    damage = %damage,
                    mode_file = %side.describe(),
                    "viewer keys: the store is damaged; {} until it is reopened, restored or \
                     reset at the PC (every change is refused)",
                    if self.damaged_mode == Some(false) {
                        "the mode file says observe: offers are admitted by the binding, as with \
                         the switch off"
                    } else {
                        "strict: every viewer key is denied"
                    }
                );
                // §10 «Повреждённый список»: the trust decisions no write took yet are lost with
                // memory, as at a restart before the write — the denied and carried removals and
                // the notes with the list. Nothing replays
                // after the repair; the binding list's rule runs then by the current list.
                if !self.pending_removal.is_empty() || !self.pending_by.is_empty() {
                    tracing::warn!(
                        denied = self.pending_removal.len(),
                        carried = self.pending_by.len(),
                        "viewer keys: the list turned damaged: the removals decided in memory and \
                         not yet written are dropped (nothing replays after the repair)"
                    );
                }
                self.pending_removal.clear();
                self.pending_by.clear();
                self.stored_last_used.clear();
                self.disk = None;
                self.damaged_raw = raw.map(|r| r.map(Arc::new));
                self.state = State::Damaged(damage);
            }
        }
    }

    /// Whether a change is in flight (staged, not yet installed or abandoned): every `stage_*`
    /// is refused [`StoreError::Busy`] meanwhile.
    pub fn is_busy(&self) -> bool {
        self.in_flight
            .as_ref()
            .is_some_and(|f| f.alive.strong_count() > 0)
    }

    pub fn is_damaged(&self) -> bool {
        matches!(self.state, State::Damaged(_))
    }

    /// While the list is damaged: the switch («Доверенные устройства», `true` = strict) its mode
    /// file gave at the load — `Some(false)` lets the admission observe instead of refusing
    /// everyone (module docs, «The mode file»). `None` while healthy, and while damaged with the
    /// mode file missing or unusable (strict). No I/O.
    pub fn damaged_mode(&self) -> Option<bool> {
        match self.state {
            State::Damaged(_) => self.damaged_mode,
            State::Ready(_) => None,
        }
    }

    /// What is wrong, for the window.
    pub fn damage(&self) -> Option<&Damage> {
        match &self.state {
            State::Damaged(d) => Some(d),
            State::Ready(_) => None,
        }
    }

    /// The switch; an error when the store is damaged (deny whatever it would say).
    pub fn switches(&self) -> Result<SwitchState, StoreError> {
        Ok(self.ready()?.switches)
    }

    /// The listed records as they are, in the order they were added, without their verdict: for
    /// tests that check the list itself. Outside the store a record is read with its verdict
    /// ([`Self::lookup`], [`Self::listed`], [`Self::listed_people`], [`Self::person_keys`]).
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Result<&[KeyRecord], StoreError> {
        Ok(&self.ready()?.keys)
    }

    /// `key_id`'s record with its verdict, while it is listed (any [`KeyState`]): for the
    /// window and the journal, which name a key until the write that takes it lands. `None`
    /// when it is not listed or the list is damaged.
    pub fn listed(&self, key_id: &KeyId) -> Option<Listed<'_>> {
        self.ready().ok()?.active(key_id).map(|record| Listed {
            record,
            state: self.state_of(record),
        })
    }

    /// Every person with a listed record, with their records and verdicts in the order they were
    /// added; people in the order of their first record (the window shows each record until the
    /// write that takes it lands).
    pub fn listed_people(&self) -> Result<Vec<(i64, Vec<Listed<'_>>)>, StoreError> {
        let list = self.ready()?;
        let mut out: Vec<(i64, Vec<Listed<'_>>)> = Vec::new();
        for record in &list.keys {
            let uid = record.person.telegram_user_id;
            let listed = Listed {
                record,
                state: self.state_of(record),
            };
            match out.iter_mut().find(|(id, _)| *id == uid) {
                Some((_, records)) => records.push(listed),
                None => out.push((uid, vec![listed])),
            }
        }
        Ok(out)
    }

    /// The person's listed keys by role and verdict ([`PersonKeys`]). Damaged: an error (no
    /// guard can be read; each caller refuses or skips).
    pub fn person_keys(&self, telegram_user_id: i64) -> Result<PersonKeys, StoreError> {
        let list = self.ready()?;
        let mut keys = PersonKeys::default();
        for r in list.keys_of(telegram_user_id) {
            let works = self.works(r);
            let id = r.key_id().clone();
            match r.role {
                BindingRole::Owner => {
                    if works {
                        keys.working_owner.push(id.clone());
                    }
                    keys.listed_owner.push(id);
                }
                BindingRole::Guest => {
                    if works {
                        keys.working_guest.push(id.clone());
                    }
                    keys.listed_guest.push(id);
                }
            }
        }
        Ok(keys)
    }

    /// §10.2: where the owner's own device stands for the strict switch — one that works
    /// ([`KeyState::Works`]), has the owner's role and is confirmed lets it on
    /// ([`OwnerDevice::Ready`]); working owner-role keys all unconfirmed ask «Подтвердить» first;
    /// none, a device added at the PC. A list that does not read: none.
    pub fn owner_device(&self) -> OwnerDevice {
        let Ok(list) = self.ready() else {
            return OwnerDevice::Missing;
        };
        let mut working = list
            .keys
            .iter()
            .filter(|r| r.role == BindingRole::Owner && self.works(r));
        match working.next() {
            None => OwnerDevice::Missing,
            Some(first) if !first.unconfirmed || working.any(|r| !r.unconfirmed) => {
                OwnerDevice::Ready
            }
            Some(_) => OwnerDevice::Unconfirmed,
        }
    }

    /// The strict switch may go on ([`Self::owner_device`] is [`OwnerDevice::Ready`]).
    pub fn has_owner_device(&self) -> bool {
        self.owner_device() == OwnerDevice::Ready
    }

    /// §5, §10.2 «Владелец на этом ПК» — the one reading every owner rule takes: a working
    /// owner-role key here, or the owner by the server's bindings (`owner_by_bindings`, the
    /// caller's current list). A list that does not read: not one (no key is written on it
    /// anyway).
    pub fn owner_here(&self, telegram_user_id: i64, owner_by_bindings: bool) -> bool {
        let Ok(keys) = self.person_keys(telegram_user_id) else {
            return false;
        };
        keys.owner_by_keys() || owner_by_bindings
    }

    /// The PC has an owner as the pairing rule reads it: someone by the bindings
    /// (`owner_bound`), or any working owner-role key here. Without one, the role of a pairing is
    /// chosen at the PC.
    pub fn has_owner(&self, owner_bound: bool) -> bool {
        owner_bound || self.owner_device() != OwnerDevice::Missing
    }

    /// The person as their newest listed record names them (any [`KeyState`]: names only, for
    /// the window, the journal and a new record of theirs). `None` with no listed record or a
    /// damaged list.
    pub fn person_names(&self, telegram_user_id: i64) -> Option<&Person> {
        self.ready()
            .ok()?
            .keys_of(telegram_user_id)
            .max_by_key(|r| r.added_at)
            .map(|r| &r.person)
    }

    /// The removed keys (for the window).
    pub fn tombstones(&self) -> Result<&[Tombstone], StoreError> {
        Ok(&self.ready()?.tombstones)
    }

    /// The spent `endorse_id`s, `grant_id`s and `inv_id`s.
    #[allow(
        clippy::type_complexity,
        reason = "three borrowed sets, named by the doc"
    )]
    pub fn spent(
        &self,
    ) -> Result<
        (
            &BTreeSet<GroundId>,
            &BTreeSet<GroundId>,
            &BTreeSet<GroundId>,
        ),
        StoreError,
    > {
        let list = self.ready()?;
        Ok((&list.spent_endorse, &list.spent_grant, &list.spent_invite))
    }

    /// The `first_use` snapshot, once taken.
    pub fn first_use_snapshot(&self) -> Result<Option<&FirstUseSnapshot>, StoreError> {
        Ok(self.ready()?.snapshot.as_ref())
    }

    /// What the list says of `key_id`, with the verdict on a listed record ([`KeyState`]). A
    /// damaged store answers [`Lookup::StoreDamaged`].
    pub fn lookup(&self, key_id: &KeyId) -> Lookup<'_> {
        let found = match &self.state {
            State::Damaged(_) => Lookup::StoreDamaged,
            State::Ready(list) => match list.active(key_id) {
                Some(r) => match self.state_of(r) {
                    KeyState::Leaving => Lookup::PendingRemoval(r),
                    KeyState::Works => Lookup::Active(r),
                },
                None => match list.tombstone(key_id) {
                    Some(t) => Lookup::Removed(t),
                    None => Lookup::Unknown,
                },
            },
        };
        match &found {
            Lookup::Active(r) => tracing::debug!(
                kid = %key_id.short(),
                user_id = r.person.telegram_user_id,
                role = r.role.as_str(),
                source = r.source.as_str(),
                unconfirmed = r.unconfirmed,
                "viewer keys: lookup: active"
            ),
            Lookup::Removed(t) => tracing::debug!(
                kid = %key_id.short(),
                user_id = t.telegram_user_id,
                origin = t.origin.as_str(),
                "viewer keys: lookup: removed"
            ),
            Lookup::PendingRemoval(r) => tracing::debug!(
                kid = %key_id.short(),
                user_id = r.person.telegram_user_id,
                "viewer keys: lookup: denied, its removal is pending"
            ),
            Lookup::Unknown => {
                tracing::debug!(kid = %key_id.short(), "viewer keys: lookup: unknown");
            }
            Lookup::StoreDamaged => tracing::debug!(
                kid = %key_id.short(),
                "viewer keys: lookup: denied, the store is damaged"
            ),
        }
        found
    }

    // --- Stage, write, install ------------------------------------------------------------

    /// Take a written change as the store's list, and end it (the store may stage again). Never
    /// file I/O.
    ///
    /// - Not this store's change in flight (another instance's, or one already ended):
    ///   [`StoreError::NotInFlight`], the store untouched.
    /// - The store is as the change was staged on: the written list becomes the store's.
    ///   `last_used_at` noted in memory since the stage is kept when later than the written one.
    /// - The store was reopened meanwhile: if the disk as the store last read it holds exactly the
    ///   written bytes, the change is in already; if it holds the bytes the write's locked re-read
    ///   found before writing (so the write landed on what the store has), the written list is
    ///   taken — `Ok(outcome)` either way. Otherwise [`StoreError::StaleBase`]: the store is marked
    ///   [`StoreError::NeedsReopen`] and the [`NotInstalled`] carries the outcome the change was
    ///   staged with.
    ///
    /// **The admission reads [`NotInstalled::reloaded`] (and [`Self::needs_reopen`]), not just
    /// the error**: what it says left the active list must lose its sessions.
    pub fn install<T>(&mut self, written: Written<T>) -> Result<T, Box<NotInstalled<T>>> {
        if !self.is_ours(written.ticket) {
            tracing::warn!(
                ticket = written.ticket,
                in_flight = self.in_flight.as_ref().map_or(0, |f| f.ticket),
                change = %written.what,
                "viewer keys: install of a change that is not this store's change in flight; \
                 refused, the store untouched"
            );
            return Err(Box::new(NotInstalled {
                error: StoreError::NotInFlight,
                outcome: written.outcome,
                reloaded: Reloaded::default(),
            }));
        }
        self.end_flight(written.ticket, "installed", &written.what);
        let Written {
            next,
            bytes,
            base,
            generation,
            what,
            outcome,
            ..
        } = written;
        if generation == self.generation {
            self.take_written(next, bytes, &what);
            return Ok(outcome);
        }
        if self.disk_holds(&bytes) {
            tracing::info!(
                staged_on = generation,
                now = self.generation,
                change = %what,
                "viewer keys: the store was reopened after this change was staged, and the file \
                 it read holds the change: in already"
            );
            return Ok(outcome);
        }
        // A damaged store holds no disk bytes (`None`): that proves nothing about a base.
        if let (Some(base), false) = (&base, self.is_damaged()) {
            if same_bytes(self.disk.as_ref(), base.as_ref()) {
                tracing::info!(
                    staged_on = generation,
                    now = self.generation,
                    change = %what,
                    "viewer keys: the store was reopened after this change was staged, on the \
                     file the write replaced: the written list taken"
                );
                self.take_written(next, bytes, &what);
                return Ok(outcome);
            }
        }
        self.needs_reopen = true;
        tracing::warn!(
            staged_on = generation,
            now = self.generation,
            change = %what,
            "viewer keys: the store changed after this change was staged and its file is neither \
             the written one nor the one the write replaced; not installed, reopen needed"
        );
        Err(Box::new(NotInstalled {
            error: StoreError::StaleBase,
            outcome,
            reloaded: Reloaded::default(),
        }))
    }

    /// The written list as the store's (no I/O).
    fn take_written(&mut self, mut next: TrustList, bytes: Bytes, what: &str) {
        let before: HashSet<KeyId> = match &self.state {
            State::Ready(current) => current.keys.iter().map(|r| r.key_id().clone()).collect(),
            State::Damaged(_) => HashSet::new(),
        };
        self.stored_last_used = stored_last_used(&next);
        self.saved_notes = (*next.notes).clone();
        if let State::Ready(current) = &self.state {
            // Memory's notes decide (they may have moved on while the write ran): the written
            // ones are what the disk has now.
            next.notes = current.notes.clone();
            for record in &mut next.keys {
                if let Some(noted) = current.active(record.key_id()).and_then(|r| r.last_used_at) {
                    if record.last_used_at.is_none_or(|t| t < noted) {
                        record.last_used_at = Some(noted);
                    }
                }
            }
        }
        tracing::info!(
            active = next.keys.len(),
            unconfirmed = next.keys.iter().filter(|r| r.unconfirmed).count(),
            tombstones = next.tombstones.len(),
            spent = next.spent_count(),
            trusted_devices_mode = next.switches.trusted_devices_mode,
            "viewer keys: {what}"
        );
        // §10.2: a key in the list is its own person's attempt no more (memory's notes may have
        // taken one while the write ran).
        drop_entered_attempts(&mut next, "the installed write");
        self.disk = Some(bytes);
        self.state = State::Ready(next);
        self.damaged_mode = None;
        self.damaged_raw = None;
        self.generation = self.generation.wrapping_add(1);
        let inherited = self.settle_pending(|id| before.contains(id));
        if !inherited.is_empty() {
            tracing::debug!(
                kids = %short_list(&inherited),
                "viewer keys: installed keys that inherited a pending removal; see \
                 pending_without_removal"
            );
        }
    }

    /// End a change in flight that will not be installed: a [`Staged`] never written, or a
    /// [`WriteFailed`]. Never file I/O.
    ///
    /// After [`StoreError::ChangedOnDisk`] the store takes the file as the write's thread loaded
    /// it and returns what that changed — only when the store is still on the generation the
    /// change was staged on; otherwise (a reopen in between) memory is left alone and the store is
    /// marked [`StoreError::NeedsReopen`] (`None`). Any other failure left the files as they were
    /// (nothing written, or the old primary stands): `None`. Not this store's change in flight:
    /// `None`, the store untouched.
    pub fn abandon(&mut self, change: impl Abandon) -> Option<Reloaded> {
        let sealed::Parts {
            ticket,
            generation,
            what,
            error,
            fresh,
            ..
        } = change.into_parts();
        if !self.is_ours(ticket) {
            tracing::warn!(
                ticket,
                in_flight = self.in_flight.as_ref().map_or(0, |f| f.ticket),
                change = %what,
                "viewer keys: abandon of a change that is not this store's change in flight; \
                 the store untouched"
            );
            return None;
        }
        self.end_flight(ticket, "abandoned", &what);
        match error {
            Some(StoreError::ChangedOnDisk) => match fresh {
                Some(loaded) if generation == self.generation => {
                    Some(self.reload_with("the file changed on disk under a staged change", loaded))
                }
                _ => {
                    self.needs_reopen = true;
                    tracing::warn!(
                        staged_on = generation,
                        now = self.generation,
                        change = %what,
                        "viewer keys: the file changed on disk under a staged change, and the \
                         store moved on since (or nothing was loaded): memory left alone, reopen \
                         needed"
                    );
                    None
                }
            },
            Some(e) => {
                tracing::debug!(
                    reason = e.as_str(),
                    change = %what,
                    "viewer keys: a staged change was not saved; the store is as it was ({e})"
                );
                None
            }
            None => {
                tracing::debug!(
                    change = %what,
                    "viewer keys: a staged change abandoned before its write"
                );
                None
            }
        }
    }

    /// Whether `ticket` is this store's change in flight.
    fn is_ours(&self, ticket: u64) -> bool {
        self.in_flight.as_ref().is_some_and(|f| f.ticket == ticket)
    }

    /// The change in flight is over (installed or abandoned).
    fn end_flight(&mut self, ticket: u64, how: &str, what: &str) {
        self.in_flight = None;
        tracing::debug!(
            ticket,
            how,
            change = what,
            "viewer keys: change in flight ended"
        );
    }

    /// Whether the primary, as this store last read or wrote it, is exactly `bytes`.
    fn disk_holds(&self, bytes: &Bytes) -> bool {
        same_bytes(self.disk.as_ref(), Some(bytes))
    }

    /// Write and install at once, on this thread (blocking). What a reload changed is logged
    /// only: these are for tests, the CLI and callers that hold no sessions.
    fn apply<T>(&mut self, staged: Staged<T>) -> Result<T, StoreError> {
        match staged.write() {
            Ok(written) => self.install(written).map_err(|not| not.error),
            Err(failed) => {
                let error = failed.error().clone();
                let _ = self.abandon(failed);
                Err(error)
            }
        }
    }

    /// Refuse a stage while a change is in flight ([`StoreError::Busy`]) or memory may be behind
    /// the disk ([`StoreError::NeedsReopen`]). A change in flight whose token is dead was lost
    /// (dropped, or its write panicked): `error`, the flight ended, a reopen needed.
    fn idle(&mut self, what: &str) -> Result<(), StoreError> {
        if let Some(flight) = &self.in_flight {
            if flight.alive.strong_count() > 0 {
                tracing::debug!(
                    in_flight = flight.ticket,
                    change = what,
                    "viewer keys: refused, another change is in flight"
                );
                return Err(StoreError::Busy);
            }
            tracing::error!(
                ticket = flight.ticket,
                change = what,
                "viewer keys: the change in flight was lost (dropped without install or abandon, \
                 or its write panicked); memory may be behind the file: reopen needed"
            );
            self.in_flight = None;
            self.needs_reopen = true;
        }
        if self.needs_reopen {
            tracing::debug!(
                change = what,
                "viewer keys: refused, the store needs a reopen first"
            );
            return Err(StoreError::NeedsReopen);
        }
        Ok(())
    }

    /// A stage's result: a change to write is now the one in flight.
    fn launch<T>(
        &mut self,
        result: Result<Staged<T>, StoreError>,
    ) -> Result<Staged<T>, StoreError> {
        if let Ok(staged) = &result {
            self.fly(staged);
        }
        result
    }

    /// The change just launched removes `ids`: they are denied from now on, and
    /// [`Self::undeny`] / [`Self::pending_without_removal`] know the change in flight takes them.
    fn removing(&mut self, ids: &[KeyId]) {
        self.deny_now(ids);
        if let Some(flight) = &mut self.in_flight {
            flight.removes = ids.to_vec();
        }
    }

    /// [`Self::launch`] for a stage that may have nothing to write.
    fn launch_some<T>(
        &mut self,
        result: Result<Option<Staged<T>>, StoreError>,
    ) -> Result<Option<Staged<T>>, StoreError> {
        if let Ok(Some(staged)) = &result {
            self.fly(staged);
        }
        result
    }

    fn fly<T>(&mut self, staged: &Staged<T>) {
        debug_assert!(self.in_flight.is_none());
        self.in_flight = Some(Flight {
            ticket: staged.ticket,
            alive: Arc::downgrade(&staged.token),
            removes: Vec::new(),
        });
    }
    /// A change of any plan, on this store's paths and generation, with a new ticket.
    fn change<T>(&self, plan: Plan, what: String, outcome: T) -> Staged<T> {
        Staged {
            plan,
            generation: self.generation,
            ticket: NEXT_TICKET.fetch_add(1, Ordering::Relaxed),
            token: Arc::new(()),
            primary: self.primary.clone(),
            backup: self.backup.clone(),
            what,
            outcome,
            #[cfg(test)]
            pause: None,
        }
    }

    /// An ordinary change, staged on the current list: the next list and the base (shared). The
    /// serializing is the write's.
    fn staged<T>(
        &self,
        mut next: TrustList,
        what: String,
        outcome: T,
    ) -> Result<Staged<T>, StoreError> {
        // «Нажатие решает сразу» (§10.1): every write carries the PC's removals made at a press
        // whose own write has not landed: a whole-state snapshot, never a lost earlier edit.
        let (gone, kept): (Vec<KeyRecord>, Vec<KeyRecord>) = std::mem::take(&mut next.keys)
            .into_iter()
            .partition(|r| match self.pending_by.get(r.key_id()) {
                None => false,
                // Design §8: the PC never applies an owner's removal from the server — a
                // `server` carry of an owner-role record is never written, the key stays
                // ([`Self::carry_removal`] withdraws one where it is made).
                Some((Origin::Server, _)) if r.role == BindingRole::Owner => {
                    tracing::warn!(
                        kid = %r.key_id().short(),
                        user_id = r.person.telegram_user_id,
                        "viewer keys: a carried server removal of an owner-role key is not \
                         written; the key stays"
                    );
                    false
                }
                Some(_) => true,
            });
        next.keys = kept;
        if !gone.is_empty() {
            tracing::debug!(
                kids = %short_list(&gone.iter().map(|r| r.key_id().clone()).collect::<Vec<_>>()),
                "viewer keys: the write carries pending removals (a snapshot of memory)"
            );
        }
        for r in gone {
            let (origin, at) = self.pending_by[r.key_id()].clone();
            next.tombstones.push(r.tombstone(origin, at));
        }
        let mut pressed = Vec::new();
        for t in &mut next.tombstones {
            if t.origin != Origin::Server {
                continue;
            }
            if let Some((Origin::Pc, at)) = self.pending_by.get(t.key_id()) {
                // This change built the key's tombstone `server` itself (a server removal
                // queued before a press at the PC): the press's origin wins (`pc`, never the
                // other way), at the press's time.
                t.origin = Origin::Pc;
                t.at = *at;
                pressed.push(t.key_id().clone());
            }
        }
        if !pressed.is_empty() {
            tracing::debug!(
                kids = %short_list(&pressed),
                "viewer keys: a server removal staged after a press at the PC: the keys are \
                 written pc (the press wins)"
            );
        }
        // §10.2: a key in the list is its own person's attempt no more — the file never keeps
        // one (an attempt «Разрешить» let in goes with the write that adds its key).
        drop_entered_attempts(&mut next, "the staged write");
        // Staged only on a ready list; a damaged one (never here) counts as strict.
        let base_strict = match &self.state {
            State::Ready(list) => list.switches.trusted_devices_mode,
            State::Damaged(_) => true,
        };
        Ok(self.change(
            Plan::Commit {
                next,
                base: self.disk.clone(),
                base_strict,
            },
            what,
            outcome,
        ))
    }

    // --- Adding ---------------------------------------------------------------------------

    /// Stage a key's add on `ground` (see the module docs for the rules).
    pub fn stage_add(
        &mut self,
        new: NewKey,
        ground: Ground,
        now_ms: i64,
    ) -> Result<Staged<AddOutcome>, StoreError> {
        let kid = new.key.key_id().short().to_string();
        let ground_name = ground.as_str();
        let result = self
            .idle("add")
            .and_then(|()| self.try_stage_add(new, ground, now_ms));
        match &result {
            Ok(staged) => tracing::debug!(
                kid = %kid,
                ground = ground_name,
                user_id = staged.outcome.telegram_user_id,
                role = staged.outcome.role.as_str(),
                unconfirmed = staged.outcome.unconfirmed,
                rpk_dropped = staged.outcome.rpk_dropped,
                lifted = staged.outcome.lifted.unwrap_or("-"),
                known_person = staged.outcome.known_person,
                "viewer keys: add staged"
            ),
            Err(e) => tracing::debug!(
                kid = %kid,
                ground = ground_name,
                reason = e.as_str(),
                "viewer keys: add refused ({e})"
            ),
        }
        self.launch(result)
    }

    /// [`Self::stage_add`], written and installed at once (blocking).
    pub fn add(
        &mut self,
        new: NewKey,
        ground: Ground,
        now_ms: i64,
    ) -> Result<AddOutcome, StoreError> {
        let staged = self.stage_add(new, ground, now_ms)?;
        self.apply(staged)
    }

    fn try_stage_add(
        &self,
        new: NewKey,
        ground: Ground,
        now_ms: i64,
    ) -> Result<Staged<AddOutcome>, StoreError> {
        let (next, what, outcome) = self.plan_add(new, ground, now_ms)?;
        self.staged(next, what, outcome)
    }

    /// Every rule of [`Self::stage_add`] without staging anything: what the add would do now, or
    /// why it is refused. No I/O, allowed while a change is in flight (the admission decides an
    /// offer here; the queue stages the add for real at its turn and decides again). Costs one
    /// clone of the list.
    pub fn check_add(
        &self,
        new: &NewKey,
        ground: &Ground,
        now_ms: i64,
    ) -> Result<AddOutcome, StoreError> {
        self.plan_add(new.clone(), ground.clone(), now_ms)
            .map(|(_, _, outcome)| outcome)
    }

    /// §5: a pairing at the PC with the owner's role for a key that is already this same
    /// person's working GUEST-role record rewrites that record to the owner's role (source
    /// `pair`, confirmed as the pairing is) instead of a second record — the owner's own device
    /// paired as a guest earlier. In strict mode with a dirty window nothing is written
    /// (`key_unconfirmed`): the record stays as it was. `None`: not this case.
    #[allow(clippy::type_complexity)]
    fn lift_to_owner(
        &self,
        list: &TrustList,
        key_id: &KeyId,
        (person, role, source): (&Person, BindingRole, &KeySource),
        unconfirmed: bool,
        strict: bool,
    ) -> Option<Result<(TrustList, String, AddOutcome), StoreError>> {
        if role != BindingRole::Owner || !matches!(source, KeySource::Pair) {
            return None;
        }
        let uid = person.telegram_user_id;
        let at = list.find(key_id)?;
        let record = list.keys.get(at)?;
        if record.person.telegram_user_id != uid
            || record.role != BindingRole::Guest
            || !self.works(record)
        {
            return None;
        }
        if unconfirmed && strict {
            tracing::trace!(
                kid = %key_id.short(),
                user_id = uid,
                "viewer keys: the owner's pairing of his own guest-role key in strict mode with a \
                 dirty window: it would not be written (key_unconfirmed), the record stays a \
                 guest's"
            );
            return Some(Err(StoreError::KeyUnconfirmed));
        }
        let mut next = list.clone();
        let r = next.keys.get_mut(at)?;
        r.role = BindingRole::Owner;
        r.source = KeySource::Pair;
        r.unconfirmed = unconfirmed;
        r.person = person.clone();
        tracing::trace!(
            kid = %key_id.short(),
            user_id = uid,
            unconfirmed,
            "viewer keys: the owner's pairing would lift his own guest-role record to the owner's \
             role"
        );
        let what = format!(
            "key {} of user {uid} lifted to the owner's role (pair{})",
            key_id.short(),
            if unconfirmed { ", unconfirmed" } else { "" },
        );
        Some(Ok((
            next,
            what,
            AddOutcome {
                key_id: key_id.clone(),
                telegram_user_id: uid,
                role: BindingRole::Owner,
                unconfirmed,
                rpk_dropped: false,
                lifted: None,
                known_person: true,
            },
        )))
    }

    fn plan_add(
        &self,
        new: NewKey,
        ground: Ground,
        now_ms: i64,
    ) -> Result<(TrustList, String, AddOutcome), StoreError> {
        let list = self.ready()?;
        let key_id = new.key.key_id().clone();
        check_new_key(&new.key, new.rpk.as_ref())?;
        // A key active already is refused after the ground's own checks (spec §10: a ground spent
        // meanwhile says so; one still valid leaves the decision to the existing record).
        let already = list.find(&key_id).is_some();
        let strict = list.switches.trusted_devices_mode;
        // §5, §10.2 `key_other_person`: a pairing at the PC never takes a key that is active or
        // removed at another person — the record or tombstone stays as it is; a removed key comes
        // back by «Разрешить» only to its own person. Before every other rule: nothing is touched.
        if let Ground::Pair { person, .. } = &ground {
            let uid = person.telegram_user_id;
            let other = list
                .active(&key_id)
                .map(|r| (r.person.telegram_user_id, "active"))
                .or_else(|| {
                    list.tombstone(&key_id)
                        .map(|t| (t.telegram_user_id, "removed"))
                })
                .filter(|(o, _)| *o != uid);
            if let Some((other_user_id, state)) = other {
                // A plan (the request window reads it every turn): trace; the press says it
                // (`admission: allow: the key is at another person`).
                tracing::trace!(
                    kid = %key_id.short(),
                    user_id = uid,
                    other_user_id,
                    state,
                    "viewer keys: pairing: the key is at another person; it would not be written \
                     (key_other_person)"
                );
                return Err(StoreError::OtherPerson(key_id));
            }
        }
        // One return rule (spec §10): `pc` and `server` — a confirmed `pair`, a `grant` over
        // the current token with a new invitation (without an invitation it is `invite_missing`),
        // or a new `endorse` of a trusted device (its signer, its spent mark); the ground's own
        // checks and then its person are decided below; `replaced` — only a confirmed `pair`. A
        // marked pair (`pc_allow`, a §3.4 window with another session) may be the server's
        // doing: it lifts nothing.
        let tomb = list.tombstone(&key_id);
        match (tomb, &ground) {
            (None, _)
            | (
                Some(_),
                Ground::Pair {
                    unconfirmed: false, ..
                },
            ) => {}
            (
                Some(Tombstone {
                    origin: Origin::Pc | Origin::Server,
                    ..
                }),
                Ground::Grant { .. } | Ground::Endorse { .. },
            ) => {}
            // §10, §5: in strict mode a pairing that would be unconfirmed is not written at all —
            // `key_unconfirmed`, whatever its tombstone (which stays).
            (
                Some(t),
                Ground::Pair {
                    unconfirmed: true, ..
                },
            ) if strict => {
                tracing::trace!(
                    kid = %key_id.short(),
                    origin = t.origin.as_str(),
                    "viewer keys: a removed key's unconfirmed pairing in strict mode: it would not \
                     be written (key_unconfirmed)"
                );
                return Err(StoreError::KeyUnconfirmed);
            }
            (Some(t), _) => {
                return Err(StoreError::Removed {
                    key_id,
                    origin: t.origin.as_str(),
                });
            }
        }
        let (person, role, source, unconfirmed) = match ground {
            Ground::Pair {
                person,
                role,
                unconfirmed,
            } => (kept_person(person)?, role, KeySource::Pair, unconfirmed),
            Ground::Endorse {
                by,
                endorse_id,
                issued_at,
            } => {
                // A signer whose removal is decided counts as removed (§10, deny_now).
                let Some(signer) = self.signer(list, &by) else {
                    return Err(
                        if list.tombstone(&by).is_some() || list.active(&by).is_some() {
                            StoreError::SignerRemoved(by)
                        } else {
                            StoreError::SignerUnknown(by)
                        },
                    );
                };
                if list.spent_endorse.contains(&endorse_id) {
                    return Err(StoreError::Spent(endorse_id));
                }
                // §10 «Одно правило возврата»: after the endorse's own checks, a removed key comes
                // back only by an endorse issued AFTER its removal (`issued_at` > the removed
                // record's `removed_at`, strictly, no tolerance: the signing device's clock against
                // the PC's, both unix ms); otherwise `key_revoked` — this ground's refusal, the next
                // one in `admit` is still tried. Decided here, over the tombstone read with the
                // list, at the admission's check and again at the write.
                if let Some(t) = tomb {
                    if i128::from(issued_at) <= i128::from(t.at) {
                        tracing::debug!(
                            kid = %key_id.short(),
                            by = %by.short(),
                            origin = t.origin.as_str(),
                            issued_at,
                            removed_at = t.at,
                            "viewer keys: the endorse is not later than the key's removal: it \
                             returns nothing (key_revoked)"
                        );
                        return Err(StoreError::Removed {
                            key_id,
                            origin: t.origin.as_str(),
                        });
                    }
                }
                // Person and role are the endorser's, whatever the caller would say; so is the
                // unconfirmed mark (§10.1: it is inherited down the chain).
                (
                    signer.person.clone(),
                    signer.role,
                    KeySource::Endorse { by, endorse_id },
                    signer.unconfirmed,
                )
            }
            Ground::Grant {
                by,
                grant_id,
                inv_id,
                invite,
                person,
                token,
            } => {
                let person = kept_person(person)?;
                let granter = self
                    .signer(list, &by)
                    .filter(|r| r.role == BindingRole::Owner)
                    .ok_or(StoreError::NotOwner)?;
                if list.spent_grant.contains(&grant_id) {
                    return Err(StoreError::Spent(grant_id));
                }
                // Deliberately strict: any owner-role record of the grant's person still listed,
                // working or not, refuses it (that removal may yet be undone),
                // as the admission's check does.
                if list
                    .keys_of(person.telegram_user_id)
                    .any(|r| r.role == BindingRole::Owner)
                {
                    return Err(StoreError::GrantRole);
                }
                // §7 «Токен выдачи»: the grant's last own check, decided again here as at the
                // first decision — a removal since replaced the token.
                if let Err(e) = self.grant_token_current(&token) {
                    tracing::debug!(
                        kid = %key_id.short(),
                        by = %by.short(),
                        "viewer keys: the grant carries another grant token than the PC's current \
                         one (a removal since it was signed): grant_stale"
                    );
                    return Err(e);
                }
                // The spec's order (§7): invite_missing, invite_bad, invite_owner_mismatch,
                // (invite_expired — the caller's), invite_spent.
                // A removed key comes back only with an invitation (§10.1), in both modes.
                let unconfirmed = match &invite {
                    None if strict || tomb.is_some() => {
                        tracing::debug!(
                            kid = %key_id.short(),
                            strict,
                            removed = tomb.is_some(),
                            "viewer keys: a grant without an invitation: invite_missing"
                        );
                        return Err(StoreError::InviteMissing);
                    }
                    None => {
                        tracing::debug!(
                            kid = %key_id.short(),
                            "viewer keys: a grant without an invitation (observe mode): the key \
                             is unconfirmed"
                        );
                        true
                    }
                    Some(inv) => {
                        if inv_id.as_ref() != Some(&inv.inv_id) {
                            tracing::debug!(
                                kid = %key_id.short(),
                                grant_inv_id = %inv_id.as_ref().map_or("-", GroundId::as_str),
                                invite_inv_id = %inv.inv_id,
                                "viewer keys: the invitation is not the grant's"
                            );
                            return Err(StoreError::InviteIdMismatch);
                        }
                        let inviter = self
                            .signer(list, &inv.by)
                            .filter(|r| r.role == BindingRole::Owner)
                            .ok_or(StoreError::InviteNotOwner)?;
                        if inviter.person.telegram_user_id != granter.person.telegram_user_id {
                            return Err(StoreError::InviteOwnerMismatch);
                        }
                        granter.unconfirmed || inviter.unconfirmed
                    }
                };
                // Spent with or without the invitation: an old request cannot come back with one.
                if let Some(inv_id) = inv_id.as_ref().filter(|i| list.spent_invite.contains(*i)) {
                    return Err(StoreError::InviteSpent(inv_id.clone()));
                }
                (
                    person,
                    BindingRole::Guest,
                    KeySource::Grant {
                        by,
                        grant_id,
                        inv_id,
                        invite_by: invite.map(|inv| inv.by),
                    },
                    unconfirmed,
                )
            }
            Ground::FirstUse { telegram_user_id } => {
                let entry = list.first_use_person(telegram_user_id)?;
                (entry.person, entry.role, KeySource::FirstUse, true)
            }
        };
        let uid = person.telegram_user_id;
        if already {
            if let Some(lifted) =
                self.lift_to_owner(list, &key_id, (&person, role, &source), unconfirmed, strict)
            {
                return lifted;
            }
            tracing::trace!(
                kid = %key_id.short(),
                ground = source.as_str(),
                "viewer keys: the key is active already: there would be no second record"
            );
            return Err(StoreError::AlreadyActive(key_id));
        }
        // A removal lifts only for its own person (a pairing at the PC decided that above): a
        // grant's person, an endorse's signer's person.
        if let Some(t) = tomb {
            if !matches!(source, KeySource::Pair) && t.telegram_user_id != uid {
                tracing::debug!(
                    kid = %key_id.short(),
                    ground = source.as_str(),
                    origin = t.origin.as_str(),
                    removed_user_id = t.telegram_user_id,
                    user_id = uid,
                    "viewer keys: a ground for another person cannot lift this removal"
                );
                return Err(StoreError::Removed {
                    key_id,
                    origin: t.origin.as_str(),
                });
            }
        }
        if unconfirmed && strict {
            return Err(StoreError::KeyUnconfirmed);
        }
        let mut rpk = new.rpk;
        let mut rpk_dropped = false;
        if let Some(r) = &rpk {
            if let Some(other) = list
                .keys
                .iter()
                .find(|k| k.rpk.as_ref() == Some(r) && k.person.telegram_user_id != uid)
            {
                if matches!(source, KeySource::Pair) {
                    // A plan: trace; the press logs `rpk_dropped`, the write's line says
                    // «without its recovery key».
                    tracing::trace!(
                        kid = %key_id.short(),
                        user_id = uid,
                        other_user_id = other.person.telegram_user_id,
                        "viewer keys: pairing: the device's recovery key is on another person's \
                         key; the key would be added without it (no recovery for it)"
                    );
                    rpk = None;
                    rpk_dropped = true;
                } else {
                    tracing::debug!(
                        kid = %key_id.short(),
                        user_id = uid,
                        other_user_id = other.person.telegram_user_id,
                        "viewer keys: the recovery key is on another person's key"
                    );
                    return Err(StoreError::RpkConflict);
                }
            }
        }
        // §7: a grant for a guest this PC has already adds the key to that person (the owner was
        // refused above, `grant_role`); the per-person limit below holds it like any other add.
        let known_person = list
            .keys_of(uid)
            .any(|r| !self.pending_removal.contains_key(r.key_id()));
        // A plan: the request window reads it every turn, so its narrative is trace; the write
        // ("add staged", `known_person`, `lifted`) and an admission's candidate say it once.
        if known_person {
            tracing::trace!(
                kid = %key_id.short(),
                user_id = uid,
                keys_of_person = list.keys_of(uid).count(),
                ground = source.as_str(),
                "viewer keys: the person has keys here already: the key would join them"
            );
        }
        let mut next = list.clone();
        let lifted = tomb.map(|t| t.origin.as_str());
        if lifted.is_some() {
            next.tombstones.retain(|t| *t.key_id() != key_id);
            tracing::trace!(
                kid = %key_id.short(),
                origin = lifted.unwrap_or("-"),
                "viewer keys: the add would lift the key's tombstone"
            );
        }
        let spends = match &source {
            KeySource::Endorse { .. } => 1,
            KeySource::Grant { .. } => 2,
            _ => 0,
        };
        // A confirmed pairing is a person's own action at the PC: not held by the tombstone limit
        // (§10). A marked one (`pc_allow`, a §3.4 window with another session) may be the
        // server's doing, so it is held like every other ground.
        next.room_for_new(
            uid,
            spends,
            matches!(source, KeySource::Pair) && !unconfirmed,
        )?;
        match &source {
            KeySource::Endorse { endorse_id, .. } => {
                next.spent_endorse.insert(endorse_id.clone());
            }
            KeySource::Grant {
                grant_id, inv_id, ..
            } => {
                next.spent_grant.insert(grant_id.clone());
                if let Some(inv_id) = inv_id {
                    next.spent_invite.insert(inv_id.clone());
                }
            }
            _ => {}
        }
        let what = format!(
            "added key {} of user {uid} ({}, {}{}{}{})",
            key_id.short(),
            role.as_str(),
            source.as_str(),
            if unconfirmed { ", unconfirmed" } else { "" },
            if rpk_dropped {
                ", without its recovery key"
            } else if rpk.is_some() {
                ", with a recovery key"
            } else {
                ""
            },
            lifted.map_or_else(String::new, |o| format!(", {o} tombstone lifted")),
        );
        let outcome = AddOutcome {
            key_id: key_id.clone(),
            telegram_user_id: uid,
            role,
            unconfirmed,
            rpk_dropped,
            lifted,
            known_person,
        };
        next.keys.push(KeyRecord {
            key: new.key,
            person,
            role,
            rpk,
            kind: new.kind,
            platform: new.platform,
            source,
            unconfirmed,
            added_at: now_ms,
            last_used_at: None,
        });
        Ok((next, what, outcome))
    }

    // --- Removing and confirming ----------------------------------------------------------

    /// Stage the removal of an active key (`pc`, or `server` for a guest's key only). Always has
    /// room.
    pub fn stage_remove(
        &mut self,
        key_id: &KeyId,
        by: Removal,
        now_ms: i64,
    ) -> Result<Staged<()>, StoreError> {
        let result = self
            .idle("remove")
            .and_then(|()| self.try_stage_remove(key_id, by, now_ms));
        if let Err(e) = &result {
            tracing::debug!(
                kid = %key_id.short(),
                by = ?by,
                reason = e.as_str(),
                "viewer keys: removal refused ({e})"
            );
        }
        let result = self.launch(result);
        if result.is_ok() {
            // Denied from the stage on: the removal is decided.
            self.removing(std::slice::from_ref(key_id));
        }
        result
    }

    /// [`Self::stage_remove`], written and installed at once (blocking).
    pub fn remove(&mut self, key_id: &KeyId, by: Removal, now_ms: i64) -> Result<(), StoreError> {
        let staged = self.stage_remove(key_id, by, now_ms)?;
        self.apply(staged)
    }

    fn try_stage_remove(
        &self,
        key_id: &KeyId,
        by: Removal,
        now_ms: i64,
    ) -> Result<Staged<()>, StoreError> {
        let list = self.ready()?;
        let i = active_index(list, key_id)?;
        let origin = match by {
            Removal::Pc => Origin::Pc,
            // Design §8: the PC never applies an owner's removal from the server.
            Removal::Server if list.keys[i].role == BindingRole::Owner => {
                return Err(StoreError::ServerRemovesOwner);
            }
            Removal::Server => Origin::Server,
        };
        let mut next = list.clone();
        let old = next.keys.remove(i);
        let what = format!(
            "removed key {} of user {} ({}, {})",
            key_id.short(),
            old.person.telegram_user_id,
            old.role.as_str(),
            origin.as_str()
        );
        next.tombstones.push(old.tombstone(origin, now_ms));
        self.staged(next, what, ())
    }

    /// At the PC (§10.1 «Подтвердить»): stage clearing the `unconfirmed` mark of one active key.
    /// `Ok(None)` when it has none (nothing to write). There is no «confirm all».
    pub fn stage_confirm(&mut self, key_id: &KeyId) -> Result<Option<Staged<()>>, StoreError> {
        let result = self
            .idle("confirm")
            .and_then(|()| self.try_stage_confirm(key_id));
        match &result {
            Ok(Some(_)) => tracing::debug!(kid = %key_id.short(), "viewer keys: confirm staged"),
            Ok(None) => tracing::debug!(
                kid = %key_id.short(),
                "viewer keys: confirm: the key is confirmed already; nothing written"
            ),
            Err(e) => tracing::debug!(
                kid = %key_id.short(),
                reason = e.as_str(),
                "viewer keys: confirm refused ({e})"
            ),
        }
        self.launch_some(result)
    }

    /// [`Self::stage_confirm`], written and installed at once (blocking). `true` when the mark
    /// was cleared, `false` when there was none.
    pub fn confirm(&mut self, key_id: &KeyId) -> Result<bool, StoreError> {
        match self.stage_confirm(key_id)? {
            Some(staged) => self.apply(staged).map(|()| true),
            None => Ok(false),
        }
    }

    fn try_stage_confirm(&self, key_id: &KeyId) -> Result<Option<Staged<()>>, StoreError> {
        let list = self.ready()?;
        let i = active_index(list, key_id)?;
        // A key whose removal is decided (§10.1 «Нажатие решает сразу») is removed for
        // every rule: no confirm of it — this write would turn it into a tombstone (the carry).
        if let Some(origin) = self.removal_decided(key_id) {
            tracing::debug!(
                kid = %key_id.short(),
                origin,
                user_id = list.keys[i].person.telegram_user_id,
                "viewer keys: confirm refused: the key's removal is decided (pending)"
            );
            return Err(StoreError::Removed {
                key_id: key_id.clone(),
                origin,
            });
        }
        if !list.keys[i].unconfirmed {
            return Ok(None);
        }
        let mut next = list.clone();
        next.keys[i].unconfirmed = false;
        let what = format!(
            "key {} of user {} confirmed at the PC",
            key_id.short(),
            next.keys[i].person.telegram_user_id
        );
        self.staged(next, what, ()).map(Some)
    }

    // --- Recovery -------------------------------------------------------------------------

    /// Stage a same-device recovery (spec §8.4), every check in one step. The caller has checked
    /// the offer's signature by the new key, the new `key_reg` (its `rpk` is `recovery.rpk`) and
    /// Telegram's attestation ([`super::TelegramVerifier::verify_attestation`]).
    ///
    /// The attestation must be for the new key ([`StoreError::RecoverAttestation`]). Candidates
    /// are the active keys with the same `rpk` **and** the attested person (none →
    /// [`StoreError::RecoverNoRecord`]; there is no «old key» hint). `rsig` must verify under that
    /// `rpk` over `r` (§8.3), which the store builds from `device_id`, `session_id`, the new
    /// `key_id` and `nonce_pc` ([`StoreError::RecoverBadSig`] — the admission journals it). The new
    /// key takes the person (names refreshed from the attestation), the **lesser** role of the
    /// candidates, the mark if any candidate has it, and `rpk`; **every** candidate becomes a
    /// tombstone `replaced`. Room: tombstones + candidates ≤ [`MAX_TOMBSTONES`]. No switch.
    pub fn stage_recover(
        &mut self,
        recovery: Recovery<'_>,
        now_ms: i64,
    ) -> Result<Staged<RecoverOutcome>, StoreError> {
        let kid = recovery.new_key.key_id().short().to_string();
        let rpk_kid = recovery.rpk.key_id().short().to_string();
        let uid = recovery.attested.user_id();
        let result = self
            .idle("recover")
            .and_then(|()| self.try_stage_recover(recovery, now_ms));
        match &result {
            Ok(staged) => tracing::debug!(
                kid = %kid,
                rpk = %rpk_kid,
                user_id = uid,
                role = staged.outcome.role.as_str(),
                unconfirmed = staged.outcome.unconfirmed,
                replaced = %short_list(&staged.outcome.replaced),
                "viewer keys: recovery staged"
            ),
            Err(e) => tracing::debug!(
                kid = %kid,
                rpk = %rpk_kid,
                user_id = uid,
                reason = e.as_str(),
                "viewer keys: recovery refused ({e})"
            ),
        }
        self.launch(result)
    }

    /// [`Self::stage_recover`], written and installed at once (blocking).
    pub fn recover(
        &mut self,
        recovery: Recovery<'_>,
        now_ms: i64,
    ) -> Result<RecoverOutcome, StoreError> {
        let staged = self.stage_recover(recovery, now_ms)?;
        self.apply(staged)
    }

    fn try_stage_recover(
        &self,
        r: Recovery<'_>,
        now_ms: i64,
    ) -> Result<Staged<RecoverOutcome>, StoreError> {
        let (next, what, outcome) = self.plan_recover(r, now_ms)?;
        self.staged(next, what, outcome)
    }

    /// Every check of [`Self::stage_recover`] (the recovery signature included) without staging
    /// anything; see [`Self::check_add`].
    pub fn check_recover(
        &self,
        recovery: Recovery<'_>,
        now_ms: i64,
    ) -> Result<RecoverOutcome, StoreError> {
        self.plan_recover(recovery, now_ms)
            .map(|(_, _, outcome)| outcome)
    }

    fn plan_recover(
        &self,
        r: Recovery<'_>,
        now_ms: i64,
    ) -> Result<(TrustList, String, RecoverOutcome), StoreError> {
        let list = self.ready()?;
        let new_id = r.new_key.key_id().clone();
        if r.attested.attested_key() != &new_id {
            tracing::debug!(
                kid = %new_id.short(),
                attested = %r.attested.attested_key().short(),
                "viewer keys: recovery: the attestation is another key's"
            );
            return Err(StoreError::RecoverAttestation);
        }
        check_new_key(&r.new_key, Some(r.rpk))?;
        let uid = r.attested.user_id();
        let same_rpk = list
            .keys
            .iter()
            .filter(|k| k.rpk.as_ref() == Some(r.rpk))
            .count();
        // A record whose removal is pending (deny_now) is removed already: no recovery from it.
        let candidates: Vec<&KeyRecord> = list
            .keys
            .iter()
            .filter(|k| k.rpk.as_ref() == Some(r.rpk) && k.person.telegram_user_id == uid)
            .filter(|k| !self.pending_removal.contains_key(k.key_id()))
            .collect();
        tracing::debug!(
            user_id = uid,
            same_rpk,
            pending_excluded = list
                .keys
                .iter()
                .filter(|k| k.rpk.as_ref() == Some(r.rpk)
                    && k.person.telegram_user_id == uid
                    && self.pending_removal.contains_key(k.key_id()))
                .count(),
            candidates = candidates.len(),
            "viewer keys: recovery: candidates by recovery key and person"
        );
        let Some(first) = candidates.first() else {
            return Err(StoreError::RecoverNoRecord);
        };
        // The candidates' own rpk (equal to the card's): the record is what the PC trusts.
        let rpk = first.rpk.as_ref().unwrap_or(r.rpk);
        let message = recover_message(r.device_id, r.session_id, &new_id, &r.nonce_pc);
        if rpk.verify(&message, r.rsig).is_err() {
            return Err(StoreError::RecoverBadSig);
        }
        // As for every new key (§4): the recovery key on another person's record too — one device
        // cannot be two people's — refuses (after the signature, spec §8.4 and recover.json).
        if let Some(other) = list
            .keys
            .iter()
            .find(|k| k.rpk.as_ref() == Some(rpk) && k.person.telegram_user_id != uid)
        {
            tracing::debug!(
                kid = %new_id.short(),
                user_id = uid,
                other_user_id = other.person.telegram_user_id,
                "viewer keys: recovery: the recovery key is on another person's key too"
            );
            return Err(StoreError::RpkConflict);
        }
        if list.find(&new_id).is_some() {
            return Err(StoreError::AlreadyActive(new_id));
        }
        if let Some(t) = list.tombstone(&new_id) {
            return Err(StoreError::Removed {
                key_id: new_id,
                origin: t.origin.as_str(),
            });
        }
        let role = if candidates.iter().any(|c| c.role == BindingRole::Guest) {
            BindingRole::Guest
        } else {
            BindingRole::Owner
        };
        let unconfirmed = candidates.iter().any(|c| c.unconfirmed);
        if unconfirmed && list.switches.trusted_devices_mode {
            return Err(StoreError::KeyUnconfirmed);
        }
        // A replacement, not a new key: only the tombstones it adds need room.
        if list.tombstones.len() + candidates.len() > MAX_TOMBSTONES {
            tracing::debug!(
                tombstones = list.tombstones.len(),
                replacing = candidates.len(),
                "viewer keys: no room for the replaced keys' tombstones"
            );
            return Err(StoreError::Full(Limit::Tombstones));
        }
        let named = candidates
            .iter()
            .find(|c| c.role == role)
            .copied()
            .unwrap_or(first);
        let person = Person {
            telegram_user_id: uid,
            first_name: r
                .attested
                .first_name()
                .and_then(kept_name)
                .or_else(|| named.person.first_name.clone()),
            username: r
                .attested
                .username()
                .and_then(kept_name)
                .or_else(|| named.person.username.clone()),
        };
        let replaced: Vec<KeyId> = candidates.iter().map(|c| c.key_id().clone()).collect();
        // §10.1: the new record inherits the replaced records' edges, stored in itself.
        let mut parents: Vec<KeyId> = Vec::new();
        for parent in candidates.iter().flat_map(|c| c.source.parents()) {
            if !parents.contains(parent) && !replaced.contains(parent) {
                parents.push(parent.clone());
            }
        }
        let mut next = list.clone();
        let (gone, kept): (Vec<KeyRecord>, Vec<KeyRecord>) = std::mem::take(&mut next.keys)
            .into_iter()
            .partition(|k| replaced.contains(k.key_id()));
        next.keys = kept;
        next.tombstones.extend(gone.iter().map(|k| {
            k.tombstone(
                Origin::Replaced {
                    new_key_id: new_id.clone(),
                },
                now_ms,
            )
        }));
        let what = format!(
            "recovered: key {} of user {uid} ({}{}) replaced {} key(s): {}; inherits {} edge(s): \
             {}",
            new_id.short(),
            role.as_str(),
            if unconfirmed { ", unconfirmed" } else { "" },
            replaced.len(),
            short_list(&replaced),
            parents.len(),
            short_list(&parents)
        );
        let outcome = RecoverOutcome {
            new_key_id: new_id,
            telegram_user_id: uid,
            role,
            unconfirmed,
            replaced: replaced.clone(),
        };
        next.keys.push(KeyRecord {
            key: r.new_key,
            person,
            role,
            rpk: Some(rpk.clone()),
            kind: r.kind,
            platform: r.platform,
            source: KeySource::Recover { replaced, parents },
            unconfirmed,
            added_at: now_ms,
            last_used_at: None,
        });
        Ok((next, what, outcome))
    }

    // --- last_used_at, the switch, the snapshot -------------------------------------------

    /// Note a connection of an active key: in memory at once, always. `Some` — a change to write
    /// and install — only when the file has no value for it or one at least
    /// [`LAST_USED_WRITE_AFTER_MS`] old (otherwise the value goes out with the next change).
    pub fn stage_touch(
        &mut self,
        key_id: &KeyId,
        now_ms: i64,
    ) -> Result<Option<Staged<()>>, StoreError> {
        let result = self.try_stage_touch(key_id, now_ms);
        if let Err(e) = &result {
            tracing::debug!(
                kid = %key_id.short(),
                reason = e.as_str(),
                "viewer keys: touch refused ({e})"
            );
        }
        self.launch_some(result)
    }

    /// [`Self::stage_touch`], written and installed at once when due (blocking). Whether it was
    /// written.
    pub fn touch(&mut self, key_id: &KeyId, now_ms: i64) -> Result<bool, StoreError> {
        match self.stage_touch(key_id, now_ms)? {
            Some(staged) => self.apply(staged).map(|()| true),
            None => Ok(false),
        }
    }

    fn try_stage_touch(
        &mut self,
        key_id: &KeyId,
        now_ms: i64,
    ) -> Result<Option<Staged<()>>, StoreError> {
        let State::Ready(list) = &mut self.state else {
            return Err(StoreError::Damaged);
        };
        let i = list
            .find(key_id)
            .ok_or_else(|| StoreError::NotFound(key_id.clone()))?;
        list.keys[i].last_used_at = Some(now_ms);
        let stored = self.stored_last_used.get(key_id).copied();
        // The notes (§10, §10.2) not yet in the file make it due too: they go with it.
        let due = self.notes_unsaved()
            || match stored {
                None => true,
                Some(t) => now_ms.saturating_sub(t) >= LAST_USED_WRITE_AFTER_MS,
            };
        if !due {
            tracing::trace!(
                kid = %key_id.short(),
                stored = stored.unwrap_or(0),
                "viewer keys: use noted in memory; the file's value is recent"
            );
            return Ok(None);
        }
        // Noted in memory either way; the write waits for the change in flight (whose install
        // keeps the later value), a reopen, or the next touch — never an error for a display time.
        if let Err(e) = self.idle("touch") {
            tracing::debug!(
                kid = %key_id.short(),
                reason = e.as_str(),
                "viewer keys: use noted in memory; written with a later change"
            );
            return Ok(None);
        }
        let next = self.ready()?.clone();
        self.staged(next, format!("key {} used", key_id.short()), ())
            .map(Some)
    }

    /// Stage switching «Доверенные устройства» on or off; `Ok(None)` when it is so already.
    pub fn stage_set_trusted_devices_mode(
        &mut self,
        on: bool,
    ) -> Result<Option<Staged<()>>, StoreError> {
        let result = self.idle("switch").and_then(|()| self.try_stage_switch(on));
        self.launch_some(result)
    }

    fn try_stage_switch(&self, on: bool) -> Result<Option<Staged<()>>, StoreError> {
        let list = match self.ready() {
            Ok(list) => list,
            Err(e) => {
                tracing::debug!(on, "viewer keys: switch refused ({e})");
                return Err(e);
            }
        };
        if list.switches.trusted_devices_mode == on {
            tracing::debug!(
                on,
                "viewer keys: trusted devices mode already so; nothing written"
            );
            return Ok(None);
        }
        let mut next = list.clone();
        next.switches.trusted_devices_mode = on;
        let what = format!(
            "trusted devices mode switched {}",
            if on { "on" } else { "off" }
        );
        self.staged(next, what, ()).map(Some)
    }

    /// [`Self::stage_set_trusted_devices_mode`], written and installed at once (blocking).
    pub fn set_trusted_devices_mode(&mut self, on: bool) -> Result<(), StoreError> {
        match self.stage_set_trusted_devices_mode(on)? {
            Some(staged) => self.apply(staged),
            None => Ok(()),
        }
    }

    /// Stage the `first_use` snapshot (§9) from the bindings of the first `agent_ready`: once.
    /// `Ok(None)` when one exists. A person listed twice is kept once, with the lesser role
    /// (`warn`).
    pub fn stage_first_use_snapshot(
        &mut self,
        people: Vec<SnapshotPerson>,
        now_ms: i64,
    ) -> Result<Option<Staged<()>>, StoreError> {
        let offered = people.len();
        let result = self
            .idle("first_use snapshot")
            .and_then(|()| self.try_stage_snapshot(people, now_ms));
        match &result {
            Ok(Some(_)) => tracing::debug!(offered, "viewer keys: first_use snapshot staged"),
            Ok(None) => tracing::debug!(
                offered,
                "viewer keys: first_use snapshot exists already; the new one ignored"
            ),
            Err(e) => tracing::debug!(
                offered,
                reason = e.as_str(),
                "viewer keys: first_use snapshot refused ({e})"
            ),
        }
        self.launch_some(result)
    }

    /// [`Self::stage_first_use_snapshot`], written and installed at once (blocking). Whether it
    /// was taken.
    pub fn take_first_use_snapshot(
        &mut self,
        people: Vec<SnapshotPerson>,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        match self.stage_first_use_snapshot(people, now_ms)? {
            Some(staged) => self.apply(staged).map(|()| true),
            None => Ok(false),
        }
    }

    fn try_stage_snapshot(
        &self,
        people: Vec<SnapshotPerson>,
        now_ms: i64,
    ) -> Result<Option<Staged<()>>, StoreError> {
        let list = self.ready()?;
        if list.snapshot.is_some() {
            return Ok(None);
        }
        if people.len() > MAX_SNAPSHOT_PEOPLE {
            return Err(StoreError::Invalid(format!(
                "{} people in the snapshot",
                people.len()
            )));
        }
        let mut kept: Vec<SnapshotPerson> = Vec::with_capacity(people.len());
        for p in people {
            let uid = p.person.telegram_user_id;
            let Ok(person) = kept_person(p.person) else {
                // One bad entry of the server's list does not cost everyone their first_use.
                tracing::warn!(
                    user_id = uid,
                    "viewer keys: first_use snapshot: a person with a user id out of range; \
                     skipped"
                );
                continue;
            };
            if let Some(seen) = kept.iter_mut().find(|k| k.person.telegram_user_id == uid) {
                let lesser = if seen.role == BindingRole::Guest || p.role == BindingRole::Guest {
                    BindingRole::Guest
                } else {
                    BindingRole::Owner
                };
                tracing::warn!(
                    user_id = uid,
                    first = seen.role.as_str(),
                    again = p.role.as_str(),
                    kept = lesser.as_str(),
                    "viewer keys: first_use snapshot: a person listed twice; kept once with the \
                     lesser role"
                );
                seen.role = lesser;
                continue;
            }
            kept.push(SnapshotPerson {
                person,
                role: p.role,
            });
        }
        let owners = kept.iter().filter(|p| p.role == BindingRole::Owner).count();
        let what = format!(
            "first_use snapshot taken: {} people, {owners} owner(s)",
            kept.len()
        );
        let mut next = list.clone();
        next.snapshot = Some(FirstUseSnapshot {
            taken_at: now_ms,
            people: kept,
        });
        self.staged(next, what, ()).map(Some)
    }

    // --- At-PC repairs --------------------------------------------------------------------

    /// At the PC: stage a reset. The outcome is the `key_id`s that were active (their live
    /// sessions must end).
    ///
    /// - Healthy store: every active key becomes a tombstone `pc` (so `first_use` stays closed
    ///   for everyone who ever had a key here; a key comes back by a pairing at the PC or a new
    ///   invited grant over the token the reset replaced);
    ///   the tombstones, the spent ids, the snapshot and the mode stay. (A full spent list stays
    ///   full: [`Limit::Spent`] then refuses endorse and grant, never pair.)
    /// - Damaged store: refused for [`DamageKind::Unreadable`] ([`StoreError::Unreadable`]:
    ///   reopen first) and for [`DamageKind::NewerVersion`] ([`StoreError::NewerVersion`]: a
    ///   newer build wrote it — upgrade instead of wiping it). Otherwise the write keeps the damaged primary as
    ///   `viewer_keys.json.damaged-<now_ms>` (a hard link or a copy; then the primary is replaced
    ///   whole: never a moment without one), and when the backup passes every check carries over
    ///   its tombstones, spent ids and snapshot and turns its active keys into tombstones `pc`;
    ///   with no usable backup the list is empty. The switch is the damaged store's effective one
    ///   ([`Self::damaged_mode`], strict when the mode file says nothing) — the window promises
    ///   it stays as it is.
    pub fn stage_reset_to_empty(&mut self, now_ms: i64) -> Result<Staged<Vec<KeyId>>, StoreError> {
        let result = self.idle("reset").and_then(|()| {
            // §7 «Токен выдачи»: a reset replaces the grant token in its own write (the staged
            // snapshot carries it). A damaged store's reset writes a fresh one of its own. Every
            // refusal comes before this (`idle`; the damaged kinds take the other branch) and a
            // ready list's stage refuses nothing, so the token is replaced only for a reset that
            // is staged: its keys are denied below, whatever its write does.
            if !self.is_damaged() {
                self.rotate_grant_token("a reset at the PC");
            }
            self.try_stage_reset(now_ms)
        });
        match &result {
            Ok(staged) => tracing::debug!(change = %staged.what, "viewer keys: reset staged"),
            Err(e) => tracing::debug!(reason = e.as_str(), "viewer keys: reset refused ({e})"),
        }
        let result = self.launch(result);
        if let Ok(staged) = &result {
            // A healthy reset denies every key it removes at once (a damaged store had none).
            self.removing(&staged.outcome);
        }
        result
    }

    fn try_stage_reset(&self, now_ms: i64) -> Result<Staged<Vec<KeyId>>, StoreError> {
        match &self.state {
            State::Ready(list) => {
                let mut next = list.clone();
                let removed: Vec<KeyId> = list.keys.iter().map(|r| r.key_id().clone()).collect();
                next.tombstones.extend(
                    std::mem::take(&mut next.keys)
                        .iter()
                        .map(|r| r.tombstone(Origin::Pc, now_ms)),
                );
                let what = format!(
                    "reset at the PC: {} active key(s) removed; tombstones, spent ids, snapshot \
                     and mode kept",
                    removed.len()
                );
                self.staged(next, what, removed)
            }
            State::Damaged(d) if d.kind == DamageKind::Unreadable => Err(StoreError::Unreadable),
            // A newer build wrote it: upgrade, do not wipe it.
            State::Damaged(d) if d.kind == DamageKind::NewerVersion => {
                Err(StoreError::NewerVersion)
            }
            State::Damaged(d) => {
                let strict = self.damaged_mode.unwrap_or(true);
                Ok(self.change(
                    Plan::ResetDamaged {
                        now_ms,
                        expect: self.damaged_expect("reset")?,
                        strict,
                    },
                    format!(
                        "a damaged store ({}) reset at the PC; trusted devices mode kept {} (mode file: {})",
                        d.kind.as_str(),
                        if strict { "on" } else { "off" },
                        describe_damaged_mode(self.damaged_mode)
                    ),
                    Vec::new(),
                ))
            }
        }
    }

    /// [`Self::stage_reset_to_empty`], written and installed at once (blocking).
    pub fn reset_to_empty(&mut self, now_ms: i64) -> Result<Vec<KeyId>, StoreError> {
        let staged = self.stage_reset_to_empty(now_ms)?;
        self.apply(staged)
    }

    /// At the PC, on a damaged store whose content is broken: stage taking the backup, if it
    /// passes every check, as the list; the write first keeps the damaged primary as
    /// `viewer_keys.json.damaged-<now_ms>`. Refused on a store that is not damaged (that would
    /// roll back the last change), on an unreadable one (that may pass: [`TrustStore::reopen`])
    /// and on a newer version's file (a newer build wrote it; an older backup is not put over it).
    /// After its install every key of [`Self::keys`] is one that joined (a damaged store had
    /// none active): the admission journals them as such. The switch is not the backup's: the
    /// damaged store's effective one ([`Self::damaged_mode`], strict when the mode file says
    /// nothing) is kept, in the list and the mode file — the window promises it stays as it is.
    pub fn stage_restore_from_backup(&mut self, now_ms: i64) -> Result<Staged<()>, StoreError> {
        let result = self
            .idle("restore")
            .and_then(|()| self.try_stage_restore(now_ms));
        match &result {
            Ok(staged) => tracing::debug!(change = %staged.what, "viewer keys: restore staged"),
            Err(e) => tracing::debug!(reason = e.as_str(), "viewer keys: restore refused ({e})"),
        }
        self.launch(result)
    }

    fn try_stage_restore(&self, now_ms: i64) -> Result<Staged<()>, StoreError> {
        match &self.state {
            State::Ready(_) => Err(StoreError::NotDamaged),
            State::Damaged(d) if d.kind == DamageKind::Unreadable => Err(StoreError::Unreadable),
            State::Damaged(d) if d.kind == DamageKind::NewerVersion => {
                Err(StoreError::NewerVersion)
            }
            State::Damaged(d) => {
                let strict = self.damaged_mode.unwrap_or(true);
                Ok(self.change(
                    Plan::Restore {
                        now_ms,
                        expect: self.damaged_expect("restore")?,
                        strict,
                    },
                    format!(
                        "restored from the backup at the PC over a damaged file ({}); trusted devices mode kept {} (mode file: {})",
                        d.kind.as_str(),
                        if strict { "on" } else { "off" },
                        describe_damaged_mode(self.damaged_mode)
                    ),
                    (),
                ))
            }
        }
    }

    /// [`Self::stage_restore_from_backup`], written and installed at once (blocking), with what
    /// it changed: every key of the restored list joined (a damaged store had none active).
    pub fn restore_from_backup(&mut self, now_ms: i64) -> Result<Reloaded, StoreError> {
        let before = self.active_view().unwrap_or_default();
        let staged = self.stage_restore_from_backup(now_ms)?;
        self.apply(staged)?;
        let reloaded = Reloaded::between(&before, self.active_view().as_ref());
        tracing::info!(
            joined = %short_list(&reloaded.joined_active),
            "viewer keys: restored from the backup"
        );
        Ok(reloaded)
    }

    /// The damaged primary a repair may write over: what this store loaded. Not known (the load
    /// could not read it): [`StoreError::Unreadable`] — reopen first.
    fn damaged_expect(&self, what: &str) -> Result<Option<Bytes>, StoreError> {
        match &self.damaged_raw {
            Some(raw) => Ok(raw.clone()),
            None => {
                tracing::debug!(
                    repair = what,
                    "viewer keys: repair refused: the damaged primary's bytes are not known \
                     (reopen first)"
                );
                Err(StoreError::Unreadable)
            }
        }
    }

    fn ready(&self) -> Result<&TrustList, StoreError> {
        match &self.state {
            State::Ready(list) => Ok(list),
            State::Damaged(_) => Err(StoreError::Damaged),
        }
    }

    // --- Queries for the PC's window (read-only, no I/O) ------------------------------------

    /// For every active key, how many **other** active keys «Удалить» on it would take with it
    /// ([`Self::deny_tree_now`], §10.1): the active keys its walk reaches through
    /// `endorse.by`, `grant.by`, `invite.by`, recoveries' `parents` and on to the records a
    /// recovery replaced, through removed keys too. One pass builds the walk's edges; then one
    /// walk per active key — O(active × list), a few
    /// thousand steps for a full list of 256 keys over 8448 tombstones in the worst case.
    pub fn dependents(&self) -> Result<HashMap<KeyId, usize>, StoreError> {
        let list = self.ready()?;
        let index = list.walk_index();
        let active: HashSet<&KeyId> = list.keys.iter().map(KeyRecord::key_id).collect();
        let mut out = HashMap::with_capacity(list.keys.len());
        for root in &list.keys {
            let root = root.key_id();
            let count = index
                .walk(root)
                .into_iter()
                .filter(|id| *id != root && active.contains(*id))
                .count();
            out.insert(root.clone(), count);
        }
        Ok(out)
    }

    /// The key that signed `key_id`'s way in — `endorse.by`, or `grant.by` (the owner's key) — and
    /// its record with its verdict while it is still in the list (`None` once removed). `Ok(None)`
    /// for a key with no signer (`pair`, `first_use`, `recover`) and for a key that is not listed.
    pub fn signed_by(
        &self,
        key_id: &KeyId,
    ) -> Result<Option<(&KeyId, Option<Listed<'_>>)>, StoreError> {
        let list = self.ready()?;
        let Some(record) = list.active(key_id) else {
            return Ok(None);
        };
        let by = match &record.source {
            KeySource::Endorse { by, .. } | KeySource::Grant { by, .. } => by,
            KeySource::Pair | KeySource::Recover { .. } | KeySource::FirstUse => return Ok(None),
        };
        Ok(Some((by, self.listed(by))))
    }

    /// The people of the `first_use` snapshot (§9) who never had a key here — none active and none
    /// removed: «ещё не подключались с ключом» (§10.1). Empty before the snapshot is taken.
    pub fn snapshot_people_without_keys(&self) -> Result<Vec<i64>, StoreError> {
        let list = self.ready()?;
        let Some(snapshot) = &list.snapshot else {
            return Ok(Vec::new());
        };
        Ok(snapshot
            .people
            .iter()
            .map(|p| p.person.telegram_user_id)
            .filter(|&uid| {
                list.keys_of(uid).next().is_none()
                    && !list.tombstones.iter().any(|t| t.telegram_user_id == uid)
            })
            .collect())
    }

    // --- §10 removed people, §10.2 attempts: the notes ----------------------------------------
    //
    // Memory decides (spec §10.1 «Нажатие решает сразу»): each note changes the list in memory at
    // once, no I/O, even while a change is in flight or the store needs a reopen; every write
    // carries the notes as they are then. [`Self::stage_flush`] writes them on their own.

    fn notes(&self) -> Option<&Notes> {
        match &self.state {
            State::Ready(list) => Some(&list.notes),
            State::Damaged(_) => None,
        }
    }

    fn notes_mut(&mut self) -> Option<&mut Notes> {
        match &mut self.state {
            State::Ready(list) => Some(&mut list.notes),
            State::Damaged(_) => None,
        }
    }

    /// The PC's current grant token (§7 «Токен выдачи»), as memory has it: what a grant must
    /// carry. `None` while the list is damaged.
    pub fn grant_token(&self) -> Option<GrantToken> {
        self.notes().map(|n| n.grant_token)
    }

    /// The grant token as the file holds it (written or read): the only one the server may hear
    /// (spec §7: after the write landed). `None` while the list is damaged.
    pub fn saved_grant_token(&self) -> Option<GrantToken> {
        self.notes().map(|_| self.saved_notes.grant_token)
    }

    /// §7 «Токен выдачи»: a grant passes only with the PC's current token, byte for byte (`""` only
    /// equals `""`) — memory's, so a token replaced and not yet written already refuses the old
    /// one. Refused [`StoreError::GrantStale`]; a damaged list [`StoreError::Damaged`].
    pub fn grant_token_current(&self, token: &GrantToken) -> Result<(), StoreError> {
        let current = self.grant_token().ok_or(StoreError::Damaged)?;
        if current == *token {
            Ok(())
        } else {
            Err(StoreError::GrantStale)
        }
    }

    /// **The one rotation of the grant token** (§7 «Токен выдачи», «Смена»), at a person's removal
    /// the PC learned of (`why`): their guest keys leave, they leave the stored binding list
    /// ([`Self::person_removed`]), and at every removal press at the PC — «Удалить» of one key
    /// ([`Self::deny_tree_now`]) as well as a person's. Fresh random bytes in memory,
    /// written with the removal's own snapshot — unless memory's token is already not the one
    /// written: that one was never sent (the server hears only a written token), so every grant
    /// is signed over an older one and this removal is covered. So one decision, or a rule run that
    /// takes several people, replaces it once, and a retried write carries the same one. Nothing
    /// while the list is damaged (a repair replaces it). Whether a new token stands unsaved now.
    fn rotate_grant_token(&mut self, why: &str) -> bool {
        let saved = self.saved_notes.grant_token;
        let Some(n) = self.notes_mut() else {
            tracing::debug!(
                why,
                "viewer keys: the grant token not replaced: the list is damaged (a repair replaces \
                 it)"
            );
            return false;
        };
        if n.grant_token != saved {
            tracing::debug!(
                why,
                "viewer keys: the grant token was already replaced and not yet written (never \
                 sent): this removal is covered by it"
            );
            return true;
        }
        n.new_grant_token(why);
        true
    }

    /// The grant token is not the one written yet (a removal's write has not landed).
    pub fn grant_token_unsaved(&self) -> bool {
        self.notes()
            .is_some_and(|n| n.grant_token != self.saved_notes.grant_token)
    }

    /// The stored last binding list (§10 «ПК знает человека», by user id). `None`: none stored
    /// (a first run, an older file, a reset), or the list is damaged.
    pub fn last_bindings(&self) -> Option<&[KnownBinding]> {
        self.notes().and_then(|n| n.last_bindings.as_deref())
    }

    /// `bindings` (the server's list as it stands now) is the stored last binding list, in memory
    /// at once; the next write carries it (the binding list's rule writes it,
    /// [`Self::bring_to_rule`]). Sorted by user id; ids the file cannot hold are left out; more
    /// than [`LAST_BINDINGS_MAX`] keep the people with keys here first (only they lose something
    /// when an unbind goes unseen). `false` when nothing changed, and while the list is damaged:
    /// nothing is remembered then (§10 «Повреждённый список»).
    ///
    /// One pass, bounded — a relay's list of any length costs O(n), never more than the bound is
    /// held: the people with keys (at most the key count), then the first others up to the
    /// bound. The caller's list is a map (one entry per person); the set dedupe is for any other
    /// caller and costs nothing more.
    pub fn note_last_bindings(&mut self, bindings: impl IntoIterator<Item = KnownBinding>) -> bool {
        if self.is_damaged() {
            tracing::debug!(
                "viewer keys: the stored last binding list not changed: the list is damaged \
                 (nothing is remembered until a repair)"
            );
            return false;
        }
        let keyed = self.keyed_people();
        let mut with_keys: Vec<KnownBinding> = Vec::new();
        let mut rest: Vec<KnownBinding> = Vec::new();
        let mut seen: HashSet<i64> = HashSet::new();
        // Everyone the list names, held or left out for the bound: leaving the stored list is a
        // removal only when the server's list does not name them now.
        let mut named: HashSet<i64> = HashSet::new();
        let (mut total, mut out_of_range, mut repeated, mut left_out) =
            (0usize, 0usize, 0usize, 0usize);
        for b in bindings {
            total += 1;
            let uid = b.telegram_user_id;
            if !user_id_ok(uid) {
                out_of_range += 1;
                continue;
            }
            named.insert(uid);
            let has_key = keyed.contains(&uid);
            if !has_key && rest.len() >= LAST_BINDINGS_MAX {
                // Not held: whether it repeats does not matter, it is left out either way.
                left_out += 1;
                continue;
            }
            if !seen.insert(uid) {
                repeated += 1;
                continue;
            }
            if has_key {
                with_keys.push(b);
            } else {
                rest.push(b);
            }
        }
        let mut list = with_keys;
        let room = LAST_BINDINGS_MAX.saturating_sub(list.len());
        left_out += rest.len().saturating_sub(room);
        rest.truncate(room);
        list.extend(rest);
        if left_out > 0 {
            tracing::warn!(
                bindings = total,
                kept = list.len(),
                left_out,
                max = LAST_BINDINGS_MAX,
                "viewer keys: more bindings than the last known list keeps: the people with keys \
                 first, the rest left out (an unbind of theirs while away is not seen)"
            );
        }
        list.sort_by_key(|b| b.telegram_user_id);
        // §7 «Токен выдачи»: a person leaving the stored list is a removal the PC learned of —
        // a keyless former owner too (the owner's own `binding_removed` keeps the record: no rule
        // runs at that message) — unless they hold a working owner-role key here (never removed by
        // the server's word).
        let working_owners: HashSet<i64> = self.ready().map_or_else(
            |_| HashSet::new(),
            |l| {
                l.keys
                    .iter()
                    .filter(|r| r.role == BindingRole::Owner && self.works(r))
                    .map(|r| r.person.telegram_user_id)
                    .collect()
            },
        );
        let left: Vec<i64> = self.last_bindings().map_or_else(Vec::new, |was| {
            was.iter()
                .map(|b| b.telegram_user_id)
                .filter(|uid| !named.contains(uid) && !working_owners.contains(uid))
                .collect()
        });
        let Some(n) = self.notes_mut() else {
            return false;
        };
        if n.last_bindings.as_ref() == Some(&list) {
            return false;
        }
        tracing::debug!(
            bindings = list.len(),
            was = n.last_bindings.as_ref().map(Vec::len),
            left = left.len(),
            out_of_range,
            repeated,
            "viewer keys: the last known binding list noted (the next write carries it)"
        );
        n.last_bindings = Some(list);
        for uid in left {
            self.person_removed(uid, "a person left the stored binding list");
        }
        true
    }

    /// Memory's notes are not yet in the file.
    pub fn notes_unsaved(&self) -> bool {
        self.notes().is_some_and(|n| *n != self.saved_notes)
    }

    /// Whether the PC knows the person (§10): bound (`bound`, the caller's bindings), or with
    /// keys, removed keys or attempts that still count.
    pub fn knows_person(&self, telegram_user_id: i64, bound: bool) -> bool {
        if bound {
            return true;
        }
        let Ok(list) = self.ready() else {
            return false;
        };
        list.keys
            .iter()
            .any(|k| k.person.telegram_user_id == telegram_user_id)
            || list
                .tombstones
                .iter()
                .any(|t| t.telegram_user_id == telegram_user_id)
            || self
                .live_attempts()
                .any(|a| a.telegram_user_id == telegram_user_id)
    }

    /// **The one step of a person's removal** (§10 «Удалённый человек»), whichever path took them
    /// — at the PC (every key, origin `pc`) or on the server's word (their guest-role keys, or
    /// their leaving the stored last binding list): the grant token is replaced
    /// ([`Self::rotate_grant_token`], once until written) and the person's attempts go. In memory
    /// at once; the next write carries it (one snapshot with the keys). Refused while the list is
    /// damaged (`false`: nothing is remembered then, §10 «Повреждённый список»).
    pub fn person_removed(&mut self, telegram_user_id: i64, why: &str) -> bool {
        let Some(n) = self.notes_mut() else {
            tracing::debug!(
                user_id = telegram_user_id,
                why,
                "viewer keys: a person's removal not noted: the list is damaged (nothing is \
                 remembered until a repair)"
            );
            return false;
        };
        let before = n.attempts.len();
        n.attempts
            .retain(|a| a.telegram_user_id != telegram_user_id);
        let attempts_dropped = before - n.attempts.len();
        tracing::info!(
            user_id = telegram_user_id,
            why,
            attempts_dropped,
            "viewer keys: a person removed: their attempts go, the grant token is replaced"
        );
        self.rotate_grant_token(why);
        true
    }

    // --- §10 «Сверка со списком сервера: одно правило» ----------------------------------------

    /// **The one rule** (§10 «Сверка со списком сервера: одно правило»; the only place that infers
    /// «the list does not name them, so they were removed»): a person the PC knows — listed keys,
    /// removed keys, attempts that still count, or the stored last binding list — whom `named`
    /// (the current list of a live connection: `agent_ready.bindings` and the binding messages
    /// since) does not name, and who holds no working owner-role key, keeps no undecided
    /// guest-role key. The holder of a working owner-role key is not touched at all (their keys,
    /// guest-role too, their attempts and the grant token stay).
    ///
    /// In memory, at `now_ms` (the PC's wall clock): each such person's undecided guest-role keys
    /// are denied and carried (origin `server`), then the one shared step of a removal
    /// ([`Self::person_removed`]); the stored last binding list becomes `named`, and each person
    /// who leaves it is removed the same way ([`Self::note_last_bindings`]). The next write staged
    /// carries all of it (a snapshot: one write). Skipped: a person with a listed key written less
    /// than [`UNBOUND_KEY_GRACE_MS`] before `now_ms` (`due_at` says when to run again). No clock
    /// decides the order, so a second run changes nothing.
    ///
    /// The per-person lookups (keys, attempts) are built once per run: O(keys + removed keys +
    /// attempts + the stored list), then each person costs their own keys.
    ///
    /// Refused, changing nothing: a damaged list ([`StoreError::Damaged`]), memory maybe behind
    /// the disk ([`StoreError::NeedsReopen`]).
    pub fn bring_to_rule(
        &mut self,
        named: &BTreeMap<i64, BindingRole>,
        now_ms: i64,
    ) -> Result<RuleRun, StoreError> {
        if self.needs_reopen {
            tracing::debug!(
                named = named.len(),
                "viewer keys: the binding list's rule not run: memory may be behind the disk (a \
                 reopen first)"
            );
            return Err(StoreError::NeedsReopen);
        }
        let list = match self.ready() {
            Ok(list) => list,
            Err(e) => {
                tracing::debug!(
                    named = named.len(),
                    "viewer keys: the binding list's rule not run: the list is damaged (nothing \
                     changes until a repair)"
                );
                return Err(e);
            }
        };
        let token_before = list.notes.grant_token;
        let mut keys_of: HashMap<i64, Vec<&KeyRecord>> = HashMap::new();
        for r in &list.keys {
            keys_of
                .entry(r.person.telegram_user_id)
                .or_default()
                .push(r);
        }
        let attempting: HashSet<i64> = self
            .live_attempts_at(now_ms)
            .map(|a| a.telegram_user_id)
            .collect();
        let mut known: BTreeSet<i64> = keys_of
            .keys()
            .copied()
            .chain(list.tombstones.iter().map(|t| t.telegram_user_id))
            .chain(attempting.iter().copied())
            .collect();
        let stored = list.notes.last_bindings.as_ref().map_or(0, Vec::len);
        let in_stored: HashSet<i64> = list
            .notes
            .last_bindings
            .iter()
            .flatten()
            .map(|b| b.telegram_user_id)
            .collect();
        known.extend(
            list.notes
                .last_bindings
                .iter()
                .flatten()
                .map(|b| b.telegram_user_id),
        );
        // (person, undecided guest keys)
        let mut takes: Vec<(i64, Vec<KeyId>)> = Vec::new();
        let (mut unnamed, mut graced, mut in_order) = (0usize, 0usize, 0usize);
        let mut due_at: Option<i64> = None;
        for uid in known {
            if named.contains_key(&uid) {
                continue;
            }
            unnamed += 1;
            let keys = keys_of.get(&uid).map_or(&[][..], Vec::as_slice);
            let grace_end = keys
                .iter()
                .filter(|r| r.added_at <= now_ms && now_ms - r.added_at < UNBOUND_KEY_GRACE_MS)
                .map(|r| r.added_at + UNBOUND_KEY_GRACE_MS)
                .min();
            if let Some(end) = grace_end {
                graced += 1;
                due_at = Some(due_at.map_or(end, |d| d.min(end)));
                tracing::debug!(
                    user_id = uid,
                    grace_ends_at = end,
                    "viewer keys: the rule: not named, but a key of theirs is younger than the \
                     grace: skipped for now (their binding may be on its way)"
                );
                continue;
            }
            let working_owner = keys
                .iter()
                .any(|r| r.role == BindingRole::Owner && self.works(r));
            let guests: Vec<KeyId> = keys
                .iter()
                .filter(|r| r.role == BindingRole::Guest && !self.removal_pending(r))
                .map(|r| r.key_id().clone())
                .collect();
            // §10: the holder of a working owner-role key is not touched at all — their keys
            // (guest-role too), attempts and the grant token stay. A person with no undecided
            // guest key who is not in the stored list is in order (removed once already).
            if working_owner || (guests.is_empty() && !in_stored.contains(&uid)) {
                in_order += 1;
                continue;
            }
            takes.push((uid, guests));
        }
        let mut run = RuleRun {
            due_at,
            ..RuleRun::default()
        };
        for (uid, guests) in takes {
            // Their leaving the stored list is the same removal ([`Self::note_last_bindings`]).
            if !guests.is_empty() {
                self.deny_now(&guests);
                self.carry_removal(&guests, Removal::Server, now_ms);
                self.person_removed(uid, "the rule: a removed person's guest keys leave");
            }
            tracing::info!(
                user_id = uid,
                guest_keys = guests.len(),
                kids = %short_list(&guests),
                at = now_ms,
                "viewer keys: the rule: not named by the current binding list: their guest-role \
                 keys leave (origin server), they leave the stored list; their sessions end"
            );
            run.ended.push(uid);
            run.denied.extend(guests);
        }
        run.list_noted = self.note_last_bindings(named.iter().map(|(uid, role)| KnownBinding {
            telegram_user_id: *uid,
            role: *role,
        }));
        run.rotated = self.grant_token() != Some(token_before);
        tracing::debug!(
            named = named.len(),
            stored,
            unnamed,
            graced,
            in_order,
            taken = run.ended.len(),
            denied = run.denied.len(),
            rotated = run.rotated,
            list_noted = run.list_noted,
            due_at = ?run.due_at,
            "viewer keys: the binding list's rule run (in memory; the next write carries it)"
        );
        Ok(run)
    }

    /// The PC's wall clock (unix ms) the attempts' age is read against (§10.2); a test's when
    /// set ([`Self::set_wall_now`]).
    pub fn wall_now(&self) -> i64 {
        #[cfg(test)]
        if let Some(t) = self.test_wall {
            return t;
        }
        crate::journal::now_ms()
    }

    /// A test's wall clock from now on (the vectors' `pc_clock_at_0_ms` + `at_ms`).
    #[cfg(test)]
    pub(crate) fn set_wall_now(&mut self, at: i64) {
        self.test_wall = Some(at);
    }

    /// §10.2: the attempts that still count by the PC's wall clock ([`attempt_counts`]) —
    /// the one place every reader goes through (the window, «Подтвердить»'s and «Разрешить»'s
    /// second steps, «Забыть удаления», who the PC knows). An older one counts for nothing even
    /// before a note drops it ([`Self::prune_attempts`]).
    fn live_attempts(&self) -> impl Iterator<Item = &Attempt> {
        self.live_attempts_at(self.wall_now())
    }

    /// [`Self::live_attempts`] at one reading of the PC's wall clock (`now_ms`).
    fn live_attempts_at(&self, now_ms: i64) -> impl Iterator<Item = &Attempt> {
        self.notes()
            .into_iter()
            .flat_map(|n| n.attempts.iter())
            .filter(move |a| attempt_counts(a, now_ms))
    }

    /// The attempts that still count (§10.2: the last try at most 30 days before the PC's
    /// clock), as memory has them.
    pub fn attempts(&self) -> Vec<&Attempt> {
        self.live_attempts().collect()
    }

    /// [`Self::attempts`] at one reading of the PC's wall clock (`now_ms`), for a reader
    /// that decides more than once by it (the window's view and its age-out deadline).
    pub fn attempts_at(&self, now_ms: i64) -> Vec<&Attempt> {
        self.live_attempts_at(now_ms).collect()
    }

    /// The PC's wall time (unix ms) after which the earliest attempt that counts at
    /// `now_ms` stops counting ([`attempt_counts`]: its last try plus [`ATTEMPT_KEEP_MS`]) — when
    /// a view that shows it is out of date. `None` with no attempt that counts. `now_ms`
    /// is the reading the view was built at, so the deadline is the shown attempts'.
    pub fn attempts_age_out_at(&self, now_ms: i64) -> Option<i64> {
        self.live_attempts_at(now_ms)
            .map(|a| a.last_at.saturating_add(ATTEMPT_KEEP_MS))
            .min()
    }

    /// How long ago (ms, by the PC's clock) the person's attempt with this key was last tried,
    /// when memory still has it but it does not count now (§10.2: older than 30 days) — «Разрешить»
    /// on it is refused `expired`, not `not_found`.
    pub fn expired_attempt_age(&self, telegram_user_id: i64, key_id: &KeyId) -> Option<i64> {
        let now = self.wall_now();
        self.notes()?
            .attempts
            .iter()
            .find(|a| a.telegram_user_id == telegram_user_id && a.key_id() == key_id)
            .filter(|a| !attempt_counts(a, now))
            .map(|a| now.saturating_sub(a.last_at))
    }

    /// Drop the attempts whose last try is more than 30 days before `now_ms` (§10.2); readers
    /// never see them anyway ([`Self::attempts`]). How many went.
    pub fn prune_attempts(&mut self, now_ms: i64) -> usize {
        let Some(n) = self.notes_mut() else {
            return 0;
        };
        let before = n.attempts.len();
        n.attempts.retain(|a| attempt_counts(a, now_ms));
        let gone = before - n.attempts.len();
        if gone > 0 {
            tracing::debug!(gone, "viewer keys: attempts older than 30 days dropped");
        }
        gone
    }

    /// [`Self::note_attempt_how`]: whether it is a new entry.
    pub fn note_attempt(&mut self, draft: Attempt, now_ms: i64) -> bool {
        self.note_attempt_how(draft, now_ms) == AttemptNoted::New
    }

    /// Note another device's attempt (§10.2), in memory; the caller checked the rest (a verified
    /// offer, a refusal that counts, a bound person). A key in the list or among the removed is
    /// no attempt. One per (person, key) — a repeat counts and moves the last time; at most
    /// [`ATTEMPTS_PER_PERSON`] per person (that person's oldest last try goes first) and
    /// [`ATTEMPTS_MAX`] in all ([`evict_attempts`]: the oldest last try goes, whoever it is).
    pub fn note_attempt_how(&mut self, draft: Attempt, now_ms: i64) -> AttemptNoted {
        let kid = draft.key_id().clone();
        let uid = draft.telegram_user_id;
        // An attempt the file's parser refuses would make every later write fail its own
        // check; never taken.
        if !user_id_ok(uid) || now_ms < 0 {
            tracing::debug!(
                kid = %kid.short(),
                user_id = uid,
                now_ms,
                "viewer keys: an attempt out of range ignored (the file could not hold it)"
            );
            return AttemptNoted::Ignored;
        }
        self.prune_attempts(now_ms);
        if self
            .ready()
            .is_ok_and(|l| l.active(&kid).is_some() || l.tombstone(&kid).is_some())
        {
            tracing::debug!(
                kid = %kid.short(),
                user_id = uid,
                "viewer keys: a key in the list or removed is no attempt"
            );
            return AttemptNoted::Ignored;
        }
        let Some(n) = self.notes_mut() else {
            tracing::debug!(
                kid = %kid.short(),
                user_id = uid,
                "viewer keys: no list to note an attempt on"
            );
            return AttemptNoted::Ignored;
        };
        if let Some(a) = n
            .attempts
            .iter_mut()
            .find(|a| a.telegram_user_id == uid && a.key_id() == &kid)
        {
            // Never before its first try (the parser refuses that): a wall clock set back
            // across a restart.
            if now_ms < a.first_at {
                tracing::debug!(
                    user_id = uid,
                    first_at = a.first_at,
                    now_ms,
                    "viewer keys: attempt repeated before its first try by the clock: last try \
                     kept at the first"
                );
            }
            a.last_at = now_ms.max(a.first_at);
            a.count = a.count.saturating_add(1);
            a.role = draft.role;
            tracing::debug!(
                kid = %kid.short(),
                user_id = uid,
                count = a.count,
                "viewer keys: attempt repeated"
            );
            return AttemptNoted::Repeated;
        }
        n.attempts.push(Attempt {
            first_at: now_ms,
            last_at: now_ms,
            count: 1,
            ..draft
        });
        let recorded = evict_attempts(&mut n.attempts, Some((uid, &kid)));
        tracing::debug!(
            kid = %kid.short(),
            user_id = uid,
            recorded,
            total = n.attempts.len(),
            "viewer keys: attempt noted"
        );
        if recorded {
            AttemptNoted::New
        } else {
            AttemptNoted::NotRecorded
        }
    }

    /// The person's attempt with this key.
    pub fn attempt(&self, telegram_user_id: i64, key_id: &KeyId) -> Option<&Attempt> {
        self.live_attempts()
            .find(|a| a.telegram_user_id == telegram_user_id && a.key_id() == key_id)
    }

    /// «Скрыть» (§10.2), or the attempt answered: dropped. Whether there was one.
    pub fn drop_attempt(&mut self, telegram_user_id: i64, key_id: &KeyId) -> bool {
        let Some(n) = self.notes_mut() else {
            return false;
        };
        let before = n.attempts.len();
        n.attempts
            .retain(|a| !(a.telegram_user_id == telegram_user_id && a.key_id() == key_id));
        let dropped = n.attempts.len() != before;
        tracing::debug!(
            kid = %key_id.short(),
            user_id = telegram_user_id,
            dropped,
            "viewer keys: attempt dropped"
        );
        dropped
    }

    /// Stage a write of memory alone when the file lacks some of it — the notes, or a removal
    /// decided and carried ([`Self::carry_removal`]) that no write took yet — (`Ok(None)`: nothing to write). The binding list's rule's write
    /// is this one ([`Self::bring_to_rule`]: its stored list, notes and guest keys' tombstones
    /// together). Refused like any change while another is in flight: memory goes with that one's
    /// next successor (each write carries it).
    pub fn stage_flush(&mut self) -> Result<Option<Staged<()>>, StoreError> {
        let carried = self.carried_now().len();
        if !self.notes_unsaved() && carried == 0 {
            return Ok(None);
        }
        tracing::debug!(
            notes_unsaved = self.notes_unsaved(),
            carried,
            "viewer keys: a write of memory alone staged (what the file lacks)"
        );
        let result = self.idle("notes").and_then(|()| {
            let next = self.ready()?.clone();
            self.staged(next, "notes".into(), ()).map(Some)
        });
        self.launch_some(result)
    }

    /// [`Self::stage_flush`], written and installed at once (blocking).
    pub fn flush(&mut self) -> Result<bool, StoreError> {
        match self.stage_flush()? {
            Some(staged) => self.apply(staged).map(|()| true),
            None => Ok(false),
        }
    }

    /// The list-wide limit a new key would hit now (spec §10: «список полон, удалите старые»), the
    /// first of active keys, tombstones (the ordinary limit, [`MAX_TOMBSTONES`]) and spent ids;
    /// `None` while there is room. The per-person limit is not the whole list's.
    pub fn full(&self) -> Result<Option<Limit>, StoreError> {
        let list = self.ready()?;
        Ok(if list.keys.len() >= MAX_ACTIVE_KEYS {
            Some(Limit::Active)
        } else if list.tombstones.len() >= MAX_TOMBSTONES {
            Some(Limit::Tombstones)
        } else if list.spent_count() >= MAX_SPENT {
            Some(Limit::Spent)
        } else {
            None
        })
    }

    /// Whether the backup at `paths` would be taken by [`Self::stage_restore_from_backup`]: it
    /// exists, is readable and of this version, and passes every check of a load. Blocking file
    /// I/O (`spawn_blocking` on the async runtime); no lock.
    pub fn backup_restorable(paths: &StorePaths) -> bool {
        match read_list(&paths.backup) {
            Ok(Some(_)) => {
                tracing::debug!("viewer keys: the backup passes every check (restorable)");
                true
            }
            Ok(None) => {
                tracing::debug!("viewer keys: no backup (nothing to restore)");
                false
            }
            Err(damage) => {
                tracing::debug!(damage = %damage, "viewer keys: the backup is not restorable");
                false
            }
        }
    }
}

/// The index of an active key, or why it is not one.
fn active_index(list: &TrustList, key_id: &KeyId) -> Result<usize, StoreError> {
    list.find(key_id)
        .ok_or_else(|| match list.tombstone(key_id) {
            Some(t) => StoreError::Removed {
                key_id: key_id.clone(),
                origin: t.origin.as_str(),
            },
            None => StoreError::NotFound(key_id.clone()),
        })
}

/// Whether two optional file contents are the same (both absent, or equal bytes).
fn same_bytes(a: Option<&Bytes>, b: Option<&Bytes>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b) || a.as_slice() == b.as_slice(),
        _ => false,
    }
}

/// `key_id`s for a log line or a change's text: their short forms, comma-separated.
fn short_list(ids: &[KeyId]) -> String {
    ids.iter().map(KeyId::short).collect::<Vec<_>>().join(",")
}

/// The removal a carried origin is written as (a carry is `pc` or `server`).
fn removal_of(origin: &Origin) -> Removal {
    match origin {
        Origin::Server => Removal::Server,
        Origin::Pc | Origin::Replaced { .. } => Removal::Pc,
    }
}

/// The check of a new key's card that needs no list: `rpk` is not the key itself. (`kind` and
/// `platform` are well-formed by their types.)
fn check_new_key(key: &ViewerKey, rpk: Option<&ViewerKey>) -> Result<(), StoreError> {
    if rpk == Some(key) {
        return Err(StoreError::Invalid(
            "the recovery key is the device key itself".into(),
        ));
    }
    Ok(())
}

fn stored_last_used(list: &TrustList) -> HashMap<KeyId, i64> {
    list.keys
        .iter()
        .filter_map(|r| r.last_used_at.map(|t| (r.key_id().clone(), t)))
        .collect()
}

fn user_id_ok(uid: i64) -> bool {
    (1..=MAX_USER_ID).contains(&uid)
}

/// A display name as kept: cleaned ([`clean_name`]), trimmed, at most [`NAME_MAX_CHARS`]
/// characters; `None` when nothing is left.
fn kept_name(raw: &str) -> Option<String> {
    let cut: String = clean_name(raw)
        .trim()
        .chars()
        .take(NAME_MAX_CHARS)
        .collect();
    let cut = cut.trim_end();
    (!cut.is_empty()).then(|| cut.to_string())
}

/// A person as kept, or why not.
fn kept_person(p: Person) -> Result<Person, StoreError> {
    if !user_id_ok(p.telegram_user_id) {
        return Err(StoreError::Invalid(
            "telegram_user_id is not in 1..=2^53-1".into(),
        ));
    }
    Ok(Person {
        telegram_user_id: p.telegram_user_id,
        first_name: p.first_name.as_deref().and_then(kept_name),
        username: p.username.as_deref().and_then(kept_name),
    })
}

/// Whether a person read from the file is one [`kept_person`] could have written.
fn is_kept_person(p: &Person) -> bool {
    kept_person(p.clone()).is_ok_and(|k| k == *p)
}

// --- The file -----------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileV1 {
    version: u32,
    switches: SwitchState,
    keys: Vec<FileKey>,
    tombstones: Vec<FileTombstone>,
    spent: FileSpent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_use_snapshot: Option<FirstUseSnapshot>,
    /// The notes (spec §10, §10.2). §7 «Токен выдачи»: required — `""` or 22 characters; a file without it is not this format.
    grant_token: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attempts: Vec<FileAttempt>,
    /// The last binding list the PC knew (absent: none stored; `[]`: an empty list).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_bindings: Option<Vec<KnownBinding>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileAttempt {
    telegram_user_id: i64,
    role: BindingRole,
    /// Kept as a check, like a key's.
    key_id: KeyId,
    spki: String,
    kind: ClientKind,
    platform: Platform,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpk: Option<String>,
    first_at: i64,
    last_at: i64,
    count: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSpent {
    endorse_ids: Vec<GroundId>,
    grant_ids: Vec<GroundId>,
    invite_ids: Vec<GroundId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileKey {
    /// Kept as a check: recomputed from `spki` at load, a mismatch is damage (spec §1.3).
    key_id: KeyId,
    /// The SPKI, base64url without padding (as on the wire).
    spki: String,
    person: Person,
    role: BindingRole,
    kind: ClientKind,
    platform: Platform,
    /// The recovery key's SPKI, base64url without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rpk: Option<String>,
    source: KeySource,
    /// Required: a file without it is not this format.
    unconfirmed: bool,
    added_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used_at: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTombstone {
    /// Kept as a check, like a key's.
    key_id: KeyId,
    spki: String,
    telegram_user_id: i64,
    origin: Origin,
    /// The spec's `removed_at` (§10): required — a removed record without it does not parse, and
    /// the list is damaged (`key_list_damaged`).
    at: i64,
    source: KeySource,
}

/// Only the version, read before the rest so a newer file is told from a broken one.
#[derive(Deserialize)]
struct VersionOnly {
    version: Option<serde_json::Value>,
}

fn serialize(list: &TrustList) -> Result<Vec<u8>, StoreError> {
    let notes = &list.notes;
    let file = FileV1 {
        version: FORMAT_VERSION,
        switches: list.switches,
        keys: list
            .keys
            .iter()
            .map(|r| FileKey {
                key_id: r.key_id().clone(),
                spki: URL_SAFE_NO_PAD.encode(r.key.spki()),
                person: r.person.clone(),
                role: r.role,
                kind: r.kind.clone(),
                platform: r.platform.clone(),
                rpk: r.rpk.as_ref().map(|k| URL_SAFE_NO_PAD.encode(k.spki())),
                source: r.source.clone(),
                unconfirmed: r.unconfirmed,
                added_at: r.added_at,
                last_used_at: r.last_used_at,
            })
            .collect(),
        tombstones: list
            .tombstones
            .iter()
            .map(|t| FileTombstone {
                key_id: t.key_id().clone(),
                spki: URL_SAFE_NO_PAD.encode(t.key.spki()),
                telegram_user_id: t.telegram_user_id,
                origin: t.origin.clone(),
                at: t.at,
                source: t.source.clone(),
            })
            .collect(),
        spent: FileSpent {
            endorse_ids: list.spent_endorse.iter().cloned().collect(),
            grant_ids: list.spent_grant.iter().cloned().collect(),
            invite_ids: list.spent_invite.iter().cloned().collect(),
        },
        first_use_snapshot: list.snapshot.clone(),
        grant_token: notes.grant_token.to_wire(),
        attempts: notes
            .attempts
            .iter()
            .map(|a| FileAttempt {
                telegram_user_id: a.telegram_user_id,
                role: a.role,
                key_id: a.key_id().clone(),
                spki: URL_SAFE_NO_PAD.encode(a.key.spki()),
                kind: a.kind.clone(),
                platform: a.platform.clone(),
                rpk: a.rpk.as_ref().map(|k| URL_SAFE_NO_PAD.encode(k.spki())),
                first_at: a.first_at,
                last_at: a.last_at,
                count: a.count,
            })
            .collect(),
        last_bindings: notes.last_bindings.clone(),
    };
    serde_json::to_vec_pretty(&file).map_err(|e| StoreError::Invalid(format!("serialize: {e}")))
}

/// What a load gives: the list and its bytes (`Ok(None)` for a first run, `Err` for damage), and
/// the mode file as read beside it.
#[derive(Debug)]
struct Loaded {
    list: Result<Option<(TrustList, Vec<u8>)>, Damage>,
    side: Side,
    /// For a damaged list: the primary as read (`Some(None)`: there was none); `None` when it
    /// could not be read, or the list is healthy.
    raw: Option<Option<Vec<u8>>>,
}

/// The list ([`load_list`]) and the mode file (blocking).
fn load(primary: &Path, backup: &Path) -> Loaded {
    let (list, raw) = load_list(primary, backup);
    Loaded {
        list,
        side: read_mode(primary),
        raw,
    }
}

/// The list read: `Ok(Some(list, bytes))`, `Ok(None)` for a first run (neither file), or the
/// damage.
type ListRead = Result<Option<(TrustList, Vec<u8>)>, Damage>;

/// The primary and its bytes, `Ok(None)` for a first run (neither file), `Err` for a damaged
/// store — with the primary's raw bytes for a damaged one (`Some(None)`: none was there).
fn load_list(primary: &Path, backup: &Path) -> (ListRead, Option<Option<Vec<u8>>>) {
    let bytes = match read_bounded(primary) {
        Ok(b) => b,
        Err(e) => return (Err(Damage::new(DamageKind::Unreadable, e)), None),
    };
    match bytes {
        Some(bytes) => match parse_read(&bytes) {
            Ok(list) => (Ok(Some((list, bytes))), None),
            Err(damage) => (Err(damage), Some(Some(bytes))),
        },
        None => match backup.try_exists() {
            Ok(false) => (Ok(None), None),
            Ok(true) => (
                Err(Damage::new(
                    DamageKind::PrimaryMissing,
                    "the list is missing while its backup exists",
                )),
                Some(None),
            ),
            Err(e) => (
                Err(Damage::new(
                    DamageKind::Unreadable,
                    format!("the backup could not be looked for: {e}"),
                )),
                None,
            ),
        },
    }
}

/// `path`'s bytes, at most one more than [`MAX_FILE_BYTES`]; `Ok(None)` when it does not exist.
fn read_bounded(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("open: {e}")),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read: {e}"))?;
    Ok(Some(bytes))
}

/// `path` read and checked, with its bytes; `Ok(None)` when it does not exist.
fn read_list(path: &Path) -> Result<Option<(TrustList, Vec<u8>)>, Damage> {
    let Some(bytes) = read_bounded(path).map_err(|e| Damage::new(DamageKind::Unreadable, e))?
    else {
        return Ok(None);
    };
    let list = parse_read(&bytes)?;
    Ok(Some((list, bytes)))
}

/// A file's bytes as read ([`read_bounded`]) checked: its size, then its content.
fn parse_read(bytes: &[u8]) -> Result<TrustList, Damage> {
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(Damage::new(
            DamageKind::TooLarge,
            format!("more than {MAX_FILE_BYTES} bytes"),
        ));
    }
    parse_list(bytes)
}

/// A viewer key from the file's base64url SPKI and the `key_id` the file says it has: a mismatch
/// is damage (spec §1.3). Quietly (one summary line per load instead).
fn file_key(spki: &str, key_id: &KeyId, what: &str) -> Result<ViewerKey, Damage> {
    let key = spki_key(spki).map_err(|e| broken(format!("{what}: spki {e}")))?;
    if key.key_id() != key_id {
        return Err(broken(format!(
            "{what}: key_id {} is not its spki's",
            key_id.short()
        )));
    }
    Ok(key)
}

/// A viewer key from base64url SPKI.
fn spki_key(text: &str) -> Result<ViewerKey, String> {
    let spki = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| "not base64url".to_string())?;
    ViewerKey::from_spki_quiet(&spki).map_err(|e| format!("not a viewer key ({e})"))
}

fn broken(detail: String) -> Damage {
    Damage::new(DamageKind::Invariant, detail)
}

/// A source's shape beyond serde's: a recovery replaced 1 to 16 distinct keys, and inherits at
/// most as many distinct edges as the list can hold keys, none of them a key it replaced.
fn source_ok(source: &KeySource) -> bool {
    match source {
        KeySource::Recover { replaced, parents } => {
            (1..=MAX_KEYS_PER_PERSON).contains(&replaced.len())
                && replaced.iter().collect::<HashSet<_>>().len() == replaced.len()
                && parents.len() <= MAX_ACTIVE_KEYS + MAX_TOMBSTONES_AT_PC
                && parents.iter().collect::<HashSet<_>>().len() == parents.len()
                && !parents.iter().any(|p| replaced.contains(p))
        }
        _ => true,
    }
}

/// Whether the ground a record or a tombstone names is among the spent (spec §10: a list where
/// it is not is damaged).
fn ground_spent(
    source: &KeySource,
    endorse: &BTreeSet<GroundId>,
    grant: &BTreeSet<GroundId>,
    invite: &BTreeSet<GroundId>,
) -> bool {
    match source {
        KeySource::Endorse { endorse_id, .. } => endorse.contains(endorse_id),
        KeySource::Grant {
            grant_id, inv_id, ..
        } => grant.contains(grant_id) && inv_id.as_ref().is_none_or(|i| invite.contains(i)),
        _ => true,
    }
}

/// The notes of a file, checked: one entry per person and per (person, key), user ids in range,
/// times not before 1970, keys that parse, a grant token of its form; attempts bounded
/// ([`ATTEMPTS_MAX`], per person [`ATTEMPTS_PER_PERSON`]); [`MAX_FILE_BYTES`] bounds the file.
fn parse_notes(file: &FileV1) -> Result<Notes, Damage> {
    // Not `""` for a malformed one: that would bring old grants back.
    let grant_token = GrantToken::parse(&file.grant_token)
        .ok_or_else(|| broken("a grant token not of its form".into()))?;
    if file.attempts.len() > ATTEMPTS_MAX {
        return Err(broken(format!("{} attempts", file.attempts.len())));
    }
    // The last binding list, bounded, one entry per person, ids in range.
    if let Some(list) = &file.last_bindings {
        if list.len() > LAST_BINDINGS_MAX {
            return Err(broken(format!("{} last bindings", list.len())));
        }
        let mut bound = HashSet::with_capacity(list.len());
        for b in list {
            if !user_id_ok(b.telegram_user_id) {
                return Err(broken("a last binding out of range".into()));
            }
            if !bound.insert(b.telegram_user_id) {
                return Err(broken("a last binding appears twice".into()));
            }
        }
    }
    let mut attempts = Vec::with_capacity(file.attempts.len());
    let mut per_person: HashMap<i64, usize> = HashMap::new();
    let mut seen = HashSet::new();
    for (i, a) in file.attempts.iter().enumerate() {
        let key = file_key(&a.spki, &a.key_id, &format!("attempt {i}"))?;
        if !user_id_ok(a.telegram_user_id)
            || a.first_at < 0
            || a.last_at < a.first_at
            || a.count == 0
        {
            return Err(broken(format!("attempt {i}: out of range")));
        }
        if !seen.insert((a.telegram_user_id, a.key_id.clone())) {
            return Err(broken(format!("attempt {i}: appears twice")));
        }
        let n = per_person.entry(a.telegram_user_id).or_default();
        *n += 1;
        if *n > ATTEMPTS_PER_PERSON {
            return Err(broken(format!("attempt {i}: too many of one person")));
        }
        let rpk = match &a.rpk {
            None => None,
            Some(text) => {
                Some(spki_key(text).map_err(|e| broken(format!("attempt {i}: rpk {e}")))?)
            }
        };
        attempts.push(Attempt {
            telegram_user_id: a.telegram_user_id,
            role: a.role,
            key,
            kind: a.kind.clone(),
            platform: a.platform.clone(),
            rpk,
            first_at: a.first_at,
            last_at: a.last_at,
            count: a.count,
        });
    }
    Ok(Notes {
        grant_token,
        attempts,
        last_bindings: file.last_bindings.clone(),
    })
}

/// The file's bytes as a list, with every invariant checked.
fn parse_list(bytes: &[u8]) -> Result<TrustList, Damage> {
    let shape = |e: serde_json::Error| {
        // Where and what kind, not serde's message: that may quote a value (a name, a key_id).
        Damage::new(
            DamageKind::NotParsable,
            format!(
                "{:?} at line {} column {}",
                e.classify(),
                e.line(),
                e.column()
            ),
        )
    };
    let version: VersionOnly = serde_json::from_slice(bytes).map_err(shape)?;
    let version = version.version.as_ref().and_then(serde_json::Value::as_u64);
    match version {
        Some(v) if v == u64::from(FORMAT_VERSION) => {}
        Some(v) if v > u64::from(FORMAT_VERSION) => {
            return Err(Damage::new(
                DamageKind::NewerVersion,
                format!("version {v}, this build knows {FORMAT_VERSION}"),
            ));
        }
        _ => {
            return Err(Damage::new(
                DamageKind::BadVersion,
                "no version this build knows",
            ));
        }
    }
    let file: FileV1 = serde_json::from_slice(bytes).map_err(shape)?;
    let notes = parse_notes(&file)?;
    if file.keys.len() > MAX_ACTIVE_KEYS {
        return Err(broken(format!("{} active keys", file.keys.len())));
    }
    // Every tombstone past MAX_TOMBSTONES_AT_PC belongs to a key that was active when the list
    // filled (adds and recoveries need room among the tombstones; removals and resets keep keys +
    // tombstones).
    if file.keys.len() + file.tombstones.len() > MAX_TOMBSTONES_AT_PC + MAX_ACTIVE_KEYS {
        return Err(broken(format!(
            "{} keys and {} tombstones",
            file.keys.len(),
            file.tombstones.len()
        )));
    }
    let set = |ids: &[GroundId]| -> Result<BTreeSet<GroundId>, Damage> {
        let set: BTreeSet<GroundId> = ids.iter().cloned().collect();
        if set.len() == ids.len() {
            Ok(set)
        } else {
            Err(broken("a spent id appears twice".into()))
        }
    };
    let spent_endorse = set(&file.spent.endorse_ids)?;
    let spent_grant = set(&file.spent.grant_ids)?;
    let spent_invite = set(&file.spent.invite_ids)?;
    let spent = spent_endorse.len() + spent_grant.len() + spent_invite.len();
    if spent > MAX_SPENT {
        return Err(broken(format!("{spent} spent ids")));
    }
    let mut keys = Vec::with_capacity(file.keys.len());
    let mut seen = HashSet::new();
    let mut per_person: HashMap<i64, usize> = HashMap::new();
    for (i, k) in file.keys.into_iter().enumerate() {
        let key = file_key(&k.spki, &k.key_id, &format!("key {i}"))?;
        if !seen.insert(k.key_id.clone()) {
            return Err(broken(format!("key_id {} appears twice", k.key_id.short())));
        }
        let uid = k.person.telegram_user_id;
        if !is_kept_person(&k.person) {
            return Err(broken(format!(
                "key {i}: a user id out of range or a name not clean"
            )));
        }
        let count = per_person.entry(uid).or_default();
        *count += 1;
        if *count > MAX_KEYS_PER_PERSON {
            return Err(broken(format!(
                "more than {MAX_KEYS_PER_PERSON} keys of user {uid}"
            )));
        }
        if k.added_at < 0 || k.last_used_at.is_some_and(|t| t < 0) {
            return Err(broken(format!("key {i}: a negative time")));
        }
        if !ground_spent(&k.source, &spent_endorse, &spent_grant, &spent_invite) {
            return Err(broken(format!(
                "key {i}: its ground is not among the spent"
            )));
        }
        if !source_ok(&k.source) {
            return Err(broken(format!("key {i}: a recovery's replaced keys")));
        }
        let rpk = match &k.rpk {
            None => None,
            Some(text) => {
                let rpk = spki_key(text).map_err(|e| broken(format!("key {i}: rpk {e}")))?;
                if rpk == key {
                    return Err(broken(format!(
                        "key {i}: the recovery key is the device key itself"
                    )));
                }
                // Two people's records with one recovery key are not damage (spec §8.4,
                // recover.json `two_persons_one_rpk`): a recovery refuses `rpk_conflict`, and no
                // new key brings in an rpk another person has (§4).
                Some(rpk)
            }
        };
        keys.push(KeyRecord {
            key,
            person: k.person,
            role: k.role,
            rpk,
            kind: k.kind,
            platform: k.platform,
            source: k.source,
            unconfirmed: k.unconfirmed,
            added_at: k.added_at,
            last_used_at: k.last_used_at,
        });
    }
    let mut tombstones = Vec::with_capacity(file.tombstones.len());
    let mut dead = HashSet::new();
    for (i, t) in file.tombstones.into_iter().enumerate() {
        let key = file_key(&t.spki, &t.key_id, &format!("removed key {i}"))?;
        if seen.contains(&t.key_id) {
            return Err(broken(format!(
                "key_id {} is both active and removed",
                t.key_id.short()
            )));
        }
        if !dead.insert(t.key_id.clone()) {
            return Err(broken(format!(
                "removed key_id {} appears twice",
                t.key_id.short()
            )));
        }
        if t.at < 0 || !user_id_ok(t.telegram_user_id) {
            return Err(broken(format!(
                "removed key {i}: a negative time or a user id out of range"
            )));
        }
        if !source_ok(&t.source) {
            return Err(broken(format!(
                "removed key {i}: a recovery's replaced keys"
            )));
        }
        if !ground_spent(&t.source, &spent_endorse, &spent_grant, &spent_invite) {
            return Err(broken(format!(
                "removed key {i}: its ground is not among the spent"
            )));
        }
        tombstones.push(Tombstone {
            key,
            telegram_user_id: t.telegram_user_id,
            origin: t.origin,
            at: t.at,
            source: t.source,
        });
    }
    if let Some(snapshot) = &file.first_use_snapshot {
        if snapshot.people.len() > MAX_SNAPSHOT_PEOPLE || snapshot.taken_at < 0 {
            return Err(broken(
                "the first_use snapshot is too large or dated before 1970".into(),
            ));
        }
        let mut people = HashSet::new();
        for p in &snapshot.people {
            if !is_kept_person(&p.person) || !people.insert(p.person.telegram_user_id) {
                return Err(broken(
                    "the first_use snapshot has a bad or repeated person".into(),
                ));
            }
        }
    }
    Ok(TrustList {
        switches: file.switches,
        keys,
        tombstones,
        spent_endorse,
        spent_grant,
        spent_invite,
        snapshot: file.first_use_snapshot,
        notes: Box::new(notes),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

    use std::sync::{Arc, Mutex, OnceLock};

    use super::*;
    use crate::viewer_keys::key::tests::fresh;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::EcdsaKeyPair;

    /// A scratch directory of its own, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("afklink-viewer-keys-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
        fn primary(&self) -> PathBuf {
            self.0.join(FILE_NAME)
        }
        fn backup(&self) -> PathBuf {
            self.0.join(BACKUP_FILE_NAME)
        }
        fn open(&self) -> TrustStore {
            TrustStore::open_in(&self.0)
        }
        /// Write `list` as the primary, bypassing the checks (it may break them on purpose).
        fn write(&self, list: &TrustList) {
            std::fs::write(self.primary(), serialize(list).unwrap()).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const NOW: i64 = 1_731_400_000_000;
    /// An endorse's `issued_at` later than every removal these tests make.
    const ISSUED: u64 = 1_731_500_000_000;
    const DEVICE_ID: &str = "8d3b1f42-6c7a-4e09-b5d8-2a9e7c1f3b64";
    const SESSION_ID: &str = "5f0c6a1e-3b2d-4c8e-9a71-0d2e4f6b8c10";
    const NONCE: [u8; 16] = [0x6d; 16];

    fn person(uid: i64) -> Person {
        Person {
            telegram_user_id: uid,
            first_name: Some("Вера".into()),
            username: Some("vera".into()),
        }
    }

    fn kind(s: &str) -> ClientKind {
        ClientKind::parse(s).unwrap()
    }

    fn platform(s: &str) -> Platform {
        Platform::parse(s).unwrap()
    }

    fn gid(n: u8) -> GroundId {
        GroundId::parse(&URL_SAFE_NO_PAD.encode([n; 16])).unwrap()
    }

    fn pair(uid: i64, role: BindingRole) -> Ground {
        Ground::Pair {
            person: person(uid),
            role,
            unconfirmed: false,
        }
    }

    fn pair_unconfirmed(uid: i64, role: BindingRole) -> Ground {
        Ground::Pair {
            person: person(uid),
            role,
            unconfirmed: true,
        }
    }

    /// An endorse issued at [`ISSUED`]: after every removal these tests make (their clock is
    /// [`NOW`] plus a little).
    fn endorse(by: &KeyId, n: u8) -> Ground {
        endorse_at(by, n, ISSUED)
    }

    /// [`endorse`] issued at `issued_at` (unix ms, the signing device's clock).
    fn endorse_at(by: &KeyId, n: u8, issued_at: u64) -> Ground {
        Ground::Endorse {
            by: by.clone(),
            endorse_id: gid(n),
            issued_at,
        }
    }

    /// A grant of `n` for `uid` by `by`, with invitation `(inv, inviter)` when given (the grant's
    /// `inv_id` is then `inv`; without one, an `inv_id` of its own, [`grant_inv_id`]).
    fn grant(by: &KeyId, n: u8, uid: i64, invite: Option<(u8, &KeyId)>) -> Ground {
        Ground::Grant {
            by: by.clone(),
            grant_id: gid(n),
            inv_id: Some(invite.map_or_else(|| grant_inv_id(n), |(inv, _)| gid(inv))),
            invite: invite.map(|(inv, inviter)| Invite {
                inv_id: gid(inv),
                by: inviter.clone(),
            }),
            person: person(uid),
            token: GrantToken::default(),
        }
    }

    /// `ground` (a grant) signed over the PC's grant token `token` instead.
    fn over(ground: Ground, token: GrantToken) -> Ground {
        match ground {
            Ground::Grant {
                by,
                grant_id,
                inv_id,
                invite,
                person,
                ..
            } => Ground::Grant {
                by,
                grant_id,
                inv_id,
                invite,
                person,
                token,
            },
            other => other,
        }
    }

    /// The `inv_id` of [`grant`]`(…, n, …, None)`.
    fn grant_inv_id(n: u8) -> GroundId {
        ground(usize::from(n), 0xA5)
    }

    /// A device: its key, and its recovery key pair (the private half signs `rsig`).
    struct Device {
        key: ViewerKey,
        rk: EcdsaKeyPair,
        rpk: ViewerKey,
    }

    impl Device {
        fn new() -> Self {
            let (_, key) = fresh();
            let (rk, rpk) = fresh();
            Self { key, rk, rpk }
        }
        fn id(&self) -> &KeyId {
            self.key.key_id()
        }
        fn new_key(&self) -> NewKey {
            NewKey {
                key: self.key.clone(),
                rpk: Some(self.rpk.clone()),
                kind: kind("telegram"),
                platform: platform("iphone"),
            }
        }
        /// The same device (same recovery key) with another device key.
        fn same_device(&self) -> NewKey {
            NewKey {
                key: fresh().1,
                ..self.new_key()
            }
        }
        fn rsig(&self, message: &[u8]) -> Vec<u8> {
            self.rk
                .sign(&SystemRandom::new(), message)
                .unwrap()
                .as_ref()
                .to_vec()
        }
    }

    fn bare(key: &ViewerKey) -> NewKey {
        NewKey {
            key: key.clone(),
            rpk: None,
            kind: kind("browser"),
            platform: platform("mac"),
        }
    }

    fn add_paired(store: &mut TrustStore, uid: i64, role: BindingRole) -> Device {
        let d = Device::new();
        store.add(d.new_key(), pair(uid, role), NOW).unwrap();
        d
    }

    /// «Удалить» as the product makes it: decided at the press ([`TrustStore::deny_tree_now`]),
    /// then its write of memory ([`TrustStore::flush`]), written and installed at once.
    fn remove_tree(
        store: &mut TrustStore,
        root: &KeyId,
        now_ms: i64,
    ) -> Result<TreeRemoval, StoreError> {
        let tree = store.deny_tree_now(root, now_ms)?;
        store.flush()?;
        Ok(tree)
    }

    /// `r` of §8.3 built here byte by byte, independently of `wire::lp`.
    fn independent_r(device_id: &str, session_id: &str, new: &KeyId, nonce: &[u8; 16]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [
            b"AFKLINK-RECOVER-V1".as_slice(),
            device_id.as_bytes(),
            session_id.as_bytes(),
            new.as_bytes().as_slice(),
            nonce.as_slice(),
        ] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// What a recovery needs besides the device: the attestation of the new key and `rsig`.
    struct Attempt {
        attested: TelegramIdentity,
        rsig: Vec<u8>,
        new_key: ViewerKey,
    }

    impl Attempt {
        /// An honest attempt: `uid` attested for a new key, `rsig` by `d`'s recovery key over `r`.
        fn new(d: &Device, uid: i64) -> Self {
            let new_key = fresh().1;
            Self::for_key(d, uid, new_key)
        }
        fn for_key(d: &Device, uid: i64, new_key: ViewerKey) -> Self {
            let rsig = d.rsig(&independent_r(
                DEVICE_ID,
                SESSION_ID,
                new_key.key_id(),
                &NONCE,
            ));
            Self {
                attested: TelegramIdentity::for_tests(
                    uid,
                    Some("Вера Н."),
                    Some("vera_new"),
                    new_key.key_id().clone(),
                ),
                rsig,
                new_key,
            }
        }
        fn recovery<'a>(&'a self, d: &'a Device) -> Recovery<'a> {
            Recovery {
                rpk: &d.rpk,
                attested: &self.attested,
                device_id: DEVICE_ID,
                session_id: SESSION_ID,
                nonce_pc: NONCE,
                rsig: &self.rsig,
                new_key: self.new_key.clone(),
                kind: kind("telegram_desktop"),
                platform: platform("windows"),
            }
        }
    }

    fn active<'a>(store: &'a TrustStore, key_id: &KeyId) -> &'a KeyRecord {
        match store.lookup(key_id) {
            Lookup::Active(r) => r,
            other => panic!("not active: {other:?}"),
        }
    }

    fn removed<'a>(store: &'a TrustStore, key_id: &KeyId) -> &'a Tombstone {
        match store.lookup(key_id) {
            Lookup::Removed(t) => t,
            other => panic!("not removed: {other:?}"),
        }
    }

    fn removed_origin(store: &TrustStore, key_id: &KeyId) -> Origin {
        removed(store, key_id).origin.clone()
    }

    fn assert_denies(store: &TrustStore, key_id: &KeyId) {
        assert!(store.is_damaged());
        assert_eq!(store.lookup(key_id), Lookup::StoreDamaged);
        assert_eq!(store.switches(), Err(StoreError::Damaged));
        assert_eq!(store.keys().unwrap_err(), StoreError::Damaged);
    }

    fn snapshot_of(people: &[(i64, BindingRole)]) -> Vec<SnapshotPerson> {
        people
            .iter()
            .map(|&(uid, role)| SnapshotPerson {
                person: Person {
                    first_name: Some(format!("Снимок {uid}")),
                    ..person(uid)
                },
                role,
            })
            .collect()
    }

    fn removal_error(origin: &'static str, key_id: &KeyId) -> StoreError {
        StoreError::Removed {
            key_id: key_id.clone(),
            origin,
        }
    }

    fn record(key: &ViewerKey, uid: i64, role: BindingRole, rpk: Option<&ViewerKey>) -> KeyRecord {
        KeyRecord {
            key: key.clone(),
            person: person(uid),
            role,
            rpk: rpk.cloned(),
            kind: kind("telegram"),
            platform: platform("android"),
            source: KeySource::Pair,
            unconfirmed: false,
            added_at: NOW,
            last_used_at: None,
        }
    }

    /// Distinct keys made once for every test (a full list needs thousands).
    fn pool() -> &'static [ViewerKey] {
        static POOL: OnceLock<Vec<ViewerKey>> = OnceLock::new();
        POOL.get_or_init(|| {
            (0..MAX_TOMBSTONES_AT_PC + MAX_ACTIVE_KEYS + 8)
                .map(|_| fresh().1)
                .collect()
        })
    }

    fn tombstone(i: usize) -> Tombstone {
        Tombstone {
            key: pool()[i].clone(),
            telegram_user_id: 900_000 + i as i64,
            origin: Origin::Pc,
            at: NOW,
            source: KeySource::Pair,
        }
    }

    fn many_keys(n: usize) -> Vec<KeyRecord> {
        (0..n)
            .map(|i| record(&fresh().1, i as i64 + 1, BindingRole::Guest, None))
            .collect()
    }

    fn ground(i: usize, tag: u8) -> GroundId {
        let mut bytes = [tag; 16];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        GroundId::parse(&URL_SAFE_NO_PAD.encode(bytes)).unwrap()
    }

    // --- Values ---------------------------------------------------------------------------------

    #[test]
    fn ground_ids_and_tags_parse_strictly() {
        assert_eq!(gid(7).as_str().len(), GROUND_ID_LEN);
        assert!(GroundId::parse("AAAAAAAAAAAAAAAAAAAAAA").is_some());
        for bad in [
            "",
            "AAAAAAAAAAAAAAAAAAAAA",   // 21
            "AAAAAAAAAAAAAAAAAAAAAAA", // 23
            "AAAAAAAAAAAAAAAAAAAAAB",  // non-zero trailing bits
            "AAAAAAAAAAAAAAAAAAAA+A",  // standard alphabet
            "AAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAA A",
        ] {
            assert!(GroundId::parse(bad).is_none(), "{bad}");
        }
        for k in ClientKind::KNOWN {
            assert!(ClientKind::parse(k).unwrap().is_known());
        }
        for p in Platform::KNOWN {
            assert!(Platform::parse(p).unwrap().is_known());
        }
        let newer = ClientKind::parse("vr_headset2").unwrap();
        assert!(!newer.is_known());
        assert!(ClientKind::parse(&"a".repeat(24)).is_some());
        for bad in [
            "",
            "Telegram",
            "iPhone",
            "tele gram",
            "tele-gram",
            "é",
            &"a".repeat(25),
        ] {
            assert!(ClientKind::parse(bad).is_none(), "{bad}");
            assert!(Platform::parse(bad).is_none(), "{bad}");
        }
    }

    // --- Round trip and format ------------------------------------------------------------------

    #[test]
    fn first_run_is_empty_and_writes_nothing() {
        let dir = Scratch::new();
        let store = dir.open();
        assert!(!store.is_damaged());
        assert_eq!(store.switches().unwrap(), SwitchState::default());
        assert!(!SwitchState::default().trusted_devices_mode);
        assert!(store.keys().unwrap().is_empty());
        assert_eq!(store.first_use_snapshot().unwrap(), None);
        assert!(!dir.primary().exists());
        assert!(!dir.backup().exists());
    }

    #[test]
    fn round_trip_of_every_kind_of_change() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        assert!(dir.primary().exists());
        assert!(!dir.backup().exists(), "no backup of a list never on disk");
        // Endorse: person and role are the endorser's.
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 1), NOW + 1)
            .unwrap();
        assert!(dir.backup().exists());
        // Grant with an invitation: a guest, the grant's person, confirmed.
        let guest = Device::new();
        let out = store
            .add(
                guest.new_key(),
                grant(owner.id(), 2, 2, Some((3, laptop.id()))),
                NOW + 2,
            )
            .unwrap();
        assert!(!out.unconfirmed);
        assert_eq!(out.role, BindingRole::Guest);
        // first_use from the snapshot.
        assert!(store
            .take_first_use_snapshot(snapshot_of(&[(3, BindingRole::Guest)]), NOW + 3)
            .unwrap());
        let migrated = Device::new();
        store
            .add(
                migrated.new_key(),
                Ground::FirstUse {
                    telegram_user_id: 3,
                },
                NOW + 4,
            )
            .unwrap();
        assert!(store.touch(owner.id(), NOW + 10).unwrap());
        store.set_trusted_devices_mode(true).unwrap();
        store.set_trusted_devices_mode(true).unwrap(); // already on: nothing written
        store.remove(guest.id(), Removal::Server, NOW + 20).unwrap();
        let attempt = Attempt::new(&owner, 1);
        let outcome = store.recover(attempt.recovery(&owner), NOW + 30).unwrap();
        assert_eq!(outcome.replaced, vec![owner.id().clone()]);
        assert_eq!(outcome.role, BindingRole::Owner);
        assert!(!outcome.unconfirmed);

        let reopened = dir.open();
        assert_eq!(reopened.keys().unwrap(), store.keys().unwrap());
        assert_eq!(reopened.tombstones().unwrap(), store.tombstones().unwrap());
        assert_eq!(reopened.spent().unwrap(), store.spent().unwrap());
        assert_eq!(
            reopened.first_use_snapshot().unwrap(),
            store.first_use_snapshot().unwrap()
        );
        assert!(reopened.switches().unwrap().trusted_devices_mode);

        let lap = active(&reopened, laptop.id());
        assert_eq!(lap.person, person(1));
        assert_eq!(lap.role, BindingRole::Owner);
        assert!(!lap.unconfirmed);
        assert_eq!(
            lap.source,
            KeySource::Endorse {
                by: owner.id().clone(),
                endorse_id: gid(1)
            }
        );
        let mig = active(&reopened, migrated.id());
        assert_eq!(mig.role, BindingRole::Guest);
        assert!(mig.unconfirmed);
        assert_eq!(mig.person.first_name.as_deref(), Some("Снимок 3"));
        assert_eq!(mig.source, KeySource::FirstUse);
        let rec = active(&reopened, attempt.new_key.key_id());
        assert_eq!(rec.role, BindingRole::Owner);
        assert_eq!(rec.person.first_name.as_deref(), Some("Вера Н."));
        assert_eq!(rec.person.username.as_deref(), Some("vera_new"));
        assert_eq!(rec.rpk.as_ref(), Some(&owner.rpk));
        assert_eq!(rec.kind, kind("telegram_desktop"));
        assert_eq!(rec.platform, platform("windows"));
        assert_eq!(
            rec.source,
            KeySource::Recover {
                replaced: vec![owner.id().clone()],
                parents: Vec::new(),
            }
        );
        let gone_guest = removed(&reopened, guest.id());
        assert_eq!(gone_guest.origin, Origin::Server);
        assert_eq!(gone_guest.key, guest.key);
        assert_eq!(
            gone_guest.source,
            KeySource::Grant {
                by: owner.id().clone(),
                grant_id: gid(2),
                inv_id: Some(gid(3)),
                invite_by: Some(laptop.id().clone()),
            }
        );
        assert_eq!(
            removed_origin(&reopened, owner.id()),
            Origin::Replaced {
                new_key_id: attempt.new_key.key_id().clone()
            }
        );
        let (spent_e, spent_g, spent_i) = reopened.spent().unwrap();
        assert!(
            spent_e.contains(&gid(1)) && spent_g.contains(&gid(2)) && spent_i.contains(&gid(3))
        );
        assert_eq!(reopened.lookup(fresh().1.key_id()), Lookup::Unknown);
    }

    #[test]
    fn the_file_format() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        store.touch(owner.id(), NOW + 1).unwrap();
        store.remove(owner.id(), Removal::Pc, NOW + 2).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.primary()).unwrap()).unwrap();
        // The one version, the grant token always there (`""` on a PC that removed nobody).
        assert_eq!(v["version"], FORMAT_VERSION);
        assert_eq!(v["grant_token"], "");
        assert_eq!(
            v["switches"],
            serde_json::json!({"trusted_devices_mode": false})
        );
        assert_eq!(v["keys"], serde_json::json!([]));
        assert_eq!(
            v["tombstones"],
            serde_json::json!([{
                "key_id": owner.id().as_str(),
                "spki": URL_SAFE_NO_PAD.encode(owner.key.spki()),
                "telegram_user_id": 1,
                "origin": {"kind": "pc"},
                "at": NOW + 2,
                "source": {"kind": "pair"},
            }])
        );
        assert_eq!(
            v["spent"],
            serde_json::json!({"endorse_ids": [], "grant_ids": [], "invite_ids": []})
        );
        assert!(v.get("first_use_snapshot").is_none());
        // The backup holds the key as it was.
        let b: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.backup()).unwrap()).unwrap();
        assert_eq!(
            b["keys"][0],
            serde_json::json!({
                "key_id": owner.id().as_str(),
                "spki": URL_SAFE_NO_PAD.encode(owner.key.spki()),
                "person": {"telegram_user_id": 1, "first_name": "Вера", "username": "vera"},
                "role": "owner",
                "kind": "telegram",
                "platform": "iphone",
                "rpk": URL_SAFE_NO_PAD.encode(owner.rpk.spki()),
                "source": {"kind": "pair"},
                "unconfirmed": false,
                "added_at": NOW,
                "last_used_at": NOW + 1,
            })
        );
        // A grant's source with its invitation, and a recovery's.
        let mut store = dir.open();
        let o2 = add_paired(&mut store, 5, BindingRole::Owner);
        let g = Device::new();
        store
            .add(g.new_key(), grant(o2.id(), 7, 6, Some((8, o2.id()))), NOW)
            .unwrap();
        let attempt = Attempt::new(&g, 6);
        store.recover(attempt.recovery(&g), NOW).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.primary()).unwrap()).unwrap();
        let t = v["tombstones"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["key_id"] == g.id().as_str())
            .unwrap()
            .clone();
        assert_eq!(
            t["source"],
            serde_json::json!({
                "kind": "grant", "by": o2.id().as_str(), "grant_id": gid(7), "inv_id": gid(8),
                "invite_by": o2.id().as_str()
            })
        );
        assert_eq!(
            t["origin"],
            serde_json::json!({"kind": "replaced", "new_key_id": attempt.new_key.key_id().as_str()})
        );
        let k = v["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["key_id"] == attempt.new_key.key_id().as_str())
            .unwrap()
            .clone();
        // The replaced record's edges are the new record's own (§10 `source.parents`): the grant's
        // signer and its invitation's, once.
        assert_eq!(
            k["source"],
            serde_json::json!({
                "kind": "recover", "replaced": [g.id().as_str()], "parents": [o2.id().as_str()]
            })
        );
        assert_eq!(v["spent"]["invite_ids"], serde_json::json!([gid(8)]));
    }

    // --- Damage ---------------------------------------------------------------------------------

    /// A store with one owner key (with an `rpk`) and one removed key, saved more than once (so a
    /// backup exists).
    fn store_with_owner(dir: &Scratch) -> (TrustStore, Device) {
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let gone = add_paired(&mut store, 9, BindingRole::Guest);
        store.remove(gone.id(), Removal::Pc, NOW).unwrap();
        store.touch(owner.id(), NOW + 1).unwrap();
        (store, owner)
    }

    /// The primary as JSON, edited by `edit`, written back.
    fn edit_primary(dir: &Scratch, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.primary()).unwrap()).unwrap();
        edit(&mut v);
        std::fs::write(dir.primary(), serde_json::to_vec(&v).unwrap()).unwrap();
    }

    /// The damage of a store with one owner key and one tombstone after `edit`; `None` when it
    /// still loads.
    fn after(edit: impl FnOnce(&mut serde_json::Value)) -> Option<DamageKind> {
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        edit_primary(&dir, edit);
        let store = dir.open();
        if store.is_damaged() {
            assert_denies(&store, owner.id());
            // The detail names no key in full.
            let detail = &store.damage().unwrap().detail;
            assert!(!detail.contains(owner.id().as_str()), "{detail}");
        }
        store.damage().map(|d| d.kind)
    }

    /// The last known binding list is a note — kept in memory at once, written by the next
    /// write (version 2), read back the same after a reopen; `[]` is a stored list, unlike none;
    /// the parser holds it to its bounds (in range, once per person, at most
    /// [`LAST_BINDINGS_MAX`]).
    #[test]
    fn the_last_known_bindings_are_a_bounded_note() {
        let dir = Scratch::new();
        let (mut store, _) = store_with_owner(&dir);
        assert_eq!(store.last_bindings(), None);
        let b = |telegram_user_id, role| KnownBinding {
            telegram_user_id,
            role,
        };
        assert!(store.note_last_bindings([
            b(5, BindingRole::Guest),
            b(1, BindingRole::Owner),
            b(0, BindingRole::Guest),
            b(5, BindingRole::Guest),
        ]));
        assert!(!store.note_last_bindings([b(1, BindingRole::Owner), b(5, BindingRole::Guest)]));
        assert!(store.notes_unsaved());
        assert!(store.flush().unwrap());
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.primary()).unwrap()).unwrap();
        assert_eq!(v["version"], FORMAT_VERSION);
        let again = dir.open();
        assert_eq!(
            again.last_bindings(),
            Some(&[b(1, BindingRole::Owner), b(5, BindingRole::Guest)][..])
        );
        let mut store = again;
        assert!(store.note_last_bindings([]));
        store.flush().unwrap();
        assert_eq!(dir.open().last_bindings(), Some(&[][..]), "[] is a list");
        let entry = |uid: i64| serde_json::json!({"telegram_user_id": uid, "role": "guest"});
        let with = |list: Vec<serde_json::Value>| {
            after(move |v| {
                v["version"] = FORMAT_VERSION.into();
                v["last_bindings"] = serde_json::Value::Array(list);
            })
        };
        let inv = Some(DamageKind::Invariant);
        assert_eq!(with(vec![entry(0)]), inv, "out of range");
        assert_eq!(with(vec![entry(5), entry(5)]), inv, "twice");
        assert_eq!(
            with((1..=LAST_BINDINGS_MAX as i64 + 1).map(entry).collect()),
            inv,
            "past the bound"
        );
        assert_eq!(
            with((1..=LAST_BINDINGS_MAX as i64).map(entry).collect()),
            None
        );
    }

    /// §10 «Отложенных проверок ПК не хранит»: `owner_checks_due` is no field of the file — a file
    /// holding one is `key_list_damaged` like any unknown field (repaired at the PC). Refutes a
    /// parser that takes it.
    #[test]
    fn deferred_owner_checks_are_no_field_of_the_file() {
        let with = |list: serde_json::Value| {
            after(move |v| {
                v["owner_checks_due"] = list;
            })
        };
        assert!(
            with(serde_json::json!([5, 9])).is_some(),
            "an unknown field"
        );
    }

    /// A relay's `agent_ready` with ≫ [`LAST_BINDINGS_MAX`] bindings (every one twice, the
    /// keyed person — the owner, 1 — last) is noted at once, bounded: the keyed person kept, the
    /// rest up to the bound. Not a stall of the orchestrator (a quadratic dedupe took minutes).
    #[test]
    fn a_flood_of_bindings_is_noted_at_once_and_keeps_the_keyed_person() {
        let dir = Scratch::new();
        let (store, _) = store_with_owner(&dir);
        let flood: Vec<KnownBinding> = (2..=200_001i64)
            .chain(2..=200_001)
            .chain([1])
            .map(|telegram_user_id| KnownBinding {
                telegram_user_id,
                role: BindingRole::Guest,
            })
            .collect();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut store = store;
            let noted = store.note_last_bindings(flood);
            let _ = tx.send((noted, store.last_bindings().map(<[_]>::to_vec)));
        });
        let (noted, list) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("noted within 5 s, not a stall");
        assert!(noted);
        let list = list.expect("a list");
        assert_eq!(list.len(), LAST_BINDINGS_MAX);
        assert!(
            list.iter().any(|b| b.telegram_user_id == 1),
            "the keyed person"
        );
        assert!(list
            .windows(2)
            .all(|w| w[0].telegram_user_id < w[1].telegram_user_id));
    }

    #[test]
    fn corrupt_primary_is_damaged_and_denies_even_with_mode_off() {
        let dir = Scratch::new();
        let (store, owner) = store_with_owner(&dir);
        assert!(!store.switches().unwrap().trusted_devices_mode);
        std::fs::write(dir.primary(), b"{ not json").unwrap();
        let mut store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::NotParsable);
        assert_denies(&store, owner.id());
        let other = Device::new();
        assert_eq!(
            store.add(other.new_key(), pair(5, BindingRole::Guest), NOW),
            Err(StoreError::Damaged)
        );
        assert_eq!(
            store.remove(owner.id(), Removal::Pc, NOW),
            Err(StoreError::Damaged)
        );
        assert_eq!(
            remove_tree(&mut store, owner.id(), NOW),
            Err(StoreError::Damaged)
        );
        assert_eq!(store.confirm(owner.id()), Err(StoreError::Damaged));
        assert_eq!(store.touch(owner.id(), NOW), Err(StoreError::Damaged));
        assert_eq!(
            store.set_trusted_devices_mode(false),
            Err(StoreError::Damaged)
        );
        assert_eq!(
            store.take_first_use_snapshot(snapshot_of(&[(1, BindingRole::Owner)]), NOW),
            Err(StoreError::Damaged)
        );
        let attempt = Attempt::new(&owner, 1);
        assert_eq!(
            store.recover(attempt.recovery(&owner), NOW),
            Err(StoreError::Damaged)
        );
        // Nothing was written over the damaged file.
        assert_eq!(std::fs::read(dir.primary()).unwrap(), b"{ not json");
    }

    #[test]
    fn truncated_file_is_damaged() {
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        let bytes = std::fs::read(dir.primary()).unwrap();
        std::fs::write(dir.primary(), &bytes[..bytes.len() / 2]).unwrap();
        let store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::NotParsable);
        assert_denies(&store, owner.id());
        std::fs::write(dir.primary(), b"").unwrap();
        assert!(dir.open().is_damaged());
    }

    #[test]
    fn key_id_that_is_not_its_spki_is_damage() {
        let other = fresh().1;
        let inv = Some(DamageKind::Invariant);
        for list in ["keys", "tombstones"] {
            assert_eq!(
                after(|v| v[list][0]["key_id"] = other.key_id().as_str().into()),
                inv,
                "{list}"
            );
            assert_eq!(
                after(|v| v[list][0]["spki"] = URL_SAFE_NO_PAD.encode(other.spki()).into()),
                inv,
                "{list}"
            );
            assert_eq!(
                after(|v| v[list][0]["spki"] = URL_SAFE_NO_PAD.encode([0u8; 91]).into()),
                inv,
                "{list}"
            );
            // The standard alphabet or padding is not the file's encoding.
            assert_eq!(
                after(|v| {
                    let spki = v[list][0]["spki"].as_str().unwrap().to_string();
                    v[list][0]["spki"] = format!("{spki}=").into();
                }),
                inv,
                "{list}"
            );
            assert_eq!(
                after(|v| v[list][0]["key_id"] = "short".into()),
                Some(DamageKind::NotParsable),
                "{list}"
            );
            assert_eq!(
                after(|v| {
                    v[list][0].as_object_mut().unwrap().remove("spki");
                }),
                Some(DamageKind::NotParsable),
                "{list}"
            );
        }
    }

    #[test]
    fn a_tombstone_keeps_its_spki_through_a_reload() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let d = add_paired(&mut store, 1, BindingRole::Guest);
        store.remove(d.id(), Removal::Server, NOW).unwrap();
        let reopened = dir.open();
        let t = removed(&reopened, d.id());
        assert_eq!(t.key, d.key);
        assert_eq!(t.spki(), d.key.spki());
        assert_eq!(t.key_id(), d.id());
        assert_eq!(t.telegram_user_id, 1);
        assert_eq!(t.source, KeySource::Pair);
        // The SPKI checks an offer's signature of the removed key (§3.4 step 6).
        let (pair_key, key) = fresh();
        let mut store = dir.open();
        store
            .add(bare(&key), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        store.remove(key.key_id(), Removal::Pc, NOW).unwrap();
        let reopened = dir.open();
        let sig = pair_key.sign(&SystemRandom::new(), b"offer").unwrap();
        assert_eq!(
            removed(&reopened, key.key_id())
                .key
                .verify(b"offer", sig.as_ref()),
            Ok(())
        );
    }

    #[test]
    fn duplicates_are_damage() {
        let inv = Some(DamageKind::Invariant);
        assert_eq!(
            after(|v| {
                let k = v["keys"][0].clone();
                v["keys"].as_array_mut().unwrap().push(k);
            }),
            inv
        );
        // A key both active and removed.
        assert_eq!(
            after(|v| {
                let mut t = v["tombstones"][0].clone();
                t["key_id"] = v["keys"][0]["key_id"].clone();
                t["spki"] = v["keys"][0]["spki"].clone();
                v["tombstones"].as_array_mut().unwrap().push(t);
            }),
            inv
        );
        assert_eq!(
            after(|v| {
                let t = v["tombstones"][0].clone();
                v["tombstones"].as_array_mut().unwrap().push(t);
            }),
            inv
        );
        for set in ["endorse_ids", "grant_ids", "invite_ids"] {
            assert_eq!(
                after(|v| v["spent"][set] = serde_json::json!([gid(1), gid(1)])),
                inv,
                "{set}"
            );
        }
        assert_eq!(
            after(|v| {
                v["first_use_snapshot"] = serde_json::json!({"taken_at": 1, "people": [
                    {"person": {"telegram_user_id": 5}, "role": "guest"},
                    {"person": {"telegram_user_id": 5}, "role": "owner"},
                ]});
            }),
            inv
        );
    }

    #[test]
    fn versions_and_shapes_this_build_does_not_know_are_damage() {
        assert_eq!(
            after(|v| v["version"] = (FORMAT_VERSION + 1).into()),
            Some(DamageKind::NewerVersion)
        );
        for bad in [serde_json::json!(0), serde_json::json!("1")] {
            assert_eq!(after(|v| v["version"] = bad), Some(DamageKind::BadVersion));
        }
        assert_eq!(
            after(|v| {
                v.as_object_mut().unwrap().remove("version");
            }),
            Some(DamageKind::BadVersion)
        );
        // An older format version is not read: no conversion of older formats (§14).
        for older in [1, 2] {
            assert_eq!(
                after(|v| v["version"] = older.into()),
                Some(DamageKind::BadVersion),
                "version {older}"
            );
        }
        let np = Some(DamageKind::NotParsable);
        // The grant token is required (§7), in its one form: never read as `""`.
        assert_eq!(
            after(|v| {
                v.as_object_mut().unwrap().remove("grant_token");
            }),
            np
        );
        assert_eq!(after(|v| v["grant_token"] = serde_json::Value::Null), np);
        for bad in [
            "A".repeat(21),
            "A".repeat(23),
            format!("{}==", "A".repeat(20)),
        ] {
            assert_eq!(
                after(|v| v["grant_token"] = bad.clone().into()),
                Some(DamageKind::Invariant),
                "{bad}"
            );
        }
        // The recovery switch is gone: a file that has it is not this format.
        assert_eq!(
            after(|v| v["switches"]["same_device_recovery"] = true.into()),
            np
        );
        assert_eq!(after(|v| v["extra"] = 1.into()), np);
        assert_eq!(after(|v| v["keys"][0]["admin"] = true.into()), np);
        assert_eq!(after(|v| v["keys"][0]["label"] = "x".into()), np);
        assert_eq!(after(|v| v["keys"][0]["role"] = "root".into()), np);
        assert_eq!(after(|v| v["keys"][0]["kind"] = "Telegram".into()), np);
        assert_eq!(after(|v| v["keys"][0]["platform"] = "iPhone".into()), np);
        assert_eq!(
            after(|v| v["keys"][0]["platform"] = "a".repeat(25).into()),
            np
        );
        for field in ["kind", "unconfirmed", "source"] {
            assert_eq!(
                after(|v| {
                    v["keys"][0].as_object_mut().unwrap().remove(field);
                }),
                np,
                "{field}"
            );
        }
        assert_eq!(after(|v| v["keys"][0]["unconfirmed"] = 0.into()), np);
        assert_eq!(
            after(|v| v["keys"][0]["source"] = serde_json::json!({"kind": "paired_at_pc"})),
            np
        );
        // The old recovery source with its hint is not this format.
        assert_eq!(
            after(|v| v["keys"][0]["source"] =
                serde_json::json!({"kind": "recover", "old": fresh().1.key_id().as_str()})),
            np
        );
        assert_eq!(
            after(|v| v["keys"][0]["person"]["name"] = "Вера".into()),
            np
        );
        assert_eq!(
            after(|v| v["spent"]["endorse_ids"] = serde_json::json!(["AAAAAAAAAAAAAAAAAAAAAB"])),
            np
        );
        assert_eq!(
            after(|v| {
                v["spent"].as_object_mut().unwrap().remove("invite_ids");
            }),
            np
        );
        assert_eq!(
            after(|v| v["tombstones"][0]["origin"] = serde_json::json!({"kind": "by_owner"})),
            np
        );
        assert_eq!(
            after(|v| {
                v["tombstones"][0].as_object_mut().unwrap().remove("source");
            }),
            np
        );
        assert_eq!(
            after(|v| v["keys"][0]["source"] = serde_json::json!({
                "kind": "grant", "by": fresh().1.key_id().as_str(), "grant_id": gid(9),
                "inv_id": gid(9), "invite": {"inv_id": gid(9)}
            })),
            np
        );
        // A grant without an inv_id is this format (spec §7: `null` on a grant without a signed
        // invitation): it parses, and the load's invariants judge it (here: its signer unknown).
        assert_ne!(
            after(|v| v["keys"][0]["source"] = serde_json::json!({
                "kind": "grant", "by": fresh().1.key_id().as_str(), "grant_id": gid(9)
            })),
            np
        );
        // A well-formed value this build does not know is kept (a newer client).
        assert_eq!(
            after(|v| v["keys"][0]["platform"] = "vision_os".into()),
            None
        );
    }

    #[test]
    fn other_invariants_are_damage() {
        let inv = Some(DamageKind::Invariant);
        for uid in [0i64, -1, 1 << 53] {
            assert_eq!(
                after(|v| v["keys"][0]["person"]["telegram_user_id"] = uid.into()),
                inv,
                "{uid}"
            );
            assert_eq!(
                after(|v| v["tombstones"][0]["telegram_user_id"] = uid.into()),
                inv,
                "{uid}"
            );
        }
        assert_eq!(
            after(|v| v["keys"][0]["person"]["first_name"] = "a".repeat(65).into()),
            inv
        );
        assert_eq!(
            after(|v| v["keys"][0]["person"]["username"] = "a\nb".into()),
            inv
        );
        assert_eq!(
            after(|v| v["keys"][0]["person"]["first_name"] = "".into()),
            inv
        );
        assert_eq!(
            after(|v| v["keys"][0]["rpk"] = URL_SAFE_NO_PAD.encode([1u8; 91]).into()),
            inv
        );
        assert_eq!(
            after(|v| {
                let mut spki = URL_SAFE_NO_PAD
                    .decode(v["keys"][0]["rpk"].as_str().unwrap())
                    .unwrap();
                spki[90] ^= 1;
                v["keys"][0]["rpk"] = URL_SAFE_NO_PAD.encode(spki).into();
            }),
            inv
        );
        assert_eq!(after(|v| v["keys"][0]["rpk"] = "not base64!".into()), inv);
        assert_eq!(
            after(|v| v["keys"][0]["rpk"] = v["keys"][0]["spki"].clone()),
            inv
        );
        assert_eq!(after(|v| v["keys"][0]["added_at"] = (-1).into()), inv);
        assert_eq!(after(|v| v["tombstones"][0]["at"] = (-1).into()), inv);
        // An endorsed or granted key whose ground is not spent: a grant's grant_id and inv_id
        // both, with or without the invitation.
        let by = fresh().1.key_id().as_str().to_string();
        for invite_by in [None, Some(by.clone())] {
            let mut source = serde_json::json!({
                "kind": "grant", "by": by, "grant_id": gid(9), "inv_id": gid(10)
            });
            if let Some(i) = &invite_by {
                source["invite_by"] = i.as_str().into();
            }
            assert_eq!(after(|v| v["keys"][0]["source"] = source.clone()), inv);
            assert_eq!(
                after(|v| {
                    v["keys"][0]["source"] = source.clone();
                    v["spent"]["grant_ids"] = serde_json::json!([gid(9)]);
                }),
                inv
            );
            assert_eq!(
                after(|v| {
                    v["keys"][0]["source"] = source.clone();
                    v["spent"]["invite_ids"] = serde_json::json!([gid(10)]);
                }),
                inv
            );
            assert_eq!(
                after(|v| {
                    v["keys"][0]["source"] = source.clone();
                    v["spent"]["grant_ids"] = serde_json::json!([gid(9)]);
                    v["spent"]["invite_ids"] = serde_json::json!([gid(10)]);
                }),
                None
            );
        }
        // A recovery that replaced nothing, or one key twice.
        for replaced in [serde_json::json!([]), serde_json::json!([by, by])] {
            assert_eq!(
                after(|v| v["keys"][0]["source"] =
                    serde_json::json!({"kind": "recover", "replaced": replaced, "parents": []})),
                inv
            );
        }
        // Inherited edges: one twice, or one that is a replaced key itself, is damage; distinct
        // others load, and none (`[]`). The field absent does not parse.
        assert_eq!(
            after(|v| v["keys"][0]["source"] =
                serde_json::json!({"kind": "recover", "replaced": [by]})),
            Some(DamageKind::NotParsable)
        );
        let other = fresh().1;
        let other = other.key_id().as_str();
        for (parents, want) in [
            (serde_json::json!([other, other]), inv),
            (serde_json::json!([by]), inv),
            (serde_json::json!([other]), None),
            (serde_json::json!([]), None),
        ] {
            assert_eq!(
                after(|v| v["keys"][0]["source"] = serde_json::json!(
                    {"kind": "recover", "replaced": [by], "parents": parents}
                )),
                want,
                "{parents}"
            );
        }
        // One recovery key, two people: not damage (a recovery refuses it instead).
        assert_eq!(
            after(|v| {
                let mut k = v["keys"][0].clone();
                let other = fresh().1;
                k["key_id"] = other.key_id().as_str().into();
                k["spki"] = URL_SAFE_NO_PAD.encode(other.spki()).into();
                k["person"]["telegram_user_id"] = 2.into();
                v["keys"].as_array_mut().unwrap().push(k);
            }),
            None
        );
    }

    #[test]
    fn missing_primary_with_a_backup_is_damage() {
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        assert!(dir.backup().exists());
        std::fs::remove_file(dir.primary()).unwrap();
        let store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::PrimaryMissing);
        assert_denies(&store, owner.id());
    }

    // --- The mode file --------------------------------------------------------------------------

    impl Scratch {
        fn mode(&self) -> PathBuf {
            self.0.join(MODE_FILE_NAME)
        }
        /// What the mode file says now.
        fn side(&self) -> Side {
            read_mode(&self.primary())
        }
        fn set_side(&self, strict: bool) {
            std::fs::write(
                self.mode(),
                format!(r#"{{"version":1,"trusted_devices_mode":{strict}}}"#),
            )
            .unwrap();
        }
        /// A mode file that can be neither written nor removed: a directory (not empty).
        fn block_side(&self) {
            let _ = std::fs::remove_file(self.mode());
            std::fs::create_dir(self.mode()).unwrap();
            std::fs::write(self.mode().join("x"), b"x").unwrap();
        }
        fn unblock_side(&self) {
            std::fs::remove_dir_all(self.mode()).unwrap();
        }
        fn damage(&self) {
            std::fs::write(self.primary(), b"garbage").unwrap();
        }
    }

    #[test]
    fn the_mode_file_follows_the_switch_at_every_write() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        assert_eq!(dir.side(), Side::Says(false), "written with the first list");
        assert_eq!(
            std::fs::read_to_string(dir.mode()).unwrap(),
            r#"{"version":1,"trusted_devices_mode":false}"#
        );
        store.set_trusted_devices_mode(true).unwrap();
        assert_eq!(dir.side(), Side::Says(true));
        store.set_trusted_devices_mode(false).unwrap();
        assert_eq!(dir.side(), Side::Says(false));
        // A healthy store says nothing of the mode file.
        assert_eq!(store.damaged_mode(), None);
        assert_eq!(dir.open().damaged_mode(), None);
    }

    #[test]
    fn an_upgrade_list_gets_its_mode_file_at_open() {
        for strict in [false, true] {
            let dir = Scratch::new();
            let (mut store, _owner) = store_with_owner(&dir);
            store.set_trusted_devices_mode(strict).unwrap();
            std::fs::remove_file(dir.mode()).unwrap();
            let store = dir.open();
            assert!(!store.is_damaged());
            assert_eq!(dir.side(), Side::Says(strict), "strict={strict}");
            // And at a reopen too.
            std::fs::remove_file(dir.mode()).unwrap();
            let mut store = store;
            let _ = store.reopen();
            assert_eq!(dir.side(), Side::Says(strict), "strict={strict}");
        }
    }

    #[test]
    fn a_healthy_list_wins_over_a_mode_file_that_disagrees() {
        // Turning on crashed after the mode file and before the list: the list is observe.
        let dir = Scratch::new();
        let (store, owner) = store_with_owner(&dir);
        drop(store);
        dir.set_side(true);
        let mut store = dir.open();
        assert!(
            !store.switches().unwrap().trusted_devices_mode,
            "the list wins"
        );
        assert_eq!(dir.side(), Side::Says(false), "set from the list at open");
        // Disagreeing after the open (a hand edit): the next write sets it.
        dir.set_side(true);
        assert!(store
            .touch(owner.id(), NOW + LAST_USED_WRITE_AFTER_MS + 1)
            .unwrap());
        assert_eq!(dir.side(), Side::Says(false), "set by the next write");

        // Turning off crashed after the list and before the mode file: the list is observe too.
        dir.set_side(true);
        let _ = store.reopen();
        assert!(!store.switches().unwrap().trusted_devices_mode);
        assert_eq!(dir.side(), Side::Says(false));
    }

    #[test]
    fn a_damaged_list_takes_the_mode_from_the_mode_file_or_is_strict() {
        /// A case: its name, the mode file (`None`: none), what a damaged list takes from it.
        type Case = (&'static str, Option<&'static [u8]>, Option<bool>);
        let cases: [Case; 6] = [
            (
                "observe",
                Some(br#"{"version":1,"trusted_devices_mode":false}"#),
                Some(false),
            ),
            (
                "strict",
                Some(br#"{"version":1,"trusted_devices_mode":true}"#),
                Some(true),
            ),
            ("missing", None, None),
            ("garbage", Some(b"{\"version\":1,"), None),
            (
                "newer",
                Some(br#"{"version":2,"trusted_devices_mode":false}"#),
                None,
            ),
            (
                "unknown field",
                Some(br#"{"version":1,"trusted_devices_mode":false,"x":1}"#),
                None,
            ),
        ];
        for (name, file, want) in cases {
            let dir = Scratch::new();
            let (store, owner) = store_with_owner(&dir);
            drop(store);
            match file {
                Some(bytes) => std::fs::write(dir.mode(), bytes).unwrap(),
                None => std::fs::remove_file(dir.mode()).unwrap(),
            }
            dir.damage();
            let mut store = dir.open();
            assert_eq!(store.damaged_mode(), want, "{name}");
            // Damaged all the same: no key, no switch, no change.
            assert_denies(&store, owner.id());
            let new = Device::new().new_key();
            assert_eq!(
                store.check_add(&new, &pair(2, BindingRole::Guest), NOW),
                Err(StoreError::Damaged),
                "{name}"
            );
            assert_eq!(
                store.set_trusted_devices_mode(true),
                Err(StoreError::Damaged),
                "{name}"
            );
            // Nothing at open rewrites the mode file of a damaged list.
            match file {
                Some(bytes) => assert_eq!(std::fs::read(dir.mode()).unwrap(), bytes, "{name}"),
                None => assert!(!dir.mode().exists(), "{name}"),
            }
            // A reopen reads it again.
            let _ = store.reopen();
            assert_eq!(store.damaged_mode(), want, "{name}");
        }
    }

    #[test]
    fn a_mode_file_that_cannot_be_made_strict_refuses_turning_the_switch_on() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        let before = std::fs::read(dir.primary()).unwrap();
        dir.block_side();
        let refused = store.set_trusted_devices_mode(true).unwrap_err();
        assert!(
            matches!(&refused, StoreError::Write(w) if w.starts_with("mode file")),
            "{refused:?}"
        );
        assert_eq!(
            std::fs::read(dir.primary()).unwrap(),
            before,
            "the list is not written"
        );
        assert!(!store.switches().unwrap().trusted_devices_mode);

        // Once it can be, the switch goes on, mode file first.
        dir.unblock_side();
        store.set_trusted_devices_mode(true).unwrap();
        assert_eq!(dir.side(), Side::Says(true));

        // Another change of a strict list with a stale mode file that cannot be fixed: saved
        // all the same (a removal must always work).
        dir.block_side();
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        store.remove(guest.id(), Removal::Pc, NOW).unwrap();
        assert!(matches!(store.lookup(guest.id()), Lookup::Removed(_)));
        assert!(matches!(store.lookup(owner.id()), Lookup::Active(_)));
    }

    #[test]
    fn turning_the_switch_off_writes_the_list_first_and_a_failed_mode_file_stays_strict() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        store.set_trusted_devices_mode(true).unwrap();
        dir.block_side();
        // The list is saved; the mode file cannot follow.
        store.set_trusted_devices_mode(false).unwrap();
        assert!(!dir.open().switches().unwrap().trusted_devices_mode);
        // Damaged now: the mode file is unusable, so strict — never observe by accident.
        dir.damage();
        let _ = store.reopen();
        assert!(store.is_damaged());
        assert_eq!(store.damaged_mode(), None);
        // The mode file as it was before the change (strict) gives strict too.
        dir.unblock_side();
        dir.set_side(true);
        let _ = store.reopen();
        assert_eq!(store.damaged_mode(), Some(true));
    }

    #[test]
    fn the_repairs_set_the_mode_file() {
        // A reset whose mode file can be neither written nor removed is refused (unreadable mode
        // file: strict, and strict must be written first), the damaged list left as it was.
        let dir = Scratch::new();
        let (store, _owner) = store_with_owner(&dir);
        drop(store);
        dir.damage();
        dir.block_side();
        let mut store = dir.open();
        assert_eq!(store.damaged_mode(), None);
        assert!(matches!(
            store.reset_to_empty(NOW),
            Err(StoreError::Write(w)) if w.starts_with("mode file")
        ));
        assert_eq!(std::fs::read(dir.primary()).unwrap(), b"garbage");
        assert!(store.is_damaged());
    }

    /// How the mode file of a damaged store is set up before a repair: `Some(on)` writes it,
    /// `None` removes it (unknown: strict).
    fn damaged_with_side(backup_strict: bool, side: Option<bool>) -> (Scratch, TrustStore) {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        if backup_strict {
            store.set_trusted_devices_mode(true).unwrap();
        }
        // One more write: the backup is the list with that switch.
        store
            .touch(owner.id(), NOW + 2 * LAST_USED_WRITE_AFTER_MS)
            .unwrap();
        let backup: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.backup()).unwrap()).unwrap();
        assert_eq!(
            backup["switches"]["trusted_devices_mode"],
            serde_json::Value::Bool(backup_strict)
        );
        drop(store);
        dir.damage();
        match side {
            Some(on) => dir.set_side(on),
            None => std::fs::remove_file(dir.mode()).unwrap(),
        }
        let store = dir.open();
        assert_eq!(store.damaged_mode(), side);
        (dir, store)
    }

    /// A restore and a reset keep the switch the window showed
    /// («Переключатель … останется как есть») — the damaged store's mode file, strict when it says
    /// nothing — in the list and in the mode file; never the backup's switch, in either direction.
    #[test]
    fn the_repairs_keep_the_effective_switch_not_the_backups() {
        // (the backup's switch, the mode file, the switch after)
        let cases = [
            (false, Some(true), true),
            (true, Some(false), false),
            (false, None, true),
            (true, Some(true), true),
            (false, Some(false), false),
        ];
        for (backup_strict, side, want) in cases {
            let why = format!("backup strict {backup_strict}, mode file {side:?}");
            let (dir, mut store) = damaged_with_side(backup_strict, side);
            let _ = store.restore_from_backup(NOW + 9).unwrap();
            assert_eq!(
                store.switches().unwrap().trusted_devices_mode,
                want,
                "restore: {why}"
            );
            assert_eq!(dir.side(), Side::Says(want), "restore: {why}");
            let reopened = dir.open();
            assert!(!reopened.is_damaged(), "restore: {why}");
            assert_eq!(
                reopened.switches().unwrap().trusted_devices_mode,
                want,
                "restore on disk: {why}"
            );

            let (dir, mut store) = damaged_with_side(backup_strict, side);
            store.reset_to_empty(NOW + 9).unwrap();
            assert_eq!(
                store.switches().unwrap().trusted_devices_mode,
                want,
                "reset: {why}"
            );
            assert_eq!(dir.side(), Side::Says(want), "reset: {why}");
            assert_eq!(
                dir.open().switches().unwrap().trusted_devices_mode,
                want,
                "reset on disk: {why}"
            );
        }
    }

    // --- At-PC repairs --------------------------------------------------------------------------

    fn kept_files(dir: &Scratch) -> Vec<(String, Vec<u8>)> {
        let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(DAMAGED_FILE_PREFIX)
            })
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();
        out.sort();
        out
    }

    /// «Удалить» B is pressed (`pc`, decided at once), then the server removes B — its person
    /// (a `server` carry, which never takes a `pc` one's place), or the key alone (a removal
    /// that stages after the press and builds B's tombstone `server` itself). The press's origin
    /// wins in the write (and the install then clears the carry): B is `pc` in memory and on
    /// disk — the origin the window's date line reads (a removal decided at this PC).
    #[test]
    fn a_server_removal_staged_after_a_pc_press_writes_the_key_pc() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let _owner = add_paired(&mut store, 1, BindingRole::Owner);
        let b = add_paired(&mut store, 2, BindingRole::Guest);
        let c = add_paired(&mut store, 3, BindingRole::Guest);
        assert_eq!(
            store.deny_tree_now(b.id(), NOW + 1).unwrap().removed,
            vec![b.id().clone()]
        );
        assert_eq!(
            store.deny_guest_keys_now(2, Removal::Server, NOW + 2),
            Ok((vec![b.id().clone()], 0))
        );
        assert_eq!(store.flush(), Ok(true));
        for s in [&store, &dir.open()] {
            assert_eq!(removed_origin(s, b.id()), Origin::Pc, "person");
            assert_eq!(removed(s, b.id()).at, NOW + 1, "the press's time");
        }
        assert_eq!(
            store.deny_tree_now(c.id(), NOW + 3).unwrap().removed,
            vec![c.id().clone()]
        );
        store.remove(c.id(), Removal::Server, NOW + 4).unwrap();
        for s in [&store, &dir.open()] {
            assert_eq!(removed_origin(s, c.id()), Origin::Pc, "key");
        }
        // Never the other way: a `pc` removal stays `pc` under a carried `server` one.
        let d = add_paired(&mut store, 4, BindingRole::Guest);
        store.deny_now(std::slice::from_ref(d.id()));
        store.carry_removal(std::slice::from_ref(d.id()), Removal::Server, NOW + 5);
        store.remove(d.id(), Removal::Pc, NOW + 6).unwrap();
        assert_eq!(removed_origin(&dir.open(), d.id()), Origin::Pc);
    }

    /// A carried `server` removal of an owner-role record (design §8: the PC never applies
    /// an owner's removal from the server) is withdrawn where it is made: the key is not denied,
    /// no write carries it and none is due for it (quiet, not a write and a journal line on
    /// every flush); the key stays active through the next write. A `pc` one is written as
    /// usual.
    #[test]
    fn a_carried_server_removal_never_takes_an_owner_key() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        store.deny_now(std::slice::from_ref(owner.id()));
        store.carry_removal(std::slice::from_ref(owner.id()), Removal::Server, NOW + 1);
        assert!(matches!(store.lookup(owner.id()), Lookup::Active(_)));
        assert_eq!(store.removal_decided(owner.id()), None);
        assert!(store.carried_now().is_empty());
        assert!(store.pending_without_removal().is_empty());
        assert_eq!(store.flush(), Ok(false), "no write is due for it");
        let _unrelated = add_paired(&mut store, 7, BindingRole::Guest);
        assert!(
            matches!(dir.open().lookup(owner.id()), Lookup::Active(_)),
            "the owner's key stays on disk"
        );
        assert!(store
            .keys()
            .unwrap()
            .iter()
            .any(|r| r.key_id() == owner.id()));
        store.carry_removal(std::slice::from_ref(owner.id()), Removal::Pc, NOW + 2);
        let _another = add_paired(&mut store, 8, BindingRole::Guest);
        assert_eq!(removed_origin(&dir.open(), owner.id()), Origin::Pc);
    }

    /// A note the file's parser would refuse never reaches memory's notes — an attempt of a user
    /// id out of range (`binding_added` with uid 0 from the server) is ignored, so every later
    /// write still passes its own check.
    #[test]
    fn notes_out_of_range_are_never_taken() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        store.flush().unwrap();
        for uid in [0, -1, MAX_USER_ID + 1] {
            assert!(!store.knows_person(uid, false), "{uid}");
            let tried = Device::new();
            assert!(
                !store.note_attempt(
                    super::Attempt {
                        telegram_user_id: uid,
                        role: BindingRole::Guest,
                        key: tried.new_key().key,
                        kind: kind("telegram"),
                        platform: platform("android"),
                        rpk: None,
                        first_at: NOW,
                        last_at: NOW,
                        count: 1,
                    },
                    NOW + 1,
                ),
                "{uid}"
            );
        }
        assert!(!store.notes_unsaved(), "nothing taken");
        // A repeated attempt with the clock set back (before its first try): still writable.
        let tried = Device::new();
        for at in [NOW + 100, NOW + 50] {
            let _ = store.note_attempt(
                super::Attempt {
                    telegram_user_id: 8,
                    role: BindingRole::Guest,
                    key: tried.new_key().key,
                    kind: kind("telegram"),
                    platform: platform("android"),
                    rpk: None,
                    first_at: at,
                    last_at: at,
                    count: 1,
                },
                at,
            );
        }
        assert!(store.flush().unwrap(), "the attempt is written");
        let mut written = dir.open();
        written.set_wall_now(NOW + 100);
        assert_eq!(written.attempts().len(), 1);
    }

    /// §10.1 «Нажатие решает сразу» across a reopen: notes decided in memory and not yet written
    /// (the write failed) survive a reopen of the unchanged file. A reopen onto a damaged primary
    /// keeps nothing of them nor of the removals decided and not yet written (the keys denied
    /// and carried), and the damaged list takes no removal step and no
    /// stored list (§10 «Повреждённый список»). A restore then brings the key back working:
    /// nothing replays. Refutes a damaged list that changes or remembers trust state.
    #[test]
    fn notes_decided_in_memory_survive_a_reopen_and_a_damaged_list_keeps_none() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        store.flush().unwrap();
        let on_disk = std::fs::read(dir.primary()).unwrap();
        assert!(store.person_removed(5, "test"));
        let token = store.grant_token();
        assert!(store.notes_unsaved());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), on_disk);
        let _ = store.reopen();
        assert_eq!(store.grant_token(), token, "memory's new token survives");
        assert!(store.notes_unsaved());
        assert_eq!(
            store.deny_tree_now(owner.id(), NOW + 10).unwrap().removed,
            vec![owner.id().clone()]
        );
        assert_eq!(store.removal_decided(owner.id()), Some("pc"));
        std::fs::write(dir.primary(), b"garbage").unwrap();
        let _ = store.reopen();
        assert!(store.is_damaged());
        assert_eq!(store.grant_token(), None, "nothing kept while damaged");
        assert_eq!(
            store.removal_decided(owner.id()),
            None,
            "the unwritten removal is lost with memory"
        );
        assert!(
            !store.person_removed(6, "test"),
            "no removal step while damaged"
        );
        assert!(!store.note_last_bindings([KnownBinding {
            telegram_user_id: 6,
            role: BindingRole::Guest,
        }]));
        assert_eq!(store.last_bindings(), None);
        assert!(!store.knows_person(6, false));
        let _ = store.restore_from_backup(NOW + 12).unwrap();
        assert!(matches!(store.lookup(owner.id()), Lookup::Active(_)));
        assert_eq!(store.removal_decided(owner.id()), None);
    }

    /// The reload's merge of the grant token (§7), the notes as last written the base: memory's
    /// when memory replaced it since the write, else the file's. A second reload keeps comparing
    /// against the file as loaded, and the next write holds the merge.
    #[test]
    fn a_reload_merges_the_grant_token_over_the_last_write() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        assert!(store.person_removed(4, "test"));
        store.flush().unwrap();
        let written = store.grant_token().unwrap();
        // Another writer: a removal there (a new token in the file).
        let file_token = {
            let mut other = dir.open();
            assert!(other.person_removed(19, "test"));
            other.flush().unwrap();
            other.grant_token().unwrap()
        };
        assert_ne!(file_token, written);
        // Memory, not written: a removal here.
        assert!(store.person_removed(8, "test"));
        let memory_token = store.grant_token().unwrap();
        assert!(memory_token != written && memory_token != file_token);
        let _ = store.reopen();
        assert_eq!(
            store.grant_token(),
            Some(memory_token),
            "memory replaced it"
        );
        assert_eq!(store.saved_grant_token(), Some(file_token));
        let _ = store.reopen();
        assert_eq!(store.grant_token(), Some(memory_token));
        assert!(store.flush().unwrap());
        assert_eq!(dir.open().grant_token(), Some(memory_token));
        // Memory did not replace the token since this write: a reload takes the file's.
        let other_token = {
            let mut other = dir.open();
            assert!(other.person_removed(21, "test"));
            other.flush().unwrap();
            other.grant_token().unwrap()
        };
        let _ = store.reopen();
        assert_eq!(store.grant_token(), Some(other_token), "the file's");
        assert_eq!(store.saved_grant_token(), Some(other_token));
    }

    /// §7 «Токен выдачи», one unsaved window: removals of two different people before any write
    /// lands replace the token once; a grant signed over the saved token (the one the server last
    /// heard) is `grant_stale` for anyone, and one over the new token goes in before that token is
    /// written; the saved token — the only one the server may hear — moves only when a write
    /// lands; a removal after that replaces it again. Refutes a token replaced per removal (one the
    /// server never hears), and old grants that pass until the write.
    #[test]
    fn two_removals_before_a_write_replace_the_token_once() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        let saved = store.saved_grant_token().unwrap();
        assert_eq!(store.grant_token(), Some(saved));
        assert!(store.person_removed(5, "test"));
        let token = store.grant_token().unwrap();
        assert_ne!(token, saved);
        assert!(store.person_removed(6, "test"));
        assert_eq!(store.grant_token(), Some(token), "one new token for both");
        assert_eq!(
            store.saved_grant_token(),
            Some(saved),
            "not heard before a write"
        );
        for (n, uid) in [(40, 20), (41, 21)] {
            assert_eq!(
                store.add(
                    Device::new().new_key(),
                    over(grant(owner.id(), n, uid, None), saved),
                    NOW + 3
                ),
                Err(StoreError::GrantStale),
                "{uid}"
            );
        }
        assert_eq!(store.saved_grant_token(), Some(saved));
        store
            .add(
                Device::new().new_key(),
                over(grant(owner.id(), 42, 22, None), token),
                NOW + 3,
            )
            .unwrap();
        assert_eq!(
            store.saved_grant_token(),
            Some(token),
            "written with that add"
        );
        assert_eq!(dir.open().grant_token(), Some(token));
        assert!(store.person_removed(7, "test"));
        let third = store.grant_token().unwrap();
        assert!(third != token && third != saved, "replaced again");
    }

    /// §7: the grant token's value is in no log line and no printed value — at a rotation, a
    /// write, a reload that takes the file's and one that keeps memory's, a grant refused
    /// `grant_stale`, a file whose token is malformed (the damage's text) — nor in `{:?}` of the
    /// notes, the list, a grant ground or the token itself.
    #[test]
    fn the_grant_token_is_never_logged_nor_printed() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        let mut tokens = Vec::new();
        let mut printed = String::new();
        let log = logged(|| {
            assert!(store.person_removed(5, "test"));
            tokens.push(store.grant_token().unwrap());
            assert!(store.flush().unwrap());
            let file_token = {
                let mut other = dir.open();
                assert!(other.person_removed(6, "test"));
                other.flush().unwrap();
                other.grant_token().unwrap()
            };
            tokens.push(file_token);
            let _ = store.reopen();
            assert_eq!(store.grant_token(), Some(file_token), "the file's");
            assert!(store.person_removed(7, "test"));
            tokens.push(store.grant_token().unwrap());
            {
                let mut other = dir.open();
                assert!(other.person_removed(8, "test"));
                other.flush().unwrap();
                tokens.push(other.grant_token().unwrap());
            }
            let _ = store.reopen();
            assert_eq!(store.grant_token(), Some(tokens[2]), "memory's");
            let stale = over(grant(owner.id(), 40, 20, None), file_token);
            printed.push_str(&format!("{stale:?}"));
            assert_eq!(
                store.add(Device::new().new_key(), stale, NOW + 5),
                Err(StoreError::GrantStale)
            );
            assert!(store.flush().unwrap());
            if let State::Ready(list) = &store.state {
                printed.push_str(&format!("{:?} {list:?}", list.notes));
            }
            printed.push_str(&format!("{:?} {:?}", store.grant_token(), tokens));
            // The written token with a character more: the damage must not quote it.
            let bad = format!("{}A", tokens[2].to_wire());
            edit_primary(&dir, |v| v["grant_token"] = bad.into());
            let damaged = dir.open();
            printed.push_str(&damaged.damage().expect("damaged").to_string());
        });
        assert!(log.contains("the grant token replaced"), "{log}");
        assert!(log.contains("the file's grant token taken"), "{log}");
        assert!(log.contains("memory's grant token kept"), "{log}");
        assert!(printed.contains("grant token not of its form"), "{printed}");
        for t in &tokens {
            let text = t.to_wire();
            assert_eq!(text.len(), 22);
            assert!(!log.contains(&text), "logged: {log}");
            assert!(!printed.contains(&text), "printed: {printed}");
        }
    }

    /// An attempt of `uid` with `d`'s key, tried at `at`.
    fn attempt_of(uid: i64, d: &Device, at: i64) -> super::Attempt {
        super::Attempt {
            telegram_user_id: uid,
            role: BindingRole::Guest,
            key: d.new_key().key,
            kind: kind("telegram"),
            platform: platform("android"),
            rpk: None,
            first_at: at,
            last_at: at,
            count: 1,
        }
    }

    /// §10: a person's removal drops their attempts in memory; a reopen of the file written
    /// before it (it still has them) never brings them back — memory's notes are kept over the
    /// file's, and the attempts the removal dropped are not the file's to add. Another person's
    /// attempt stays; the next write and a fresh process have none of the removed person's.
    #[test]
    fn a_reopen_never_brings_back_attempts_a_removal_dropped() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let now = crate::journal::now_ms();
        let (tried, other) = (Device::new(), Device::new());
        assert!(store.note_attempt(attempt_of(5, &tried, now), now));
        assert!(store.note_attempt(attempt_of(6, &other, now), now));
        assert!(store.flush().unwrap());
        assert!(store.person_removed(5, "test"));
        assert!(
            store.attempt(5, tried.id()).is_none(),
            "the removal dropped it"
        );
        let _ = store.reopen();
        assert!(
            store.attempt(5, tried.id()).is_none(),
            "the reopen brought it back"
        );
        assert!(store.attempt(6, other.id()).is_some(), "another's stays");
        assert!(store.flush().unwrap());
        let fresh = dir.open();
        assert!(fresh.attempt(5, tried.id()).is_none());
        assert!(fresh.attempt(6, other.id()).is_some());
    }

    /// The lines of `src` where a string literal holds a run of 8+ spaces between words: a
    /// multi-line literal whose `\` line continuation was lost (rustfmt joins the next line's
    /// indentation into the text). Counted by the quotes before the run on the same line.
    fn lost_continuations(src: &str) -> Vec<usize> {
        let mut found = Vec::new();
        for (n, line) in src.lines().enumerate() {
            let b = line.as_bytes();
            let mut quotes = 0usize;
            let mut i = 0;
            while i < b.len() {
                match b[i] {
                    b'\\' => i += 1,
                    b'"' => quotes += 1,
                    b' ' if quotes % 2 == 1 && i > 0 && b[i - 1] != b' ' => {
                        let run = b[i..].iter().take_while(|&&c| c == b' ').count();
                        if run >= 8 && i + run < b.len() && b[i + run] != b'"' {
                            found.push(n + 1);
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        found
    }

    /// No log literal in the keys code lost its `\` continuation — the
    /// message would carry a run of spaces. The checker itself catches such a line.
    #[test]
    fn no_log_literal_lost_its_line_continuation() {
        let broken = format!("    \"has{}none: not recorded\"", " ".repeat(18));
        assert_eq!(lost_continuations(&broken), vec![1], "the checker");
        let joined = format!("    \"has \\\n{}none\"", " ".repeat(17));
        assert!(lost_continuations(&joined).is_empty(), "a continuation");
        for (name, src) in [
            ("viewer_keys/store.rs", include_str!("store.rs")),
            ("viewer_keys/mod.rs", include_str!("mod.rs")),
            ("trusted.rs", include_str!("../trusted.rs")),
            ("admission/mod.rs", include_str!("../admission/mod.rs")),
            ("agent.rs", include_str!("../agent.rs")),
            ("journal.rs", include_str!("../journal.rs")),
        ] {
            assert_eq!(lost_continuations(src), Vec::<usize>::new(), "{name}");
        }
    }

    /// §10.2: the file has A–D of person 7; memory repeated B and noted E, which evicted A
    /// (the per-person cap), not yet written. A reopen merges per (person, key) — B keeps memory's
    /// fresher last try and count — and keeps the cap: A stays out, E is in, at most 4 of 7, and
    /// the next write succeeds (its own parse check would refuse a fifth).
    #[test]
    fn a_reopen_merges_attempts_per_key_and_keeps_the_per_person_cap() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let mut at = crate::journal::now_ms();
        let file = try_fresh(&mut store, 7, 4, &mut at);
        assert!(store.flush().unwrap());
        let b_at = at + 10;
        assert_eq!(
            store.note_attempt_how(attempt_of(7, &file[1], b_at), b_at),
            AttemptNoted::Repeated
        );
        at = b_at + 1;
        let e = try_fresh(&mut store, 7, 1, &mut at).remove(0);
        assert!(store.attempt(7, file[0].id()).is_none(), "E evicted A");
        assert!(store.notes_unsaved());
        let _ = store.reopen();
        let want: Vec<(i64, KeyId)> = [&file[1], &file[2], &file[3], &e]
            .iter()
            .map(|d| (7, d.id().clone()))
            .collect();
        let mut got = attempt_ids(&store);
        got.sort_by(|a, b| a.1.cmp(&b.1));
        let mut want_sorted = want.clone();
        want_sorted.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(got, want_sorted, "after the reopen: B–E of 7, A not back");
        let b = store.attempt(7, file[1].id()).unwrap();
        assert_eq!((b.last_at, b.count), (b_at, 2), "B: memory's fresher try");
        assert!(store.flush().unwrap(), "the next write succeeds");
        let fresh = dir.open();
        let mut got = attempt_ids(&fresh);
        got.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(got, want_sorted, "a fresh process");
        let b = fresh.attempt(7, file[1].id()).unwrap();
        assert_eq!((b.last_at, b.count), (b_at, 2));
    }

    /// §10.2: the file has 64 attempts; memory noted a 65th, which evicted one (the cap in
    /// all), not yet written. A reopen keeps 64 by the same rule — the evicted one stays out, the
    /// newcomer stays in — and the next write succeeds.
    #[test]
    fn a_reopen_merges_attempts_and_keeps_the_cap_in_all() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let mut at = crate::journal::now_ms();
        let first = try_fresh(&mut store, 100, 1, &mut at).remove(0);
        for uid in 101..164 {
            try_fresh(&mut store, uid, 1, &mut at);
        }
        assert_eq!(store.attempts().len(), ATTEMPTS_MAX);
        assert!(store.flush().unwrap());
        let newcomer = try_fresh(&mut store, 500, 1, &mut at).remove(0);
        assert!(store.attempt(100, first.id()).is_none(), "the oldest went");
        let _ = store.reopen();
        assert_eq!(store.attempts().len(), ATTEMPTS_MAX, "after the reopen");
        assert!(store.attempt(500, newcomer.id()).is_some(), "the newcomer");
        assert!(
            store.attempt(100, first.id()).is_none(),
            "the evicted one back"
        );
        assert!(store.flush().unwrap(), "the next write succeeds");
        let fresh = dir.open();
        assert_eq!(fresh.attempts().len(), ATTEMPTS_MAX);
        assert!(fresh.attempt(500, newcomer.id()).is_some());
    }

    /// §10.2: a reload's merge holds an attempt of a key the file has entered at that
    /// same person beside a full per-person cap. The entered one goes and takes no place; the
    /// attempt it had pushed out in memory stays out (memory dropped it since the last write:
    /// the merge's three-way rule against the last write does not bring it back).
    #[test]
    fn a_reload_drops_entered_attempts_before_the_caps() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let mut at = crate::journal::now_ms();
        let file = try_fresh(&mut store, 7, 3, &mut at);
        assert!(store.flush().unwrap());
        let d = try_fresh(&mut store, 7, 1, &mut at).remove(0);
        let e = try_fresh(&mut store, 7, 1, &mut at).remove(0);
        assert!(
            store.attempt(7, file[0].id()).is_none(),
            "E pushed A out in memory"
        );
        assert!(store.notes_unsaved());
        // Another process lets E in at person 7 (the file still has A, B, C).
        let mut other = dir.open();
        other
            .add(e.new_key(), pair(7, BindingRole::Guest), NOW)
            .unwrap();
        drop(other);
        let _ = store.reopen();
        let mut got = attempt_ids(&store);
        got.sort_by(|a, b| a.1.cmp(&b.1));
        let mut want: Vec<(i64, KeyId)> = [&file[1], &file[2], &d]
            .iter()
            .map(|x| (7, x.id().clone()))
            .collect();
        want.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(
            got, want,
            "B–D of 7: E entered and took no place, A stays out"
        );
        assert!(store.flush().unwrap(), "the next write succeeds");
        let mut fresh = attempt_ids(&dir.open());
        fresh.sort_by(|a, b| a.1.cmp(&b.1));
        assert_eq!(fresh, want, "a fresh process");
    }

    /// The attempts as memory has them: (person, key), in list order.
    fn attempt_ids(store: &TrustStore) -> Vec<(i64, KeyId)> {
        store
            .attempts()
            .iter()
            .map(|a| (a.telegram_user_id, a.key_id().clone()))
            .collect()
    }

    /// Note `n` fresh-key attempts of `uid`, one ms apart from `*at` on.
    fn try_fresh(store: &mut TrustStore, uid: i64, n: usize, at: &mut i64) -> Vec<Device> {
        (0..n)
            .map(|_| {
                let d = Device::new();
                let _ = store.note_attempt(attempt_of(uid, &d, *at), *at);
                *at += 1;
                d
            })
            .collect()
    }

    /// §10.2: attempts are evicted by age only — the 65th in all evicts the oldest last try,
    /// whoever's it is: a person with an active key here (once spared) loses theirs like anyone.
    #[test]
    fn attempts_full_evicts_the_oldest_whoever_it_is() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let _key = add_paired(&mut store, 2, BindingRole::Guest);
        let mut at = crate::journal::now_ms();
        let oldest = try_fresh(&mut store, 2, 1, &mut at).remove(0);
        for uid in 100..163 {
            try_fresh(&mut store, uid, 1, &mut at);
        }
        let before = attempt_ids(&store);
        assert_eq!(before.len(), ATTEMPTS_MAX);
        let newcomer = Device::new();
        assert_eq!(
            store.note_attempt_how(attempt_of(1000, &newcomer, at), at),
            AttemptNoted::New,
            "the 65th is recorded"
        );
        let mut want: Vec<(i64, KeyId)> = before[1..].to_vec();
        want.push((1000, newcomer.id().clone()));
        assert_eq!(attempt_ids(&store), want, "the oldest went");
        assert!(store.attempt(2, oldest.id()).is_none());
    }

    /// §10.2: the per-person cap of 4 comes first — at 64 in all, a person's fifth
    /// key evicts that person's own oldest attempt, with a key here or not, and nobody else's.
    #[test]
    fn the_per_person_cap_comes_before_the_cap_in_all() {
        for traced in [false, true] {
            let dir = Scratch::new();
            let (mut store, _owner) = store_with_owner(&dir);
            if traced {
                let _key = add_paired(&mut store, 2, BindingRole::Guest);
            }
            let mut at = crate::journal::now_ms();
            for uid in 100..115 {
                try_fresh(&mut store, uid, 4, &mut at);
            }
            let mine = try_fresh(&mut store, 2, 4, &mut at);
            let before = attempt_ids(&store);
            assert_eq!(before.len(), ATTEMPTS_MAX);
            let fifth = try_fresh(&mut store, 2, 1, &mut at).remove(0);
            let mut want: Vec<(i64, KeyId)> = before
                .into_iter()
                .filter(|(_, k)| k != mine[0].id())
                .collect();
            want.push((2, fifth.id().clone()));
            assert_eq!(attempt_ids(&store), want, "traced: {traced}");
        }
    }

    /// §10.2: a key entering the list drops only the SAME person's attempts with
    /// it; another person's attempt with that key stays — through the write, its removal and a
    /// reopen.
    #[test]
    fn a_key_entering_drops_only_its_own_persons_attempt() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let at = crate::journal::now_ms();
        let k = Device::new();
        assert!(store.note_attempt(attempt_of(5, &k, at), at));
        assert!(store.note_attempt(attempt_of(6, &k, at + 1), at + 1));
        store
            .add(k.new_key(), pair(5, BindingRole::Guest), NOW)
            .unwrap();
        assert!(
            store.attempt(5, k.id()).is_none(),
            "the entering person's goes"
        );
        assert!(store.attempt(6, k.id()).is_some(), "another person's stays");
        assert!(dir.open().attempt(6, k.id()).is_some(), "written");
        store.remove(k.id(), Removal::Pc, NOW + 1).unwrap();
        assert!(
            store.attempt(6, k.id()).is_some(),
            "the key's removal keeps it"
        );
        let _ = store.reopen();
        assert!(store.attempt(6, k.id()).is_some(), "the reopen keeps it");
    }

    #[test]
    fn restore_from_backup_takes_only_a_good_backup_and_keeps_the_damaged_file() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        assert_eq!(store.restore_from_backup(NOW), Err(StoreError::NotDamaged));

        std::fs::write(dir.primary(), b"garbage").unwrap();
        let backup = std::fs::read(dir.backup()).unwrap();
        std::fs::write(dir.backup(), b"{\"version\":1").unwrap();
        let mut store = dir.open();
        assert!(matches!(
            store.restore_from_backup(NOW),
            Err(StoreError::BackupUnusable(_))
        ));
        assert_denies(&store, owner.id());
        std::fs::write(dir.backup(), &backup).unwrap();
        let backup_token = parse_list(&backup).unwrap().notes.grant_token;
        let reloaded = store.restore_from_backup(NOW + 7).unwrap();
        // Every key of the restored list joined.
        assert_eq!(reloaded.joined_active, vec![owner.id().clone()]);
        assert!(reloaded.left_active.is_empty() && !reloaded.damaged);
        active(&store, owner.id());
        // The backup's list, written again with a new grant token in the same write (§7): a
        // grant over the backup's token is stale.
        let written = parse_list(&std::fs::read(dir.primary()).unwrap()).unwrap();
        let mut from_backup = parse_list(&backup).unwrap();
        let token = store.grant_token().unwrap();
        assert!(token != backup_token && !token.is_empty());
        assert_eq!(written.notes.grant_token, token);
        from_backup.notes.grant_token = token;
        assert_eq!(written, from_backup);
        assert_eq!(
            store.grant_token_current(&backup_token),
            Err(StoreError::GrantStale)
        );
        // The damaged primary was kept first.
        assert_eq!(
            kept_files(&dir),
            vec![(
                format!("{DAMAGED_FILE_PREFIX}{}", NOW + 7),
                b"garbage".to_vec()
            )]
        );
        // The restored store writes on: its view of the disk is the restored bytes.
        store
            .touch(owner.id(), NOW + 2 * LAST_USED_WRITE_AFTER_MS)
            .unwrap();
        let reopened = dir.open();
        assert!(!reopened.is_damaged());
        active(&reopened, owner.id());

        std::fs::write(dir.primary(), b"garbage").unwrap();
        std::fs::remove_file(dir.backup()).unwrap();
        let mut store = dir.open();
        assert!(matches!(
            store.restore_from_backup(NOW),
            Err(StoreError::BackupUnusable(_))
        ));
    }

    #[test]
    fn a_reset_is_refused_over_a_newer_backup() {
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        // The primary is broken; the backup is a newer build's.
        std::fs::write(dir.primary(), b"garbage").unwrap();
        let mut backup: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.backup()).unwrap()).unwrap();
        backup["version"] = (FORMAT_VERSION + 1).into();
        std::fs::write(dir.backup(), serde_json::to_vec(&backup).unwrap()).unwrap();
        let newer_backup = std::fs::read(dir.backup()).unwrap();
        let mut store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::NotParsable);
        // Upgrade, do not wipe what the newer backup holds.
        assert_eq!(store.reset_to_empty(NOW), Err(StoreError::NewerVersion));
        assert!(!store.is_busy() && !store.needs_reopen());
        assert_denies(&store, owner.id());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), b"garbage");
        assert_eq!(std::fs::read(dir.backup()).unwrap(), newer_backup);
        assert!(kept_files(&dir).is_empty());
    }

    #[test]
    fn restore_and_reset_are_refused_over_a_newer_version() {
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        // A newer build wrote both files.
        edit_primary(&dir, |v| v["version"] = (FORMAT_VERSION + 1).into());
        let mut backup: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.backup()).unwrap()).unwrap();
        backup["version"] = (FORMAT_VERSION + 1).into();
        std::fs::write(dir.backup(), serde_json::to_vec(&backup).unwrap()).unwrap();
        let newer = std::fs::read(dir.primary()).unwrap();
        let newer_backup = std::fs::read(dir.backup()).unwrap();
        let mut store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::NewerVersion);
        assert_eq!(
            store.restore_from_backup(NOW),
            Err(StoreError::NewerVersion)
        );
        // Upgrade, do not wipe.
        assert_eq!(store.reset_to_empty(NOW), Err(StoreError::NewerVersion));
        assert!(!store.is_busy());
        assert_denies(&store, owner.id());
        // Nothing touched: the newer files stand, nothing kept aside.
        assert_eq!(std::fs::read(dir.primary()).unwrap(), newer);
        assert_eq!(std::fs::read(dir.backup()).unwrap(), newer_backup);
        assert!(kept_files(&dir).is_empty());
    }

    #[test]
    fn reopen_after_unreadable_and_no_repair_for_it() {
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        let good = std::fs::read(dir.primary()).unwrap();
        // A directory where the file should be: opening or reading it fails, on Windows and Unix.
        std::fs::remove_file(dir.primary()).unwrap();
        std::fs::create_dir(dir.primary()).unwrap();
        let mut store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::Unreadable);
        assert_denies(&store, owner.id());
        assert_eq!(store.restore_from_backup(NOW), Err(StoreError::Unreadable));
        assert_eq!(store.reset_to_empty(NOW), Err(StoreError::Unreadable));
        assert!(kept_files(&dir).is_empty());
        let reloaded = store.reopen();
        assert!(reloaded.damaged && reloaded.left_active.is_empty());
        assert_eq!(store.damage().unwrap().kind, DamageKind::Unreadable);
        // It passes: the keys come back as joined.
        std::fs::remove_dir(dir.primary()).unwrap();
        std::fs::write(dir.primary(), &good).unwrap();
        let reloaded = store.reopen();
        assert_eq!(reloaded.joined_active, vec![owner.id().clone()]);
        assert!(!reloaded.damaged);
        assert!(!store.is_damaged());
        active(&store, owner.id());
        let d = Device::new();
        store
            .add(d.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
    }

    /// A repair (restore or reset) writes only over the damaged primary this store loaded. Another
    /// process (the CLI opens the store too) that repaired it, damaged it otherwise, put a newer
    /// version there or removed it meanwhile wins: the repair is refused `changed_on_disk`, the
    /// file stays, and the store takes what is there now. Over exactly the bytes it loaded, the
    /// repair goes on.
    #[test]
    fn restore_and_reset_refuse_a_primary_changed_since_the_load() {
        fn repair(store: &mut TrustStore, how: &str, now: i64) -> Result<(), StoreError> {
            match how {
                "restore" => store.restore_from_backup(now).map(|_| ()),
                _ => store.reset_to_empty(now).map(|_| ()),
            }
        }
        for how in ["restore", "reset"] {
            let dir = Scratch::new();
            let (_, owner) = store_with_owner(&dir);
            let good = std::fs::read(dir.primary()).unwrap();

            // Repaired by another process meanwhile: a healthy list now.
            std::fs::write(dir.primary(), b"garbage").unwrap();
            let mut store = dir.open();
            assert!(store.is_damaged());
            let mut other = dir.open();
            let _ = other.restore_from_backup(NOW).unwrap();
            let healthy = std::fs::read(dir.primary()).unwrap();
            assert_eq!(
                repair(&mut store, how, NOW + 1),
                Err(StoreError::ChangedOnDisk),
                "{how}: repaired meanwhile"
            );
            assert_eq!(std::fs::read(dir.primary()).unwrap(), healthy, "{how}");
            assert!(
                !store.is_damaged(),
                "{how}: the store took the repaired file"
            );
            active(&store, owner.id());

            // Damaged otherwise meanwhile.
            std::fs::write(dir.primary(), b"garbage").unwrap();
            let mut store = dir.open();
            std::fs::write(dir.primary(), b"other garbage").unwrap();
            let kept_before = kept_files(&dir).len();
            assert_eq!(
                repair(&mut store, how, NOW + 2),
                Err(StoreError::ChangedOnDisk),
                "{how}: other damage"
            );
            assert_eq!(std::fs::read(dir.primary()).unwrap(), b"other garbage");
            assert_eq!(
                kept_files(&dir).len(),
                kept_before,
                "{how}: nothing kept aside"
            );
            assert_denies(&store, owner.id());

            // A newer version meanwhile: never overwritten.
            let mut newer: serde_json::Value = serde_json::from_slice(&good).unwrap();
            newer["version"] = (FORMAT_VERSION + 1).into();
            let newer = serde_json::to_vec(&newer).unwrap();
            std::fs::write(dir.primary(), &newer).unwrap();
            assert_eq!(
                repair(&mut store, how, NOW + 3),
                Err(StoreError::ChangedOnDisk),
                "{how}: newer version"
            );
            assert_eq!(std::fs::read(dir.primary()).unwrap(), newer);
            assert_eq!(store.damage().unwrap().kind, DamageKind::NewerVersion);

            // Loaded with no primary (its backup there); one appears meanwhile.
            std::fs::remove_file(dir.primary()).unwrap();
            let mut store = dir.open();
            assert_eq!(store.damage().unwrap().kind, DamageKind::PrimaryMissing);
            std::fs::write(dir.primary(), b"garbage").unwrap();
            assert_eq!(
                repair(&mut store, how, NOW + 4),
                Err(StoreError::ChangedOnDisk),
                "{how}: a primary appeared"
            );
            assert_eq!(std::fs::read(dir.primary()).unwrap(), b"garbage");

            // The store reloaded the garbage it now sees: over exactly those bytes it repairs.
            assert!(store.is_damaged());
            repair(&mut store, how, NOW + 5).unwrap();
            assert!(!store.is_damaged(), "{how}: repaired");
            assert_ne!(std::fs::read(dir.primary()).unwrap(), b"garbage");
        }
    }

    #[test]
    fn reset_of_a_damaged_store_carries_over_the_backup_and_keeps_the_switch() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = Device::new();
        store
            .add(
                guest.new_key(),
                grant(owner.id(), 1, 2, Some((2, owner.id()))),
                NOW,
            )
            .unwrap();
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 3), NOW)
            .unwrap();
        store.remove(laptop.id(), Removal::Pc, NOW).unwrap();
        store
            .take_first_use_snapshot(snapshot_of(&[(1, BindingRole::Owner)]), NOW)
            .unwrap();
        assert!(!store.switches().unwrap().trusted_devices_mode);
        // The backup is the list before the snapshot: owner and guest active, laptop removed.
        let backup = std::fs::read(dir.backup()).unwrap();
        std::fs::write(dir.primary(), b"garbage").unwrap();
        let mut store = dir.open();
        // Its mode file says observe (written with the list): the reset keeps it.
        assert_eq!(store.damaged_mode(), Some(false));
        let out = store.reset_to_empty(NOW + 5).unwrap();
        assert!(out.is_empty(), "no key was active in a damaged store");
        assert!(!store.is_damaged());
        assert!(store.keys().unwrap().is_empty());
        assert!(!store.switches().unwrap().trusted_devices_mode);
        // The backup's active keys are tombstones `pc` now; its own tombstone stays.
        for k in [owner.id(), guest.id(), laptop.id()] {
            assert_eq!(removed_origin(&store, k), Origin::Pc);
        }
        assert_eq!(removed(&store, owner.id()).at, NOW + 5);
        // Its spent ids came along: no replay of the guest's grant or invitation.
        let (e, g, i) = store.spent().unwrap();
        assert!(e.contains(&gid(3)) && g.contains(&gid(1)) && i.contains(&gid(2)));
        // The backup had no snapshot yet.
        assert_eq!(store.first_use_snapshot().unwrap(), None);
        let kept = dir.0.join(format!("{DAMAGED_FILE_PREFIX}{}", NOW + 5));
        assert_eq!(std::fs::read(&kept).unwrap(), b"garbage");
        // The damaged primary did not go to the backup.
        assert_eq!(std::fs::read(dir.backup()).unwrap(), backup);
        let reopened = dir.open();
        assert_eq!(reopened.tombstones().unwrap(), store.tombstones().unwrap());
        assert!(!reopened.switches().unwrap().trusted_devices_mode);
        // A pairing at the PC is the way back.
        store
            .add(owner.new_key(), pair(1, BindingRole::Owner), NOW + 6)
            .unwrap();

        // A second reset in the same millisecond keeps the second file too; a backup that does
        // not load gives an empty list.
        std::fs::write(dir.primary(), b"garbage 2").unwrap();
        std::fs::write(dir.backup(), b"also garbage").unwrap();
        let mut store = dir.open();
        store.reset_to_empty(NOW + 5).unwrap();
        let kept2 = dir.0.join(format!("{DAMAGED_FILE_PREFIX}{}-1", NOW + 5));
        assert_eq!(std::fs::read(&kept2).unwrap(), b"garbage 2");
        assert_eq!(std::fs::read(&kept).unwrap(), b"garbage");
        assert!(store.keys().unwrap().is_empty());
        assert!(store.tombstones().unwrap().is_empty());
        assert!(!store.switches().unwrap().trusted_devices_mode);
        // No primary (only a backup, which loads): nothing to keep, the backup carried over.
        let dir = Scratch::new();
        let (_, owner) = store_with_owner(&dir);
        std::fs::remove_file(dir.primary()).unwrap();
        let mut store = dir.open();
        assert_eq!(store.damage().unwrap().kind, DamageKind::PrimaryMissing);
        store.reset_to_empty(NOW + 6).unwrap();
        assert!(!store.switches().unwrap().trusted_devices_mode);
        assert_eq!(removed_origin(&store, owner.id()), Origin::Pc);
        assert!(kept_files(&dir).is_empty());
    }

    #[test]
    fn reset_of_a_healthy_store_removes_every_key_and_keeps_the_rest() {
        for mode in [false, true] {
            let dir = Scratch::new();
            let (mut store, owner) = store_with_owner(&dir);
            store
                .take_first_use_snapshot(snapshot_of(&[(1, BindingRole::Owner)]), NOW)
                .unwrap();
            store.set_trusted_devices_mode(mode).unwrap();
            let tombs_before = store.tombstones().unwrap().len();
            let out = store.reset_to_empty(NOW + 1).unwrap();
            assert_eq!(out, vec![owner.id().clone()]);
            assert_eq!(store.switches().unwrap().trusted_devices_mode, mode);
            assert!(store.first_use_snapshot().unwrap().is_some());
            assert!(store.keys().unwrap().is_empty());
            assert_eq!(store.tombstones().unwrap().len(), tombs_before + 1);
            assert_eq!(removed_origin(&store, owner.id()), Origin::Pc);
            let reopened = dir.open();
            assert_eq!(reopened.switches().unwrap().trusted_devices_mode, mode);
            assert!(reopened.first_use_snapshot().unwrap().is_some());
            assert_eq!(reopened.tombstones().unwrap(), store.tombstones().unwrap());
        }

        // After a reset first_use stays closed for whoever had a key, and the spent grounds stand:
        // the owner re-pairs the same key at the PC, and the server's replay of an old grant, its
        // invitation and an old endorsement is refused.
        let dir = Scratch::new();
        let mut store = dir.open();
        store
            .take_first_use_snapshot(
                snapshot_of(&[(1, BindingRole::Owner), (2, BindingRole::Guest)]),
                NOW,
            )
            .unwrap();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = Device::new();
        store
            .add(
                guest.new_key(),
                grant(owner.id(), 1, 2, Some((3, owner.id()))),
                NOW,
            )
            .unwrap();
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 2), NOW)
            .unwrap();
        assert_eq!(
            store.grant_token(),
            Some(GrantToken::default()),
            "a new PC's"
        );
        // A reset refused (another change in flight) replaces nothing: no key left, the token as
        // it was.
        let held = store.keys().unwrap().len();
        let busy = store
            .stage_add(Device::new().new_key(), pair(3, BindingRole::Guest), NOW)
            .unwrap();
        assert_eq!(
            store.stage_reset_to_empty(NOW + 1).err(),
            Some(StoreError::Busy)
        );
        assert_eq!(store.grant_token(), Some(GrantToken::default()));
        assert!(!store.grant_token_unsaved());
        assert_eq!(store.keys().unwrap().len(), held);
        assert!(matches!(store.lookup(owner.id()), Lookup::Active(_)));
        store.apply(busy).unwrap();
        assert_eq!(store.grant_token(), Some(GrantToken::default()));
        store.reset_to_empty(NOW + 1).unwrap();
        assert!(store.keys().unwrap().is_empty());
        // §7: the reset replaced the token in its own write — never `""` after it.
        let token = store.grant_token().unwrap();
        assert!(!token.is_empty());
        let mut store = dir.open();
        assert_eq!(store.grant_token(), Some(token), "written with the reset");
        for uid in [1, 2] {
            assert_eq!(
                store.add(
                    Device::new().new_key(),
                    Ground::FirstUse {
                        telegram_user_id: uid
                    },
                    NOW + 2
                ),
                Err(StoreError::FirstUseClosed("the person has a removed key"))
            );
        }
        store
            .add(owner.new_key(), pair(1, BindingRole::Owner), NOW + 2)
            .unwrap();
        let fresh_guest = Device::new();
        assert_eq!(
            store.add(
                fresh_guest.new_key(),
                grant(owner.id(), 1, 2, Some((3, owner.id()))),
                NOW + 3
            ),
            Err(StoreError::Spent(gid(1)))
        );
        // A grant signed over `""` (before the reset) is stale now, whatever else it is.
        assert_eq!(
            store.add(
                fresh_guest.new_key(),
                grant(owner.id(), 4, 2, Some((5, owner.id()))),
                NOW + 3
            ),
            Err(StoreError::GrantStale)
        );
        assert_eq!(
            store.add(
                fresh_guest.new_key(),
                over(grant(owner.id(), 4, 2, Some((3, owner.id()))), token),
                NOW + 3
            ),
            Err(StoreError::InviteSpent(gid(3)))
        );
        assert_eq!(
            store.add(Device::new().new_key(), endorse(owner.id(), 2), NOW + 3),
            Err(StoreError::Spent(gid(2)))
        );
        // A new grant on a new invitation, over the current token, still lets a guest in.
        store
            .add(
                fresh_guest.new_key(),
                over(grant(owner.id(), 4, 2, Some((5, owner.id()))), token),
                NOW + 4,
            )
            .unwrap();
    }

    #[test]
    fn a_failed_write_changes_nothing() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        let primary = std::fs::read(dir.primary()).unwrap();
        // The backup's place taken by a directory: the backup cannot be written, so nothing is.
        std::fs::remove_file(dir.backup()).unwrap();
        std::fs::create_dir(dir.backup()).unwrap();
        std::fs::write(dir.backup().join("x"), b"x").unwrap();
        let guest = Device::new();
        assert!(matches!(
            store.add(guest.new_key(), pair(2, BindingRole::Guest), NOW),
            Err(StoreError::Write(_))
        ));
        assert_eq!(store.lookup(guest.id()), Lookup::Unknown);
        assert!(matches!(
            store.remove(owner.id(), Removal::Pc, NOW),
            Err(StoreError::Write(_))
        ));
        // Not removed in the list; denied from the stage on, until the retry or an undeny.
        assert!(matches!(
            store.lookup(owner.id()),
            Lookup::PendingRemoval(_)
        ));
        store.undeny(std::slice::from_ref(owner.id()));
        active(&store, owner.id());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), primary);
        let reopened = dir.open();
        active(&reopened, owner.id());
        assert_eq!(reopened.lookup(guest.id()), Lookup::Unknown);
    }

    #[test]
    fn two_instances_on_one_file() {
        let dir = Scratch::new();
        let (mut a, owner) = store_with_owner(&dir);
        let mut b = dir.open();
        active(&b, owner.id());
        // A disables the key; B, which still trusts it, then tries a change of its own.
        a.remove(owner.id(), Removal::Pc, NOW + 5).unwrap();
        let d = Device::new();
        assert_eq!(
            b.add(d.new_key(), pair(2, BindingRole::Guest), NOW + 6),
            Err(StoreError::ChangedOnDisk)
        );
        // B reloaded: the disable stands, there and on disk.
        assert_eq!(removed_origin(&b, owner.id()), Origin::Pc);
        b.add(d.new_key(), pair(2, BindingRole::Guest), NOW + 6)
            .unwrap();
        let c = dir.open();
        assert_eq!(removed_origin(&c, owner.id()), Origin::Pc);
        active(&c, d.id());
        // Now A is behind: its change is refused the same way and the disable still stands.
        assert_eq!(
            a.set_trusted_devices_mode(true),
            Err(StoreError::ChangedOnDisk)
        );
        active(&a, d.id());
        // A first-run instance whose file appeared meanwhile (another writer) is refused too.
        let other = Scratch::new();
        let mut first_run = other.open();
        std::fs::write(other.primary(), std::fs::read(dir.primary()).unwrap()).unwrap();
        assert_eq!(
            first_run.add(Device::new().new_key(), pair(3, BindingRole::Guest), NOW),
            Err(StoreError::ChangedOnDisk)
        );
        assert_eq!(removed_origin(&first_run, owner.id()), Origin::Pc);
    }

    #[test]
    fn last_used_is_written_at_most_every_ten_minutes() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let d = add_paired(&mut store, 1, BindingRole::Owner);
        // Nothing stored yet: written.
        assert!(store.touch(d.id(), NOW).unwrap());
        let on_disk = std::fs::read(dir.primary()).unwrap();
        // Five minutes later: memory only.
        assert!(!store.touch(d.id(), NOW + 300_000).unwrap());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), on_disk);
        assert_eq!(active(&store, d.id()).last_used_at, Some(NOW + 300_000));
        assert_eq!(active(&dir.open(), d.id()).last_used_at, Some(NOW));
        // With the next change of any kind, the memory's value is written.
        store.set_trusted_devices_mode(true).unwrap();
        assert_eq!(
            active(&dir.open(), d.id()).last_used_at,
            Some(NOW + 300_000)
        );
        // Ten minutes after the stored value: written.
        assert!(!store
            .touch(d.id(), NOW + 300_000 + LAST_USED_WRITE_AFTER_MS - 1)
            .unwrap());
        assert!(store
            .touch(d.id(), NOW + 300_000 + LAST_USED_WRITE_AFTER_MS)
            .unwrap());
        assert_eq!(
            active(&dir.open(), d.id()).last_used_at,
            Some(NOW + 300_000 + LAST_USED_WRITE_AFTER_MS)
        );
        let unknown = fresh().1;
        assert_eq!(
            store.touch(unknown.key_id(), NOW),
            Err(StoreError::NotFound(unknown.key_id().clone()))
        );
    }

    // --- Stage, write, install ------------------------------------------------------------------

    #[test]
    fn a_staged_change_crosses_threads() {
        fn send<T: Send + 'static>(_: &T) {}
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let staged = store
            .stage_add(Device::new().new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        send(&staged);
        // Written on another thread, installed here.
        let written = std::thread::spawn(move || staged.write())
            .join()
            .unwrap()
            .unwrap();
        send(&written);
        let out = store.install(written).unwrap();
        active(&store, &out.key_id);
        active(&dir.open(), &out.key_id);
        // A failed write crosses back too.
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        std::fs::write(dir.primary(), b"changed elsewhere").unwrap();
        let failed = std::thread::spawn(move || staged.write())
            .join()
            .unwrap()
            .unwrap_err();
        send(&failed);
        assert_eq!(*failed.error(), StoreError::ChangedOnDisk);
        assert!(store.abandon(failed).unwrap().damaged);
    }

    #[test]
    fn staging_does_no_io_and_changes_nothing_until_installed() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let on_disk = std::fs::read(dir.primary()).unwrap();
        let d = Device::new();
        let staged = store
            .stage_add(d.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        assert_eq!(staged.outcome().key_id, *d.id());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), on_disk);
        assert_eq!(store.lookup(d.id()), Lookup::Unknown);
        let written = staged.write().unwrap();
        assert_eq!(written.outcome().key_id, *d.id());
        // On disk now, not yet in memory.
        active(&dir.open(), d.id());
        assert_eq!(store.lookup(d.id()), Lookup::Unknown);
        store.install(written).unwrap();
        active(&store, d.id());
        // A stage needs no file at all: the directory gone, the stage still decides; the write
        // fails (the file it was built on is gone) and the abandon follows the disk.
        drop(dir);
        let staged = store
            .stage_add(Device::new().new_key(), endorse(owner.id(), 2), NOW)
            .unwrap();
        let failed = staged.write().unwrap_err();
        match failed.error() {
            StoreError::ChangedOnDisk => {
                let reloaded = store.abandon(failed).unwrap();
                assert!(reloaded.left_active.contains(d.id()), "{reloaded:?}");
            }
            StoreError::Write(_) => {
                assert_eq!(store.abandon(failed), None);
                active(&store, d.id());
            }
            other => panic!("{other:?}"),
        }
        assert!(!store.is_busy());
    }

    #[test]
    fn one_change_in_flight_at_a_time() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        assert!(!store.is_busy());
        let first = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        assert!(store.is_busy());
        // Every stage is refused while it is in flight …
        let d = Device::new();
        assert_eq!(
            store
                .stage_add(d.new_key(), pair(3, BindingRole::Guest), NOW)
                .unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(
            store
                .stage_remove(guest.id(), Removal::Server, NOW)
                .unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(
            store.stage_confirm(owner.id()).unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(
            store.stage_set_trusted_devices_mode(false).unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(
            store
                .stage_first_use_snapshot(snapshot_of(&[(5, BindingRole::Guest)]), NOW)
                .unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(
            store.stage_reset_to_empty(NOW).unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(
            store.stage_restore_from_backup(NOW).unwrap_err(),
            StoreError::Busy
        );
        let attempt = Attempt::new(&owner, 1);
        assert_eq!(
            store
                .stage_recover(attempt.recovery(&owner), NOW)
                .unwrap_err(),
            StoreError::Busy
        );
        // … but a touch is never refused: the use is noted in memory, its write waits.
        assert!(store.stage_touch(guest.id(), NOW + 5).unwrap().is_none());
        assert_eq!(active(&store, guest.id()).last_used_at, Some(NOW + 5));
        // Abandoned before its write: free again, nothing changed.
        assert_eq!(store.abandon(first), None);
        assert!(!store.is_busy());
        assert!(!store.switches().unwrap().trusted_devices_mode);
        // A failed write keeps it busy until abandoned.
        let second = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        std::fs::remove_file(dir.backup()).unwrap();
        std::fs::create_dir(dir.backup()).unwrap();
        std::fs::write(dir.backup().join("x"), b"x").unwrap();
        let failed = second.write().unwrap_err();
        assert!(matches!(failed.error(), StoreError::Write(_)));
        assert_eq!(
            store.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(store.abandon(failed), None);
        std::fs::remove_dir_all(dir.backup()).unwrap();
        // An install ends it too; a no-op stage (nothing to write) never starts one.
        assert!(store.stage_confirm(owner.id()).unwrap().is_none());
        assert!(!store.is_busy());
        let third = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        store.install(third.write().unwrap()).unwrap();
        assert!(!store.is_busy());
        // The use noted while busy went out with that change.
        assert_eq!(active(&dir.open(), guest.id()).last_used_at, Some(NOW + 5));
        let touch = store
            .stage_touch(guest.id(), NOW + 5 + LAST_USED_WRITE_AFTER_MS)
            .unwrap();
        assert!(touch.is_some());
        assert!(store.is_busy());
    }

    #[test]
    fn two_writes_on_one_base_cannot_both_land() {
        use std::sync::mpsc;
        use std::time::Duration;
        let dir = Scratch::new();
        let (mut a, owner) = store_with_owner(&dir);
        // Another instance on the same file and the same bytes (as a timed-out write's store was
        // before the one-in-flight rule): only the process-wide lock orders the two writes.
        let mut b = dir.open();
        let (reached_tx, reached_rx) = mpsc::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let go_rx = Mutex::new(go_rx);
        // A: the PC removes the owner key; its write pauses after its re-read check.
        let removal = a
            .stage_remove(owner.id(), Removal::Pc, NOW)
            .unwrap()
            .with_pause(Arc::new(move || {
                reached_tx.send(()).unwrap();
                go_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap();
            }));
        let ta = std::thread::spawn(move || removal.write());
        reached_rx.recv_timeout(Duration::from_secs(30)).unwrap();
        // While A is in flight, its store stages nothing else.
        assert_eq!(
            a.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::Busy
        );
        // B: a change on the same base, written while A sits between its check and its write.
        let d = Device::new();
        let add = b
            .stage_add(d.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        let tb = std::thread::spawn(move || add.write());
        std::thread::sleep(Duration::from_millis(200));
        assert!(!tb.is_finished(), "B waits for the write lock A holds");
        go_tx.send(()).unwrap();
        let wa = ta.join().unwrap().unwrap();
        let fb = tb.join().unwrap().unwrap_err();
        // A landed; B found the file changed under it, so it did not undo the removal.
        assert_eq!(*fb.error(), StoreError::ChangedOnDisk);
        a.install(wa).unwrap();
        let reloaded = b.abandon(fb).unwrap();
        assert_eq!(reloaded.left_active, vec![owner.id().clone()]);
        assert!(reloaded.joined_active.is_empty());
        assert_eq!(removed_origin(&b, owner.id()), Origin::Pc);
        let disk = dir.open();
        assert_eq!(removed_origin(&disk, owner.id()), Origin::Pc);
        assert_eq!(disk.lookup(d.id()), Lookup::Unknown);
    }

    #[test]
    fn a_write_refused_for_a_changed_file_reports_what_the_reload_changed() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        // Another writer removes a key between the stage and the write: a stale removal.
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        let mut other = dir.open();
        other.remove(owner.id(), Removal::Pc, NOW).unwrap();
        let theirs = std::fs::read(dir.primary()).unwrap();
        let failed = staged.write().unwrap_err();
        assert_eq!(*failed.error(), StoreError::ChangedOnDisk);
        assert_eq!(std::fs::read(dir.primary()).unwrap(), theirs);
        active(&store, owner.id());
        let reloaded = store.abandon(failed).unwrap();
        assert_eq!(reloaded.left_active, vec![owner.id().clone()]);
        assert!(reloaded.joined_active.is_empty() && reloaded.changed.is_empty());
        assert!(!reloaded.damaged);
        assert_eq!(removed_origin(&store, owner.id()), Origin::Pc);
        assert!(!store.switches().unwrap().trusted_devices_mode);
        // Another writer adds a key and confirms one: a stale add.
        let mut other = dir.open();
        let d = Device::new();
        other
            .add(d.new_key(), pair_unconfirmed(3, BindingRole::Guest), NOW)
            .unwrap();
        let staged = store
            .stage_add(d.new_key(), pair(3, BindingRole::Guest), NOW)
            .unwrap();
        other.remove(guest.id(), Removal::Server, NOW).unwrap();
        let failed = staged.write().unwrap_err();
        let reloaded = store.abandon(failed).unwrap();
        assert_eq!(reloaded.joined_active, vec![d.id().clone()]);
        assert_eq!(reloaded.left_active, vec![guest.id().clone()]);
        assert!(active(&store, d.id()).unconfirmed);
    }

    #[test]
    fn install_after_a_reopen_takes_a_change_that_landed() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        // The write lands, then the store is reopened (it reads the change), then the install.
        let d = Device::new();
        let staged = store
            .stage_add(d.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        let written = staged.write().unwrap();
        let reloaded = store.reopen();
        assert_eq!(reloaded.joined_active, vec![d.id().clone()]);
        assert!(
            store.is_busy(),
            "a reopen does not end the change in flight"
        );
        let out = store.install(written).unwrap();
        assert_eq!(out.key_id, *d.id());
        assert!(!store.is_busy());
        active(&store, d.id());
        // Reopened before the write lands: the reopen read the very bytes the write's locked
        // re-read then found and replaced, so the written list is taken — no I/O in the install.
        let d2 = Device::new();
        let staged = store
            .stage_add(d2.new_key(), endorse(owner.id(), 2), NOW)
            .unwrap();
        assert!(store.reopen().is_empty());
        let written = staged.write().unwrap();
        let primary = std::fs::read(dir.primary()).unwrap();
        // The file is not read by the install: moving it away changes nothing.
        std::fs::remove_file(dir.primary()).unwrap();
        let out = store.install(written).unwrap();
        std::fs::write(dir.primary(), &primary).unwrap();
        assert_eq!(out.key_id, *d2.id());
        active(&store, d2.id());
        assert!(!store.needs_reopen());
        // Landed, then overwritten by another writer, and the store reopened on that: the disk it
        // read is neither the written bytes nor the replaced ones. Not installed, memory
        // untouched, the outcome returned, a reopen needed.
        let d3 = Device::new();
        let staged = store
            .stage_add(d3.new_key(), endorse(owner.id(), 3), NOW)
            .unwrap();
        let written = staged.write().unwrap();
        let mut other = dir.open();
        other.remove(d.id(), Removal::Pc, NOW).unwrap();
        other.remove(d3.id(), Removal::Pc, NOW).unwrap();
        let reopened = store.reopen();
        assert_eq!(reopened.left_active, vec![d.id().clone()]);
        let not = store.install(written).unwrap_err();
        assert_eq!(not.error, StoreError::StaleBase);
        assert_eq!(not.outcome.key_id, *d3.id());
        assert!(not.reloaded.is_empty());
        assert!(!store.is_busy());
        assert!(store.needs_reopen());
        // Memory is what the reopen read: d3 removed, d removed.
        assert_eq!(removed_origin(&store, d3.id()), Origin::Pc);
        assert_eq!(
            store.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::NeedsReopen
        );
        assert!(store.reopen().is_empty());
        assert_eq!(removed_origin(&store, d.id()), Origin::Pc);
        store.set_trusted_devices_mode(true).unwrap();
    }

    #[test]
    fn install_after_a_reopen_on_the_replaced_file_takes_the_written_list() {
        // The rule's other side: reopened before the write landed, then overwritten — the
        // locked re-read proved the write landed on what the store holds, so the written list is
        // taken; the later writer is caught by the next write's re-read.
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let d = Device::new();
        let staged = store
            .stage_add(d.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        let _ = store.reopen();
        let written = staged.write().unwrap();
        let mut other = dir.open();
        other.remove(owner.id(), Removal::Pc, NOW).unwrap();
        store.install(written).unwrap();
        active(&store, d.id());
        let failed = store
            .stage_set_trusted_devices_mode(true)
            .unwrap()
            .unwrap()
            .write()
            .unwrap_err();
        assert_eq!(*failed.error(), StoreError::ChangedOnDisk);
        let reloaded = store.abandon(failed).unwrap();
        assert_eq!(reloaded.left_active, vec![owner.id().clone()]);
    }

    #[test]
    fn install_of_a_foreign_change_is_refused_and_touches_nothing() {
        let dir = Scratch::new();
        let (mut a, owner) = store_with_owner(&dir);
        let other_dir = Scratch::new();
        let mut b = other_dir.open();
        let b_owner = add_paired(&mut b, 5, BindingRole::Owner);
        let b_disk = std::fs::read(other_dir.primary()).unwrap();
        let d = Device::new();
        let written = a
            .stage_add(d.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap()
            .write()
            .unwrap();
        let not = b.install(written).unwrap_err();
        assert_eq!(not.error, StoreError::NotInFlight);
        assert_eq!(not.outcome.key_id, *d.id());
        assert_eq!(b.lookup(d.id()), Lookup::Unknown);
        active(&b, b_owner.id());
        assert!(!b.is_busy() && !b.needs_reopen());
        assert_eq!(std::fs::read(other_dir.primary()).unwrap(), b_disk);
        // `b` stages on.
        b.set_trusted_devices_mode(true).unwrap();
        // `a` lost its change (consumed elsewhere): it notices at its next stage.
        assert_eq!(
            a.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::NeedsReopen
        );
        let reloaded = a.reopen();
        assert_eq!(reloaded.joined_active, vec![d.id().clone()]);
        a.set_trusted_devices_mode(true).unwrap();
    }

    #[test]
    fn a_lost_change_needs_a_reopen() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        // A written change dropped (say, the background await gave up): the next stage sees it.
        let d = Device::new();
        let written = store
            .stage_add(d.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap()
            .write()
            .unwrap();
        drop(written);
        let mut refused = None;
        let log = logged(|| {
            refused = Some(store.stage_set_trusted_devices_mode(true).unwrap_err());
        });
        assert_eq!(refused, Some(StoreError::NeedsReopen));
        assert!(
            log.contains("ERROR") && log.contains("change in flight was lost"),
            "{log}"
        );
        assert!(!store.is_busy() && store.needs_reopen());
        // Every stage is refused the same way; a touch is not, nor a deny.
        assert_eq!(
            store
                .stage_remove(owner.id(), Removal::Pc, NOW)
                .unwrap_err(),
            StoreError::NeedsReopen
        );
        assert!(store
            .stage_touch(owner.id(), NOW + 2 * LAST_USED_WRITE_AFTER_MS)
            .unwrap()
            .is_none());
        store.deny_now(std::slice::from_ref(owner.id()));
        assert!(matches!(
            store.lookup(owner.id()),
            Lookup::PendingRemoval(_)
        ));
        // The reopen: memory follows the file (the dropped change had landed), stages work.
        let reloaded = store.reopen();
        assert_eq!(reloaded.joined_active, vec![d.id().clone()]);
        assert!(!store.needs_reopen());
        store.remove(owner.id(), Removal::Pc, NOW).unwrap();
        assert!(matches!(store.lookup(owner.id()), Lookup::Removed(_)));

        // A staged change dropped before its write.
        drop(store.stage_set_trusted_devices_mode(true).unwrap().unwrap());
        assert_eq!(
            store.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::NeedsReopen
        );
        assert!(store.reopen().is_empty());

        // A write that panics (on its thread, holding the write lock).
        let staged = store
            .stage_set_trusted_devices_mode(true)
            .unwrap()
            .unwrap()
            .with_pause(Arc::new(|| panic!("a write that panics, on purpose")));
        assert!(std::thread::spawn(move || staged.write()).join().is_err());
        assert_eq!(
            store.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::NeedsReopen
        );
        assert!(store.reopen().is_empty());
        // The poisoned lock does not stop the next write.
        store.set_trusted_devices_mode(true).unwrap();
        assert!(dir.open().switches().unwrap().trusted_devices_mode);
    }

    #[test]
    fn a_removal_denies_at_once_while_the_store_is_busy() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        let other = add_paired(&mut store, 3, BindingRole::Guest);
        // A change in flight; the server removes the guest meanwhile.
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        store.deny_now(std::slice::from_ref(guest.id()));
        match store.lookup(guest.id()) {
            Lookup::PendingRemoval(r) => assert_eq!(r.key, guest.key),
            other => panic!("{other:?}"),
        }
        active(&store, owner.id());
        assert_eq!(
            store
                .stage_remove(guest.id(), Removal::Server, NOW)
                .unwrap_err(),
            StoreError::Busy
        );
        // The change in flight installs: the guest is still active in the list, still denied.
        store.install(staged.write().unwrap()).unwrap();
        assert!(matches!(
            store.lookup(guest.id()),
            Lookup::PendingRemoval(_)
        ));
        // The queued removal goes through: the deny gives way to the tombstone.
        store.remove(guest.id(), Removal::Server, NOW).unwrap();
        assert!(matches!(store.lookup(guest.id()), Lookup::Removed(_)));
        // Brought back at the PC, it is active again (the pending mark is gone).
        store
            .add(guest.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        active(&store, guest.id());
        // A removal that lands by a reload clears the mark too.
        store.deny_now(std::slice::from_ref(other.id()));
        let staged = store
            .stage_set_trusted_devices_mode(false)
            .unwrap()
            .unwrap();
        let mut elsewhere = dir.open();
        elsewhere.remove(other.id(), Removal::Pc, NOW).unwrap();
        let failed = staged.write().unwrap_err();
        let reloaded = store.abandon(failed).unwrap();
        assert_eq!(reloaded.left_active, vec![other.id().clone()]);
        assert!(matches!(store.lookup(other.id()), Lookup::Removed(_)));
        store
            .add(other.new_key(), pair(3, BindingRole::Guest), NOW)
            .unwrap();
        active(&store, other.id());
        // A damaged store answers damaged, pending or not.
        store.deny_now(std::slice::from_ref(owner.id()));
        std::fs::write(dir.primary(), b"garbage").unwrap();
        let _ = store.reopen();
        assert_eq!(store.lookup(owner.id()), Lookup::StoreDamaged);
    }

    #[test]
    fn a_pending_key_signs_nothing_and_recovers_nothing() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let other_owner = add_paired(&mut store, 1, BindingRole::Owner);
        store.deny_now(std::slice::from_ref(owner.id()));
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), endorse(owner.id(), 1), NOW),
            Err(StoreError::SignerRemoved(owner.id().clone()))
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(owner.id(), 2, 3, Some((3, owner.id()))),
                NOW
            ),
            Err(StoreError::NotOwner)
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(other_owner.id(), 4, 3, Some((5, owner.id()))),
                NOW
            ),
            Err(StoreError::InviteNotOwner)
        );
        let attempt = Attempt::new(&owner, 1);
        assert_eq!(
            store.recover(attempt.recovery(&owner), NOW),
            Err(StoreError::RecoverNoRecord)
        );
        // The other owner still signs.
        store
            .add(d.new_key(), endorse(other_owner.id(), 6), NOW)
            .unwrap();
    }

    #[test]
    fn an_in_flight_endorse_or_recovery_by_a_pending_key_installs_pending() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        // An endorse by the owner key is in flight when its removal is decided.
        let child = Device::new();
        let staged = store
            .stage_add(child.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        store.deny_now(std::slice::from_ref(owner.id()));
        store.install(staged.write().unwrap()).unwrap();
        assert!(matches!(
            store.lookup(child.id()),
            Lookup::PendingRemoval(_)
        ));
        // … and a grandchild that joins by a reload (another writer) inherits it too.
        let mut other = dir.open();
        let grandchild = Device::new();
        other
            .add(grandchild.new_key(), endorse(child.id(), 2), NOW)
            .unwrap();
        let reloaded = store.reopen();
        assert_eq!(reloaded.inherited_pending, vec![grandchild.id().clone()]);
        // Both report the key they inherited from: the one denied directly (itself listed with
        // none: its removal is not staged yet either).
        let pending = store.pending_without_removal();
        assert_eq!(pending.len(), 3);
        for p in &pending {
            let expected = (p.key_id != *owner.id()).then(|| owner.id().clone());
            assert_eq!(p.inherited_from, expected, "{p:?}");
        }
        assert!(matches!(
            store.lookup(grandchild.id()),
            Lookup::PendingRemoval(_)
        ));
        // A recovery of a device in flight when its key's removal is decided: the successor.
        let dir = Scratch::new();
        let mut store = dir.open();
        let phone = add_paired(&mut store, 2, BindingRole::Guest);
        let attempt = Attempt::new(&phone, 2);
        let staged = store.stage_recover(attempt.recovery(&phone), NOW).unwrap();
        store.deny_now(std::slice::from_ref(phone.id()));
        let out = store.install(staged.write().unwrap()).unwrap();
        assert_eq!(out.replaced, vec![phone.id().clone()]);
        assert!(matches!(
            store.lookup(attempt.new_key.key_id()),
            Lookup::PendingRemoval(_)
        ));
        // The replaced key itself is a tombstone now: it is no longer in the set.
        assert!(matches!(store.lookup(phone.id()), Lookup::Removed(_)));
        // Keys that were active before the deny are not swept in: only those that join.
        let dir = Scratch::new();
        let mut store = dir.open();
        let root = add_paired(&mut store, 3, BindingRole::Owner);
        let old_child = Device::new();
        store
            .add(old_child.new_key(), endorse(root.id(), 7), NOW)
            .unwrap();
        store.deny_now(std::slice::from_ref(root.id()));
        store.set_trusted_devices_mode(true).unwrap();
        active(&store, old_child.id());
    }

    #[test]
    fn deny_tree_and_person_deny_what_the_removal_takes() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let root = add_paired(&mut store, 1, BindingRole::Owner);
        let child = Device::new();
        store
            .add(child.new_key(), endorse(root.id(), 1), NOW)
            .unwrap();
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        let guest_laptop = Device::new();
        store
            .add(guest_laptop.new_key(), endorse(guest.id(), 2), NOW)
            .unwrap();
        let bystander = add_paired(&mut store, 3, BindingRole::Guest);
        // While a change is in flight.
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        let tree = store.deny_tree_now(root.id(), 0).unwrap().removed;
        assert_eq!(tree, vec![root.id().clone(), child.id().clone()]);
        // «Удалить человека» at the PC, as the product denies it (`press_remove_person`).
        let mut person = store.deny_person_tree_now(2, 0).removed;
        person.sort();
        let mut theirs = vec![guest.id().clone(), guest_laptop.id().clone()];
        theirs.sort();
        assert_eq!(person, theirs);
        for k in [root.id(), child.id(), guest.id(), guest_laptop.id()] {
            assert!(
                matches!(store.lookup(k), Lookup::PendingRemoval(_)),
                "{k:?}"
            );
        }
        active(&store, bystander.id());
        assert!(matches!(
            store.deny_tree_now(fresh().1.key_id(), 0),
            Err(StoreError::NotFound(_))
        ));
        store.install(staged.write().unwrap()).unwrap();
        // The next write that lands — every write a snapshot of memory — takes both, `pc`.
        assert_eq!(store.flush(), Ok(true));
        for k in tree.iter().chain(&person) {
            match store.lookup(k) {
                Lookup::Removed(t) => assert_eq!(t.origin, Origin::Pc, "{k:?}"),
                other => panic!("{k:?} not removed by the carry: {other:?}"),
            }
        }
        active(&store, bystander.id());
        // A staged removal denies at the stage; abandoned, it stays denied until undenied.
        let staged = store
            .stage_remove(bystander.id(), Removal::Server, NOW)
            .unwrap();
        assert!(matches!(
            store.lookup(bystander.id()),
            Lookup::PendingRemoval(_)
        ));
        assert_eq!(store.abandon(staged), None);
        assert!(matches!(
            store.lookup(bystander.id()),
            Lookup::PendingRemoval(_)
        ));
        store.undeny(std::slice::from_ref(bystander.id()));
        active(&store, bystander.id());
        // A removal refused for good: the admission undenies.
        let owner = add_paired(&mut store, 5, BindingRole::Owner);
        store.deny_now(std::slice::from_ref(owner.id()));
        assert_eq!(
            store.remove(owner.id(), Removal::Server, NOW),
            Err(StoreError::ServerRemovesOwner)
        );
        store.undeny(std::slice::from_ref(owner.id()));
        active(&store, owner.id());
        // A healthy reset denies every key it removes at the stage.
        let reset = store.stage_reset_to_empty(NOW).unwrap();
        assert!(matches!(
            store.lookup(owner.id()),
            Lookup::PendingRemoval(_)
        ));
        let removed_ids = store.install(reset.write().unwrap()).unwrap();
        assert!(removed_ids.contains(owner.id()));
        assert!(matches!(store.lookup(owner.id()), Lookup::Removed(_)));
    }

    #[test]
    fn a_marked_pair_lifts_no_removal() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        let other = add_paired(&mut store, 3, BindingRole::Guest);
        store.remove(guest.id(), Removal::Pc, NOW).unwrap();
        store.remove(other.id(), Removal::Server, NOW).unwrap();
        assert_eq!(
            store.add(
                guest.new_key(),
                pair_unconfirmed(2, BindingRole::Guest),
                NOW
            ),
            Err(removal_error("pc", guest.id()))
        );
        assert_eq!(
            store.add(
                other.new_key(),
                pair_unconfirmed(3, BindingRole::Guest),
                NOW
            ),
            Err(removal_error("server", other.id()))
        );
        // A confirmed pairing at the PC lifts both.
        store
            .add(guest.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        store
            .add(other.new_key(), pair(3, BindingRole::Guest), NOW)
            .unwrap();
    }

    #[test]
    fn install_on_a_store_damaged_since_proves_no_base() {
        let dir = Scratch::new();
        // A first run: no primary; the change is staged on «no file».
        let mut store = dir.open();
        let d = Device::new();
        let staged = store
            .stage_add(d.new_key(), pair(1, BindingRole::Owner), NOW)
            .unwrap();
        let written = staged.write().unwrap();
        // The primary garbled after the write; the store reopens on it: damaged, no bytes.
        std::fs::write(dir.primary(), b"garbage").unwrap();
        let reloaded = store.reopen();
        assert!(reloaded.damaged);
        let not = store.install(written).unwrap_err();
        assert_eq!(not.error, StoreError::StaleBase);
        assert!(store.needs_reopen());
        assert!(store.is_damaged());
        assert_eq!(store.lookup(d.id()), Lookup::StoreDamaged);
    }

    #[test]
    fn a_reopen_ends_a_lost_change() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let _owner = add_paired(&mut store, 1, BindingRole::Owner);
        drop(store.stage_set_trusted_devices_mode(true).unwrap().unwrap());
        // The reopen comes first (no stage saw the loss).
        let mut reloaded = None;
        let log = logged(|| reloaded = Some(store.reopen()));
        assert!(reloaded.unwrap().is_empty());
        assert!(
            log.contains("ERROR") && log.contains("ended by the reopen"),
            "{log}"
        );
        assert!(!store.is_busy() && !store.needs_reopen());
        store.set_trusted_devices_mode(true).unwrap();
        // The split reopen: the load on another thread, taken here.
        let paths = store.paths();
        let loaded = std::thread::spawn(move || TrustStore::reopen_load(&paths))
            .join()
            .unwrap();
        assert!(store.take_reopen(loaded).is_empty());
        assert!(store.switches().unwrap().trusted_devices_mode);
    }

    #[test]
    fn a_foreign_abandon_touches_nothing() {
        let dir = Scratch::new();
        let mut a = dir.open();
        let owner = add_paired(&mut a, 1, BindingRole::Owner);
        let other_dir = Scratch::new();
        let mut b = other_dir.open();
        let _b_owner = add_paired(&mut b, 5, BindingRole::Owner);
        // `b` has a change of its own in flight.
        let b_staged = b.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        // `a`'s write fails for a changed file; handed to `b` by mistake.
        let a_staged = a.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        let mut elsewhere = dir.open();
        elsewhere.remove(owner.id(), Removal::Pc, NOW).unwrap();
        let failed = a_staged.write().unwrap_err();
        assert_eq!(b.abandon(failed), None);
        assert!(b.is_busy() && !b.needs_reopen());
        b.install(b_staged.write().unwrap()).unwrap();
        assert!(b.switches().unwrap().trusted_devices_mode);
    }

    #[test]
    fn an_abandon_after_a_changed_file_without_a_load_needs_a_reopen() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        // A failed write that carries no load of the file.
        let failed = WriteFailed(Box::new(Failure {
            error: StoreError::ChangedOnDisk,
            ticket: staged.ticket,
            what: staged.what.clone(),
            outcome: (),
            generation: staged.generation,
            token: staged.token.clone(),
            fresh: None,
        }));
        drop(staged);
        assert_eq!(store.abandon(failed), None);
        assert!(store.needs_reopen() && !store.is_busy());
        active(&store, owner.id());
        assert!(!store.switches().unwrap().trusted_devices_mode);
        assert!(store.reopen().is_empty());
        store.set_trusted_devices_mode(true).unwrap();
    }

    #[test]
    fn a_stale_reopen_load_is_not_taken() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let k = add_paired(&mut store, 1, BindingRole::Owner);
        let _other = add_paired(&mut store, 2, BindingRole::Guest);
        // The load is read, then a removal of K installs, then the old load arrives.
        let paths = store.paths();
        let old = std::thread::spawn(move || TrustStore::reopen_load(&paths))
            .join()
            .unwrap();
        store.remove(k.id(), Removal::Pc, NOW).unwrap();
        let reloaded = store.take_reopen(old);
        assert!(reloaded.needs_reopen && reloaded.is_empty());
        assert!(matches!(store.lookup(k.id()), Lookup::Removed(_)));
        assert!(store.needs_reopen());
        assert_eq!(
            store.stage_set_trusted_devices_mode(true).unwrap_err(),
            StoreError::NeedsReopen
        );
        // Another store's load (same files) is refused the same way.
        let twin = dir.open();
        let foreign = TrustStore::reopen_load(&twin.paths());
        assert!(store.take_reopen(foreign).needs_reopen);
        // A fresh load is taken.
        let fresh_load = TrustStore::reopen_load(&store.paths());
        let reloaded = store.take_reopen(fresh_load);
        assert!(!reloaded.needs_reopen && reloaded.is_empty());
        assert!(!store.needs_reopen());
        assert!(matches!(store.lookup(k.id()), Lookup::Removed(_)));
        store.set_trusted_devices_mode(true).unwrap();
    }

    #[test]
    fn an_inherited_pending_mark_reaches_the_file() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let k = add_paired(&mut store, 2, BindingRole::Guest);
        let unrelated = add_paired(&mut store, 3, BindingRole::Guest);
        // K is denied (say, the server removed the guest) while its recovery is in flight.
        let attempt = Attempt::new(&k, 2);
        let staged = store.stage_recover(attempt.recovery(&k), NOW).unwrap();
        store.deny_now(std::slice::from_ref(k.id()));
        store.install(staged.write().unwrap()).unwrap();
        let successor = attempt.new_key.key_id().clone();
        // K' inherited the mark and is reported as needing a removal of its own.
        assert_eq!(
            store.pending_without_removal(),
            vec![PendingKey {
                key_id: successor.clone(),
                inherited_from: Some(k.id().clone()),
                by: Removal::Pc,
            }]
        );
        active(&store, unrelated.id());
        // The admission stages it with the parent's Removal; while in flight it is not listed.
        let removal = store
            .stage_remove(&successor, Removal::Server, NOW)
            .unwrap();
        assert!(store.pending_without_removal().is_empty());
        store.install(removal.write().unwrap()).unwrap();
        assert!(store.pending_without_removal().is_empty());
        // On disk: K' removed (server), K replaced.
        let disk = dir.open();
        assert_eq!(removed_origin(&disk, &successor), Origin::Server);
        assert!(matches!(disk.lookup(k.id()), Lookup::Removed(_)));
        active(&disk, unrelated.id());
    }

    #[test]
    fn undeny_leaves_what_the_change_in_flight_removes() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let k = add_paired(&mut store, 2, BindingRole::Guest);
        let other = add_paired(&mut store, 3, BindingRole::Guest);
        let removal = store.stage_remove(k.id(), Removal::Server, NOW).unwrap();
        store.deny_now(std::slice::from_ref(other.id()));
        store.undeny(&[k.id().clone(), other.id().clone()]);
        // K stays denied: the change in flight removes it; the other is undenied.
        assert!(matches!(store.lookup(k.id()), Lookup::PendingRemoval(_)));
        active(&store, other.id());
        // Abandoned: now an undeny takes it.
        assert_eq!(store.abandon(removal), None);
        store.undeny(std::slice::from_ref(k.id()));
        active(&store, k.id());
    }

    #[test]
    fn an_abandon_after_a_reopen_does_not_roll_memory_back() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        // Another writer (X): the write fails, and its thread loads X.
        let mut other = dir.open();
        let x = Device::new();
        other
            .add(x.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        let failed = staged.write().unwrap_err();
        assert_eq!(*failed.error(), StoreError::ChangedOnDisk);
        // Then another change (Y), and the store reopens on Y before the abandon.
        other.remove(owner.id(), Removal::Pc, NOW).unwrap();
        let reloaded = store.reopen();
        assert_eq!(reloaded.left_active, vec![owner.id().clone()]);
        // The abandon must not put X (where the owner is still active) back.
        assert_eq!(store.abandon(failed), None);
        assert!(store.needs_reopen());
        assert_eq!(removed_origin(&store, owner.id()), Origin::Pc);
        active(&store, x.id());
        assert!(store.reopen().is_empty());
        store.set_trusted_devices_mode(true).unwrap();
    }

    #[test]
    fn a_write_past_its_time_limit_is_installed_when_it_ends() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let late = Device::new();
        let staged = store
            .stage_add(late.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        // The caller's 2 s limit fired: the session is refused, the write goes on in the
        // background and the store stays busy — a PC removal now cannot be staged on the old base
        // (and later undone by the late write).
        let handle = std::thread::spawn(move || staged.write());
        assert_eq!(
            store
                .stage_remove(owner.id(), Removal::Pc, NOW)
                .unwrap_err(),
            StoreError::Busy
        );
        assert_eq!(store.lookup(late.id()), Lookup::Unknown);
        // The background await ends: installed, with its outcome.
        let out = store.install(handle.join().unwrap().unwrap()).unwrap();
        assert_eq!(out.key_id, *late.id());
        active(&store, late.id());
        // Then the removal goes through and stands.
        store.remove(owner.id(), Removal::Pc, NOW).unwrap();
        let disk = dir.open();
        assert_eq!(removed_origin(&disk, owner.id()), Origin::Pc);
        active(&disk, late.id());
    }

    #[test]
    fn an_install_keeps_a_later_use_noted_in_memory() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let d = add_paired(&mut store, 1, BindingRole::Owner);
        assert!(store.touch(d.id(), NOW).unwrap());
        let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
        // A use noted in memory between the stage and the install (not written: recent).
        assert!(store.stage_touch(d.id(), NOW + 1000).unwrap().is_none());
        let written = staged.write().unwrap();
        store.install(written).unwrap();
        assert_eq!(active(&store, d.id()).last_used_at, Some(NOW + 1000));
        assert_eq!(active(&dir.open(), d.id()).last_used_at, Some(NOW));
    }

    // --- Adding: grounds, tombstones, spent, limits ---------------------------------------------

    #[test]
    fn endorse_and_grant_need_an_active_rightful_key() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        let gone = add_paired(&mut store, 1, BindingRole::Owner);
        store.remove(gone.id(), Removal::Pc, NOW).unwrap();
        let unknown = fresh().1;
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), endorse(unknown.key_id(), 1), NOW),
            Err(StoreError::SignerUnknown(unknown.key_id().clone()))
        );
        assert_eq!(
            store.add(d.new_key(), endorse(gone.id(), 1), NOW),
            Err(StoreError::SignerRemoved(gone.id().clone()))
        );
        for by in [unknown.key_id(), gone.id(), guest.id()] {
            assert_eq!(
                store.add(d.new_key(), grant(by, 2, 3, Some((9, owner.id()))), NOW),
                Err(StoreError::NotOwner)
            );
        }
        // A grant for someone who is an owner here.
        assert_eq!(
            store.add(
                d.new_key(),
                grant(owner.id(), 2, 1, Some((9, owner.id()))),
                NOW
            ),
            Err(StoreError::GrantRole)
        );
        // A guest's endorsement gives a guest's key of the guest's person.
        store.add(d.new_key(), endorse(guest.id(), 3), NOW).unwrap();
        let r = active(&store, d.id());
        assert_eq!(r.role, BindingRole::Guest);
        assert_eq!(r.person.telegram_user_id, 2);
        // Nothing refused above spent its ground.
        let (e, g, i) = store.spent().unwrap();
        assert_eq!(e.iter().collect::<Vec<_>>(), vec![&gid(3)]);
        assert!(g.is_empty() && i.is_empty());
    }

    #[test]
    fn invitations_are_checked_and_spent() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let owner_laptop = Device::new();
        store
            .add(owner_laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        let other_owner = add_paired(&mut store, 5, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        let gone = add_paired(&mut store, 1, BindingRole::Owner);
        store.remove(gone.id(), Removal::Pc, NOW).unwrap();
        let d = Device::new();
        // The invitation's signer: an active owner's key, of the granting owner.
        for inviter in [guest.id(), gone.id(), fresh().1.key_id()] {
            assert_eq!(
                store.add(
                    d.new_key(),
                    grant(owner.id(), 2, 3, Some((3, inviter))),
                    NOW
                ),
                Err(StoreError::InviteNotOwner)
            );
        }
        assert_eq!(
            store.add(
                d.new_key(),
                grant(owner.id(), 2, 3, Some((3, other_owner.id()))),
                NOW
            ),
            Err(StoreError::InviteOwnerMismatch)
        );
        // Another device of the same owner may have signed the invitation (§7).
        store
            .add(
                d.new_key(),
                grant(owner.id(), 2, 3, Some((3, owner_laptop.id()))),
                NOW,
            )
            .unwrap();
        let (_, g, i) = store.spent().unwrap();
        assert!(g.contains(&gid(2)) && i.contains(&gid(3)));
        // The same invitation again, with a new grant: spent; and after a reopen.
        let d2 = Device::new();
        let replay = grant(owner.id(), 4, 3, Some((3, owner.id())));
        assert_eq!(
            store.add(d2.new_key(), replay.clone(), NOW),
            Err(StoreError::InviteSpent(gid(3)))
        );
        let mut store = dir.open();
        assert_eq!(
            store.add(d2.new_key(), replay, NOW),
            Err(StoreError::InviteSpent(gid(3)))
        );
        // The id sets are separate: an inv_id equal to a spent grant_id is unspent.
        store
            .add(
                d2.new_key(),
                grant(owner.id(), 6, 3, Some((2, owner.id()))),
                NOW,
            )
            .unwrap();
    }

    /// Spec §7 «Новое устройство уже привязанного гостя»: a grant for a guest the PC has joins
    /// that guest's keys (`known_person`), up to the per-person limit; a pending removal is no key.
    #[test]
    fn a_grant_for_a_known_guest_joins_the_guest_up_to_the_limit() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let first = Device::new();
        let out = store
            .add(
                first.new_key(),
                grant(owner.id(), 1, 2, Some((101, owner.id()))),
                NOW,
            )
            .unwrap();
        assert!(!out.known_person, "the first key makes a new guest");
        let second = Device::new();
        let out = store
            .add(
                second.new_key(),
                grant(owner.id(), 2, 2, Some((102, owner.id()))),
                NOW,
            )
            .unwrap();
        assert!(out.known_person, "the second device joins the guest");
        assert_eq!(
            (out.telegram_user_id, out.role, out.unconfirmed),
            (2, BindingRole::Guest, false)
        );
        let people = store.listed_people().unwrap();
        assert_eq!(people.len(), 2, "no second person");
        assert_eq!(people[1].1.len(), 2);
        // Up to MAX_KEYS_PER_PERSON, then `limit`; the refused grant spends nothing.
        for n in 3..=u8::try_from(MAX_KEYS_PER_PERSON).unwrap() {
            store
                .add(
                    Device::new().new_key(),
                    grant(owner.id(), n, 2, Some((100 + n, owner.id()))),
                    NOW,
                )
                .unwrap();
        }
        let over = grant(owner.id(), 40, 2, Some((140, owner.id())));
        assert_eq!(
            store.add(Device::new().new_key(), over.clone(), NOW),
            Err(StoreError::Full(Limit::PerPerson))
        );
        let (_, g, i) = store.spent().unwrap();
        assert!(!g.contains(&gid(40)) && !i.contains(&gid(140)));
        // A guest whose every key's removal is pending is no known person.
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        store.deny_now(&[guest.id().clone()]);
        let out = store
            .check_add(
                &Device::new().new_key(),
                &grant(owner.id(), 1, 2, Some((101, owner.id()))),
                NOW,
            )
            .unwrap();
        assert!(!out.known_person);
    }

    #[test]
    fn a_grant_without_an_invitation_is_observe_only_and_unconfirmed() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let d = Device::new();
        let out = store
            .add(d.new_key(), grant(owner.id(), 1, 2, None), NOW)
            .unwrap();
        assert!(out.unconfirmed);
        assert!(active(&store, d.id()).unconfirmed);
        // Its inv_id is spent all the same (§7: the grant carries it).
        let (_, g, i) = store.spent().unwrap();
        assert!(g.contains(&gid(1)) && i.iter().eq([&grant_inv_id(1)]));
        assert_eq!(
            active(&store, d.id()).source,
            KeySource::Grant {
                by: owner.id().clone(),
                grant_id: gid(1),
                inv_id: Some(grant_inv_id(1)),
                invite_by: None,
            }
        );
        // The same request again with the invitation and a new grant_id: the invitation is spent.
        let again = Device::new();
        let with_invite = Ground::Grant {
            by: owner.id().clone(),
            grant_id: gid(7),
            inv_id: Some(grant_inv_id(1)),
            invite: Some(Invite {
                inv_id: grant_inv_id(1),
                by: owner.id().clone(),
            }),
            person: person(2),
            token: GrantToken::default(),
        };
        assert_eq!(
            store.add(again.new_key(), with_invite, NOW),
            Err(StoreError::InviteSpent(grant_inv_id(1)))
        );
        // … and without it, under a new grant_id.
        let without = Ground::Grant {
            by: owner.id().clone(),
            grant_id: gid(8),
            inv_id: Some(grant_inv_id(1)),
            invite: None,
            person: person(2),
            token: GrantToken::default(),
        };
        assert_eq!(
            store.add(again.new_key(), without, NOW),
            Err(StoreError::InviteSpent(grant_inv_id(1)))
        );
        // An invitation for another inv_id than the grant's.
        let mismatched = Ground::Grant {
            by: owner.id().clone(),
            grant_id: gid(9),
            inv_id: Some(gid(10)),
            invite: Some(Invite {
                inv_id: gid(11),
                by: owner.id().clone(),
            }),
            person: person(3),
            token: GrantToken::default(),
        };
        assert_eq!(
            store.add(again.new_key(), mismatched, NOW),
            Err(StoreError::InviteIdMismatch)
        );
        let (_, g, i) = store.spent().unwrap();
        assert!(!g.contains(&gid(7)) && !g.contains(&gid(8)) && !g.contains(&gid(9)));
        assert!(!i.contains(&gid(10)) && !i.contains(&gid(11)));
        store.set_trusted_devices_mode(true).unwrap();
        assert_eq!(
            store.add(Device::new().new_key(), grant(owner.id(), 2, 3, None), NOW),
            Err(StoreError::InviteMissing)
        );
        assert!(!store.spent().unwrap().1.contains(&gid(2)));
    }

    #[test]
    fn bad_cards_and_people_are_refused() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        assert_eq!(
            store.add(owner.new_key(), pair(1, BindingRole::Owner), NOW),
            Err(StoreError::AlreadyActive(owner.id().clone()))
        );
        let d = Device::new();
        let own_rpk = NewKey {
            rpk: Some(d.key.clone()),
            ..d.new_key()
        };
        assert!(matches!(
            store.add(own_rpk, pair(2, BindingRole::Guest), NOW),
            Err(StoreError::Invalid(_))
        ));
        for uid in [0, -5, 1 << 53] {
            assert!(matches!(
                store.add(d.new_key(), pair(uid, BindingRole::Guest), NOW),
                Err(StoreError::Invalid(_))
            ));
        }
        // Names are cleaned and cut; an empty one is no name.
        store
            .add(
                d.new_key(),
                Ground::Pair {
                    person: Person {
                        telegram_user_id: (1 << 53) - 1,
                        first_name: Some(format!("  Ве\u{202e}ра\n{}", "я".repeat(100))),
                        username: Some("\u{200b}".into()),
                    },
                    role: BindingRole::Guest,
                    unconfirmed: false,
                },
                NOW,
            )
            .unwrap();
        let r = active(&dir.open(), d.id()).clone();
        let name = r.person.first_name.unwrap();
        assert!(name.starts_with("Вера "));
        assert_eq!(name.chars().count(), NAME_MAX_CHARS);
        assert_eq!(r.person.username, None);
        // A browser's key has no recovery key.
        let browser = fresh().1;
        store
            .add(bare(&browser), pair(3, BindingRole::Guest), NOW)
            .unwrap();
        let r = active(&dir.open(), browser.key_id()).clone();
        assert_eq!(r.rpk, None);
        assert_eq!(r.kind.as_str(), "browser");
    }

    #[test]
    fn a_recovery_key_of_another_person_is_a_conflict_except_at_pairing() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        store
            .take_first_use_snapshot(snapshot_of(&[(3, BindingRole::Guest)]), NOW)
            .unwrap();
        // The owner's device's recovery key, on cards of other people's keys.
        let theirs = |key: ViewerKey| NewKey {
            key,
            rpk: Some(owner.rpk.clone()),
            kind: kind("telegram"),
            platform: platform("android"),
        };
        for ground in [
            endorse(guest.id(), 1),
            grant(owner.id(), 2, 4, Some((3, owner.id()))),
            Ground::FirstUse {
                telegram_user_id: 3,
            },
        ] {
            assert_eq!(
                store.add(theirs(fresh().1), ground, NOW),
                Err(StoreError::RpkConflict)
            );
        }
        // Nothing spent by the refusals.
        let (e, g, i) = store.spent().unwrap();
        assert!(e.is_empty() && g.is_empty() && i.is_empty());
        // A pairing at the PC adds the key, without the recovery key.
        let paired = fresh().1;
        let out = store
            .add(theirs(paired.clone()), pair(4, BindingRole::Guest), NOW)
            .unwrap();
        assert!(out.rpk_dropped);
        assert_eq!(active(&store, paired.key_id()).rpk, None);
        assert_eq!(active(&dir.open(), paired.key_id()).rpk, None);
        // The same person's own other key may share it (one device, two records).
        let out = store
            .add(owner.same_device(), pair(1, BindingRole::Guest), NOW)
            .unwrap();
        assert!(!out.rpk_dropped);
    }

    #[test]
    fn removed_keys_come_back_only_as_their_origin_allows() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        store
            .take_first_use_snapshot(
                snapshot_of(&[(1, BindingRole::Owner), (2, BindingRole::Guest)]),
                NOW,
            )
            .unwrap();
        let invited = |n: u8, inv: u8, uid: i64| grant(owner.id(), n, uid, Some((inv, owner.id())));

        // `pc`: `pair`, a `grant` with a new invitation, or a new `endorse` — for its own person
        // (one return rule: `first_use` and a ground for another person stay refused).
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        store.remove(laptop.id(), Removal::Pc, NOW).unwrap();
        for ground in [
            invited(3, 103, 2),
            Ground::FirstUse {
                telegram_user_id: 1,
            },
        ] {
            assert_eq!(
                store.add(laptop.new_key(), ground, NOW),
                Err(removal_error("pc", laptop.id()))
            );
        }
        // Nor does a recovery to it (§10: `recover` lifts nothing): the new key's removed record,
        // read with the list, refuses it (`key_revoked`); nothing changes.
        let attempt = Attempt::for_key(&owner, 1, laptop.new_key().key);
        assert_eq!(
            store.recover(attempt.recovery(&owner), NOW).err(),
            Some(removal_error("pc", laptop.id()))
        );
        active(&store, owner.id());
        // The first endorse stays spent; a new one of the same person's device lifts it.
        assert_eq!(
            store.add(laptop.new_key(), endorse(owner.id(), 1), NOW),
            Err(StoreError::Spent(gid(1)))
        );
        let out = store
            .add(laptop.new_key(), endorse(owner.id(), 2), NOW)
            .unwrap();
        assert_eq!(out.lifted, Some("pc"));
        assert_eq!(active(&store, laptop.id()).role, BindingRole::Owner);
        store.remove(laptop.id(), Removal::Pc, NOW).unwrap();
        let out = store
            .add(laptop.new_key(), pair(1, BindingRole::Owner), NOW)
            .unwrap();
        assert_eq!(out.lifted, Some("pc"));
        active(&store, laptop.id());

        // `server` (a guest's key): `pair`, or a `grant` with a new invitation for the same
        // person.
        let guest = Device::new();
        store
            .add(guest.new_key(), invited(10, 110, 2), NOW)
            .unwrap();
        store.remove(guest.id(), Removal::Server, NOW).unwrap();
        for ground in [
            // The owner's device signs: another person than this removal's.
            endorse(owner.id(), 11),
            Ground::FirstUse {
                telegram_user_id: 2,
            },
            // With an invitation, for another person: not this removal's.
            invited(13, 113, 3),
        ] {
            assert_eq!(
                store.add(guest.new_key(), ground, NOW),
                Err(removal_error("server", guest.id()))
            );
        }
        // Without an invitation: never lifts a removal (§10.1), `invite_missing`.
        assert_eq!(
            store.add(guest.new_key(), grant(owner.id(), 12, 2, None), NOW),
            Err(StoreError::InviteMissing)
        );
        // The old grant, then the old invitation, replayed: spent.
        assert_eq!(
            store.add(guest.new_key(), invited(10, 114, 2), NOW),
            Err(StoreError::Spent(gid(10)))
        );
        assert_eq!(
            store.add(guest.new_key(), invited(15, 110, 2), NOW),
            Err(StoreError::InviteSpent(gid(110)))
        );
        // Nothing refused spent anything.
        let (_, g, i) = store.spent().unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(i.len(), 1);
        let out = store
            .add(guest.new_key(), invited(16, 116, 2), NOW)
            .unwrap();
        assert_eq!(out.lifted, Some("server"));
        assert!(!out.unconfirmed);
        assert_eq!(active(&store, guest.id()).role, BindingRole::Guest);
        store.remove(guest.id(), Removal::Server, NOW).unwrap();
        store
            .add(guest.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        active(&store, guest.id());

        // `replaced`: only `pair`.
        let attempt = Attempt::new(&owner, 1);
        store.recover(attempt.recovery(&owner), NOW).unwrap();
        let new_owner = attempt.new_key.key_id();
        assert_eq!(
            store.add(owner.new_key(), endorse(new_owner, 20), NOW),
            Err(removal_error("replaced", owner.id()))
        );
        assert_eq!(
            store.add(
                owner.new_key(),
                grant(new_owner, 21, 3, Some((121, new_owner))),
                NOW
            ),
            Err(removal_error("replaced", owner.id()))
        );
        store
            .add(owner.new_key(), pair(1, BindingRole::Owner), NOW)
            .unwrap();
        active(&store, owner.id());
        let reopened = dir.open();
        assert_eq!(reopened.keys().unwrap(), store.keys().unwrap());
        assert!(reopened.tombstones().unwrap().is_empty());
    }

    #[test]
    fn spent_grounds_outlive_their_keys() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        store.remove(laptop.id(), Removal::Pc, NOW).unwrap();
        let guest = Device::new();
        store
            .add(
                guest.new_key(),
                grant(owner.id(), 2, 2, Some((3, owner.id()))),
                NOW,
            )
            .unwrap();
        store.remove(guest.id(), Removal::Pc, NOW).unwrap();
        let mut store = dir.open();
        // New keys, old grounds.
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), endorse(owner.id(), 1), NOW),
            Err(StoreError::Spent(gid(1)))
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(owner.id(), 2, 2, Some((4, owner.id()))),
                NOW
            ),
            Err(StoreError::Spent(gid(2)))
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(owner.id(), 5, 2, Some((3, owner.id()))),
                NOW
            ),
            Err(StoreError::InviteSpent(gid(3)))
        );
        // The id sets are separate: a grant_id equal to a spent endorse_id is unspent.
        store
            .add(
                d.new_key(),
                grant(owner.id(), 1, 2, Some((6, owner.id()))),
                NOW,
            )
            .unwrap();
    }

    #[test]
    fn the_server_never_removes_an_owner_key() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        store
            .take_first_use_snapshot(snapshot_of(&[(1, BindingRole::Owner)]), NOW)
            .unwrap();
        assert_eq!(
            store.remove(owner.id(), Removal::Server, NOW),
            Err(StoreError::ServerRemovesOwner)
        );
        active(&store, owner.id());
        assert!(store.tombstones().unwrap().is_empty());
        // … so the server cannot then slip in a first_use key for the owner.
        let d = Device::new();
        let fu = Ground::FirstUse {
            telegram_user_id: 1,
        };
        assert_eq!(
            store.add(d.new_key(), fu.clone(), NOW),
            Err(StoreError::FirstUseClosed("the person has a key"))
        );
        // A removal at the PC leaves a tombstone, which closes first_use too.
        store.remove(owner.id(), Removal::Pc, NOW).unwrap();
        assert_eq!(
            store.add(d.new_key(), fu, NOW),
            Err(StoreError::FirstUseClosed("the person has a removed key"))
        );
        // Unknown and removed keys cannot be removed again.
        assert_eq!(
            store.remove(owner.id(), Removal::Pc, NOW),
            Err(removal_error("pc", owner.id()))
        );
        assert_eq!(
            store.remove(d.id(), Removal::Server, NOW),
            Err(StoreError::NotFound(d.id().clone()))
        );
    }

    /// A guest unbound ([`TrustStore::deny_guest_keys_now`], then the write of memory): every
    /// guest-role key of the person, origin `server` (or `pc` at the PC), in one write; owner-role
    /// keys stay, a person mixing roles included (design §8).
    #[test]
    fn a_guest_unbound_loses_every_guest_key_in_one_write_and_owner_keys_stay() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let owner_laptop = Device::new();
        store
            .add(owner_laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        let guest = add_paired(&mut store, 2, BindingRole::Guest);
        let guest_laptop = Device::new();
        store
            .add(guest_laptop.new_key(), endorse(guest.id(), 2), NOW)
            .unwrap();
        let other = add_paired(&mut store, 3, BindingRole::Guest);
        // The server removes a guest: every key of the guest, origin `server`, one write.
        let before = std::fs::read(dir.primary()).unwrap();
        assert_eq!(
            store.deny_guest_keys_now(2, Removal::Server, NOW + 1),
            Ok((vec![guest.id().clone(), guest_laptop.id().clone()], 0))
        );
        assert_eq!(store.flush(), Ok(true));
        for k in [guest.id(), guest_laptop.id()] {
            assert_eq!(removed_origin(&store, k), Origin::Server);
            assert_eq!(removed(&store, k).at, NOW + 1);
        }
        assert_eq!(std::fs::read(dir.backup()).unwrap(), before);
        active(&store, other.id());
        // Never an owner's keys from the server: nothing denied, nothing to write.
        let on_disk = std::fs::read(dir.primary()).unwrap();
        assert_eq!(
            store.deny_guest_keys_now(1, Removal::Server, NOW),
            Ok((vec![], 2))
        );
        assert_eq!(store.flush(), Ok(false));
        assert_eq!(std::fs::read(dir.primary()).unwrap(), on_disk);
        active(&store, owner.id());
        active(&store, owner_laptop.id());
        // A person mixing roles: the guest-role key goes, the owner-role one stays.
        let mixed = add_paired(&mut store, 3, BindingRole::Owner);
        assert_eq!(
            store.deny_guest_keys_now(3, Removal::Server, NOW + 2),
            Ok((vec![other.id().clone()], 1))
        );
        assert_eq!(store.flush(), Ok(true));
        assert_eq!(removed_origin(&store, other.id()), Origin::Server);
        active(&store, mixed.id());
        // At the PC: origin `pc`.
        let pc_guest = add_paired(&mut store, 4, BindingRole::Guest);
        assert_eq!(
            store.deny_guest_keys_now(4, Removal::Pc, NOW + 3),
            Ok((vec![pc_guest.id().clone()], 0))
        );
        assert_eq!(store.flush(), Ok(true));
        assert_eq!(removed_origin(&store, pc_guest.id()), Origin::Pc);
        // Nobody: nothing denied, nothing to write, no change in flight.
        let on_disk = std::fs::read(dir.primary()).unwrap();
        assert_eq!(
            store.deny_guest_keys_now(77, Removal::Server, NOW),
            Ok((vec![], 0))
        );
        assert_eq!(store.flush(), Ok(false));
        assert!(!store.is_busy());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), on_disk);
        let reopened = dir.open();
        assert_eq!(reopened.tombstones().unwrap(), store.tombstones().unwrap());
    }

    #[test]
    fn first_use_follows_the_snapshot() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let fu = |uid: i64| Ground::FirstUse {
            telegram_user_id: uid,
        };
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), fu(1), NOW),
            Err(StoreError::FirstUseClosed("no snapshot taken yet"))
        );
        // More people than a PC has bindings: refused, nothing taken.
        let too_many: Vec<(i64, BindingRole)> = (1..=MAX_SNAPSHOT_PEOPLE as i64 + 1)
            .map(|uid| (uid, BindingRole::Guest))
            .collect();
        assert!(matches!(
            store.take_first_use_snapshot(snapshot_of(&too_many), NOW),
            Err(StoreError::Invalid(_))
        ));
        assert!(!store.is_busy());
        assert_eq!(store.first_use_snapshot().unwrap(), None);
        // A person listed twice is kept once, with the lesser role; the rest is taken.
        assert!(store
            .take_first_use_snapshot(
                snapshot_of(&[
                    (1, BindingRole::Owner),
                    (2, BindingRole::Guest),
                    (4, BindingRole::Guest),
                    (5, BindingRole::Owner),
                    (5, BindingRole::Guest),
                    (6, BindingRole::Owner),
                    (6, BindingRole::Owner),
                    // Out of range: skipped, the rest is taken.
                    (0, BindingRole::Owner),
                    (MAX_USER_ID + 1, BindingRole::Guest),
                ]),
                NOW
            )
            .unwrap());
        let snapshot = store.first_use_snapshot().unwrap().unwrap().clone();
        assert_eq!(snapshot.people.len(), 5);
        let role_of = |uid: i64| {
            snapshot
                .people
                .iter()
                .find(|p| p.person.telegram_user_id == uid)
                .unwrap()
                .role
        };
        assert_eq!(role_of(5), BindingRole::Guest);
        assert_eq!(role_of(6), BindingRole::Owner);
        // A second one is ignored, even after a reopen.
        let mut store = dir.open();
        assert!(!store
            .take_first_use_snapshot(snapshot_of(&[(9, BindingRole::Owner)]), NOW + 1)
            .unwrap());
        assert_eq!(store.first_use_snapshot().unwrap().unwrap(), &snapshot);
        assert_eq!(
            store.add(d.new_key(), fu(9), NOW),
            Err(StoreError::FirstUseClosed(
                "the person is not in the snapshot"
            ))
        );
        // Role and person from the snapshot, whatever else is known; always unconfirmed.
        let out = store.add(d.new_key(), fu(2), NOW).unwrap();
        assert!(out.unconfirmed);
        let r = active(&store, d.id());
        assert_eq!(r.role, BindingRole::Guest);
        assert!(r.unconfirmed);
        assert_eq!(r.person.first_name.as_deref(), Some("Снимок 2"));
        assert_eq!(r.source, KeySource::FirstUse);
        // A second first_use for that person: its own refusal, in either mode.
        let d2 = Device::new();
        assert_eq!(
            store.add(d2.new_key(), fu(2), NOW),
            Err(StoreError::FirstUseAgain)
        );
        // A person with a removed key (the server removed the guest).
        let g = Device::new();
        store
            .add(g.new_key(), pair(4, BindingRole::Guest), NOW)
            .unwrap();
        store.remove(g.id(), Removal::Server, NOW).unwrap();
        assert_eq!(
            store.add(d2.new_key(), fu(4), NOW),
            Err(StoreError::FirstUseClosed("the person has a removed key"))
        );
        // Strict mode closes first_use.
        store.set_trusted_devices_mode(true).unwrap();
        assert_eq!(
            store.add(d2.new_key(), fu(1), NOW),
            Err(StoreError::FirstUseClosed("trusted devices mode is on"))
        );
        assert_eq!(
            store.add(d2.new_key(), fu(2), NOW),
            Err(StoreError::FirstUseAgain)
        );
        store.set_trusted_devices_mode(false).unwrap();
        store.add(d2.new_key(), fu(1), NOW).unwrap();
        assert_eq!(active(&store, d2.id()).role, BindingRole::Owner);
    }

    #[test]
    fn at_most_sixteen_keys_per_person() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let keys: Vec<Device> = (0..MAX_KEYS_PER_PERSON)
            .map(|_| add_paired(&mut store, 1, BindingRole::Owner))
            .collect();
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), pair(1, BindingRole::Owner), NOW),
            Err(StoreError::Full(Limit::PerPerson))
        );
        assert_eq!(
            store.add(d.new_key(), endorse(keys[0].id(), 1), NOW),
            Err(StoreError::Full(Limit::PerPerson))
        );
        // Another person has room; a removal makes room.
        store
            .add(Device::new().new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        store.remove(keys[3].id(), Removal::Pc, NOW).unwrap();
        store
            .add(d.new_key(), pair(1, BindingRole::Owner), NOW)
            .unwrap();
    }

    #[test]
    fn bounds_on_load_and_on_add() {
        // 256 active: no new key; 257: damage.
        let dir = Scratch::new();
        dir.write(&TrustList {
            keys: many_keys(MAX_ACTIVE_KEYS),
            ..TrustList::default()
        });
        let mut store = dir.open();
        assert!(!store.is_damaged());
        assert_eq!(
            store.add(Device::new().new_key(), pair(9999, BindingRole::Guest), NOW),
            Err(StoreError::Full(Limit::Active))
        );
        let dir = Scratch::new();
        dir.write(&TrustList {
            keys: many_keys(MAX_ACTIVE_KEYS + 1),
            ..TrustList::default()
        });
        assert_eq!(dir.open().damage().unwrap().kind, DamageKind::Invariant);

        // 4096 tombstones: no new key but a pairing at the PC, and removal works and goes past the
        // limit.
        let dir = Scratch::new();
        let keys = many_keys(2);
        dir.write(&TrustList {
            keys: keys.clone(),
            tombstones: (0..MAX_TOMBSTONES).map(tombstone).collect(),
            ..TrustList::default()
        });
        let mut store = dir.open();
        assert_eq!(
            store.add(Device::new().new_key(), endorse(keys[0].key_id(), 1), NOW),
            Err(StoreError::Full(Limit::Tombstones))
        );
        store.remove(keys[0].key_id(), Removal::Pc, NOW).unwrap();
        assert_eq!(store.tombstones().unwrap().len(), MAX_TOMBSTONES + 1);
        assert!(!dir.open().is_damaged());
        // Nothing was evicted.
        assert!(matches!(
            store.lookup(tombstone(0).key_id()),
            Lookup::Removed(_)
        ));
        // A pairing stops at the file's own ceiling.
        let dir = Scratch::new();
        dir.write(&TrustList {
            keys: many_keys(1),
            tombstones: (0..MAX_TOMBSTONES_AT_PC).map(tombstone).collect(),
            ..TrustList::default()
        });
        let mut store = dir.open();
        assert!(!store.is_damaged());
        assert_eq!(
            store.add(Device::new().new_key(), pair(9999, BindingRole::Guest), NOW),
            Err(StoreError::Full(Limit::Tombstones))
        );
        // Past what removals could reach: damage.
        let dir = Scratch::new();
        dir.write(&TrustList {
            keys: many_keys(1),
            tombstones: (0..MAX_TOMBSTONES_AT_PC + MAX_ACTIVE_KEYS)
                .map(tombstone)
                .collect(),
            ..TrustList::default()
        });
        assert_eq!(dir.open().damage().unwrap().kind, DamageKind::Invariant);
        // The fullest list a file may hold is far below the file size limit.
        let fullest = TrustList {
            keys: (0..MAX_ACTIVE_KEYS)
                .map(|i| {
                    let mut r = record(
                        &pool()[i],
                        i as i64 + 1,
                        BindingRole::Guest,
                        Some(&pool()[i + 1]),
                    );
                    r.source = KeySource::Grant {
                        by: pool()[i + 2].key_id().clone(),
                        grant_id: ground(i, 1),
                        inv_id: Some(ground(i, 2)),
                        invite_by: Some(pool()[i + 3].key_id().clone()),
                    };
                    r
                })
                .collect(),
            tombstones: (MAX_ACTIVE_KEYS + 8..MAX_TOMBSTONES_AT_PC + 8)
                .map(|i| Tombstone {
                    source: KeySource::Grant {
                        by: pool()[0].key_id().clone(),
                        grant_id: ground(i, 1),
                        inv_id: Some(ground(i, 2)),
                        invite_by: Some(pool()[1].key_id().clone()),
                    },
                    ..tombstone(i)
                })
                .collect(),
            spent_endorse: (0..MAX_SPENT).map(|i| ground(i, 0)).collect(),
            // The notes at their bounds too — a full last known binding list, the longest ids.
            notes: Box::new(Notes {
                grant_token: GrantToken::fresh(GrantToken::default()),
                attempts: Vec::new(),
                last_bindings: Some(
                    (0..LAST_BINDINGS_MAX as i64)
                        .map(|i| KnownBinding {
                            telegram_user_id: MAX_USER_ID - i,
                            role: BindingRole::Guest,
                        })
                        .collect(),
                ),
            }),
            ..TrustList::default()
        };
        let size = serialize(&fullest).unwrap().len() as u64;
        assert!(size * 2 < MAX_FILE_BYTES, "{size} bytes");

        // 4095 spent: an endorse (one id) fits, a grant with an invitation (two) does not; at
        // 4096 no endorse, but a pair still works.
        let dir = Scratch::new();
        let owner = fresh().1;
        dir.write(&TrustList {
            keys: vec![record(&owner, 1, BindingRole::Owner, None)],
            spent_endorse: (0..1365).map(|i| ground(i, 0)).collect(),
            spent_grant: (0..1365).map(|i| ground(i, 1)).collect(),
            spent_invite: (0..1365).map(|i| ground(i, 2)).collect(),
            ..TrustList::default()
        });
        let mut store = dir.open();
        assert!(!store.is_damaged());
        assert_eq!(
            store.add(
                Device::new().new_key(),
                grant(owner.key_id(), 200, 2, Some((201, owner.key_id()))),
                NOW
            ),
            Err(StoreError::Full(Limit::Spent))
        );
        store
            .add(Device::new().new_key(), endorse(owner.key_id(), 200), NOW)
            .unwrap();
        assert_eq!(
            store.add(Device::new().new_key(), endorse(owner.key_id(), 202), NOW),
            Err(StoreError::Full(Limit::Spent))
        );
        store
            .add(Device::new().new_key(), pair(1, BindingRole::Owner), NOW)
            .unwrap();
        // 4097 spent in a file: damage, whichever sets hold them.
        let dir = Scratch::new();
        dir.write(&TrustList {
            spent_endorse: (0..2000).map(|i| ground(i, 0)).collect(),
            spent_invite: (0..=MAX_SPENT - 2000).map(|i| ground(i, 2)).collect(),
            ..TrustList::default()
        });
        assert_eq!(dir.open().damage().unwrap().kind, DamageKind::Invariant);

        // 17 keys of one person in a file: damage.
        let dir = Scratch::new();
        dir.write(&TrustList {
            keys: (0..=MAX_KEYS_PER_PERSON)
                .map(|_| record(&fresh().1, 1, BindingRole::Guest, None))
                .collect(),
            ..TrustList::default()
        });
        assert_eq!(dir.open().damage().unwrap().kind, DamageKind::Invariant);

        let dir = Scratch::new();
        std::fs::write(dir.primary(), vec![b' '; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert_eq!(dir.open().damage().unwrap().kind, DamageKind::TooLarge);
    }

    #[test]
    fn a_flood_of_tombstones_does_not_lock_the_pc_out() {
        // The server's grounds filled the tombstones.
        let dir = Scratch::new();
        let owner = fresh().1;
        dir.write(&TrustList {
            keys: vec![record(&owner, 1, BindingRole::Owner, None)],
            tombstones: (0..MAX_TOMBSTONES).map(tombstone).collect(),
            snapshot: Some(FirstUseSnapshot {
                taken_at: NOW,
                people: snapshot_of(&[(5, BindingRole::Guest)]),
            }),
            ..TrustList::default()
        });
        let mut store = dir.open();
        assert!(!store.is_damaged());
        // No key on any of the server's grounds …
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), endorse(owner.key_id(), 1), NOW),
            Err(StoreError::Full(Limit::Tombstones))
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(owner.key_id(), 2, 3, Some((3, owner.key_id()))),
                NOW
            ),
            Err(StoreError::Full(Limit::Tombstones))
        );
        assert_eq!(
            store.add(
                d.new_key(),
                Ground::FirstUse {
                    telegram_user_id: 5
                },
                NOW
            ),
            Err(StoreError::Full(Limit::Tombstones))
        );
        // … nor on a marked pairing (`pc_allow`, a window with another session) …
        assert_eq!(
            store.add(d.new_key(), pair_unconfirmed(2, BindingRole::Guest), NOW),
            Err(StoreError::Full(Limit::Tombstones))
        );
        // … but a confirmed pairing at the PC goes through, again after a removal past the limit.
        store
            .add(d.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        store.remove(d.id(), Removal::Pc, NOW).unwrap();
        assert_eq!(store.tombstones().unwrap().len(), MAX_TOMBSTONES + 1);
        let d2 = Device::new();
        store
            .add(d2.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        // It brings back its own removed key too.
        store
            .add(d.new_key(), pair(2, BindingRole::Guest), NOW)
            .unwrap();
        let reopened = dir.open();
        assert!(!reopened.is_damaged());
        active(&reopened, d.id());
        active(&reopened, d2.id());
    }

    // --- unconfirmed (§10.1) --------------------------------------------------------------------

    #[test]
    fn unconfirmed_comes_from_the_ground_and_runs_down_the_chain() {
        let dir = Scratch::new();
        let mut store = dir.open();
        store
            .take_first_use_snapshot(snapshot_of(&[(7, BindingRole::Owner)]), NOW)
            .unwrap();
        let sure = add_paired(&mut store, 1, BindingRole::Owner);
        // A pairing the admission marks.
        let marked = Device::new();
        let out = store
            .add(
                marked.new_key(),
                pair_unconfirmed(1, BindingRole::Owner),
                NOW,
            )
            .unwrap();
        assert!(out.unconfirmed);
        // first_use.
        let migrated = Device::new();
        assert!(
            store
                .add(
                    migrated.new_key(),
                    Ground::FirstUse {
                        telegram_user_id: 7
                    },
                    NOW
                )
                .unwrap()
                .unconfirmed
        );
        // A grant without an invitation.
        let no_invite = Device::new();
        assert!(
            store
                .add(no_invite.new_key(), grant(sure.id(), 1, 2, None), NOW)
                .unwrap()
                .unconfirmed
        );
        // Inherited from the endorser …
        let by_marked = Device::new();
        assert!(
            store
                .add(by_marked.new_key(), endorse(marked.id(), 2), NOW)
                .unwrap()
                .unconfirmed
        );
        let by_migrated = Device::new();
        assert!(
            store
                .add(by_migrated.new_key(), endorse(migrated.id(), 3), NOW)
                .unwrap()
                .unconfirmed
        );
        // … from the grant's signer, and from the invitation's.
        let granted_by_marked = Device::new();
        assert!(
            store
                .add(
                    granted_by_marked.new_key(),
                    grant(marked.id(), 4, 3, Some((5, sure.id()))),
                    NOW
                )
                .unwrap()
                .unconfirmed
        );
        let invited_by_marked = Device::new();
        assert!(
            store
                .add(
                    invited_by_marked.new_key(),
                    grant(sure.id(), 6, 4, Some((7, marked.id()))),
                    NOW
                )
                .unwrap()
                .unconfirmed
        );
        // … and down a second step.
        let grandchild = Device::new();
        assert!(
            store
                .add(grandchild.new_key(), endorse(by_marked.id(), 8), NOW)
                .unwrap()
                .unconfirmed
        );
        // Confirmed signers give a confirmed key.
        let clean = Device::new();
        assert!(
            !store
                .add(
                    clean.new_key(),
                    grant(sure.id(), 9, 5, Some((10, sure.id()))),
                    NOW
                )
                .unwrap()
                .unconfirmed
        );
        let clean2 = Device::new();
        assert!(
            !store
                .add(clean2.new_key(), endorse(sure.id(), 11), NOW)
                .unwrap()
                .unconfirmed
        );
        // A recovery inherits the mark from any record it replaces.
        let one_device = add_paired(&mut store, 8, BindingRole::Guest);
        store
            .add(
                one_device.same_device(),
                pair_unconfirmed(8, BindingRole::Guest),
                NOW,
            )
            .unwrap();
        let attempt = Attempt::new(&one_device, 8);
        let out = store.recover(attempt.recovery(&one_device), NOW).unwrap();
        assert!(out.unconfirmed);
        assert_eq!(out.replaced.len(), 2);
        // Everything as written.
        let reopened = dir.open();
        for (d, want) in [
            (sure.id(), false),
            (marked.id(), true),
            (migrated.id(), true),
            (no_invite.id(), true),
            (by_marked.id(), true),
            (by_migrated.id(), true),
            (granted_by_marked.id(), true),
            (invited_by_marked.id(), true),
            (grandchild.id(), true),
            (clean.id(), false),
            (clean2.id(), false),
            (attempt.new_key.key_id(), true),
        ] {
            assert_eq!(active(&reopened, d).unconfirmed, want, "{d:?}");
        }
    }

    #[test]
    fn strict_mode_adds_no_unconfirmed_key() {
        let dir = Scratch::new();
        let mut store = dir.open();
        store
            .take_first_use_snapshot(snapshot_of(&[(7, BindingRole::Owner)]), NOW)
            .unwrap();
        let sure = add_paired(&mut store, 1, BindingRole::Owner);
        let marked = Device::new();
        store
            .add(
                marked.new_key(),
                pair_unconfirmed(1, BindingRole::Owner),
                NOW,
            )
            .unwrap();
        let one_device = add_paired(&mut store, 8, BindingRole::Guest);
        store
            .add(
                one_device.same_device(),
                pair_unconfirmed(8, BindingRole::Guest),
                NOW,
            )
            .unwrap();
        store.set_trusted_devices_mode(true).unwrap();
        let before = std::fs::read(dir.primary()).unwrap();
        let d = Device::new();
        assert_eq!(
            store.add(d.new_key(), pair_unconfirmed(2, BindingRole::Guest), NOW),
            Err(StoreError::KeyUnconfirmed)
        );
        assert_eq!(
            store.add(
                d.new_key(),
                Ground::FirstUse {
                    telegram_user_id: 7
                },
                NOW
            ),
            Err(StoreError::FirstUseClosed("trusted devices mode is on"))
        );
        assert_eq!(
            store.add(d.new_key(), grant(sure.id(), 1, 2, None), NOW),
            Err(StoreError::InviteMissing)
        );
        assert_eq!(
            store.add(d.new_key(), endorse(marked.id(), 2), NOW),
            Err(StoreError::KeyUnconfirmed)
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(marked.id(), 3, 2, Some((4, sure.id()))),
                NOW
            ),
            Err(StoreError::KeyUnconfirmed)
        );
        assert_eq!(
            store.add(
                d.new_key(),
                grant(sure.id(), 5, 2, Some((6, marked.id()))),
                NOW
            ),
            Err(StoreError::KeyUnconfirmed)
        );
        let attempt = Attempt::new(&one_device, 8);
        assert_eq!(
            store.recover(attempt.recovery(&one_device), NOW),
            Err(StoreError::KeyUnconfirmed)
        );
        // Nothing written, nothing spent.
        assert_eq!(std::fs::read(dir.primary()).unwrap(), before);
        // Confirmed paths still work in strict mode.
        store.add(d.new_key(), endorse(sure.id(), 7), NOW).unwrap();
        store
            .add(Device::new().new_key(), pair(3, BindingRole::Guest), NOW)
            .unwrap();
    }

    #[test]
    fn confirm_clears_one_mark_at_a_time() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let marked = Device::new();
        store
            .add(
                marked.new_key(),
                pair_unconfirmed(1, BindingRole::Owner),
                NOW,
            )
            .unwrap();
        let child = Device::new();
        store
            .add(child.new_key(), endorse(marked.id(), 1), NOW)
            .unwrap();
        assert!(store.confirm(marked.id()).unwrap());
        assert!(!active(&store, marked.id()).unconfirmed);
        assert!(!active(&dir.open(), marked.id()).unconfirmed);
        // The child keeps its own mark: no «confirm all».
        assert!(active(&store, child.id()).unconfirmed);
        // Confirmed already: nothing to write.
        let on_disk = std::fs::read(dir.primary()).unwrap();
        assert!(!store.confirm(marked.id()).unwrap());
        assert_eq!(std::fs::read(dir.primary()).unwrap(), on_disk);
        // Unknown and removed keys.
        let unknown = fresh().1;
        assert_eq!(
            store.confirm(unknown.key_id()),
            Err(StoreError::NotFound(unknown.key_id().clone()))
        );
        store.remove(child.id(), Removal::Pc, NOW).unwrap();
        assert_eq!(
            store.confirm(child.id()),
            Err(removal_error("pc", child.id()))
        );
        // A confirmed key's next endorsement is confirmed, also in strict mode.
        store.set_trusted_devices_mode(true).unwrap();
        let next = Device::new();
        assert!(
            !store
                .add(next.new_key(), endorse(marked.id(), 2), NOW)
                .unwrap()
                .unconfirmed
        );
    }

    #[test]
    fn delete_takes_the_whole_chain_in_one_write() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let root = add_paired(&mut store, 1, BindingRole::Owner);
        let other_owner = add_paired(&mut store, 1, BindingRole::Owner);
        // root → child (endorse) → grandchild (grant by child, invitation by the other owner).
        let child = Device::new();
        store
            .add(child.new_key(), endorse(root.id(), 1), NOW)
            .unwrap();
        let grandchild = Device::new();
        store
            .add(
                grandchild.new_key(),
                grant(child.id(), 2, 2, Some((3, other_owner.id()))),
                NOW,
            )
            .unwrap();
        // Invited by the root only: a descendant through `invite.by`.
        let invited = Device::new();
        store
            .add(
                invited.new_key(),
                grant(other_owner.id(), 4, 3, Some((5, root.id()))),
                NOW,
            )
            .unwrap();
        let unrelated = add_paired(&mut store, 4, BindingRole::Guest);
        let before = std::fs::read(dir.primary()).unwrap();
        let removed_ids = remove_tree(&mut store, root.id(), NOW + 1).unwrap().removed;
        assert_eq!(removed_ids[0], *root.id());
        assert_eq!(removed_ids.len(), 4);
        for k in [root.id(), child.id(), grandchild.id(), invited.id()] {
            assert!(removed_ids.contains(k));
            assert_eq!(removed_origin(&store, k), Origin::Pc);
        }
        active(&store, other_owner.id());
        active(&store, unrelated.id());
        // One write: the backup is the list as it was just before.
        assert_eq!(std::fs::read(dir.backup()).unwrap(), before);
        let reopened = dir.open();
        assert_eq!(reopened.tombstones().unwrap(), store.tombstones().unwrap());
        // A removed root with nothing left below it: nothing to end; an unknown root: refused.
        assert_eq!(
            remove_tree(&mut store, root.id(), NOW).unwrap().removed,
            Vec::<KeyId>::new()
        );
        let unknown = fresh().1;
        assert_eq!(
            remove_tree(&mut store, unknown.key_id(), NOW),
            Err(StoreError::NotFound(unknown.key_id().clone()))
        );
        // A leaf: itself only.
        assert_eq!(
            remove_tree(&mut store, unrelated.id(), NOW)
                .unwrap()
                .removed,
            vec![unrelated.id().clone()]
        );
    }

    #[test]
    fn descendants_are_found_through_removed_keys_and_recoveries() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let root = add_paired(&mut store, 1, BindingRole::Owner);
        let middle = Device::new();
        store
            .add(middle.new_key(), endorse(root.id(), 1), NOW)
            .unwrap();
        let leaf = Device::new();
        store
            .add(leaf.new_key(), endorse(middle.id(), 2), NOW)
            .unwrap();
        // The middle key removed alone: the leaf still descends from the root.
        store.remove(middle.id(), Removal::Pc, NOW).unwrap();
        // Another of the root's children recovered on its device: the new key inherits its place.
        let phone = Device::new();
        store
            .add(phone.new_key(), endorse(root.id(), 3), NOW)
            .unwrap();
        let attempt = Attempt::new(&phone, 1);
        store.recover(attempt.recovery(&phone), NOW).unwrap();
        let unrelated = add_paired(&mut store, 1, BindingRole::Owner);
        let removed_ids = remove_tree(&mut store, root.id(), NOW).unwrap().removed;
        assert_eq!(removed_ids.len(), 3);
        for k in [root.id(), leaf.id(), attempt.new_key.key_id()] {
            assert!(removed_ids.contains(k), "{k:?}");
        }
        active(&store, unrelated.id());
    }

    #[test]
    fn removal_with_descendants_starts_from_a_removed_root() {
        let dir = Scratch::new();
        let mut store = dir.open();
        // A guest's key, and a key it endorsed; the server removes the guest's first key.
        let root = add_paired(&mut store, 2, BindingRole::Guest);
        let child = Device::new();
        store
            .add(child.new_key(), endorse(root.id(), 1), NOW)
            .unwrap();
        store.remove(root.id(), Removal::Server, NOW).unwrap();
        // «Удалить» at the PC on the removed root: its descendants go; the root's own removal
        // stays the server's (a walk changes no tombstone).
        let out = remove_tree(&mut store, root.id(), NOW + 1).unwrap();
        assert_eq!(out.removed, vec![child.id().clone()]);
        assert_eq!(removed_origin(&store, root.id()), Origin::Server);
        assert_eq!(removed_origin(&store, child.id()), Origin::Pc);
        assert_eq!(removed_origin(&dir.open(), root.id()), Origin::Server);
    }

    /// Not a defect; defence in depth. B — a guest X granted, removed by the
    /// server — is lifted by a fresh grant of another owner's key U whose write is in flight when
    /// the person removes X («Удалить»). Through the PC's window this cannot happen: the lift's
    /// offer is a first offer waiting for its write, which locks the trust window like any session
    /// not signed by a confirmed owner key (§3.4, §10.1), so «Удалить» is refused until it lands.
    /// Here the store is driven directly, and its order is still sound: the lift was decided
    /// first, so it comes first — once installed, B is U's (a lifted record's edges are its new
    /// source; §10.1 walks a revoked record's old edges only «while it stays revoked») and X's
    /// removal — its write of memory, as the press decided it (B was not active then) — leaves B,
    /// exactly as had the two steps run one after the other. Z, which B endorsed before its
    /// removal, was in X's tree when «Удалить» was pressed (counted then, through B's tombstone):
    /// it is denied at once, and the next write — X's own here — carries its removal (`pc`): the
    /// press decides (§10.1).
    #[test]
    fn a_lift_in_flight_comes_before_a_removal_pressed_after_it() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let x = add_paired(&mut store, 1, BindingRole::Owner);
        let u = add_paired(&mut store, 5, BindingRole::Owner);
        let b = Device::new();
        store
            .add(b.new_key(), grant(x.id(), 1, 2, Some((2, x.id()))), NOW)
            .unwrap();
        let z = Device::new();
        store.add(z.new_key(), endorse(b.id(), 3), NOW).unwrap();
        store.remove(b.id(), Removal::Server, NOW).unwrap();
        // The lift: staged and written, not installed yet.
        let lift = store
            .stage_add(b.new_key(), grant(u.id(), 4, 2, Some((5, u.id()))), NOW + 1)
            .unwrap()
            .write()
            .unwrap();
        // «Удалить» X now: denied at once — X and Z (through B's tombstone); B is not active.
        let denied: HashSet<KeyId> = store
            .deny_tree_now(x.id(), 0)
            .unwrap()
            .removed
            .into_iter()
            .collect();
        assert_eq!(denied, HashSet::from([x.id().clone(), z.id().clone()]));
        store.install(lift).unwrap();
        assert_eq!(active(&store, b.id()).source.parents(), vec![u.id()]);
        // X's removal, its write of memory: X as the press decided it; B is U's now and stays.
        assert_eq!(store.flush(), Ok(true));
        assert_eq!(removed_origin(&store, x.id()), Origin::Pc);
        active(&store, b.id());
        // Z: in X's tree when the person pressed — the press decided it («Нажатие решает сразу»):
        // X's write, a snapshot of memory, carries Z's removal too (`pc`).
        assert_eq!(removed_origin(&store, z.id()), Origin::Pc);
        assert_eq!(removed_origin(&dir.open(), z.id()), Origin::Pc);
        assert!(store.pending_without_removal().is_empty());
        // The other order — the removal first — replaces the token: the grant signed before it
        // is stale; B's tombstone stays `server`.
        let dir = Scratch::new();
        let mut store = dir.open();
        let x = add_paired(&mut store, 1, BindingRole::Owner);
        let u = add_paired(&mut store, 5, BindingRole::Owner);
        store
            .add(b.new_key(), grant(x.id(), 1, 2, Some((2, x.id()))), NOW)
            .unwrap();
        store.remove(b.id(), Removal::Server, NOW).unwrap();
        let out = remove_tree(&mut store, x.id(), NOW + 1).unwrap();
        assert_eq!(out.removed, vec![x.id().clone()]);
        assert_eq!(removed_origin(&store, b.id()), Origin::Server);
        assert_eq!(
            store.add(b.new_key(), grant(u.id(), 4, 2, Some((5, u.id()))), NOW + 2),
            Err(StoreError::GrantStale)
        );
    }

    /// «Нажатие решает сразу» (spec §10.1, b24cd56; §7 «Смена»). B — a guest X granted, removed
    /// by the server — sits in X's tree. «Удалить» X is pressed and its write FAILS (an injected
    /// I/O error: the backup path is a directory) and parks. The press decided in memory: X
    /// denied, the grant token replaced; B's tombstone stays `server`. A fresh grant for B from an
    /// independent owner key U signed over the old token is `grant_stale`. An unrelated write
    /// that lands meanwhile is a snapshot of memory: it carries X's removal and the new token, so
    /// the parked removal is superseded; a fresh process reads them. Without the token at the
    /// press the old grant lifts B; without the carried removal X stays active on disk.
    #[test]
    fn a_removal_decides_at_the_press_even_while_its_write_is_parked() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let x = add_paired(&mut store, 1, BindingRole::Owner);
        let u = add_paired(&mut store, 5, BindingRole::Owner);
        let b = Device::new();
        store
            .add(b.new_key(), grant(x.id(), 1, 2, Some((2, x.id()))), NOW)
            .unwrap();
        store.remove(b.id(), Removal::Server, NOW).unwrap();
        let old = store.grant_token().unwrap();
        // The press: denied and the token replaced in memory at once; B stays `server`.
        let denied = store.deny_tree_now(x.id(), NOW + 1).unwrap().removed;
        assert_eq!(denied, vec![x.id().clone()]);
        assert_eq!(removed_origin(&store, b.id()), Origin::Server);
        let new_token = store.grant_token().unwrap();
        assert_ne!(new_token, old);
        // Its write fails (injected) and parks.
        let jam = dir.backup();
        let _ = std::fs::remove_file(&jam);
        std::fs::create_dir_all(jam.join("jam")).unwrap();
        let staged = store.stage_flush().unwrap().unwrap();
        let failed = staged.write().unwrap_err();
        assert!(
            matches!(failed.error(), StoreError::Write(_)),
            "{:?}",
            failed.error()
        );
        let _ = store.abandon(failed);
        if store.needs_reopen() {
            let _ = store.reopen();
        }
        assert_eq!(dir.open().grant_token(), Some(old), "nothing landed");
        // A fresh grant from U for B over the old token: stale, the press decided.
        std::fs::remove_dir_all(&jam).unwrap();
        assert_eq!(
            store.add(
                b.new_key(),
                over(grant(u.id(), 4, 2, Some((5, u.id()))), old),
                NOW + 2
            ),
            Err(StoreError::GrantStale)
        );
        // An unrelated write lands first: a snapshot of memory, it carries the parked removal —
        // X removed `pc` — and the new token; a fresh process reads both.
        let c = add_paired(&mut store, 7, BindingRole::Guest);
        let on_disk = dir.open();
        assert_eq!(removed_origin(&on_disk, b.id()), Origin::Server);
        assert_eq!(removed_origin(&on_disk, x.id()), Origin::Pc);
        assert_eq!(on_disk.grant_token(), Some(new_token));
        active(&on_disk, c.id());
        assert!(!matches!(
            store.lookup(x.id()),
            Lookup::Active(_) | Lookup::PendingRemoval(_)
        ));
        // The parked removal's write of memory, tried again, is superseded: nothing to write.
        assert_eq!(store.flush(), Ok(false));
        assert_eq!(
            dir.open().add(
                b.new_key(),
                over(grant(u.id(), 6, 2, Some((7, u.id()))), old),
                NOW + 4
            ),
            Err(StoreError::GrantStale)
        );
    }

    // --- Recovery -------------------------------------------------------------------------------

    #[test]
    fn recovery_refusals() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let before = std::fs::read(dir.primary()).unwrap();
        let attempt = Attempt::new(&owner, 1);

        // No record with this recovery key.
        let stranger = Device::new();
        let theirs = Attempt::new(&stranger, 1);
        assert_eq!(
            store.recover(theirs.recovery(&stranger), NOW),
            Err(StoreError::RecoverNoRecord)
        );
        // Another person's attestation: the owner's record is not a candidate for them.
        let other_person = Attempt::new(&owner, 2);
        assert_eq!(
            store.recover(other_person.recovery(&owner), NOW),
            Err(StoreError::RecoverNoRecord)
        );
        // An attestation of another key than the new one.
        let mut other_key = Attempt::new(&owner, 1);
        other_key.attested = TelegramIdentity::for_tests(1, None, None, fresh().1.key_id().clone());
        assert_eq!(
            store.recover(other_key.recovery(&owner), NOW),
            Err(StoreError::RecoverAttestation)
        );
        // Bad recovery signatures: over another session, PC, new key or nonce (the store builds
        // `r` from its own arguments), by another key, a flipped bit, short, zeros.
        let new_id = attempt.new_key.key_id();
        let mut flipped = attempt.rsig.clone();
        flipped[10] ^= 1;
        for bad in [
            owner.rsig(&independent_r(DEVICE_ID, "other-session", new_id, &NONCE)),
            owner.rsig(&independent_r("other-pc", SESSION_ID, new_id, &NONCE)),
            owner.rsig(&independent_r(
                DEVICE_ID,
                SESSION_ID,
                fresh().1.key_id(),
                &NONCE,
            )),
            owner.rsig(&independent_r(DEVICE_ID, SESSION_ID, new_id, &[0; 16])),
            stranger.rsig(&independent_r(DEVICE_ID, SESSION_ID, new_id, &NONCE)),
            flipped,
            attempt.rsig[..63].to_vec(),
            vec![0u8; 64],
        ] {
            let mut a = Attempt::for_key(&owner, 1, attempt.new_key.clone());
            a.rsig = bad;
            assert_eq!(
                store.recover(a.recovery(&owner), NOW),
                Err(StoreError::RecoverBadSig)
            );
        }
        // The right signature with the store told another nonce or session.
        let mut r = attempt.recovery(&owner);
        r.nonce_pc = [1; 16];
        assert_eq!(store.recover(r, NOW), Err(StoreError::RecoverBadSig));
        let mut r = attempt.recovery(&owner);
        r.session_id = "5f0c6a1e-3b2d-4c8e-9a71-0d2e4f6b8c11";
        assert_eq!(store.recover(r, NOW), Err(StoreError::RecoverBadSig));
        // A new key that is active, or the recovery key itself.
        let same = Attempt::for_key(&owner, 1, owner.key.clone());
        assert_eq!(
            store.recover(same.recovery(&owner), NOW),
            Err(StoreError::AlreadyActive(owner.id().clone()))
        );
        let itself = Attempt::for_key(&owner, 1, owner.rpk.clone());
        assert!(matches!(
            store.recover(itself.recovery(&owner), NOW),
            Err(StoreError::Invalid(_))
        ));
        // Nothing changed.
        assert_eq!(std::fs::read(dir.primary()).unwrap(), before);
        active(&store, owner.id());

        // A new key that was removed.
        let gone = add_paired(&mut store, 1, BindingRole::Owner);
        store.remove(gone.id(), Removal::Pc, NOW).unwrap();
        let again = Attempt::for_key(&owner, 1, gone.key.clone());
        assert_eq!(
            store.recover(again.recovery(&owner), NOW),
            Err(removal_error("pc", gone.id()))
        );
        // A removed record's recovery key finds nothing.
        let after_removal = Attempt::new(&gone, 1);
        assert_eq!(
            store.recover(after_removal.recovery(&gone), NOW),
            Err(StoreError::RecoverNoRecord)
        );
        // And the honest attempt goes through.
        store.recover(attempt.recovery(&owner), NOW).unwrap();
    }

    #[test]
    fn a_recovery_never_crosses_people() {
        // Two people's records with one recovery key cannot load (invariant); a pairing drops the
        // second one's rpk. So the other person's record is never a candidate: refused, not
        // replaced.
        let dir = Scratch::new();
        let mut store = dir.open();
        let vera = add_paired(&mut store, 1, BindingRole::Owner);
        let petya_key = fresh().1;
        let out = store
            .add(
                NewKey {
                    key: petya_key.clone(),
                    rpk: Some(vera.rpk.clone()),
                    kind: kind("telegram"),
                    platform: platform("android"),
                },
                pair(2, BindingRole::Guest),
                NOW,
            )
            .unwrap();
        assert!(out.rpk_dropped);
        let as_petya = Attempt::new(&vera, 2);
        assert_eq!(
            store.recover(as_petya.recovery(&vera), NOW),
            Err(StoreError::RecoverNoRecord)
        );
        active(&store, vera.id());
        active(&store, petya_key.key_id());
    }

    /// One person with two records of one device (one recovery key): an owner's and a guest's.
    fn shared_rpk(dir: &Scratch) -> (TrustStore, Device, NewKey) {
        let mut store = dir.open();
        let device = add_paired(&mut store, 1, BindingRole::Owner);
        let second = device.same_device();
        store
            .add(second.clone(), pair(1, BindingRole::Guest), NOW)
            .unwrap();
        // Someone else's record stays out of it.
        add_paired(&mut store, 2, BindingRole::Guest);
        (store, device, second)
    }

    #[test]
    fn recovery_takes_the_lesser_role_and_replaces_every_candidate() {
        let dir = Scratch::new();
        let (mut store, device, guest_rec) = shared_rpk(&dir);
        let attempt = Attempt::new(&device, 1);
        let out = store.recover(attempt.recovery(&device), NOW + 9).unwrap();
        assert_eq!(out.role, BindingRole::Guest);
        assert_eq!(out.telegram_user_id, 1);
        assert_eq!(out.replaced.len(), 2);
        let new_rec = active(&store, attempt.new_key.key_id());
        assert_eq!(new_rec.role, BindingRole::Guest);
        assert_eq!(new_rec.added_at, NOW + 9);
        assert_eq!(
            new_rec.source,
            KeySource::Recover {
                replaced: out.replaced.clone(),
                parents: Vec::new(),
            }
        );
        for gone in [device.id(), guest_rec.key.key_id()] {
            assert!(out.replaced.contains(gone));
            let t = removed(&store, gone);
            assert_eq!(
                t.origin,
                Origin::Replaced {
                    new_key_id: attempt.new_key.key_id().clone()
                }
            );
            assert_eq!(t.at, NOW + 9);
        }
        assert_eq!(store.keys().unwrap().len(), 2);
        let reopened = dir.open();
        assert_eq!(reopened.keys().unwrap(), store.keys().unwrap());
        // An owner's single record stays an owner's.
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let attempt = Attempt::new(&owner, 1);
        assert_eq!(
            store.recover(attempt.recovery(&owner), NOW).unwrap().role,
            BindingRole::Owner
        );
    }

    #[test]
    fn recovery_needs_room_for_every_replaced_key() {
        let device = Device::new();
        let second = device.same_device();
        let both = |tombstones: usize| {
            let dir = Scratch::new();
            let mut first = record(&device.key, 7777, BindingRole::Guest, Some(&device.rpk));
            first.person = person(7777);
            let mut other = record(&second.key, 7777, BindingRole::Guest, Some(&device.rpk));
            other.person = person(7777);
            dir.write(&TrustList {
                keys: vec![first, other],
                tombstones: (0..tombstones).map(tombstone).collect(),
                ..TrustList::default()
            });
            dir
        };
        // 4095 tombstones + 2 replaced > 4096: refused; a removal still works.
        let dir = both(MAX_TOMBSTONES - 1);
        let mut store = dir.open();
        assert!(!store.is_damaged());
        let attempt = Attempt::new(&device, 7777);
        assert_eq!(
            store.recover(attempt.recovery(&device), NOW),
            Err(StoreError::Full(Limit::Tombstones))
        );
        store.remove(device.id(), Removal::Pc, NOW).unwrap();
        // 4094 + 2 = 4096: room.
        let dir = both(MAX_TOMBSTONES - 2);
        let mut store = dir.open();
        let out = store.recover(attempt.recovery(&device), NOW).unwrap();
        assert_eq!(out.replaced.len(), 2);
        assert_eq!(store.tombstones().unwrap().len(), MAX_TOMBSTONES);
        assert!(!dir.open().is_damaged());
    }

    #[test]
    fn recovery_works_on_a_full_list() {
        let dir = Scratch::new();
        let device = Device::new();
        let mut keys = many_keys(MAX_ACTIVE_KEYS - 1);
        keys.push(record(
            &device.key,
            7777,
            BindingRole::Guest,
            Some(&device.rpk),
        ));
        dir.write(&TrustList {
            keys,
            ..TrustList::default()
        });
        let mut store = dir.open();
        assert_eq!(
            store.add(Device::new().new_key(), pair(1, BindingRole::Guest), NOW),
            Err(StoreError::Full(Limit::Active))
        );
        let attempt = Attempt::new(&device, 7777);
        let out = store.recover(attempt.recovery(&device), NOW).unwrap();
        assert_eq!(out.replaced, vec![device.id().clone()]);
        assert_eq!(store.keys().unwrap().len(), MAX_ACTIVE_KEYS);
    }

    // --- Logs -----------------------------------------------------------------------------------

    /// What `f` logs at every level, on this thread.
    fn logged(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let ours = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .with_writer(move || writer.clone())
                .finish(),
        );
        // A second live dispatcher makes tracing ask every one of them rather than cache "off" for
        // a call site another test's subscriber saw first.
        let _second = tracing::Dispatch::new(tracing_subscriber::registry());
        tracing::dispatcher::with_default(&ours, f);
        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        log
    }

    #[test]
    fn logs_and_errors_name_keys_by_eight_characters() {
        let dir = Scratch::new();
        let mut ids: Vec<KeyId> = Vec::new();
        let mut texts: Vec<String> = Vec::new();
        let log = logged(|| {
            let mut store = dir.open();
            let owner = add_paired(&mut store, 1, BindingRole::Owner);
            let laptop = Device::new();
            store
                .add(laptop.new_key(), endorse(owner.id(), 1), NOW)
                .unwrap();
            let guest = Device::new();
            store
                .add(
                    guest.new_key(),
                    grant(owner.id(), 2, 2, Some((3, owner.id()))),
                    NOW,
                )
                .unwrap();
            store.lookup(guest.id());
            store.touch(owner.id(), NOW).unwrap();
            store.remove(guest.id(), Removal::Server, NOW).unwrap();
            store.lookup(guest.id());
            let attempt = Attempt::new(&owner, 1);
            store.recover(attempt.recovery(&owner), NOW).unwrap();
            // Refusals of every kind that name a key.
            for e in [
                store
                    .add(owner.new_key(), endorse(laptop.id(), 4), NOW)
                    .unwrap_err(),
                store
                    .add(laptop.new_key(), pair(1, BindingRole::Owner), NOW)
                    .unwrap_err(),
                store.remove(guest.id(), Removal::Pc, NOW).unwrap_err(),
                store.confirm(owner.id()).unwrap_err(),
                store
                    .add(Device::new().new_key(), endorse(owner.id(), 5), NOW)
                    .unwrap_err(),
                store
                    .add(Device::new().new_key(), endorse(guest.id(), 6), NOW)
                    .unwrap_err(),
            ] {
                texts.push(e.to_string());
                texts.push(format!("{e:?}"));
            }
            remove_tree(&mut store, laptop.id(), NOW).unwrap();
            let staged = store.stage_set_trusted_devices_mode(true).unwrap().unwrap();
            texts.push(format!("{staged:?}"));
            // A damaged file whose key_id is not its SPKI's.
            edit_primary(&dir, |v| {
                v["keys"][0]["key_id"] = owner.id().as_str().into();
            });
            let damaged = dir.open();
            texts.push(damaged.damage().unwrap().to_string());
            ViewerKey::from_spki(owner.key.spki()).unwrap();
            ids.extend(
                [
                    owner.id(),
                    laptop.id(),
                    guest.id(),
                    attempt.new_key.key_id(),
                ]
                .into_iter()
                .cloned(),
            );
            ids.push(owner.rpk.key_id().clone());
        });
        assert!(!log.is_empty());
        for id in &ids {
            assert!(
                !log.contains(id.as_str()),
                "a full key_id in the log:\n{log}"
            );
            for text in &texts {
                assert!(!text.contains(id.as_str()), "a full key_id in: {text}");
            }
        }
        // The short form is what names them.
        assert!(log.contains(&format!("kid={}", ids[0].short())), "{log}");
        assert!(texts.iter().any(|t| t.contains(ids[0].short())));
    }

    // --- Queries for the PC's window ----------------------------------------------------------

    /// `dependents` counts what «Удалить» would take besides the key itself — through endorse,
    /// grant and a removed link — and agrees with what the removal then takes.
    #[test]
    fn dependents_count_the_active_keys_a_removal_takes_with_it() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        let guest = Device::new();
        store
            .add(
                guest.new_key(),
                grant(laptop.id(), 2, 5, Some((3, owner.id()))),
                NOW,
            )
            .unwrap();
        let guest_phone = Device::new();
        store
            .add(guest_phone.new_key(), endorse(guest.id(), 4), NOW)
            .unwrap();
        let other = add_paired(&mut store, 7, BindingRole::Guest);
        // A removed link: the guest's phone still descends from the owner through it.
        store.remove(guest.id(), Removal::Server, NOW).unwrap();

        let deps = store.dependents().unwrap();
        assert_eq!(deps.len(), 4, "one count per active key");
        assert_eq!(deps[owner.id()], 2, "laptop and the guest's phone");
        assert_eq!(
            deps[laptop.id()],
            1,
            "the guest's phone, through the removed guest"
        );
        assert_eq!(deps[guest_phone.id()], 0);
        assert_eq!(deps[other.id()], 0);

        let removed = remove_tree(&mut store, owner.id(), NOW).unwrap().removed;
        assert_eq!(removed.len(), 1 + 2);
        assert_eq!(store.dependents().unwrap()[other.id()], 0);
    }

    /// `signed_by` names the signer of an endorse or a grant, with its record while it is active.
    #[test]
    fn signed_by_resolves_the_signer_while_it_is_in_the_list() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        let guest = Device::new();
        store
            .add(
                guest.new_key(),
                grant(owner.id(), 2, 5, Some((3, owner.id()))),
                NOW,
            )
            .unwrap();

        assert_eq!(
            store.signed_by(owner.id()).unwrap(),
            None,
            "a pairing has no signer"
        );
        let (by, record) = store.signed_by(laptop.id()).unwrap().unwrap();
        assert_eq!(by, owner.id());
        assert_eq!(record.map(|l| l.record.key_id()), Some(owner.id()));
        let (by, _) = store.signed_by(guest.id()).unwrap().unwrap();
        assert_eq!(by, owner.id(), "a grant's signer is the owner's key");

        // The laptop's own key removed: its endorse's signer is still the owner's.
        store.remove(owner.id(), Removal::Pc, NOW).unwrap();
        let (by, record) = store.signed_by(laptop.id()).unwrap().unwrap();
        assert_eq!(by, owner.id());
        assert!(record.is_none(), "the signer is out of the list");
        assert_eq!(store.signed_by(owner.id()).unwrap(), None, "not active");
    }

    /// `people` groups the active keys by person; `snapshot_people_without_keys` lists the
    /// snapshot's people who never had one here; `full` names a list-wide limit.
    #[test]
    fn people_waiting_and_full_read_the_list() {
        let dir = Scratch::new();
        let mut store = dir.open();
        assert!(store.snapshot_people_without_keys().unwrap().is_empty());
        store
            .take_first_use_snapshot(
                snapshot_of(&[
                    (1, BindingRole::Owner),
                    (5, BindingRole::Guest),
                    (6, BindingRole::Guest),
                    (8, BindingRole::Guest),
                ]),
                NOW,
            )
            .unwrap();
        let a = add_paired(&mut store, 1, BindingRole::Owner);
        let b = add_paired(&mut store, 5, BindingRole::Guest);
        let c = add_paired(&mut store, 1, BindingRole::Owner);
        let d = add_paired(&mut store, 6, BindingRole::Guest);
        store.remove(d.id(), Removal::Pc, NOW).unwrap();

        let people = store.listed_people().unwrap();
        let ids: Vec<(i64, Vec<&KeyId>)> = people
            .iter()
            .map(|(uid, keys)| (*uid, keys.iter().map(|l| l.record.key_id()).collect()))
            .collect();
        assert_eq!(ids, vec![(1, vec![a.id(), c.id()]), (5, vec![b.id()])]);
        // 6 had a key (removed), 1 and 5 have one: only 8 never connected with a key.
        assert_eq!(store.snapshot_people_without_keys().unwrap(), vec![8]);
        assert_eq!(store.full().unwrap(), None);

        // A list at its tombstone limit is full for new keys.
        let list = TrustList {
            tombstones: (0..MAX_TOMBSTONES).map(tombstone).collect(),
            ..TrustList::default()
        };
        let dir = Scratch::new();
        dir.write(&list);
        let store = dir.open();
        assert!(!store.is_damaged(), "{:?}", store.damage());
        assert_eq!(store.full().unwrap(), Some(Limit::Tombstones));
    }

    /// Every query answers «damaged» on a damaged store; the backup check reads the backup.
    #[test]
    fn window_queries_on_a_damaged_store_and_the_backup_check() {
        let dir = Scratch::new();
        // Its later changes put a good list in the backup.
        let (store, owner) = store_with_owner(&dir);
        assert!(TrustStore::backup_restorable(&store.paths()));

        std::fs::write(dir.primary(), b"{ not json").unwrap();
        let store = dir.open();
        assert_eq!(store.dependents(), Err(StoreError::Damaged));
        assert_eq!(store.signed_by(owner.id()), Err(StoreError::Damaged));
        assert_eq!(store.listed_people(), Err(StoreError::Damaged));
        assert_eq!(store.person_keys(1), Err(StoreError::Damaged));
        assert!(store.listed(owner.id()).is_none());
        assert!(store.person_names(1).is_none());
        assert_eq!(
            store.snapshot_people_without_keys(),
            Err(StoreError::Damaged)
        );
        assert_eq!(store.full(), Err(StoreError::Damaged));
        assert!(TrustStore::backup_restorable(&store.paths()));

        std::fs::write(dir.backup(), b"{\"version\":1").unwrap();
        assert!(!TrustStore::backup_restorable(&store.paths()));
        std::fs::write(dir.backup(), b"{\"version\":99}").unwrap();
        assert!(
            !TrustStore::backup_restorable(&store.paths()),
            "a newer one"
        );
        std::fs::remove_file(dir.backup()).unwrap();
        assert!(!TrustStore::backup_restorable(&store.paths()));
    }

    // --- §10 «Сверка со списком сервера: одно правило» ([`TrustStore::bring_to_rule`]) --------

    /// The current binding list of the rule's tests: these people, as guests.
    fn named(people: &[i64]) -> BTreeMap<i64, BindingRole> {
        people
            .iter()
            .map(|uid| (*uid, BindingRole::Guest))
            .collect()
    }

    /// Past the grace of every key added at `NOW`.
    const LATER: i64 = NOW + UNBOUND_KEY_GRACE_MS;

    /// The rule takes an unnamed guest — the guest key denied (pending, origin server), their
    /// attempts gone and the grant token replaced (the one shared step), their sessions to end —
    /// and leaves a named guest and the owner as they are; the stored list becomes the current
    /// one. Refutes a rule that takes a named person, spares an unnamed one, or leaves the stored
    /// list behind.
    #[test]
    fn the_rule_takes_an_unnamed_guest_and_spares_the_named() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let gone = add_paired(&mut store, 5, BindingRole::Guest);
        let kept = add_paired(&mut store, 6, BindingRole::Guest);
        let tried = Device::new();
        assert!(store.note_attempt(attempt_of(5, &tried, NOW), NOW));
        let token = store.grant_token();
        let run = store.bring_to_rule(&named(&[1, 6]), LATER).unwrap();
        assert_eq!(run.ended, vec![5]);
        assert_eq!(run.denied, vec![gone.id().clone()]);
        assert!(run.list_noted && run.rotated && run.due_at.is_none());
        assert_ne!(store.grant_token(), token);
        assert!(store.attempt(5, tried.id()).is_none(), "their attempts go");
        assert!(matches!(store.lookup(gone.id()), Lookup::PendingRemoval(_)));
        assert_eq!(store.removal_decided(gone.id()), Some("server"));
        assert!(matches!(store.lookup(kept.id()), Lookup::Active(_)));
        assert!(matches!(store.lookup(owner.id()), Lookup::Active(_)));
        let stored: Vec<i64> = store
            .last_bindings()
            .unwrap()
            .iter()
            .map(|b| b.telegram_user_id)
            .collect();
        assert_eq!(stored, vec![1, 6]);
    }

    /// §10: the holder of a working owner-role key whom the list does not name is not touched at
    /// all — their owner-role key, their guest-role key, their attempts and the grant token stay,
    /// and none of their sessions end. A person whose only owner-role key is leaving (its removal
    /// decided) has nothing the rule takes: the rule carries no owner-role key. Refutes a rule
    /// that removes an owner key — or a working owner's guest key — on the server's word.
    #[test]
    fn the_rule_never_touches_a_working_owner_key_holder() {
        let dir = Scratch::new();
        let mut store = dir.open();
        store.set_wall_now(NOW);
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let owners_guest = add_paired(&mut store, 1, BindingRole::Guest);
        let tried = Device::new();
        assert!(store.note_attempt(attempt_of(1, &tried, NOW), NOW));
        let leaving = add_paired(&mut store, 7, BindingRole::Owner);
        store.deny_now(std::slice::from_ref(leaving.id()));
        let token = store.grant_token();
        let run = store.bring_to_rule(&named(&[]), LATER).unwrap();
        assert!(matches!(store.lookup(owner.id()), Lookup::Active(_)));
        assert!(
            matches!(store.lookup(owners_guest.id()), Lookup::Active(_)),
            "their guest-role key stays"
        );
        assert!(
            store.attempt(1, tried.id()).is_some(),
            "their attempts stay"
        );
        assert_eq!(store.grant_token(), token, "the token stays");
        assert!(run.ended.is_empty() && run.denied.is_empty(), "{run:?}");
        assert_eq!(
            store.removal_decided(leaving.id()),
            Some("pending"),
            "the rule carries no owner-role key (never `server`)"
        );
    }

    /// «Запас»: a person with a key younger than [`UNBOUND_KEY_GRACE_MS`] is skipped, and the run
    /// says when the grace ends; at that time they are taken. A key written «in the future» (the
    /// clock went back) gives no grace. Refutes a grace that never ends, one counted from the
    /// wrong end, or one a clock moved back extends.
    #[test]
    fn the_rule_spares_a_fresh_key_for_the_grace_only() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let fresh = add_paired(&mut store, 5, BindingRole::Guest);
        let run = store.bring_to_rule(&named(&[]), LATER - 1).unwrap();
        assert!(run.ended.is_empty() && run.denied.is_empty());
        assert_eq!(run.due_at, Some(LATER));
        assert!(matches!(store.lookup(fresh.id()), Lookup::Active(_)));
        let run = store.bring_to_rule(&named(&[]), LATER).unwrap();
        assert_eq!(run.ended, vec![5]);
        assert_eq!(run.due_at, None);

        let dir = Scratch::new();
        let mut store = dir.open();
        let ahead = add_paired(&mut store, 6, BindingRole::Guest);
        let run = store.bring_to_rule(&named(&[]), NOW - 1).unwrap();
        assert_eq!(run.ended, vec![6], "a key from the future gives no grace");
        assert!(matches!(
            store.lookup(ahead.id()),
            Lookup::PendingRemoval(_)
        ));
    }

    /// A second run changes nothing — no key, no token, no list — and a run with the stored list
    /// equal to the current one and nobody to take changes nothing either. Refutes a rule that
    /// replaces the token or rewrites on every run.
    #[test]
    fn a_second_run_of_the_rule_changes_nothing() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let _ = add_paired(&mut store, 1, BindingRole::Owner);
        let _ = add_paired(&mut store, 5, BindingRole::Guest);
        assert!(store.bring_to_rule(&named(&[1]), LATER).unwrap().changed());
        let token = store.grant_token();
        let again = store.bring_to_rule(&named(&[1]), LATER + 60_000).unwrap();
        assert!(!again.changed(), "{again:?}");
        assert!(again.ended.is_empty());
        assert_eq!(store.grant_token(), token);
        // Written and installed: still nothing to do.
        assert!(store.flush().unwrap());
        let after = store.bring_to_rule(&named(&[1]), LATER + 120_000).unwrap();
        assert!(!after.changed(), "{after:?}");
        assert_eq!(store.grant_token(), token);
    }

    /// Who the rule takes (§10): a person with an undecided guest key, and one who leaves the
    /// stored last list (a person who never had a key here: the token is replaced all the same).
    /// A person with only a removed key, or only an attempt, and not in the stored list has
    /// nothing the rule takes. After one run nothing is left to change. Refutes a rule that misses
    /// a person leaving the stored list, or one that re-takes the already removed.
    #[test]
    fn the_rule_takes_guest_keys_and_people_who_leave_the_stored_list() {
        let dir = Scratch::new();
        let mut store = dir.open();
        store.set_wall_now(NOW);
        let removed = add_paired(&mut store, 5, BindingRole::Guest);
        store.remove(removed.id(), Removal::Pc, NOW).unwrap();
        let tried = Device::new();
        assert!(store.note_attempt(attempt_of(6, &tried, NOW), NOW));
        assert!(store.note_last_bindings([KnownBinding {
            telegram_user_id: 7,
            role: BindingRole::Guest,
        }]));
        assert!(store.flush().unwrap());
        let token = store.grant_token();
        let run = store.bring_to_rule(&named(&[]), LATER).unwrap();
        assert_eq!(
            run.ended,
            vec![7],
            "the keyless person who left the stored list"
        );
        assert!(run.rotated, "the token replaced for them");
        assert_ne!(store.grant_token(), token);
        assert!(store.attempt(6, tried.id()).is_some());
        let again = store.bring_to_rule(&named(&[]), LATER + 1).unwrap();
        assert!(!again.changed(), "{again:?}");
    }

    /// One write carries the whole run — the guest key's `server` tombstone, the new grant token
    /// and the stored last list — as a fresh process reads it. Refutes a run whose parts land in
    /// different writes (a crash between them).
    #[test]
    fn one_write_carries_the_rules_tombstone_token_and_list() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let _ = add_paired(&mut store, 1, BindingRole::Owner);
        let gone = add_paired(&mut store, 5, BindingRole::Guest);
        let _ = store.bring_to_rule(&named(&[1]), LATER).unwrap();
        assert!(store.flush().unwrap());
        let fresh = dir.open();
        assert_eq!(removed_origin(&fresh, gone.id()), Origin::Server);
        assert_eq!(fresh.grant_token(), store.grant_token());
        assert_eq!(fresh.last_bindings().unwrap().len(), 1);
    }

    /// A damaged list and memory that may be behind the disk refuse the rule and change
    /// nothing. Refutes a rule that runs on a list it cannot read.
    #[test]
    fn the_rule_refuses_a_damaged_list_and_a_needed_reopen() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let guest = add_paired(&mut store, 5, BindingRole::Guest);
        store.needs_reopen = true;
        assert_eq!(
            store.bring_to_rule(&named(&[]), LATER),
            Err(StoreError::NeedsReopen)
        );
        assert!(matches!(store.lookup(guest.id()), Lookup::Active(_)));
        std::fs::write(dir.primary(), b"{ not json").unwrap();
        let mut damaged = dir.open();
        assert_eq!(
            damaged.bring_to_rule(&named(&[]), LATER),
            Err(StoreError::Damaged)
        );
    }

    /// §10: a person removed at the PC (every key a `pc` tombstone, the one shared step): an old
    /// grant is refused `grant_stale` (the token replaced), a NEW invited grant from the owner
    /// over the new token lands for the same person, and a pairing at the PC lands with one call.
    /// Their attempts went with the removal. The SAME key comes back too (one return rule,
    /// Nov): an old grant for it is `grant_stale`, a grant without an invitation `invite_missing`
    /// (nothing lifted), a new invited grant returns it to the person, a guest's key, confirmed.
    #[test]
    fn a_person_removed_at_the_pc_comes_back_by_a_new_grant_or_a_pairing() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        let c = add_paired(&mut store, 5, BindingRole::Guest);
        let tried = Device::new();
        assert!(store.note_attempt(attempt_of(5, &tried, NOW), NOW));
        let old = store.grant_token().unwrap();
        let tree = store.deny_person_tree_now(5, NOW + 1);
        assert_eq!(tree.removed.len(), 1);
        assert!(store.attempt(5, tried.id()).is_none(), "their attempts go");
        let new_token = store.grant_token().unwrap();
        assert_ne!(new_token, old, "the token replaced");
        assert!(store.flush().unwrap());
        assert_eq!(
            store.add(
                Device::new().new_key(),
                over(grant(owner.id(), 40, 5, Some((140, owner.id()))), old),
                NOW + 2
            ),
            Err(StoreError::GrantStale),
            "an old grant"
        );
        // The same key C: an old grant for it, then one without an invitation — nothing lifted.
        assert_eq!(
            store.add(
                c.new_key(),
                over(grant(owner.id(), 42, 5, Some((142, owner.id()))), old),
                NOW + 2
            ),
            Err(StoreError::GrantStale),
            "an old grant for C"
        );
        assert_eq!(
            store.add(
                c.new_key(),
                over(grant(owner.id(), 43, 5, None), new_token),
                NOW + 2
            ),
            Err(StoreError::InviteMissing),
            "a grant for C without an invitation"
        );
        assert_eq!(
            removed_origin(&store, c.id()),
            Origin::Pc,
            "C stays removed"
        );
        store
            .add(
                c.new_key(),
                over(grant(owner.id(), 44, 5, Some((144, owner.id()))), new_token),
                NOW + 3,
            )
            .expect("a new invited grant returns C");
        let back = active(&store, c.id());
        assert_eq!(back.person.telegram_user_id, 5);
        assert_eq!(back.role, BindingRole::Guest);
        assert!(!back.unconfirmed, "confirmed, as a grant's key is");
        store
            .add(
                Device::new().new_key(),
                over(grant(owner.id(), 41, 5, Some((141, owner.id()))), new_token),
                NOW + 3,
            )
            .expect("a new invited grant lands");
        store
            .add(
                Device::new().new_key(),
                pair(5, BindingRole::Guest),
                NOW + 4,
            )
            .expect("a pairing at the PC lands");
        assert_eq!(store.person_keys(5).unwrap().working_guest.len(), 3);
    }

    /// §7 «Смена»: every accepted «Удалить» of one key at the PC replaces the grant
    /// token — in both modes, of an owner-role key, and when its walk only goes through
    /// tombstones; a refused one (a key the list does not know) keeps it. An invitation signed
    /// before the press is `grant_stale`; a new one after it returns the same key to the same
    /// person. A single key's removal is no removal of the person: their attempts stay.
    #[test]
    fn every_single_key_removal_press_replaces_the_token() {
        for strict in [false, true] {
            let dir = Scratch::new();
            let (mut store, owner) = store_with_owner(&dir);
            if strict {
                store.set_trusted_devices_mode(true).unwrap();
            }
            let second_owner = add_paired(&mut store, 1, BindingRole::Owner);
            let c = Device::new();
            let tok = store.grant_token().unwrap();
            store
                .add(
                    c.new_key(),
                    over(grant(owner.id(), 50, 5, Some((150, owner.id()))), tok),
                    NOW,
                )
                .unwrap();
            let tried = Device::new();
            let now = crate::journal::now_ms();
            assert!(store.note_attempt(attempt_of(5, &tried, now), now));
            let before = store.grant_token().unwrap();
            let unknown = Device::new();
            assert_eq!(
                store.deny_tree_now(unknown.id(), NOW + 1),
                Err(StoreError::NotFound(unknown.id().clone())),
                "{strict}"
            );
            assert_eq!(
                store.grant_token().unwrap(),
                before,
                "refused: kept ({strict})"
            );
            assert_eq!(
                store.deny_tree_now(c.id(), NOW + 1).unwrap().removed,
                vec![c.id().clone()]
            );
            let after = store.grant_token().unwrap();
            assert_ne!(after, before, "«Удалить» replaced it ({strict})");
            assert!(
                store.attempt(5, tried.id()).is_some(),
                "a single key's removal keeps the person's attempts ({strict})"
            );
            assert!(store.flush().unwrap());
            assert_eq!(
                store.add(
                    c.new_key(),
                    over(grant(owner.id(), 51, 5, Some((151, owner.id()))), before),
                    NOW + 2
                ),
                Err(StoreError::GrantStale),
                "signed before the press ({strict})"
            );
            store
                .add(
                    c.new_key(),
                    over(grant(owner.id(), 52, 5, Some((152, owner.id()))), after),
                    NOW + 3,
                )
                .expect("a new invitation after the press returns C");
            let back = active(&store, c.id());
            assert_eq!(
                (back.person.telegram_user_id, back.role, back.unconfirmed),
                (5, BindingRole::Guest, false)
            );
            // An owner-role key.
            let t = store.grant_token().unwrap();
            let _ = store.deny_tree_now(second_owner.id(), NOW + 4).unwrap();
            assert_ne!(store.grant_token().unwrap(), t, "owner key ({strict})");
            assert!(store.flush().unwrap());
            // A walk only through tombstones: nothing listed is denied, the token still goes.
            let t = store.grant_token().unwrap();
            let walk = store.deny_tree_now(second_owner.id(), NOW + 5).unwrap();
            assert!(walk.removed.is_empty());
            assert_ne!(
                store.grant_token().unwrap(),
                t,
                "tombstones only ({strict})"
            );
            assert!(store.flush().unwrap());
            assert_eq!(dir.open().grant_token(), store.grant_token(), "written");
        }
    }

    /// §10 one return rule: a removed key of origin `pc` or `server` comes back by a new
    /// invited grant to ITS OWN person (the agent's same-person check covers both origins); a
    /// grant naming another person is refused `key_revoked`, the tombstone stays with its person.
    #[test]
    fn a_new_invited_grant_returns_a_removed_key_only_to_its_own_person() {
        for (by, origin) in [(Removal::Pc, Origin::Pc), (Removal::Server, Origin::Server)] {
            let dir = Scratch::new();
            let (mut store, owner) = store_with_owner(&dir);
            let g = add_paired(&mut store, 5, BindingRole::Guest);
            let _other = add_paired(&mut store, 6, BindingRole::Guest);
            store.remove(g.id(), by, NOW).unwrap();
            let tok = store.grant_token().unwrap();
            assert_eq!(
                store.add(
                    g.new_key(),
                    over(grant(owner.id(), 70, 6, Some((170, owner.id()))), tok),
                    NOW + 1
                ),
                Err(removal_error(origin.as_str(), g.id())),
                "another person ({origin:?})"
            );
            assert_eq!(removed(&store, g.id()).telegram_user_id, 5);
            assert_eq!(removed_origin(&store, g.id()), origin);
            store
                .add(
                    g.new_key(),
                    over(grant(owner.id(), 71, 5, Some((171, owner.id()))), tok),
                    NOW + 2,
                )
                .expect("the same person");
            let back = active(&store, g.id());
            assert_eq!(
                (back.person.telegram_user_id, back.role, back.unconfirmed),
                (5, BindingRole::Guest, false),
                "{origin:?}"
            );
        }
    }

    /// §10: `replaced` (a key a recovery replaced) — only a confirmed pairing lifts it; a new
    /// invited grant over the current token is `key_revoked`, nothing spent.
    #[test]
    fn a_replaced_key_comes_back_only_by_a_pairing() {
        let dir = Scratch::new();
        let (mut store, owner) = store_with_owner(&dir);
        let phone = add_paired(&mut store, 5, BindingRole::Guest);
        let attempt = Attempt::new(&phone, 5);
        store.recover(attempt.recovery(&phone), NOW).unwrap();
        assert!(matches!(
            removed_origin(&store, phone.id()),
            Origin::Replaced { .. }
        ));
        let tok = store.grant_token().unwrap();
        assert_eq!(
            store.add(
                bare(&phone.key),
                over(grant(owner.id(), 80, 5, Some((180, owner.id()))), tok),
                NOW + 1
            ),
            Err(removal_error("replaced", phone.id()))
        );
        store
            .add(bare(&phone.key), pair(5, BindingRole::Guest), NOW + 2)
            .expect("a confirmed pairing lifts it");
    }

    /// §10, §5: an unconfirmed pairing (`pc_allow`, a dirty window) lifts no removal, of either
    /// origin: observe — `key_revoked`; strict — `key_unconfirmed`; the tombstone stays.
    #[test]
    fn an_unconfirmed_pairing_lifts_no_removal() {
        for strict in [false, true] {
            for (by, origin) in [(Removal::Pc, Origin::Pc), (Removal::Server, Origin::Server)] {
                let dir = Scratch::new();
                let (mut store, _owner) = store_with_owner(&dir);
                if strict {
                    store.set_trusted_devices_mode(true).unwrap();
                }
                let g = add_paired(&mut store, 5, BindingRole::Guest);
                store.remove(g.id(), by, NOW).unwrap();
                let marked = Ground::Pair {
                    person: person(5),
                    role: BindingRole::Guest,
                    unconfirmed: true,
                };
                assert_eq!(
                    store.add(g.new_key(), marked, NOW + 1),
                    Err(if strict {
                        StoreError::KeyUnconfirmed
                    } else {
                        removal_error(origin.as_str(), g.id())
                    }),
                    "{strict} {origin:?}"
                );
                assert_eq!(removed_origin(&store, g.id()), origin);
            }
        }
    }

    /// §10: a person removed on the server's word — their guest-role keys `server` tombstones,
    /// their owner-role keys stay, their attempts dropped, the token replaced once — and the PC's
    /// removal run the SAME one step ([`TrustStore::person_removed`]): both log its one line.
    #[test]
    fn both_removal_paths_run_the_one_shared_step() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let owner_key = add_paired(&mut store, 5, BindingRole::Owner);
        let guest = add_paired(&mut store, 5, BindingRole::Guest);
        let tried = Device::new();
        assert!(store.note_attempt(attempt_of(5, &tried, NOW), NOW));
        let token = store.grant_token();
        let mut server = None;
        let log = logged(|| server = Some(store.deny_guest_keys_now(5, Removal::Server, NOW + 1)));
        assert_eq!(server.unwrap(), Ok((vec![guest.id().clone()], 1)));
        assert!(log.contains("a person removed: their attempts go"), "{log}");
        assert!(matches!(store.lookup(owner_key.id()), Lookup::Active(_)));
        assert!(store.attempt(5, tried.id()).is_none(), "attempts dropped");
        let once = store.grant_token();
        assert_ne!(once, token, "the token replaced");
        assert!(store.flush().unwrap());
        assert_eq!(removed_origin(&store, guest.id()), Origin::Server);
        // The PC's removal of another person: the same line, the same step.
        let other = add_paired(&mut store, 6, BindingRole::Guest);
        let log = logged(|| {
            let _ = store.deny_person_tree_now(6, NOW + 2);
        });
        assert!(log.contains("a person removed: their attempts go"), "{log}");
        assert_ne!(store.grant_token(), once);
        assert_eq!(store.removal_decided(other.id()), Some("pc"));
    }

    /// §7: a person who never had a key here leaving the stored last binding list replaces the
    /// grant token (an invitation for them may be out).
    #[test]
    fn a_keyless_person_leaving_the_stored_list_replaces_the_token() {
        let dir = Scratch::new();
        let (mut store, _owner) = store_with_owner(&dir);
        let b = |telegram_user_id| KnownBinding {
            telegram_user_id,
            role: BindingRole::Guest,
        };
        assert!(store.note_last_bindings([b(1), b(7)]));
        let token = store.grant_token();
        assert!(store.note_last_bindings([b(1)]));
        assert_ne!(store.grant_token(), token, "7 left: replaced");
        let again = store.grant_token();
        assert!(!store.note_last_bindings([b(1)]));
        assert_eq!(store.grant_token(), again, "nobody left: kept");
    }

    /// The list file has one format: a file of the earlier format, with the removed-people field,
    /// is damaged (never read nor upgraded).
    #[test]
    fn a_file_with_the_removed_people_field_is_damaged() {
        assert_eq!(
            after(|v| {
                v["removed_people"] = serde_json::json!([
                    {"telegram_user_id": 5, "removed_at": NOW, "mark": "server", "seq": 0}
                ]);
            }),
            Some(DamageKind::NotParsable)
        );
        assert_eq!(
            after(|v| v["removed_people"] = serde_json::json!([])),
            Some(DamageKind::NotParsable)
        );
    }

    /// §10 «Действующий ключ»: one verdict on a listed record everywhere — its removal decided,
    /// else it works. A leaving owner's record stays listed but gives no owner by keys, and
    /// nothing it signs passes: an invitation (`invite.by`) or an endorse, in both modes. Refutes
    /// a leaving record read as active (admitting, signing, guarding).
    #[test]
    fn a_listed_record_is_read_with_its_verdict() {
        for strict in [false, true] {
            let dir = Scratch::new();
            let mut store = dir.open();
            let phone = add_paired(&mut store, 1, BindingRole::Owner);
            let laptop = add_paired(&mut store, 1, BindingRole::Owner);
            let _guest = add_paired(&mut store, 5, BindingRole::Guest);
            store.set_trusted_devices_mode(strict).unwrap();
            let new = Device::new();
            let grants = |n: u8| {
                [
                    grant(phone.id(), n, 9, Some((n + 100, phone.id()))),
                    grant(phone.id(), n + 1, 9, Some((n + 101, laptop.id()))),
                ]
            };
            assert!(matches!(store.lookup(phone.id()), Lookup::Active(_)));
            let keys = store.person_keys(1).unwrap();
            assert!(keys.owner_by_keys() && !keys.owner_keys_not_working());
            assert_eq!(
                keys.working_owner,
                [phone.id().clone(), laptop.id().clone()]
            );
            for g in grants(1) {
                store.check_add(&new.new_key(), &g, NOW).unwrap();
            }
            store.deny_now(std::slice::from_ref(laptop.id()));
            assert!(matches!(
                store.lookup(laptop.id()),
                Lookup::PendingRemoval(_)
            ));
            let people = store.listed_people().unwrap();
            let states: Vec<KeyState> = people[0].1.iter().map(|l| l.state).collect();
            assert_eq!(states, [KeyState::Works, KeyState::Leaving], "both listed");
            assert_eq!(people[1].1[0].state, KeyState::Works);
            let keys = store.person_keys(1).unwrap();
            assert_eq!(keys.working_owner, [phone.id().clone()]);
            store.check_add(&new.new_key(), &grants(5)[0], NOW).unwrap();
            assert_eq!(
                store.check_add(&new.new_key(), &grants(5)[1], NOW).err(),
                Some(StoreError::InviteNotOwner),
                "the leaving laptop invites nobody"
            );
            assert_eq!(
                store
                    .check_add(&new.new_key(), &endorse(laptop.id(), 7), NOW)
                    .err()
                    .map(|e| e.as_str()),
                Some("signer_removed"),
                "the leaving laptop endorses nobody"
            );
            assert_eq!(store.person_names(1).map(|p| p.telegram_user_id), Some(1));
        }
    }

    /// §10 «Одно правило возврата», the time at the write: a removed key's add over an endorse
    /// issued NOT later than its removed record's `removed_at` — one millisecond before, and the
    /// very millisecond — is refused `Removed` (the admission's `key_revoked`) by the add itself
    /// (`stage_add`, which the queue runs at its turn), the endorse's own checks passed: nothing
    /// written, nothing spent, the key stays removed. One millisecond later it lifts the key.
    #[test]
    fn an_endorse_not_later_than_the_removal_is_refused_at_the_write() {
        let dir = Scratch::new();
        let mut store = dir.open();
        let owner = add_paired(&mut store, 1, BindingRole::Owner);
        let laptop = Device::new();
        store
            .add(laptop.new_key(), endorse(owner.id(), 1), NOW)
            .unwrap();
        store.remove(laptop.id(), Removal::Pc, NOW + 5).unwrap();
        let Lookup::Removed(t) = store.lookup(laptop.id()) else {
            panic!("removed")
        };
        let removed_at = u64::try_from(t.at).unwrap();
        let spent = |s: &TrustStore| s.spent().unwrap().0.clone();
        let before = spent(&store);
        for (n, issued_at) in [(2, removed_at - 1), (3, removed_at)] {
            assert_eq!(
                store.add(
                    laptop.new_key(),
                    endorse_at(owner.id(), n, issued_at),
                    NOW + 10
                ),
                Err(removal_error("pc", laptop.id())),
                "issued at removed_at {:+}",
                i128::from(issued_at) - i128::from(removed_at)
            );
            assert!(matches!(store.lookup(laptop.id()), Lookup::Removed(_)));
            assert_eq!(spent(&store), before, "nothing spent");
        }
        let out = store
            .add(
                laptop.new_key(),
                endorse_at(owner.id(), 4, removed_at + 1),
                NOW + 10,
            )
            .unwrap();
        assert_eq!(out.lifted, Some("pc"), "one millisecond later it returns");
    }
}
