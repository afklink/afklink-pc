//! The connection journal: who was on this PC and when, kept on the PC for the desktop app's
//! «Журнал».
//!
//! # What is in it
//!
//! One entry per session whose video came up, and one per event: access given (a binding the owner
//! allowed: on this PC, or in Telegram for a guest he invited), access taken away (unbound on this
//! PC or in the Mini App), and an attempt refused while the PC was paused (the agent tells the
//! journal once per person per pause). An attempt that never got as far as video is not an entry:
//! such attempts come in bursts on a bad network and say nothing the logs do not.
//!
//! A session's entry carries who, from which Telegram client, when the video came up, when and why
//! the session ended, whether «Только игра» was on, and whether the network was weak for a notable
//! share of it. No IP address, by design.
//!
//! The file ([`FILE_NAME`]) is append-only JSON Lines where the last line for an id wins. Kept for
//! [`KEEP_DAYS`] days and at most [`KEEP_ENTRIES`] entries, the oldest going first. Written
//! whatever the log level: this is data, not a log. Read by nothing but this module, and sent
//! nowhere («Отправить логи» does not carry it).
//!
//! # Threads
//!
//! Called from the orchestrator (sessions starting and ending, bindings, the pause), from each
//! session's event task (the viewer's client) and control task (one sample a second), from the
//! window's commands and from the app's way out. Every call is memory work behind one lock, and
//! quick: the lock is NEVER held across the disk. A call decides under the lock and
//! hands its file work — an append of its lines, or a rewrite of the whole file — still under it
//! (so the file gets the work in the order of the calls), to the journal's own writer thread
//! (`afklink-journal`, started with the first write) through a FIFO bounded at [`QUEUE_MAX`]:
//! when that much is waiting, the waiting work is replaced by one rewrite of the journal as
//! memory has it (which holds all of it), so the queue never grows and no caller waits. A write
//! that fails is said at `warn` (once, then `debug`); its entries stay in memory, so the window
//! shows them, and the next rewrite (a compaction, or the next start) puts them on the disk.
//!
//! At exit the app's way out calls [`Journal::drain`] on the main thread, which waits at most
//! [`DRAIN_LIMIT`] for the writer; a drop waits as long when it is not on the async runtime (and
//! not at all on it). What is left past the bound is said at `warn` and may not reach the disk —
//! the same as a failed write: a session it would have closed is closed at the next start as
//! «Приложение закрыто».

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::sync::lock;

/// The journal's file, in the data directory beside config.json.
///
/// JSON Lines, one entry per line, about 200 bytes each, appended and never edited in place. A
/// session's entry is written when its video comes up, again whenever something about it changes
/// (its client, «Только игра», weak network), at least every [`SEEN_EVERY_MS`] while it runs
/// (`seen`), and once more when it ends. On reading, the last line for an id wins, so a crash loses
/// at most a minute of a session and a torn last line only itself. The file is rewritten whole (a
/// temporary file renamed over it) at startup and whenever the superseded lines pile up past
/// [`COMPACT_SLACK`].
pub const FILE_NAME: &str = "connections.jsonl";

/// How long an entry is kept, from when it happened.
pub const KEEP_DAYS: i64 = 90;

/// The most entries kept, whatever their age.
pub const KEEP_ENTRIES: usize = 1000;

/// A session's end reason for a session the app closed under it: a clean exit with the session up,
/// or a process that died with it up (found open at the next start). The journal's own label, never
/// a `session_end` reason on the wire.
pub const APP_CLOSED: &str = "app_closed";

/// A session's end reason for a session whose viewer closed the connection itself — its DTLS or
/// SCTP said goodbye (`PeerEnd::ViewerClosed` in the transport: «Отключиться», the Mini App's
/// screen closing) — while the backend's reason for that end has not come
/// ([`SERVER_REASON_WAIT_MS`]). An ordinary end. The journal's own label, never a `session_end`
/// reason on the wire, where the same end is `peer_closed`.
pub const VIEWER_LEFT: &str = "viewer_left";

/// How long an entry closed by its peer's own end ([`Journal::session_ended_by_peer`]) takes the
/// backend's reason for it in place of its own. The viewer's reason was measured 0.1 s after its
/// goodbye, through a VPN; two seconds leaves room for a slow link without keeping anything waiting
/// (the entry is written at once either way).
pub const SERVER_REASON_WAIT_MS: i64 = 2_000;

/// How often an open session's entry is written while nothing else about it changes: where a
/// session left open by a process that died ends. A minute, the unit its duration is shown in.
pub const SEEN_EVERY_MS: i64 = 60_000;

/// Superseded lines the file may carry before it is rewritten without them.
pub const COMPACT_SLACK: usize = 300;

/// File work (appends, rewrites) the writer thread may have waiting. With this much waiting,
/// the waiting work is replaced by ONE rewrite of the journal as memory has it ([`Writer::push`]):
/// the queue stays bounded and no caller waits for the disk.
pub const QUEUE_MAX: usize = 64;

/// How long the app's exit ([`Journal::drain`]) — and a journal's drop off the async runtime
/// — waits for the writer to finish what is queued. Past it, what is left is said at `warn` and
/// may not reach the disk (as a failed write). Two seconds: some 20 slow appends, in the main
/// thread's exit budget beside the goodbye.
pub const DRAIN_LIMIT: Duration = Duration::from_secs(2);

/// A weak second: the viewer's picture stood still for the network (drain mode, `net_stall`), or
/// the video went at this frame rate or lower …
pub const WEAK_FPS: u32 = 15;
/// … or at this height or lower while the ladder chose it (a height the viewer pinned is their
/// choice, not the network's).
pub const WEAK_HEIGHT: u32 = 360;
/// A session is marked «Плохая связь» (`app.journalWeak`) when at least
/// this many of its seconds were weak …
pub const WEAK_MIN_SECS: u32 = 10;
/// … and they were at least one in this many of its seconds with video.
pub const WEAK_SHARE_DIVISOR: u32 = 5;

/// The longest name kept, in characters.
const NAME_MAX: usize = 64;
/// The longest platform string kept: Telegram's are a few letters.
const PLATFORM_MAX: usize = 32;

const DAY_MS: i64 = 86_400_000;

/// Unix milliseconds by the PC's clock: what every entry is dated in.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What an entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A session whose video came up.
    Session,
    /// The owner allowed a pairing request: the person has access («Доступ выдан»).
    Granted,
    /// The owner let a guest in from Telegram by his invite, and nobody at the PC was asked
    /// (`binding_added.via: invite`): «Доступ по приглашению» in place of «Доступ выдан». A build
    /// older than this kind drops the line when it reads the file (as any line it
    /// cannot read), and only that line.
    Invited,
    /// A binding was removed, on this PC or in the Mini App («Доступ отозван»).
    Revoked,
    /// A session request refused because the PC was paused after «Приостановить доступ»
    /// («Отклонено: ПК на паузе»).
    Paused,
    /// «Доверенные устройства» switched on at this PC: about the PC, naming nobody (`user` 0, an
    /// empty name). Written after the change is in the list's file, never before. A build older
    /// than these three kinds drops the line when it reads the file, and only that line.
    TrustedOn,
    /// «Доверенные устройства» switched off at this PC: as [`Kind::TrustedOn`].
    TrustedOff,
    /// One of a person's trusted devices left the list at this PC (removed with its descendants,
    /// the person removed, a guest unbound): the person, and the device in
    /// [`Entry::trusted_device`]. Written after the removal is in the list's file.
    DeviceUntrusted,
    /// A device joined the person's trusted devices (device keys: «Разрешить», a vouching device,
    /// the owner's grant, the first use): «Новое устройство», the device in
    /// [`Entry::trusted_device`]. Written after the key is in the list's file. A build older than
    /// these five kinds drops the line when it reads the file, and only that line.
    DeviceAdded,
    /// A device restored its key on the same device (recovery): «Ключ доступа восстановлен».
    /// Written after the change is in the list's file.
    KeyRestored,
    /// A session refused in strict mode: the device had no key («Отклонено: нет ключа доступа»).
    DeclinedNoKey,
    /// A session refused in strict mode: the device's key was removed («…удалено из доверенных»).
    DeclinedUntrusted,
    /// A session refused in strict mode: the PC does not take the device
    /// («…неизвестное устройство»): an unknown or unconfirmed key, a ground refused.
    DeclinedUnknown,
    /// A device this PC does not know tried to get in as a person who has a key here, and its
    /// signature checked (spec §9, §10.1): «Попытка подключения с неизвестного устройства», the
    /// person and no device. A build older than this kind drops the line when it reads the file,
    /// and only that line.
    OtherDeviceAttempt,
    /// The PC was added to a party (party spec §6: its owner's «ПК в пати» taken, written): about
    /// the PC, naming nobody, the party in [`Entry::party`]. Written once the delegation is in the
    /// list's file. A build older than these four kinds drops the line when it reads the file,
    /// and only that line.
    PartyAdded,
    /// The PC is in a party no more (it left, by the server's word or at the PC; the owner key
    /// that signed it went; a reset): as [`Kind::PartyAdded`].
    PartyLeft,
    /// A party of the PC's has another leader now: the leader is the person, the party in
    /// [`Entry::party`].
    PartyLeader,
    /// A party member's first device joined the PC's trusted devices by the leader's grant
    /// (party spec §5.4): the person, the device, the party.
    PartyGuest,
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Granted => "granted",
            Self::Invited => "invited",
            Self::Revoked => "revoked",
            Self::Paused => "paused",
            Self::TrustedOn => "trusted_on",
            Self::TrustedOff => "trusted_off",
            Self::DeviceUntrusted => "device_untrusted",
            Self::DeviceAdded => "device_added",
            Self::KeyRestored => "key_restored",
            Self::DeclinedNoKey => "declined_no_key",
            Self::DeclinedUntrusted => "declined_untrusted",
            Self::DeclinedUnknown => "declined_unknown",
            Self::OtherDeviceAttempt => "other_device_attempt",
            Self::PartyAdded => "party_added",
            Self::PartyLeft => "party_left",
            Self::PartyLeader => "party_leader",
            Self::PartyGuest => "party_guest",
        }
    }
}

/// One line of the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// The session's id; a fresh UUID for an event.
    pub id: String,
    pub kind: Kind,
    /// The person's Telegram id.
    pub user: i64,
    /// The person as the window names them: first name, else `@username`, else `#id`
    /// (`crate::person_name`), as of the entry.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Unix ms: when the session's video came up, or when the event happened.
    pub at: i64,
    /// Sessions: when it ended, Unix ms; absent while it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<i64>,
    /// Sessions: why it ended — a `session_end` reason (the agent's own, or the viewer's as the
    /// backend passed it on), or [`APP_CLOSED`]. `Declined*` kinds: why the connection was
    /// refused, when the window names it apart ([`Journal::declined`]); a word this build does
    /// not know is kept as it is. [`Kind::OtherDeviceAttempt`]: the attempt's reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Sessions: the viewer's Telegram platform (`ios`, `android`, `macos`, `tdesktop`, `weba` …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Sessions: «Только игра» was on at some point while the video was up.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub game_only: bool,
    /// Sessions: the network was weak for a notable share of the session ([`is_weak`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub weak: bool,
    /// Sessions: when the entry was last written while the session ran, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<i64>,
    /// [`Kind::DeviceUntrusted`]: the device it is about. Absent from every other entry, and from
    /// lines older builds wrote (which still load).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_device: Option<TrustedDevice>,
    /// [`Kind::DeviceAdded`]: a new device of a guest this PC already had (spec §7
    /// «Новое устройство гостя»), not a new person. Absent (false) from every other entry and from
    /// older lines.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest_new_device: bool,
    /// [`Kind::DeviceAdded`]: the device that vouched for it (`endorse.by` / `grant.by`), while
    /// it is in the list. Absent from every other entry and from older lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_device: Option<TrustedDevice>,
    /// [`Kind::OtherDeviceAttempt`]: the trying device's key id (a public key's hash, never
    /// shown); its reason (`key_unknown`, or `admit_refused`'s detail) is in [`Entry::reason`].
    /// For the record only: the window's attempts are the trusted list's notes (spec §10.2).
    /// Absent from every other entry and from older lines.
    // not-a-key-name: a viewer device key's id (a public key's hash), never a keyboard key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_key: Option<String>,
    /// The `Party*` kinds, and [`Kind::DeviceAdded`] of a member's new device through a party: the
    /// party's name as its join signed it. Absent from every other entry and from older lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
}

/// A trusted device as a journal entry names it: what client, on what, and how it had come into
/// the list. Raw values as the list keeps them (`afklink_core::viewer_keys`): the client `kind`
/// and the `platform` from the viewer's signed key card (display only), the source as the list
/// names it (`pair`, `endorse`, `grant`, `recover`, `first_use`). The window maps them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub kind: String,
    pub platform: String,
    pub source: String,
}

/// The device a session came from, by its Telegram platform — what the window names it («iPhone»,
/// «Android», «Mac», «Компьютер», «Браузер»).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Device {
    /// `ios`. An iPad says `ios` as well and is called an iPhone: an accepted inexactness.
    Iphone,
    /// `android`, and Telegram X's `android_x`.
    Android,
    /// `macos`, the native macOS client.
    Mac,
    /// `tdesktop` (Telegram Desktop on Windows, Linux or macOS) and `unigram` (Windows).
    Desktop,
    /// Telegram Web (`weba`, `webk`, any `web…`), or a plain browser outside Telegram (`browser`).
    Browser,
}

impl Device {
    /// The device a platform string names; `None` for one this build does not know, which the
    /// window then does not show.
    pub fn of(platform: &str) -> Option<Self> {
        match platform {
            "ios" => Some(Self::Iphone),
            "android" | "android_x" => Some(Self::Android),
            "macos" => Some(Self::Mac),
            "tdesktop" | "unigram" => Some(Self::Desktop),
            "browser" => Some(Self::Browser),
            p if p.starts_with("web") => Some(Self::Browser),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Iphone => "iphone",
            Self::Android => "android",
            Self::Mac => "mac",
            Self::Desktop => "desktop",
            Self::Browser => "browser",
        }
    }
}

/// How a session ended, as the journal says it: an ordinary end carries no label, the rest two or
/// three words («Прерван на ПК», «Прерван владельцем», «Доступ отозван», «Связь потеряна», «Сбой»,
/// «Приложение закрыто»).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ending {
    /// The viewer left, or the same person connected again: no label.
    Ordinary,
    /// The owner pressed «Приостановить доступ».
    Pc,
    /// The PC's owner pressed «Прервать сеанс» under the bot's message about a guest
    /// (`owner_ended`): «Прерван владельцем» (`app.journalEndOwner`). The
    /// guest keeps access and may connect again, so not [`Ending::Revoked`].
    Owner,
    /// The person's access was taken away: unbound, or blocked by an admin (`blocked`).
    Revoked,
    /// The link went: ICE, the viewer's or the agent's signaling, the peer.
    Lost,
    /// Something broke: the capture, the encoder, the viewer's player, the agent's bookkeeping.
    Failed,
    /// [`APP_CLOSED`].
    AppClosed,
}

impl Ending {
    /// How a reason ends a session; `None` for a reason this build does not know (a newer viewer or
    /// backend), which the journal shows without a label.
    ///
    /// Every reason in the contract's `SESSION_END_REASONS` is listed (a test holds it to the
    /// fixture), plus the agent's local `server_ended` and the journal's [`APP_CLOSED`] and
    /// [`VIEWER_LEFT`].
    pub fn of(reason: &str) -> Option<Self> {
        use afklink_protocol::end_reason as r;
        Some(match reason {
            "viewer_ended"
            | "viewer_closed"
            | "viewer_cancelled"
            | "viewer_retry"
            | "viewer_render_reconnect"
            | "superseded"
            | "agent_ended" => Self::Ordinary,
            // The website's sign-in the viewer used ended («Выйти», or every browser signed out
            // from the bot): the viewer's own side going, not this PC's access, which stays.
            "signed_out" => Self::Ordinary,
            // The PC's owner pressed «Прервать сеанс» under the bot's message about a guest
            // connecting: the guest keeps access and may connect again. Words of its
            // own, «Прерван владельцем» — «Прерван на ПК» would say the wrong place,
            // «Доступ отозван» the wrong thing.
            r::OWNER_ENDED => Self::Owner,
            // The backend (or the viewer through it) ended it and gave no reason of its own.
            r::local::SERVER_ENDED => Self::Ordinary,
            // The viewer closed its connection itself and the backend's word did not come.
            VIEWER_LEFT => Self::Ordinary,
            // A refused request has no video, so it is never a session here; were it one, the
            // owner's pause ended it.
            r::KILL_SWITCH | r::PAUSED_ON_PC => Self::Pc,
            r::UNBOUND => Self::Revoked,
            // An admin blocked the account or this PC (the invite-only beta),
            // and every session of it ended: access taken away,
            // «Доступ отозван» — until the block is lifted. Also the agent's own label for what it
            // ends itself on `device_blocked`.
            r::BLOCKED => Self::Revoked,
            // Device keys (spec §11): the device is not (or is no longer) let in — its key removed,
            // strict mode on, a key or a nonce the PC does not take: «Доступ отозван».
            "key_revoked" | "key_required" | "key_unconfirmed" | "key_unknown" | "admit_refused"
            | "nonce_stale" => Self::Revoked,
            // A proof that did not hold, a fingerprint switched mid-session, a list that could not
            // be read or written: a failure.
            "proof_invalid" | "fingerprint_changed" | "key_list_damaged" => Self::Failed,
            "ice_failed"
            | r::ICE_TIMEOUT
            | r::ICE_RESTART_FAILED
            | "viewer_disconnected"
            | r::AGENT_DISCONNECTED
            | "viewer_signaling_lost"
            | "viewer_signaling_error"
            | "viewer_media_stalled"
            | "viewer_connect_timeout"
            // The connection closed with no goodbye from the viewer and no word from the backend
            // (the viewer's own goodbye is `VIEWER_LEFT` here).
            | r::PEER_CLOSED
            | "server_shutdown" => Self::Lost,
            r::CAPTURE_LOST
            | r::CAPTURE_ERROR
            | r::ENCODER_ERROR
            | "viewer_pipeline_stalled"
            | "viewer_agent_unresponsive"
            | "viewer_render_stalled"
            | "viewer_start_failed"
            | r::PEER_ERROR
            | r::INTERNAL_ERROR
            | r::NO_SESSION_REQUEST
            | r::UNKNOWN_SESSION => Self::Failed,
            APP_CLOSED => Self::AppClosed,
            _ => return None,
        })
    }

    /// The label the window shows, or `None` for an ordinary end.
    pub const fn label(self) -> Option<&'static str> {
        match self {
            Self::Ordinary => None,
            Self::Pc => Some("pc"),
            Self::Owner => Some("owner"),
            Self::Revoked => Some("revoked"),
            Self::Lost => Some("lost"),
            Self::Failed => Some("failed"),
            Self::AppClosed => Some("app_closed"),
        }
    }
}

/// Whether one second of a session's video was weak: the picture stood still for the network (drain
/// mode, which the viewer is told as `net_stall`), or the ladder held the video at [`WEAK_FPS`] or
/// below, or at [`WEAK_HEIGHT`] or below while no height was pinned by the viewer.
pub fn weak_second(draining: bool, pinned: bool, max_h: u32, fps: u32) -> bool {
    draining || fps <= WEAK_FPS || (!pinned && max_h <= WEAK_HEIGHT)
}

/// Whether a session with `secs` seconds of video, `weak` of them weak ([`weak_second`]), was on a
/// weak network as the journal says it: at least [`WEAK_MIN_SECS`] weak seconds, and at least one
/// in [`WEAK_SHARE_DIVISOR`].
pub fn is_weak(secs: u32, weak: u32) -> bool {
    weak >= WEAK_MIN_SECS && weak.saturating_mul(WEAK_SHARE_DIVISOR) >= secs
}

/// A session whose video just came up.
#[derive(Debug, Clone)]
pub struct SessionStart<'a> {
    pub session_id: &'a str,
    pub user: i64,
    pub name: &'a str,
    pub username: Option<&'a str>,
    /// «Только игра» is on now.
    pub game_only: bool,
}

/// The person an event is about.
#[derive(Debug, Clone, Copy)]
pub struct Person<'a> {
    pub user: i64,
    pub name: &'a str,
    pub username: Option<&'a str>,
}

/// One event of a batch ([`Journal::events`]) — [`Journal::event`]'s, its person owned
/// (the batch is written off the caller's thread).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonEvent {
    pub kind: Kind,
    pub user: i64,
    pub name: String,
    pub username: Option<String>,
}

/// One second of a session's video, as its control task saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Second {
    /// [`weak_second`].
    pub weak: bool,
    /// The session was in game-only mode.
    pub game_only: bool,
}

/// An entry as the window gets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub entry: Entry,
    /// A session going on now.
    pub live: bool,
    pub device: Option<Device>,
    /// How it ended; `None` while it runs, for an event, and for an ordinary end or an unknown
    /// reason.
    pub ending: Option<Ending>,
}

impl View {
    fn of(entry: &Entry, live: bool) -> Self {
        let ending = if live || entry.kind != Kind::Session {
            None
        } else {
            entry
                .reason
                .as_deref()
                .and_then(Ending::of)
                .filter(|e| *e != Ending::Ordinary)
        };
        Self {
            device: entry.platform.as_deref().and_then(Device::of),
            ending,
            live,
            entry: entry.clone(),
        }
    }
}

/// A session going on now, with what its seconds added up to.
#[derive(Debug, Clone)]
struct Live {
    entry: Entry,
    /// Seconds of video sampled, and how many of them were weak.
    secs: u32,
    weak_secs: u32,
    /// When the entry was last written, Unix ms.
    written_at: i64,
}

/// A session's entry its peer's own end closed ([`Journal::session_ended_by_peer`]), open to the
/// backend's reason until `until` (Unix ms).
#[derive(Debug, Clone)]
struct Waiting {
    id: String,
    until: i64,
}

#[derive(Debug, Default)]
struct Inner {
    /// Where the file is; `None` keeps the journal in memory only (no data directory).
    path: Option<PathBuf>,
    /// Ended sessions and events, oldest first.
    done: Vec<Entry>,
    /// Sessions going on now, in the order their video came up.
    live: Vec<Live>,
    /// Entries in `done` closed by their peer's own end, still open to the backend's reason; a few
    /// at most (each for [`SERVER_REASON_WAIT_MS`]), let go on the next end or at exit.
    waiting: Vec<Waiting>,
    /// Lines in the file, superseded ones included, once the work queued is done (a failed
    /// write is not taken back: the next compaction comes sooner, and rewrites the file whole).
    lines: usize,
    /// The file's writer (`None` with no file): its own thread, so no call waits on the
    /// disk ([`Writer::push`]).
    writer: Option<Arc<Writer>>,
}

/// What reading the file found, for the startup line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Loaded {
    lines: usize,
    unreadable: usize,
    superseded: usize,
    closed_at_start: usize,
    expired: usize,
    over_limit: usize,
}

/// The journal. One per process, shared by the agent and the window's commands.
#[derive(Debug)]
pub struct Journal {
    inner: Mutex<Inner>,
}

impl Drop for Journal {
    /// The writer finishes what is queued, then ends. Off the async runtime (the app's main
    /// thread, a test) the drop waits for it at most [`DRAIN_LIMIT`]; on the runtime it does not
    /// wait (a worker must not block), and the writer goes on alone.
    fn drop(&mut self) {
        let writer = self
            .inner
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .writer
            .take();
        let Some(writer) = writer else {
            return;
        };
        // A writer that died (a panic) with work queued gets a new thread to finish it.
        writer.revive("the journal's drop");
        writer.close();
        if tokio::runtime::Handle::try_current().is_ok() {
            tracing::debug!(
                file = %writer.path.display(),
                "connection journal: dropped on the async runtime: not waiting for the writer, \
                 which finishes what is queued alone"
            );
            return;
        }
        if writer.wait_ended(DRAIN_LIMIT) {
            tracing::trace!(
                file = %writer.path.display(),
                "connection journal: dropped; the writer finished"
            );
        }
    }
}

impl Journal {
    /// The journal at [`FILE_NAME`] in the data directory (`crate::paths::afklink_dir`), read, with
    /// sessions left open by the last process closed, old entries dropped and the file rewritten.
    /// Without a data directory, a journal in memory only (said at `warn`).
    pub fn open_default(now_ms: i64) -> Self {
        match crate::paths::afklink_dir() {
            Ok(dir) => Self::open(Some(dir.join(FILE_NAME)), now_ms),
            Err(e) => {
                tracing::warn!(
                    "connection journal: no data directory ({e:#}); kept in memory for this run only"
                );
                Self::open(None, now_ms)
            }
        }
    }

    /// The journal at `path` (`None`: in memory only); see [`Self::open_default`].
    pub fn open(path: Option<PathBuf>, now_ms: i64) -> Self {
        let mut inner = Inner {
            writer: path.clone().map(Writer::new),
            path,
            ..Inner::default()
        };
        let loaded = inner.load(now_ms);
        let changed = loaded.unreadable
            + loaded.superseded
            + loaded.closed_at_start
            + loaded.expired
            + loaded.over_limit
            > 0;
        if changed {
            inner.rewrite("startup: superseded, unreadable, closed or dropped lines");
        }
        tracing::info!(
            file = %inner.path.as_ref().map_or_else(|| "-".to_string(), |p| p.display().to_string()),
            entries = inner.done.len(),
            lines = loaded.lines,
            unreadable = loaded.unreadable,
            superseded = loaded.superseded,
            closed_at_start = loaded.closed_at_start,
            expired = loaded.expired,
            over_limit = loaded.over_limit,
            rewritten = changed,
            keep_days = KEEP_DAYS,
            keep_entries = KEEP_ENTRIES,
            "connection journal opened (written whatever the log level)"
        );
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// A session's video came up: its entry is opened and written. A second call for the same
    /// session (an ICE restart's reconnect) changes nothing.
    pub fn session_started(&self, start: &SessionStart<'_>, now_ms: i64) {
        let mut inner = lock(&self.inner);
        if inner.live.iter().any(|l| l.entry.id == start.session_id) {
            tracing::debug!(
                session = start.session_id,
                "connection journal: the session's video came up again; its entry stays"
            );
            return;
        }
        let entry = Entry {
            id: start.session_id.to_string(),
            kind: Kind::Session,
            user: start.user,
            name: bounded(start.name, NAME_MAX),
            username: start.username.map(|u| bounded(u, NAME_MAX)),
            at: now_ms,
            end: None,
            reason: None,
            platform: None,
            game_only: start.game_only,
            weak: false,
            seen: Some(now_ms),
            trusted_device: None,
            guest_new_device: false,
            by_device: None,
            attempt_key: None,
            party: None,
        };
        tracing::debug!(
            session = start.session_id,
            user = start.user,
            name = %entry.name,
            game_only = start.game_only,
            at = now_ms,
            "connection journal: a session's video came up; its entry opened"
        );
        inner.append(&entry);
        inner.live.push(Live {
            entry,
            secs: 0,
            weak_secs: 0,
            written_at: now_ms,
        });
    }

    /// The viewer's Telegram platform, from its first report that names one. True when the
    /// session's entry is open and has it now; false when it is not open (its video has not come up
    /// yet, or the session has ended), so the caller tries again with the next report.
    pub fn session_platform(&self, session_id: &str, platform: &str, now_ms: i64) -> bool {
        let Some(platform) = clean_platform(platform) else {
            tracing::debug!(
                session = session_id,
                platform = %platform.chars().take(PLATFORM_MAX).collect::<String>(),
                "connection journal: the viewer's platform is not one a journal keeps (too long or \
                 odd characters); left out"
            );
            // Nothing will make it keepable: stop asking.
            return true;
        };
        let mut inner = lock(&self.inner);
        let Some(index) = inner.live_index(session_id) else {
            tracing::trace!(
                session = session_id,
                "connection journal: a platform for a session whose entry is not open; asked again"
            );
            return false;
        };
        if inner.live[index].entry.platform.as_deref() == Some(platform.as_str()) {
            return true;
        }
        tracing::debug!(
            session = session_id,
            platform = %platform,
            device = Device::of(&platform).map_or("-", Device::as_str),
            "connection journal: the viewer's client noted"
        );
        inner.live[index].entry.platform = Some(platform);
        inner.write_live(index, now_ms);
        true
    }

    /// One second of a session's video: counted towards «Плохая связь», and «Только игра» noted.
    /// The entry is written when either changes, and every [`SEEN_EVERY_MS`] otherwise.
    pub fn session_second(&self, session_id: &str, second: Second, now_ms: i64) {
        let mut inner = lock(&self.inner);
        let Some(index) = inner.live_index(session_id) else {
            // The control task samples from the session's setup on; the video comes up a moment
            // later. Every second until then.
            tracing::trace!(
                session = session_id,
                "connection journal: a second of a session whose entry is not open"
            );
            return;
        };
        let live = &mut inner.live[index];
        live.secs = live.secs.saturating_add(1);
        if second.weak {
            live.weak_secs = live.weak_secs.saturating_add(1);
        }
        let weak = is_weak(live.secs, live.weak_secs);
        let mut why = None;
        if second.game_only && !live.entry.game_only {
            live.entry.game_only = true;
            why = Some("«Только игра» turned on during the session");
        }
        if weak != live.entry.weak {
            live.entry.weak = weak;
            why = Some(if weak {
                "the weak seconds reached a notable share"
            } else {
                "the weak seconds fell below a notable share"
            });
        }
        let due = now_ms.saturating_sub(live.written_at) >= SEEN_EVERY_MS;
        let (secs, weak_secs, game_only, weak_now) = (
            live.secs,
            live.weak_secs,
            live.entry.game_only,
            live.entry.weak,
        );
        if let Some(why) = why {
            tracing::debug!(
                session = session_id,
                secs,
                weak_secs,
                weak = weak_now,
                game_only,
                "connection journal: the session's entry changed: {why}"
            );
            inner.write_live(index, now_ms);
        } else if due {
            tracing::trace!(
                session = session_id,
                secs,
                weak_secs,
                "connection journal: the running session's entry rewritten (seen)"
            );
            inner.write_live(index, now_ms);
        }
    }

    /// A session ended with `reason`, the agent's own. The first end of a session whose video came
    /// up closes its entry; any other end (a second report of it, a session that never had video,
    /// one its peer's end closed already) is nothing here.
    pub fn session_ended(&self, session_id: &str, reason: &str, now_ms: i64) {
        let mut inner = lock(&self.inner);
        if !inner.close_live(session_id, reason, now_ms) {
            inner.no_open_entry(session_id, reason, now_ms);
        }
    }

    /// A session's peer ended by itself (`peer_closed`), and the backend may yet say why: its entry
    /// is closed now with `reason` ([`VIEWER_LEFT`] for the viewer's goodbye, `peer_closed`
    /// otherwise), and the backend's reason takes that one's place if
    /// [`Self::session_ended_by_server`] brings it within [`SERVER_REASON_WAIT_MS`].
    ///
    /// The viewer's «Отключиться» sends its `session_end` (`viewer_closed`) to the backend and
    /// closes its connection in the same moment. The goodbye, peer to peer, lands first, and the
    /// peer ends as `peer_closed`, which alone would read «Связь потеряна». The backend's relay of
    /// the viewer's reason follows a tenth of a second later, or never, when the agent's own
    /// `peer_closed` reached the backend first and the viewer's end then found no session there.
    /// So the entry is closed at once and written again if the backend's reason comes, the last
    /// line winning: nothing waits, a crash in between leaves the first, and nothing of the
    /// session's teardown waits either.
    pub fn session_ended_by_peer(&self, session_id: &str, reason: &str, now_ms: i64) {
        let mut inner = lock(&self.inner);
        inner.let_go_of_waits(now_ms);
        if !inner.close_live(session_id, reason, now_ms) {
            inner.no_open_entry(session_id, reason, now_ms);
            return;
        }
        let until = now_ms.saturating_add(SERVER_REASON_WAIT_MS);
        inner.waiting.retain(|w| w.id != session_id);
        inner.waiting.push(Waiting {
            id: session_id.to_string(),
            until,
        });
        tracing::debug!(
            session = session_id,
            reason,
            wait_ms = SERVER_REASON_WAIT_MS,
            waiting = inner.waiting.len(),
            "connection journal: closed by the peer's own end, as {reason} for now; the backend's \
             reason takes its place if it comes within the wait"
        );
    }

    /// The backend ended a session (its `session_end`), with its reason — the viewer's, passed on —
    /// or `server_ended` when it gave none. A running session's entry closes with it, as with
    /// [`Self::session_ended`]. An entry its peer's end closed within [`SERVER_REASON_WAIT_MS`]
    /// takes it in place of its own, keeping its end time; unless it says nothing more —
    /// `server_ended`, or `unknown_session` (the backend did not have the session any more: the
    /// agent's own end got there first).
    pub fn session_ended_by_server(&self, session_id: &str, reason: &str, now_ms: i64) {
        let mut inner = lock(&self.inner);
        if inner.close_live(session_id, reason, now_ms) {
            return;
        }
        match inner.take_wait(session_id) {
            Some(wait) if now_ms <= wait.until => {
                inner.take_server_reason(session_id, reason, now_ms)
            }
            Some(wait) => tracing::debug!(
                session = session_id,
                reason,
                late_ms = now_ms - wait.until,
                "connection journal: the backend's reason came after the wait; the entry keeps the \
                 one its peer's end gave it"
            ),
            None => inner.no_open_entry(session_id, reason, now_ms),
        }
        inner.let_go_of_waits(now_ms);
    }

    /// An event about `person` ([`Kind::Granted`], [`Kind::Invited`], [`Kind::Revoked`] or
    /// [`Kind::Paused`]).
    pub fn event(&self, kind: Kind, person: Person<'_>, now_ms: i64) {
        if kind == Kind::Session {
            tracing::warn!(
                user = person.user,
                "connection journal: a session passed as an event; not written"
            );
            return;
        }
        self.write_event(kind, person, None, now_ms);
    }

    /// Events about people ([`Self::event`]'s kinds), in their order, as ONE file write —
    /// one open, one `write_all` of all their lines — then kept as one by one would be (the same
    /// [`KEEP_DAYS`] / [`KEEP_ENTRIES`] bound, one prune and one compaction check for them all).
    /// For a comparison's many changes (`agent_ready` after a break), so a flood is not a file
    /// write each. A [`Kind::Session`] among them is left out (`warn`), as at [`Self::event`].
    pub fn events(&self, batch: &[PersonEvent], now_ms: i64) {
        let entries: Vec<Entry> = batch
            .iter()
            .filter_map(|e| {
                if e.kind == Kind::Session {
                    tracing::warn!(
                        user = e.user,
                        "connection journal: a session passed as an event in a batch; not written"
                    );
                    return None;
                }
                Some(event_entry(
                    e.kind,
                    Person {
                        user: e.user,
                        name: &e.name,
                        username: e.username.as_deref(),
                    },
                    None,
                    false,
                    None,
                    now_ms,
                ))
            })
            .collect();
        if entries.is_empty() {
            tracing::debug!(
                passed = batch.len(),
                "connection journal: a batch of events with nothing to write"
            );
            return;
        }
        tracing::debug!(
            entries = entries.len(),
            passed = batch.len(),
            at = now_ms,
            "connection journal: events kept and queued together (one file write)"
        );
        let mut inner = lock(&self.inner);
        inner.append_many(&entries);
        inner.push_done_many(entries, now_ms);
    }

    /// A trusted devices' event, written after the change is in the list's file:
    /// [`Kind::TrustedOn`] / [`Kind::TrustedOff`] with no person (`None`: `user` 0, an empty name)
    /// and no device, [`Kind::DeviceUntrusted`], [`Kind::DeviceAdded`] and [`Kind::KeyRestored`]
    /// with the person and the device, the `Declined*` kinds and [`Kind::OtherDeviceAttempt`]
    /// with the person. Any other kind,
    /// or a device event without its person or device, is not written (`warn`).
    pub fn trusted_event(
        &self,
        kind: Kind,
        person: Option<Person<'_>>,
        device: Option<TrustedDevice>,
        now_ms: i64,
    ) {
        let fits = match kind {
            Kind::TrustedOn | Kind::TrustedOff => person.is_none() && device.is_none(),
            Kind::DeviceUntrusted | Kind::DeviceAdded | Kind::KeyRestored => {
                person.is_some() && device.is_some()
            }
            Kind::DeclinedNoKey
            | Kind::DeclinedUntrusted
            | Kind::DeclinedUnknown
            | Kind::OtherDeviceAttempt => person.is_some(),
            _ => false,
        };
        if !fits {
            tracing::warn!(
                kind = kind.as_str(),
                person = person.is_some(),
                device = device.is_some(),
                "connection journal: not a trusted devices' event as passed; not written"
            );
            return;
        }
        let person = person.unwrap_or(Person {
            user: 0,
            name: "",
            username: None,
        });
        self.write_event(kind, person, device, now_ms);
    }

    /// [`Kind::DeviceAdded`] (after the key is in the list's file): the person, the device, the
    /// device that vouched for it (`by`), and whether it is a known guest's new device
    /// (`guest_new_device`, spec §7) rather than a new person's.
    pub fn device_added(
        &self,
        person: Person<'_>,
        device: TrustedDevice,
        by: Option<TrustedDevice>,
        guest_new_device: bool,
        now_ms: i64,
    ) {
        self.write_entry(
            Kind::DeviceAdded,
            person,
            Some(device),
            guest_new_device,
            by,
            now_ms,
        );
    }

    fn write_event(
        &self,
        kind: Kind,
        person: Person<'_>,
        trusted_device: Option<TrustedDevice>,
        now_ms: i64,
    ) {
        self.write_entry(kind, person, trusted_device, false, None, now_ms);
    }

    /// A `Declined*` kind with the person and, when the refusal has one, its reason word
    /// (`grant_stale`, `key_unconfirmed`) in [`Entry::reason`]; without one the
    /// line is as [`Journal::trusted_event`] writes it. Any other kind is not written (`warn`).
    pub fn declined(&self, kind: Kind, person: Person<'_>, reason: Option<&str>, now_ms: i64) {
        if !matches!(
            kind,
            Kind::DeclinedNoKey | Kind::DeclinedUntrusted | Kind::DeclinedUnknown
        ) {
            tracing::warn!(
                kind = kind.as_str(),
                "connection journal: not a refusal's kind; not written"
            );
            return;
        }
        let mut entry = event_entry(kind, person, None, false, None, now_ms);
        entry.reason = reason.map(|r| bounded(r, PLATFORM_MAX));
        self.write_built(entry, now_ms);
    }

    /// [`Kind::OtherDeviceAttempt`] with the trying device's key id and the attempt's reason (the
    /// person, no device).
    pub fn other_device_attempt(
        &self,
        person: Person<'_>,
        key_id: &str,
        reason: &str,
        now_ms: i64,
    ) {
        let mut entry = event_entry(Kind::OtherDeviceAttempt, person, None, false, None, now_ms);
        entry.reason = Some(bounded(reason, PLATFORM_MAX));
        entry.attempt_key = Some(bounded(key_id, NAME_MAX));
        self.write_built(entry, now_ms);
    }

    /// A party's event (party spec §5.4, §6), after the change is in the list's file:
    /// [`Kind::PartyAdded`] and [`Kind::PartyLeft`] with no person (`user` 0) and no device,
    /// [`Kind::PartyLeader`] with the new leader, [`Kind::PartyGuest`] with the member and the
    /// device, and [`Kind::DeviceAdded`] with a member and the device as a known guest's new one;
    /// `party` the party's name as shown ([`crate::person_name::clean_name`] by the caller).
    pub fn party_event(
        &self,
        kind: Kind,
        party: &str,
        person: Option<Person<'_>>,
        device: Option<TrustedDevice>,
        now_ms: i64,
    ) {
        let person = person.unwrap_or(Person {
            user: 0,
            name: "",
            username: None,
        });
        let mut entry = event_entry(
            kind,
            person,
            device,
            kind == Kind::DeviceAdded,
            None,
            now_ms,
        );
        entry.party = Some(bounded(party, NAME_MAX));
        self.write_built(entry, now_ms);
    }

    fn write_entry(
        &self,
        kind: Kind,
        person: Person<'_>,
        trusted_device: Option<TrustedDevice>,
        guest_new_device: bool,
        by_device: Option<TrustedDevice>,
        now_ms: i64,
    ) {
        let entry = event_entry(
            kind,
            person,
            trusted_device,
            guest_new_device,
            by_device,
            now_ms,
        );
        self.write_built(entry, now_ms);
    }

    fn write_built(&self, entry: Entry, now_ms: i64) {
        tracing::debug!(
            kind = entry.kind.as_str(),
            user = entry.user,
            name = %entry.name,
            device = ?entry.trusted_device,
            guest_new_device = entry.guest_new_device,
            by_device = ?entry.by_device,
            reason = entry.reason.as_deref().unwrap_or("-"),
            attempt_key = entry.attempt_key.is_some(),
            at = now_ms,
            "connection journal: an event written"
        );
        let mut inner = lock(&self.inner);
        inner.append(&entry);
        inner.push_done(entry, now_ms);
    }
}

/// An event's entry (no session fields).
fn event_entry(
    kind: Kind,
    person: Person<'_>,
    trusted_device: Option<TrustedDevice>,
    guest_new_device: bool,
    by_device: Option<TrustedDevice>,
    now_ms: i64,
) -> Entry {
    let bound_device = |d: TrustedDevice| TrustedDevice {
        kind: bounded(&d.kind, PLATFORM_MAX),
        platform: bounded(&d.platform, PLATFORM_MAX),
        source: bounded(&d.source, PLATFORM_MAX),
    };
    Entry {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        user: person.user,
        name: bounded(person.name, NAME_MAX),
        username: person.username.map(|u| bounded(u, NAME_MAX)),
        at: now_ms,
        end: None,
        reason: None,
        platform: None,
        game_only: false,
        weak: false,
        seen: None,
        trusted_device: trusted_device.map(bound_device),
        guest_new_device,
        by_device: by_device.map(bound_device),
        attempt_key: None,
        party: None,
    }
}

impl Journal {
    /// Tests only: every file write from now on waits `delay` first (a slow disk).
    #[cfg(test)]
    pub fn slow_file_writes(&self, delay: Duration) {
        if let Some(writer) = self.writer() {
            lock(&writer.slot).write_delay = Some(delay);
        }
    }

    /// Tests only: the file writes done so far (appends and rewrites).
    #[cfg(test)]
    pub fn file_writes(&self) -> usize {
        self.writer().map_or(0, |w| lock(&w.slot).file_writes)
    }

    /// Tests only: every file write from now on stops at the returned gate until released.
    #[cfg(test)]
    pub fn hold_file_writes(&self) -> Arc<WriteGate> {
        let gate = WriteGate::held();
        if let Some(writer) = self.writer() {
            lock(&writer.slot).gate = Some(gate.clone());
        }
        gate
    }

    /// Tests only: the write held at the gate panics once the gate lets it pass.
    #[cfg(test)]
    pub fn panic_in_the_held_write(&self) {
        if let Some(writer) = self.writer() {
            lock(&writer.slot).panic_next = true;
        }
    }

    /// Tests only: a writer thread runs (or is being started).
    #[cfg(test)]
    pub fn writer_running(&self) -> bool {
        self.writer().is_some_and(|w| lock(&w.slot).running)
    }

    /// Tests only: the last write failed.
    #[cfg(test)]
    pub fn write_failed(&self) -> bool {
        self.writer().is_some_and(|w| lock(&w.slot).write_failed)
    }

    /// Tests only: file work waiting for the writer (not the one in progress).
    #[cfg(test)]
    pub fn queued(&self) -> usize {
        self.writer().map_or(0, |w| lock(&w.slot).queue.len())
    }

    /// The writer, its lock let go at once (never held while a caller then waits on the writer).
    fn writer(&self) -> Option<Arc<Writer>> {
        lock(&self.inner).writer.clone()
    }

    /// Wait, at most `limit`, until the writer has carried out everything queued so far —
    /// the app's way out, on its main thread after [`Self::app_closing`]. True when it did (or
    /// there is no file); false when the bound ran out or no writer thread runs (said at `warn`
    /// with what was left: it may not reach the disk). Blocks the caller: never on the async
    /// runtime. Holds no lock of the journal while it waits.
    pub fn drain(&self, limit: Duration) -> bool {
        match self.writer() {
            Some(writer) => writer.drain(limit),
            None => {
                tracing::trace!("connection journal: in memory only; nothing to drain");
                true
            }
        }
    }

    /// The app is exiting: every session still going on is closed as [`APP_CLOSED`] now. An entry
    /// still open to the backend's reason keeps the one it has, written already. A process that
    /// died without this (a crash, a power cut, a kill) leaves a session open on disk: the next
    /// start closes it as [`APP_CLOSED`] too, ending where it was last written.
    pub fn app_closing(&self, now_ms: i64) {
        let mut inner = lock(&self.inner);
        if !inner.waiting.is_empty() {
            let waiting = std::mem::take(&mut inner.waiting);
            tracing::debug!(
                entries = waiting.len(),
                sessions = %waiting.iter().map(|w| w.id.as_str()).collect::<Vec<_>>().join(","),
                "connection journal: entries closed by their peer's end were still open to the \
                 backend's reason at exit; they keep the one they have (written already)"
            );
        }
        if inner.live.is_empty() {
            tracing::debug!("connection journal: no session going on at exit");
            return;
        }
        let live = std::mem::take(&mut inner.live);
        for l in live {
            let entry = close(l, APP_CLOSED, now_ms);
            tracing::debug!(
                session = %entry.id,
                user = entry.user,
                duration_s = (entry.end.unwrap_or(entry.at) - entry.at) / 1000,
                "connection journal: a session going on at exit closed as app_closed"
            );
            inner.append(&entry);
            inner.push_done(entry, now_ms);
        }
    }

    /// Every entry, newest first: the sessions going on now, then the rest by when they happened.
    pub fn entries(&self) -> Vec<View> {
        let inner = lock(&self.inner);
        let mut live: Vec<View> = inner
            .live
            .iter()
            .map(|l| View::of(&l.entry, true))
            .collect();
        live.sort_by_key(|v| std::cmp::Reverse(v.entry.at));
        let mut done: Vec<View> = inner.done.iter().map(|e| View::of(e, false)).collect();
        done.sort_by_key(|v| std::cmp::Reverse(v.entry.at));
        live.extend(done);
        live
    }

    /// The newest entry — a session going on now first — or `None` for an empty journal.
    pub fn last(&self) -> Option<View> {
        let inner = lock(&self.inner);
        if let Some(l) = inner.live.iter().max_by_key(|l| l.entry.at) {
            return Some(View::of(&l.entry, true));
        }
        inner
            .done
            .iter()
            .max_by_key(|e| e.at)
            .map(|e| View::of(e, false))
    }

    /// The last name and username the journal has for `user`, newest first: for an event about
    /// someone the agent has no binding for any more.
    pub fn known_name(&self, user: i64) -> Option<(String, Option<String>)> {
        let inner = lock(&self.inner);
        inner
            .live
            .iter()
            .map(|l| &l.entry)
            .chain(inner.done.iter().rev())
            .find(|e| e.user == user)
            .map(|e| (e.name.clone(), e.username.clone()))
    }
}

impl Inner {
    fn live_index(&self, session_id: &str) -> Option<usize> {
        self.live.iter().position(|l| l.entry.id == session_id)
    }

    /// Close the running session's entry with `reason` and write it; false when it is not running.
    fn close_live(&mut self, session_id: &str, reason: &str, now_ms: i64) -> bool {
        let Some(index) = self.live_index(session_id) else {
            return false;
        };
        let live = self.live.remove(index);
        let ending = Ending::of(reason);
        if ending.is_none() {
            tracing::warn!(
                session = session_id,
                reason,
                "connection journal: an end reason this build does not know; the entry shows no \
                 label for it"
            );
        }
        let entry = close(live, reason, now_ms);
        tracing::debug!(
            session = session_id,
            user = entry.user,
            reason,
            ending = ending.and_then(Ending::label).unwrap_or("-"),
            duration_s = (entry.end.unwrap_or(entry.at) - entry.at) / 1000,
            platform = entry.platform.as_deref().unwrap_or("-"),
            game_only = entry.game_only,
            weak = entry.weak,
            "connection journal: a session's entry closed"
        );
        self.append(&entry);
        self.push_done(entry, now_ms);
        true
    }

    /// An end for a session whose entry is not open, said so: no video came up, it was closed
    /// already — by the end it is a second report of, or by its peer's own end and waiting for the
    /// backend's reason (which this end, the agent's own, is not).
    fn no_open_entry(&self, session_id: &str, reason: &str, now_ms: i64) {
        if let Some(wait) = self.waiting.iter().find(|w| w.id == session_id) {
            tracing::debug!(
                session = session_id,
                reason,
                wait_left_ms = wait.until.saturating_sub(now_ms),
                "connection journal: an end for an entry its peer's end closed already, waiting for \
                 the backend's reason: nothing written"
            );
        } else {
            tracing::debug!(
                session = session_id,
                reason,
                "connection journal: an end for no open entry (no video came up, or it was closed \
                 already): nothing written"
            );
        }
    }

    /// Take `session_id`'s wait for the backend's reason, run out or not.
    fn take_wait(&mut self, session_id: &str) -> Option<Waiting> {
        let index = self.waiting.iter().position(|w| w.id == session_id)?;
        Some(self.waiting.remove(index))
    }

    /// Let go of every wait for the backend's reason that has run out: those entries keep theirs.
    fn let_go_of_waits(&mut self, now_ms: i64) {
        let before = self.waiting.len();
        self.waiting.retain(|w| {
            let open = now_ms <= w.until;
            if !open {
                tracing::debug!(
                    session = %w.id,
                    over_ms = now_ms - w.until,
                    "connection journal: no reason from the backend within the wait; the entry \
                     keeps the one its peer's end gave it"
                );
            }
            open
        });
        if self.waiting.len() != before {
            tracing::trace!(
                let_go = before - self.waiting.len(),
                waiting = self.waiting.len(),
                "connection journal: waits for the backend's reason let go"
            );
        }
    }

    /// The backend's `reason` for a session whose entry its peer's end closed, within the wait: it
    /// replaces the entry's own and the entry is written again, its end time kept. Not when it says
    /// nothing more than the entry has.
    fn take_server_reason(&mut self, session_id: &str, reason: &str, now_ms: i64) {
        use afklink_protocol::end_reason as r;
        let Some(index) = self
            .done
            .iter()
            .rposition(|e| e.id == session_id && e.kind == Kind::Session)
        else {
            tracing::debug!(
                session = session_id,
                reason,
                "connection journal: the backend's reason for an entry no longer kept; nothing \
                 written"
            );
            return;
        };
        let was = self.done[index].reason.clone().unwrap_or_default();
        let after_ms = now_ms.saturating_sub(self.done[index].end.unwrap_or(now_ms));
        if reason == r::local::SERVER_ENDED || reason == r::UNKNOWN_SESSION {
            tracing::debug!(
                session = session_id,
                reason,
                kept = %was,
                after_ms,
                "connection journal: the backend's end names no reason of its own; the entry keeps \
                 the one its peer's end gave it"
            );
            return;
        }
        let bounded_reason = bounded(reason, NAME_MAX);
        if was == bounded_reason {
            tracing::debug!(
                session = session_id,
                reason,
                after_ms,
                "connection journal: the backend's reason is the entry's already; nothing written"
            );
            return;
        }
        let ending = Ending::of(reason);
        if ending.is_none() {
            tracing::warn!(
                session = session_id,
                reason,
                "connection journal: an end reason this build does not know; the entry shows no \
                 label for it"
            );
        }
        let label = |why: &str| Ending::of(why).and_then(Ending::label).unwrap_or("-");
        tracing::debug!(
            session = session_id,
            from = %was,
            to = reason,
            ending_from = label(&was),
            ending_to = ending.and_then(Ending::label).unwrap_or("-"),
            after_ms,
            "connection journal: the backend's reason for the end takes the place of the one the \
             peer's end gave"
        );
        self.done[index].reason = Some(bounded_reason);
        let entry = self.done[index].clone();
        self.append(&entry);
    }

    /// Write the running session at `index` again, as of now.
    fn write_live(&mut self, index: usize, now_ms: i64) {
        let entry = {
            let live = &mut self.live[index];
            live.entry.seen = Some(now_ms);
            live.written_at = now_ms;
            live.entry.clone()
        };
        self.append(&entry);
    }

    /// Keep an ended session or an event, drop what is past [`KEEP_DAYS`] or [`KEEP_ENTRIES`], and
    /// rewrite the file once the superseded lines pass [`COMPACT_SLACK`].
    fn push_done(&mut self, entry: Entry, now_ms: i64) {
        self.done.push(entry);
        self.push_done_settle(now_ms);
    }

    /// What follows keeping entries: the bound, then the compaction.
    fn push_done_settle(&mut self, now_ms: i64) {
        let (expired, over_limit) = self.prune(now_ms);
        if expired + over_limit > 0 {
            tracing::debug!(
                expired,
                over_limit,
                kept = self.done.len(),
                "connection journal: old entries dropped (kept {KEEP_DAYS} days, at most \
                 {KEEP_ENTRIES})"
            );
        }
        let entries = self.done.len() + self.live.len();
        if self.lines > entries + COMPACT_SLACK {
            self.rewrite("superseded lines piled up");
        }
    }

    /// [`Self::push_done`] for several entries at once: kept in their order, one prune,
    /// one compaction check.
    fn push_done_many(&mut self, entries: Vec<Entry>, now_ms: i64) {
        self.done.extend(entries);
        self.push_done_settle(now_ms);
    }

    /// Drop entries past [`KEEP_DAYS`], then the oldest past [`KEEP_ENTRIES`]: `(expired,
    /// over_limit)`.
    fn prune(&mut self, now_ms: i64) -> (usize, usize) {
        let horizon = now_ms.saturating_sub(KEEP_DAYS * DAY_MS);
        let before = self.done.len();
        self.done.retain(|e| e.at >= horizon);
        let expired = before - self.done.len();
        let over_limit = self.done.len().saturating_sub(KEEP_ENTRIES);
        if over_limit > 0 {
            // Oldest first, so the first ones are the ones to go.
            self.done.sort_by_key(|e| e.at);
            self.done.drain(..over_limit);
        }
        (expired, over_limit)
    }

    /// Hand `op` to the writer (nothing with no file), keeping [`Self::lines`] as the file
    /// will be. Under the journal's lock, so the file gets the work in the order of the calls.
    fn queue(&mut self, op: FileOp) {
        let Some(writer) = self.writer.clone() else {
            return;
        };
        let added = op.entries();
        let (done, live) = (&self.done, &self.live);
        match writer.push(op, || snapshot(done, live)) {
            Some(lines) => self.lines = lines,
            None => self.lines += added,
        }
    }

    /// Append one line (by the writer).
    fn append(&mut self, entry: &Entry) {
        self.queue(FileOp::Append(vec![entry.clone()]));
    }

    /// Append several lines with ONE open and ONE `write_all`, in their order (by the
    /// writer; an entry that does not serialize is left out, `warn`).
    fn append_many(&mut self, entries: &[Entry]) {
        if entries.is_empty() {
            return;
        }
        self.queue(FileOp::Append(entries.to_vec()));
    }

    /// Write every entry kept to a new file and put it in the old one's place (by the writer:
    /// what is kept now, the work still waiting before it dropped, since this holds it).
    fn rewrite(&mut self, why: &str) {
        if self.writer.is_none() {
            return;
        }
        tracing::debug!(
            why,
            lines_before = self.lines,
            entries = self.done.len() + self.live.len(),
            "connection journal: the file is to be rewritten"
        );
        let entries = snapshot(&self.done, &self.live);
        self.queue(FileOp::Rewrite {
            entries,
            why: why.to_string(),
        });
    }

    /// Read the file: the last line for each id, sessions left open closed as [`APP_CLOSED`], old
    /// entries dropped.
    fn load(&mut self, now_ms: i64) -> Loaded {
        let mut loaded = Loaded::default();
        let Some(path) = self.path.clone() else {
            return loaded;
        };
        let text = match std::fs::read(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    file = %path.display(),
                    "connection journal: no file yet; it starts with the first entry"
                );
                return loaded;
            }
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    "connection journal: the file not read ({e}); starting empty, the file is left \
                     as it is until the first entry"
                );
                return loaded;
            }
        };
        // The last line for an id wins; the order of first sight is kept for equal times.
        let mut by_id: Vec<Entry> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            loaded.lines += 1;
            match serde_json::from_str::<Entry>(line) {
                Ok(entry) => match by_id.iter_mut().find(|e| e.id == entry.id) {
                    Some(known) => {
                        loaded.superseded += 1;
                        *known = entry;
                    }
                    None => by_id.push(entry),
                },
                Err(e) => {
                    loaded.unreadable += 1;
                    tracing::debug!(
                        line = loaded.lines,
                        bytes = line.len(),
                        "connection journal: a line not read ({e}); dropped"
                    );
                }
            }
        }
        for entry in &mut by_id {
            if entry.kind == Kind::Session && entry.end.is_none() {
                let end = entry.seen.unwrap_or(entry.at).max(entry.at);
                entry.end = Some(end);
                entry.reason = Some(APP_CLOSED.to_string());
                entry.seen = None;
                loaded.closed_at_start += 1;
                tracing::debug!(
                    session = %entry.id,
                    user = entry.user,
                    at = entry.at,
                    end,
                    "connection journal: a session left open by the last process closed as \
                     app_closed, ending when it was last written"
                );
            }
        }
        self.lines = loaded.lines;
        self.done = by_id;
        let (expired, over_limit) = self.prune(now_ms);
        loaded.expired = expired;
        loaded.over_limit = over_limit;
        self.done.sort_by_key(|e| e.at);
        loaded
    }
}

/// Every entry the journal keeps, as a rewrite writes them: the ended ones, then the running.
fn snapshot(done: &[Entry], live: &[Live]) -> Vec<Entry> {
    done.iter()
        .chain(live.iter().map(|l| &l.entry))
        .cloned()
        .collect()
}

/// The journal's writer thread's name.
const WRITER_THREAD: &str = "afklink-journal";

/// A file write that took this long or more is said at warn: the disk is slow (only the writer
/// waited).
const SLOW_WRITE: Duration = Duration::from_secs(1);

/// File work handed to the writer thread ([`Writer`]), in the order the journal decided it.
#[derive(Debug)]
enum FileOp {
    /// Lines appended in their order: one open, one `write_all`.
    Append(Vec<Entry>),
    /// The file rewritten whole with these entries (a temporary file renamed over it): every
    /// entry the journal keeps, as of when it was queued.
    Rewrite { entries: Vec<Entry>, why: String },
}

impl FileOp {
    fn what(&self) -> &'static str {
        match self {
            Self::Append(_) => "append",
            Self::Rewrite { .. } => "rewrite",
        }
    }

    fn entries(&self) -> usize {
        match self {
            Self::Append(entries) | Self::Rewrite { entries, .. } => entries.len(),
        }
    }
}

/// The file write the writer thread is inside, and since when.
#[derive(Debug, Clone, Copy)]
struct Busy {
    what: &'static str,
    entries: usize,
    since: Instant,
    /// A caller already said at warn that this write is slow (once per write).
    said_slow: bool,
}

/// The writer thread's mailbox, behind [`Writer::slot`].
#[derive(Debug)]
struct Slot {
    /// File work not yet begun, oldest first; at most [`QUEUE_MAX`].
    queue: VecDeque<FileOp>,
    /// The write the thread is inside (on the disk, no lock held).
    busy: Option<Busy>,
    /// A thread is running, or being started, for this slot.
    running: bool,
    /// The journal is gone: the thread ends once nothing is queued.
    closed: bool,
    /// The last write failed (said once at warn; the next that works says so at info).
    write_failed: bool,
    /// A write taking this long or more is a warning ([`SLOW_WRITE`]).
    slow: Duration,
    /// Tests only: each file write waits this long first.
    #[cfg(test)]
    write_delay: Option<Duration>,
    /// Tests only: holds each file write, as a disk that does not answer would.
    #[cfg(test)]
    gate: Option<Arc<WriteGate>>,
    /// Tests only: the file writes done (appends and rewrites).
    #[cfg(test)]
    file_writes: usize,
    /// Tests only: the write at the gate panics once it passes.
    #[cfg(test)]
    panic_next: bool,
}

/// The journal file's writer — its own thread and a bounded FIFO
/// of file work. Lock order: the journal's [`Inner`], then [`Self::slot`]; the thread takes only
/// the slot, and never across the disk.
#[derive(Debug)]
struct Writer {
    path: PathBuf,
    slot: Mutex<Slot>,
    /// Wakes the thread: work, or the journal gone.
    work: Condvar,
    /// The thread finished a write or ended ([`Self::drain`], [`Self::wait_ended`]).
    idle: Condvar,
}

impl Writer {
    fn new(path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            path,
            slot: Mutex::new(Slot {
                queue: VecDeque::new(),
                busy: None,
                running: false,
                closed: false,
                write_failed: false,
                slow: SLOW_WRITE,
                #[cfg(test)]
                write_delay: None,
                #[cfg(test)]
                gate: None,
                #[cfg(test)]
                file_writes: 0,
                #[cfg(test)]
                panic_next: false,
            }),
            work: Condvar::new(),
            idle: Condvar::new(),
        })
    }

    /// Hand `op` to the writer thread, starting it the first time; called under the journal's
    /// lock, which orders the work (order on disk = order of the calls). Never waits for the disk
    /// or the thread: the slot's lock is held only to queue. A rewrite takes the place of the
    /// work still waiting (it holds all of it). With [`QUEUE_MAX`] waiting, `op` and the waiting
    /// work are replaced by ONE rewrite of `snapshot()` — the journal as memory has it — followed
    /// by `op`, so the queue never grows past the bound. `Some(n)`: the file is to hold `n` lines
    /// (a rewrite); `None`: `op`'s lines are appended.
    fn push(self: &Arc<Self>, op: FileOp, snapshot: impl FnOnce() -> Vec<Entry>) -> Option<usize> {
        let what = op.what();
        let entries = op.entries();
        let mut slot = lock(&self.slot);
        let waiting = slot.queue.len();
        let (rewrite_lines, replaced, coalesced) = match op {
            FileOp::Rewrite { .. } => {
                slot.queue.clear();
                slot.queue.push_back(op);
                (Some(entries), waiting, false)
            }
            FileOp::Append(_) if waiting >= QUEUE_MAX => {
                // `op` goes after the rewrite: its entry may not be in memory's lists yet (a
                // session's end is written before it is kept); one that is comes twice, the same
                // line, and the last line for an id wins.
                let all = snapshot();
                let lines = all.len() + entries;
                slot.queue.clear();
                slot.queue.push_back(FileOp::Rewrite {
                    entries: all,
                    why: format!("the writer's queue was full ({waiting} waiting)"),
                });
                slot.queue.push_back(op);
                (Some(lines), waiting, true)
            }
            FileOp::Append(_) => {
                slot.queue.push_back(op);
                (None, 0, false)
            }
        };
        let queued = slot.queue.len();
        let slow = slot.slow;
        let busy = slot.busy.as_mut().map(|b| {
            let took = b.since.elapsed();
            let say = took >= slow && !b.said_slow;
            if say {
                b.said_slow = true;
            }
            (b.what, b.entries, took, say)
        });
        let start = !slot.running;
        slot.running = true;
        drop(slot);
        self.work.notify_one();
        if let Some((busy_what, busy_entries, took, true)) = busy {
            tracing::warn!(
                file = %self.path.display(),
                in_progress = busy_what,
                in_progress_entries = busy_entries,
                in_progress_ms = ms(took),
                slow_ms = ms(slow),
                queued,
                "connection journal: the writer is still inside a file write ({busy_what}) after \
                 {} ms: the disk does not answer (only the writer waits; the journal goes on in \
                 memory); this work waits its turn",
                ms(took)
            );
        }
        if coalesced {
            tracing::debug!(
                file = %self.path.display(),
                replaced,
                bound = QUEUE_MAX,
                lines = rewrite_lines.unwrap_or(0),
                "connection journal: the writer's queue is full; the waiting work is replaced by \
                 one rewrite of the journal as memory has it (it holds all of it, in order)"
            );
        } else if replaced > 0 {
            tracing::debug!(
                file = %self.path.display(),
                replaced,
                lines = entries,
                "connection journal: a rewrite takes the place of the work still waiting (it holds \
                 all of it)"
            );
        }
        tracing::trace!(
            file = %self.path.display(),
            what,
            entries,
            queued,
            in_progress = busy.map_or("-", |b| b.0),
            starts_thread = start,
            "connection journal: queued for the writer"
        );
        if start {
            self.start();
        }
        rewrite_lines
    }

    /// Start the writer thread, logging as this thread's subscriber (the process's, or a test's).
    fn start(self: &Arc<Self>) {
        let writer = Arc::clone(self);
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let spawned = std::thread::Builder::new()
            .name(WRITER_THREAD.into())
            .spawn(move || tracing::dispatcher::with_default(&dispatch, || writer.run()));
        match spawned {
            Ok(_) => tracing::debug!(
                file = %self.path.display(),
                thread = WRITER_THREAD,
                "connection journal: the writer thread started"
            ),
            Err(e) => {
                lock(&self.slot).running = false;
                // A drain waiting for this start sees at once that no thread runs.
                self.idle.notify_all();
                tracing::warn!(
                    file = %self.path.display(),
                    "connection journal: no thread to write the file ({e}); the work waits, and \
                     the next entry tries to start it again; the journal goes on in memory"
                );
            }
        }
    }

    /// The writer thread: each piece of work in turn, on the disk with no lock held, until the
    /// journal is gone and nothing is queued. Idle without a timeout: nothing waits on this
    /// thread but a bounded drain, and a push or the journal's drop wakes it.
    fn run(&self) {
        let _unwind = Unwind(self);
        loop {
            let op = {
                let mut slot = lock(&self.slot);
                loop {
                    if let Some(op) = slot.queue.pop_front() {
                        slot.busy = Some(Busy {
                            what: op.what(),
                            entries: op.entries(),
                            since: Instant::now(),
                            said_slow: false,
                        });
                        break op;
                    }
                    if slot.closed {
                        slot.running = false;
                        tracing::debug!(
                            file = %self.path.display(),
                            "connection journal: the writer ends: nothing left to write and the \
                             journal is gone"
                        );
                        drop(slot);
                        self.idle.notify_all();
                        return;
                    }
                    slot = self.work.wait(slot).unwrap_or_else(PoisonError::into_inner);
                }
            };
            let started = Instant::now();
            #[cfg(test)]
            self.test_disk();
            let result = self.apply(&op);
            self.report(&op, result, started.elapsed());
            lock(&self.slot).busy = None;
            self.idle.notify_all();
        }
    }

    /// Carry out `op` on the disk: the lines written.
    fn apply(&self, op: &FileOp) -> std::io::Result<usize> {
        let (entries, rewrite) = match op {
            FileOp::Append(entries) => (entries, false),
            FileOp::Rewrite { entries, .. } => (entries, true),
        };
        let mut text = String::new();
        let mut count = 0usize;
        for entry in entries {
            match serde_json::to_string(entry) {
                Ok(line) => {
                    text.push_str(&line);
                    text.push('\n');
                    count += 1;
                }
                Err(e) => {
                    tracing::warn!(id = %entry.id, "connection journal: an entry not serialized: {e}");
                }
            }
        }
        if !rewrite {
            if count == 0 {
                return Ok(0);
            }
            return OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .and_then(|mut file| file.write_all(text.as_bytes()))
                .map(|()| count);
        }
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let result =
            std::fs::write(&tmp, text.as_bytes()).and_then(|()| std::fs::rename(&tmp, &self.path));
        if result.is_err() {
            if let Err(e) = std::fs::remove_file(&tmp) {
                tracing::trace!("connection journal: no temporary file to remove: {e}");
            }
        }
        result.map(|()| count)
    }

    /// How `op` ended and how long the disk took ([`Slot::slow`] and over at warn). A failed
    /// write: said at warn once (then debug) — its entries stay in memory (the window shows
    /// them) and a later rewrite of this process (the next compaction) puts them on disk; one
    /// that never comes before the process exits loses them (the next start reads the file).
    fn report(&self, op: &FileOp, result: std::io::Result<usize>, took: Duration) {
        let file = self.path.display();
        let took_ms = ms(took);
        let (recovered, failed_before, slow) = {
            let mut slot = lock(&self.slot);
            let failed_before = slot.write_failed;
            slot.write_failed = result.is_err();
            (
                failed_before && result.is_ok(),
                failed_before,
                took >= slot.slow,
            )
        };
        if recovered {
            tracing::info!(file = %file, "connection journal: the file is written again");
        }
        match (op, result) {
            (_, Ok(lines)) if slow => tracing::warn!(
                file = %file,
                what = op.what(),
                lines,
                took_ms,
                "connection journal: written; the disk took long (only the writer waited)"
            ),
            (FileOp::Append(_), Ok(lines)) => tracing::trace!(
                file = %file,
                lines,
                took_ms,
                "connection journal: lines appended"
            ),
            (FileOp::Rewrite { why, .. }, Ok(lines)) => tracing::debug!(
                file = %file,
                why = %why,
                lines,
                took_ms,
                "connection journal: the file rewritten"
            ),
            (_, Err(e)) if failed_before => tracing::debug!(
                file = %file,
                what = op.what(),
                entries = op.entries(),
                took_ms,
                "connection journal: still not written ({e}); kept in memory"
            ),
            (_, Err(e)) => tracing::warn!(
                file = %file,
                what = op.what(),
                entries = op.entries(),
                took_ms,
                "connection journal: not written ({e}); the entries stay in memory (the window \
                 shows them) and reach the file only with a later rewrite while this process \
                 runs (a compaction); if it exits first, they are lost"
            ),
        }
    }

    /// Work is queued and no thread runs for it (the writer panicked,
    /// or its start failed): a new writer thread is started for it now (`at`, said at info).
    /// Never waits.
    fn revive(self: &Arc<Self>, at: &'static str) {
        let queued = {
            let mut slot = lock(&self.slot);
            if slot.running || slot.queue.is_empty() {
                return;
            }
            slot.running = true;
            slot.queue.len()
        };
        tracing::info!(
            file = %self.path.display(),
            at,
            queued,
            "connection journal: work queued and no writer thread runs for it: a new writer is \
             started"
        );
        self.start();
    }

    /// Wait (bounded by `limit`) until nothing is queued or in progress; false when the bound ran
    /// out (said at warn with what was left) or no thread runs for queued work. A writer
    /// that died with work queued is started again first ([`Self::revive`]), and the wait ends
    /// as soon as no thread runs (it never waits out its bound for a writer that is gone).
    fn drain(self: &Arc<Self>, limit: Duration) -> bool {
        let started = Instant::now();
        self.revive("a drain");
        let slot = lock(&self.slot);
        let (slot, waited) = self
            .idle
            .wait_timeout_while(slot, limit, |s| {
                s.running && (!s.queue.is_empty() || s.busy.is_some())
            })
            .unwrap_or_else(PoisonError::into_inner);
        if !waited.timed_out() && !slot.queue.is_empty() {
            let queued = slot.queue.len();
            drop(slot);
            tracing::warn!(
                file = %self.path.display(),
                queued,
                "connection journal: work queued and no writer thread runs for it; the file \
                 holds what it held (the journal had it in memory)"
            );
            return false;
        }
        if waited.timed_out() {
            let queued = slot.queue.len();
            let lines: usize = slot.queue.iter().map(FileOp::entries).sum();
            let busy = slot
                .busy
                .map(|b| (b.what, b.entries, ms(b.since.elapsed())));
            drop(slot);
            tracing::warn!(
                file = %self.path.display(),
                limit_ms = ms(limit),
                queued,
                queued_entries = lines,
                in_progress = busy.map_or("-", |b| b.0),
                in_progress_entries = busy.map(|b| b.1),
                in_progress_ms = busy.map(|b| b.2),
                "connection journal: the writer did not finish within the drain's bound: the disk \
                 is slow; what is left may not reach the file (the journal had it in memory)"
            );
            return false;
        }
        drop(slot);
        tracing::debug!(
            file = %self.path.display(),
            took_ms = ms(started.elapsed()),
            "connection journal: drained: everything queued is on the disk (or said failed)"
        );
        true
    }

    /// The journal is gone: the thread finishes what is queued, then ends. Never waits.
    fn close(&self) {
        let mut slot = lock(&self.slot);
        slot.closed = true;
        let queued = slot.queue.len();
        let busy = slot.busy.map(|b| b.what);
        let running = slot.running;
        drop(slot);
        self.work.notify_all();
        if queued > 0 && !running {
            tracing::warn!(
                file = %self.path.display(),
                queued,
                "connection journal: closed with work no thread could write; the file holds what \
                 it held"
            );
        } else if queued > 0 || busy.is_some() {
            tracing::debug!(
                file = %self.path.display(),
                queued,
                in_progress = busy.unwrap_or("-"),
                "connection journal: closed with work still to write; the writer finishes it"
            );
        }
    }

    /// Wait (bounded by `limit`) until the thread ended (or none runs); false when the bound ran
    /// out (said at warn with what was left).
    fn wait_ended(&self, limit: Duration) -> bool {
        let slot = lock(&self.slot);
        let (slot, waited) = self
            .idle
            .wait_timeout_while(slot, limit, |s| s.running)
            .unwrap_or_else(PoisonError::into_inner);
        if !waited.timed_out() && !slot.queue.is_empty() {
            // The thread ended (a panic inside a write) with
            // work queued: once the journal is closed nothing starts a writer again.
            let queued = slot.queue.len();
            let lines: usize = slot.queue.iter().map(FileOp::entries).sum();
            let closed = slot.closed;
            drop(slot);
            tracing::warn!(
                file = %self.path.display(),
                queued,
                queued_entries = lines,
                closed,
                "connection journal: the writer ended with work still queued: it is not written \
                 (the file holds what it held; the journal had it in memory)"
            );
            return false;
        }
        if waited.timed_out() {
            let queued = slot.queue.len();
            let busy = slot.busy.map(|b| (b.what, ms(b.since.elapsed())));
            drop(slot);
            tracing::warn!(
                file = %self.path.display(),
                limit_ms = ms(limit),
                queued,
                in_progress = busy.map_or("-", |b| b.0),
                in_progress_ms = busy.map(|b| b.1),
                "connection journal: dropped while the writer is still at the disk past the bound; \
                 it goes on alone, and what is left may not reach the file if the process exits"
            );
            return false;
        }
        true
    }

    /// Tests: what a disk does inside a write — counted, slowed, held at the gate.
    #[cfg(test)]
    fn test_disk(&self) {
        let (delay, gate) = {
            let mut slot = lock(&self.slot);
            slot.file_writes += 1;
            (slot.write_delay, slot.gate.clone())
        };
        if let Some(d) = delay {
            std::thread::sleep(d);
        }
        if let Some(gate) = gate {
            gate.pass();
        }
        if std::mem::take(&mut lock(&self.slot).panic_next) {
            panic!("connection journal (test): a writer panic inside a write");
        }
    }

    /// Tests: wait (bounded by `limit`) until nothing is queued or in progress, silently.
    #[cfg(test)]
    fn flush(&self, limit: Duration) -> bool {
        let slot = lock(&self.slot);
        let (_slot, waited) = self
            .idle
            .wait_timeout_while(slot, limit, |s| !s.queue.is_empty() || s.busy.is_some())
            .unwrap_or_else(PoisonError::into_inner);
        !waited.timed_out()
    }
}

/// Unwinding out of [`Writer::run`] (a panic inside a write): clears the slot's thread and the
/// write in progress, so the next push starts a new thread, and says what was lost. Queued work
/// stays for that thread. On a normal end it does nothing.
struct Unwind<'a>(&'a Writer);

impl Drop for Unwind<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let writer = self.0;
        let mut slot = lock(&writer.slot);
        let lost = slot.busy.take();
        slot.running = false;
        // The write lost to the panic is a failed write — the next
        // that works says the file is written again.
        if lost.is_some() {
            slot.write_failed = true;
        }
        let queued = slot.queue.len();
        // After the journal is dropped no entry comes to start
        // a new writer — the queued work is not written then.
        let closed = slot.closed;
        tracing::error!(
            file = %writer.path.display(),
            thread = WRITER_THREAD,
            in_progress = lost.map_or("-", |b| b.what),
            in_progress_entries = lost.map(|b| b.entries),
            queued,
            closed,
            "connection journal: the writer panicked inside a file write; that write counts as \
             failed (the entries stay in memory); {}",
            if closed {
                "the journal is closed, so no new writer starts: what is queued is not written \
                 (the file holds what it held)"
            } else {
                "the next entry or a drain starts a new writer, which also writes what is queued"
            }
        );
        drop(slot);
        writer.idle.notify_all();
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A running session's entry as it ends.
fn close(live: Live, reason: &str, now_ms: i64) -> Entry {
    let mut entry = live.entry;
    entry.end = Some(now_ms.max(entry.at));
    entry.reason = Some(bounded(reason, NAME_MAX));
    entry.weak = is_weak(live.secs, live.weak_secs);
    entry.seen = None;
    entry
}

/// `text` cut to `max` characters.
fn bounded(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// A platform string a journal keeps: short, letters, digits, `_` and `-`.
fn clean_platform(platform: &str) -> Option<String> {
    let p = platform.trim();
    (!p.is_empty()
        && p.len() <= PLATFORM_MAX
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then(|| p.to_ascii_lowercase())
}

/// Tests only: a disk that does not answer until released. A file write stops in
/// [`Self::pass`] while the gate is held (at most [`Self::LIMIT`], so a test fails, not hangs).
#[cfg(test)]
#[derive(Debug, Default)]
pub struct WriteGate {
    state: Mutex<WriteGateState>,
    changed: Condvar,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct WriteGateState {
    held: bool,
    /// File writes that reached the gate.
    entered: u64,
}

#[cfg(test)]
impl WriteGate {
    /// Longer than any bound a test asserts.
    pub const LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

    fn held() -> std::sync::Arc<Self> {
        let gate = Self::default();
        lock(&gate.state).held = true;
        std::sync::Arc::new(gate)
    }

    fn pass(&self) {
        let mut state = lock(&self.state);
        state.entered += 1;
        self.changed.notify_all();
        let (_state, waited) = self
            .changed
            .wait_timeout_while(state, Self::LIMIT, |s| s.held)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if waited.timed_out() {
            tracing::warn!(
                "connection journal (test): the gate was never released; the write goes on"
            );
        }
    }

    /// Wait (bounded by `limit`) until `n` file writes reached the gate.
    pub fn wait_entered(&self, n: u64, limit: std::time::Duration) -> bool {
        let state = lock(&self.state);
        let (_state, waited) = self
            .changed
            .wait_timeout_while(state, limit, |s| s.entered < n)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        !waited.timed_out()
    }

    /// File writes that reached the gate so far.
    pub fn entered(&self) -> u64 {
        lock(&self.state).entered
    }

    pub fn release(&self) {
        lock(&self.state).held = false;
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A journal file of its own under the temp dir, removed on drop; with the writers of the
    /// journals it opened, so the file is read once they are done.
    struct TempJournal(PathBuf, std::cell::RefCell<Vec<Arc<Writer>>>);

    impl TempJournal {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("afklink-journal-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir.join(FILE_NAME), std::cell::RefCell::default())
        }

        fn open(&self, now_ms: i64) -> Journal {
            let j = Journal::open(Some(self.0.clone()), now_ms);
            if let Some(writer) = j.writer() {
                self.1.borrow_mut().push(writer);
            }
            j
        }

        /// The file's lines once every writer of this file is done (≤ 10 s each).
        fn lines(&self) -> Vec<String> {
            for writer in self.1.borrow().iter() {
                assert!(writer.flush(Duration::from_secs(10)), "the writer finished");
            }
            std::fs::read_to_string(&self.0)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    impl Drop for TempJournal {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    const T0: i64 = 1_790_000_000_000;
    const MIN: i64 = 60_000;

    fn start<'a>(id: &'a str, name: &'a str) -> SessionStart<'a> {
        SessionStart {
            session_id: id,
            user: 5_000_000_001,
            name,
            username: Some("vera"),
            game_only: false,
        }
    }

    fn vera() -> Person<'static> {
        Person {
            user: 5_000_000_001,
            name: "Вера",
            username: Some("vera"),
        }
    }

    #[test]
    fn a_session_is_written_when_its_video_comes_up_and_when_it_ends() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        assert!(j.last().is_none(), "a new journal is empty");
        j.session_started(&start("s1", "Вера"), T0);
        let live = j.last().expect("the running session");
        assert!(live.live);
        assert_eq!(live.entry.name, "Вера");
        assert_eq!(tmp.lines().len(), 1, "written at once");

        assert!(j.session_platform("s1", "ios", T0 + 1000));
        j.session_ended("s1", "viewer_ended", T0 + 72 * MIN);
        let done = j.last().expect("the ended session");
        assert!(!done.live);
        assert_eq!(done.entry.end, Some(T0 + 72 * MIN));
        assert_eq!(done.device, Some(Device::Iphone));
        assert_eq!(done.ending, None, "an ordinary end carries no label");

        // Read back by a new process: the same entry, the superseded lines gone.
        drop(j);
        let again = tmp.open(T0 + 73 * MIN);
        let entries = again.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry.platform.as_deref(), Some("ios"));
        assert_eq!(entries[0].entry.reason.as_deref(), Some("viewer_ended"));
        assert_eq!(tmp.lines().len(), 1, "compacted at startup");
    }

    #[test]
    fn an_end_without_video_and_a_second_end_write_nothing() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        // A request that never got its video: nothing.
        j.session_ended("never", "ice_timeout", T0);
        assert!(j.last().is_none());
        assert!(tmp.lines().is_empty());
        // The first end counts; the backend's echo of it does not.
        j.session_started(&start("s1", "Вера"), T0);
        j.session_ended("s1", "viewer_closed", T0 + MIN);
        j.session_ended("s1", "server_ended", T0 + 2 * MIN);
        let entries = j.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry.reason.as_deref(), Some("viewer_closed"));
        assert_eq!(entries[0].entry.end, Some(T0 + MIN));
    }

    #[test]
    fn a_session_open_at_the_last_exit_is_closed_at_startup_as_app_closed() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.session_started(&start("s1", "Вера"), T0);
            // Ten minutes of video, written once a minute.
            for s in 1..=600 {
                j.session_second(
                    "s1",
                    Second {
                        weak: false,
                        game_only: false,
                    },
                    T0 + s * 1000,
                );
            }
            // The process dies here: no end, no app_closing.
        }
        let j = tmp.open(T0 + 600 * MIN);
        let entries = j.entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert!(!e.live);
        assert_eq!(e.entry.reason.as_deref(), Some(APP_CLOSED));
        assert_eq!(e.ending, Some(Ending::AppClosed));
        assert_eq!(
            e.entry.end,
            Some(T0 + 10 * MIN),
            "ends where it was last written"
        );
        assert_eq!(tmp.lines().len(), 1);
    }

    #[test]
    fn a_clean_exit_closes_the_running_sessions_now() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.app_closing(T0 + 5 * MIN);
        let e = j.last().expect("entry");
        assert!(!e.live);
        assert_eq!(e.ending, Some(Ending::AppClosed));
        assert_eq!(e.entry.end, Some(T0 + 5 * MIN));
    }

    #[test]
    fn entries_older_than_ninety_days_and_past_a_thousand_go() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        j.event(Kind::Granted, vera(), T0);
        j.event(Kind::Revoked, vera(), T0 + DAY_MS);
        // Ninety days after the first, plus a moment: the first has gone, the second stays.
        j.event(Kind::Paused, vera(), T0 + KEEP_DAYS * DAY_MS + 1);
        let kinds: Vec<Kind> = j.entries().iter().map(|v| v.entry.kind).collect();
        assert_eq!(kinds, [Kind::Paused, Kind::Revoked]);

        // The limit: the oldest go first.
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        for i in 0..(KEEP_ENTRIES as i64 + 5) {
            j.event(Kind::Paused, vera(), T0 + i * 1000);
        }
        let entries = j.entries();
        assert_eq!(entries.len(), KEEP_ENTRIES);
        assert_eq!(entries.last().map(|v| v.entry.at), Some(T0 + 5 * 1000));
        drop(j);
        // And on the next start the file holds no more than that.
        let again = tmp.open(T0 + 2 * DAY_MS);
        assert_eq!(again.entries().len(), KEEP_ENTRIES);
        assert_eq!(tmp.lines().len(), KEEP_ENTRIES);
    }

    /// A guest the owner let in by his invite is its own kind of event, «Доступ по приглашению»,
    /// written as `invited` and read back as it was, beside «Доступ выдан».
    #[test]
    fn access_by_invite_is_kept_apart_from_access_given() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.event(Kind::Granted, vera(), T0);
            j.event(
                Kind::Invited,
                Person {
                    user: 42,
                    name: "Друг",
                    username: Some("friend"),
                },
                T0 + MIN,
            );
        }
        assert!(
            tmp.lines()
                .last()
                .is_some_and(|l| l.contains(r#""kind":"invited""#)),
            "{:?}",
            tmp.lines()
        );
        let j = tmp.open(T0 + 2 * MIN);
        let entries = j.entries();
        let kinds: Vec<(Kind, &str)> = entries
            .iter()
            .map(|v| (v.entry.kind, v.entry.name.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [(Kind::Invited, "Друг"), (Kind::Granted, "Вера")],
            "newest first"
        );
        let invited = &entries[0];
        assert!(!invited.live);
        assert_eq!(invited.ending, None, "an event has no ending");
        assert_eq!(invited.entry.username.as_deref(), Some("friend"));
    }

    #[test]
    fn a_torn_or_unknown_line_costs_only_itself() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.event(Kind::Granted, vera(), T0);
        }
        let mut text = std::fs::read_to_string(&tmp.0).expect("written");
        text.push_str(
            "{\"id\":\"x\",\"kind\":\"from_the_future\",\"user\":1,\"name\":\"n\",\"at\":1}\n",
        );
        text.push_str("{\"id\":\"torn\",\"ki");
        std::fs::write(&tmp.0, text).expect("write");
        let j = tmp.open(T0 + MIN);
        assert_eq!(j.entries().len(), 1);
        assert_eq!(
            tmp.lines().len(),
            1,
            "the unreadable lines are dropped on the rewrite"
        );
    }

    #[test]
    fn every_contract_end_reason_has_a_label_or_none_on_purpose() {
        // `SESSION_END_REASONS` as the contract emits it: a reason added there and not here shows
        // without a label and warns; this makes it a decision instead.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol/fixtures/session-end-reasons.json");
        let raw = std::fs::read_to_string(&path).expect("the contract's end reasons");
        let reasons: Vec<String> = serde_json::from_str(&raw).expect("a list of strings");
        assert!(!reasons.is_empty());
        for reason in &reasons {
            assert!(Ending::of(reason).is_some(), "{reason} is not classified");
        }
        // The local ones, and their labels.
        let label = |r: &str| Ending::of(r).and_then(Ending::label);
        assert_eq!(label("server_ended"), None);
        assert_eq!(label("viewer_ended"), None);
        assert_eq!(label("superseded"), None);
        assert_eq!(label("signed_out"), None);
        assert_eq!(
            label("owner_ended"),
            Some("owner"),
            "the guest keeps access: «Прерван владельцем», not «revoked»"
        );
        assert_eq!(label("viewer_render_reconnect"), None);
        assert_eq!(label("kill_switch"), Some("pc"));
        assert_eq!(label("unbound"), Some("revoked"));
        assert_eq!(
            label("blocked"),
            Some("revoked"),
            "an admin's block takes the access away: «Доступ отозван»"
        );
        assert_eq!(label("ice_timeout"), Some("lost"));
        assert_eq!(label("viewer_signaling_lost"), Some("lost"));
        assert_eq!(label("peer_closed"), Some("lost"));
        assert_eq!(label("server_shutdown"), Some("lost"));
        assert_eq!(label("capture_lost"), Some("failed"));
        assert_eq!(label("viewer_render_stalled"), Some("failed"));
        assert_eq!(label("unknown_session"), Some("failed"));
        assert_eq!(label(APP_CLOSED), Some("app_closed"));
        assert_eq!(
            label(VIEWER_LEFT),
            None,
            "the viewer's goodbye is an ordinary end"
        );
        // The journal's own reasons are never the wire's: one in the contract would mean two things.
        for own in [APP_CLOSED, VIEWER_LEFT] {
            assert!(
                !reasons.iter().any(|r| r == own),
                "{own} is a contract reason"
            );
        }
        // A reason from a newer build: no label.
        assert_eq!(Ending::of("viewer_teleported"), None);
    }

    /// The reason the last line for `id` in the file gives: what the next start reads.
    fn reason_on_disk(tmp: &TempJournal, id: &str) -> Option<String> {
        tmp.lines()
            .iter()
            .rev()
            .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
            .find(|e| e.id == id)
            .and_then(|e| e.reason)
    }

    /// «Отключиться» on an iPhone, the viewer's goodbye
    /// landing 0.1 s before the backend's `viewer_closed` (or with none after it), and the journal
    /// saying «Связь потеряна». The goodbye is an ordinary end at once, and the backend's reason,
    /// when it comes in time, takes its place — the end time stays the goodbye's.
    #[test]
    fn the_viewers_goodbye_is_an_ordinary_end_and_takes_the_backends_reason() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        j.session_started(&start("s1", "Вера"), T0);
        let gone = T0 + 5 * MIN;

        j.session_ended_by_peer("s1", VIEWER_LEFT, gone);
        let e = j.last().expect("entry");
        assert!(!e.live, "closed at once: nothing waits");
        assert_eq!(
            e.ending, None,
            "an ordinary end, before any word from the backend"
        );
        assert_eq!(e.entry.end, Some(gone));
        assert_eq!(reason_on_disk(&tmp, "s1").as_deref(), Some(VIEWER_LEFT));

        // The agent's own end that follows (its `SessionEnded`, `peer_closed`) changes nothing.
        j.session_ended("s1", "peer_closed", gone + 20);
        assert_eq!(
            j.last().and_then(|v| v.entry.reason),
            Some(VIEWER_LEFT.into())
        );

        // The backend's relay of the viewer's reason, a tenth of a second later.
        j.session_ended_by_server("s1", "viewer_closed", gone + 100);
        let e = j.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_closed"));
        assert_eq!(e.ending, None);
        assert_eq!(e.entry.end, Some(gone), "the end is the goodbye's");
        assert_eq!(reason_on_disk(&tmp, "s1").as_deref(), Some("viewer_closed"));

        // A second word from the backend is not waited for any more.
        j.session_ended_by_server("s1", "viewer_signaling_lost", gone + 200);
        assert_eq!(j.last().and_then(|v| v.ending), None);

        drop(j);
        let again = tmp.open(gone + MIN);
        let e = again.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_closed"));
        assert_eq!(e.ending, None);
    }

    /// The viewer's goodbye with no word from the backend in time — the agent's `peer_closed` got
    /// there first and the viewer's end found no session, or the screen closed with its
    /// socket — stays an ordinary end; a late reason, or one that says nothing, changes nothing.
    #[test]
    fn the_viewers_goodbye_with_no_word_from_the_backend_stays_an_ordinary_end() {
        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_ended_by_peer("s1", VIEWER_LEFT, T0 + MIN);
        // Within the wait, but nothing more than the entry has.
        j.session_ended_by_server("s1", "unknown_session", T0 + MIN + 50);
        assert_eq!(
            j.last().and_then(|v| v.entry.reason),
            Some(VIEWER_LEFT.into())
        );
        assert_eq!(j.last().and_then(|v| v.ending), None);

        j.session_started(&start("s2", "Вера"), T0 + 2 * MIN);
        j.session_ended_by_peer("s2", VIEWER_LEFT, T0 + 3 * MIN);
        j.session_ended_by_server("s2", "server_ended", T0 + 3 * MIN + 50);
        assert_eq!(
            j.last().and_then(|v| v.entry.reason),
            Some(VIEWER_LEFT.into())
        );

        // After the wait: a «lost» reason does not count any more.
        j.session_started(&start("s3", "Вера"), T0 + 4 * MIN);
        j.session_ended_by_peer("s3", VIEWER_LEFT, T0 + 5 * MIN);
        j.session_ended_by_server(
            "s3",
            "viewer_signaling_lost",
            T0 + 5 * MIN + SERVER_REASON_WAIT_MS + 1,
        );
        let e = j.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some(VIEWER_LEFT));
        assert_eq!(e.ending, None);
    }

    /// A connection that closed with no goodbye from the viewer is «Связь потеряна» — unless the
    /// backend says, in time, why the viewer ended it.
    #[test]
    fn a_close_without_the_viewers_goodbye_is_lost_unless_the_backend_says_otherwise() {
        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_ended_by_peer("s1", "peer_closed", T0 + MIN);
        assert_eq!(j.last().and_then(|v| v.ending), Some(Ending::Lost));
        j.session_ended_by_server("s1", "viewer_ended", T0 + MIN + 300);
        let e = j.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_ended"));
        assert_eq!(e.ending, None);

        // The backend's word can say lost, too.
        j.session_started(&start("s2", "Вера"), T0 + 2 * MIN);
        j.session_ended_by_peer("s2", VIEWER_LEFT, T0 + 3 * MIN);
        j.session_ended_by_server("s2", "viewer_signaling_lost", T0 + 3 * MIN + 300);
        assert_eq!(j.last().and_then(|v| v.ending), Some(Ending::Lost));

        // And with no word, a close without a goodbye stays lost.
        j.session_started(&start("s3", "Вера"), T0 + 4 * MIN);
        j.session_ended_by_peer("s3", "peer_closed", T0 + 5 * MIN);
        j.session_ended_by_server("s3", "viewer_closed", T0 + 6 * MIN);
        assert_eq!(j.last().and_then(|v| v.ending), Some(Ending::Lost));
    }

    /// A link that died — ICE gave up, nothing said goodbye — is «Связь потеряна», and the
    /// backend's word after it is no reason to change that: only an end by the peer itself waits.
    #[test]
    fn a_lost_link_stays_lost_whatever_the_backend_says_after() {
        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_ended("s1", "ice_timeout", T0 + MIN);
        j.session_ended_by_server("s1", "viewer_closed", T0 + MIN + 100);
        let e = j.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("ice_timeout"));
        assert_eq!(e.ending, Some(Ending::Lost));
    }

    /// The usual order — the backend's word first — closes the entry with it, and the peer's end
    /// after it is nothing.
    #[test]
    fn the_backends_word_first_closes_the_entry_and_the_peers_end_after_is_nothing() {
        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_ended_by_server("s1", "viewer_media_stalled", T0 + MIN);
        j.session_ended_by_peer("s1", VIEWER_LEFT, T0 + MIN + 100);
        let e = j.last().expect("entry");
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_media_stalled"));
        assert_eq!(e.entry.end, Some(T0 + MIN));
        assert_eq!(e.ending, Some(Ending::Lost));
    }

    /// An exit inside the wait loses nothing: the entry was written when the peer ended, it is not
    /// closed again as «Приложение закрыто», and the next start reads it as it was; a session still
    /// running at the exit is closed as usual.
    #[test]
    fn an_exit_inside_the_wait_keeps_the_entry_as_written() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_started(&start("s2", "Дима"), T0 + MIN);
        j.session_ended_by_peer("s1", VIEWER_LEFT, T0 + 2 * MIN);
        j.app_closing(T0 + 2 * MIN + 10);
        let reasons: Vec<(String, Option<String>)> = j
            .entries()
            .into_iter()
            .map(|v| (v.entry.id, v.entry.reason))
            .collect();
        assert!(
            reasons.contains(&("s1".into(), Some(VIEWER_LEFT.into()))),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&("s2".into(), Some(APP_CLOSED.into()))),
            "{reasons:?}"
        );
        // A word from the backend after the exit has nothing to wait on.
        j.session_ended_by_server("s1", "viewer_signaling_lost", T0 + 2 * MIN + 20);
        assert_eq!(reason_on_disk(&tmp, "s1").as_deref(), Some(VIEWER_LEFT));

        drop(j);
        let again = tmp.open(T0 + 10 * MIN);
        let s1 = again
            .entries()
            .into_iter()
            .find(|v| v.entry.id == "s1")
            .expect("s1");
        assert_eq!(s1.entry.reason.as_deref(), Some(VIEWER_LEFT));
        assert_eq!(s1.entry.end, Some(T0 + 2 * MIN));
        assert_eq!(s1.ending, None);
    }

    #[test]
    fn an_unknown_reason_ends_the_session_without_a_label() {
        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_ended("s1", "viewer_teleported", T0 + MIN);
        let e = j.last().expect("entry");
        assert_eq!(e.ending, None);
        assert_eq!(e.entry.reason.as_deref(), Some("viewer_teleported"));
    }

    #[test]
    fn the_device_is_named_by_the_telegram_platform() {
        assert_eq!(Device::of("ios"), Some(Device::Iphone));
        assert_eq!(Device::of("android"), Some(Device::Android));
        assert_eq!(Device::of("android_x"), Some(Device::Android));
        assert_eq!(Device::of("macos"), Some(Device::Mac));
        assert_eq!(Device::of("tdesktop"), Some(Device::Desktop));
        assert_eq!(Device::of("unigram"), Some(Device::Desktop));
        assert_eq!(Device::of("weba"), Some(Device::Browser));
        assert_eq!(Device::of("webk"), Some(Device::Browser));
        assert_eq!(Device::of("browser"), Some(Device::Browser));
        assert_eq!(Device::of("unknown"), None);
        assert_eq!(Device::of(""), None);

        // What a journal keeps of a peer's string.
        assert_eq!(clean_platform(" IOS "), Some("ios".to_string()));
        assert_eq!(clean_platform("tdesktop"), Some("tdesktop".to_string()));
        assert_eq!(clean_platform("<script>"), None);
        assert_eq!(clean_platform(&"x".repeat(PLATFORM_MAX + 1)), None);
    }

    #[test]
    fn a_platform_before_the_video_is_asked_again_and_kept_after() {
        let j = Journal::open(None, T0);
        assert!(!j.session_platform("s1", "android", T0), "not open yet");
        j.session_started(&start("s1", "Вера"), T0);
        assert!(j.session_platform("s1", "android", T0 + 1000));
        assert_eq!(j.last().and_then(|v| v.device), Some(Device::Android));
        // An unkeepable string is never asked for again.
        assert!(j.session_platform("s1", "{{bad}}", T0 + 2000));
    }

    #[test]
    fn weak_network_is_a_notable_share_of_weak_seconds() {
        assert!(
            weak_second(true, false, 1080, 30),
            "the picture stood still"
        );
        assert!(weak_second(false, false, 1080, 15), "15 fps or less");
        assert!(weak_second(false, false, 360, 30), "the ladder's 360p");
        assert!(
            !weak_second(false, true, 360, 30),
            "a 360p the viewer pinned"
        );
        assert!(!weak_second(false, false, 540, 30));
        assert!(!weak_second(false, false, 1080, 60));

        assert!(!is_weak(100, 9), "too few weak seconds");
        assert!(is_weak(50, 10));
        assert!(is_weak(100, 20), "one in five");
        assert!(!is_weak(101, 20));

        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        let sample = |weak, at| {
            j.session_second(
                "s1",
                Second {
                    weak,
                    game_only: false,
                },
                at,
            );
        };
        for s in 0..40 {
            sample(s < 12, T0 + s * 1000);
        }
        assert!(j.last().is_some_and(|v| v.entry.weak), "12 of 40 seconds");
        // A long good stretch after it: the share falls below a fifth and the label goes.
        for s in 40..100 {
            sample(false, T0 + s * 1000);
        }
        j.session_ended("s1", "viewer_ended", T0 + 100_000);
        assert!(j.last().is_some_and(|v| !v.entry.weak), "12 of 100 seconds");
    }

    #[test]
    fn game_only_is_noted_once_seen() {
        let j = Journal::open(None, T0);
        j.session_started(&start("s1", "Вера"), T0);
        j.session_second(
            "s1",
            Second {
                weak: false,
                game_only: true,
            },
            T0 + 1000,
        );
        j.session_second(
            "s1",
            Second {
                weak: false,
                game_only: false,
            },
            T0 + 2000,
        );
        j.session_ended("s1", "kill_switch", T0 + 3000);
        let e = j.last().expect("entry");
        assert!(e.entry.game_only);
        assert_eq!(e.ending, Some(Ending::Pc));
    }

    #[test]
    fn the_newest_entry_is_the_running_session_then_the_latest() {
        let j = Journal::open(None, T0);
        j.event(Kind::Granted, vera(), T0);
        assert_eq!(j.last().map(|v| v.entry.kind), Some(Kind::Granted));
        j.session_started(&start("s1", "Вера"), T0 + MIN);
        j.event(Kind::Paused, vera(), T0 + 2 * MIN);
        let last = j.last().expect("entry");
        assert!(last.live, "a running session leads");
        let kinds: Vec<(Kind, bool)> = j.entries().iter().map(|v| (v.entry.kind, v.live)).collect();
        assert_eq!(
            kinds,
            [
                (Kind::Session, true),
                (Kind::Paused, false),
                (Kind::Granted, false)
            ]
        );
        assert_eq!(
            j.known_name(5_000_000_001),
            Some(("Вера".to_string(), Some("vera".to_string())))
        );
        assert_eq!(j.known_name(1), None);
    }

    #[test]
    fn superseded_lines_are_compacted_while_running() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        j.session_started(&start("s1", "Вера"), T0);
        // A long session: one write a minute.
        for m in 1..=(COMPACT_SLACK as i64 + 20) {
            j.session_second(
                "s1",
                Second {
                    weak: false,
                    game_only: false,
                },
                T0 + m * MIN,
            );
        }
        // The next kept entry finds the pile and rewrites. Or a full writer's queue rewrote
        // the file first (the writes come faster than a test's disk), leaving at most a queue's
        // worth of lines after it; either way no pile is left.
        j.event(Kind::Paused, vera(), T0 + 400 * MIN);
        let lines = tmp.lines().len();
        assert!(lines <= 2 + QUEUE_MAX, "{lines} lines");
        drop(j);
        assert_eq!(
            tmp.open(T0 + 401 * MIN).entries().len(),
            2,
            "both entries kept"
        );
    }

    fn phone() -> TrustedDevice {
        TrustedDevice {
            kind: "telegram".into(),
            platform: "iphone".into(),
            source: "pair".into(),
        }
    }

    /// The trusted devices' kinds: the switch names nobody, a device leaving names its person and
    /// device; a malformed call writes nothing. They survive a reopen, and a line an older build
    /// wrote (no `trusted_device`) still loads beside them.
    #[test]
    fn trusted_devices_events_are_written_and_read_back() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.event(Kind::Granted, vera(), T0);
            j.trusted_event(Kind::TrustedOn, None, None, T0 + MIN);
            j.trusted_event(
                Kind::DeviceUntrusted,
                Some(vera()),
                Some(phone()),
                T0 + 2 * MIN,
            );
            j.trusted_event(Kind::TrustedOff, None, None, T0 + 3 * MIN);
            // Not as the kinds want them: nothing written.
            j.trusted_event(Kind::TrustedOn, Some(vera()), None, T0 + 4 * MIN);
            j.trusted_event(Kind::DeviceUntrusted, Some(vera()), None, T0 + 4 * MIN);
            j.trusted_event(Kind::DeviceUntrusted, None, Some(phone()), T0 + 4 * MIN);
            j.trusted_event(Kind::Granted, Some(vera()), None, T0 + 4 * MIN);
        }
        let lines = tmp.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].contains(r#""kind":"granted""#) && !lines[0].contains("trusted_device"));
        assert!(lines[1].contains(r#""kind":"trusted_on""#) && lines[1].contains(r#""user":0"#));
        assert!(lines[2].contains(
            r#""trusted_device":{"kind":"telegram","platform":"iphone","source":"pair"}"#
        ));
        let j = tmp.open(T0 + 5 * MIN);
        let entries: Vec<(Kind, i64, String, Option<TrustedDevice>)> = j
            .entries()
            .into_iter()
            .map(|v| {
                (
                    v.entry.kind,
                    v.entry.user,
                    v.entry.name,
                    v.entry.trusted_device,
                )
            })
            .collect();
        assert_eq!(
            entries,
            [
                (Kind::TrustedOff, 0, String::new(), None),
                (
                    Kind::DeviceUntrusted,
                    5_000_000_001,
                    "Вера".into(),
                    Some(phone())
                ),
                (Kind::TrustedOn, 0, String::new(), None),
                (Kind::Granted, 5_000_000_001, "Вера".into(), None),
            ]
        );
    }

    /// «Новое устройство» (`device_added`): a known guest's new device carries
    /// `guest_new_device` and the device that vouched for it; a new person's carries neither, so
    /// its line is as a build without them writes it. Both read back after a reopen, and the
    /// `Declined*` kinds need the person only.
    #[test]
    fn device_added_says_a_known_guests_new_device_and_who_vouched() {
        let tmp = TempJournal::new();
        let desktop = TrustedDevice {
            kind: "telegram_desktop".into(),
            platform: "mac".into(),
            source: "pair".into(),
        };
        {
            let j = tmp.open(T0);
            j.device_added(vera(), phone(), Some(desktop.clone()), true, T0);
            j.device_added(vera(), phone(), None, false, T0 + MIN);
            j.trusted_event(Kind::DeclinedNoKey, Some(vera()), None, T0 + 2 * MIN);
            j.trusted_event(Kind::DeclinedUnknown, None, None, T0 + 2 * MIN);
        }
        let lines = tmp.lines();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].contains(r#""kind":"device_added""#));
        assert!(lines[0].contains(r#""guest_new_device":true"#));
        assert!(lines[0].contains(
            r#""by_device":{"kind":"telegram_desktop","platform":"mac","source":"pair"}"#
        ));
        assert!(!lines[1].contains("guest_new_device") && !lines[1].contains("by_device"));
        assert!(lines[2].contains(r#""kind":"declined_no_key""#));
        let j = tmp.open(T0 + 3 * MIN);
        let entries: Vec<(Kind, bool, Option<TrustedDevice>)> = j
            .entries()
            .into_iter()
            .map(|v| (v.entry.kind, v.entry.guest_new_device, v.entry.by_device))
            .collect();
        assert_eq!(
            entries,
            [
                (Kind::DeclinedNoKey, false, None),
                (Kind::DeviceAdded, false, None),
                (Kind::DeviceAdded, true, Some(desktop)),
            ]
        );
    }

    /// «Попытка подключения с неизвестного устройства» (`other_device_attempt`): the person and
    /// no device — written as the other events are, read back after a reopen; without its person
    /// it is not written. A build that does not know the kind drops only that line (the file's
    /// rule for any line it cannot read).
    #[test]
    fn another_devices_attempt_names_the_person_only() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.trusted_event(Kind::OtherDeviceAttempt, Some(vera()), None, T0);
            j.trusted_event(Kind::OtherDeviceAttempt, None, None, T0 + MIN);
        }
        let lines = tmp.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(r#""kind":"other_device_attempt""#));
        assert!(!lines[0].contains("trusted_device"));
        let j = tmp.open(T0 + 2 * MIN);
        let entries: Vec<(Kind, i64, Option<TrustedDevice>)> = j
            .entries()
            .into_iter()
            .map(|v| (v.entry.kind, v.entry.user, v.entry.trusted_device))
            .collect();
        assert_eq!(entries, [(Kind::OtherDeviceAttempt, 5_000_000_001, None)]);
    }

    /// An attempt is written with its key and reason (the line only: the
    /// window's attempts live on the trusted list's notes, spec §10.2).
    #[test]
    fn attempts_are_written_with_their_key_and_reason() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.other_device_attempt(vera(), "old-key", "key_unknown", T0);
            j.trusted_event(Kind::OtherDeviceAttempt, Some(vera()), None, T0 + MIN);
            j.other_device_attempt(vera(), "k1", "recover_bad_sig", T0 + 2 * MIN);
        }
        let lines = tmp.lines();
        assert!(lines[2].contains(r#""attempt_key":"k1""#), "{lines:?}");
        assert!(lines[2].contains(r#""reason":"recover_bad_sig""#));
        assert!(!lines[1].contains("attempt_key"));
        assert!(lines[0].contains(r#""attempt_key":"old-key""#));
    }

    /// A refusal's reason (`declined`) is written and read back after a reopen; a refusal without
    /// one is today's line (no `reason`); a reason word this build does not know is kept and read;
    /// a kind that is not a refusal is not written.
    #[test]
    fn a_refusals_reason_round_trips() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.declined(Kind::DeclinedUnknown, vera(), Some("grant_stale"), T0);
            j.declined(Kind::DeclinedUnknown, vera(), None, T0 + MIN);
            j.declined(Kind::Granted, vera(), Some("grant_stale"), T0 + MIN);
        }
        let mut lines = tmp.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains(r#""reason":"grant_stale""#));
        assert!(!lines[1].contains("reason"), "{lines:?}");
        // A newer build's word, written into the file as that build would write it.
        let mut newer: serde_json::Value = serde_json::from_str(&lines[0]).expect("the line reads");
        newer["id"] = serde_json::json!("newer-line");
        newer["at"] = serde_json::json!(T0 + 2 * MIN);
        newer["reason"] = serde_json::json!("a_newer_reason");
        lines.push(newer.to_string());
        std::fs::write(&tmp.0, lines.join("\n") + "\n").expect("the file is written");
        let j = tmp.open(T0 + 3 * MIN);
        let entries: Vec<(Kind, Option<String>)> = j
            .entries()
            .into_iter()
            .map(|v| (v.entry.kind, v.entry.reason))
            .collect();
        assert_eq!(
            entries,
            [
                (Kind::DeclinedUnknown, Some("a_newer_reason".into())),
                (Kind::DeclinedUnknown, None),
                (Kind::DeclinedUnknown, Some("grant_stale".into())),
            ]
        );
    }

    fn person_event(kind: Kind, user: i64, name: &str) -> PersonEvent {
        PersonEvent {
            kind,
            user,
            name: name.to_string(),
            username: None,
        }
    }

    /// A batch whose file write the disk holds does not hold the
    /// next journal call, nor `known_name` — the journal's lock is never held across the disk.
    #[test]
    fn a_slow_disk_never_holds_the_next_journal_call() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        let gate = j.hold_file_writes();
        let batch = vec![person_event(Kind::Revoked, 7, "Old")];
        let j = &j;
        std::thread::scope(|scope| {
            scope.spawn(|| j.events(&batch, T0));
            assert!(
                gate.wait_entered(1, std::time::Duration::from_secs(5)),
                "the batch's write reached the disk"
            );
            let (tx, rx) = std::sync::mpsc::channel();
            scope.spawn(move || {
                j.event(
                    Kind::Granted,
                    Person {
                        user: 7,
                        name: "New",
                        username: None,
                    },
                    T0 + 1,
                );
                let _ = tx.send(j.known_name(7));
            });
            let got = rx.recv_timeout(std::time::Duration::from_secs(2));
            gate.release();
            assert_eq!(
                got.ok().flatten().map(|(name, _)| name).as_deref(),
                Some("New"),
                "the next call and known_name went on while the disk held the batch"
            );
        });
    }

    /// A batch, then a single event — on disk in that order, and the newest name wins
    /// after a reopen.
    #[test]
    fn the_file_holds_the_calls_in_their_order() {
        let tmp = TempJournal::new();
        {
            let j = tmp.open(T0);
            j.slow_file_writes(std::time::Duration::from_millis(50));
            j.events(&[person_event(Kind::Revoked, 7, "Old")], T0);
            j.event(
                Kind::Granted,
                Person {
                    user: 7,
                    name: "New",
                    username: None,
                },
                T0 + 1,
            );
            assert_eq!(j.known_name(7).map(|(n, _)| n).as_deref(), Some("New"));
        }
        let lines = tmp.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains(r#""name":"Old""#), "{lines:?}");
        assert!(lines[1].contains(r#""name":"New""#), "{lines:?}");
        let again = tmp.open(T0 + MIN);
        assert_eq!(again.known_name(7).map(|(n, _)| n).as_deref(), Some("New"));
    }

    /// What is queued when the journal goes is written before its drop returns (a slow
    /// disk, within [`DRAIN_LIMIT`]).
    #[test]
    fn a_drop_drains_what_is_queued_within_the_bound() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        j.slow_file_writes(std::time::Duration::from_millis(100));
        for i in 0..5 {
            j.event(Kind::Granted, vera(), T0 + i);
        }
        let started = std::time::Instant::now();
        drop(j);
        let took = started.elapsed();
        // Read right after the drop, not through `TempJournal::lines` (which waits for the
        // writer itself): the drop's own wait put the lines on disk.
        let on_disk = std::fs::read_to_string(&tmp.0).unwrap_or_default();
        assert!(took < DRAIN_LIMIT, "the drop took {took:?}");
        assert_eq!(
            on_disk.lines().count(),
            5,
            "every queued line is on disk when the drop returns"
        );
    }

    /// Dropped on the async runtime the journal does not wait for
    /// the writer (a worker must not block) — the drop returns at once though the disk holds the
    /// write — and the writer finishes what is queued alone once the disk answers.
    #[test]
    fn a_drop_on_the_runtime_does_not_wait_and_the_writer_finishes_alone() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        assert!(j.drain(DRAIN_LIMIT), "the start's rewrite is done");
        let gate = j.hold_file_writes();
        j.event(Kind::Granted, vera(), T0);
        j.event(Kind::Revoked, vera(), T0 + 1);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let took = runtime.block_on(async move {
            let started = std::time::Instant::now();
            drop(j);
            started.elapsed()
        });
        assert!(
            took < std::time::Duration::from_millis(500),
            "the drop on the runtime waited {took:?}"
        );
        gate.release();
        assert_eq!(tmp.lines().len(), 2, "the writer finished alone");
    }

    /// A writer that panics inside a write leaves work queued.
    /// The lost write counts as failed (`write_failed`), and a drain does not wait out its whole
    /// bound for a thread that is gone: it starts a new writer, which writes what is queued — the
    /// drain returns `true` well within the bound and the file is written again.
    #[test]
    fn a_writer_panic_is_seen_by_the_drain_which_starts_a_new_writer() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        assert!(j.drain(DRAIN_LIMIT), "the start's rewrite is done");
        let gate = j.hold_file_writes();
        j.event(Kind::Granted, vera(), T0);
        assert!(
            gate.wait_entered(1, std::time::Duration::from_secs(5)),
            "the first write is at the disk"
        );
        j.event(Kind::Revoked, vera(), T0 + 1);
        j.event(Kind::Granted, vera(), T0 + 2);
        assert_eq!(j.queued(), 2, "two waiting behind the held write");
        j.panic_in_the_held_write();
        gate.release();
        let waited = std::time::Instant::now();
        while j.writer_running() {
            assert!(
                waited.elapsed() < std::time::Duration::from_secs(5),
                "the writer did not end"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            j.write_failed(),
            "the write lost to the panic counts as failed"
        );
        assert_eq!(j.queued(), 2, "the queued work is left");
        let started = std::time::Instant::now();
        let drained = j.drain(DRAIN_LIMIT);
        let took = started.elapsed();
        assert!(
            drained,
            "the drain saw the dead writer and a new one wrote the queue"
        );
        assert!(
            took < DRAIN_LIMIT / 2,
            "the drain waited {took:?} for a writer that was gone"
        );
        assert!(!j.write_failed(), "the file is written again");
        drop(j);
        let lines = tmp.lines();
        assert_eq!(lines.len(), 2, "the two queued lines on disk: {lines:?}");
    }

    /// A drain ALREADY WAITING when the writer panics returns as soon as the
    /// thread is gone — its wait ends on "no thread runs" ([`Writer::drain`]'s predicate), not
    /// at its bound — and says `false` (queued work, no thread for it). The work stays queued for
    /// the next drain or entry, which starts a new writer.
    #[test]
    fn a_drain_waiting_when_the_writer_panics_returns_at_once() {
        let tmp = TempJournal::new();
        let j = std::sync::Arc::new(tmp.open(T0));
        assert!(j.drain(DRAIN_LIMIT), "the start's rewrite is done");
        let gate = j.hold_file_writes();
        j.event(Kind::Granted, vera(), T0);
        assert!(
            gate.wait_entered(1, std::time::Duration::from_secs(5)),
            "the first write is at the disk"
        );
        j.event(Kind::Revoked, vera(), T0 + 1);
        assert_eq!(j.queued(), 1, "one waiting behind the held write");
        j.panic_in_the_held_write();
        let limit = std::time::Duration::from_secs(8);
        let drainer = {
            let j = std::sync::Arc::clone(&j);
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                let drained = j.drain(limit);
                (drained, started.elapsed())
            })
        };
        // The drain is waiting (the write is held), then the write panics.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!drainer.is_finished(), "the drain waits for the held write");
        gate.release();
        let (drained, took) = drainer.join().expect("the drain's thread");
        assert!(
            took < limit / 2,
            "the drain waited {took:?} for a writer that was gone"
        );
        assert!(!drained, "queued work with no thread for it: not drained");
        assert!(
            j.write_failed(),
            "the write lost to the panic counts as failed"
        );
        assert_eq!(j.queued(), 1, "the queued work is left");
        assert!(j.drain(DRAIN_LIMIT), "the next drain starts a new writer");
        let j = std::sync::Arc::try_unwrap(j).expect("one journal");
        drop(j);
        assert_eq!(tmp.lines().len(), 1, "the queued line on disk");
    }

    /// The journal is closed (its drop) and the writer panics
    /// inside the write the drop waits for, with work still queued: the wait for its end does
    /// not say "finished" — the queued work is not written (no later entry starts a writer).
    #[test]
    fn a_writer_panic_after_the_close_is_not_a_finished_writer() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        assert!(j.drain(DRAIN_LIMIT), "the start's rewrite is done");
        let gate = j.hold_file_writes();
        j.event(Kind::Granted, vera(), T0);
        assert!(
            gate.wait_entered(1, std::time::Duration::from_secs(5)),
            "the first write is at the disk"
        );
        j.event(Kind::Revoked, vera(), T0 + 1);
        assert_eq!(j.queued(), 1, "one waiting behind the held write");
        j.panic_in_the_held_write();
        let writer = j.writer().expect("a writer");
        writer.close();
        let waiter = {
            let writer = Arc::clone(&writer);
            std::thread::spawn(move || writer.wait_ended(std::time::Duration::from_secs(8)))
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        gate.release();
        let ended = waiter.join().expect("the wait's thread");
        assert!(
            !ended,
            "the writer ended with work queued and unwritten: not a finished writer"
        );
        assert_eq!(j.queued(), 1, "the queued work is left");
        drop(j);
    }

    /// A disk that does not answer holds neither the calls nor the drop past
    /// [`DRAIN_LIMIT`]; the entries stay in memory until then.
    #[test]
    fn a_drop_on_a_disk_that_does_not_answer_returns_within_the_bound() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        let gate = j.hold_file_writes();
        let started = std::time::Instant::now();
        j.event(Kind::Granted, vera(), T0);
        j.event(Kind::Revoked, vera(), T0 + 1);
        assert_eq!(j.entries().len(), 2, "kept in memory");
        drop(j);
        let took = started.elapsed();
        gate.release();
        assert!(
            took < DRAIN_LIMIT + std::time::Duration::from_secs(1),
            "the calls and the drop took {took:?}"
        );
    }

    /// While the disk holds a write, the work waiting for the writer never passes
    /// [`QUEUE_MAX`] (the waiting work becomes one rewrite of the journal as memory has it), no
    /// call waits, and every entry reaches the file once the disk answers.
    #[test]
    fn the_writers_queue_stays_bounded_while_the_disk_is_held() {
        let tmp = TempJournal::new();
        let j = tmp.open(T0);
        let gate = j.hold_file_writes();
        j.event(Kind::Granted, vera(), T0);
        assert!(
            gate.wait_entered(1, std::time::Duration::from_secs(5)),
            "the first write is at the disk"
        );
        let started = std::time::Instant::now();
        let mut most = 0;
        for i in 1..300 {
            j.event(Kind::Granted, vera(), T0 + i);
            most = most.max(j.queued());
        }
        let took = started.elapsed();
        gate.release();
        assert!(most <= QUEUE_MAX, "{most} waiting");
        assert!(
            took < std::time::Duration::from_secs(5),
            "300 calls took {took:?} on a held disk"
        );
        assert_eq!(j.entries().len(), 300, "kept in memory");
        let lines = tmp.lines().len();
        assert!(lines <= 300 + QUEUE_MAX, "{lines} lines");
        assert!(
            j.file_writes() < 300,
            "{} file writes for 300 events",
            j.file_writes()
        );
        drop(j);
        assert_eq!(tmp.open(T0 + MIN).entries().len(), 300, "all on disk");
    }
}
