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
//! window's commands and from the app's way out. Everything is behind one lock and quick: a write
//! is one short append, rare by construction.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
}

impl Kind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Granted => "granted",
            Self::Invited => "invited",
            Self::Revoked => "revoked",
            Self::Paused => "paused",
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
    /// backend passed it on), or [`APP_CLOSED`].
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
    /// Lines in the file, superseded ones included, as far as this process knows.
    lines: usize,
    /// The last write failed (said once at `warn`; the next one that works says so at `info`).
    write_failed: bool,
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
        let entry = Entry {
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
        };
        tracing::debug!(
            kind = kind.as_str(),
            user = person.user,
            name = %entry.name,
            at = now_ms,
            "connection journal: an event written"
        );
        let mut inner = lock(&self.inner);
        inner.append(&entry);
        inner.push_done(entry, now_ms);
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

    /// Append one line.
    fn append(&mut self, entry: &Entry) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let line = match serde_json::to_string(entry) {
            Ok(line) => line,
            Err(e) => {
                tracing::warn!(id = %entry.id, "connection journal: an entry not serialized: {e}");
                return;
            }
        };
        let written = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(format!("{line}\n").as_bytes()));
        match written {
            Ok(()) => {
                self.lines += 1;
                self.note_write_ok();
            }
            Err(e) => self.note_write_failed(&format!("append to {}: {e}", path.display())),
        }
    }

    /// Write every entry kept to a new file and put it in the old one's place.
    fn rewrite(&mut self, why: &str) {
        let Some(path) = self.path.clone() else {
            return;
        };
        let mut text = String::new();
        let mut count = 0usize;
        for entry in self.done.iter().chain(self.live.iter().map(|l| &l.entry)) {
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
        let mut tmp = path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let result =
            std::fs::write(&tmp, text.as_bytes()).and_then(|()| std::fs::rename(&tmp, &path));
        match result {
            Ok(()) => {
                tracing::debug!(
                    file = %path.display(),
                    why,
                    lines_before = self.lines,
                    lines = count,
                    "connection journal: the file rewritten"
                );
                self.lines = count;
                self.note_write_ok();
            }
            Err(e) => {
                if let Err(e) = std::fs::remove_file(&tmp) {
                    tracing::trace!("connection journal: no temporary file to remove: {e}");
                }
                self.note_write_failed(&format!("rewrite {}: {e}", path.display()));
            }
        }
    }

    fn note_write_ok(&mut self) {
        if std::mem::replace(&mut self.write_failed, false) {
            tracing::info!("connection journal: the file is written again");
        }
    }

    fn note_write_failed(&mut self, what: &str) {
        if std::mem::replace(&mut self.write_failed, true) {
            tracing::debug!("connection journal: still not written ({what}); kept in memory");
        } else {
            tracing::warn!(
                "connection journal: not written ({what}); kept in memory until a write works"
            );
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A journal file of its own under the temp dir, removed on drop.
    struct TempJournal(PathBuf);

    impl TempJournal {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("afklink-journal-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir.join(FILE_NAME))
        }

        fn open(&self, now_ms: i64) -> Journal {
            Journal::open(Some(self.0.clone()), now_ms)
        }

        fn lines(&self) -> Vec<String> {
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
        // The next kept entry finds the pile and rewrites.
        j.event(Kind::Paused, vera(), T0 + 400 * MIN);
        assert!(tmp.lines().len() <= 2, "{} lines", tmp.lines().len());
    }
}
