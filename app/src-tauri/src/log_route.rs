//! Which file a line goes to: the system log, or the file of the session it belongs to.
//!
//! Not daily logs: each session has its file, and the rest (updates, the driver and so on) goes to
//! one system log. Names on disk and retention: `log_retention`. The queue and the writer thread:
//! `log_file`.
//!
//! # The rule
//!
//! A line is sorted when it is written ([`FileWriter`]):
//!
//! 1. **A system event**, a target in [`SYSTEM_TARGETS`], goes to the system log, always. While a
//!    session is live a copy goes to its file too: an update check or a driver install during a
//!    session is part of what happened to it, and its file reads whole on its own.
//! 2. **A line that names a session** (its full id anywhere in the line) goes to that session's
//!    file only, while it is open. With two sessions live, each one's own lines stay apart. A line
//!    naming a session with no file (refused before it was accepted, or already closed) falls to
//!    rule 3.
//! 3. **Any other line** goes to the file of every session that takes such lines now (live, or in
//!    its teardown), and with none, to the system log. So startup, config, the tray and signaling
//!    land in the system log outside sessions and in the session's file during one.
//!
//! A session's file follows its life as the agent reports it (`afklink_core::SessionLog`): opened
//! when the request is accepted, live, a [`TEARDOWN`], a tail of its own lines until telemetry
//! stops (at most [`TAIL_MAX`]), then closed with a footer. The stages are on [`Scope`]. The system
//! log records each file opened and closed, so it is their index.
//!
//! # Two sessions at once
//!
//! A line that names no session (the `pipeline` line, the encoder's, the capture's) cannot be told
//! apart, so it is written to **each** file that takes such lines rather than guessed into one: a
//! wrong guess would silently mix one session's lines into the other's file, while a copy only
//! costs bytes. Each file marks where the overlap starts and ends («another session is live
//! alongside», `alongside=` in the newcomer's header, a line when the other ends). Lines that name
//! their session are never copied.
//!
//! # What it costs a logging thread
//!
//! One lock and, while a session is open, a scan of the line for each open session's id (36 bytes
//! in a line of a few hundred), and a copy into the queue. No disk: the writer thread does that.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, TryLockError, Weak};
use std::time::{Duration, Instant};

use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

use crate::log_file::{
    self, notice, report_line, CloseSession, Dest, Footer, LostLines, Msg, OpenSession, Queue,
    WriterSettings, SYSTEM,
};
use crate::log_retention::{
    session_file_name, short_id, LocalTime, RetentionRules, SESSIONS_DIR, SYSTEM_LOG,
    SYSTEM_MAX_BYTES, SYSTEM_ROTATIONS,
};

/// The target of the system events logged from `lib.rs`: settings changes, the app's exit, panics.
pub(crate) const SYSTEM_TARGET: &str = "afklink_app_lib::system";

/// The system events, by target (and every module under one): the system log always, and a copy to
/// a live session's file.
pub(crate) const SYSTEM_TARGETS: [&str; 13] = [
    SYSTEM_TARGET,
    // What Windows said about the session and the power state (shutdown, sleep, resume), and the
    // goodbye to the backend each called for: how a PC left the list is read in one place.
    "afklink_app_lib::system_events",
    "afklink_core::goodbye",
    // Which way to the server — the configured address or the RU entry — and every path failure,
    // switch and record behind it: one story across starts, whatever session was live.
    "afklink_core::entry",
    // Update checks, downloads, the swap, the health report and the watchdog's launch.
    "afklink_app_lib::updater",
    // The input driver's install, repair and removal, and its Windows Installer log.
    "afklink_app_lib::fakerinput_setup",
    // The game helper: its setup, its signal's every change, and its own log mirrored line by line
    // (`::helper`) — so a session's file has what the helper decided during it.
    "afklink_app_lib::game_helper",
    // The driver's and the update's staged files.
    "afklink_app_lib::staged_file",
    "afklink_app_lib::autostart",
    // «Отправить логи».
    "afklink_app_lib::diagnostics",
    "afklink_app_lib::toast_identity",
    "afklink_app_lib::webview_runtime",
    // The beacon sent on the way out when the app cannot start.
    "afklink_app_lib::start_failure",
];

/// Whether a line of `target` is a system event ([`SYSTEM_TARGETS`]).
pub(crate) fn is_system_target(target: &str) -> bool {
    SYSTEM_TARGETS.iter().any(|system| {
        target
            .strip_prefix(system)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
    })
}

/// How long after its end a session's file still takes the lines that name no session: its
/// teardown's lines come within about a second of the end (measured: the last, the tray's, 310 ms
/// after it; `heartbeat stopped` ticks once a second).
pub(crate) const TEARDOWN: Duration = Duration::from_secs(3);

/// The longest a session's file waits after the end for its telemetry task to stop: twice the
/// interval it looks at (`TELEMETRY_INTERVAL_MS`, 15 s), so a busy runtime does not cut its line off.
pub(crate) const TAIL_MAX: Duration =
    Duration::from_millis(2 * afklink_protocol::TELEMETRY_INTERVAL_MS);

/// How often the retention rules run besides at the start and after each session's file closes.
const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// How long closing the files on the way out waits for the router's lock before giving up — it runs
/// in the panic hook, where waiting without end is how a crash becomes a hang.
const LOCK_PATIENCE: Duration = Duration::from_millis(200);

/// The router's numbers: [`RouteSettings::APP`] in the app, smaller in tests.
#[derive(Debug, Clone)]
pub(crate) struct RouteSettings {
    pub(crate) queue_lines: usize,
    pub(crate) teardown: Duration,
    pub(crate) tail_max: Duration,
    pub(crate) system_max_bytes: u64,
    pub(crate) system_rotations: u32,
    pub(crate) retention: RetentionRules,
    /// Run [`LogFiles::tick`] once a second on a thread of its own. Off in tests, which tick by hand
    /// with the times they choose.
    pub(crate) housekeeping: bool,
}

impl RouteSettings {
    pub(crate) const APP: Self = Self {
        queue_lines: log_file::QUEUE_LINES,
        teardown: TEARDOWN,
        tail_max: TAIL_MAX,
        system_max_bytes: SYSTEM_MAX_BYTES,
        system_rotations: SYSTEM_ROTATIONS,
        retention: RetentionRules::DEFAULT,
        housekeeping: true,
    };
}

/// The app's log files: the system log and a file per session, with the rule that sorts lines
/// between them. One per process; `lib.rs` keeps it.
pub(crate) struct LogFiles {
    state: Mutex<State>,
    /// Held while the files are being opened: the disk is touched outside `state`'s lock, so a
    /// logging thread never waits on it, and two openers cannot both start a writer.
    opening: Mutex<()>,
    settings: RouteSettings,
    /// The build's label, for a session file's header.
    build: String,
}

struct State {
    /// The writer thread's queue, once the files are open.
    queue: Option<Queue>,
    /// The level is not `off`: a session gets a file, a closing file a last line.
    on: bool,
    /// The level in effect, as a session file's header states it.
    level: String,
    system_lost: LostLines,
    /// Sessions with a file (or one to have when the log is on), oldest first.
    scopes: Vec<Scope>,
    next_dest: Dest,
    /// Closed on the way out: nothing opens again, nothing more is written.
    shut: bool,
    last_sweep: Option<Instant>,
}

/// A session, as far as its file is concerned. Its file, from first line to last:
///
/// - **Opened** when its request is accepted, just before the request's own line; the header names
///   the session, the viewer's Telegram id (as the log has it already), the build, the log level
///   and any session live alongside.
/// - **Live** until the session ends.
/// - **Teardown**, [`TEARDOWN`] after the end: the lines that follow an end name no session
///   (`encode loop finished`, `WGC capture stopped`, `heartbeat stopped`, the tray back to idle),
///   so for these seconds every line without a session still comes here.
/// - **Tail**: then only its own lines, until its telemetry task, the last to notice the end,
///   reports `telemetry stopped`, and at most [`TAIL_MAX`] after the end. A session that ended
///   before it started (a failed setup, a request the viewer gave up on) has no telemetry task and
///   closes after the teardown.
/// - **Closed** with a footer that says why (`finished`, `tail_timeout`, `not_started`, or the
///   process's end: `app_exit`, `panic`, …), how many lines it holds and how many it lost.
struct Scope {
    id: String,
    dest: Dest,
    telegram_user_id: i64,
    /// The file's name in `sessions\`.
    name: String,
    requested: LocalTime,
    opened_at: Instant,
    started: bool,
    /// When it ended, and why.
    ended: Option<(Instant, String)>,
    finished_at: Option<Instant>,
    lost: LostLines,
    /// Its file was asked for (the writer opens it, or falls back to the system log).
    file: bool,
}

impl Scope {
    /// Whether it takes the lines that name no session at `now`: live, or in its teardown.
    fn takes_untagged(&self, now: Instant, settings: &RouteSettings) -> bool {
        match &self.ended {
            None => true,
            Some((at, _)) => at
                .checked_add(settings.teardown)
                .is_none_or(|end| now < end),
        }
    }

    /// When its file closes: after the teardown, and after its last task stopped — or [`TAIL_MAX`]
    /// after the end when that never comes; right after the teardown when it never started. `None`
    /// while it has not ended.
    fn closes_at(&self, settings: &RouteSettings) -> Option<Instant> {
        let (ended, _) = self.ended.as_ref()?;
        let teardown_end = ended.checked_add(settings.teardown)?;
        match (self.finished_at, self.started) {
            (Some(finished), _) => Some(finished.max(teardown_end)),
            (None, true) => ended.checked_add(settings.tail_max),
            (None, false) => Some(teardown_end),
        }
    }

    fn over(&self, now: Instant, settings: &RouteSettings) -> bool {
        self.closes_at(settings).is_some_and(|at| now >= at)
    }

    /// Why it closes when it is over.
    fn why_closed(&self) -> &'static str {
        if self.finished_at.is_some() {
            "finished"
        } else if self.started {
            "tail_timeout"
        } else {
            "not_started"
        }
    }
}

fn contains(line: &[u8], id: &[u8]) -> bool {
    !id.is_empty() && line.windows(id.len()).any(|w| w == id)
}

fn alongside_text(ids: &[String]) -> String {
    if ids.is_empty() {
        "-".to_string()
    } else {
        ids.join(",")
    }
}

/// Ask the writer to close `scope`'s file, with its last line unless the log is off. `false` when
/// the writer thread is gone (and the file with it).
fn close(queue: Option<&Queue>, on: bool, scope: Scope, why: &'static str, now: Instant) -> bool {
    let Some(queue) = queue.filter(|_| scope.file) else {
        return true;
    };
    let footer = on.then(|| Footer {
        why,
        end_reason: scope.ended.map(|(_, reason)| reason),
        open_for: now.saturating_duration_since(scope.opened_at),
        session_id: scope.id,
    });
    queue.command(Msg::Close(CloseSession {
        dest: scope.dest,
        footer,
    }))
}

/// What a hook found, to be logged once the lock is let go: a `tracing` line under it would come
/// back into this router and wait for the lock it holds.
enum Outcome {
    Nothing,
    Opened { file: bool, alongside: Vec<String> },
    AlreadyOpen,
    Ended { started: bool },
    EndedAgain,
    Unknown,
    WriterGone,
}

impl LogFiles {
    pub(crate) fn new(build: String, settings: RouteSettings) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                queue: None,
                on: false,
                level: "-".to_string(),
                system_lost: LostLines::default(),
                scopes: Vec::new(),
                next_dest: SYSTEM + 1,
                shut: false,
                last_sweep: None,
            }),
            opening: Mutex::new(()),
            settings,
            build,
        })
    }

    /// The subscriber's writer for the file layer.
    pub(crate) fn writer(self: &Arc<Self>) -> FileWriter {
        FileWriter(Arc::clone(self))
    }

    /// The level in effect (`level`, as a header states it), and whether it writes at all. Off, no
    /// session gets a file and no file a last line; back on, the live sessions' files are opened.
    pub(crate) fn set_level(&self, level: String, on: bool) {
        let opened = {
            let mut guard = afklink_core::lock(&self.state);
            let st = &mut *guard;
            st.level = level;
            st.on = on;
            if on {
                self.open_files(st, Instant::now(), "log_switched_on")
            } else {
                0
            }
        };
        if opened > 0 {
            tracing::debug!(
                opened,
                "session log: the log is on; the files of the sessions live now are opened"
            );
        }
    }

    /// Open the system log in `dir` and start the writer thread, unless they are running already:
    /// `Ok(Some(dir))` when this call opened them. The files of the sessions already open follow
    /// when the log is on, and the retention rules run once.
    pub(crate) fn open(self: &Arc<Self>, dir: &Path) -> Result<Option<PathBuf>, String> {
        let _opening = afklink_core::lock(&self.opening);
        let system_lost = {
            let st = afklink_core::lock(&self.state);
            if st.shut {
                return Err("the log files are closed: the app is on its way out".to_string());
            }
            if st.queue.is_some() {
                return Ok(None);
            }
            st.system_lost.clone()
        };
        let queue = log_file::start_writer(
            WriterSettings {
                dir: dir.to_path_buf(),
                system_max_bytes: self.settings.system_max_bytes,
                system_rotations: self.settings.system_rotations,
                retention: self.settings.retention,
                queue_lines: self.settings.queue_lines,
            },
            system_lost,
        )
        .map_err(|e| format!("open {}: {e}", dir.join(SYSTEM_LOG).display()))?;
        let (opened, swept) = {
            let mut guard = afklink_core::lock(&self.state);
            let st = &mut *guard;
            if st.shut {
                // Closed while this was opening: the writer ends when its queue drops.
                return Err("the log files are closed: the app is on its way out".to_string());
            }
            let swept = queue.command(Msg::Sweep);
            st.last_sweep = Some(Instant::now());
            st.queue = Some(queue);
            let opened = if st.on {
                self.open_files(st, Instant::now(), "log_switched_on")
            } else {
                0
            };
            (opened, swept)
        };
        if !swept {
            tracing::warn!("log files: the writer thread ended as it started; nothing is written");
        }
        if opened > 0 {
            tracing::debug!(
                opened,
                "session log: the files of the sessions live now are opened"
            );
        }
        if self.settings.housekeeping {
            spawn_housekeeping(Arc::downgrade(self));
        }
        Ok(Some(dir.to_path_buf()))
    }

    /// Ask for the files of the sessions that have none yet; how many were asked for. Under the
    /// state's lock.
    fn open_files(&self, st: &mut State, now: Instant, opened_on: &str) -> usize {
        let Some(queue) = st.queue.as_ref() else {
            return 0;
        };
        let mut asked = Vec::new();
        for (i, scope) in st.scopes.iter().enumerate().filter(|(_, s)| !s.file) {
            let alongside: Vec<String> = st
                .scopes
                .iter()
                .filter(|o| o.id != scope.id && o.takes_untagged(now, &self.settings))
                .map(|o| short_id(&o.id))
                .collect();
            if queue.command(self.open_msg(scope, &st.level, &alongside, opened_on)) {
                asked.push(i);
            }
        }
        for i in &asked {
            if let Some(scope) = st.scopes.get_mut(*i) {
                scope.file = true;
            }
        }
        asked.len()
    }

    /// The writer's order to open `scope`'s file, with its header.
    fn open_msg(&self, scope: &Scope, level: &str, alongside: &[String], opened_on: &str) -> Msg {
        let header = format!(
            "session log opened session={} telegram_user_id={} build={:?} log_level={level:?} \
             pid={} requested={:?} file={:?} alongside={} opened_on={opened_on}",
            scope.id,
            scope.telegram_user_id,
            self.build,
            std::process::id(),
            scope.requested.display(),
            scope.name,
            alongside_text(alongside),
        );
        Msg::Open(OpenSession {
            dest: scope.dest,
            name: scope.name.clone(),
            header: notice(Level::INFO, log_file::TARGET, &header),
            about: format!(
                "session={} telegram_user_id={} alongside={}",
                scope.id,
                scope.telegram_user_id,
                alongside_text(alongside)
            ),
            lost: scope.lost.clone(),
        })
    }

    /// Sort one formatted line to its file(s) and queue it there (the module's rule). Nothing when no
    /// file is open: the level is off, or the files could not be opened.
    pub(crate) fn route_line(&self, line: &[u8], system_target: bool, now: Instant) {
        let guard = afklink_core::lock(&self.state);
        let st = &*guard;
        let Some(queue) = st.queue.as_ref() else {
            return;
        };
        if st.scopes.is_empty() {
            queue.line(SYSTEM, line, &st.system_lost);
            return;
        }
        let settings = &self.settings;
        if system_target {
            queue.line(SYSTEM, line, &st.system_lost);
            for scope in st
                .scopes
                .iter()
                .filter(|s| s.file && s.takes_untagged(now, settings))
            {
                queue.line(scope.dest, line, &scope.lost);
            }
            return;
        }
        let mut named = false;
        for scope in st
            .scopes
            .iter()
            .filter(|s| s.file && !s.over(now, settings) && contains(line, s.id.as_bytes()))
        {
            queue.line(scope.dest, line, &scope.lost);
            named = true;
        }
        if named {
            return;
        }
        let mut taken = false;
        for scope in st
            .scopes
            .iter()
            .filter(|s| s.file && s.takes_untagged(now, settings))
        {
            queue.line(scope.dest, line, &scope.lost);
            taken = true;
        }
        if !taken {
            queue.line(SYSTEM, line, &st.system_lost);
        }
    }

    /// A session request was accepted at `now` (`requested`, on the PC's clock): its lines are its
    /// own from here (`afklink_core::SessionLog::opened`).
    pub(crate) fn opened_at(
        &self,
        session_id: &str,
        telegram_user_id: i64,
        now: Instant,
        requested: LocalTime,
    ) {
        if session_id.is_empty() {
            tracing::warn!(
                telegram_user_id,
                "session log: a session with an empty id; its lines stay in the system log"
            );
            return;
        }
        let name = session_file_name(requested, session_id);
        let outcome = {
            let mut guard = afklink_core::lock(&self.state);
            let st = &mut *guard;
            if st.shut {
                Outcome::Nothing
            } else if st.scopes.iter().any(|s| s.id == session_id) {
                Outcome::AlreadyOpen
            } else {
                let dest = st.next_dest;
                st.next_dest = st.next_dest.saturating_add(1);
                let alongside: Vec<String> = st
                    .scopes
                    .iter()
                    .filter(|s| s.takes_untagged(now, &self.settings))
                    .map(|s| short_id(&s.id))
                    .collect();
                let mut scope = Scope {
                    id: session_id.to_string(),
                    dest,
                    telegram_user_id,
                    name: name.clone(),
                    requested,
                    opened_at: now,
                    started: false,
                    ended: None,
                    finished_at: None,
                    lost: LostLines::default(),
                    file: false,
                };
                if let Some(queue) = st.queue.as_ref() {
                    let marker = notice(
                        Level::INFO,
                        log_file::TARGET,
                        &format!(
                            "session log: another session is live alongside this one, {} \
                             (session={session_id}); until it ends, lines that name no session \
                             are written to both files",
                            short_id(session_id)
                        ),
                    );
                    for other in st
                        .scopes
                        .iter()
                        .filter(|s| s.file && s.takes_untagged(now, &self.settings))
                    {
                        queue.line(other.dest, &marker, &other.lost);
                    }
                    if st.on {
                        scope.file = queue.command(self.open_msg(
                            &scope,
                            &st.level,
                            &alongside,
                            // Not `session_request`: `ladder_replay` splits a log at that word.
                            "request_accepted",
                        ));
                    }
                }
                let file = scope.file;
                st.scopes.push(scope);
                Outcome::Opened { file, alongside }
            }
        };
        match outcome {
            Outcome::Opened { file, alongside } => tracing::debug!(
                session = %session_id,
                telegram_user_id,
                file = %format!("{SESSIONS_DIR}\\{name}"),
                file_open = file,
                alongside = %alongside_text(&alongside),
                "session log: this session's lines go to its own file from here"
            ),
            Outcome::AlreadyOpen => tracing::debug!(
                session = %session_id,
                "session log: a second request for a session that has its file; it keeps it"
            ),
            _ => {}
        }
    }

    /// The session's capture, encoder and peer are running (`afklink_core::SessionLog::started`).
    pub(crate) fn started_at(&self, session_id: &str) {
        let known = {
            let mut guard = afklink_core::lock(&self.state);
            match guard.scopes.iter_mut().find(|s| s.id == session_id) {
                Some(scope) => {
                    scope.started = true;
                    true
                }
                None => false,
            }
        };
        if !known {
            tracing::trace!(session = %session_id, "session log: a start for a session with no file");
        }
    }

    /// The session ended at `now` (`afklink_core::SessionLog::ended`): its teardown follows, then its
    /// tail.
    pub(crate) fn ended_at(&self, session_id: &str, reason: &str, now: Instant) {
        let outcome = {
            let mut guard = afklink_core::lock(&self.state);
            let st = &mut *guard;
            let first = st
                .scopes
                .iter_mut()
                .find(|s| s.id == session_id)
                .map(|scope| match scope.ended {
                    None => {
                        scope.ended = Some((now, reason.to_string()));
                        Some(scope.started)
                    }
                    Some(_) => None,
                });
            match first {
                None => Outcome::Unknown,
                Some(None) => Outcome::EndedAgain,
                Some(Some(started)) => {
                    if let Some(queue) = st.queue.as_ref() {
                        let marker = notice(
                            Level::INFO,
                            log_file::TARGET,
                            &format!(
                                "session log: the session alongside, {}, ended ({reason}); after \
                                 its teardown ({} s) lines that name no session are this \
                                 session's alone again",
                                short_id(session_id),
                                self.settings.teardown.as_secs()
                            ),
                        );
                        for other in st.scopes.iter().filter(|s| {
                            s.id != session_id && s.file && s.takes_untagged(now, &self.settings)
                        }) {
                            queue.line(other.dest, &marker, &other.lost);
                        }
                    }
                    Outcome::Ended { started }
                }
            }
        };
        match outcome {
            Outcome::Ended { started } => tracing::debug!(
                session = %session_id,
                reason,
                started,
                teardown_ms = self.settings.teardown.as_millis() as u64,
                tail_max_ms = self.settings.tail_max.as_millis() as u64,
                "session log: the session ended; lines that name no session still come to its file \
                 for its teardown, then only its own until its last task stops{}",
                if started {
                    ""
                } else {
                    " (it never started: its file closes after the teardown)"
                }
            ),
            Outcome::EndedAgain => tracing::trace!(
                session = %session_id,
                reason,
                "session log: a second end for a session; the first counts"
            ),
            Outcome::Unknown => tracing::debug!(
                session = %session_id,
                reason,
                "session log: an end for a session with no file: a request refused before it was \
                 accepted, or one whose file has closed"
            ),
            _ => {}
        }
    }

    /// The session's last task stopped at `now` (`afklink_core::SessionLog::finished`): its file
    /// closes, at once if its teardown is over.
    pub(crate) fn finished_at(&self, session_id: &str, now: Instant) {
        let outcome = {
            let mut guard = afklink_core::lock(&self.state);
            let st = &mut *guard;
            match st.scopes.iter().position(|s| s.id == session_id) {
                None => Outcome::Unknown,
                Some(i) => {
                    let over = match st.scopes.get_mut(i) {
                        Some(scope) => {
                            scope.finished_at = Some(now);
                            scope.over(now, &self.settings)
                        }
                        None => false,
                    };
                    if over {
                        let scope = st.scopes.remove(i);
                        if close(st.queue.as_ref(), st.on, scope, "finished", now) {
                            Outcome::Nothing
                        } else {
                            Outcome::WriterGone
                        }
                    } else {
                        Outcome::Nothing
                    }
                }
            }
        };
        match outcome {
            Outcome::Unknown => tracing::debug!(
                session = %session_id,
                "session log: its last task stopped after its file had closed; what it logged in \
                 between is in the system log"
            ),
            Outcome::WriterGone => warn_writer_gone(),
            _ => {}
        }
    }

    /// Once a second (the housekeeping thread): close the files whose sessions are over, report
    /// each file's new losses in it, and run the retention rules once an hour.
    pub(crate) fn tick(&self, now: Instant) {
        let mut writer_gone = false;
        {
            let mut guard = afklink_core::lock(&self.state);
            let st = &mut *guard;
            if st.shut {
                return;
            }
            let over: Vec<Scope> = st
                .scopes
                .extract_if(.., |s| s.over(now, &self.settings))
                .collect();
            for scope in over {
                let why = scope.why_closed();
                writer_gone |= !close(st.queue.as_ref(), st.on, scope, why, now);
            }
            if let Some(queue) = st.queue.as_ref() {
                if let Some((_, line)) = report_line(&st.system_lost, SYSTEM_LOG) {
                    queue.line(SYSTEM, &line, &st.system_lost);
                }
                for scope in st.scopes.iter().filter(|s| s.file) {
                    let file = format!("{SESSIONS_DIR}\\{}", scope.name);
                    if let Some((_, line)) = report_line(&scope.lost, &file) {
                        queue.line(scope.dest, &line, &scope.lost);
                    }
                }
                if st
                    .last_sweep
                    .is_none_or(|at| now.saturating_duration_since(at) >= SWEEP_EVERY)
                {
                    writer_gone |= !queue.command(Msg::Sweep);
                    st.last_sweep = Some(now);
                }
            }
        }
        if writer_gone {
            warn_writer_gone();
        }
    }

    fn is_shut(&self) -> bool {
        afklink_core::lock(&self.state).shut
    }

    /// See `Queue::pretend_waiting`: a full queue, for a test.
    #[cfg(test)]
    fn pretend_waiting(&self, lines: isize) {
        if let Some(queue) = afklink_core::lock(&self.state).queue.as_ref() {
            queue.pretend_waiting(lines);
        }
    }

    /// Wait up to `wait` for everything queued so far to be on disk: before a report reads the
    /// files. `false` when nothing is open or the writer did not answer in time.
    pub(crate) fn flush(&self, wait: Duration) -> bool {
        let (done, answered) = mpsc::sync_channel(1);
        let sent = afklink_core::lock(&self.state)
            .queue
            .as_ref()
            .is_some_and(|queue| queue.command(Msg::Flush(done)));
        sent && answered.recv_timeout(wait).is_ok()
    }

    /// On the way out: the last loss report, every session file closed with a last line saying
    /// `why`, and up to `wait` for the writer to put everything on disk. Nothing is written after.
    /// `false` when the lock or the writer did not answer in time.
    ///
    /// The lock is only tried, for [`LOCK_PATIENCE`]: this runs in the panic hook, where waiting on
    /// a lock the panicking thread may hold is how a crash becomes a hang.
    pub(crate) fn shutdown(&self, why: &'static str, wait: Duration) -> bool {
        let give_up = Instant::now() + LOCK_PATIENCE;
        let mut guard = loop {
            match self.state.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::Poisoned(p)) => break p.into_inner(),
                Err(TryLockError::WouldBlock) if Instant::now() < give_up => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TryLockError::WouldBlock) => return false,
            }
        };
        let st = &mut *guard;
        if st.shut {
            return true;
        }
        st.shut = true;
        let Some(queue) = st.queue.take() else {
            return true;
        };
        let now = Instant::now();
        if let Some((_, line)) = report_line(&st.system_lost, SYSTEM_LOG) {
            queue.line(SYSTEM, &line, &st.system_lost);
        }
        let on = st.on;
        for scope in st.scopes.drain(..) {
            // A gone writer is caught below: the shutdown is not answered.
            close(Some(&queue), on, scope, why, now);
        }
        drop(guard);
        let (done, answered) = mpsc::sync_channel(1);
        queue.command(Msg::Shutdown(done)) && answered.recv_timeout(wait).is_ok()
    }
}

fn warn_writer_gone() {
    tracing::warn!(
        "log files: the writer thread is gone; nothing more reaches the files (stdout and the \
         flight recorder still have the lines)"
    );
}

/// [`LogFiles::tick`] every `CHECK_EVERY`, on a thread of its own, until the files close: nothing
/// else in the app wakes that often while idle, and the loss reports have to come from outside the
/// queue they describe. A thread that cannot start leaves the losses to the last report on exit and
/// the session files open until then, and says so.
fn spawn_housekeeping(files: Weak<LogFiles>) {
    let spawned = std::thread::Builder::new()
        .name("afklink-log-housekeeping".to_string())
        .spawn(move || loop {
            std::thread::sleep(log_file::CHECK_EVERY);
            let Some(files) = files.upgrade() else {
                return;
            };
            if files.is_shut() {
                return;
            }
            files.tick(Instant::now());
        });
    if let Err(e) = spawned {
        tracing::warn!(
            "log files: the housekeeping thread did not start ({e}); lines the files lose are \
             reported only on exit, and a session's file closes only then"
        );
    }
}

impl afklink_core::SessionLog for LogFiles {
    fn opened(&self, session_id: &str, telegram_user_id: i64) {
        self.opened_at(
            session_id,
            telegram_user_id,
            Instant::now(),
            LocalTime::now(),
        );
    }

    fn started(&self, session_id: &str) {
        self.started_at(session_id);
    }

    fn ended(&self, session_id: &str, reason: &str) {
        self.ended_at(session_id, reason, Instant::now());
    }

    fn finished(&self, session_id: &str) {
        self.finished_at(session_id, Instant::now());
    }
}

/// The file layer's writer: every line through [`LogFiles::route_line`], with its target read from
/// the event's metadata.
#[derive(Clone)]
pub(crate) struct FileWriter(Arc<LogFiles>);

/// One event's writer.
pub(crate) struct RoutedLine<'a> {
    files: &'a LogFiles,
    system: bool,
}

impl<'a> MakeWriter<'a> for FileWriter {
    type Writer = RoutedLine<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        RoutedLine {
            files: &self.0,
            system: false,
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        RoutedLine {
            files: &self.0,
            system: is_system_target(meta.target()),
        }
    }
}

impl io::Write for RoutedLine<'_> {
    /// The formatting layer hands over a whole line in one `write_all` (it formats into a buffer
    /// first), so each write is one line.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.files.route_line(buf, self.system, Instant::now());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use afklink_core::logging::LogLevel;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    const A: &str = "d1020ebf-00d8-4048-a861-f51293d9135e";
    const B: &str = "d59808dd-b872-4544-a313-f03e5db569aa";

    /// A folder of its own under the temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(what: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("afklink-route-{what}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }

        fn session(&self, id: &str, requested: LocalTime) -> String {
            read(
                &self
                    .0
                    .join(SESSIONS_DIR)
                    .join(session_file_name(requested, id)),
            )
        }

        fn system(&self) -> String {
            read(&self.0.join(SYSTEM_LOG))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// The app's settings, but no housekeeping thread: the tests tick with the times they choose.
    fn open(dir: &TempDir) -> Arc<LogFiles> {
        let files = LogFiles::new(
            "0.1.0 · 3a3bc46 · dev".to_string(),
            RouteSettings {
                housekeeping: false,
                ..RouteSettings::APP
            },
        );
        files.set_level("debug".to_string(), true);
        assert_eq!(files.open(&dir.0), Ok(Some(dir.0.clone())));
        files
    }

    /// Everything queued written and every file closed: what the test reads next is complete.
    fn close(files: &LogFiles) {
        assert!(files.shutdown("test_end", Duration::from_secs(30)));
    }

    fn line(files: &LogFiles, text: &str, at: Instant) {
        files.route_line(format!("{text}\n").as_bytes(), false, at);
    }

    fn system_line(files: &LogFiles, text: &str, at: Instant) {
        files.route_line(format!("{text}\n").as_bytes(), true, at);
    }

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    /// The file's lines, each cut to what follows the machinery's `target: ` when it is one of its
    /// own (their timestamps differ every run), or whole.
    fn lines(text: &str) -> Vec<String> {
        text.lines()
            .map(|l| match l.split_once("afklink_app_lib::log_file: ") {
                Some((_, rest)) => format!("# {rest}"),
                None => l.to_string(),
            })
            .collect()
    }

    fn starts(lines: &[String], expected: &[&str]) {
        assert_eq!(lines.len(), expected.len(), "{lines:#?}");
        for (line, start) in lines.iter().zip(expected) {
            assert!(
                line.starts_with(start),
                "{line:?} does not start {start:?}\n{lines:#?}"
            );
        }
    }

    /// One session from its request to its telemetry's stop: its lines — named or not, the system
    /// events copied in — go to its file, which opens with its header and closes with its footer;
    /// before it, after its teardown and after its close, the system log has the rest, and records
    /// the file opened and closed.
    #[test]
    fn a_session_takes_its_lines_and_the_system_log_the_rest() {
        let dir = TempDir::new("one");
        let files = open(&dir);
        let t0 = Instant::now();
        let requested = LocalTime::now();

        line(&files, "before any session", t0);
        files.opened_at(A, 5_000_000_001, t0, requested);
        line(
            &files,
            &format!("session_request {A} from user 5000000001"),
            t0,
        );
        line(&files, "pipeline fps=60", t0 + secs(1));
        system_line(&files, "update check: up to date", t0 + secs(2));
        // A session with no file of its own is not a name: the line is the live session's.
        line(
            &files,
            &format!("session request refused session={B}"),
            t0 + secs(2),
        );
        files.started_at(A);
        files.ended_at(A, "peer_closed", t0 + secs(10));
        line(
            &files,
            "encode loop finished",
            t0 + Duration::from_millis(10_500),
        );
        line(&files, "signaling reconnect", t0 + secs(14));
        system_line(&files, "log level changed", t0 + secs(15));
        line(
            &files,
            &format!("telemetry stopped session={A}"),
            t0 + secs(20),
        );
        files.finished_at(A, t0 + secs(20));
        line(&files, &format!("late session={A}"), t0 + secs(21));
        close(&files);

        let session = lines(&dir.session(A, requested));
        let name = session_file_name(requested, A);
        starts(
            &session,
            &[
                &format!(
                    "# session log opened session={A} telegram_user_id=5000000001 \
                     build=\"0.1.0 · 3a3bc46 · dev\" log_level=\"debug\" pid="
                ),
                &format!("session_request {A} from user 5000000001"),
                "pipeline fps=60",
                "update check: up to date",
                &format!("session request refused session={B}"),
                "encode loop finished",
                &format!("telemetry stopped session={A}"),
                &format!(
                    "# session log closed session={A} why=finished end_reason=peer_closed \
                     lines=6 lost=0 queue_full=0 write_failed=0 open_s=20"
                ),
            ],
        );
        assert!(
            session[0].contains(&format!(
                "file={name:?} alongside=- opened_on=request_accepted"
            )),
            "{}",
            session[0]
        );
        starts(
            &lines(&dir.system()),
            &[
                "before any session",
                &format!(
                    "# session log opened: sessions\\{name} session={A} \
                     telegram_user_id=5000000001 alongside=-"
                ),
                "update check: up to date",
                "signaling reconnect",
                "log level changed",
                &format!("# session log closed: sessions\\{name} session={A} why=finished"),
                &format!("late session={A}"),
            ],
        );
    }

    /// Two sessions at once: what names neither goes to both, what names one to that one only, and
    /// each file says where the overlap starts and ends. After the second's teardown the first has
    /// the lines to itself again.
    #[test]
    fn two_sessions_share_what_names_neither_and_keep_their_own() {
        let dir = TempDir::new("two");
        let files = open(&dir);
        let t0 = Instant::now();
        let requested = LocalTime::now();

        files.opened_at(A, 42, t0, requested);
        files.started_at(A);
        files.opened_at(B, 43, t0 + secs(1), requested);
        files.started_at(B);
        line(&files, "pipeline shared", t0 + secs(2));
        line(&files, &format!("mine session={A}"), t0 + secs(2));
        line(&files, &format!("mine session={B}"), t0 + secs(2));
        files.ended_at(B, "peer_closed", t0 + secs(5));
        line(&files, "teardown of the second, shared", t0 + secs(6));
        line(&files, "after the second's teardown", t0 + secs(9));
        files.finished_at(B, t0 + secs(9));
        // Its file closed: a line that names it names no session with a file, and is the live one's.
        line(&files, &format!("late session={B}"), t0 + secs(10));
        close(&files);

        starts(
            &lines(&dir.session(A, requested)),
            &[
                &format!("# session log opened session={A} telegram_user_id=42"),
                &format!(
                    "# session log: another session is live alongside this one, d59808dd \
                     (session={B}); until it ends, lines that name no session are written to \
                     both files"
                ),
                "pipeline shared",
                &format!("mine session={A}"),
                "# session log: the session alongside, d59808dd, ended (peer_closed)",
                "teardown of the second, shared",
                "after the second's teardown",
                &format!("late session={B}"),
                // Five of the sessions' and the two lines about the overlap.
                &format!(
                    "# session log closed session={A} why=test_end end_reason=- lines=7 lost=0"
                ),
            ],
        );
        let second = lines(&dir.session(B, requested));
        starts(
            &second,
            &[
                &format!("# session log opened session={B} telegram_user_id=43"),
                "pipeline shared",
                &format!("mine session={B}"),
                "teardown of the second, shared",
                &format!(
                    "# session log closed session={B} why=finished end_reason=peer_closed lines=3"
                ),
            ],
        );
        assert!(second[0].contains("alongside=d1020ebf "), "{}", second[0]);
        let system = lines(&dir.system());
        starts(
            &system,
            &[
                "# session log opened: sessions\\",
                "# session log opened: sessions\\",
                &format!(
                    "# session log closed: sessions\\{}",
                    session_file_name(requested, B)
                ),
                &format!(
                    "# session log closed: sessions\\{}",
                    session_file_name(requested, A)
                ),
            ],
        );
    }

    /// A session whose last task never reports closes at the tail's bound; one that never started
    /// closes after its teardown; one whose last task stops early still keeps its teardown.
    #[test]
    fn the_tail_waits_for_the_last_task_within_its_bound() {
        let dir = TempDir::new("tail");
        let files = open(&dir);
        let t0 = Instant::now();
        let requested = LocalTime::now();
        const C: &str = "cc1a93cd-f57c-40c4-b647-470455aca451";

        // Started, ended, its telemetry never heard from.
        files.opened_at(A, 42, t0, requested);
        files.started_at(A);
        files.ended_at(A, "ice_timeout", t0);
        line(&files, &format!("in the tail session={A}"), t0 + secs(29));
        files.tick(t0 + secs(29));
        files.tick(t0 + secs(30));
        line(
            &files,
            &format!("after the bound session={A}"),
            t0 + secs(31),
        );
        // A request that never started.
        files.opened_at(B, 42, t0 + secs(40), requested);
        files.ended_at(B, "server_ended", t0 + secs(40));
        files.tick(t0 + secs(42));
        line(
            &files,
            &format!("still in the teardown session={B}"),
            t0 + secs(42),
        );
        files.tick(t0 + secs(43));
        line(
            &files,
            &format!("after its close session={B}"),
            t0 + secs(44),
        );
        // Its telemetry stops a second after the end: the teardown still has two to go.
        files.opened_at(C, 42, t0 + secs(50), requested);
        files.started_at(C);
        files.ended_at(C, "peer_closed", t0 + secs(50));
        files.finished_at(C, t0 + secs(51));
        line(&files, "encode loop finished", t0 + secs(52));
        files.tick(t0 + secs(53));
        line(&files, "nothing live", t0 + secs(54));
        close(&files);

        starts(
            &lines(&dir.session(A, requested)),
            &[
                "# session log opened",
                &format!("in the tail session={A}"),
                &format!(
                    "# session log closed session={A} why=tail_timeout end_reason=ice_timeout"
                ),
            ],
        );
        starts(
            &lines(&dir.session(B, requested)),
            &[
                "# session log opened",
                &format!("still in the teardown session={B}"),
                &format!(
                    "# session log closed session={B} why=not_started end_reason=server_ended"
                ),
            ],
        );
        starts(
            &lines(&dir.session(C, requested)),
            &[
                "# session log opened",
                "encode loop finished",
                &format!("# session log closed session={C} why=finished"),
            ],
        );
        let system = dir.system();
        for line in [
            format!("after its close session={B}"),
            format!("after the bound session={A}"),
            "nothing live".to_string(),
        ] {
            assert!(system.contains(&line), "{line:?} is not in:\n{system}");
        }
    }

    /// `off`: a session gets no file (nor its lines, which `off` does not let through); on again,
    /// the live session's file opens with a header that says so, and at `off` again it closes
    /// without a last line.
    #[test]
    fn off_opens_no_file_and_on_again_opens_the_live_ones() {
        let dir = TempDir::new("off");
        let files = open(&dir);
        let t0 = Instant::now();
        let requested = LocalTime::now();
        let path = dir
            .0
            .join(SESSIONS_DIR)
            .join(session_file_name(requested, A));

        files.set_level("off".to_string(), false);
        files.opened_at(A, 42, t0, requested);
        assert!(files.flush(Duration::from_secs(30)));
        assert!(!path.exists(), "off opens no file");
        files.set_level("info".to_string(), true);
        line(&files, "pipeline fps=60", t0 + secs(1));
        files.set_level("off".to_string(), false);
        files.ended_at(A, "peer_closed", t0 + secs(2));
        files.tick(t0 + secs(5));
        close(&files);

        let session = lines(&read(&path));
        starts(
            &session,
            &[
                &format!("# session log opened session={A}"),
                "pipeline fps=60",
            ],
        );
        assert!(
            session[0].contains("log_level=\"info\"")
                && session[0].ends_with("opened_on=log_switched_on"),
            "{}",
            session[0]
        );
    }

    /// Each file's losses are counted for it and reported in it: a line of a session the queue
    /// refused is said in that session's file (and its last line), one of the system log in the
    /// system log.
    #[test]
    fn each_file_reports_its_own_losses() {
        let dir = TempDir::new("losses");
        let files = open(&dir);
        let t0 = Instant::now();
        let requested = LocalTime::now();
        let full = isize::try_from(log_file::QUEUE_LINES).expect("fits");

        files.pretend_waiting(full);
        line(&files, "a system line lost", t0);
        files.pretend_waiting(-full);
        files.opened_at(A, 42, t0, requested);
        files.pretend_waiting(full);
        line(&files, &format!("a session line lost session={A}"), t0);
        files.pretend_waiting(-full);
        files.tick(t0 + secs(1));
        line(
            &files,
            &format!("after the report session={A}"),
            t0 + secs(1),
        );
        close(&files);

        let name = session_file_name(requested, A);
        let session = lines(&dir.session(A, requested));
        starts(
            &session,
            &[
                "# session log opened",
                "# log file: lines are missing from the file",
                &format!("after the report session={A}"),
                &format!("# session log closed session={A} why=test_end end_reason=- lines=2 lost=1 queue_full=1"),
            ],
        );
        assert!(
            session[1].contains(&format!("lost=1 queue_full=1 write_failed=0 lost_total=1 last_write_error=\"-\" file=\"sessions\\\\{name}\"")),
            "{}",
            session[1]
        );
        let system = lines(&dir.system());
        let reports: Vec<&String> = system
            .iter()
            .filter(|l| l.contains("lines are missing"))
            .collect();
        assert_eq!(reports.len(), 1, "{system:#?}");
        assert!(
            reports[0].contains("lost=1 queue_full=1")
                && reports[0].contains("file=\"system.log\"")
        );
        assert!(
            !system.iter().any(|l| l.contains("lost session=")),
            "{system:#?}"
        );
    }

    /// Through the subscriber, as the app logs: a system target goes to the system log and the live
    /// session's file, an ordinary line to the session's file only, and an event that cannot be
    /// formatted leaves its line there too.
    #[test]
    fn the_file_layer_sorts_by_target_and_session() {
        struct Unprintable;
        impl std::fmt::Display for Unprintable {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                Err(std::fmt::Error)
            }
        }

        let dir = TempDir::new("layer");
        let files = open(&dir);
        let requested = LocalTime::now();
        let subscriber = tracing_subscriber::registry()
            .with(LogLevel::Debug.filter())
            .with(log_file::file_layer(files.writer()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "afklink_core::agent", "before the session");
            files.opened_at(A, 42, Instant::now(), requested);
            tracing::info!(target: "afklink_app_lib::updater::task", "update check: up to date");
            tracing::info!(target: SYSTEM_TARGET, "log level changed");
            tracing::debug!(target: "afklink_core::agent", "rate control moved");
            tracing::info!(target: "afklink_core::agent", session = %A, "session started");
            tracing::info!(value = %Unprintable, "an event that cannot be formatted");
        });
        close(&files);

        let session = dir.session(A, requested);
        let system = dir.system();
        for (text, in_session, in_system) in [
            ("before the session", false, true),
            (
                "session log: this session's lines go to its own file",
                true,
                false,
            ),
            (
                " INFO afklink_app_lib::updater::task: update check: up to date",
                true,
                true,
            ),
            (
                " INFO afklink_app_lib::system: log level changed",
                true,
                true,
            ),
            ("rate control moved", true, false),
            (&format!("session started session={A}") as &str, true, false),
            ("Unable to format the following event", true, false),
        ] {
            assert_eq!(
                session.contains(text),
                in_session,
                "{text:?} in the session:\n{session}"
            );
            assert_eq!(
                system.contains(text),
                in_system,
                "{text:?} in the system log:\n{system}"
            );
        }
    }

    /// The files open with the retention rules run once: an old session file and an old daily file
    /// go, each said in the system log; everything else stays.
    #[test]
    fn old_files_go_when_the_files_open_and_the_system_log_says_so() {
        let dir = TempDir::new("retention");
        let sessions = dir.0.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).expect("sessions dir");
        let old = session_file_name(LocalTime::new(2020, 1, 1, 0, 0, 0), "old00000");
        let fresh = session_file_name(LocalTime::now(), "fresh000");
        std::fs::write(sessions.join(&old), "x\n").expect("write");
        std::fs::write(sessions.join(&fresh), "x\n").expect("write");
        std::fs::write(dir.0.join("afklink-app.2020-01-01.log"), "x\n").expect("write");
        let files = open(&dir);
        close(&files);

        assert!(!sessions.join(&old).exists());
        assert!(sessions.join(&fresh).exists());
        assert!(!dir.0.join("afklink-app.2020-01-01.log").exists());
        let system = dir.system();
        assert!(
            system.contains(&format!(
                "log retention: removed sessions\\{old} bytes=2 rule=older_than_max_age (scheduled)"
            )),
            "{system}"
        );
        assert!(
            system.contains(
                "log retention: removed afklink-app.2020-01-01.log bytes=2 rule=old_daily_file"
            ),
            "{system}"
        );
    }

    #[test]
    fn system_events_are_told_by_their_target() {
        for target in [
            "afklink_app_lib::system",
            "afklink_app_lib::updater",
            "afklink_app_lib::updater::watchdog",
            "afklink_app_lib::fakerinput_setup::msi_log",
            "afklink_app_lib::game_helper",
            "afklink_app_lib::game_helper::helper",
            "afklink_app_lib::staged_file",
            "afklink_app_lib::autostart",
            "afklink_app_lib::diagnostics::package",
            "afklink_app_lib::toast_identity",
            "afklink_app_lib::webview_runtime",
            "afklink_app_lib::start_failure",
            "afklink_app_lib::system_events",
            "afklink_app_lib::system_events::win",
            "afklink_core::goodbye",
            "afklink_core::entry",
        ] {
            assert!(is_system_target(target), "{target}");
        }
        for target in [
            "afklink_app_lib",
            "afklink_app_lib::updaterx",
            "afklink_app_lib::tray_theme",
            "afklink_app_lib::log_route",
            "afklink_core::agent",
            "afklink_transport::signaling",
            "afklink_input::fakerinput",
        ] {
            assert!(!is_system_target(target), "{target}");
        }
    }
}
