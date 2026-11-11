//! The helper's decisions, free of Windows: when to launch the game, when a start failed, when to
//! stop launching, when the game hangs and is closed, and when to bring the game's window back to
//! the front. [`Desktop`] is the Windows half (`windows.rs`); the tests give it a fake desktop and
//! their own clock.
//!
//! Everything here happens only while the app's signal allows it ([`Signal::Allowed`]: a session
//! is live and the owner's settings match the installed record). Without it the helper does
//! nothing at all — the person at the PC can close the game, minimize it, use other windows.
//!
//! # A signal read seconds ago is not a permission
//!
//! A tick reads the signal at its start, then looks at the desktop, which under a full CPU can take
//! 16–25 s; a session may end, and another begin, in that time. So every action — the launch,
//! `WM_CLOSE`, TerminateProcess, bringing the window to the front — reads the signal again right
//! before it ([`Desktop::signal`]); not set any more, the action is not done, the signal's going off
//! is taken in at once (the counts stop with it) and the rest of the tick does nothing. A count
//! toward closing the game counts only time the helper watched the signal: two ticks' reads more
//! than [`SIGNAL_GAP_MAX`] apart, and it starts over. A slow tick is logged ([`slow_tick`]).
//!
//! # A launch's fate
//!
//! A launch of the helper's waits for the game's window (`launch_pending`: the viewer's
//! «Игра запускается»). So does a game the helper is about to close as hung and launch again (its
//! window gone while its process runs, counted toward [`WINDOW_LOST_AFTER`], or being closed) as
//! long as a launch follows: the viewer is not told «Игра не запущена» while the helper restarts
//! it. The window up, the launch has come; up at [`FAST_EXIT_WITHIN`] after it, the launch has
//! survived. The game — every process of the record's two exes — gone before that is a failed
//! start, and the next launch waits [`backoff`], counted from when the game went.
//!
//! A loader may hand over to a process the record does not know (Scryde's `ScrydeGame_Lite.exe`
//! starts `ScrydeGame.exe`, an anticheat updater, which starts `ScrydeGame.bin` 3.7 s after the
//! loader exited), and for those seconds nothing of the game runs. So a launch exe that is not the
//! window exe, gone with nothing of the game after it (no process of the window exe seen since the
//! launch, its window never up), is not a failed start yet: for [`HANDOVER_WITHIN`] the launch
//! stays pending and nothing is launched. A process of the game in that time, and the launch goes
//! on; none, and it is a failed start. There is no wait for a game that is its own launch exe, a
//! window exe's process seen and then gone, a game the helper closed as hung, or a launch
//! [`LAUNCHER_WAIT_MAX`] old. The signal off ends the wait, no failed start counted.
//!
//! # A game that hangs
//!
//! The game's processes running with no window is not always a game starting: Scryde's own crash
//! report («Scryde Crash Report») keeps `ScrydeGame.bin` alive until someone closes it, and a viewer
//! who sees only the game's window cannot. The helper calls the game hung when
//!
//! - its window was up and has been gone [`WINDOW_LOST_AFTER`] while the process that showed it
//!   still runs — up in this session or in an earlier one of this helper's run, so a session
//!   started again after the crash still finds it; or
//! - [`WINDOW_WITHIN`] after the helper's launch no window has come at all;
//!
//! in both only while no loader is starting the game (it may be patching) and [`HANDOVER_WITHIN`]
//! after the last one exited. It then asks the game's windows to close (`WM_CLOSE`), waits up to
//! [`CLOSE_GRACE`] and ends what is left with TerminateProcess — processes whose path cannot be read
//! are never touched. The usual restart policy follows. A loader still running
//! [`LAUNCHER_WAIT_MAX`] after the helper's launch with no window ever is not closed: the helper
//! gives up until the next session.
//!
//! # «Игра не запускается»: the failed-launch mark
//!
//! Giving up ends the launches of one session only. The mark the app shows lives longer
//! ([`StateFile::failed_launch_since_ms`]): set when the helper gives up, kept across sessions and
//! across the helper's own restarts ([`Supervisor::carry_over`] reads the last `state.json` back;
//! it launches nothing), and cleared only when the game is seen to run — its window up at
//! [`FAST_EXIT_WITHIN`] after a launch, however it was started. A setup removes `state.json`, so a
//! new installation starts clean.

use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::log::{unix_ms, Level, Log};
use crate::record::{file_name, Record};

/// How often the helper looks: the signal, the game's processes, its window, the front window.
pub const POLL: Duration = Duration::from_millis(500);

/// A tick — the signal read, the look, the actions, `state.json` — longer than this is said, with
/// how long it took ([`slow_tick`]). A tick takes milliseconds; under a full CPU at below-normal
/// task priority it took 16–25 s (see [`crate::TASK_PRIORITY`]).
pub const SLOW_TICK: Duration = Duration::from_secs(2);

/// Two ticks' reads of the signal further apart than this — a [`SLOW_TICK`] and the [`POLL`] after
/// it — and the helper cannot vouch the signal stayed set in between: the app may have ended a
/// session and begun another. The count toward closing a game whose window went, and a closing
/// begun, start over then: time the helper did not see allowed is not counted toward an action.
pub const SIGNAL_GAP_MAX: Duration = Duration::from_millis(2_500);

/// After a launch, the next one waits at least this long (GameGuard's own interval is 30 s): a game
/// that dies on start does not get started twice a second. The first launch of a session is at
/// once.
pub const LAUNCH_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// The game (every one of its processes) gone this soon after a launch is a failed start: it crashed
/// on start or never came up. A minute covers a loader handing over to the game (5 s for Scryde)
/// and an anticheat's update window many times over. Gone later, a run counts as one
/// only if its window was up at this mark: a game that crashed at 10 s and hangs on in its crash
/// report has not run. A loader gone before any process of the window exe ran first gets
/// [`HANDOVER_WITHIN`] for one to come (the module's «A launch's fate»).
pub const FAST_EXIT_WITHIN: Duration = Duration::from_secs(60);

/// No game window this long after the helper's launch, and no loader running (a loader may patch
/// for 60–120 s): the game hangs, and is closed. While a loader runs, it is only
/// said, once.
pub const WINDOW_WITHIN: Duration = Duration::from_secs(120);

/// The game's window gone this long while the process that showed it still runs: the game crashed
/// or hangs. After a normal close Scryde's `ScrydeGame.bin` lives on about 9 s; 30 s leaves room
/// to spare. A window back sooner starts the count over.
pub const WINDOW_LOST_AFTER: Duration = Duration::from_secs(30);

/// A loader that exits hands over to the game: the game's window gets this long after that before
/// the game counts as hung (Scryde's is up 3.8 s after the loader exits).
/// And a loader of the helper's launch gone with nothing of the game after it gets this long, from
/// the look that found the game gone, for a process of the game to come before the launch is a
/// failed start: it may hand over through a process the record does not know (Scryde's
/// `ScrydeGame_Lite.exe`: `ScrydeGame.bin` came 3.7 s after; the module's «A launch's fate»).
pub const HANDOVER_WITHIN: Duration = WINDOW_LOST_AFTER;

/// Asked to close (`WM_CLOSE` to its windows), a hung game gets this long to exit before what is
/// left of it is ended with TerminateProcess.
pub const CLOSE_GRACE: Duration = Duration::from_secs(10);

/// The exit code of a game process the helper ends.
pub const TERMINATE_EXIT_CODE: u32 = 1;

/// A loader still running this long after the helper's launch, with no game window ever: the helper
/// gives up until the next session (and sets the failed-launch mark, «Игра не запускается» in the
/// app until the game runs) and leaves the loader alone — it may be downloading a patch, or waiting
/// for someone to press «Play». Scryde's anticheat update takes seconds; 10 min leaves room for
/// other games' patches.
pub const LAUNCHER_WAIT_MAX: Duration = Duration::from_secs(10 * 60);

/// The pause after the n-th failed start in a row: 30 s, doubling, at most [`BACKOFF_MAX`]
/// counted from when the game went.
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
pub const BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

/// Failed starts in a row after which the helper launches nothing more until the next session —
/// otherwise a broken game would loop start-crash for hours.
pub const MAX_FAILED_STARTS: u32 = 3;

/// Focus refused: the next try after 1 s, doubling, at most 10 s — not every half second, which
/// would only make the taskbar button flash. Starts over on success or when another window comes to
/// the front.
pub const FOCUS_RETRY_MIN: Duration = Duration::from_secs(1);
pub const FOCUS_RETRY_MAX: Duration = Duration::from_secs(10);

/// A summary line this often while allowed, so a long session's log shows the helper alive.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(5 * 60);

/// `state.json`'s format.
pub const STATE_FORMAT: u32 = 1;

/// What the app's signal said on a tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// Set: a session is live, and the owner's settings are what the record was installed for.
    Allowed,
    /// The app is running and does not allow it now.
    NotSet,
    /// No signal object: the app is not running (or not this build).
    Absent,
    /// Opening or reading it failed: treated as not allowed.
    Unreadable(String),
}

impl Signal {
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Allowed => "set (a session is live)".to_string(),
            Self::NotSet => "not set (no session, or the settings do not allow it)".to_string(),
            Self::Absent => "absent (the app is not running)".to_string(),
            Self::Unreadable(e) => format!("unreadable ({e})"),
        }
    }
}

/// The helper's state, as `state.json` gives it to the app.
///
/// No value is added for a hung game being closed: an app built before it reads `state.json` with
/// this same enum, and a value it does not know fails the whole file (format 1) — it would show no
/// state at all. That is [`HelperState::Launching`] with a `reason` saying so.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperState {
    /// Not allowed: nothing is done.
    Idle,
    /// Allowed, the game is not running, the next launch is not due yet.
    Waiting,
    /// Launched, or the game's processes run with no window: starting, or — `reason` says which —
    /// its loader gone and its handover waited for ([`HANDOVER_WITHIN`]), its window gone and the
    /// count before it is closed running, or a hung game being closed.
    Launching,
    /// The game's window is up.
    Running,
    /// No more launches this session: [`MAX_FAILED_STARTS`] failed starts in a row, or a loader
    /// that ran [`LAUNCHER_WAIT_MAX`] with no game window. What the app shows for it outlives the
    /// session: [`StateFile::failed_launch_since_ms`].
    GaveUp,
    /// Windows refused to start the launch exe at this task's level, or the record is unusable:
    /// the owner has to confirm the setup again.
    NeedsSetup,
}

impl HelperState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Waiting => "waiting",
            Self::Launching => "launching",
            Self::Running => "running",
            Self::GaveUp => "gave_up",
            Self::NeedsSetup => "needs_setup",
        }
    }
}

/// `state.json`, beside the helper's log: what the app shows. Written on every change and every
/// [`crate::STATE_REFRESH`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFile {
    pub format: u32,
    pub state: HelperState,
    pub reason: String,
    /// When the state began, Unix ms.
    pub since_ms: u64,
    /// When this file was written, Unix ms: an old one means the helper stopped.
    pub updated_ms: u64,
    pub pid: u32,
    pub elevated: bool,
    /// Launches this session, and failed starts in a row.
    pub launches: u32,
    pub failed_starts: u32,
    /// Since the helper started: focus returned by each method, and refused.
    pub focus_set_foreground: u32,
    pub focus_uia: u32,
    pub focus_refused: u32,
    /// The helper launched the game itself in this session and waits for its window: from the
    /// launch until the window comes, the start fails (the game gone — for a loader gone with
    /// nothing of the game after it, once its handover has had [`HANDOVER_WITHIN`] — or closed as
    /// hung) or the helper gives up — and only while the app allows it to act. Also while the
    /// helper is about to close the game as hung and launch it again: its window gone while its
    /// process runs (a crash report keeping it alive), or the closing itself — when a launch
    /// follows. Never for a game started by hand before its window is up, one Windows refused to
    /// close, one whose closing gives up, or the pause before the next launch. The app tells the
    /// sessions' heartbeats, and the viewer says «Игра запускается» (`game.launching` in the
    /// contract).
    ///
    /// A field with a default, not a state: an app built before it ignores it (no
    /// `deny_unknown_fields`), and this app reads an older helper's file as `false`.
    #[serde(default)]
    pub launch_pending: bool,
    /// The failed-launch mark (the module's «Игра не запускается»): since when, Unix ms — when the
    /// helper gave up, in this run or one before it. `None`: the game has not failed to start, or
    /// has run since. The app shows «Игра не запускается» while it is set.
    ///
    /// A field with a default, like `launch_pending`: an app built before it ignores it, and this
    /// app reads an older helper's file as `None` (and then goes by `state == gave_up` alone).
    #[serde(default)]
    pub failed_launch_since_ms: Option<u64>,
}

impl StateFile {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let state: StateFile =
            serde_json::from_slice(bytes).map_err(|e| format!("state.json unreadable: {e}"))?;
        if state.format != STATE_FORMAT {
            return Err(format!("state.json has format {}", state.format));
        }
        Ok(state)
    }
}

/// The game's window: a visible top-level window of one of its processes, with the bound class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GameWindow {
    pub id: usize,
    /// The process it belongs to.
    pub pid: u32,
    pub minimized: bool,
}

/// The window in front, as far as focus is concerned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Foreground {
    /// None: the secure desktop (an elevation prompt), the lock screen, a switch in progress.
    #[default]
    Nothing,
    /// A window of one of the game's processes — its splash, a dialog, the game itself.
    Game,
    /// A window or menu of AFKLink itself: never taken from, so the person at the PC can always
    /// turn the mode off.
    AfkLink {
        exe: String,
    },
    /// A menu is open in the front window's thread: someone is using it.
    Menu {
        exe: String,
    },
    Other {
        window: usize,
        exe: String,
    },
    /// Its process could not be read.
    Unreadable {
        window: usize,
        error: String,
    },
}

/// One look at the desktop.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    /// Processes in this Windows session whose full path is the launch exe or the window exe.
    pub game_pids: Vec<u32>,
    /// Those of `game_pids` that are the launch exe, when it is not also the window exe: a loader,
    /// which may be patching before the game starts.
    pub loader_pids: Vec<u32>,
    /// Processes in this session named like either exe whose path could not be read (access
    /// denied): maybe the game, so it is not launched next to them — and never closed.
    pub unreadable: Vec<u32>,
    pub window: Option<GameWindow>,
    pub foreground: Foreground,
    /// The process the helper started exited since the last look: its pid and exit code.
    pub launched_exit: Option<(u32, Option<i32>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchError {
    /// `ERROR_ELEVATION_REQUIRED` (740): the exe needs administrator, this task runs without.
    ElevationRequired,
    NotFound(String),
    Other(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusMethod {
    SetForeground,
    Uia,
}

impl FocusMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetForeground => "SetForegroundWindow",
            Self::Uia => "UI Automation SetFocus",
        }
    }
}

/// How a focus try went: the method that brought the game to the front, or `None` when Windows
/// refused every one; `detail` says what each step answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FocusOutcome {
    pub method: Option<FocusMethod>,
    pub detail: String,
}

/// One of the game's processes as the helper is about to close it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameProcess {
    pub pid: u32,
    pub path: String,
    /// When it started (`GetProcessTimes`, 100 ns units since 1601): ids are reused, so this tells
    /// the process named here from a later one with the same id.
    pub started: u64,
}

/// A visible top-level window of the game's processes, and how `WM_CLOSE` to it went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedWindow {
    pub pid: u32,
    pub window: usize,
    pub class: String,
    pub title: String,
    /// `Err`: what Windows answered (or that the window was gone before the message).
    pub posted: Result<(), String>,
}

/// What [`Desktop::close_windows`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloseRequest {
    /// The processes confirmed the game's — this session, one of the record's two exes — with
    /// their start times, for [`Desktop::terminate`].
    pub processes: Vec<GameProcess>,
    /// Ids not closed, and why: gone, not the game any more, not readable.
    pub skipped: Vec<(u32, String)>,
    pub windows: Vec<ClosedWindow>,
    /// The windows could not be listed: no `WM_CLOSE` went out.
    pub windows_error: Option<String>,
    /// What Windows says of the processes, for the log (debug): the integrity levels of the game's
    /// processes, once each, and of the helper — why a `WM_CLOSE` or TerminateProcess is refused.
    pub notes: Vec<String>,
}

/// How TerminateProcess on one of the game's processes went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminateOutcome {
    /// Ended within the short wait after it: its exit code.
    Ended(Option<u32>),
    /// TerminateProcess went through; the process had not ended by the end of the short wait.
    Requested,
    /// It had ended on its own before: its exit code.
    AlreadyEnded(Option<u32>),
    /// Not the process named any more (gone, or its id another process's): nothing was done.
    NotTheGame(String),
    /// Access denied: a helper without rights, a game with them.
    Denied(String),
    Failed(String),
}

/// The Windows half.
pub trait Desktop {
    /// The app's signal as it is now — read again right before every action: the tick's own read
    /// may be seconds old by then (the module's «A signal read seconds ago…»).
    fn signal(&mut self) -> Signal;
    /// The clock those reads are timed with: how long after the tick's own read an action came.
    fn now(&mut self) -> Instant;
    fn observe(&mut self, record: &Record) -> Result<Observation, String>;
    /// Start the launch exe, with no arguments, in its folder: the new process's id.
    fn launch(&mut self, exe: &str) -> Result<u32, LaunchError>;
    /// Restore the window if it is minimized and bring it to the front.
    fn focus(&mut self, record: &Record, window: GameWindow) -> FocusOutcome;
    /// Post `WM_CLOSE` to every visible top-level window of these processes, each process first
    /// checked to be the game's: in this Windows session, its full path one of the record's two
    /// exes. Posted, not sent: a hung window cannot hold the helper.
    fn close_windows(&mut self, record: &Record, pids: &[u32]) -> CloseRequest;
    /// End one process with TerminateProcess, if it is still the one [`Self::close_windows`]
    /// confirmed — the same path and start time, checked on the handle that ends it — then wait a
    /// moment for its exit code.
    fn terminate(&mut self, record: &Record, process: &GameProcess) -> TerminateOutcome;
}

/// The pause after `failed` failed starts in a row.
pub fn backoff(failed: u32) -> Duration {
    if failed == 0 {
        return Duration::ZERO;
    }
    BACKOFF_BASE
        .saturating_mul(1 << (failed - 1).min(16))
        .min(BACKOFF_MAX)
}

/// The pause after `refused` refused focus tries in a row.
pub fn focus_delay(refused: u32) -> Duration {
    FOCUS_RETRY_MIN
        .saturating_mul(1 << refused.saturating_sub(1).min(16))
        .min(FOCUS_RETRY_MAX)
}

/// The warning for a tick that took `took`, when it is longer than [`SLOW_TICK`]; `None` otherwise.
pub fn slow_tick(took: Duration) -> Option<String> {
    (took > SLOW_TICK).then(|| {
        format!(
            "tick took {} (over {}: the PC is loaded, or Windows answered slowly); each action in \
             it read the app's signal again first",
            secs(took),
            secs(SLOW_TICK)
        )
    })
}

fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

fn mins(d: Duration) -> String {
    format!("{:.1} min", d.as_secs_f64() / 60.0)
}

fn code(code: Option<u32>) -> String {
    code.map_or("unknown".to_string(), |c| c.to_string())
}

/// What one session (one stretch of [`Signal::Allowed`]) has done: a new session starts it over.
#[derive(Debug, Default)]
struct Period {
    last_launch: Option<Instant>,
    launch: Option<Launch>,
    gone_at: Option<Instant>,
    failed_starts: u32,
    gave_up: bool,
    /// Why, with `gave_up`: for `state.json`.
    gave_up_why: String,
    launches: u32,
    waiting_noted: bool,
    focus: FocusRetry,
    /// The game's processes run with no window, and it is counted against them.
    blind: Option<Blind>,
    /// The last look a loader that is starting the game was running.
    loader_at: Option<Instant>,
    /// Those loaders at the last look of the game running without its window: for
    /// `launch_pending`'s why, and its bound ([`LAUNCHER_WAIT_MAX`]).
    starting_loaders: Vec<u32>,
    closing: Option<Closing>,
    /// Since when the game's window has been up on every look, this session: a minute of it takes
    /// the failed-launch mark off, however the game was started.
    window_since: Option<Instant>,
}

/// Since when the failed-launch mark is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkSince {
    /// Set in this run of the helper.
    Now(Instant),
    /// Carried over from the last run's `state.json`, Unix ms.
    Carried(u64),
}

impl MarkSince {
    fn unix_ms(self, now: Instant, wall: SystemTime) -> u64 {
        match self {
            Self::Now(at) => unix_ms(
                wall.checked_sub(now.saturating_duration_since(at))
                    .unwrap_or(wall),
            ),
            Self::Carried(ms) => ms,
        }
    }
}

#[derive(Debug)]
struct Launch {
    at: Instant,
    pid: u32,
    window_seen: bool,
    survived: bool,
    /// A process of the window exe — one of the game's that is not a loader — seen at a look since
    /// the launch: the loader has handed over, and the game gone from then on is a failed start at
    /// once (no wait for a handover).
    game_seen: bool,
    /// Looks since the launch at which only loaders of the game ran: for the log.
    loader_looks: u32,
    /// The launched process's exit, once seen: its code (`None` inside: Windows gave none).
    exit: Option<Option<i32>>,
    /// The loader gone with nothing of the game after it: since the look that found the game gone,
    /// its handover is waited for ([`HANDOVER_WITHIN`]) — the launch stays, pending, and nothing is
    /// launched (the module's «A launch's fate»).
    handover_since: Option<Instant>,
    /// Waits for a handover this launch has had (a loader back during one, then gone again, gets
    /// another): for the log.
    handovers: u32,
}

impl Launch {
    fn new(at: Instant, pid: u32) -> Self {
        Self {
            at,
            pid,
            window_seen: false,
            survived: false,
            game_seen: false,
            loader_looks: 0,
            exit: None,
            handover_since: None,
            handovers: 0,
        }
    }

    /// How the launched process went, for the log.
    fn exit_note(&self) -> String {
        match self.exit {
            Some(Some(code)) => format!("exited with code {code}"),
            Some(None) => "exited, its exit code unknown".to_string(),
            None => "its exit not seen yet".to_string(),
        }
    }
}

/// [`Supervisor::handover`]: whether a launch whose game is gone waits for its loader's handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handover {
    /// Waited for (begun at this look or before): the launch stays.
    Waiting,
    /// Waited for in vain: a failed start, the game gone at this look.
    RanOut(Instant),
    /// Not waited for: the game's going is judged now.
    No,
}

/// The game's processes running with no window.
#[derive(Debug)]
struct Blind {
    /// Its window was up and went, the process that showed it still running ([`WINDOW_LOST_AFTER`]);
    /// else a launch of the helper's whose window has not come yet ([`WINDOW_WITHIN`]).
    lost: bool,
    /// When the window went (or, in a session begun without it, when that session began); the
    /// launch, for a window that has not come.
    since: Instant,
    /// A loader running past the count: said once.
    loader_noted: bool,
}

/// A hung game being closed.
#[derive(Debug)]
struct Closing {
    at: Instant,
    /// When the game counts as gone for the restart policy: when its window went; for a window
    /// that never came, when the helper decided.
    gone_at: Instant,
    lost: bool,
    /// The game's processes when the helper decided, and those confirmed the game's.
    pids: Vec<u32>,
    processes: Vec<GameProcess>,
    stage: Stage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// `WM_CLOSE` posted; TerminateProcess once [`CLOSE_GRACE`] has passed.
    Asked,
    /// TerminateProcess called then; said once more if the game outlives [`CLOSE_GRACE`] after it.
    Ended { at: Instant, late_noted: bool },
    /// Windows refused (or nothing could be confirmed the game's): nothing more is tried until the
    /// game goes, its window comes back or the session ends.
    Refused,
}

impl Stage {
    fn describe(self) -> &'static str {
        match self {
            Self::Asked => "after WM_CLOSE",
            Self::Ended { .. } => "after TerminateProcess",
            Self::Refused => "after Windows refused to close it",
        }
    }

    fn reason(self) -> String {
        match self {
            Self::Asked => format!(
                "closing the hung game: WM_CLOSE sent to its windows, TerminateProcess if it is \
                 still there after {}",
                secs(CLOSE_GRACE)
            ),
            Self::Ended { .. } => {
                "closing the hung game: TerminateProcess done, waiting for it to exit".to_string()
            }
            Self::Refused => {
                "the game hangs and Windows refused to close it (access denied): waiting"
                    .to_string()
            }
        }
    }
}

#[derive(Debug, Default)]
struct FocusRetry {
    refused: u32,
    retry_at: Option<Instant>,
    /// The window that was in front when focus was last refused.
    refused_on: Option<usize>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Totals {
    focus_set_foreground: u32,
    focus_uia: u32,
    focus_refused: u32,
}

pub struct Supervisor {
    record: Record,
    state: HelperState,
    reason: String,
    since: Instant,
    dirty: bool,
    signal: Option<Signal>,
    allowed: bool,
    /// When a tick last read the signal set, at its start: the next tick's read more than
    /// [`SIGNAL_GAP_MAX`] after it, and the counts toward closing the game start over. Only the
    /// ticks' own reads count — one right before an action says the signal is set then, not that
    /// it stayed set since the tick began.
    signal_seen_at: Option<Instant>,
    needs_setup: Option<String>,
    period: Period,
    running: bool,
    unreadable: Vec<u32>,
    observe_failures: u32,
    left_alone: Option<String>,
    totals: Totals,
    last_summary: Instant,
    /// The process that showed the game's window last, while it runs — kept across sessions: a
    /// session begun after a crash finds it without its window.
    window_owner: Option<u32>,
    /// Since when the helper has seen that process run without the game's window — kept across
    /// sessions like it, for the log only: the count toward closing the game starts over with each
    /// session (`Period`), and a new session says how long the window has been gone in all.
    window_gone_at: Option<Instant>,
    /// Loaders that were running while the game's window was up: they stay beside the game and
    /// start nothing, unlike a loader that comes after.
    resident_loaders: Vec<u32>,
    /// `state.json`'s `launch_pending` as last written ([`Self::launch_pending`]): a change is
    /// logged with why, and written at once.
    launch_pending: bool,
    /// `launch_pending` is on for a launch the helper predicts after closing the game as hung
    /// ([`Self::relaunch_after_hang`]): its going off with no launch and no pause is a drift
    /// between that prediction and [`Self::follow_game`], said as a warning.
    pending_relaunch: bool,
    /// The failed-launch mark (the module's «Игра не запускается»): kept across sessions, and
    /// across the helper's restarts through [`Self::carry_over`].
    failed_launch: Option<MarkSince>,
}

impl Supervisor {
    pub fn new(record: Record, now: Instant) -> Self {
        Self {
            record,
            state: HelperState::Idle,
            reason: "started; the app's signal not read yet".to_string(),
            since: now,
            dirty: true,
            signal: None,
            allowed: false,
            signal_seen_at: None,
            needs_setup: None,
            period: Period::default(),
            running: false,
            unreadable: Vec::new(),
            observe_failures: 0,
            left_alone: None,
            totals: Totals::default(),
            last_summary: now,
            window_owner: None,
            window_gone_at: None,
            resident_loaders: Vec::new(),
            launch_pending: false,
            pending_relaunch: false,
            failed_launch: None,
        }
    }

    pub fn state(&self) -> HelperState {
        self.state
    }

    /// Whether the failed-launch mark is set (`state.json`'s `failed_launch_since_ms`).
    pub fn failed_launch(&self) -> bool {
        self.failed_launch.is_some()
    }

    /// At the helper's start: the mark its last run left in `state.json` (`previous`, read back
    /// from its own data directory) is kept — a mark for the app's window only: nothing is launched
    /// for it, and the next session tries as any would. An older helper's file has none.
    pub fn carry_over(&mut self, previous: &StateFile, wall: SystemTime, log: &mut impl Log) {
        let Some(since_ms) = previous.failed_launch_since_ms else {
            log.line(
                Level::Debug,
                &format!(
                    "the last run's {} has no failed-launch mark (it was {}: {})",
                    crate::STATE_FILE,
                    previous.state.as_str(),
                    previous.reason
                ),
            );
            return;
        };
        let ago = Duration::from_millis(unix_ms(wall).saturating_sub(since_ms));
        log.line(
            Level::Info,
            &format!(
                "the last run's failed-launch mark is carried over (set {} ago; that run was {}: \
                 {}): the app shows «Игра не запускается» until the game runs {} with its window; \
                 nothing is launched for it",
                mins(ago),
                previous.state.as_str(),
                previous.reason,
                secs(FAST_EXIT_WITHIN)
            ),
        );
        self.failed_launch = Some(MarkSince::Carried(since_ms));
        self.dirty = true;
    }

    /// The helper gave up (`why`): the mark is set, or stays as it was set first.
    fn mark_failed_launch(&mut self, now: Instant, why: &str, log: &mut impl Log) {
        match self.failed_launch {
            Some(since) => log.line(
                Level::Debug,
                &format!(
                    "the failed-launch mark stays ({}): given up again — {why}",
                    match since {
                        MarkSince::Now(at) => format!(
                            "set {} ago in this run",
                            mins(now.saturating_duration_since(at))
                        ),
                        MarkSince::Carried(ms) => format!("carried over, set at {ms} ms"),
                    }
                ),
            ),
            None => {
                self.failed_launch = Some(MarkSince::Now(now));
                self.dirty = true;
                log.line(
                    Level::Info,
                    &format!(
                        "failed-launch mark set ({why}): the app shows «Игра не запускается» \
                         until the game runs {} with its window — in this session, a later one, \
                         or after the helper restarts",
                        secs(FAST_EXIT_WITHIN)
                    ),
                );
            }
        }
    }

    /// The game ran (`why`): the mark, if set, is taken off.
    fn clear_failed_launch(&mut self, why: &str, log: &mut impl Log) {
        if self.failed_launch.take().is_some() {
            self.dirty = true;
            log.line(
                Level::Info,
                &format!(
                    "failed-launch mark taken off: {why}; the app no longer shows «Игра не \
                     запускается»"
                ),
            );
        }
    }

    /// Whether a launch of the helper's waits for the game's window now (`state.json`'s
    /// `launch_pending`).
    pub fn launch_pending(&self) -> bool {
        self.launch_pending
    }

    /// Whether `state.json` has something new since the last call.
    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    pub fn state_file(
        &self,
        now: Instant,
        wall: SystemTime,
        pid: u32,
        elevated: bool,
    ) -> StateFile {
        let since = wall
            .checked_sub(now.saturating_duration_since(self.since))
            .unwrap_or(wall);
        StateFile {
            format: STATE_FORMAT,
            state: self.state,
            reason: self.reason.clone(),
            since_ms: unix_ms(since),
            updated_ms: unix_ms(wall),
            pid,
            elevated,
            launches: self.period.launches,
            failed_starts: self.period.failed_starts,
            focus_set_foreground: self.totals.focus_set_foreground,
            focus_uia: self.totals.focus_uia,
            focus_refused: self.totals.focus_refused,
            launch_pending: self.launch_pending,
            failed_launch_since_ms: self.failed_launch.map(|since| since.unix_ms(now, wall)),
        }
    }

    pub fn tick(
        &mut self,
        now: Instant,
        signal: Signal,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) {
        self.step(now, signal, desktop, log);
        self.note_launch_pending(now, log);
    }

    /// Whether a launch of the helper's waits for the game's window — and why, either way. Only
    /// while allowed, with nothing asking for the setup and not given up: a launch of this session
    /// whose window has not come, or a game the helper is about to launch again — its window gone
    /// while its process runs (counted toward [`WINDOW_LOST_AFTER`]) or being closed as hung — when
    /// a launch follows the closing ([`Self::relaunch_after_hang`]; not after Windows refused it).
    fn launch_pending_now(&self, now: Instant) -> (bool, String) {
        if !self.allowed {
            return (false, "not allowed by the app".to_string());
        }
        if self.needs_setup.is_some() {
            return (false, "the setup is needed again".to_string());
        }
        if self.period.gave_up {
            return (false, format!("given up ({})", self.period.gave_up_why));
        }
        if let Some(closing) = &self.period.closing {
            if matches!(closing.stage, Stage::Refused) {
                return (
                    false,
                    "the game hangs and Windows refused to close it: nothing more is tried until \
                     it goes, its window comes back or the session ends"
                        .to_string(),
                );
            }
            // TerminateProcess went through and the game outlived its grace after it: nothing
            // more is tried until it goes — no launch is in sight (said once, by the warning).
            if let Stage::Ended {
                at,
                late_noted: true,
            } = closing.stage
            {
                return (
                    false,
                    format!(
                        "the hung game still runs {} after TerminateProcess: nothing more is \
                         tried until it goes, its window comes back or the session ends",
                        secs(now.saturating_duration_since(at))
                    ),
                );
            }
            return match self.relaunch_after_hang(now, closing.gone_at) {
                Ok(how) => (
                    true,
                    format!(
                        "closing the hung game: {} ({} ago), then launching it again ({how})",
                        closing.stage.describe(),
                        secs(now.saturating_duration_since(closing.at))
                    ),
                ),
                Err(why) => (
                    false,
                    format!(
                        "the game hangs and is being closed ({}), but {why}",
                        closing.stage.describe()
                    ),
                ),
            };
        }
        if let Some(blind) = self.period.blind.as_ref().filter(|b| b.lost) {
            let gone = now.saturating_duration_since(blind.since);
            let owner = self.window_owner.unwrap_or_default();
            let starting = &self.period.starting_loaders;
            // A launch exe started after the window went holds the closing off as long as it
            // runs (`watch_window`) — a patch, a launcher waiting for «Play», someone at the PC:
            // past the bound a loader of the helper's own launch gets, no launch is in sight.
            if !starting.is_empty() && gone >= LAUNCHER_WAIT_MAX {
                return (
                    false,
                    format!(
                        "its window has been gone {} while its process (pid {owner}) runs, and a \
                         launch exe started after it went still runs (pids {starting:?}), past {}: \
                         the closing waits for it, and nothing says the game is starting — it \
                         may be patching, or waiting for someone",
                        mins(gone),
                        mins(LAUNCHER_WAIT_MAX)
                    ),
                );
            }
            let when = if !starting.is_empty() {
                format!(
                    "{} after the launch exe running beside it (pids {starting:?}) exits",
                    secs(HANDOVER_WITHIN)
                )
            } else if let Some(at) = self.period.loader_at.filter(|at| *at >= blind.since) {
                format!(
                    "at {} since it went, and not before {} after the launch exe that ran \
                     meanwhile exited ({} ago)",
                    secs(WINDOW_LOST_AFTER),
                    secs(HANDOVER_WITHIN),
                    secs(now.saturating_duration_since(at))
                )
            } else {
                format!("at {}", secs(WINDOW_LOST_AFTER))
            };
            return match self.relaunch_after_hang(now, blind.since) {
                Ok(how) => (
                    true,
                    format!(
                        "its window is gone {} while its process (pid {owner}) runs: the helper \
                         closes it as hung {when} and launches it again ({how})",
                        secs(gone)
                    ),
                ),
                Err(why) => (
                    false,
                    format!(
                        "the game's window went and its process runs on (counted as maybe hung), \
                         but {why}"
                    ),
                ),
            };
        }
        match &self.period.launch {
            None => (
                false,
                "no launch of the helper's this session waits for the window (none yet, or the \
                 last one is over)"
                    .to_string(),
            ),
            // Come at the launch, or back after it went (a count toward closing the game ended).
            Some(launch) if launch.window_seen => (
                false,
                format!(
                    "the game's window is up, {} after the helper's launch",
                    secs(now.saturating_duration_since(launch.at))
                ),
            ),
            Some(Launch {
                at,
                pid,
                handover_since: Some(since),
                ..
            }) => (
                true,
                format!(
                    "launched pid {pid} {} ago; its loader went {} ago with nothing of the game \
                     after it — the game's process is waited for up to {}",
                    secs(now.saturating_duration_since(*at)),
                    secs(now.saturating_duration_since(*since)),
                    secs(HANDOVER_WITHIN)
                ),
            ),
            Some(launch) => (
                true,
                format!(
                    "launched pid {} {} ago, its window not up yet (game pids running: {})",
                    launch.pid,
                    secs(now.saturating_duration_since(launch.at)),
                    if self.running { "yes" } else { "none yet" }
                ),
            ),
        }
    }

    /// A hung game closed — counted gone at `gone_at`, as [`Self::follow_game`] will count it —
    /// whether the helper launches it again: `Ok` with when, `Err` why not. The closing ends this
    /// session's launch of the helper's, if one runs: as a failed start unless it ran
    /// [`FAST_EXIT_WITHIN`] with its window up at the mark — and the last allowed failed start
    /// gives up ([`MAX_FAILED_STARTS`]), nothing launched after it. (Given up already, or the setup
    /// needed: the caller has said so first. The record always names a launch exe: one without is
    /// refused at load.)
    fn relaunch_after_hang(&self, now: Instant, gone_at: Instant) -> Result<String, String> {
        let Some(launch) = &self.period.launch else {
            return Ok(format!(
                "not launched by the helper this session: {}",
                self.relaunch_when(now, gone_at, self.period.failed_starts)
            ));
        };
        let ran = gone_at.saturating_duration_since(launch.at);
        if ran >= FAST_EXIT_WITHIN && launch.window_seen && launch.survived {
            return Ok(format!(
                "a normal run of {} after the helper's launch: {}",
                secs(ran),
                self.relaunch_when(now, gone_at, 0)
            ));
        }
        let n = self.period.failed_starts + 1;
        if n >= MAX_FAILED_STARTS {
            return Err(format!(
                "its closing ends the helper's launch (pid {}, {} before the game went) as failed \
                 start {n} of {MAX_FAILED_STARTS} in a row: the helper gives up then and launches \
                 nothing more this session",
                launch.pid,
                secs(ran)
            ));
        }
        Ok(format!(
            "failed start {n} of {MAX_FAILED_STARTS} in a row for the helper's launch (pid {}, {} \
             before the game went): {}",
            launch.pid,
            secs(ran),
            self.relaunch_when(now, gone_at, n)
        ))
    }

    /// When the launch after a hung game's closing comes — [`Self::next_launch_at`] as it will
    /// be once the game is gone (counted gone at `gone_at`, `failed` failed starts in a row then):
    /// at once, or after what is left of the pause, during which nothing is pending.
    fn relaunch_when(&self, now: Instant, gone_at: Instant, failed: u32) -> String {
        let Some(last) = self.period.last_launch else {
            return "launched as soon as it is gone".to_string();
        };
        let min = last + LAUNCH_MIN_INTERVAL;
        let due = if failed > 0 {
            min.max(gone_at + backoff(failed))
        } else {
            min
        };
        if due <= now {
            return "launched as soon as it is gone".to_string();
        }
        format!(
            "launched again once it is gone, not before {} from now ({}); not pending while it \
             waits",
            secs(due - now),
            if failed > 0 {
                format!(
                    "the pause after {failed} failed start(s) in a row: {} from when it counts as \
                     gone",
                    secs(backoff(failed))
                )
            } else {
                format!("{} after the last launch", secs(LAUNCH_MIN_INTERVAL))
            }
        )
    }

    /// A relaunch predicted while the game was closed did not come: allowed, no setup needed, not
    /// given up, the game gone, no launch of the helper's running and none held off by a pause
    /// ([`Self::next_launch_at`]) — `Some` with what the helper sees. `None` for every way a
    /// prediction legitimately ends: the window back, the signal off, a refusal, the pause.
    fn relaunch_drift(&self, now: Instant) -> Option<String> {
        if !self.allowed || self.needs_setup.is_some() || self.period.gave_up || self.running {
            return None;
        }
        if self.period.launch.is_some() {
            return None;
        }
        if self.next_launch_at().is_some_and(|due| due > now) {
            return None;
        }
        Some(format!(
            "the game is gone, no launch of the helper's runs, no pause holds one (failed starts \
             {}, last launch {})",
            self.period.failed_starts,
            self.period
                .last_launch
                .map_or("none".to_string(), |at| format!(
                    "{} ago",
                    secs(now.saturating_duration_since(at))
                ))
        ))
    }

    /// `launch_pending` for `state.json`: a change is logged with why and written at once — the
    /// viewer's «Игра запускается» begins and ends with it.
    fn note_launch_pending(&mut self, now: Instant, log: &mut impl Log) {
        let (pending, why) = self.launch_pending_now(now);
        let was_relaunch = std::mem::replace(
            &mut self.pending_relaunch,
            pending
                && (self.period.closing.is_some()
                    || self.period.blind.as_ref().is_some_and(|b| b.lost)),
        );
        if pending == self.launch_pending {
            return;
        }
        // On for a launch predicted after closing the game, off now with the game gone, nothing
        // launched and no pause holding the launch: the prediction and what the helper did
        // part ways — a defect to see in the log, not something the viewer should guess at.
        if !pending && was_relaunch {
            if let Some(drift) = self.relaunch_drift(now) {
                log.line(
                    Level::Warn,
                    &format!(
                        "launch pending goes off without the launch it promised ({drift}); now: \
                         {why}"
                    ),
                );
            }
        }
        self.launch_pending = pending;
        self.dirty = true;
        log.line(
            Level::Info,
            &format!(
                "launch pending {} ({why}){}",
                if pending { "on" } else { "off" },
                if pending {
                    ": the viewer is told the game is starting"
                } else {
                    ""
                }
            ),
        );
    }

    fn step(
        &mut self,
        now: Instant,
        signal: Signal,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) {
        self.note_signal(now, signal, log);
        if let Some(why) = self.needs_setup.clone() {
            self.set_state(now, HelperState::NeedsSetup, why, log);
            return;
        }
        if !self.allowed {
            self.idle(now, log);
            return;
        }
        let obs = match desktop.observe(&self.record) {
            Ok(obs) => {
                if self.observe_failures > 0 {
                    log.line(
                        Level::Info,
                        &format!(
                            "processes and windows read again after {} failed tries",
                            self.observe_failures
                        ),
                    );
                    self.observe_failures = 0;
                }
                obs
            }
            Err(e) => {
                self.observe_failures += 1;
                // Once, then once a minute while it lasts.
                if self.observe_failures % 120 == 1 {
                    log.line(
                        Level::Warn,
                        &format!(
                            "processes and windows not read ({e}); nothing is done on such a tick \
                             (failure {} in a row)",
                            self.observe_failures
                        ),
                    );
                }
                return;
            }
        };
        if let Some((pid, code)) = obs.launched_exit {
            log.line(
                Level::Info,
                &format!(
                    "the process the helper started (pid {pid}) exited with code {}",
                    code.map_or("-".to_string(), |c| c.to_string())
                ),
            );
        }
        self.note_unreadable(&obs, log);
        let running = !obs.game_pids.is_empty() || !obs.unreadable.is_empty();
        self.follow_game(now, running, &obs, log);
        self.follow_window(now, &obs, log);
        if running {
            self.watch_window(now, &obs, desktop, log);
        } else {
            self.maybe_launch(now, desktop, log);
        }
        // The signal went off during this tick, seen right before an action: nothing more on it.
        if !self.allowed {
            self.idle(now, log);
            return;
        }
        let (state, reason) = self.state_now(running, &obs);
        self.set_state(now, state, reason, log);
        if self.needs_setup.is_none() {
            self.focus(now, &obs, desktop, log);
            if !self.allowed {
                self.idle(now, log);
                return;
            }
        }
        self.summary(now, &obs, log);
    }

    /// Not allowed: nothing is done.
    fn idle(&mut self, now: Instant, log: &mut impl Log) {
        self.set_state(
            now,
            HelperState::Idle,
            "not allowed by the app: nothing is done".to_string(),
            log,
        );
    }

    /// Right before an action (`action`, for the log): the app's signal read again — the tick's own
    /// read, at `now`, may be seconds old. Still set: `true`, act. Otherwise the action is not done,
    /// and the signal's going off is taken in at once ([`Self::note_signal`]): a closing begun and
    /// the count toward one stop with it, and the rest of the tick does nothing (`step`).
    fn act_allowed(
        &mut self,
        now: Instant,
        action: &str,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) -> bool {
        let signal = desktop.signal();
        let after = desktop.now().saturating_duration_since(now);
        if signal == Signal::Allowed {
            log.line(
                Level::Debug,
                &format!(
                    "the app's signal read again before {action}: still set ({} after the tick's \
                     read)",
                    secs(after)
                ),
            );
            return true;
        }
        log.line(
            Level::Info,
            &format!(
                "the app's signal went off during this tick (read {} ago): {action} not done",
                secs(after)
            ),
        );
        self.note_signal(now, signal, log);
        false
    }

    /// A tick's read of the signal set, the last one at `seen` and this one at `now`: further apart
    /// than [`SIGNAL_GAP_MAX`] (a slow tick), the helper cannot vouch the signal stayed set — the
    /// app may have ended a session and begun another in between. The count toward closing a game
    /// whose window went starts over, and a closing begun is dropped (counted again from its lost
    /// window): neither counts time the helper did not see allowed. A launch's own count
    /// ([`WINDOW_WITHIN`] after the helper's launch) is anchored on that launch, and stays; so does
    /// a wait for its loader's handover, from the look that found the game gone (a launch after it
    /// reads the signal again, as any).
    fn note_gap(&mut self, now: Instant, seen: Instant, log: &mut impl Log) {
        let gap = now.saturating_duration_since(seen);
        if gap <= SIGNAL_GAP_MAX {
            return;
        }
        let mut restarted = Vec::new();
        if let Some(closing) = self.period.closing.take() {
            restarted.push(format!(
                "the closing of the hung game is dropped ({}, begun {} ago; pids {:?}) — counted \
                 again from its window",
                closing.stage.describe(),
                secs(now.saturating_duration_since(closing.at)),
                closing.pids
            ));
        }
        if let Some(blind) = self.period.blind.take_if(|blind| blind.lost) {
            restarted.push(format!(
                "the count for the game's lost window starts over (it was at {})",
                secs(now.saturating_duration_since(blind.since))
            ));
        }
        if restarted.is_empty() {
            log.line(
                Level::Debug,
                &format!(
                    "the app's signal was not read for {} (over {}: a slow tick); no count toward \
                     closing the game runs",
                    secs(gap),
                    secs(SIGNAL_GAP_MAX)
                ),
            );
            return;
        }
        self.dirty = true;
        log.line(
            Level::Info,
            &format!(
                "the app's signal was not read for {} (over {}: a slow tick) — the app may have \
                 ended a session and begun another meanwhile: {}",
                secs(gap),
                secs(SIGNAL_GAP_MAX),
                restarted.join("; ")
            ),
        );
    }

    fn note_signal(&mut self, now: Instant, signal: Signal, log: &mut impl Log) {
        let allowed = signal == Signal::Allowed;
        if self.signal.as_ref() != Some(&signal) {
            log.line(
                Level::Info,
                &format!(
                    "the app's signal: {} (was {})",
                    signal.describe(),
                    self.signal
                        .as_ref()
                        .map_or("not read yet".to_string(), Signal::describe)
                ),
            );
            self.signal = Some(signal);
        }
        if allowed && self.allowed {
            if let Some(seen) = self.signal_seen_at {
                self.note_gap(now, seen, log);
            }
        }
        if allowed && !self.allowed {
            let before = (self.period.failed_starts, self.period.gave_up);
            // A decision, not an oversight (`nothing_is_closed_outside_a_session_and_a_new_…`,
            // `a_count_toward_closing_starts_over_…`): the count toward closing a game whose
            // window went is the session's — said here, not kept.
            if let (Some(owner), Some(gone)) = (self.window_owner, self.window_gone_at) {
                log.line(
                    Level::Debug,
                    &format!(
                        "the window of pid {owner} has been gone {} (as far as the helper saw); the \
                         count toward closing it starts over: a new session — someone at the PC \
                         may be at it",
                        secs(now.saturating_duration_since(gone))
                    ),
                );
            }
            self.period = Period::default();
            self.last_summary = now;
            log.line(
                Level::Info,
                &format!(
                    "allowed: the game is launched if it is not running, and brought back to the \
                     front{}{}",
                    match before {
                        (_, true) => "; the last session's give-up is over",
                        (0, false) => "",
                        _ => "; the last session's failed starts are forgotten",
                    },
                    if self.failed_launch.is_some() {
                        "; the failed-launch mark stays until the game runs a minute with its window"
                    } else {
                        ""
                    }
                ),
            );
        }
        if !allowed && self.allowed {
            log.line(
                Level::Info,
                "not allowed any more: nothing is done, the game is left as it is",
            );
            // Nothing is closed outside a session: a closing begun, or a count running, stops here.
            if let Some(closing) = self.period.closing.take() {
                log.line(
                    Level::Info,
                    &format!(
                        "the closing of the hung game stops with it ({}, begun {} ago; pids {:?})",
                        closing.stage.describe(),
                        secs(now.saturating_duration_since(closing.at)),
                        closing.pids
                    ),
                );
            }
            if let Some(blind) = self.period.blind.take() {
                if blind.lost {
                    log.line(
                        Level::Info,
                        &format!(
                            "the count for the game's lost window stops with it, at {}",
                            secs(now.saturating_duration_since(blind.since))
                        ),
                    );
                }
            }
            // A wait for a loader's handover is the session's: it ends here, no failed start
            // counted, and the next session's period starts without it.
            if let Some(launch) = self.period.launch.as_mut() {
                if let Some(since) = launch.handover_since.take() {
                    log.line(
                        Level::Info,
                        &format!(
                            "the wait for the handover of the launched loader (pid {}, {}) stops \
                             with it, {} after its loader went: no failed start is counted, \
                             nothing is launched",
                            launch.pid,
                            launch.exit_note(),
                            secs(now.saturating_duration_since(since))
                        ),
                    );
                }
            }
            self.left_alone = None;
        }
        self.allowed = allowed;
        // Read off (here or right before an action), nothing is watched until a tick reads it set.
        self.signal_seen_at = allowed.then_some(now);
    }

    fn note_unreadable(&mut self, obs: &Observation, log: &mut impl Log) {
        if obs.unreadable == self.unreadable {
            return;
        }
        if obs.unreadable.is_empty() {
            log.line(
                Level::Info,
                &format!(
                    "the unreadable processes named like the game are gone (pids {:?})",
                    self.unreadable
                ),
            );
        } else {
            log.line(
                Level::Warn,
                &format!(
                    "processes named like the game cannot be read (pids {:?}, access denied): \
                     counted as maybe the game, so it is not launched beside them, and never closed",
                    obs.unreadable
                ),
            );
        }
        self.unreadable = obs.unreadable.clone();
    }

    /// A launch's fate — its window, a run long enough, or a failed start — and the game coming or
    /// going without one. A game the helper closed counts as gone when its window went; a loader
    /// gone with nothing of the game after it is first waited for ([`Self::handover`]).
    fn follow_game(&mut self, now: Instant, running: bool, obs: &Observation, log: &mut impl Log) {
        let was = std::mem::replace(&mut self.running, running);
        let closed = if running {
            None
        } else {
            self.period.closing.take()
        };
        let gone_at = closed.as_ref().map_or(now, |c| c.gone_at);
        if let Some(closing) = &closed {
            log.line(
                Level::Info,
                &format!(
                    "the hung game is gone {} after the helper began closing it ({}); it counts \
                     as gone {} ago, when {}",
                    secs(now.saturating_duration_since(closing.at)),
                    closing.stage.describe(),
                    secs(now.saturating_duration_since(closing.gone_at)),
                    if closing.lost {
                        "its window went"
                    } else {
                        "the helper found it hung"
                    }
                ),
            );
        }
        if !running {
            self.period.blind = None;
            self.window_owner = None;
            self.window_gone_at = None;
            self.resident_loaders.clear();
        }
        let closed_note = if closed.is_some() {
            "; closed by the helper: it hung"
        } else {
            ""
        };
        let has_loader = self.record.is_loader(&self.record.launch_exe);
        if let Some(launch) = self.period.launch.as_mut() {
            let after = now.saturating_duration_since(launch.at);
            if let Some((_, code)) = obs.launched_exit.filter(|(pid, _)| *pid == launch.pid) {
                launch.exit = Some(code);
                // Exited between the look's exit check and its process list: seen a look after
                // the wait began.
                if let Some(since) = launch.handover_since {
                    log.line(
                        Level::Debug,
                        &format!(
                            "the launched loader (pid {}) {}: seen {} into the wait for its \
                             handover",
                            launch.pid,
                            launch.exit_note(),
                            secs(now.saturating_duration_since(since))
                        ),
                    );
                }
            }
            if running {
                let window_exe: Vec<u32> = obs
                    .game_pids
                    .iter()
                    .copied()
                    .filter(|pid| !obs.loader_pids.contains(pid))
                    .collect();
                if window_exe.is_empty() {
                    if !obs.game_pids.is_empty() {
                        launch.loader_looks += 1;
                    }
                } else if !launch.game_seen {
                    launch.game_seen = true;
                    if has_loader {
                        log.line(
                            Level::Debug,
                            &format!(
                                "a process of the window exe runs {} after the launch (pids \
                                 {window_exe:?}): the loader has handed over — the game gone from \
                                 now on is a failed start at once, with no wait for a handover",
                                secs(after)
                            ),
                        );
                    }
                }
                if let Some(since) = launch.handover_since.take() {
                    log.line(
                        Level::Info,
                        &format!(
                            "the game's process came {} after the launched loader went (pids \
                             {:?}, maybe {:?}; loaders among them {:?}): the wait for the \
                             handover ends — the helper's launch goes on, {} after it, pending \
                             until the game's window",
                            secs(now.saturating_duration_since(since)),
                            obs.game_pids,
                            obs.unreadable,
                            obs.loader_pids,
                            secs(after)
                        ),
                    );
                    self.dirty = true;
                }
            }
            if obs.window.is_some() && !launch.window_seen {
                launch.window_seen = true;
                log.line(
                    Level::Info,
                    &format!("the game's window is up {} after the launch", secs(after)),
                );
            }
            if running {
                // Its window up at the minute's mark, not only once before it.
                if obs.window.is_some() && !launch.survived && after >= FAST_EXIT_WITHIN {
                    launch.survived = true;
                    if self.period.failed_starts > 0 {
                        log.line(
                            Level::Info,
                            &format!(
                                "the game has run {} with its window: the {} failed start(s) \
                                 before are forgotten",
                                secs(after),
                                self.period.failed_starts
                            ),
                        );
                    }
                    self.period.failed_starts = 0;
                    self.dirty = true;
                    self.clear_failed_launch(
                        &format!(
                            "the helper's launch survived — the game's window is up {} after it",
                            secs(after)
                        ),
                        log,
                    );
                }
                return;
            }
            let (pid, at, window_seen, survived) =
                (launch.pid, launch.at, launch.window_seen, launch.survived);
            // A window that came has shown the game ran: only a launch without one may be waiting
            // for its loader's handover.
            let (gone_at, handover_note) = if window_seen {
                (gone_at, String::new())
            } else {
                match self.handover(now, has_loader, closed.is_some(), log) {
                    Handover::Waiting => return,
                    Handover::RanOut(since) => (
                        since,
                        format!(
                            "; nothing of the game came within {} after its loader went",
                            secs(HANDOVER_WITHIN)
                        ),
                    ),
                    Handover::No => (gone_at, String::new()),
                }
            };
            let ran = gone_at.saturating_duration_since(at);
            self.period.launch = None;
            self.period.gone_at = Some(gone_at);
            if ran < FAST_EXIT_WITHIN || !window_seen || !survived {
                self.failed_start(
                    now,
                    format!(
                        "the game is gone {} after the launch (pid {pid}; its window \
                         {}{closed_note}{handover_note})",
                        secs(ran),
                        match (window_seen, survived) {
                            (false, _) => "never came",
                            (true, false) => "was up, but not at the minute's mark",
                            (true, true) => "was up",
                        }
                    ),
                    log,
                );
            } else {
                log.line(
                    Level::Info,
                    &format!(
                        "the game exited {} after the launch, after a normal run{closed_note}; it \
                         is launched again when the pause allows",
                        secs(ran)
                    ),
                );
                self.period.failed_starts = 0;
            }
            return;
        }
        if was && !running {
            self.period.gone_at = Some(gone_at);
            log.line(
                Level::Info,
                &format!(
                    "the game is gone (it was not started by the helper this session{closed_note})"
                ),
            );
        } else if !was && running {
            log.line(
                Level::Info,
                &format!(
                    "the game is running (pids {:?}, maybe {:?}), not started by the helper",
                    obs.game_pids, obs.unreadable
                ),
            );
        }
    }

    /// A launch of the helper's whose window never came, its game gone at this look (`closed`: the
    /// helper closed it as hung): whether its loader's handover is waited for — the wait begun at
    /// this look, still within [`HANDOVER_WITHIN`], or run out — or the game's going is judged now
    /// (the module's «A launch's fate»). Said once each: the wait's start, its end, and why none.
    fn handover(
        &mut self,
        now: Instant,
        has_loader: bool,
        closed: bool,
        log: &mut impl Log,
    ) -> Handover {
        let exe = file_name(&self.record.launch_exe).to_string();
        let Some(launch) = self.period.launch.as_mut() else {
            return Handover::No;
        };
        let after = now.saturating_duration_since(launch.at);
        if let Some(since) = launch.handover_since {
            let waited = now.saturating_duration_since(since);
            if waited < HANDOVER_WITHIN {
                return Handover::Waiting;
            }
            log.line(
                Level::Info,
                &format!(
                    "nothing of the game came {} after the launched loader {exe} (pid {}, {}) \
                     went: the wait for its handover is over — the launch failed; the game counts \
                     as gone {} ago, at the look that found it gone, {} after the launch",
                    secs(waited),
                    launch.pid,
                    launch.exit_note(),
                    secs(waited),
                    secs(since.saturating_duration_since(launch.at))
                ),
            );
            return Handover::RanOut(since);
        }
        let no_wait = if !has_loader {
            Some("the launch exe is the window exe: no loader to hand over".to_string())
        } else if closed {
            Some("the helper closed the game as hung".to_string())
        } else if launch.game_seen {
            Some(
                "a process of the window exe ran since the launch: the loader had handed over"
                    .to_string(),
            )
        } else if after >= LAUNCHER_WAIT_MAX {
            Some(format!(
                "the launch was {} ago: its loader has had its {}",
                mins(after),
                mins(LAUNCHER_WAIT_MAX)
            ))
        } else {
            None
        };
        if let Some(why) = no_wait {
            log.line(
                Level::Debug,
                &format!(
                    "the game is gone {} after the launch (pid {}, {}), its window never up: no \
                     wait for a handover — {why}",
                    secs(after),
                    launch.pid,
                    launch.exit_note()
                ),
            );
            return Handover::No;
        }
        launch.handover_since = Some(now);
        launch.handovers += 1;
        log.line(
            Level::Info,
            &format!(
                "nothing of the game runs {} after the launch, and the launched loader {exe} (pid \
                 {}, {}) is gone; no process of the window exe has run since the launch ({}) — the \
                 loader may be handing over to a process the record does not know: waiting up to \
                 {} for the game's process before this counts as a failed start; the launch stays \
                 pending, nothing is launched meanwhile{}",
                secs(after),
                launch.pid,
                launch.exit_note(),
                match launch.loader_looks {
                    0 => "the loader itself not seen running at a look".to_string(),
                    n => format!("only the loader seen running, at {n} look(s)"),
                },
                secs(HANDOVER_WITHIN),
                if launch.handovers > 1 {
                    format!(" (wait {} of this launch)", launch.handovers)
                } else {
                    String::new()
                }
            ),
        );
        self.dirty = true;
        Handover::Waiting
    }

    /// The game's window on every look since when: up [`FAST_EXIT_WITHIN`] on end, the game runs —
    /// the failed-launch mark comes off, however the game was started (a launch of the helper's
    /// usually takes it off sooner, by surviving: [`Self::follow_game`]).
    fn follow_window(&mut self, now: Instant, obs: &Observation, log: &mut impl Log) {
        if obs.window.is_none() {
            self.period.window_since = None;
            return;
        }
        let since = *self.period.window_since.get_or_insert(now);
        let up = now.saturating_duration_since(since);
        if up >= FAST_EXIT_WITHIN && self.failed_launch.is_some() {
            self.clear_failed_launch(
                &format!(
                    "the game's window has been up {} on end ({})",
                    secs(up),
                    if self.period.launch.is_some() {
                        "launched by the helper this session"
                    } else {
                        "not launched by the helper this session: by hand, or before it"
                    }
                ),
                log,
            );
        }
    }

    fn failed_start(&mut self, now: Instant, what: String, log: &mut impl Log) {
        self.period.failed_starts += 1;
        self.dirty = true;
        let n = self.period.failed_starts;
        if self.period.gave_up {
            log.line(
                Level::Warn,
                &format!(
                    "{what}: failed start {n} in a row; no launches until the next session anyway \
                     ({})",
                    self.period.gave_up_why
                ),
            );
        } else if n >= MAX_FAILED_STARTS {
            log.line(
                Level::Error,
                &format!(
                    "{what}: failed start {n} of {MAX_FAILED_STARTS} in a row — no more launches \
                     until the next session"
                ),
            );
            self.give_up(
                now,
                format!("{MAX_FAILED_STARTS} failed starts in a row"),
                log,
            );
        } else {
            log.line(
                Level::Warn,
                &format!(
                    "{what}: failed start {n} of {MAX_FAILED_STARTS} in a row; the next launch \
                     waits {} after it",
                    secs(backoff(n).max(LAUNCH_MIN_INTERVAL))
                ),
            );
        }
    }

    /// No more launches this session — and the failed-launch mark, which outlives it.
    fn give_up(&mut self, now: Instant, why: String, log: &mut impl Log) {
        self.mark_failed_launch(now, &why, log);
        self.period.gave_up = true;
        self.period.gave_up_why = why;
        self.dirty = true;
    }

    /// When the next launch is due: `None` for the first one of a session — at once.
    fn next_launch_at(&self) -> Option<Instant> {
        let last = self.period.last_launch?;
        let min = last + LAUNCH_MIN_INTERVAL;
        let paused = match self.period.gone_at {
            Some(gone) if self.period.failed_starts > 0 => {
                gone + backoff(self.period.failed_starts)
            }
            _ => min,
        };
        Some(min.max(paused))
    }

    fn maybe_launch(&mut self, now: Instant, desktop: &mut impl Desktop, log: &mut impl Log) {
        if self.period.gave_up {
            return;
        }
        // The last launch waits for its loader's handover: it is not over — whatever the pause
        // since it ([`LAUNCH_MIN_INTERVAL`] may pass meanwhile). Said when the wait began.
        if self
            .period
            .launch
            .as_ref()
            .is_some_and(|launch| launch.handover_since.is_some())
        {
            return;
        }
        let due = self.next_launch_at();
        let why = match (self.period.last_launch, self.period.failed_starts) {
            (None, _) => "the first launch this session".to_string(),
            (Some(_), 0) => "the game is not running".to_string(),
            (Some(_), n) => format!("after {n} failed start(s), a pause of {}", secs(backoff(n))),
        };
        if let Some(due) = due.filter(|due| now < *due) {
            if !self.period.waiting_noted {
                self.period.waiting_noted = true;
                log.line(
                    Level::Info,
                    &format!(
                        "the game is not running; the next launch in {} ({why})",
                        secs(due - now)
                    ),
                );
            }
            return;
        }
        self.period.waiting_noted = false;
        let exe = self.record.launch_exe.clone();
        if !self.act_allowed(now, &format!("launching {exe} ({why})"), desktop, log) {
            return;
        }
        log.line(Level::Info, &format!("launching {exe}: {why}"));
        self.period.last_launch = Some(now);
        self.dirty = true;
        match desktop.launch(&exe) {
            Ok(pid) => {
                self.period.launches += 1;
                self.period.launch = Some(Launch::new(now, pid));
                log.line(
                    Level::Info,
                    &format!(
                        "started {} as pid {pid} (launch {} this session)",
                        file_name(&exe),
                        self.period.launches
                    ),
                );
            }
            Err(LaunchError::ElevationRequired) => {
                self.needs_setup = Some(
                    "Windows needs administrator for the launch exe and this task runs without \
                     (ERROR_ELEVATION_REQUIRED, 740)"
                        .to_string(),
                );
                log.line(
                    Level::Error,
                    &format!(
                        "launching {exe}: Windows answered ERROR_ELEVATION_REQUIRED (740) — the \
                         exe needs administrator and this task runs without; no more launches \
                         until the owner confirms the setup again"
                    ),
                );
            }
            Err(LaunchError::NotFound(e) | LaunchError::Other(e)) => {
                self.period.gone_at = Some(now);
                self.failed_start(now, format!("launching {exe} failed ({e})"), log);
            }
        }
    }

    /// The game runs: its window up, or how long it has not been, and a hung game closed (the
    /// module's «A game that hangs»).
    fn watch_window(
        &mut self,
        now: Instant,
        obs: &Observation,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) {
        if let Some(window) = obs.window {
            self.window_up(now, window, obs, log);
            return;
        }
        if let Some(owner) = self.window_owner {
            if !obs.game_pids.contains(&owner) && !obs.unreadable.contains(&owner) {
                log.line(
                    Level::Debug,
                    &format!(
                        "the process that showed the game's window (pid {owner}) is gone; game \
                         pids now {:?}",
                        obs.game_pids
                    ),
                );
                self.window_owner = None;
                self.window_gone_at = None;
            }
        }
        let starting: Vec<u32> = obs
            .loader_pids
            .iter()
            .copied()
            .filter(|pid| !self.resident_loaders.contains(pid))
            .collect();
        if !starting.is_empty() {
            self.period.loader_at = Some(now);
        }
        self.period.starting_loaders.clone_from(&starting);
        if self.period.closing.is_some() {
            self.continue_closing(now, obs, desktop, log);
            return;
        }
        // Only processes whose path was read are ever closed: with none, there is nothing to count.
        if obs.game_pids.is_empty() {
            self.period.blind = None;
            return;
        }
        let lost = self
            .window_owner
            .is_some_and(|owner| obs.game_pids.contains(&owner));
        let launched = self
            .period
            .launch
            .as_ref()
            .filter(|launch| !launch.window_seen)
            .map(|launch| launch.at);
        match (&self.period.blind, lost, launched) {
            (Some(blind), _, _) if blind.lost == lost && (lost || launched.is_some()) => {}
            (_, true, _) => {
                let first_seen = *self.window_gone_at.get_or_insert(now);
                let in_all = now.saturating_duration_since(first_seen);
                log.line(
                    Level::Info,
                    &format!(
                        "the game's window is gone; the process that showed it (pid {}) runs \
                         (game pids {:?}): closed as hung if the window is not back within {}{}",
                        self.window_owner.unwrap_or_default(),
                        obs.game_pids,
                        secs(WINDOW_LOST_AFTER),
                        if in_all.is_zero() {
                            String::new()
                        } else {
                            format!(
                                " — counted from now; gone {} in all (since an earlier session or \
                                 count)",
                                secs(in_all)
                            )
                        }
                    ),
                );
                self.period.blind = Some(Blind {
                    lost: true,
                    since: now,
                    loader_noted: false,
                });
                self.dirty = true;
            }
            (_, false, Some(at)) => {
                self.period.blind = Some(Blind {
                    lost: false,
                    since: at,
                    loader_noted: false,
                });
            }
            // Started by someone else (or by the game itself) after its window's process went: the
            // person at the PC, or the game, is at it.
            (_, false, None) => {
                self.period.blind = None;
                return;
            }
        }
        let gave_up = self.period.gave_up;
        let loader_at = self.period.loader_at;
        let Some(blind) = self.period.blind.as_mut() else {
            return;
        };
        let waited = now.saturating_duration_since(blind.since);
        let budget = if blind.lost {
            WINDOW_LOST_AFTER
        } else {
            WINDOW_WITHIN
        };
        if !starting.is_empty() {
            if !blind.lost && waited >= LAUNCHER_WAIT_MAX && !gave_up {
                let why = format!(
                    "the launch exe has run {} with no game window (its launcher may be waiting \
                     for «Play»)",
                    mins(waited)
                );
                log.line(
                    Level::Error,
                    &format!(
                        "no game window {} after the launch, and the launch exe still runs (pids \
                         {starting:?}; game pids {:?}): the helper gives up until the next \
                         session; the launch exe is left running — it may be patching, or \
                         waiting for someone",
                        secs(waited),
                        obs.game_pids
                    ),
                );
                self.give_up(now, why, log);
                return;
            }
            if waited >= budget && !blind.loader_noted {
                blind.loader_noted = true;
                log.line(
                    Level::Warn,
                    &format!(
                        "no game window {} {}, and the launch exe runs (pids {starting:?}; a \
                         patch, or a launcher waiting for «Play»?): waiting — the game is closed \
                         as hung if its window is not up {} after the launch exe exits{}",
                        secs(waited),
                        if blind.lost {
                            "since it went"
                        } else {
                            "after the launch"
                        },
                        secs(HANDOVER_WITHIN),
                        if blind.lost {
                            String::new()
                        } else {
                            format!(
                                "; the helper gives up if it still runs {} after the launch",
                                mins(LAUNCHER_WAIT_MAX)
                            )
                        }
                    ),
                );
            }
            return;
        }
        if waited < budget {
            return;
        }
        if let Some(at) = loader_at.filter(|at| *at >= blind.since) {
            if now.saturating_duration_since(at) < HANDOVER_WITHIN {
                return;
            }
        }
        if gave_up {
            // Nothing would be launched after it: the game is left as it is.
            return;
        }
        self.begin_closing(now, obs, desktop, log);
    }

    fn window_up(
        &mut self,
        now: Instant,
        window: GameWindow,
        obs: &Observation,
        log: &mut impl Log,
    ) {
        if self.window_owner != Some(window.pid) {
            log.line(
                Level::Debug,
                &format!(
                    "the game's window belongs to pid {} (game pids {:?}, loaders beside it {:?})",
                    window.pid, obs.game_pids, obs.loader_pids
                ),
            );
            self.window_owner = Some(window.pid);
        }
        self.window_gone_at = None;
        if self.resident_loaders != obs.loader_pids {
            self.resident_loaders.clone_from(&obs.loader_pids);
        }
        if let Some(closing) = self.period.closing.take() {
            log.line(
                Level::Info,
                &format!(
                    "the game's window is back {} after the helper began closing it ({}): the \
                     closing stops",
                    secs(now.saturating_duration_since(closing.at)),
                    closing.stage.describe()
                ),
            );
            self.dirty = true;
        }
        if let Some(blind) = self.period.blind.take() {
            if blind.lost {
                log.line(
                    Level::Info,
                    &format!(
                        "the game's window is back after {}: not closed",
                        secs(now.saturating_duration_since(blind.since))
                    ),
                );
                self.dirty = true;
            }
        }
    }

    fn begin_closing(
        &mut self,
        now: Instant,
        obs: &Observation,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) {
        if self.period.blind.is_none() {
            return;
        }
        // Before the count is taken: a signal gone off stops it (`note_signal`), at its figure.
        if !self.act_allowed(
            now,
            &format!(
                "closing the hung game (WM_CLOSE to the windows of pids {:?})",
                obs.game_pids
            ),
            desktop,
            log,
        ) {
            return;
        }
        let Some(blind) = self.period.blind.take() else {
            return;
        };
        let waited = now.saturating_duration_since(blind.since);
        let what = if blind.lost {
            format!(
                "its window has been gone {} and the process that showed it (pid {}) runs",
                secs(waited),
                self.window_owner.unwrap_or_default()
            )
        } else {
            format!(
                "no game window {} after the launch, {}",
                secs(waited),
                match self.period.loader_at.filter(|at| *at >= blind.since) {
                    Some(at) => format!(
                        "its launch exe gone {} ago",
                        secs(now.saturating_duration_since(at))
                    ),
                    None => "no launch exe seen running".to_string(),
                }
            )
        };
        log.line(
            Level::Warn,
            &format!(
                "the game hangs: {what} (game pids {:?}{}) — closing it: WM_CLOSE to its windows, \
                 TerminateProcess if it is still there after {}",
                obs.game_pids,
                if obs.unreadable.is_empty() {
                    String::new()
                } else {
                    format!("; unreadable pids {:?} are not touched", obs.unreadable)
                },
                secs(CLOSE_GRACE)
            ),
        );
        let request = desktop.close_windows(&self.record, &obs.game_pids);
        log.line(
            Level::Info,
            &format!(
                "closing: {}{}",
                if request.processes.is_empty() {
                    "no process confirmed the game's".to_string()
                } else {
                    request
                        .processes
                        .iter()
                        .map(|p| format!("pid {} ({})", p.pid, p.path))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if request.skipped.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; left alone: {}",
                        request
                            .skipped
                            .iter()
                            .map(|(pid, why)| format!("pid {pid} ({why})"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            ),
        );
        for note in &request.notes {
            log.line(Level::Debug, &format!("closing: {note}"));
        }
        if let Some(e) = &request.windows_error {
            log.line(
                Level::Warn,
                &format!("the windows were not listed ({e}): no WM_CLOSE went out"),
            );
        }
        for window in &request.windows {
            log.line(
                match window.posted {
                    Ok(()) => Level::Info,
                    Err(_) => Level::Warn,
                },
                &format!(
                    "WM_CLOSE to window {:#x} of pid {} (class {:?}, title {:?}): {}",
                    window.window,
                    window.pid,
                    window.class,
                    window.title,
                    match &window.posted {
                        Ok(()) => "posted".to_string(),
                        Err(e) => format!("not posted ({e})"),
                    }
                ),
            );
        }
        if request.windows.is_empty() && !request.processes.is_empty() {
            log.line(
                Level::Info,
                &format!(
                    "no visible window of the game's processes to send WM_CLOSE to: \
                     TerminateProcess after {}",
                    secs(CLOSE_GRACE)
                ),
            );
        }
        let stage = if request.processes.is_empty() {
            log.line(
                Level::Warn,
                "none of the game's processes was confirmed for closing: nothing more is tried \
                 until they go, its window comes back or the session ends",
            );
            Stage::Refused
        } else {
            Stage::Asked
        };
        self.period.closing = Some(Closing {
            at: now,
            gone_at: if blind.lost { blind.since } else { now },
            lost: blind.lost,
            pids: obs.game_pids.clone(),
            processes: request.processes,
            stage,
        });
        self.dirty = true;
    }

    fn continue_closing(
        &mut self,
        now: Instant,
        obs: &Observation,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) {
        let Some(closing) = self.period.closing.as_mut() else {
            return;
        };
        let alive = |pid: &u32| obs.game_pids.contains(pid) || obs.unreadable.contains(pid);
        if !closing.pids.iter().any(alive) {
            log.line(
                Level::Info,
                &format!(
                    "the hung game's processes {:?} are gone {} after the helper began closing it \
                     ({}); others of the game's run now (pids {:?}, maybe {:?})",
                    closing.pids,
                    secs(now.saturating_duration_since(closing.at)),
                    closing.stage.describe(),
                    obs.game_pids,
                    obs.unreadable
                ),
            );
            self.period.closing = None;
            self.dirty = true;
            return;
        }
        match closing.stage {
            Stage::Asked if now.saturating_duration_since(closing.at) >= CLOSE_GRACE => {
                let left: Vec<GameProcess> = closing
                    .processes
                    .iter()
                    .filter(|p| obs.game_pids.contains(&p.pid))
                    .cloned()
                    .collect();
                log.line(
                    Level::Info,
                    &format!(
                        "the hung game is still there {} after WM_CLOSE (pids {:?}): \
                         TerminateProcess",
                        secs(now.saturating_duration_since(closing.at)),
                        left.iter().map(|p| p.pid).collect::<Vec<_>>()
                    ),
                );
                let mut gone = false;
                for process in &left {
                    // Each one right after the signal is read again: gone off, the closing goes
                    // with it (`note_signal`) and what is left is not ended.
                    if !self.act_allowed(
                        now,
                        &format!("TerminateProcess on pid {} ({})", process.pid, process.path),
                        desktop,
                        log,
                    ) {
                        return;
                    }
                    let outcome = desktop.terminate(&self.record, process);
                    let (level, said) = match &outcome {
                        TerminateOutcome::Ended(c) => (
                            Level::Info,
                            format!("ended by TerminateProcess, exit code {}", code(*c)),
                        ),
                        TerminateOutcome::Requested => (
                            Level::Info,
                            "TerminateProcess done; not ended within the short wait".to_string(),
                        ),
                        TerminateOutcome::AlreadyEnded(c) => (
                            Level::Info,
                            format!("had already ended on its own, exit code {}", code(*c)),
                        ),
                        TerminateOutcome::NotTheGame(why) => {
                            (Level::Info, format!("not ended: {why}"))
                        }
                        TerminateOutcome::Denied(e) => (
                            Level::Warn,
                            format!(
                                "not ended: Windows refused (access denied: {e}) — a helper \
                                 without rights and a game with them?"
                            ),
                        ),
                        TerminateOutcome::Failed(e) => (
                            Level::Warn,
                            format!("not ended: TerminateProcess failed ({e})"),
                        ),
                    };
                    log.line(
                        level,
                        &format!("pid {} ({}): {said}", process.pid, process.path),
                    );
                    gone |= !matches!(
                        outcome,
                        TerminateOutcome::Denied(_) | TerminateOutcome::Failed(_)
                    );
                }
                // The signal held for each: the closing is still there.
                let Some(closing) = self.period.closing.as_mut() else {
                    return;
                };
                closing.stage = if gone {
                    Stage::Ended {
                        at: now,
                        late_noted: false,
                    }
                } else {
                    log.line(
                        Level::Warn,
                        &format!(
                            "the hung game could not be ended (pids {:?}): waiting as before; \
                             nothing more is tried until it goes, its window comes back or the \
                             session ends",
                            closing.pids
                        ),
                    );
                    Stage::Refused
                };
                self.dirty = true;
            }
            Stage::Ended {
                at,
                late_noted: false,
            } if now.saturating_duration_since(at) >= CLOSE_GRACE => {
                closing.stage = Stage::Ended {
                    at,
                    late_noted: true,
                };
                log.line(
                    Level::Warn,
                    &format!(
                        "the hung game still runs {} after TerminateProcess (pids {:?}): waiting \
                         for it to exit",
                        secs(now.saturating_duration_since(at)),
                        closing
                            .pids
                            .iter()
                            .filter(|pid| alive(pid))
                            .collect::<Vec<_>>()
                    ),
                );
            }
            _ => {}
        }
    }

    fn state_now(&self, running: bool, obs: &Observation) -> (HelperState, String) {
        if let Some(why) = &self.needs_setup {
            return (HelperState::NeedsSetup, why.clone());
        }
        if running && obs.window.is_some() {
            return (HelperState::Running, "the game's window is up".to_string());
        }
        if self.period.gave_up {
            return (HelperState::GaveUp, self.period.gave_up_why.clone());
        }
        if let Some(closing) = &self.period.closing {
            return (HelperState::Launching, closing.stage.reason());
        }
        if self.period.blind.as_ref().is_some_and(|b| b.lost) {
            return (
                HelperState::Launching,
                format!(
                    "the game's window is gone and the process that showed it runs: closed as \
                     hung if the window is not back within {}",
                    secs(WINDOW_LOST_AFTER)
                ),
            );
        }
        if running && obs.game_pids.is_empty() {
            (
                HelperState::Launching,
                "a process named like the game cannot be read: maybe the game".to_string(),
            )
        } else if running {
            (
                HelperState::Launching,
                "the game's processes run, its window is not up yet".to_string(),
            )
        } else if self
            .period
            .launch
            .as_ref()
            .is_some_and(|launch| launch.handover_since.is_some())
        {
            (
                HelperState::Launching,
                format!(
                    "the launched loader is gone with nothing of the game after it: its handover \
                     is waited for, up to {} for the game's process, then a failed start",
                    secs(HANDOVER_WITHIN)
                ),
            )
        } else if self.period.launch.is_some() {
            (
                HelperState::Launching,
                "launched; its process not seen yet".to_string(),
            )
        } else {
            (
                HelperState::Waiting,
                "the game is not running; the next launch is not due yet".to_string(),
            )
        }
    }

    fn set_state(&mut self, now: Instant, state: HelperState, reason: String, log: &mut impl Log) {
        if state != self.state {
            log.line(
                Level::Info,
                &format!(
                    "state {} -> {} ({reason}), after {} in {}",
                    self.state.as_str(),
                    state.as_str(),
                    secs(now.saturating_duration_since(self.since)),
                    self.state.as_str()
                ),
            );
            self.state = state;
            self.since = now;
            self.reason = reason;
            self.dirty = true;
        } else if reason != self.reason {
            self.reason = reason;
            self.dirty = true;
        }
    }

    fn left_alone(&mut self, why: Option<String>, log: &mut impl Log) {
        if why == self.left_alone {
            return;
        }
        if let Some(why) = &why {
            log.line(Level::Debug, &format!("focus left alone: {why}"));
        }
        self.left_alone = why;
    }

    fn focus(
        &mut self,
        now: Instant,
        obs: &Observation,
        desktop: &mut impl Desktop,
        log: &mut impl Log,
    ) {
        let Some(window) = obs.window else {
            self.left_alone(Some("no game window to bring forward".to_string()), log);
            return;
        };
        let (front, front_exe) = match &obs.foreground {
            Foreground::Game if !window.minimized => {
                let retry = &mut self.period.focus;
                if retry.refused > 0 {
                    log.line(
                        Level::Info,
                        &format!(
                            "the game is in front again after {} refused tries",
                            retry.refused
                        ),
                    );
                }
                *retry = FocusRetry::default();
                self.left_alone(None, log);
                return;
            }
            // Its own window minimized while one of its others is in front: restore it.
            Foreground::Game => (window.id, "the game itself".to_string()),
            Foreground::Nothing => {
                return self.left_alone(
                    Some(
                        "no window is in front (the secure desktop, the lock screen or a switch)"
                            .to_string(),
                    ),
                    log,
                );
            }
            Foreground::AfkLink { exe } => {
                return self.left_alone(
                    Some(format!("AFKLink's own window is in front ({exe})")),
                    log,
                );
            }
            Foreground::Menu { exe } => {
                return self.left_alone(Some(format!("a menu is open in front ({exe})")), log);
            }
            Foreground::Unreadable { error, .. } => {
                return self.left_alone(
                    Some(format!("the window in front cannot be read ({error})")),
                    log,
                );
            }
            Foreground::Other { window, exe } => (*window, exe.clone()),
        };
        self.left_alone(None, log);
        let retry = &mut self.period.focus;
        if retry.refused_on.is_some_and(|w| w != front) {
            log.line(
                Level::Debug,
                &format!(
                    "another window is in front now ({front_exe}): focus tries start over after \
                     {} refused",
                    retry.refused
                ),
            );
            *retry = FocusRetry::default();
        }
        if retry.retry_at.is_some_and(|at| now < at) {
            return;
        }
        let restored = if window.minimized {
            ", the game minimized"
        } else {
            ""
        };
        if !self.act_allowed(
            now,
            &format!("bringing the game's window to the front ({front_exe} in front{restored})"),
            desktop,
            log,
        ) {
            return;
        }
        let outcome = desktop.focus(&self.record, window);
        let retry = &mut self.period.focus;
        self.dirty = true;
        match outcome.method {
            Some(method) => {
                match method {
                    FocusMethod::SetForeground => self.totals.focus_set_foreground += 1,
                    FocusMethod::Uia => self.totals.focus_uia += 1,
                }
                log.line(
                    Level::Info,
                    &format!(
                        "focus back on the game via {} ({front_exe} was in front{restored}; {} \
                         refused tries before): {}",
                        method.as_str(),
                        retry.refused,
                        outcome.detail
                    ),
                );
                *retry = FocusRetry::default();
            }
            None => {
                retry.refused += 1;
                let delay = focus_delay(retry.refused);
                retry.retry_at = Some(now + delay);
                retry.refused_on = Some(front);
                self.totals.focus_refused += 1;
                log.line(
                    if retry.refused == 1 {
                        Level::Warn
                    } else {
                        Level::Info
                    },
                    &format!(
                        "focus refused (try {}, {front_exe} in front{restored}): {}; next try in {}",
                        retry.refused,
                        outcome.detail,
                        secs(delay)
                    ),
                );
            }
        }
    }

    fn summary(&mut self, now: Instant, obs: &Observation, log: &mut impl Log) {
        if now.saturating_duration_since(self.last_summary) < SUMMARY_EVERY {
            return;
        }
        self.last_summary = now;
        log.line(
            Level::Info,
            &format!(
                "summary: {} for {}; game pids {:?}; this session {} launch(es), {} failed start(s) \
                 in a row; failed-launch mark {}; focus returned {} time(s) via \
                 SetForegroundWindow, {} via UI Automation, refused {} (since the helper started)",
                self.state.as_str(),
                secs(now.saturating_duration_since(self.since)),
                obs.game_pids,
                self.period.launches,
                self.period.failed_starts,
                if self.failed_launch.is_some() {
                    "set"
                } else {
                    "not set"
                },
                self.totals.focus_set_foreground,
                self.totals.focus_uia,
                self.totals.focus_refused
            ),
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::record::tests::record;

    #[derive(Default)]
    struct Lines(Vec<(Level, String)>);

    impl Log for Lines {
        fn line(&mut self, level: Level, message: &str) {
            self.0.push((level, message.to_string()));
        }
    }

    impl Lines {
        fn count(&self, needle: &str) -> usize {
            self.0.iter().filter(|(_, l)| l.contains(needle)).count()
        }
        fn count_at(&self, level: Level, needle: &str) -> usize {
            self.0
                .iter()
                .filter(|(at, l)| *at == level && l.contains(needle))
                .count()
        }
    }

    #[derive(Default)]
    struct Fake {
        obs: Observation,
        observe_error: Option<String>,
        observed: u32,
        launches: Vec<String>,
        launch_error: Option<LaunchError>,
        focuses: Vec<GameWindow>,
        focus_works: Option<FocusMethod>,
        /// The pids each `close_windows` was asked about.
        closes: Vec<Vec<u32>>,
        /// Pids `close_windows` cannot confirm the game's.
        not_the_game: Vec<u32>,
        terminated: Vec<u32>,
        terminate_reply: Option<TerminateOutcome>,
        /// What `PostMessageW(WM_CLOSE)` answers for every window; `None`: posted.
        close_refused: Option<String>,
        /// The tick's own signal and clock, as `Run::at` gives them: what a read again before an
        /// action answers unless a test says otherwise.
        tick_signal: Option<Signal>,
        tick_at: Option<Instant>,
        /// How long the tick has run by the time an action reads the signal again.
        tick_takes: Duration,
        /// What those reads answer, in turn; none left: the tick's own signal.
        rereads: std::collections::VecDeque<Signal>,
        /// Reads made before actions.
        reread: u32,
    }

    impl Desktop for Fake {
        fn signal(&mut self) -> Signal {
            self.reread += 1;
            self.rereads
                .pop_front()
                .or_else(|| self.tick_signal.clone())
                .unwrap_or(Signal::Absent)
        }
        fn now(&mut self) -> Instant {
            self.tick_at.unwrap() + self.tick_takes
        }
        fn observe(&mut self, _: &Record) -> Result<Observation, String> {
            self.observed += 1;
            match &self.observe_error {
                Some(e) => Err(e.clone()),
                // The exit of the process the helper started is said once, as Windows' is.
                None => {
                    let obs = self.obs.clone();
                    self.obs.launched_exit = None;
                    Ok(obs)
                }
            }
        }
        fn launch(&mut self, exe: &str) -> Result<u32, LaunchError> {
            self.launches.push(exe.to_string());
            match &self.launch_error {
                Some(e) => Err(e.clone()),
                None => Ok(1000 + self.launches.len() as u32),
            }
        }
        fn focus(&mut self, _: &Record, window: GameWindow) -> FocusOutcome {
            self.focuses.push(window);
            FocusOutcome {
                method: self.focus_works,
                detail: "fake".into(),
            }
        }
        fn close_windows(&mut self, record: &Record, pids: &[u32]) -> CloseRequest {
            self.closes.push(pids.to_vec());
            let mut request = CloseRequest::default();
            for &pid in pids {
                if self.not_the_game.contains(&pid) {
                    request
                        .skipped
                        .push((pid, "not the game's exe any more".into()));
                    continue;
                }
                request.processes.push(GameProcess {
                    pid,
                    path: record.window_exe.clone(),
                    started: 5000 + u64::from(pid),
                });
                request.windows.push(ClosedWindow {
                    pid,
                    window: 0x500 + pid as usize,
                    class: "#32770".into(),
                    title: "Scryde Crash Report".into(),
                    posted: self.close_refused.clone().map_or(Ok(()), Err),
                });
                request
                    .notes
                    .push(format!("integrity level of pid {pid}: medium (0x2000)"));
            }
            request
        }
        fn terminate(&mut self, _: &Record, process: &GameProcess) -> TerminateOutcome {
            self.terminated.push(process.pid);
            self.terminate_reply
                .clone()
                .unwrap_or(TerminateOutcome::Ended(Some(TERMINATE_EXIT_CODE)))
        }
    }

    struct Run {
        sup: Supervisor,
        fake: Fake,
        log: Lines,
        t0: Instant,
    }

    impl Run {
        fn new() -> Self {
            Self::with(record())
        }
        fn with(record: Record) -> Self {
            let t0 = Instant::now();
            Self {
                sup: Supervisor::new(record, t0),
                fake: Fake::default(),
                log: Lines::default(),
                t0,
            }
        }
        fn at(&mut self, secs: f64, signal: Signal) {
            let now = self.t0 + Duration::from_secs_f64(secs);
            self.fake.tick_signal = Some(signal.clone());
            self.fake.tick_at = Some(now);
            self.sup.tick(now, signal, &mut self.fake, &mut self.log);
        }
        fn on(&mut self, secs: f64) {
            self.at(secs, Signal::Allowed);
        }
        /// Every half second from `from` to `to`, both included.
        fn on_through(&mut self, from: f64, to: f64) {
            let mut t = from;
            while t <= to + 1e-9 {
                self.on(t);
                t += 0.5;
            }
        }
        fn game(&mut self, pids: &[u32], window: bool) {
            self.fake.obs.game_pids = pids.to_vec();
            self.fake.obs.window = window.then(|| GameWindow {
                id: 77,
                pid: pids.last().copied().unwrap_or_default(),
                minimized: false,
            });
        }
        /// `loaders` (the launch exe) and `bins` (the window exe) run; the window is `bins`' last's.
        fn game_with_loader(&mut self, loaders: &[u32], bins: &[u32], window: bool) {
            self.game(&[loaders, bins].concat(), false);
            self.fake.obs.loader_pids = loaders.to_vec();
            self.fake.obs.window = window.then(|| GameWindow {
                id: 77,
                pid: bins.last().copied().unwrap_or_default(),
                minimized: false,
            });
        }
        /// Scryde's game, launched at 0 s: the loader (10) until 5 s, then the `.bin` (11) with
        /// its window from 9 s, up until `until`.
        fn launched_and_running(&mut self, until: f64) {
            self.on(0.0);
            self.game_with_loader(&[10], &[], false);
            self.on(0.5);
            self.game_with_loader(&[10], &[11], false);
            self.on(1.5);
            self.game_with_loader(&[], &[11], false);
            self.on(5.0);
            self.game(&[11], true);
            self.on_through(9.0, until);
            assert_eq!(self.sup.state(), HelperState::Running);
            assert_eq!(self.fake.launches.len(), 1);
        }
    }

    #[test]
    fn without_the_signal_nothing_is_looked_at_or_done() {
        let mut run = Run::new();
        for (i, signal) in [
            Signal::Absent,
            Signal::NotSet,
            Signal::Unreadable("denied".into()),
        ]
        .into_iter()
        .enumerate()
        {
            run.at(i as f64, signal);
        }
        assert_eq!(run.fake.observed, 0);
        assert!(run.fake.launches.is_empty() && run.fake.focuses.is_empty());
        assert_eq!(run.sup.state(), HelperState::Idle);
        assert_eq!(run.log.count("the app's signal:"), 3);
    }

    #[test]
    fn the_first_launch_is_at_once_and_a_normal_exit_relaunches_after_the_minimum() {
        let mut run = Run::new();
        run.on(0.0);
        assert_eq!(run.fake.launches, vec![record().launch_exe]);
        assert_eq!(run.sup.state(), HelperState::Launching);
        // The loader, then the game's window: running, nothing launched twice.
        run.game(&[10], false);
        run.on(0.5);
        run.game(&[11], true);
        run.on(9.0);
        assert_eq!(run.sup.state(), HelperState::Running);
        run.on(70.0);
        // Closed by the user after a normal run: launched again at once (30 s since the last).
        run.game(&[], false);
        run.on(80.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert_eq!(run.log.count("after a normal run"), 1);
        // Gone right after this launch: not before 30 s after it.
        run.on(80.5);
        run.on(109.0);
        assert_eq!(run.fake.launches.len(), 2);
        run.on(110.5);
        assert_eq!(run.fake.launches.len(), 3);
        assert!(run.fake.closes.is_empty());
    }

    #[test]
    fn failed_starts_back_off_and_three_stop_launches_until_the_next_session() {
        let mut run = Run::new();
        run.on(0.0);
        run.game(&[10], true);
        run.on(1.0);
        // Crashed 10 s after the launch: the first failed start, a 30 s pause from then.
        run.game(&[], false);
        run.on(10.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        run.on(39.5);
        assert_eq!(run.fake.launches.len(), 1);
        run.on(40.0);
        assert_eq!(run.fake.launches.len(), 2);
        run.game(&[12], true);
        run.on(41.0);
        run.game(&[], false);
        run.on(50.0);
        // The second: 60 s from 50 s.
        run.on(109.5);
        assert_eq!(run.fake.launches.len(), 2);
        run.on(110.0);
        assert_eq!(run.fake.launches.len(), 3);
        run.on(115.0);
        // Its process never showed up at all: the loader may be handing over to a process the
        // record does not know — waited for 30 s from this look, still launching.
        assert_eq!(run.sup.period.failed_starts, 2);
        assert_eq!(run.sup.state(), HelperState::Launching);
        run.on(144.5);
        assert_eq!(run.sup.period.failed_starts, 2);
        // Nothing came: the third failed start, and the end of launches.
        run.on(145.0);
        assert_eq!(run.sup.period.failed_starts, 3);
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        for s in 0..20 {
            run.on(150.0 + f64::from(s) * 60.0);
        }
        assert_eq!(run.fake.launches.len(), 3);
        assert_eq!(run.log.count("no more launches until the next session"), 1);
        // The next session starts afresh: launched at once.
        run.at(1400.0, Signal::NotSet);
        assert_eq!(run.sup.state(), HelperState::Idle);
        run.on(1401.0);
        assert_eq!(run.fake.launches.len(), 4);
        assert_eq!(run.log.count("the last session's give-up is over"), 1);
    }

    #[test]
    fn a_run_with_its_window_past_a_minute_forgets_failed_starts() {
        let mut run = Run::new();
        run.on(0.0);
        run.game(&[], false);
        // Nothing of the game at 5 s: its loader's handover is waited for 30 s, then a failed
        // start, the pause counted from 5 s — launched again at once.
        run.on(5.0);
        assert_eq!(run.sup.period.failed_starts, 0);
        run.on(35.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert_eq!(run.fake.launches.len(), 2);
        run.game(&[10], true);
        run.on(36.0);
        run.on(96.0);
        assert_eq!(run.sup.period.failed_starts, 0);
    }

    #[test]
    fn a_launch_whose_loader_runs_long_is_waited_for_and_dying_without_a_window_is_a_failed_start()
    {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        run.on(1.0);
        // Still loading at two minutes: said once, and not launched again, nothing closed.
        for s in 2..=130 {
            run.on(f64::from(s));
        }
        assert_eq!(run.fake.launches.len(), 1);
        assert!(run.fake.closes.is_empty());
        assert_eq!(run.sup.state(), HelperState::Launching);
        assert_eq!(
            run.log.count_at(
                Level::Warn,
                "no game window 120.0 s after the launch, and the launch exe runs"
            ),
            1
        );
        // Gone without ever showing its window, well after a minute, and nothing of the game after
        // it: its handover is waited for 30 s — then still a failed start.
        run.game(&[], false);
        run.fake.obs.loader_pids.clear();
        run.on_through(131.0, 160.5);
        assert_eq!(run.sup.period.failed_starts, 0);
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(
            run.log.count(
                "no process of the window exe has run since the launch (only the loader seen \
                 running, at 130 look(s))"
            ),
            1
        );
        run.on(161.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert_eq!(run.log.count("its window never came"), 1);
    }

    #[test]
    fn an_unreadable_process_named_like_the_game_is_maybe_the_game() {
        let mut run = Run::new();
        run.fake.obs.unreadable = vec![42];
        for s in 0..10 {
            run.on(f64::from(s));
        }
        assert!(run.fake.launches.is_empty());
        assert_eq!(run.sup.state(), HelperState::Launching);
        assert_eq!(run.log.count("cannot be read (pids [42]"), 1);
        run.fake.obs.unreadable.clear();
        run.on(10.0);
        assert_eq!(
            run.log
                .count("the unreadable processes named like the game are gone"),
            1
        );
        // It was maybe the game and is gone; nothing was launched yet this session: at once.
        assert_eq!(run.fake.launches.len(), 1);
    }

    #[test]
    fn elevation_required_stops_launches_and_asks_for_setup() {
        let mut run = Run::new();
        run.fake.launch_error = Some(LaunchError::ElevationRequired);
        run.on(0.0);
        assert_eq!(run.sup.state(), HelperState::NeedsSetup);
        run.at(1.0, Signal::NotSet);
        run.on(2.0);
        run.on(100.0);
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(run.sup.state(), HelperState::NeedsSetup);
        assert_eq!(run.log.count("ERROR_ELEVATION_REQUIRED (740)"), 1);
    }

    #[test]
    fn a_launch_that_fails_counts_as_a_failed_start() {
        let mut run = Run::new();
        run.fake.launch_error = Some(LaunchError::NotFound("file not found".into()));
        for s in 0..400 {
            run.on(f64::from(s));
        }
        assert_eq!(run.fake.launches.len(), 3);
        assert_eq!(run.sup.state(), HelperState::GaveUp);
    }

    #[test]
    fn a_failed_look_skips_the_tick_and_is_said_once() {
        let mut run = Run::new();
        run.fake.observe_error = Some("snapshot failed".into());
        for s in 0..20 {
            run.on(f64::from(s) * 0.5);
        }
        assert!(run.fake.launches.is_empty());
        assert_eq!(run.log.count("processes and windows not read"), 1);
        run.fake.observe_error = None;
        run.on(11.0);
        assert_eq!(run.log.count("read again after 20 failed tries"), 1);
        assert_eq!(run.fake.launches.len(), 1);
    }

    /* ── A game that hangs ────────────────────────────────────────────────────────────────── */

    /// (a) A crash report keeps the `.bin` alive without the game's window.
    /// 30 s later its windows get WM_CLOSE, it exits, and the game is launched again — after a run
    /// of 100 s, a normal one: at once.
    #[test]
    fn a_crash_report_that_keeps_the_game_alive_is_closed_and_the_game_launched_again() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 129.5);
        assert!(run.fake.closes.is_empty(), "not before 30 s");
        assert_eq!(run.sup.state(), HelperState::Launching);
        assert!(
            run.sup.reason.contains("closed as hung"),
            "{}",
            run.sup.reason
        );
        run.on(130.0);
        assert_eq!(run.fake.closes, vec![vec![11]]);
        assert_eq!(
            run.log.count_at(
                Level::Warn,
                "the game hangs: its window has been gone 30.0 s and the process that showed it (pid 11) runs"
            ),
            1
        );
        assert_eq!(
            run.log
                .count("closing: pid 11 (D:\\Games\\Scryde\\Scryde\\ScrydeGame.bin)"),
            1
        );
        assert_eq!(
            run.log
                .count("of pid 11 (class \"#32770\", title \"Scryde Crash Report\"): posted"),
            1
        );
        assert!(
            run.sup.reason.contains("WM_CLOSE sent"),
            "{}",
            run.sup.reason
        );
        // The report closed, the process exits: launched again at once, nothing terminated.
        run.game(&[], false);
        run.on(131.0);
        assert!(run.fake.terminated.is_empty());
        assert_eq!(run.fake.launches.len(), 2);
        assert_eq!(
            run.log
                .count("it counts as gone 31.0 s ago, when its window went"),
            1
        );
        assert_eq!(
            run.log
                .count("after a normal run; closed by the helper: it hung"),
            1
        );
        assert_eq!(run.sup.period.failed_starts, 0);
    }

    /// (b) The report does not close within 10 s: TerminateProcess, then the launch.
    #[test]
    fn a_hung_game_that_outlives_wm_close_is_terminated_and_launched_again() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 139.5);
        assert_eq!(run.fake.closes.len(), 1);
        assert!(run.fake.terminated.is_empty(), "WM_CLOSE gets 10 s");
        run.on(140.0);
        assert_eq!(run.fake.terminated, vec![11]);
        assert_eq!(run.log.count("ended by TerminateProcess, exit code 1"), 1);
        assert!(
            run.sup.reason.contains("TerminateProcess done"),
            "{}",
            run.sup.reason
        );
        run.game(&[], false);
        run.on(140.5);
        assert_eq!(run.fake.launches.len(), 2);
        assert_eq!(
            run.log.count("began closing it (after TerminateProcess)"),
            1
        );
    }

    /// (c) An ordinary close: the window goes, the `.bin` follows 9 s later. Nothing is closed,
    /// the game is launched again as after any normal run.
    #[test]
    fn a_normal_close_is_not_taken_for_a_hang() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 108.5);
        run.game(&[], false);
        run.on(109.0);
        assert!(run.fake.closes.is_empty() && run.fake.terminated.is_empty());
        assert_eq!(run.fake.launches.len(), 2);
        assert_eq!(run.log.count("after a normal run; it is launched again"), 1);
    }

    /// (d) The window back after 15 s: the count starts over, nothing is closed.
    #[test]
    fn a_window_back_within_the_count_is_left_alone() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 114.5);
        assert!(run.sup.launch_pending(), "the window gone, a restart ahead");
        run.game(&[11], true);
        run.on_through(115.0, 120.0);
        assert_eq!(
            run.log
                .count("the game's window is back after 15.0 s: not closed"),
            1
        );
        // Back: «Игра запускается» ends with it, on the same tick.
        assert!(!run.sup.launch_pending());
        assert!(!pending_in_file(&run, 120.0));
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "launch pending off (the game's window is up, 115.0 s after the helper's launch)"
            ),
            1
        );
        // Gone again: a new count of its own.
        run.game(&[11], false);
        run.on_through(120.5, 150.0);
        assert!(run.fake.closes.is_empty());
        run.on(150.5);
        assert_eq!(run.fake.closes.len(), 1);
    }

    /// (e) After the helper's launch: no window at 120 s while the loader runs — waited for; the
    /// loader gone and the `.bin` without a window — closed once the handover has had its 30 s.
    #[test]
    fn a_launch_without_a_window_is_closed_only_once_its_loader_is_gone() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        run.on_through(0.5, 100.0);
        run.game_with_loader(&[10], &[11], false);
        run.on_through(100.5, 199.5);
        assert!(run.fake.closes.is_empty(), "the loader may be patching");
        assert_eq!(run.log.count("and the launch exe runs (pids [10]"), 1);
        run.game_with_loader(&[], &[11], false);
        run.on_through(200.0, 229.0);
        assert!(run.fake.closes.is_empty(), "the handover gets its 30 s");
        run.on(229.5);
        assert_eq!(run.fake.closes, vec![vec![11]]);
        assert_eq!(
            run.log
                .count("the game hangs: no game window 229.5 s after the launch, its launch exe gone 30.0 s ago"),
            1
        );
        // Closed: a failed start (its window never came), the pause, then the next launch.
        run.game(&[], false);
        run.on(230.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert_eq!(
            run.log
                .count("its window never came; closed by the helper: it hung"),
            1
        );
        run.on(259.0);
        assert_eq!(run.fake.launches.len(), 1);
        run.on(259.5);
        assert_eq!(run.fake.launches.len(), 2);
    }

    /// (f) The launch exe is the window exe (no loader): 120 s without a window is a hang.
    #[test]
    fn a_game_that_is_its_own_launch_exe_hangs_at_two_minutes() {
        let mut run = Run::new();
        run.on(0.0);
        run.game(&[11], false);
        run.on_through(0.5, 119.5);
        assert!(run.fake.closes.is_empty());
        run.on(120.0);
        assert_eq!(run.fake.closes, vec![vec![11]]);
        assert_eq!(run.log.count("no launch exe seen running"), 1);
    }

    /// (B) The loader still runs 10 min after the launch with no window: given up until the next
    /// session, the loader left running; nothing more is launched.
    #[test]
    fn a_loader_running_ten_minutes_without_a_window_gives_up_and_is_left_alone() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        for s in 1..=599 {
            run.on(f64::from(s));
        }
        assert_eq!(run.sup.state(), HelperState::Launching);
        run.on(600.0);
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        assert!(
            run.sup
                .reason
                .contains("has run 10.0 min with no game window")
                && run.sup.reason.contains("«Play»"),
            "{}",
            run.sup.reason
        );
        assert_eq!(
            run.log
                .count_at(Level::Error, "the helper gives up until the next session"),
            1
        );
        for s in 601..=900 {
            run.on(f64::from(s));
        }
        assert!(run.fake.closes.is_empty() && run.fake.terminated.is_empty());
        // The loader exits at last, with nothing after it: no launch until the next session — and
        // no wait for a handover, the loader has had its 10 min.
        run.game(&[], false);
        run.fake.obs.loader_pids.clear();
        run.on(901.0);
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "no wait for a handover — the launch was 15.0 min ago: its loader has had its \
                 10.0 min"
            ),
            1
        );
        run.on(1000.0);
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        // The next session starts afresh.
        run.at(1001.0, Signal::NotSet);
        run.on(1003.0);
        assert_eq!(run.fake.launches.len(), 2);
    }

    /// (g) The session ends during the count, or during the closing: nothing is closed or ended
    /// outside it. A new session that finds the same process still without its window counts
    /// afresh — the full 30 s again — and closes it then.
    #[test]
    fn nothing_is_closed_outside_a_session_and_a_new_session_counts_afresh() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 120.0);
        for s in 121..=200 {
            run.at(f64::from(s), Signal::NotSet);
        }
        assert!(run.fake.closes.is_empty());
        assert_eq!(
            run.log
                .count("the count for the game's lost window stops with it, at 21.0 s"),
            1
        );
        // Back: the same process, still without its window.
        run.on_through(201.0, 230.5);
        assert!(run.fake.closes.is_empty());
        run.on(231.0);
        assert_eq!(run.fake.closes.len(), 1);
        // Taken off between WM_CLOSE and TerminateProcess: nothing is ended.
        run.at(235.0, Signal::NotSet);
        assert_eq!(
            run.log
                .count("the closing of the hung game stops with it (after WM_CLOSE"),
            1
        );
        for s in 236..=300 {
            run.at(f64::from(s), Signal::NotSet);
        }
        assert!(run.fake.terminated.is_empty());
    }

    /// (h) A process whose path cannot be read is never closed: neither counted nor named in a
    /// closing.
    #[test]
    fn an_unreadable_process_is_never_closed() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        // The window's process cannot be read any more: nothing to count against.
        run.game(&[], false);
        run.fake.obs.unreadable = vec![11];
        run.on_through(100.0, 200.0);
        assert!(run.fake.closes.is_empty());
        // Readable again beside an unreadable one: only the readable one is closed.
        run.game(&[11], false);
        run.fake.obs.unreadable = vec![42];
        run.on_through(200.5, 230.5);
        assert_eq!(run.fake.closes, vec![vec![11]]);
        assert_eq!(run.log.count("unreadable pids [42] are not touched"), 1);
        run.on_through(231.0, 241.0);
        assert_eq!(run.fake.terminated, vec![11]);
    }

    /// (i) Windows refuses TerminateProcess: said once, then waited for as before — no try on
    /// every tick.
    #[test]
    fn a_refused_terminate_is_said_once_and_not_tried_again() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.fake.terminate_reply = Some(TerminateOutcome::Denied("access denied".into()));
        run.game(&[11], false);
        run.on_through(100.0, 400.0);
        assert_eq!(run.fake.closes.len(), 1);
        assert_eq!(run.fake.terminated, vec![11]);
        assert_eq!(
            run.log
                .count_at(Level::Warn, "Windows refused (access denied"),
            1
        );
        assert_eq!(run.log.count("the hung game could not be ended"), 1);
        assert_eq!(run.sup.state(), HelperState::Launching);
        assert!(
            run.sup.reason.contains("refused to close it"),
            "{}",
            run.sup.reason
        );
        // Nothing more is tried: no launch follows until it goes — not pending from the refusal.
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count(
                "launch pending off (the game hangs and Windows refused to close it: nothing more \
                 is tried"
            ),
            1
        );
        // It exits by itself at last (someone closed the report at the PC): launched again.
        run.game(&[], false);
        run.on(400.5);
        assert_eq!(run.fake.launches.len(), 2);
    }

    /// A process that stopped being confirmed the game's is left alone, and with none confirmed
    /// nothing is tried again on the next ticks.
    #[test]
    fn a_process_not_confirmed_the_games_is_left_alone() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.fake.not_the_game = vec![11];
        run.game(&[11], false);
        run.on_through(100.0, 300.0);
        assert_eq!(run.fake.closes.len(), 1);
        assert!(run.fake.terminated.is_empty());
        assert_eq!(
            run.log
                .count("left alone: pid 11 (not the game's exe any more)"),
            1
        );
    }

    /// A crash 10 s after its window came, the crash report open past the minute: the run did not
    /// survive, so it is a failed start, and three of them stop the launches.
    #[test]
    fn a_crash_soon_after_the_window_is_a_failed_start_however_long_the_report_stays() {
        let mut run = Run::new();
        let mut t = 0.0;
        for n in 1..=3_u32 {
            // Up to the n-th launch (the pause after a failed start counts from when the window
            // went): then its window from +1 s, gone at +8 s, the report staying.
            while run.fake.launches.len() < n as usize {
                run.on(t);
                t += 0.5;
            }
            run.game(&[11], true);
            run.on_through(t + 0.5, t + 7.5);
            run.game(&[11], false);
            run.on_through(t + 8.0, t + 38.0);
            assert_eq!(run.fake.closes.len(), n as usize);
            run.game(&[], false);
            t += 38.5;
            run.on(t);
            t += 0.5;
            assert_eq!(run.sup.period.failed_starts, n);
        }
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        assert_eq!(
            run.log
                .count("its window was up, but not at the minute's mark; closed by the helper"),
            3
        );
    }

    /// A launcher that stays beside the game is not a loader starting it: the game's lost window
    /// is counted, and the launcher closed with the game.
    #[test]
    fn a_launcher_that_stays_beside_the_game_does_not_hold_the_count() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[11], false);
        run.on(1.0);
        run.game_with_loader(&[10], &[11], true);
        run.on_through(2.0, 99.5);
        run.game_with_loader(&[10], &[11], false);
        run.on_through(100.0, 130.0);
        assert_eq!(run.fake.closes, vec![vec![10, 11]]);
    }

    /// A loader that starts after the window went — the game restarting itself, or someone at the
    /// PC — holds the count; its handover gets its 30 s after it exits.
    #[test]
    fn a_loader_that_comes_after_the_window_went_holds_the_count() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 110.0);
        run.game_with_loader(&[20], &[11], false);
        run.on_through(110.5, 200.0);
        assert!(run.fake.closes.is_empty());
        assert_eq!(
            run.log
                .count("no game window 30.0 s since it went, and the launch exe runs"),
            1
        );
        run.game(&[11], false);
        run.fake.obs.loader_pids.clear();
        run.on_through(200.5, 229.5);
        assert!(run.fake.closes.is_empty());
        run.on(230.0);
        assert_eq!(run.fake.closes, vec![vec![11]]);
    }

    /// The window back while the game is being closed: the closing stops, nothing is ended.
    #[test]
    fn a_window_back_during_the_closing_stops_it() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 130.0);
        assert_eq!(run.fake.closes.len(), 1);
        run.game(&[11], true);
        run.on_through(130.5, 200.0);
        assert!(run.fake.terminated.is_empty());
        assert_eq!(run.log.count("the closing stops"), 1);
        assert_eq!(run.sup.state(), HelperState::Running);
    }

    #[test]
    fn focus_is_never_taken_from_afklink_a_menu_nothing_or_the_game_itself() {
        let mut run = Run::new();
        run.game(&[10], true);
        for (i, front) in [
            Foreground::Game,
            Foreground::Nothing,
            Foreground::AfkLink {
                exe: "AFKLink.exe".into(),
            },
            Foreground::Menu {
                exe: "explorer.exe".into(),
            },
            Foreground::Unreadable {
                window: 5,
                error: "denied".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            run.fake.obs.foreground = front;
            run.on(i as f64);
            run.on(i as f64 + 0.5);
        }
        assert!(run.fake.focuses.is_empty());
        assert_eq!(run.log.count("AFKLink's own window is in front"), 1);
        // Neither is a window outside the session's: nothing in front while not allowed.
        run.fake.obs.foreground = Foreground::Other {
            window: 5,
            exe: "notepad.exe".into(),
        };
        run.at(10.0, Signal::NotSet);
        assert!(run.fake.focuses.is_empty());
        run.fake.focus_works = Some(FocusMethod::SetForeground);
        run.on(11.0);
        assert_eq!(run.fake.focuses.len(), 1);
        assert_eq!(
            run.log
                .count("focus back on the game via SetForegroundWindow"),
            1
        );
    }

    #[test]
    fn refused_focus_backs_off_and_starts_over_on_another_window() {
        let mut run = Run::new();
        run.game(&[10], true);
        run.fake.obs.foreground = Foreground::Other {
            window: 5,
            exe: "notepad.exe".into(),
        };
        // Tries at 0, 1, 3, 7, 15, 25, 35: 1 s, doubling, at most 10 s.
        for tick in 0..=72 {
            run.on(f64::from(tick) * 0.5);
        }
        assert_eq!(run.fake.focuses.len(), 7);
        assert_eq!(run.sup.totals.focus_refused, 7);
        // Another window in front: at once.
        run.fake.obs.foreground = Foreground::Other {
            window: 6,
            exe: "explorer.exe".into(),
        };
        run.on(36.5);
        assert_eq!(run.fake.focuses.len(), 8);
        // A minimized game is restored by the next try, and UI Automation's success is said so.
        run.fake.obs.window = Some(GameWindow {
            id: 77,
            pid: 10,
            minimized: true,
        });
        run.fake.focus_works = Some(FocusMethod::Uia);
        run.on(37.5);
        assert_eq!(run.fake.focuses.len(), 9);
        assert!(run.fake.focuses.last().unwrap().minimized);
        assert_eq!(run.log.count("via UI Automation SetFocus"), 1);
        assert_eq!(run.sup.totals.focus_uia, 1);
        // Success starts over: the next refusal waits one second again.
        run.fake.focus_works = None;
        run.fake.obs.window = Some(GameWindow {
            id: 77,
            pid: 10,
            minimized: false,
        });
        run.on(38.0);
        run.on(38.5);
        run.on(39.0);
        assert_eq!(run.fake.focuses.len(), 11);
    }

    #[test]
    fn the_state_file_says_what_the_app_shows() {
        let mut run = Run::new();
        run.on(0.0);
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let state = run
            .sup
            .state_file(run.t0 + Duration::from_secs(5), wall, 7, true);
        assert_eq!(state.state, HelperState::Launching);
        assert_eq!(state.launches, 1);
        assert_eq!(state.updated_ms - state.since_ms, 5000);
        let parsed = StateFile::parse(serde_json::to_string(&state).unwrap().as_bytes()).unwrap();
        assert_eq!(parsed, state);
        assert!(serde_json::to_string(&state)
            .unwrap()
            .contains("\"state\":\"launching\""));
        assert!(StateFile::parse(b"{}").is_err());
    }

    /// Closing a hung game writes no state an app built before it cannot read: the state is
    /// `launching`, the reason says what goes on.
    #[test]
    fn the_closing_is_a_state_older_apps_read() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 130.0);
        let state = run.sup.state_file(
            run.t0 + Duration::from_secs(130),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            7,
            true,
        );
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"state\":\"launching\""), "{json}");
        assert!(
            state.reason.contains("closing the hung game"),
            "{}",
            state.reason
        );
        for known in [
            "idle",
            "waiting",
            "launching",
            "running",
            "gave_up",
            "needs_setup",
        ] {
            let other = json.replace("\"launching\"", &format!("\"{known}\""));
            assert!(StateFile::parse(other.as_bytes()).is_ok(), "{known}");
        }
    }

    /* ── «Игра запускается»: launch_pending ─────────────────────────────────────────────────── */

    fn pending_in_file(run: &Run, secs: f64) -> bool {
        run.sup
            .state_file(
                run.t0 + Duration::from_secs_f64(secs),
                SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
                7,
                true,
            )
            .launch_pending
    }

    /// Scryde's game launched by the helper: pending from the launch — the loader, then the
    /// `.bin` without its window — until the window is up; said once each way, and written at once.
    #[test]
    fn a_launch_of_the_helpers_is_pending_until_the_games_window_comes() {
        let mut run = Run::new();
        run.on(0.0);
        assert!(
            run.sup.launch_pending(),
            "launched; its process not seen yet"
        );
        assert!(pending_in_file(&run, 0.0));
        assert!(run.sup.take_dirty(), "written at once");
        run.game_with_loader(&[10], &[], false);
        run.on(0.5);
        run.game_with_loader(&[10], &[11], false);
        run.on(1.5);
        run.game_with_loader(&[], &[11], false);
        run.on_through(5.0, 8.5);
        assert!(
            run.sup.launch_pending(),
            "the .bin runs, its window not yet"
        );
        run.game(&[11], true);
        run.on(9.0);
        assert!(!run.sup.launch_pending());
        assert!(!pending_in_file(&run, 9.0));
        assert_eq!(
            run.log
                .count_at(Level::Info, "launch pending on (launched pid 1001"),
            1
        );
        assert_eq!(
            run.log.count(
                "launch pending off (the game's window is up, 9.0 s after the helper's launch)"
            ),
            1
        );
        // Closed by the user after a normal run: gone, then launched again — pending again.
        run.on_through(9.5, 80.0);
        run.game(&[], false);
        run.on(80.5);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
        assert_eq!(run.log.count("launch pending on"), 2);
    }

    /// A game started by hand is not a launch of the helper's while its window has not come. Once
    /// its window was up and went, its process lingering, the helper launches it again either way
    /// — once it is gone, or after closing it as hung — so the viewer is told the game is starting
    /// from then on, through the helper's own launch.
    #[test]
    fn a_game_started_by_hand_is_not_pending_but_its_restart_is() {
        let mut run = Run::new();
        run.game(&[11], false);
        run.on_through(0.0, 20.0);
        assert!(run.fake.launches.is_empty());
        assert!(
            !run.sup.launch_pending(),
            "started by hand, its window not up yet"
        );
        assert_eq!(run.log.count("launch pending"), 0);
        run.game(&[11], true);
        run.on_through(20.5, 99.5);
        // Closed by hand: the `.bin` lives on 9 s without its window.
        run.game(&[11], false);
        run.on(100.0);
        assert!(run.sup.launch_pending(), "its window gone, a restart ahead");
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "launch pending on (its window is gone 0.0 s while its process (pid 11) runs: the \
                 helper closes it as hung at 30.0 s and launches it again (not launched by the \
                 helper this session: launched as soon as it is gone))"
            ),
            1
        );
        run.on_through(100.5, 108.5);
        assert!(run.sup.launch_pending());
        // Gone: the session's first launch, at once — pending on without a break.
        run.game(&[], false);
        run.on(109.0);
        assert_eq!(run.fake.launches.len(), 1);
        assert!(run.sup.launch_pending());
        assert_eq!(run.log.count("launch pending on"), 1);
        assert_eq!(run.log.count("launch pending off"), 0);
    }

    /// A start that fails stops being pending: not during the pause before the next launch, and
    /// pending again only from that launch.
    #[test]
    fn a_failed_start_ends_the_pending_launch_until_the_next_one() {
        let mut run = Run::new();
        run.on(0.0);
        run.game(&[10], false);
        run.on(1.0);
        assert!(run.sup.launch_pending());
        // Gone 10 s after the launch without its window: a failed start, a 30 s pause.
        run.game(&[], false);
        run.on(10.0);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log
                .count("launch pending off (no launch of the helper's this session waits"),
            1
        );
        run.on_through(10.5, 39.5);
        assert!(
            !run.sup.launch_pending(),
            "the pause before the next launch"
        );
        run.on(40.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
    }

    /// A launch with no window by 120 s, its loader gone, is closed as hung: still pending while it
    /// is closed — a launch follows — then not during the pause its failed start brings, and
    /// pending again from the next launch.
    #[test]
    fn a_launch_closed_as_hung_stays_pending_until_its_failed_start() {
        let mut run = Run::new();
        run.on(0.0);
        run.game(&[11], false);
        run.on_through(0.5, 119.5);
        assert!(run.sup.launch_pending());
        run.on(120.0);
        assert_eq!(run.fake.closes, vec![vec![11]]);
        assert!(run.sup.launch_pending());
        assert!(pending_in_file(&run, 120.0));
        let (pending, why) = run
            .sup
            .launch_pending_now(run.t0 + Duration::from_secs(125));
        assert!(pending);
        assert!(
            why.starts_with(
                "closing the hung game: after WM_CLOSE (5.0 s ago), then launching it again \
                 (failed start 1 of 3 in a row for the helper's launch (pid 1001, 120.0 s before \
                 the game went): launched again once it is gone, not before 25.0 s from now (the \
                 pause after 1 failed start(s) in a row: 30.0 s from when it counts as gone); not \
                 pending while it waits)"
            ),
            "{why}"
        );
        assert_eq!(run.log.count("launch pending off"), 0);
        // Gone: the failed start — the pause, 30 s from the closing, not pending.
        run.game(&[], false);
        run.on(121.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log
                .count("launch pending off (no launch of the helper's this session waits"),
            1
        );
        run.on_through(121.5, 149.5);
        assert_eq!(run.fake.launches.len(), 1);
        run.on(150.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
    }

    /// A crash report: the game's window went, its process stayed. Pending from
    /// that look — through the 30 s count, `WM_CLOSE`, TerminateProcess — into the helper's own
    /// launch after it, with no «off» between: the viewer reads «Игра запускается» throughout.
    #[test]
    fn a_lost_window_is_pending_while_the_helper_closes_and_launches_the_game_again() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on(100.0);
        assert!(run.sup.launch_pending());
        assert!(pending_in_file(&run, 100.0));
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "launch pending on (its window is gone 0.0 s while its process (pid 11) runs: the \
                 helper closes it as hung at 30.0 s and launches it again (a normal run of 100.0 s \
                 after the helper's launch: launched as soon as it is gone))"
            ),
            1
        );
        run.on_through(100.5, 139.5);
        assert_eq!(run.fake.closes.len(), 1);
        assert!(run.sup.launch_pending(), "after WM_CLOSE");
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "closing: integrity level of pid 11: medium (0x2000)"
            ),
            1
        );
        run.on(140.0);
        assert_eq!(run.fake.terminated, vec![11]);
        assert!(run.sup.launch_pending(), "after TerminateProcess");
        run.game(&[], false);
        run.on(140.5);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending(), "the new launch's own");
        // On at the launch, off at its window (9 s), on when it went: nothing between.
        assert_eq!(run.log.count("launch pending on"), 2);
        assert_eq!(run.log.count("launch pending off"), 1);
    }

    /// `WM_CLOSE` to «Scryde Crash Report» refused (access
    /// denied) — TerminateProcess still follows, so still pending, the refusal said with the
    /// window's thread and whether Windows takes it for hung. The viewer leaving first, nothing is
    /// ended and not pending; the next session starts the count over (said, with how long the
    /// window has been gone), pending at once, and the game is ended and launched again.
    #[test]
    fn a_crash_report_refusing_wm_close_is_pending_until_terminated_across_sessions() {
        let mut run = Run::new();
        run.fake.close_refused = Some(
            "Access is denied. (0x80070005); the window's thread 7 of pid 11, IsHungAppWindow: no"
                .into(),
        );
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 130.0);
        assert_eq!(run.fake.closes.len(), 1);
        assert_eq!(
            run.log.count_at(
                Level::Warn,
                "(class \"#32770\", title \"Scryde Crash Report\"): not posted (Access is denied. \
                 (0x80070005); the window's thread 7 of pid 11, IsHungAppWindow: no)"
            ),
            1
        );
        assert!(run.sup.launch_pending(), "TerminateProcess still follows");
        // The viewer leaves a second later, before TerminateProcess.
        run.at(131.0, Signal::NotSet);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count("launch pending off (not allowed by the app)"),
            1
        );
        for s in 132..=600 {
            run.at(f64::from(s), Signal::NotSet);
        }
        assert!(run.fake.terminated.is_empty());
        // The next session: the same process, still without its window.
        run.on(601.0);
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "the window of pid 11 has been gone 501.0 s (as far as the helper saw); the count \
                 toward closing it starts over: a new session — someone at the PC may be at it"
            ),
            1
        );
        assert_eq!(
            run.log
                .count("counted from now; gone 501.0 s in all (since an earlier session or count)"),
            1
        );
        assert!(
            run.sup.launch_pending(),
            "pending from the session's first look"
        );
        run.on_through(601.5, 630.5);
        assert_eq!(run.fake.closes.len(), 1, "the count starts over");
        run.on_through(631.0, 641.0);
        assert_eq!(run.fake.closes.len(), 2);
        assert_eq!(run.fake.terminated, vec![11]);
        assert!(run.sup.launch_pending());
        run.game(&[], false);
        run.on(641.5);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
        // The window back: the next session does not say a lost window.
        run.game(&[12], true);
        run.on(650.0);
        run.at(651.0, Signal::NotSet);
        run.on(652.0);
        assert_eq!(run.log.count("the window of pid"), 1);
    }

    /// A lost window whose closing would be the last failed start allowed — the helper gives up
    /// then, nothing launched after it — is not pending: «Игра запускается» would be untrue.
    #[test]
    fn a_lost_window_whose_closing_would_give_up_is_not_pending() {
        let mut run = Run::new();
        let mut t = 0.0;
        for n in 1..=MAX_FAILED_STARTS {
            while run.fake.launches.len() < n as usize {
                run.on(t);
                t += 0.5;
            }
            run.game(&[11], true);
            run.on_through(t + 0.5, t + 7.5);
            // Crashed 8 s after its launch, the report staying.
            run.game(&[11], false);
            run.on_through(t + 8.0, t + 20.0);
            let (pending, why) = run
                .sup
                .launch_pending_now(run.t0 + Duration::from_secs_f64(t + 20.0));
            assert_eq!(pending, n < MAX_FAILED_STARTS, "crash {n}: {why}");
            assert_eq!(run.sup.launch_pending(), pending, "crash {n}");
            if n == MAX_FAILED_STARTS {
                assert!(
                    why.contains(
                        "as failed start 3 of 3 in a row: the helper gives up then and launches \
                         nothing more this session"
                    ),
                    "{why}"
                );
            }
            run.on_through(t + 20.5, t + 38.0);
            assert_eq!(run.fake.closes.len(), n as usize);
            assert_eq!(run.sup.launch_pending(), pending, "closing {n}");
            run.game(&[], false);
            t += 38.5;
            run.on(t);
            t += 0.5;
        }
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        assert!(!run.sup.launch_pending());
        assert_no_drift(&run);
    }

    const DRIFT: &str = "launch pending goes off without the launch it promised";

    fn assert_no_drift(run: &Run) {
        assert_eq!(run.log.count_at(Level::Warn, DRIFT), 0);
    }

    /// The `launch pending` lines in order, each cut to `width` characters after the word.
    fn pending_lines(run: &Run, width: usize) -> Vec<String> {
        run.log
            .0
            .iter()
            .filter_map(|(_, l)| l.strip_prefix("launch pending "))
            .map(|l| l.chars().take(width).collect())
            .collect()
    }

    /// After failed starts, a game started by hand whose window went is launched again when the
    /// pause after them allows — as `next_launch_at` counts it, from when its window went — and
    /// `launch_pending` says so: on from the window's going, on through a launch the pause
    /// already allows (1 failed start), off for what is left of a longer one (2).
    #[test]
    fn a_hand_started_game_after_failed_starts_is_launched_when_the_pause_allows() {
        let mut run = Run::new();
        run.on(0.0);
        run.game(&[10], true);
        run.on(1.0);
        // Crashed: failed start 1, the next launch at 40 s.
        run.game(&[], false);
        run.on(10.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        // Started by hand meanwhile; its window up, then gone, its process staying.
        run.game(&[20], false);
        run.on(12.0);
        run.game(&[20], true);
        run.on(15.0);
        run.game(&[20], false);
        run.on(20.0);
        let (pending, why) = run.sup.launch_pending_now(run.t0 + Duration::from_secs(20));
        assert!(pending);
        assert!(
            why.ends_with(
                "(not launched by the helper this session: launched again once it is gone, not \
                 before 30.0 s from now (the pause after 1 failed start(s) in a row: 30.0 s from \
                 when it counts as gone); not pending while it waits)"
            ),
            "{why}"
        );
        run.on_through(20.5, 50.0);
        assert_eq!(run.fake.closes.len(), 1);
        // Gone at 51 s: the pause (30 s from 20 s) is over — launched at once, pending throughout.
        run.game(&[], false);
        run.on(51.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());

        // That launch crashes too: failed start 2, the next launch at 120 s.
        run.game(&[30], true);
        run.on(52.0);
        run.game(&[], false);
        run.on(60.0);
        assert_eq!(run.sup.period.failed_starts, 2);
        run.game(&[40], false);
        run.on(62.0);
        run.game(&[40], true);
        run.on(65.0);
        run.game(&[40], false);
        run.on(70.0);
        let (pending, why) = run.sup.launch_pending_now(run.t0 + Duration::from_secs(70));
        assert!(pending);
        assert!(
            why.contains(
                "not before 60.0 s from now (the pause after 2 failed start(s) in a row: 60.0 s"
            ),
            "{why}"
        );
        run.on_through(70.5, 100.0);
        assert_eq!(run.fake.closes.len(), 2);
        // Gone at 101 s: 60 s from 70 s is 130 s — not pending meanwhile, launched then.
        run.game(&[], false);
        run.on_through(101.0, 129.5);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(!run.sup.launch_pending());
        run.on(130.0);
        assert_eq!(run.fake.launches.len(), 3);
        assert!(run.sup.launch_pending());
        assert_eq!(
            pending_lines(&run, 32),
            vec![
                "on (launched pid 1001 0.0 s ago,",
                "off (the game's window is up, 1.",
                "on (its window is gone 0.0 s whi",
                "off (the game's window is up, 1.",
                "on (its window is gone 0.0 s whi",
                "off (no launch of the helper's t",
                "on (launched pid 1003 0.0 s ago,",
            ]
        );
        assert_no_drift(&run);
    }

    /// TerminateProcess went through and the game outlives its grace after it: nothing more is
    /// tried, so nothing is pending — not «Игра запускается» for ever. Gone at last, it is
    /// launched again, pending from that launch.
    #[test]
    fn a_game_that_outlives_terminate_process_is_no_longer_pending() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.fake.terminate_reply = Some(TerminateOutcome::Requested);
        run.game(&[11], false);
        run.on_through(100.0, 149.5);
        assert_eq!(run.fake.terminated, vec![11]);
        assert!(run.sup.launch_pending(), "within the grace after it");
        run.on(150.0);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count(
                "launch pending off (the hung game still runs 10.0 s after TerminateProcess: \
                 nothing more is tried"
            ),
            1
        );
        run.on_through(150.5, 300.0);
        assert!(!run.sup.launch_pending());
        assert_eq!(run.log.count("launch pending off"), 2);
        run.game(&[], false);
        run.on(300.5);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
        assert_no_drift(&run);
    }

    /// A launch exe started after the window went holds the closing off while it runs: pending,
    /// saying so, up to the bound a loader gets ([`LAUNCHER_WAIT_MAX`]) — then not, for as long as
    /// it runs. Gone, the closing is due again 30 s after it, and pending with it.
    #[test]
    fn a_lost_window_held_off_by_a_loader_is_pending_only_up_to_the_loaders_bound() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 109.5);
        assert!(run.sup.launch_pending());
        run.game_with_loader(&[20], &[11], false);
        run.on(110.0);
        let (pending, why) = run
            .sup
            .launch_pending_now(run.t0 + Duration::from_secs(110));
        assert!(pending);
        assert!(
            why.contains(
                "the helper closes it as hung 30.0 s after the launch exe running beside it (pids \
                 [20]) exits and launches it again"
            ),
            "{why}"
        );
        run.on_through(110.5, 699.5);
        assert!(run.sup.launch_pending());
        run.on(700.0);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count(
                "launch pending off (its window has been gone 10.0 min while its process (pid 11) \
                 runs, and a launch exe started after it went still runs (pids [20]), past 10.0 \
                 min"
            ),
            1
        );
        run.on_through(700.5, 749.5);
        assert!(run.fake.closes.is_empty());
        // The loader exits: the closing is due 30 s after it.
        run.game(&[11], false);
        run.fake.obs.loader_pids.clear();
        run.on(750.0);
        assert!(run.sup.launch_pending());
        let (_, why) = run
            .sup
            .launch_pending_now(run.t0 + Duration::from_secs(750));
        assert!(
            why.contains(
                "closes it as hung at 30.0 s since it went, and not before 30.0 s after the launch \
                 exe that ran meanwhile exited (0.5 s ago)"
            ),
            "{why}"
        );
        run.on_through(750.5, 779.0);
        assert!(run.fake.closes.is_empty());
        run.on(779.5);
        assert_eq!(run.fake.closes.len(), 1);
        assert!(run.sup.launch_pending());
        assert_no_drift(&run);
    }

    /// The drift guard: pending on for a predicted relaunch, then off with the game gone, nothing
    /// launched and no pause — said once as a warning.
    #[test]
    fn a_predicted_relaunch_that_does_not_come_is_warned_about_once() {
        let mut run = Run::new();
        run.sup.allowed = true;
        run.sup.launch_pending = true;
        run.sup.pending_relaunch = true;
        run.sup.note_launch_pending(run.t0, &mut run.log);
        assert!(!run.sup.launch_pending());
        assert_eq!(run.log.count_at(Level::Warn, DRIFT), 1);
        run.sup.note_launch_pending(run.t0, &mut run.log);
        assert_eq!(run.log.count_at(Level::Warn, DRIFT), 1);
    }

    /// The loader running 10 min without the game's window: given up, and not pending.
    #[test]
    fn a_launch_given_up_on_is_no_longer_pending() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        for s in 1..=599 {
            run.on(f64::from(s));
        }
        assert!(run.sup.launch_pending());
        run.on(600.0);
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        assert!(!run.sup.launch_pending());
        assert_eq!(run.log.count("launch pending off (given up"), 1);
    }

    /// The session over: not pending, whatever the game does; the next session starts afresh and
    /// does not count a launch of the last one as its own.
    #[test]
    fn a_launch_is_pending_only_during_the_session() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        run.on(1.0);
        assert!(run.sup.launch_pending());
        run.at(2.0, Signal::NotSet);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count("launch pending off (not allowed by the app)"),
            1
        );
        run.at(3.0, Signal::Absent);
        // A new session while the loader still runs: it is not this session's launch.
        run.on(4.0);
        assert!(!run.sup.launch_pending());
        assert_eq!(run.fake.launches.len(), 1);
    }

    /// `launch_pending` is a field older apps skip and this app reads as `false` from an older
    /// helper: neither fails the file, the format stays 1.
    #[test]
    fn launch_pending_is_read_by_old_and_new_apps_alike() {
        let mut run = Run::new();
        run.on(0.0);
        let state = run.sup.state_file(
            run.t0,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            7,
            true,
        );
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"launch_pending\":true"), "{json}");
        assert_eq!(state.format, STATE_FORMAT);
        // An older helper's file: no such field.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("launch_pending");
        let old = StateFile::parse(value.to_string().as_bytes()).unwrap();
        assert!(!old.launch_pending);
        // A newer helper's file with a field this build does not know: read all the same, as an
        // app built before `launch_pending` reads this one.
        value
            .as_object_mut()
            .unwrap()
            .insert("something_newer".into(), serde_json::json!(1));
        assert!(StateFile::parse(value.to_string().as_bytes()).is_ok());
    }

    /* ── A loader's handover ────────────────────────────────────────────────────────────────── */

    /// The record's launch exe is the loader `ScrydeGame_Lite.exe`; it starts
    /// `ScrydeGame.exe` (an anticheat updater the record does not know) and is gone at the first
    /// look, code 0; that one starts `ScrydeGame.bin` at 4.3 s — a splash first, the game's window
    /// at 17.2 s. For 3.7 s nothing of the game ran: not a failed start — the launch waits for the
    /// handover, pending all along (the viewer's «Игра запускается», never «Игра не запущена»), and
    /// once the `.bin` comes it is the helper's launch as any: pending until its window, surviving
    /// at the minute's mark.
    #[test]
    fn a_loader_handing_over_through_a_process_the_record_does_not_know_is_waited_for() {
        let mut run = Run::with(Record {
            launch_exe: r"C:\Scryde-Client\Scryde\ScrydeGame_Lite.exe".into(),
            window_exe: r"C:\Scryde-Client\Scryde\ScrydeGame.bin".into(),
            ..record()
        });
        // A mark from an earlier run: the launch surviving takes it off, as any of the helper's.
        let previous = StateFile {
            failed_launch_since_ms: Some(WALL_MS - 600_000),
            ..file_at(&Run::new(), 0.0)
        };
        run.sup.carry_over(
            &previous,
            SystemTime::UNIX_EPOCH + Duration::from_millis(WALL_MS),
            &mut run.log,
        );
        run.on(0.0);
        assert_eq!(run.fake.launches.len(), 1);
        assert!(run.sup.launch_pending());
        // The first look after the launch: the loader gone (code 0), nothing of the game runs.
        run.fake.obs.launched_exit = Some((1001, Some(0)));
        run.on(0.5);
        assert!(run.sup.launch_pending());
        assert_eq!(run.sup.state(), HelperState::Launching);
        assert!(
            run.sup
                .reason
                .contains("its handover is waited for, up to 30.0 s for the game's process"),
            "{}",
            run.sup.reason
        );
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "nothing of the game runs 0.5 s after the launch, and the launched loader \
                 ScrydeGame_Lite.exe (pid 1001, exited with code 0) is gone; no process of the \
                 window exe has run since the launch (the loader itself not seen running at a \
                 look) — the loader may be handing over to a process the record does not know: \
                 waiting up to 30.0 s for the game's process before this counts as a failed \
                 start; the launch stays pending, nothing is launched meanwhile"
            ),
            1
        );
        // Nothing of the game for 3.7 s: pending, launching, nothing launched, no failed start.
        let mut t = 1.0;
        while t <= 4.0 {
            run.on(t);
            assert!(run.sup.launch_pending(), "at {t} s");
            assert_eq!(run.sup.state(), HelperState::Launching, "at {t} s");
            t += 0.5;
        }
        // The `.bin`, started by a process the record does not know: the wait ends.
        run.game_with_loader(&[], &[1248], false);
        run.on(4.5);
        assert!(run.sup.launch_pending());
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "the game's process came 4.0 s after the launched loader went (pids [1248], maybe \
                 []; loaders among them []): the wait for the handover ends — the helper's launch \
                 goes on, 4.5 s after it, pending until the game's window"
            ),
            1
        );
        // Its splash — no game window — until 17.2 s: pending, as any launch of the helper's.
        let mut t = 5.0;
        while t <= 17.0 {
            run.on(t);
            assert!(run.sup.launch_pending(), "at {t} s");
            assert_eq!(run.sup.state(), HelperState::Launching, "at {t} s");
            t += 0.5;
        }
        run.game(&[1248], true);
        run.on(17.5);
        assert!(!run.sup.launch_pending());
        assert_eq!(run.sup.state(), HelperState::Running);
        run.on_through(18.0, 60.0);
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(run.sup.period.failed_starts, 0);
        assert!(!run.sup.failed_launch());
        assert_eq!(
            run.log.count(
                "failed-launch mark taken off: the helper's launch survived — the game's window \
                 is up 60.0 s after it"
            ),
            1
        );
        assert_eq!(run.log.count_at(Level::Warn, "failed start"), 0);
        assert_eq!(run.log.count("-> waiting"), 0);
        assert_eq!(
            run.log
                .count_at(Level::Info, "launch pending on (launched pid 1001"),
            1
        );
        assert_eq!(
            run.log.count(
                "launch pending off (the game's window is up, 17.5 s after the helper's launch)"
            ),
            1
        );
        assert_eq!(run.log.count("launch pending"), 2);
    }

    /// The loader gone and nothing of the game for 30 s: a failed start then, the game counted gone
    /// at the look that found it gone — the pause runs from there, so the first launch after it is
    /// due as the wait ends. Nothing is launched during a wait, though the 30 s since the launch
    /// pass in it. The second such start pauses 60 s from its look: not pending for the rest.
    #[test]
    fn a_handover_that_never_comes_is_a_failed_start_counted_from_when_the_loader_went() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        run.on(0.5);
        run.game_with_loader(&[], &[], false);
        run.fake.obs.launched_exit = Some((1001, Some(0)));
        run.on(1.0);
        let mut t = 1.5;
        while t <= 30.5 {
            run.on(t);
            assert!(run.sup.launch_pending(), "at {t} s");
            t += 0.5;
        }
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(run.sup.period.failed_starts, 0);
        assert_eq!(run.log.count("the next launch in"), 0);
        assert_eq!(
            run.log.count(
                "no process of the window exe has run since the launch (only the loader seen \
                 running, at 1 look(s))"
            ),
            1
        );
        run.on(31.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "nothing of the game came 30.0 s after the launched loader ScrydeGame.exe (pid \
                 1001, exited with code 0) went: the wait for its handover is over — the launch \
                 failed; the game counts as gone 30.0 s ago, at the look that found it gone, 1.0 s \
                 after the launch"
            ),
            1
        );
        assert_eq!(
            run.log.count_at(
                Level::Warn,
                "the game is gone 1.0 s after the launch (pid 1001; its window never came; \
                 nothing of the game came within 30.0 s after its loader went): failed start 1 of \
                 3 in a row"
            ),
            1
        );
        // The pause (30 s) counted from 1.0 s is over: launched again at once, pending again.
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
        // The second loader gone at its first look too, code 1: another wait, nothing launched.
        run.fake.obs.launched_exit = Some((1002, Some(1)));
        run.on(31.5);
        run.on_through(32.0, 61.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
        assert_eq!(run.sup.state(), HelperState::Launching);
        run.on(61.5);
        assert_eq!(run.sup.period.failed_starts, 2);
        assert_eq!(
            run.sup.period.gone_at,
            Some(run.t0 + Duration::from_secs_f64(31.5))
        );
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log
                .count("launch pending off (no launch of the helper's this session waits"),
            1
        );
        assert_eq!(run.sup.state(), HelperState::Waiting);
        assert_eq!(
            run.log
                .count("(pid 1002, exited with code 1) went: the wait for its handover is over"),
            1
        );
        // 60 s from 31.5 s, the look that found it gone — not from the wait's end.
        run.on_through(62.0, 91.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(!run.sup.launch_pending());
        run.on(91.5);
        assert_eq!(run.fake.launches.len(), 3);
        assert!(run.sup.launch_pending());
        assert_eq!(run.log.count_at(Level::Warn, "failed start"), 2);
    }

    /// A game that is its own launch exe has no loader to hand over: gone at once after the
    /// launch, it is a failed start at once, as ever.
    #[test]
    fn a_game_that_is_its_own_launch_exe_gone_at_once_is_a_failed_start_at_once() {
        let plain = r"C:\Games\Plain\game.exe".to_string();
        let mut run = Run::with(Record {
            launch_exe: plain.clone(),
            window_exe: plain,
            ..record()
        });
        run.on(0.0);
        run.fake.obs.launched_exit = Some((1001, Some(0)));
        run.on(0.5);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert!(!run.sup.launch_pending());
        assert_eq!(run.sup.state(), HelperState::Waiting);
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "the game is gone 0.5 s after the launch (pid 1001, exited with code 0), its \
                 window never up: no wait for a handover — the launch exe is the window exe: no \
                 loader to hand over"
            ),
            1
        );
        assert_eq!(
            run.log.count_at(
                Level::Warn,
                "the game is gone 0.5 s after the launch (pid 1001; its window never came): \
                 failed start 1 of 3"
            ),
            1
        );
        assert_eq!(run.log.count("handover is waited for"), 0);
        assert_eq!(run.log.count("waiting up to"), 0);
        // The pause from 0.5 s.
        run.on_through(1.0, 30.0);
        assert_eq!(run.fake.launches.len(), 1);
        run.on(30.5);
        assert_eq!(run.fake.launches.len(), 2);
    }

    /// The loader handed over — a process of the window exe seen — and then everything gone: the
    /// game crashed on start. A failed start at once, no wait.
    #[test]
    fn a_game_gone_after_its_loader_handed_over_is_a_failed_start_at_once() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        run.on(0.5);
        run.game_with_loader(&[10], &[11], false);
        run.on(1.0);
        run.game_with_loader(&[], &[11], false);
        run.on_through(1.5, 2.5);
        run.game_with_loader(&[], &[], false);
        run.on(3.0);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "a process of the window exe runs 1.0 s after the launch (pids [11]): the loader \
                 has handed over"
            ),
            1
        );
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "no wait for a handover — a process of the window exe ran since the launch"
            ),
            1
        );
        assert_eq!(
            run.log.count_at(
                Level::Warn,
                "the game is gone 3.0 s after the launch (pid 1001; its window never came): \
                 failed start 1 of 3"
            ),
            1
        );
        assert_eq!(run.log.count("waiting up to"), 0);
        // Its pause: 30 s from 3.0 s.
        run.on_through(3.5, 32.5);
        assert_eq!(run.fake.launches.len(), 1);
        run.on(33.0);
        assert_eq!(run.fake.launches.len(), 2);
    }

    /// The loader back during the wait (a launcher that restarts itself): the wait ends and the
    /// launch goes on; gone again with still nothing of the window exe, a wait of its own. Its exit
    /// seen only after the wait began is said then.
    #[test]
    fn a_loader_back_during_the_wait_ends_it_and_gone_again_is_waited_for_again() {
        let mut run = Run::new();
        run.on(0.0);
        run.on(0.5);
        assert_eq!(
            run.log.count(
                "the launched loader ScrydeGame.exe (pid 1001, its exit not seen yet) is gone"
            ),
            1
        );
        run.fake.obs.launched_exit = Some((1001, Some(0)));
        run.on(1.0);
        assert_eq!(
            run.log.count_at(
                Level::Debug,
                "the launched loader (pid 1001) exited with code 0: seen 0.5 s into the wait for \
                 its handover"
            ),
            1
        );
        run.on_through(1.5, 9.5);
        run.game_with_loader(&[20], &[], false);
        run.on_through(10.0, 20.0);
        assert_eq!(
            run.log.count(
                "the game's process came 9.5 s after the launched loader went (pids [20], maybe \
                 []; loaders among them [20])"
            ),
            1
        );
        assert!(run.sup.launch_pending());
        run.game_with_loader(&[], &[], false);
        run.on(20.5);
        assert_eq!(
            run.log.count(
                "(pid 1001, exited with code 0) is gone; no process of the window exe has run \
                 since the launch (only the loader seen running, at 21 look(s))"
            ),
            1
        );
        assert_eq!(run.log.count("(wait 2 of this launch)"), 1);
        run.on_through(21.0, 50.0);
        assert_eq!(run.sup.period.failed_starts, 0);
        assert_eq!(run.fake.launches.len(), 1);
        assert!(run.sup.launch_pending());
        run.on(50.5);
        assert_eq!(run.sup.period.failed_starts, 1);
        assert_eq!(
            run.log
                .count("the game is gone 20.5 s after the launch (pid 1001; its window never came"),
            1
        );
        // The pause from 20.5 s is over with the wait: launched again at once.
        assert_eq!(run.fake.launches.len(), 2);
    }

    /// The session ends during the wait for a handover: the wait stops with it — nothing pending,
    /// no failed start counted, nothing launched — and the next session starts afresh: its own
    /// launch at once, and the last session's wait never comes back as a failed start.
    #[test]
    fn a_wait_for_a_handover_ends_with_the_session_and_does_not_reach_the_next() {
        let mut run = Run::new();
        run.on(0.0);
        run.fake.obs.launched_exit = Some((1001, Some(0)));
        run.on(0.5);
        run.on_through(1.0, 5.0);
        assert!(run.sup.launch_pending());
        run.at(5.5, Signal::NotSet);
        assert_eq!(run.sup.state(), HelperState::Idle);
        assert!(!run.sup.launch_pending());
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "the wait for the handover of the launched loader (pid 1001, exited with code 0) \
                 stops with it, 5.0 s after its loader went: no failed start is counted, nothing \
                 is launched"
            ),
            1
        );
        assert_eq!(
            run.log.count("launch pending off (not allowed by the app)"),
            1
        );
        for s in 6..=60 {
            run.at(f64::from(s), Signal::NotSet);
        }
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(run.sup.period.failed_starts, 0);
        // The next session: launched at once, as the first of a session.
        run.on(61.0);
        assert_eq!(run.fake.launches.len(), 2);
        assert!(run.sup.launch_pending());
        assert_eq!(
            run.log
                .count_at(Level::Info, ": the first launch this session"),
            2
        );
        run.game(&[11], true);
        run.on_through(61.5, 130.0);
        assert_eq!(run.sup.period.failed_starts, 0);
        assert_eq!(run.sup.state(), HelperState::Running);
        assert_eq!(run.log.count_at(Level::Warn, "failed start"), 0);
        assert_eq!(run.log.count("the wait for the handover"), 1);
    }

    /* ── «Игра не запускается»: the failed-launch mark ─────────────────────────────────────── */

    /// The wall clock at the run's start, Unix ms.
    const WALL_MS: u64 = 1_790_000_000_000;

    /// `state.json` at `secs` into the run, the wall clock going with the run's.
    fn file_at(run: &Run, secs: f64) -> StateFile {
        let after = Duration::from_secs_f64(secs);
        run.sup.state_file(
            run.t0 + after,
            SystemTime::UNIX_EPOCH + Duration::from_millis(WALL_MS) + after,
            7,
            true,
        )
    }

    /// Three failed starts: given up, and the mark set — it outlives the session (the next one
    /// launches as ever) and comes off only when a launch survives: its window up a minute after it.
    #[test]
    fn giving_up_sets_the_mark_which_outlives_the_session_until_a_launch_survives() {
        let mut run = Run::new();
        run.fake.launch_error = Some(LaunchError::NotFound("file not found".into()));
        for s in 0..400 {
            run.on(f64::from(s));
        }
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        assert!(run.sup.failed_launch());
        // Since when: the third failed start (the starts at 0 s, 30 s and 90 s).
        assert_eq!(
            file_at(&run, 400.0).failed_launch_since_ms,
            Some(WALL_MS + 90_000)
        );
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "failed-launch mark set (3 failed starts in a row)"
            ),
            1
        );
        // The session over: idle, and still marked.
        run.at(400.5, Signal::NotSet);
        assert_eq!(run.sup.state(), HelperState::Idle);
        assert!(file_at(&run, 400.5).failed_launch_since_ms.is_some());
        // The next session launches at once; the game comes up and its window stays.
        run.fake.launch_error = None;
        run.on(500.0);
        assert_eq!(run.fake.launches.len(), 4);
        assert_eq!(
            run.log
                .count("the failed-launch mark stays until the game runs a minute"),
            1
        );
        run.game(&[11], true);
        run.on_through(509.0, 559.5);
        assert!(run.sup.failed_launch(), "not before the minute's mark");
        run.on(560.0);
        assert!(!run.sup.failed_launch());
        assert_eq!(file_at(&run, 560.0).failed_launch_since_ms, None);
        assert_eq!(
            run.log.count(
                "failed-launch mark taken off: the helper's launch survived — the game's window \
                 is up 60.0 s after it"
            ),
            1
        );
    }

    /// The loader that runs 10 min without the game's window sets the mark too; given up again in
    /// a later session, the mark keeps when it was first set.
    #[test]
    fn a_loader_given_up_on_sets_the_mark_and_a_second_give_up_keeps_it() {
        let mut run = Run::new();
        run.on(0.0);
        run.game_with_loader(&[10], &[], false);
        for s in 1..=600 {
            run.on(f64::from(s));
        }
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        let first = file_at(&run, 600.0).failed_launch_since_ms;
        assert_eq!(first, Some(WALL_MS + 600_000));
        run.game(&[], false);
        run.fake.obs.loader_pids.clear();
        run.at(601.0, Signal::NotSet);
        run.on(603.0);
        run.game_with_loader(&[20], &[], false);
        for s in 604..=1203 {
            run.on(f64::from(s));
        }
        assert_eq!(run.sup.state(), HelperState::GaveUp);
        assert_eq!(file_at(&run, 1203.0).failed_launch_since_ms, first);
        assert_eq!(run.log.count("the failed-launch mark stays (set"), 1);
    }

    /// The game started by hand (or before the session), its window up a minute on end: the mark
    /// comes off. A window gone in between starts the minute over; nothing is launched meanwhile.
    #[test]
    fn a_game_run_by_hand_a_minute_with_its_window_takes_the_mark_off() {
        let mut run = Run::new();
        let previous = StateFile {
            failed_launch_since_ms: Some(WALL_MS - 3_600_000),
            ..file_at(&Run::new(), 0.0)
        };
        run.sup.carry_over(
            &previous,
            SystemTime::UNIX_EPOCH + Duration::from_millis(WALL_MS),
            &mut run.log,
        );
        assert!(run.sup.failed_launch());
        run.game(&[11], true);
        run.on_through(0.0, 40.0);
        run.game(&[11], false);
        run.on(40.5);
        run.game(&[11], true);
        run.on_through(41.0, 100.5);
        assert!(run.sup.failed_launch(), "the minute starts over at 41 s");
        run.on(101.0);
        assert!(!run.sup.failed_launch());
        assert!(run.fake.launches.is_empty());
        assert_eq!(
            run.log.count(
                "failed-launch mark taken off: the game's window has been up 60.0 s on end (not \
                 launched by the helper this session"
            ),
            1
        );
    }

    /// At its start the helper keeps its last run's mark, as it was — and launches nothing for it;
    /// a file without one (an older helper's, or none set) carries nothing over.
    #[test]
    fn the_last_runs_mark_is_carried_over_and_launches_nothing() {
        let wall = SystemTime::UNIX_EPOCH + Duration::from_millis(WALL_MS);
        let mut run = Run::new();
        let previous = StateFile {
            state: HelperState::Idle,
            reason: "not allowed by the app: nothing is done".into(),
            failed_launch_since_ms: Some(WALL_MS - 30 * 60 * 1000),
            ..file_at(&Run::new(), 0.0)
        };
        run.sup.take_dirty();
        run.sup.carry_over(&previous, wall, &mut run.log);
        assert_eq!(
            file_at(&run, 0.0).failed_launch_since_ms,
            Some(WALL_MS - 30 * 60 * 1000)
        );
        // Kept as it was, whenever the file is written.
        assert_eq!(
            file_at(&run, 3600.0).failed_launch_since_ms,
            Some(WALL_MS - 30 * 60 * 1000)
        );
        assert!(run.sup.take_dirty(), "written at once");
        assert_eq!(
            run.log
                .count("the last run's failed-launch mark is carried over (set 30.0 min ago"),
            1
        );
        // Outside a session nothing is looked at or launched.
        run.at(1.0, Signal::NotSet);
        assert_eq!(run.fake.observed, 0);
        assert!(run.fake.launches.is_empty());
        // None to carry.
        let mut fresh = Run::new();
        let none = StateFile {
            failed_launch_since_ms: None,
            ..previous
        };
        fresh.sup.carry_over(&none, wall, &mut fresh.log);
        assert!(!fresh.sup.failed_launch());
        assert_eq!(
            fresh
                .log
                .count_at(Level::Debug, "has no failed-launch mark"),
            1
        );
    }

    /// `failed_launch_since_ms` is a field an app built before it skips, and this app reads an
    /// older helper's file without it as `None`: the format stays 1.
    #[test]
    fn the_mark_is_read_by_old_and_new_apps_alike() {
        let mut run = Run::new();
        run.fake.launch_error = Some(LaunchError::NotFound("file not found".into()));
        for s in 0..400 {
            run.on(f64::from(s));
        }
        let json = serde_json::to_string(&file_at(&run, 400.0)).unwrap();
        assert!(json.contains("\"failed_launch_since_ms\":"), "{json}");
        // An older app, from before `launch_pending` and the mark: its struct, as it was.
        #[derive(Deserialize)]
        #[allow(dead_code, reason = "only parsed")]
        struct StateFile020 {
            format: u32,
            state: HelperState,
            reason: String,
            since_ms: u64,
            updated_ms: u64,
            pid: u32,
            elevated: bool,
            launches: u32,
            failed_starts: u32,
            focus_set_foreground: u32,
            focus_uia: u32,
            focus_refused: u32,
        }
        let old: StateFile020 = serde_json::from_str(&json).unwrap();
        assert_eq!(old.state, HelperState::GaveUp);
        // An older helper's file, read here: no mark.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("failed_launch_since_ms");
        let older = StateFile::parse(value.to_string().as_bytes()).unwrap();
        assert_eq!(older.failed_launch_since_ms, None);
        assert_eq!(older.format, STATE_FORMAT);
    }

    /* ── A signal read seconds ago is not a permission ──────────────────────────────────────── */

    /// The session that allowed the tick ended while the tick looked (20 s
    /// under a full CPU) — the game is not launched, the signal's going off is taken in at once, and
    /// the next session launches at once, as any does.
    #[test]
    fn a_launch_is_not_done_when_the_signal_went_off_during_the_tick() {
        let mut run = Run::new();
        run.fake.tick_takes = Duration::from_secs(20);
        run.fake.rereads.push_back(Signal::NotSet);
        run.on(0.0);
        assert!(run.fake.launches.is_empty());
        assert_eq!(run.fake.reread, 1);
        assert_eq!(
            run.log.count_at(
                Level::Info,
                &format!(
                    "the app's signal went off during this tick (read 20.0 s ago): launching {} \
                     (the first launch this session) not done",
                    record().launch_exe
                )
            ),
            1
        );
        assert_eq!(run.log.count("not allowed any more"), 1);
        assert_eq!(run.sup.state(), HelperState::Idle);
        assert!(!run.sup.launch_pending());
        // Off on the next tick too: nothing new is said or done.
        run.fake.tick_takes = Duration::ZERO;
        run.at(20.5, Signal::NotSet);
        assert_eq!(run.log.count("not allowed any more"), 1);
        assert!(run.fake.launches.is_empty());
        // The next session: the signal read again before the launch, still set — launched at once.
        run.on(30.0);
        assert_eq!(run.fake.launches.len(), 1);
        assert_eq!(run.fake.reread, 2);
        assert_eq!(
            run.log
                .count_at(Level::Debug, "the app's signal read again before launching"),
            1
        );
    }

    /// The count for the lost window reached 30 s at a tick's start, and the signal went off while
    /// the tick looked: no WM_CLOSE, the count stops at its figure — and a later session counts
    /// afresh, the full 30 s.
    #[test]
    fn a_hung_game_is_not_closed_when_the_signal_went_off_during_the_tick() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 129.5);
        run.fake.rereads.push_back(Signal::NotSet);
        run.fake.tick_takes = Duration::from_secs(16);
        run.on(130.0);
        assert!(run.fake.closes.is_empty());
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "the app's signal went off during this tick (read 16.0 s ago): closing the hung \
                 game (WM_CLOSE to the windows of pids [11]) not done"
            ),
            1
        );
        assert_eq!(
            run.log
                .count("the count for the game's lost window stops with it, at 30.0 s"),
            1
        );
        assert_eq!(run.log.count("the game hangs:"), 0);
        assert_eq!(run.sup.state(), HelperState::Idle);
        run.fake.tick_takes = Duration::ZERO;
        for s in 131..=200 {
            run.at(f64::from(s), Signal::NotSet);
        }
        assert!(run.fake.closes.is_empty());
        // A session again, the same process still without its window: 30 s from its start.
        run.on_through(201.0, 230.5);
        assert!(run.fake.closes.is_empty());
        run.on(231.0);
        assert_eq!(run.fake.closes, vec![vec![11]]);
    }

    /// WM_CLOSE went out during the session; the signal went off before TerminateProcess, between
    /// two of the game's processes: the first is ended, the second is not, and the closing stops.
    #[test]
    fn terminate_process_reads_the_signal_again_before_each_process() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11, 12], false);
        run.on_through(100.0, 139.5);
        assert_eq!(run.fake.closes, vec![vec![11, 12]]);
        assert!(run.fake.terminated.is_empty());
        run.fake.rereads.extend([Signal::Allowed, Signal::NotSet]);
        run.fake.tick_takes = Duration::from_secs(3);
        run.on(140.0);
        assert_eq!(run.fake.terminated, vec![11]);
        assert_eq!(
            run.log.count_at(
                Level::Info,
                &format!(
                    "the app's signal went off during this tick (read 3.0 s ago): \
                     TerminateProcess on pid 12 ({}) not done",
                    record().window_exe
                )
            ),
            1
        );
        assert_eq!(
            run.log
                .count("the closing of the hung game stops with it (after WM_CLOSE"),
            1
        );
        run.fake.tick_takes = Duration::ZERO;
        for s in 141..=200 {
            run.at(f64::from(s), Signal::NotSet);
        }
        assert_eq!(run.fake.terminated, vec![11]);
    }

    /// Another window in front of the game's: the signal gone off before the try — the game is not
    /// brought forward, nor is it counted as refused; set again, it is, as ever.
    #[test]
    fn the_game_is_not_brought_forward_when_the_signal_went_off_during_the_tick() {
        let mut run = Run::new();
        run.game(&[10], true);
        run.fake.obs.foreground = Foreground::Other {
            window: 5,
            exe: "notepad.exe".into(),
        };
        run.fake.focus_works = Some(FocusMethod::SetForeground);
        run.fake.rereads.push_back(Signal::NotSet);
        run.fake.tick_takes = Duration::from_secs(5);
        run.on(0.0);
        assert!(run.fake.focuses.is_empty());
        assert_eq!(run.sup.totals.focus_refused, 0);
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "the app's signal went off during this tick (read 5.0 s ago): bringing the game's \
                 window to the front (notepad.exe in front) not done"
            ),
            1
        );
        assert_eq!(run.sup.state(), HelperState::Idle);
        run.fake.tick_takes = Duration::ZERO;
        run.at(0.5, Signal::NotSet);
        run.on(1.0);
        assert_eq!(run.fake.focuses.len(), 1);
        assert_eq!(
            run.log
                .count("focus back on the game via SetForegroundWindow"),
            1
        );
    }

    /// Ticks seconds apart (a loaded PC): the time between their reads of the signal is not counted
    /// toward closing the game — the app may have ended a session and begun another — so the count
    /// starts over; with ticks on time it runs its 30 s and the game is closed as ever. A closing
    /// begun and a gap before its TerminateProcess: dropped, counted again from the lost window.
    #[test]
    fn a_count_toward_closing_starts_over_after_a_gap_between_the_signals_reads() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 120.0);
        // The next tick reads it 9 s after the last (slow ticks took 16–25 s): 29 s would count
        // otherwise.
        run.on(129.0);
        assert_eq!(
            run.log.count_at(
                Level::Info,
                "the app's signal was not read for 9.0 s (over 2.5 s: a slow tick) — the app may \
                 have ended a session and begun another meanwhile: the count for the game's lost \
                 window starts over (it was at 29.0 s)"
            ),
            1
        );
        run.on_through(129.5, 158.5);
        assert!(run.fake.closes.is_empty(), "30 s are counted from 129 s");
        run.on(159.0);
        assert_eq!(run.fake.closes, vec![vec![11]]);
        run.on(175.0);
        assert!(run.fake.terminated.is_empty());
        assert_eq!(
            run.log
                .count("the closing of the hung game is dropped (after WM_CLOSE, begun 16.0 s ago"),
            1
        );
        assert_eq!(run.sup.state(), HelperState::Launching);
        // On time again: 30 s, WM_CLOSE, 10 s, TerminateProcess.
        run.on_through(175.5, 215.0);
        assert_eq!(run.fake.closes.len(), 2);
        assert_eq!(run.fake.terminated, vec![11]);
    }

    /// The normal path reads the signal again once per action, and acts as it always did.
    #[test]
    fn each_action_reads_the_signal_again_once() {
        let mut run = Run::new();
        run.launched_and_running(99.5);
        run.game(&[11], false);
        run.on_through(100.0, 140.0);
        run.game(&[], false);
        run.on(140.5);
        // The launch, WM_CLOSE, TerminateProcess, the launch again.
        assert_eq!(run.fake.reread, 4);
        assert_eq!(
            (
                run.fake.launches.len(),
                run.fake.closes.len(),
                run.fake.terminated.len()
            ),
            (2, 1, 1)
        );
        assert_eq!(run.log.count("went off during this tick"), 0);
    }

    #[test]
    fn a_slow_tick_is_said_with_how_long_it_took() {
        assert_eq!(slow_tick(Duration::from_millis(30)), None);
        assert_eq!(slow_tick(SLOW_TICK), None);
        let line = slow_tick(Duration::from_millis(16_300)).unwrap();
        assert!(line.starts_with("tick took 16.3 s (over 2.0 s"), "{line}");
        assert_eq!(SIGNAL_GAP_MAX, SLOW_TICK + POLL);
    }

    #[test]
    fn the_pauses_double_to_their_ceilings() {
        assert_eq!(backoff(0), Duration::ZERO);
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(4), Duration::from_secs(240));
        assert_eq!(backoff(5), BACKOFF_MAX);
        assert_eq!(backoff(40), BACKOFF_MAX);
        assert_eq!(focus_delay(1), Duration::from_secs(1));
        assert_eq!(focus_delay(4), Duration::from_secs(8));
        assert_eq!(focus_delay(5), FOCUS_RETRY_MAX);
        assert_eq!(focus_delay(99), FOCUS_RETRY_MAX);
    }
}
