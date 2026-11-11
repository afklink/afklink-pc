//! The game helper of «Только игра»: during a session it launches the game the owner approved,
//! closes it when it hangs without its window (a crash report of its own) so it can be launched
//! again, and brings its window back to the front (the supervisor's «A game that hangs»).
//!
//! # Trust
//!
//! It runs from a Task Scheduler task, at the level the launch exe needs: HIGHEST for a game whose
//! manifest (or compatibility layer) asks for administrator, LUA for any other — an ordinary game
//! never runs as administrator. What it launches and which window is the game come only from the
//! [`Record`] beside its exe in `Program Files\AFKLink\GameHelper\<SID>`, written by the app's
//! elevated setup after Windows' confirmation; users read that directory and cannot write it.
//! Nothing else configures the helper: no arguments, no config.json. It closes nothing but
//! processes of the record's two exes in its own Windows session — a game that hangs, during a
//! session — and never one whose path it cannot read.
//!
//! The app's one say is the signal ([`SIGNAL_NAME`]): an event in the session's `Local\` namespace
//! that the helper opens and closes again on every tick. Absent (the app is not running),
//! unreadable or not set: nothing is done. It is a permission, not a command — a process that
//! forges it can only make the helper launch or focus the game the owner approved, or close that
//! game when it runs with no window.
//!
//! Its log ([`log`]) and `state.json` go to the install directory when it runs elevated, and to
//! `user\` there (writable by the owner) when it does not: an elevated helper never writes where
//! the owner's other programs could. The elevated setup logs to `setup.log` in the install
//! directory, never to the helper's file.

mod log;
mod record;
mod supervisor;
#[cfg(windows)]
mod windows;

use std::time::Duration;

pub use log::{
    format_line, parse_line, unix_ms, utc_stamp, HelperLog, Level, Log, LOG_FILE, LOG_MAX_BYTES,
    LOG_OLD_FILE, SETUP_LOG_FILE, SETUP_LOG_OLD_FILE,
};
pub use record::{
    check_class, check_launch_exe, check_path, default_launch_exe, file_name, layers_require_admin,
    manifest_execution_level, manifest_text, run_level_for, same_path, valid_sid, ExecutionLevel,
    Record, RunLevel, RECORD_FORMAT,
};
pub use supervisor::{
    backoff, focus_delay, slow_tick, CloseRequest, ClosedWindow, Desktop, FocusMethod,
    FocusOutcome, Foreground, GameProcess, GameWindow, HelperState, LaunchError, Observation,
    Signal, StateFile, Supervisor, TerminateOutcome, BACKOFF_BASE, BACKOFF_MAX, CLOSE_GRACE,
    FAST_EXIT_WITHIN, FOCUS_RETRY_MAX, FOCUS_RETRY_MIN, HANDOVER_WITHIN, LAUNCHER_WAIT_MAX,
    LAUNCH_MIN_INTERVAL, MAX_FAILED_STARTS, POLL, SIGNAL_GAP_MAX, SLOW_TICK, STATE_FORMAT,
    TERMINATE_EXIT_CODE, WINDOW_LOST_AFTER, WINDOW_WITHIN,
};

/// The helper's exe in its install directory.
pub const EXE_NAME: &str = "afklink-game-helper.exe";
/// What it may do: written by the setup only (see [`Record`]).
pub const RECORD_FILE: &str = "record.json";
/// Its state for the app (see [`StateFile`]).
pub const STATE_FILE: &str = "state.json";
/// The subdirectory a helper without rights writes its log and state in.
pub const USER_DIR: &str = "user";
/// The app's signal: set while the helper may act.
pub const SIGNAL_NAME: &str = r"Local\AFKLink.GameHelper.Allow";
/// `state.json` is rewritten at least this often, so the app can tell a stopped helper by its age.
pub const STATE_REFRESH: Duration = Duration::from_secs(30);
/// The helper task's priority in Task Scheduler: 5, a normal-priority process (as programs started
/// from Explorer). Without it a task gets Task Scheduler's default 7 — below normal: under a full
/// CPU the helper's ticks then took 16–25 s (it acted on a signal read that long ago), and the game
/// it launched inherited the class. The setup writes it into the
/// record ([`Record::task_priority`]); a record without it is an older setup's, and the app asks
/// for the setup again («Нужно обновление»).
pub const TASK_PRIORITY: u8 = 5;

/// The helper's process: runs until its task stops it; the exit code says why it could not start.
pub fn run() -> i32 {
    #[cfg(windows)]
    {
        windows::run()
    }
    #[cfg(not(windows))]
    {
        1
    }
}
