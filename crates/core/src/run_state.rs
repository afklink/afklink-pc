//! How this agent's previous process ended, and the record on disk that lets the next one say so:
//! `agent_hello.boot_id` and `agent_hello.last_exit`. With them the server tells a session the last
//! process left behind when it died (`ended_detail` `crash`) from one the network took (`network`).
//!
//! The record is `run_state.json` in the data directory ([`crate::paths::afklink_dir`]:
//! `%APPDATA%\AFKLink`, or the CLI's `--data-dir`): one small JSON object, always rewritten whole
//! through a temporary file that is flushed to the disk before the rename, so a reader finds the
//! old record or the new one, never half of either, even after the power is cut.
//!
//! # Use
//!
//! - [`RunState::open`] reads what the previous process left and decides its `last_exit`. It writes
//!   nothing, so the desktop app can read before Tauri starts.
//! - [`RunState::claim`] makes the record this process's once it is the one instance, and keeps it
//!   alive every [`ALIVE_EVERY`] on a thread of its own.
//! - [`record_exit`], [`record_panic`] and [`take_back_exit`] record how this process ends. A
//!   process may hear of its end more than once; the rule for which exit stands is on `replaces`.
//!
//! Sleep is not an exit: the process carries on after it, and `alive_at` with it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use afklink_protocol::metrics::{PreviousRecord, EPOCH_MS_MAX};
use afklink_protocol::{AgentExitKind, AgentLastExit};
use afklink_transport::HelloInfo;

use crate::build_info::BuildInfo;
use crate::sync::lock;

/// The file's name in the data directory.
pub const FILE_NAME: &str = "run_state.json";

/// The record's format; a later one may add fields (an older reader ignores them).
const VERSION: u32 = 1;

/// How often a running process writes that it is alive: how far before its death a `crash` is
/// dated, at most. One small file a minute.
pub const ALIVE_EVERY: Duration = Duration::from_secs(60);

/// An exit recorded this long ago by a process still running did not happen: the next touch takes
/// it back. Well past the slowest real exit (an update's fallback, a goodbye's budget).
pub const EXIT_STALE_AFTER: Duration = Duration::from_secs(120);

/// How many times a panic hook tries the record's lock, 10 ms apart, before writing without it.
const PANIC_LOCK_TRIES: u32 = 20;

/// How long a real reboot takes past the previous process's death: a blue screen's dump and
/// restart, a reset, power back after a short cut — the firmware, Windows' loader and the kernel up
/// to its first tick — about a minute on a slow PC; doubled.
pub const REBOOT_SLACK: Duration = Duration::from_secs(120);

/// A boot this soon after the previous process's last sign of life is one it went down with: it
/// died no later than [`ALIVE_EVERY`] after its last mark, and the machine was back within
/// [`REBOOT_SLACK`] — three minutes in all. A boot later than that tells nothing: the process may
/// have died alone earlier, or the PC slept (`GetTickCount64` counts sleep) and lost power asleep.
pub const RESTART_WINDOW: Duration =
    Duration::from_secs(ALIVE_EVERY.as_secs() + REBOOT_SLACK.as_secs());

/// The name tokio gives its worker and blocking-pool threads: Tauri's shared runtime. A write made
/// on one is not flushed there — a flush may stall the worker — but by the run state's thread, at
/// once.
const ASYNC_WORKER: &str = "tokio-runtime-worker";

/// A flush of the record that took this long is a warning: the disk is slow or stalled, and the
/// thread that wrote (the main thread on the way out) waited on it.
pub const SLOW_FLUSH: Duration = Duration::from_millis(500);

/// The temporary file of the panic hook's write made without the record's lock: not the one another
/// thread's write may be using at that moment.
const PANIC_TMP_SUFFIX: &str = ".panic.tmp";

/// What [`RunState::put`] did with a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Put {
    /// Put in place.
    Renamed,
    /// Dropped: the panic's record, written without the lock, is on disk and stays.
    Sealed,
}

/// How a write puts the record's bytes on the disk before the rename: `File::sync_all`
/// (`FlushFileBuffers`); a test puts in one that fails.
type FlushFn = fn(&std::fs::File) -> std::io::Result<()>;

/// How this process is ending, as the code that ends it knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// The owner quit: the tray's «Выход», the CLI's Ctrl-C, the CLI stopping by itself.
    App,
    /// The app exits so the update's watchdog can put the new version in place.
    Update,
    /// Windows ends the session: shut down, restart, log off.
    OsShutdown,
    /// A panic on the main thread: the process goes with it.
    Panic,
    /// The orchestrator (`Agent::run`) returned while the app was not leaving, and the desktop app
    /// relaunches itself (`supervise`): the contract's `crash` — the process ended abnormally —
    /// since it has no word of its own for it.
    AgentFailed,
}

impl ExitKind {
    /// The contract's word for it.
    pub const fn wire(self) -> AgentExitKind {
        match self {
            Self::App => AgentExitKind::AppExit,
            Self::Update => AgentExitKind::UpdateExit,
            Self::OsShutdown => AgentExitKind::OsShutdown,
            Self::Panic => AgentExitKind::Panic,
            Self::AgentFailed => AgentExitKind::Crash,
        }
    }
}

/// The exit a record says, with its time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ExitMark {
    kind: AgentExitKind,
    at: u64,
}

/// What a panic hook writes beside the `panic` exit, for the next start's `agent_crashed`:
/// where, hashed — never the panic's message, which may carry anything — on which
/// thread, and after how long.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PanicMark {
    /// The panic's location (`file:line:column`) hashed ([`place_hash`]): the same place hashes the
    /// same, and nothing of the source path is sent.
    place_hash: String,
    /// The panicking thread's name, held to the contract's shape ([`thread_name`]).
    thread: String,
    /// Seconds from the process's start to the panic.
    uptime_s: u64,
}

/// The file's content:
///
/// ```json
/// {"v":1,"boot_id":"6b1e0c2a-…","pid":4242,"version":"0.5.1","started_at":1789599000000,
///  "alive_at":1789599900000,"exit":{"kind":"app_exit","at":1789599960000}}
/// ```
///
/// | when                                         | written                                       |
/// |----------------------------------------------|-----------------------------------------------|
/// | the process claims it ([`RunState::claim`])  | a new `boot_id`, `started_at` = `alive_at` = now, no `exit` |
/// | every [`ALIVE_EVERY`]                        | `alive_at` = now                              |
/// | a clean exit ([`record_exit`])               | `exit`: `app_exit` (the tray's «Выход», the CLI stopped), `update_exit` (the exit for an update), `os_shutdown` (Windows ends the session) |
/// | a panic on the main thread ([`record_panic`])| `exit`: `panic`, and `panic`: where (hashed), the thread, the uptime — the next start's `agent_crashed` ([`RunState::previous_crash`]) |
/// | Windows cancels the end of the session       | the `os_shutdown` is taken back ([`take_back_exit`]) |
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    v: u32,
    boot_id: String,
    #[serde(default)]
    pid: u32,
    /// The version that wrote it (`CARGO_PKG_VERSION`, the workspace's): `agent_crashed.version`.
    /// Absent from records of builds before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    started_at: u64,
    alive_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit: Option<ExitMark>,
    /// With a `panic` exit: the panic's summary. Absent from records of builds before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    panic: Option<PanicMark>,
}

/// The version this build writes in its record.
const THIS_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A panic's location, hashed: FNV-1a 64 of `file:line:column`, 16 lowercase hex digits
/// (`PLACE_HASH_PATTERN`). A stable name for the place, not a secret: the same place in the same
/// build hashes the same, so one bug is one row.
pub fn place_hash(file: &str, line: u32, column: u32) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let text = format!("{file}:{line}:{column}");
    let hash = text
        .bytes()
        .fold(OFFSET, |h, b| (h ^ u64::from(b)).wrapping_mul(PRIME));
    format!("{hash:016x}")
}

/// A thread's name as the contract takes it (`THREAD_NAME_PATTERN`): itself when it fits, else
/// `unnamed` for none and `other` for one that does not.
pub fn thread_name(name: Option<&str>) -> &str {
    match name {
        None => "unnamed",
        Some(n) if afklink_protocol::metrics::is_thread_name(n) => n,
        Some(_) => "other",
    }
}

/// The previous process's panic, as the next start reports it (`agent_crashed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashSummary {
    /// When it panicked, Unix ms on this PC's clock: the event's `at`, the same on every resend.
    pub at: u64,
    pub version: String,
    pub place_hash: String,
    pub thread: String,
    pub uptime_s: u64,
    /// The crashed process's boot id.
    pub boot_id: Option<String>,
}

/// What [`RunState::open`] found of the previous process.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Previous {
    /// No file: a first run, or a build that kept none.
    Missing,
    /// A file that could not be read at all (not its absence), or a whole one this build cannot
    /// read as a record (another build's, a rollback's leftover), and why: nothing is known of its
    /// end.
    Unreadable(String),
    /// A torn file ([`is_torn`]) — empty, zeros, cut short — and what it held. Only the previous
    /// process writes it, whole and renamed into place, so this is the PC going down while it was
    /// being written. `modified`: the file's modified time, when it is a possible one (after
    /// 1970, within the contract's bounds, not after this start).
    Torn {
        what: String,
        modified: Option<u64>,
    },
    Found(Record),
}

impl Previous {
    /// The contract's word for it (`agent_started.previous_record`).
    fn wire(&self) -> PreviousRecord {
        match self {
            Self::Missing => PreviousRecord::Missing,
            Self::Unreadable(_) | Self::Torn { .. } => PreviousRecord::Unreadable,
            Self::Found(_) => PreviousRecord::Found,
        }
    }
}

/// How the previous process ended, decided from what [`RunState::open`] found, and why (the why is
/// for the log):
///
/// | the file                       | `last_exit`                                               |
/// |--------------------------------|-----------------------------------------------------------|
/// | an exit recorded               | that kind, at its time                                    |
/// | running, no exit recorded      | `crash`, at `alive_at` — the last minute it was known alive |
/// | missing                        | `unknown`: a first run, or a build that kept none         |
/// | torn: empty, zeros, cut short ([`is_torn`]) | `crash`, at the file's modified time when it is a possible one, and a warning: the PC went down while the previous process was writing it |
/// | there, but it cannot be read, or is whole JSON this build does not read (another build's) | `unknown`, and a warning |
fn decide(previous: &Previous) -> (AgentLastExit, &'static str) {
    let at = |ms: u64| (ms > 0 && ms <= EPOCH_MS_MAX).then_some(ms);
    match previous {
        Previous::Missing => (
            AgentLastExit {
                kind: AgentExitKind::Unknown,
                at: None,
            },
            "no run state file: a first run, or the previous build kept none",
        ),
        Previous::Unreadable(_) => (
            AgentLastExit {
                kind: AgentExitKind::Unknown,
                at: None,
            },
            "the run state file could not be read, or holds a record this build does not read",
        ),
        Previous::Torn { modified, .. } => (
            AgentLastExit {
                kind: AgentExitKind::Crash,
                at: *modified,
            },
            "the run state file is there but holds no record (empty, zeros or cut short): the PC \
             went down while the previous process was writing it; a crash, dated by the file's \
             modified time",
        ),
        Previous::Found(record) => match record.exit {
            Some(mark) => (
                AgentLastExit {
                    kind: mark.kind,
                    at: at(mark.at),
                },
                "the previous process recorded its exit",
            ),
            None => (
                AgentLastExit {
                    kind: AgentExitKind::Crash,
                    at: at(record.alive_at),
                },
                "the previous process said it was running and recorded no exit: it died without \
                 a word (killed, a native fault, power lost); dated by its last alive mark",
            ),
        },
    }
}

/// The verdict of [`restarted`]: whether the previous process went down with the PC, the boot's gap
/// after its last sign of life (ms, negative when the boot came first; for the log), and why.
///
/// `agent_started` carries the verdict as `pc_restarted`, beside what was found (`previous_record`:
/// `found`, `missing`, `unreadable`). The boot time is now minus `GetTickCount64`
/// ([`windows_boot_ms`]); only the verdict goes on the wire, never the boot time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Restart {
    verdict: Option<bool>,
    gap_ms: Option<i64>,
    why: &'static str,
}

/// Whether the previous process went down with the PC, given when Windows booted (`boot_at`, Unix
/// ms on this PC's clock).
///
/// A process cannot outlive a boot, so the boot is either before it started or after it died; it
/// died between its last sign of life (the record's alive mark, or the file's time for a record
/// that held nothing) and [`ALIVE_EVERY`] later, the next mark it never wrote. So:
///
/// - a boot before it started (for a file's time: before that time): `false` — this Windows was
///   running while it was, and it ended on its own (or across a fast startup, which resumes Windows
///   rather than booting it);
/// - a boot within [`RESTART_WINDOW`] after its last sign of life: `true` — it went down with the
///   PC (power, a reset, a blue screen, a shutdown or restart);
/// - a boot later than that: nothing said. It may have died alone and the PC been restarted days
///   later, or the PC slept (`GetTickCount64` counts sleep) and lost power asleep;
/// - a boot inside its run: impossible on one clock — the clock was moved; nothing said.
fn restarted(previous: &Previous, boot_at: Option<u64>) -> Restart {
    let none = |why| Restart {
        verdict: None,
        gap_ms: None,
        why,
    };
    let Some(boot) = boot_at else {
        return none("when Windows booted is not known");
    };
    let (started, last) = match previous {
        Previous::Missing => return none("no record to compare the boot with"),
        Previous::Unreadable(_) => return none("the record could not be read"),
        Previous::Torn { modified: None, .. } => {
            return none("the record held nothing and its file has no possible time")
        }
        // The file's time is the only one: the process ran then, so a boot before it is "before".
        Previous::Torn {
            modified: Some(m), ..
        } => (*m, *m),
        Previous::Found(r) if r.started_at == 0 || r.alive_at == 0 => {
            return none("the record has no times to compare the boot with")
        }
        Previous::Found(r) => (r.started_at, r.alive_at),
    };
    let gap = i64::try_from(boot).unwrap_or(i64::MAX) - i64::try_from(last).unwrap_or(i64::MAX);
    let window = i64::try_from(RESTART_WINDOW.as_millis()).unwrap_or(i64::MAX);
    let (verdict, why) = if boot < started {
        (
            Some(false),
            "Windows was running before the previous process's run: it ended on its own (or \
             across a fast startup)",
        )
    } else if gap <= 0 {
        (
            None,
            "Windows' boot falls inside the previous process's run: the clock was moved; not told",
        )
    } else if gap <= window {
        (
            Some(true),
            "Windows booted within the restart window after the previous process's last sign of \
             life: it went down with the PC",
        )
    } else {
        (
            None,
            "Windows booted long after the previous process's last sign of life: it may have died \
             alone before, or the PC slept and lost power; not told",
        )
    };
    Restart {
        verdict,
        gap_ms: Some(gap),
        why,
    }
}

/// When Windows last booted afresh, Unix ms on this PC's clock: `now` minus the milliseconds since
/// the boot (`GetTickCount64`, which counts sleep and hibernation, and goes on across a fast
/// startup). A read of a counter Windows keeps in memory: no wait, safe on any thread. `None` off
/// Windows, or when the count is past `now` (a clock before the boot).
fn windows_boot_ms(now: u64) -> Option<u64> {
    #[cfg(windows)]
    {
        // SAFETY: no arguments and no state; it returns a counter.
        let up = unsafe { windows::Win32::System::SystemInformation::GetTickCount64() };
        let boot = now.checked_sub(up).filter(|&b| b > 0);
        if boot.is_none() {
            tracing::debug!(
                now,
                up_ms = up,
                "run state: the time since the boot is past the clock's now; when Windows booted \
                 is not known"
            );
        }
        boot
    }
    #[cfg(not(windows))]
    {
        tracing::debug!(now, "run state: not Windows; the boot time is not read");
        None
    }
}

/// Whether bytes that are not a record (`e`) are what an unflushed write leaves after a power cut —
/// the file torn — rather than a whole file of another shape: nothing, zeros and blanks, any zero
/// byte (this code's JSON never has one; a cluster not yet written reads as zeros), or JSON cut
/// short (`e` at the end of the input). A whole JSON value of the wrong shape — a later build's
/// record, which a rollback can leave — is not torn.
fn is_torn(bytes: &[u8], e: &serde_json::Error) -> bool {
    bytes.iter().all(|&b| b == 0 || b.is_ascii_whitespace()) || bytes.contains(&0) || e.is_eof()
}

/// What a file that holds no record held, for the log: nothing, zeros, or something else.
fn torn_shape(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "empty".into()
    } else if bytes.iter().all(|&b| b == 0) {
        format!("{} zero bytes", bytes.len())
    } else if bytes.iter().all(|&b| b == 0 || b.is_ascii_whitespace()) {
        format!("{} bytes of zeros and blanks", bytes.len())
    } else {
        format!("{} bytes, not a record", bytes.len())
    }
}

/// The file's modified time, Unix ms, when it is a possible one for a record written before `now`:
/// after 1970, within the contract's bounds and not after `now` (a clock moved back since). Said at
/// debug when it is not.
fn modified_ms(path: &Path, now: u64) -> Option<u64> {
    let modified = match std::fs::metadata(path).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(
                file = %path.display(),
                "run state: the file's modified time is not known ({e})"
            );
            return None;
        }
    };
    let ms = modified
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    if ms > 0 && ms <= EPOCH_MS_MAX && ms <= now {
        Some(ms)
    } else {
        tracing::debug!(
            modified_ms = ms,
            now,
            "run state: the file's modified time is not a possible one (before 1970, past the \
             bounds or after now); the crash is not dated"
        );
        None
    }
}

/// Whether `new` replaces `old` as the exit that stands.
///
/// A process may hear of its end more than once: an update or a shutdown records its kind, and the
/// app's exit that follows would say `app_exit`. The more specific word stands: `app_exit` never
/// replaces another kind, and another kind replaces `app_exit`. A panic replaces anything, since it
/// is what ended the process. An exit recorded by a process still alive [`EXIT_STALE_AFTER`] later
/// did not happen (a shutdown cancelled without a word) and is taken back by the next touch.
fn replaces(old: AgentExitKind, new: AgentExitKind) -> bool {
    match (old, new) {
        (_, AgentExitKind::Panic) => old != AgentExitKind::Panic,
        (_, AgentExitKind::AppExit) => false,
        (AgentExitKind::AppExit, _) => true,
        _ => false,
    }
}

/// Unix ms now, on this PC's clock; 0 before 1970.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// This process's run state: what the previous one left, and the record this one keeps.
#[derive(Debug)]
pub struct RunState {
    path: PathBuf,
    boot_id: String,
    started_at: u64,
    previous: Previous,
    last_exit: AgentLastExit,
    why: &'static str,
    /// Whether the previous process went down with the PC ([`restarted`]).
    restart: Restart,
    /// When Windows booted, Unix ms on this PC's clock, for the log only (never on the wire).
    boot_at: Option<u64>,
    record: Mutex<Record>,
    claimed: AtomicBool,
    /// A write failed last time: the next failure is debug, the next success says it recovered.
    write_failed: AtomicBool,
    /// A flush failed last time: the same, for the flush.
    flush_failed: AtomicBool,
    /// How a write flushes the temporary file ([`FlushFn`]).
    flush: FlushFn,
    /// A panic hook wrote the record without its lock ([`Self::panicked`]): the record in memory
    /// lacks the panic, so no later write may put it on disk over the panic's.
    panic_sealed: AtomicBool,
    /// Wakes the run state's thread to write a flushed mark now: a write made on an async worker
    /// is not flushed there ([`ASYNC_WORKER`]). Set by [`Self::claim`] once the thread runs.
    wake: OnceLock<std::sync::mpsc::SyncSender<()>>,
}

impl RunState {
    /// Read what the previous process left in `dir` and decide how it ended, and whether Windows
    /// booted since ([`windows_boot_ms`]: a counter read, no wait); make this process's boot id.
    /// Writes nothing ([`Self::claim`] does).
    pub fn open(dir: &Path) -> Self {
        let now = now_ms();
        Self::read_at(dir, now, windows_boot_ms(now))
    }

    /// [`Self::open`] in the data directory ([`crate::paths::afklink_dir`]). `None` when there is
    /// none to be had (it could not be created), which costs the hello its last exit and nothing
    /// else.
    pub fn open_default() -> Option<Self> {
        match crate::paths::afklink_dir() {
            Ok(dir) => Some(Self::open(&dir)),
            Err(e) => {
                tracing::warn!(
                    "run state: no data directory ({e:#}); the hello says nothing of the previous \
                     process"
                );
                None
            }
        }
    }

    /// [`Self::read_at`] without a boot time (tests).
    #[cfg(test)]
    fn open_at(dir: &Path, now: u64) -> Self {
        Self::read_at(dir, now, None)
    }

    /// [`Self::open`] at `now`, with Windows booted at `boot_at` (both Unix ms on this PC's clock).
    pub(crate) fn read_at(dir: &Path, now: u64, boot_at: Option<u64>) -> Self {
        let path = dir.join(FILE_NAME);
        let previous = match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Record>(&bytes) {
                Ok(record) => Previous::Found(record),
                Err(e) if is_torn(&bytes, &e) => Previous::Torn {
                    what: format!("{} ({e})", torn_shape(&bytes)),
                    modified: modified_ms(&path, now),
                },
                Err(e) => Previous::Unreadable(format!(
                    "{}, whole but not a record this build reads (another build's?): {e}",
                    torn_shape(&bytes)
                )),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Previous::Missing,
            Err(e) => Previous::Unreadable(format!("read: {e}")),
        };
        let (last_exit, why) = decide(&previous);
        let restart = restarted(&previous, boot_at);
        let boot_id = uuid::Uuid::new_v4().to_string();
        tracing::debug!(
            file = %path.display(),
            found = previous.wire().as_str(),
            last_exit = last_exit.kind.as_str(),
            last_exit_at = ?last_exit.at,
            pc_restarted = ?restart.verdict,
            boot_at = ?boot_at,
            boot_gap_ms = ?restart.gap_ms,
            restart_window_s = RESTART_WINDOW.as_secs(),
            restart_why = restart.why,
            boot_id = %boot_id,
            "run state read (nothing written until this process claims it)"
        );
        let record = Record {
            v: VERSION,
            boot_id: boot_id.clone(),
            pid: std::process::id(),
            version: Some(THIS_VERSION.to_string()),
            started_at: now,
            alive_at: now,
            exit: None,
            panic: None,
        };
        Self {
            path,
            boot_id,
            started_at: now,
            previous,
            last_exit,
            why,
            restart,
            boot_at,
            record: Mutex::new(record),
            claimed: AtomicBool::new(false),
            write_failed: AtomicBool::new(false),
            flush_failed: AtomicBool::new(false),
            flush: std::fs::File::sync_all,
            panic_sealed: AtomicBool::new(false),
            wake: OnceLock::new(),
        }
    }

    /// What this start found of the previous process's record (`agent_started.previous_record`).
    pub fn previous_record(&self) -> PreviousRecord {
        self.previous.wire()
    }

    /// Whether the previous process went down with the PC (`agent_started.pc_restarted`,
    /// [`restarted`]); `None` when that cannot be told.
    pub fn pc_restarted(&self) -> Option<bool> {
        self.restart.verdict
    }

    /// This process's random id, new on every start (`agent_hello.boot_id`).
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// How the previous process ended (`agent_hello.last_exit`).
    pub fn last_exit(&self) -> AgentLastExit {
        self.last_exit
    }

    /// When this process started, Unix ms on the PC's clock.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// The previous process's panic, when it ended in one and its record has the summary (a build
    /// with this field wrote it): what `agent_crashed` reports. `None` otherwise — said at debug
    /// when the exit was a panic but the record lacks the summary (a build before it).
    pub fn previous_crash(&self) -> Option<CrashSummary> {
        if self.last_exit.kind != AgentExitKind::Panic {
            return None;
        }
        let Previous::Found(record) = &self.previous else {
            return None;
        };
        let (Some(panic), Some(version), Some(at)) =
            (&record.panic, &record.version, self.last_exit.at)
        else {
            tracing::debug!(
                has_summary = record.panic.is_some(),
                has_version = record.version.is_some(),
                has_time = self.last_exit.at.is_some(),
                "run state: the previous process panicked, but its record lacks what agent_crashed \
                 needs (a build before the panic summary): no agent_crashed"
            );
            return None;
        };
        Some(CrashSummary {
            at,
            version: version.clone(),
            place_hash: panic.place_hash.clone(),
            thread: panic.thread.clone(),
            uptime_s: panic.uptime_s,
            boot_id: Some(record.boot_id.clone())
                .filter(|b| afklink_protocol::diagnostics::is_uuid(b)),
        })
    }

    /// What `agent_hello` says beyond the device: `build` (left out when the build's own values
    /// do not fit the contract, `BuildInfo::wire`), this process's boot id and the previous one's
    /// exit. Not the hardware fingerprint: the agent reads that itself, off its start
    /// (`Agent::with_hw_reader`).
    pub fn hello(&self, build: &BuildInfo) -> HelloInfo {
        HelloInfo {
            build: build.wire(),
            boot_id: afklink_protocol::diagnostics::is_uuid(&self.boot_id)
                .then(|| self.boot_id.clone()),
            last_exit: Some(self.last_exit),
            hw: None,
        }
    }

    /// Make the record this process's: write it as running, keep it alive every [`ALIVE_EVERY`] on
    /// a thread of its own, and make it the one [`record_exit`] and [`record_panic`] write to. Logs
    /// the previous process's end, once. A second claim does nothing.
    ///
    /// The desktop app reads before Tauri starts and claims only once it is the one instance
    /// (`.setup`): a second launch, which the single-instance lock ends at once, never touches the
    /// running one's record. Nothing is written before the claim, so a panic before it is not
    /// recorded, and the next start reads whatever the last claimed process left.
    pub fn claim(self: &Arc<Self>) {
        if !self.claim_record() {
            return;
        }
        if CURRENT.set(Arc::clone(self)).is_err() {
            tracing::warn!(
                boot_id = %self.boot_id,
                "run state: another record was claimed in this process first; exits are recorded \
                 there"
            );
        }
        let state = Arc::clone(self);
        // One wake at most waits: a second asks for the flush the first will make.
        let (wake, woken) = std::sync::mpsc::sync_channel::<()>(1);
        // The first mark at once: it is the claim's record flushed to the disk, here rather than on
        // the thread that claimed (the main thread). Then one a minute, or at once when a write on
        // an async worker asks for its flush ([`Self::flush_soon`]).
        let spawned = std::thread::Builder::new()
            .name("afklink-run-state".into())
            .spawn(move || loop {
                state.touch(now_ms());
                match woken.recv_timeout(ALIVE_EVERY) {
                    Ok(()) => tracing::trace!("run state: woken to flush a write made elsewhere"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::debug!("run state: no one can wake this thread; a mark a minute");
                        std::thread::sleep(ALIVE_EVERY);
                    }
                }
            });
        match spawned {
            Ok(_) => {
                if self.wake.set(wake).is_err() {
                    tracing::debug!("run state: the thread's wake was set already");
                }
            }
            Err(e) => {
                tracing::warn!(
                    "run state: no thread to keep it alive ({e}); a crash will be dated by this \
                     process's start, and the claim's record is flushed here"
                );
                self.touch(now_ms());
            }
        }
    }

    /// Ask the run state's thread to write a flushed mark now, for a write that was not flushed
    /// where it was made. Never waits.
    fn flush_soon(&self, what: &str) {
        match self.wake.get().map(|w| w.try_send(())) {
            Some(Ok(())) => tracing::trace!(what, "run state: the flush handed to its thread"),
            Some(Err(std::sync::mpsc::TrySendError::Full(()))) => {
                tracing::trace!(what, "run state: a flush is asked for already");
            }
            Some(Err(std::sync::mpsc::TrySendError::Disconnected(()))) | None => {
                tracing::debug!(
                    what,
                    "run state: no thread to hand the flush to; the write stays unflushed"
                );
            }
        }
    }

    /// The claim's writing, without the thread and the process-wide slot: whether this was the
    /// first claim.
    fn claim_record(&self) -> bool {
        if self.claimed.swap(true, Ordering::SeqCst) {
            tracing::debug!(boot_id = %self.boot_id, "run state: claimed already");
            return false;
        }
        let (previous_boot, previous_pid, previous_started_at) = match &self.previous {
            Previous::Found(r) => (Some(r.boot_id.as_str()), Some(r.pid), Some(r.started_at)),
            _ => (None, None, None),
        };
        let unreadable = match &self.previous {
            Previous::Unreadable(why) => Some(why.as_str()),
            _ => None,
        };
        if let Some(problem) = unreadable {
            tracing::warn!(
                file = %self.path.display(),
                problem,
                "run state: the previous record could not be read; the previous process's end is \
                 unknown"
            );
        }
        if let Previous::Torn { what, modified } = &self.previous {
            tracing::warn!(
                file = %self.path.display(),
                held = %what,
                modified_ms = ?modified,
                pc_restarted = ?self.restart.verdict,
                "run state: the previous record holds nothing — the PC most likely lost power \
                 while it was being written; reported as a crash at the file's time"
            );
        }
        tracing::info!(
            boot_id = %self.boot_id,
            last_exit = self.last_exit.kind.as_str(),
            last_exit_at = ?self.last_exit.at,
            previous_record = self.previous.wire().as_str(),
            pc_restarted = ?self.restart.verdict,
            boot_at = ?self.boot_at,
            boot_gap_ms = ?self.restart.gap_ms,
            restart_why = self.restart.why,
            previous_boot = previous_boot.unwrap_or("-"),
            previous_pid = ?previous_pid,
            previous_started_at = ?previous_started_at,
            why = self.why,
            "process started: the previous process ended as last_exit (sent in agent_hello)"
        );
        let record = lock(&self.record);
        // Not flushed here, on the thread that claims (the desktop app's main thread): the run
        // state's thread writes a flushed mark right after ([`Self::claim`]).
        self.write_with(&record, "claimed: running", false);
        true
    }

    /// The minute's mark: alive at `now`. Takes back an exit recorded so long ago that it did not
    /// happen ([`EXIT_STALE_AFTER`]).
    ///
    /// Every change is written while the record's lock is held, so two writers cannot put an older
    /// record on disk after a newer one (a minute's mark after the exit it never saw).
    fn touch(&self, now: u64) {
        let mut record = lock(&self.record);
        record.alive_at = now;
        if let Some(mark) = record.exit {
            let ago = now.saturating_sub(mark.at);
            if ago >= u64::try_from(EXIT_STALE_AFTER.as_millis()).unwrap_or(u64::MAX) {
                tracing::warn!(
                    kind = mark.kind.as_str(),
                    ago_ms = ago,
                    "run state: an exit was recorded and the process is still running long after: \
                     it did not happen (a shutdown cancelled without a word?); back to running"
                );
                record.exit = None;
            }
        }
        tracing::trace!(alive_at = now, "run state: alive");
        self.write(&record, "alive");
    }

    /// Record a panic as this process's exit, from a panic hook, with its summary (`place_hash` and
    /// `thread`, held to the contract's shapes by the caller). The record's lock may be held — by
    /// another thread's write for a moment, or by this very thread, panicking inside one — so it is
    /// only tried, for a short while; then the record is written from what never changes.
    fn panicked(&self, now: u64, place_hash: String, thread: &str) {
        let mark = ExitMark {
            kind: AgentExitKind::Panic,
            at: now,
        };
        let summary = PanicMark {
            place_hash,
            thread: thread.to_string(),
            uptime_s: (now.saturating_sub(self.started_at) / 1000)
                .min(afklink_protocol::metrics::UPTIME_SECONDS_MAX),
        };
        for _ in 0..PANIC_LOCK_TRIES {
            let mut record = match self.record.try_lock() {
                Ok(record) => record,
                Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            record.exit = Some(mark);
            record.alive_at = now;
            record.panic = Some(summary);
            tracing::info!(
                place_hash = %record.panic.as_ref().map_or("-", |p| p.place_hash.as_str()),
                thread,
                uptime_s = record.panic.as_ref().map_or(0, |p| p.uptime_s),
                "run state: this process's exit recorded: panic (the next start reports it as \
                 agent_crashed)"
            );
            self.write(&record, "panic");
            return;
        }
        let record = Record {
            v: VERSION,
            boot_id: self.boot_id.clone(),
            pid: std::process::id(),
            version: Some(THIS_VERSION.to_string()),
            started_at: self.started_at,
            alive_at: now,
            exit: Some(mark),
            panic: Some(summary),
        };
        tracing::info!(
            thread,
            "run state: this process's exit recorded: panic, written without the record's lock (it \
             stayed held); later writes are dropped so as not to hide it"
        );
        self.write_whole(&record, "panic (the record's lock was held)", true, true);
    }

    /// Record that this process is ending as `kind` (`why`, for the log), unless a more specific
    /// exit stands already (see the module docs).
    pub fn exiting(&self, kind: ExitKind, why: &str) {
        self.exiting_at(kind, why, now_ms());
    }

    fn exiting_at(&self, kind: ExitKind, why: &str, now: u64) {
        let new = kind.wire();
        let mut record = lock(&self.record);
        match record.exit {
            Some(old) if !replaces(old.kind, new) => {
                tracing::debug!(
                    kept = old.kind.as_str(),
                    asked = new.as_str(),
                    why,
                    "run state: an exit is recorded already and stands"
                );
                return;
            }
            Some(old) => tracing::debug!(
                was = old.kind.as_str(),
                now = new.as_str(),
                why,
                "run state: the recorded exit is replaced by a more specific one"
            ),
            None => {}
        }
        record.exit = Some(ExitMark { kind: new, at: now });
        record.alive_at = now;
        tracing::info!(
            kind = new.as_str(),
            why,
            claimed = self.claimed.load(Ordering::SeqCst),
            "run state: this process's exit recorded"
        );
        self.write(&record, "exit");
    }

    /// Take back a recorded `os_shutdown`: Windows cancelled the end of the session.
    pub fn exit_taken_back(&self, why: &str) {
        let mut record = lock(&self.record);
        match record.exit {
            Some(mark) if mark.kind == AgentExitKind::OsShutdown => {
                record.exit = None;
                tracing::info!(why, "run state: the shutdown's exit taken back; running");
                self.write(&record, "exit taken back");
            }
            other => tracing::debug!(
                why,
                recorded = other.map_or("none", |m| m.kind.as_str()),
                "run state: no shutdown recorded to take back"
            ),
        }
    }

    /// Write `record` whole, flushed to the disk (`FlushFileBuffers`) before the rename
    /// ([`Self::write_with`]). Without the flush NTFS logs the rename before the data reaches the
    /// disk, and a PC that loses power in that window starts again with a file of the right length
    /// full of zeros (seen on two PCs in production).
    ///
    /// Where each write is flushed: the claim's own write is not flushed on the thread that claims
    /// (the desktop app's main thread), nor a write made on an async worker (the updater's exit, on
    /// Tauri's runtime); the run state's thread writes a flushed mark right after either. Every
    /// other write is flushed where it is made: the minute's mark on the run state's thread, a
    /// shutdown on the system events thread, a quit or a panic on the main thread on the way out.
    /// One small file takes about 1.4 ms on an NVMe disk (measured) and tens of ms on a spinning
    /// one; [`SLOW_FLUSH`] and over is a warning.
    fn write(&self, record: &Record, what: &str) {
        self.write_with(record, what, true);
    }

    /// Write `record` whole: a temporary file beside it, flushed to the disk when `flush`, then a
    /// rename over it. Only once claimed. A flush that fails does not stop the rename: the record
    /// is then as safe as an unflushed one, which is better than the old record left in place.
    ///
    /// On an async worker ([`ASYNC_WORKER`]: the updater's exit, made on Tauri's runtime) the flush
    /// is not made here, where it could stall the worker and hold the record's lock for it: the
    /// write is put in place unflushed and the run state's thread writes a flushed mark at once
    /// ([`Self::flush_soon`]). With no such thread running, it is flushed here after all.
    fn write_with(&self, record: &Record, what: &str, flush: bool) {
        self.write_whole(record, what, flush, false);
    }

    /// [`Self::write_with`], or for the panic hook's write made without the record's lock
    /// (`unlocked`): its own temporary file — another thread may be inside a write of its own — and
    /// the record sealed first, so no write that thread finishes later puts its panic-less record
    /// over the panic's.
    fn write_whole(&self, record: &Record, what: &str, flush: bool, unlocked: bool) {
        if !self.claimed.load(Ordering::SeqCst) {
            tracing::debug!(
                what,
                "run state: not claimed by this process; nothing written"
            );
            return;
        }
        if unlocked {
            self.panic_sealed.store(true, Ordering::SeqCst);
        } else if self.panic_sealed.load(Ordering::SeqCst) {
            tracing::debug!(
                what,
                "run state: the panic's record is on disk, written without the lock; this write \
                 would hide it, and is dropped"
            );
            return;
        }
        let on_worker = std::thread::current().name() == Some(ASYNC_WORKER);
        let defer = flush && on_worker && !unlocked && self.wake.get().is_some();
        if flush && on_worker && !defer {
            tracing::debug!(
                what,
                "run state: written on an async worker with no run state thread to hand the flush \
                 to; flushed here"
            );
        }
        let result = serde_json::to_vec(record)
            .map_err(std::io::Error::other)
            .and_then(|bytes| self.put(&bytes, flush && !defer, what, unlocked));
        match result {
            Ok(Put::Renamed) => {
                if self.write_failed.swap(false, Ordering::SeqCst) {
                    tracing::info!(what, "run state: written again");
                } else {
                    tracing::trace!(what, flush, defer, "run state written");
                }
                if defer {
                    self.flush_soon(what);
                }
            }
            Ok(Put::Sealed) => {}
            Err(e) => {
                if self.write_failed.swap(true, Ordering::SeqCst) {
                    tracing::debug!(what, "run state: still not written: {e}");
                } else {
                    tracing::warn!(
                        file = %self.path.display(),
                        what,
                        "run state: not written ({e}); the next start may misjudge how this \
                         process ended"
                    );
                }
            }
        }
    }

    /// `bytes` into the temporary file beside the record (the panic hook's unlocked write has one
    /// of its own, [`PANIC_TMP_SUFFIX`]), flushed when `flush` ([`Self::flush`]), then renamed over
    /// the record. The flush's outcome is said at once ([`Self::note_flush`]), whatever the rename
    /// does next; its failure is not this function's error — the rename goes ahead. A write that
    /// finds the record sealed by the panic's after its flush ([`Self::write_whole`]) is dropped.
    fn put(&self, bytes: &[u8], flush: bool, what: &str, unlocked: bool) -> std::io::Result<Put> {
        use std::io::Write as _;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(if unlocked { PANIC_TMP_SUFFIX } else { ".tmp" });
        let tmp = PathBuf::from(tmp);
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        let flushed = flush.then(|| {
            let started = Instant::now();
            let result = (self.flush)(&file);
            (result, started.elapsed())
        });
        drop(file);
        self.note_flush(what, flushed);
        if !unlocked && self.panic_sealed.load(Ordering::SeqCst) {
            tracing::debug!(
                what,
                "run state: the panic's record was put in place during this write; this one is \
                 dropped"
            );
            if let Err(e) = std::fs::remove_file(&tmp) {
                tracing::debug!(
                    what,
                    "run state: the dropped write's temporary file stays: {e}"
                );
            }
            return Ok(Put::Sealed);
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(Put::Renamed)
    }

    /// Say how the flush of a write went: a failure once at warn (then debug until one succeeds,
    /// which is said at info), a slow one at warn with the thread that waited, the rest at trace.
    fn note_flush(&self, what: &str, flushed: Option<(std::io::Result<()>, Duration)>) {
        let Some((result, took)) = flushed else {
            tracing::trace!(
                what,
                "run state: put in place without a flush (the run state's thread flushes next)"
            );
            return;
        };
        let took_ms = u64::try_from(took.as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(()) => {
                if self.flush_failed.swap(false, Ordering::SeqCst) {
                    tracing::info!(what, took_ms, "run state: flushed to the disk again");
                }
                if took >= SLOW_FLUSH {
                    tracing::warn!(
                        what,
                        took_ms,
                        thread = std::thread::current().name().unwrap_or("unnamed"),
                        "run state: the disk took long to flush the record; this thread waited"
                    );
                } else {
                    tracing::trace!(
                        what,
                        took_us = u64::try_from(took.as_micros()).unwrap_or(u64::MAX),
                        "run state: flushed"
                    );
                }
            }
            Err(e) => {
                if self.flush_failed.swap(true, Ordering::SeqCst) {
                    tracing::debug!(what, took_ms, "run state: still not flushed: {e}");
                } else {
                    tracing::warn!(
                        file = %self.path.display(),
                        what,
                        took_ms,
                        "run state: the record was not flushed to the disk ({e}); put in place all \
                         the same — a power cut in the next seconds may leave it empty, and the \
                         next start then says crash"
                    );
                }
            }
        }
    }
}

/// The record this process claimed ([`RunState::claim`]).
static CURRENT: OnceLock<Arc<RunState>> = OnceLock::new();

/// This process's run state, once claimed.
pub fn current() -> Option<&'static Arc<RunState>> {
    CURRENT.get()
}

/// Record this process's exit as `kind` (`why`, for the log) in the claimed record. Before a claim
/// (or in a process that keeps none) there is nothing to record into: said at debug.
pub fn record_exit(kind: ExitKind, why: &str) {
    match CURRENT.get() {
        Some(state) => state.exiting(kind, why),
        None => tracing::debug!(
            kind = kind.wire().as_str(),
            why,
            "run state: none claimed; the exit is not recorded"
        ),
    }
}

/// The exit this process has recorded so far (an update's, a shutdown's, a quit's), if any: what
/// tells the desktop app's supervisor that the orchestrator's end is part of a leaving. Reads the
/// record under its lock — held only for a write, never across a wait for another thread.
pub fn recorded_exit() -> Option<AgentExitKind> {
    CURRENT
        .get()
        .and_then(|state| lock(&state.record).exit.map(|mark| mark.kind))
}

/// The orchestrator panicked on a runtime worker and the process relaunches itself because of it
/// (the desktop app's `supervise`): recorded as this process's exit, `panic`, with its summary, as
/// a main thread's panic is — `place_hash` ([`place_hash`]) as the panic hook saw it, `None` when
/// it was not seen (`unknown`). The next start reports it (`agent_crashed`).
pub fn record_agent_panic(place: Option<String>, thread: Option<&str>) {
    let hash = place.unwrap_or_else(|| place_hash("unknown", 0, 0));
    match CURRENT.get() {
        Some(state) => state.panicked(now_ms(), hash, thread_name(thread)),
        None => {
            tracing::debug!("run state: none claimed; the orchestrator's panic is not recorded")
        }
    }
}

/// Take back a recorded `os_shutdown`: the end of the Windows session was cancelled.
pub fn take_back_exit(why: &str) {
    match CURRENT.get() {
        Some(state) => state.exit_taken_back(why),
        None => tracing::debug!(why, "run state: none claimed; nothing to take back"),
    }
}

/// From a panic hook: a panic on `thread` at `place`. Only the main thread's ends the process (the
/// tokio workers' and the encode thread's are caught and survived), so only it is recorded as the
/// exit, with its summary — the place hashed ([`place_hash`]), never the message; any other is
/// noted and the process carries on.
pub fn record_panic(thread: Option<&str>, place: Option<&std::panic::Location<'_>>) {
    if thread == Some("main") {
        let hash = place.map_or_else(
            || place_hash("unknown", 0, 0),
            |p| place_hash(p.file(), p.line(), p.column()),
        );
        match CURRENT.get() {
            Some(state) => state.panicked(now_ms(), hash, thread_name(thread)),
            None => tracing::debug!("run state: none claimed; the panic is not recorded"),
        }
    } else {
        tracing::debug!(
            thread = thread.unwrap_or("unnamed"),
            "run state: a panic off the main thread; the process usually survives it, so it is not \
             recorded as the exit"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory of this test's own under the system's temp directory.
    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("afklink-run-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn read(dir: &Path) -> Record {
        let text = std::fs::read_to_string(dir.join(FILE_NAME)).expect("the file");
        serde_json::from_str(&text).expect("a record")
    }

    /// A process that claims, lives and ends as `kind`: the next start reads that kind at the time
    /// it was recorded.
    fn run_and_exit(dir: &Path, kind: ExitKind, at: u64) -> String {
        let state = RunState::open_at(dir, at - 60_000);
        assert!(state.claim_record());
        state.touch(at - 30_000);
        state.exiting_at(kind, "test", at);
        state.boot_id().to_string()
    }

    #[test]
    fn no_file_is_a_first_run_and_unknown() {
        let d = dir("first");
        let state = RunState::open_at(&d, 1_000);
        assert_eq!(
            state.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Unknown,
                at: None
            }
        );
        assert!(
            !d.join(FILE_NAME).exists(),
            "reading writes nothing before the claim"
        );
        assert!(state.claim_record());
        let r = read(&d);
        assert_eq!(r.boot_id, state.boot_id());
        assert_eq!((r.started_at, r.alive_at, r.exit), (1_000, 1_000, None));
        assert!(!state.claim_record(), "a second claim does nothing");
    }

    #[test]
    fn each_recorded_exit_kind_is_the_next_starts_last_exit() {
        for (kind, word) in [
            (ExitKind::App, AgentExitKind::AppExit),
            (ExitKind::Update, AgentExitKind::UpdateExit),
            (ExitKind::OsShutdown, AgentExitKind::OsShutdown),
            (ExitKind::Panic, AgentExitKind::Panic),
            // The orchestrator failed and the app relaunched itself: `crash`.
            (ExitKind::AgentFailed, AgentExitKind::Crash),
        ] {
            // Not `crash` alone: another test's directory.
            let d = dir(&format!("exit-{}", word.as_str()));
            let at = 1_789_599_960_000;
            let before = run_and_exit(&d, kind, at);
            let next = RunState::open_at(&d, at + 5_000);
            assert_eq!(
                next.last_exit(),
                AgentLastExit {
                    kind: word,
                    at: Some(at)
                },
                "{word}"
            );
            assert_ne!(next.boot_id(), before, "a new boot id per process");
        }
    }

    /// Killed without a word: the file says running, and the crash is dated by the last alive mark.
    #[test]
    fn a_record_left_running_is_a_crash_at_its_last_alive_mark() {
        let d = dir("crash");
        let state = RunState::open_at(&d, 1_789_599_000_000);
        assert!(state.claim_record());
        state.touch(1_789_599_060_000);
        state.touch(1_789_599_120_000);
        drop(state);
        let next = RunState::open_at(&d, 1_789_599_500_000);
        assert_eq!(
            next.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Crash,
                at: Some(1_789_599_120_000)
            }
        );
        assert!(next.last_exit().kind.is_crash());
    }

    /// Put `content` in the record's file with `modified` (Unix ms) as its modified time.
    fn put_file(dir: &Path, content: &[u8], modified: u64) {
        let path = dir.join(FILE_NAME);
        std::fs::write(&path, content).expect("write");
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|f| f.set_modified(UNIX_EPOCH + Duration::from_millis(modified)))
            .expect("set the modified time");
    }

    /// A file that holds no record — what NTFS leaves of an unflushed write after a power cut: the
    /// right length in zeros, or nothing — is a crash at the file's modified time, not `unknown`;
    /// `previous_record` says `unreadable`, and the claim replaces the file.
    #[test]
    fn a_record_that_holds_nothing_is_a_crash_at_the_files_time() {
        let modified = 1_789_599_120_000;
        let now = 1_789_599_500_000;
        for (name, content) in [
            ("zeros", vec![0u8; 187]),
            ("empty", Vec::new()),
            ("zeros_and_blanks", b"\0\0\0\n  ".to_vec()),
            ("cut_short", b"{\"v\":1,\"boot_id\":".to_vec()),
            ("prefix_then_zeros", b"{\"v\":1,\"boot\0\0\0\0".to_vec()),
        ] {
            let d = dir(name);
            put_file(&d, &content, modified);
            let state = RunState::open_at(&d, now);
            assert_eq!(
                state.last_exit(),
                AgentLastExit {
                    kind: AgentExitKind::Crash,
                    at: Some(modified)
                },
                "{name}"
            );
            assert!(matches!(state.previous, Previous::Torn { .. }), "{name}");
            assert_eq!(
                state.previous_record(),
                PreviousRecord::Unreadable,
                "{name}"
            );
            assert_eq!(state.previous_crash(), None, "{name}: no panic summary");
            assert!(state.claim_record());
            assert_eq!(read(&d).boot_id, state.boot_id(), "{name}");
        }
        assert_eq!(torn_shape(&[]), "empty");
        assert_eq!(torn_shape(&[0; 4]), "4 zero bytes");
    }

    /// A whole JSON value that is not a record this build reads — the wrong shape, or a later
    /// build's incompatible record, which a rollback by the update's watchdog can leave — is not a
    /// torn write: `unknown`, not `crash`; `previous_record` `unreadable`; the claim replaces it.
    #[test]
    fn a_whole_file_of_another_shape_is_unknown() {
        for (name, content) in [
            ("wrong_shape", r#"{"hello":true}"#),
            (
                "later_incompatible",
                r#"{"v":3,"boot_id":{"id":"6b1e0c2a"},"pid":7,"started_at":"yesterday",
                   "alive_at":2}"#,
            ),
            ("an_array", "[1,2,3]"),
        ] {
            let d = dir(name);
            put_file(&d, content.as_bytes(), 1_789_599_120_000);
            let state = RunState::read_at(&d, 1_789_599_500_000, Some(1_789_599_150_000));
            assert_eq!(
                state.last_exit(),
                AgentLastExit {
                    kind: AgentExitKind::Unknown,
                    at: None
                },
                "{name}"
            );
            assert!(matches!(state.previous, Previous::Unreadable(_)), "{name}");
            assert_eq!(
                state.previous_record(),
                PreviousRecord::Unreadable,
                "{name}"
            );
            assert_eq!(state.pc_restarted(), None, "{name}");
            assert!(state.claim_record());
            assert_eq!(read(&d).boot_id, state.boot_id(), "{name}");
        }
    }

    /// The file's time is the crash's only when it is a possible one: not after this start (a clock
    /// moved back), not before 1970. Still a crash, undated.
    #[test]
    fn an_impossible_file_time_leaves_the_crash_undated() {
        let d = dir("torn_future");
        put_file(&d, &[0; 64], 1_789_599_900_000);
        let state = RunState::open_at(&d, 1_789_599_500_000);
        assert_eq!(
            state.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Crash,
                at: None
            }
        );
        assert_eq!(
            restarted(&state.previous, Some(1_789_599_000_000)).verdict,
            None,
            "no time to compare the boot with"
        );
    }

    /// A torn record read without a boot time: still a crash at the file's time, no restart said.
    #[test]
    fn a_torn_record_without_a_boot_time_tells_no_restart() {
        let d = dir("torn_no_boot");
        put_file(&d, &[0; 64], 1_789_599_120_000);
        let state = RunState::read_at(&d, 1_789_599_500_000, None);
        assert_eq!(state.last_exit().kind, AgentExitKind::Crash);
        assert_eq!(state.last_exit().at, Some(1_789_599_120_000));
        assert_eq!(state.pc_restarted(), None);
        assert_eq!(state.restart.gap_ms, None);
    }

    /// A file that cannot be read at all — here a folder in its place — tells nothing: `unknown`.
    #[test]
    fn a_file_that_cannot_be_read_is_unknown() {
        let d = dir("unreadable");
        std::fs::create_dir_all(d.join(FILE_NAME)).expect("a folder in the file's place");
        let state = RunState::read_at(&d, 5_000, Some(1_000));
        assert_eq!(
            state.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Unknown,
                at: None
            }
        );
        assert!(matches!(state.previous, Previous::Unreadable(_)));
        assert_eq!(state.previous_record(), PreviousRecord::Unreadable);
        assert_eq!(state.pc_restarted(), None);
    }

    /// Missing: `unknown`, `previous_record` `missing`, and no restart verdict whatever the boot.
    #[test]
    fn a_missing_record_tells_no_restart() {
        let d = dir("missing_boot");
        let state = RunState::read_at(&d, 1_789_599_500_000, Some(1_789_599_400_000));
        assert_eq!(state.last_exit().kind, AgentExitKind::Unknown);
        assert_eq!(state.previous_record(), PreviousRecord::Missing);
        assert_eq!(state.pc_restarted(), None);
    }

    /// Windows booted within the restart window after the previous process's last alive mark: it
    /// went down with the PC. Booted before it started: it ended alone. Booted long after the
    /// window (a lone kill on Monday, a reboot on Thursday; an `app_exit`, then a reboot days
    /// later): not said. In between start and mark: the clock moved; not said. No boot time: not
    /// said.
    #[test]
    fn a_boot_after_the_last_alive_mark_is_a_restart() {
        let window = u64::try_from(RESTART_WINDOW.as_millis()).unwrap();
        assert_eq!(
            window, 180_000,
            "a minute's mark plus two minutes to reboot"
        );
        let started = 1_789_599_000_000;
        let alive = 1_789_599_120_000;
        let d = dir("restart");
        let state = RunState::open_at(&d, started);
        assert!(state.claim_record());
        state.touch(alive);
        drop(state);
        let at = |boot| RunState::read_at(&d, alive + 600_000, boot);
        let after = at(Some(alive + 45_000));
        assert_eq!(after.pc_restarted(), Some(true));
        assert_eq!(after.previous_record(), PreviousRecord::Found);
        assert_eq!(
            after.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Crash,
                at: Some(alive)
            },
            "the exit's word is unchanged: a crash, at its last alive mark"
        );
        assert_eq!(after.restart.gap_ms, Some(45_000));
        assert_eq!(
            at(Some(alive + window)).pc_restarted(),
            Some(true),
            "the window's edge"
        );
        assert_eq!(
            at(Some(alive + window + 1)).pc_restarted(),
            None,
            "just past it"
        );
        let days = 3 * 24 * 3_600_000;
        let thursday = RunState::read_at(&d, alive + days + 60_000, Some(alive + days));
        assert_eq!(thursday.pc_restarted(), None, "a reboot days later");
        assert_eq!(thursday.restart.gap_ms, Some(i64::try_from(days).unwrap()));
        assert_eq!(at(Some(started - 20_000)).pc_restarted(), Some(false));
        assert_eq!(at(Some(started + 60_000)).pc_restarted(), None);
        assert_eq!(at(None).pc_restarted(), None);

        // A shutdown recorded, then the boot: the PC restarted, as it said it would.
        let d = dir("restart_after_shutdown");
        run_and_exit(&d, ExitKind::OsShutdown, alive);
        let next = RunState::read_at(&d, alive + 90_000, Some(alive + 30_000));
        assert_eq!(next.last_exit().kind, AgentExitKind::OsShutdown);
        assert_eq!(next.pc_restarted(), Some(true));

        // The owner quit, and the PC was restarted days later: not said.
        let d = dir("quit_then_reboot");
        run_and_exit(&d, ExitKind::App, alive);
        let next = RunState::read_at(&d, alive + days + 60_000, Some(alive + days));
        assert_eq!(next.last_exit().kind, AgentExitKind::AppExit);
        assert_eq!(next.pc_restarted(), None);

        // A record that held nothing: the file's time is the last sign of life.
        let d = dir("restart_torn");
        put_file(&d, &[0; 32], alive);
        let torn = |boot| RunState::read_at(&d, alive + days + 90_000, Some(boot)).pc_restarted();
        assert_eq!(torn(alive + 30_000), Some(true));
        assert_eq!(torn(alive - 30_000), Some(false));
        assert_eq!(torn(alive + days), None, "long after: not said");
    }

    /// Flushes counted by [`worker_counting_flush`] (only the async worker test uses it).
    static WORKER_FLUSHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn worker_counting_flush(file: &std::fs::File) -> std::io::Result<()> {
        WORKER_FLUSHES.fetch_add(1, Ordering::SeqCst);
        file.sync_all()
    }

    /// A write on an async worker (the updater's exit) is put in place unflushed and its flush
    /// handed to the run state's thread; with no such thread, the worker flushes it after all.
    #[test]
    fn a_write_on_an_async_worker_hands_its_flush_to_the_run_state_thread() {
        let on_worker = |state: Arc<RunState>| {
            std::thread::Builder::new()
                .name(ASYNC_WORKER.into())
                .spawn(move || state.exiting_at(ExitKind::Update, "the update", 2_000))
                .expect("a thread")
                .join()
                .expect("no panic");
        };
        let d = dir("worker");
        let mut state = RunState::open_at(&d, 1_000);
        state.flush = worker_counting_flush;
        let (wake, woken) = std::sync::mpsc::sync_channel(1);
        assert!(state.wake.set(wake).is_ok());
        assert!(state.claim_record());
        let state = Arc::new(state);
        on_worker(Arc::clone(&state));
        assert_eq!(
            WORKER_FLUSHES.load(Ordering::SeqCst),
            0,
            "not on the worker"
        );
        assert_eq!(
            read(&d).exit.map(|m| m.kind),
            Some(AgentExitKind::UpdateExit),
            "but put in place"
        );
        assert_eq!(woken.try_recv(), Ok(()), "the run state's thread is asked");

        let d = dir("worker_alone");
        let mut state = RunState::open_at(&d, 1_000);
        state.flush = worker_counting_flush;
        assert!(state.claim_record());
        on_worker(Arc::new(state));
        assert_eq!(
            WORKER_FLUSHES.load(Ordering::SeqCst),
            1,
            "no thread: flushed here"
        );
        assert_eq!(
            read(&d).exit.map(|m| m.kind),
            Some(AgentExitKind::UpdateExit)
        );
    }

    /// A panic hook that cannot get the record's lock writes through its own temporary file and
    /// seals the record: a write the lock's holder finishes afterwards — here the minute's mark,
    /// from a record in memory that never heard of the panic — is dropped, and the panic stands.
    #[test]
    fn a_panic_written_without_the_lock_is_not_hidden_by_a_later_write() {
        let d = dir("panic_sealed");
        let state = RunState::open_at(&d, 1_000);
        assert!(state.claim_record());
        {
            let _held = state.record.lock().expect("the lock");
            state.panicked(5_000, place_hash("src/lib.rs", 1, 1), "main");
        }
        assert!(state.panic_sealed.load(Ordering::SeqCst));
        assert!(!d.join(format!("{FILE_NAME}{PANIC_TMP_SUFFIX}")).exists());
        state.touch(6_000);
        state.exiting_at(ExitKind::App, "the exit after the panic", 6_500);
        let on_disk = read(&d);
        assert_eq!(on_disk.exit.map(|m| m.kind), Some(AgentExitKind::Panic));
        assert_eq!(on_disk.alive_at, 5_000, "the later writes were dropped");
        assert!(!d.join(format!("{FILE_NAME}.tmp")).exists());
    }

    /// Windows' boot time on this machine: before now, and after 1970 (the counter is real).
    #[test]
    #[cfg(windows)]
    fn the_boot_time_is_before_now() {
        let now = now_ms();
        let boot = windows_boot_ms(now).expect("a boot time on Windows");
        assert!(boot > 0 && boot <= now, "{boot} vs {now}");
        assert_eq!(windows_boot_ms(1), None, "a clock before the boot");
    }

    /// Flushes counted by [`counting_flush`] (only the flush test uses it).
    static FLUSHES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn counting_flush(file: &std::fs::File) -> std::io::Result<()> {
        FLUSHES.fetch_add(1, Ordering::SeqCst);
        file.sync_all()
    }

    fn failing_flush(_: &std::fs::File) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "injected: the disk refused the flush",
        ))
    }

    /// Every write but the claim's is flushed before its rename; a flush that fails is noted (a
    /// warning once) and the rename goes ahead all the same; a flush that works again is noted too.
    #[test]
    fn every_write_but_the_claims_is_flushed_and_a_failed_flush_still_renames() {
        let d = dir("flush");
        let mut state = RunState::open_at(&d, 1_000);
        state.flush = counting_flush;
        assert!(state.claim_record());
        assert_eq!(
            FLUSHES.load(Ordering::SeqCst),
            0,
            "the claim's write is not"
        );
        state.touch(2_000);
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 1, "the minute's mark is");
        state.exiting_at(ExitKind::App, "quit", 3_000);
        assert_eq!(FLUSHES.load(Ordering::SeqCst), 2, "an exit is");
        assert!(!state.flush_failed.load(Ordering::SeqCst));

        state.flush = failing_flush;
        state.touch(4_000);
        assert!(
            state.flush_failed.load(Ordering::SeqCst),
            "the failure noted"
        );
        assert!(
            !state.write_failed.load(Ordering::SeqCst),
            "but the write is not one"
        );
        let on_disk = read(&d);
        assert_eq!(on_disk.alive_at, 4_000, "the rename went ahead");
        assert_eq!(on_disk.boot_id, state.boot_id());
        state.touch(5_000);
        assert_eq!(read(&d).alive_at, 5_000, "and again");
        assert!(
            !d.join(format!("{FILE_NAME}.tmp")).exists(),
            "no temporary file left"
        );

        state.flush = std::fs::File::sync_all;
        state.touch(6_000);
        assert!(!state.flush_failed.load(Ordering::SeqCst), "recovered");
        assert_eq!(read(&d).alive_at, 6_000);
    }

    /// A field this build does not know (a later build's) does not make the record unreadable.
    #[test]
    fn a_later_records_extra_fields_are_ignored() {
        let d = dir("later");
        std::fs::write(
            d.join(FILE_NAME),
            r#"{"v":2,"boot_id":"b","pid":7,"started_at":1,"alive_at":2,
               "exit":{"kind":"update_exit","at":3,"to":"0.6.0"},"dump":{"place":"x"}}"#,
        )
        .expect("write");
        let state = RunState::open_at(&d, 10);
        assert_eq!(
            state.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::UpdateExit,
                at: Some(3)
            }
        );
    }

    /// The more specific exit stands: an update's or a shutdown's is not overwritten by the app's
    /// exit that follows; the app's is replaced by either; a panic replaces anything.
    #[test]
    fn the_more_specific_exit_stands() {
        assert!(!replaces(AgentExitKind::UpdateExit, AgentExitKind::AppExit));
        assert!(!replaces(AgentExitKind::OsShutdown, AgentExitKind::AppExit));
        assert!(replaces(AgentExitKind::AppExit, AgentExitKind::OsShutdown));
        assert!(replaces(AgentExitKind::AppExit, AgentExitKind::UpdateExit));
        assert!(replaces(AgentExitKind::UpdateExit, AgentExitKind::Panic));
        assert!(!replaces(AgentExitKind::Panic, AgentExitKind::Panic));
        assert!(!replaces(
            AgentExitKind::UpdateExit,
            AgentExitKind::OsShutdown
        ));

        let d = dir("update_then_quit");
        let state = RunState::open_at(&d, 1_000);
        assert!(state.claim_record());
        state.exiting_at(ExitKind::Update, "the update", 2_000);
        state.exiting_at(ExitKind::App, "RunEvent::Exit", 2_500);
        assert_eq!(
            read(&d).exit,
            Some(ExitMark {
                kind: AgentExitKind::UpdateExit,
                at: 2_000
            })
        );
        state.exiting_at(ExitKind::Panic, "panic on the way out", 2_600);
        assert_eq!(read(&d).exit.map(|m| m.kind), Some(AgentExitKind::Panic));
    }

    /// Windows asks to end the session, then cancels: the shutdown is taken back and the process
    /// is running again; a crash later is a crash.
    #[test]
    fn a_cancelled_shutdown_is_taken_back() {
        let d = dir("cancelled");
        let state = RunState::open_at(&d, 1_000);
        assert!(state.claim_record());
        state.exiting_at(ExitKind::OsShutdown, "WM_QUERYENDSESSION", 2_000);
        assert_eq!(
            read(&d).exit.map(|m| m.kind),
            Some(AgentExitKind::OsShutdown)
        );
        state.exit_taken_back("WM_ENDSESSION FALSE");
        assert_eq!(read(&d).exit, None);
        state.touch(3_000);
        let next = RunState::open_at(&d, 9_000);
        assert_eq!(
            next.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Crash,
                at: Some(3_000)
            }
        );
        // Taking back anything but a shutdown does nothing.
        let state = RunState::open_at(&d, 10_000);
        assert!(state.claim_record());
        state.exiting_at(ExitKind::App, "quit", 11_000);
        state.exit_taken_back("a stray cancel");
        assert_eq!(read(&d).exit.map(|m| m.kind), Some(AgentExitKind::AppExit));
    }

    /// An exit recorded by a process still alive long after did not happen: the touch takes it
    /// back.
    #[test]
    fn a_stale_exit_is_taken_back_by_the_touch() {
        let d = dir("stale");
        let state = RunState::open_at(&d, 1_000);
        assert!(state.claim_record());
        state.exiting_at(ExitKind::OsShutdown, "WM_QUERYENDSESSION", 2_000);
        state.touch(2_000 + 60_000);
        assert!(
            read(&d).exit.is_some(),
            "a minute later it may still be exiting"
        );
        state.touch(2_000 + 125_000);
        assert_eq!(read(&d).exit, None, "two minutes on, it did not happen");
    }

    /// Before the claim nothing is written — a second instance the single-instance lock ends never
    /// touches the running one's record.
    #[test]
    fn nothing_is_written_before_the_claim() {
        let d = dir("unclaimed");
        let first = RunState::open_at(&d, 1_000);
        assert!(first.claim_record());
        let second = RunState::open_at(&d, 2_000);
        second.exiting_at(ExitKind::App, "the second instance exits", 2_100);
        second.touch(2_200);
        assert_eq!(read(&d).boot_id, first.boot_id());
        assert_eq!(read(&d).exit, None);
    }

    /// A panic hook records the panic even while the record's lock is held — here by the very
    /// thread that panics, the case a plain lock would deadlock on — and the next start says
    /// `panic`, at its time.
    #[test]
    fn a_panic_is_recorded_even_with_the_records_lock_held() {
        let d = dir("panic_locked");
        let state = RunState::open_at(&d, 1_000);
        assert!(state.claim_record());
        let held = state.record.lock().expect("the lock");
        state.panicked(5_000, place_hash("src/lib.rs", 1, 1), "main");
        drop(held);
        let next = RunState::open_at(&d, 9_000);
        assert_eq!(
            next.last_exit(),
            AgentLastExit {
                kind: AgentExitKind::Panic,
                at: Some(5_000)
            }
        );
        assert_eq!(
            read(&d).boot_id,
            state.boot_id(),
            "the same process's record"
        );

        // Unlocked: the record itself takes it.
        let d = dir("panic_free");
        let state = RunState::open_at(&d, 1_000);
        assert!(state.claim_record());
        state.panicked(6_000, place_hash("src/lib.rs", 1, 1), "main");
        assert_eq!(
            read(&d).exit,
            Some(ExitMark {
                kind: AgentExitKind::Panic,
                at: 6_000
            })
        );
    }

    /// Only the main thread's panic is the process's exit: a worker's is survived.
    #[test]
    fn a_panic_off_the_main_thread_is_not_an_exit() {
        // No record is claimed in the test process, so this only must not panic or block.
        let here = std::panic::Location::caller();
        record_panic(Some("tokio-runtime-worker"), Some(here));
        record_panic(None, None);
        record_panic(Some("main"), Some(here));
    }

    /// A panic's summary — the place hashed, the thread, the time it had run — is the next start's
    /// `agent_crashed`, at the panic's own time; never the panic's message.
    #[test]
    fn a_panic_is_summarised_for_the_next_start() {
        let d = dir("panic_summary");
        let at = 1_789_599_960_000;
        let state = RunState::open_at(&d, at - 5_400_000);
        assert!(state.claim_record());
        let hash = place_hash("crates/core/src/agent.rs", 4210, 17);
        state.panicked(at, hash.clone(), "main");
        let next = RunState::open_at(&d, at + 5_000);
        let crash = next.previous_crash().expect("a crash to report");
        assert_eq!(
            crash,
            CrashSummary {
                at,
                version: THIS_VERSION.to_string(),
                place_hash: hash.clone(),
                thread: "main".into(),
                uptime_s: 5_400,
                boot_id: Some(state.boot_id().to_string()),
            }
        );
        assert!(afklink_protocol::metrics::is_place_hash(&hash), "{hash}");
        assert_eq!(hash.len(), 16);
        assert_eq!(
            hash,
            place_hash("crates/core/src/agent.rs", 4210, 17),
            "the same place hashes the same"
        );
        assert_ne!(hash, place_hash("crates/core/src/agent.rs", 4211, 17));
        let text = std::fs::read_to_string(d.join(FILE_NAME)).expect("the file");
        assert!(!text.contains("agent.rs"), "no source path on disk: {text}");

        // Any other exit has nothing to report; nor has a panic recorded by a build before the
        // summary (no `panic`, no `version`).
        let d = dir("panic_old");
        run_and_exit(&d, ExitKind::App, at);
        assert_eq!(RunState::open_at(&d, at + 1).previous_crash(), None);
        std::fs::write(
            d.join(FILE_NAME),
            r#"{"v":1,"boot_id":"b","pid":7,"started_at":1,"alive_at":2,
               "exit":{"kind":"panic","at":3}}"#,
        )
        .expect("write");
        let old = RunState::open_at(&d, 10);
        assert_eq!(old.last_exit().kind, AgentExitKind::Panic);
        assert_eq!(old.previous_crash(), None);
    }

    #[test]
    fn thread_names_are_held_to_the_contract() {
        assert_eq!(thread_name(Some("main")), "main");
        assert_eq!(
            thread_name(Some("tokio-runtime-worker")),
            "tokio-runtime-worker"
        );
        assert_eq!(thread_name(Some("encode-3fa85f64 5717")), "other");
        assert_eq!(thread_name(None), "unnamed");
    }

    /// The time is left out when it is not one the contract takes.
    #[test]
    fn an_impossible_time_is_left_out() {
        let found = |alive_at: u64| {
            Previous::Found(Record {
                v: 1,
                boot_id: "b".into(),
                pid: 1,
                version: None,
                started_at: 0,
                alive_at,
                exit: None,
                panic: None,
            })
        };
        assert_eq!(decide(&found(0)).0.at, None);
        assert_eq!(decide(&found(EPOCH_MS_MAX + 1)).0.at, None);
        assert_eq!(decide(&found(EPOCH_MS_MAX)).0.at, Some(EPOCH_MS_MAX));
    }

    /// The hello's fields: the build as `BuildInfo::wire` gives it, a UUID boot id, the last exit.
    #[test]
    fn the_hello_names_the_build_the_boot_and_the_last_exit() {
        let d = dir("hello");
        let at = 1_789_599_960_000;
        run_and_exit(&d, ExitKind::Panic, at);
        let state = RunState::open_at(&d, at + 1_000);
        let build = BuildInfo::from_stamp(
            "0.5.1",
            "1d38642aa0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
            "0",
            "",
            "release",
        );
        let hello = state.hello(&build);
        let wire = hello.build.as_ref().expect("a build");
        assert_eq!(wire.version, "0.5.1");
        assert_eq!(
            wire.commit.as_deref(),
            Some("1d38642aa0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5")
        );
        assert_eq!(wire.dirty, Some(false));
        assert!(afklink_protocol::diagnostics::is_uuid(
            hello.boot_id.as_deref().expect("a boot id")
        ));
        assert_eq!(
            hello.last_exit,
            Some(AgentLastExit {
                kind: AgentExitKind::Panic,
                at: Some(at)
            })
        );
    }
}
