//! The orchestrator's supervision: what the app does when `Agent::run` ends while the app is not
//! leaving.
//!
//! `run` connects, serves and reconnects for the app's whole life; nothing in the app ends it. When
//! it ends anyway (a panic on the runtime worker that polled it, an error it could not get past),
//! an unsupervised app would stay open with the tray and the window and no link to the server: the
//! PC would leave «Мои ПК» until someone restarted it by hand.
//!
//! # What is done
//!
//! [`spawn`] runs `run` as a task of its own inside a task-local scope ([`IN_AGENT`]) that the
//! panic hook looks for ([`note_panic`]). A second task awaits its end and hands it to the
//! `afklink-supervise` thread, where [`on_end_with`] judges it:
//!
//! - **the app is leaving** ([`leaving_from`]): said at `info`, nothing done;
//! - otherwise an `error` with the cause, the link marked down («Нет связи», as for any outage),
//!   every key and button the injector holds released, and the pause («Прервать все сеансы»), when
//!   in force, written to config.json. The live sessions are ended by the orchestrator's drop. Then
//!   one of:
//!   - **a new version on probation with its watchdog alive**: no relaunch. The process exits with
//!     [`EXIT_AGENT_ENDED`] and no clean exit, so the watchdog rolls the update back. A relaunch
//!     here would start the new exe behind the watchdog's back;
//!   - **a relaunch** of the app's own exe, at most [`MAX_RELAUNCHES`] within [`RELAUNCH_WINDOW`],
//!     counted in [`FILE_NAME`] so a crash loop across processes stops;
//!   - **past the limit**: the app stays up with no link, and says so at `error`.
//!
//! # Threads
//!
//! The end is awaited on the runtime (an await on a join handle). Everything after it runs on
//! `afklink-supervise`, never on a runtime worker: the record's file, the run state, config.json,
//! the injector's release (on a thread of its own, waited for at most [`RELEASE_WAIT`]), the exe's
//! start. The main thread is asked for the window's visibility with `run_on_main_thread` and
//! answered over a channel waited for at most [`MAIN_THREAD_WAIT`], nothing held meanwhile. The
//! agent state's lock is taken once, for a store, and the config's for the pause's write: one after
//! the other, never both, and neither across a wait. `app.exit` only posts to the event loop.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use afklink_core::traits::InputInjector;
use afklink_core::{AgentControl, PauseKept};
use afklink_protocol::AgentExitKind;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime};

use crate::log_route::SYSTEM_TARGET;

/// At most this many relaunches within [`RELAUNCH_WINDOW`]; past it the app stays up offline.
pub(crate) const MAX_RELAUNCHES: usize = 3;

/// The window the relaunches are counted in.
pub(crate) const RELAUNCH_WINDOW: Duration = Duration::from_secs(60 * 60);

/// The relaunches' record, beside `run_state.json`.
pub(crate) const FILE_NAME: &str = "relaunches.json";

/// The exit code of a process that ends because its orchestrator ended (relaunched, or handed to
/// the update's watchdog): not 0 — it is no clean exit.
pub(crate) const EXIT_AGENT_ENDED: i32 = 5;

/// How long the process may take to leave after its exit is asked before it ends itself outright:
/// well inside the new process's wait for it (`updater::RELAUNCH_WAIT`, 30 s).
pub(crate) const EXIT_FALLBACK: Duration = Duration::from_secs(10);

/// How long the injector's release may take before the supervisor goes on without it (a release
/// with its retries is ~2 s at worst).
pub(crate) const RELEASE_WAIT: Duration = Duration::from_secs(3);

/// How long the main thread has to say whether the main window is visible.
pub(crate) const MAIN_THREAD_WAIT: Duration = Duration::from_secs(5);

/// A record larger than this is not ours: not read (and no relaunch).
const FILE_MAX_BYTES: u64 = 4096;

tokio::task_local! {
    /// Set while the orchestrator's task is polled: a panic under it is the orchestrator's.
    static IN_AGENT: ();
}

/// Set once the app is on its way out: an end of the orchestrator then is part of it.
static LEAVING: AtomicBool = AtomicBool::new(false);

/// Set once the supervisor ends the process because its orchestrator ended: the exit that follows
/// is no clean one ([`abnormal_exit`]).
static ABNORMAL_EXIT: AtomicBool = AtomicBool::new(false);

/// What the panic hook saw of the last panic inside the orchestrator's task.
static AGENT_PANIC: Mutex<Option<AgentPanic>> = Mutex::new(None);

/// A panic inside the orchestrator's task, as the panic hook saw it: never its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentPanic {
    /// Its place, hashed (`afklink_core::run_state::place_hash`).
    pub(crate) place_hash: Option<String>,
    /// The worker it happened on.
    pub(crate) thread: Option<String>,
}

/// How the orchestrator's task ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentEnd {
    /// `run` returned `Ok`: nothing can command it any more.
    Returned,
    /// `run` returned an error (its chain).
    Failed(String),
    /// It panicked; what the hook saw of it, when it did.
    Panicked(Option<AgentPanic>),
    /// The task was cancelled: the runtime is shutting down.
    Cancelled,
}

impl AgentEnd {
    fn kind(&self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Failed(_) => "failed",
            Self::Panicked(_) => "panicked",
            Self::Cancelled => "cancelled",
        }
    }
}

/// What to do about an end ([`decide`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The app is leaving (why): nothing.
    Leaving(&'static str),
    /// Relaunch; `recent`: the relaunches within the window before this one.
    Relaunch { recent: usize },
    /// No relaunch: `recent` relaunches within the window already; one is allowed again at
    /// `again_at_ms` (Unix ms).
    StayDown { recent: usize, again_at_ms: u64 },
}

/// The app is on its way out (`why`, for the log): its exit was requested. From the event loop.
pub(crate) fn leaving(why: &'static str) {
    if !LEAVING.swap(true, Ordering::SeqCst) {
        tracing::debug!(
            why,
            "supervise: the app is leaving; an end of the orchestrator is no failure"
        );
    }
}

/// The exit under way is the supervisor's — the orchestrator ended — and no clean one: an update's
/// watchdog must not be told of a quit (`updater::on_exit`).
pub(crate) fn abnormal_exit() -> bool {
    ABNORMAL_EXIT.load(Ordering::SeqCst)
}

/// From the panic hook: a panic on `thread` at `place`. Noted when it is inside the orchestrator's
/// task ([`IN_AGENT`]); never waits (the note's lock is only tried).
pub(crate) fn note_panic(thread: Option<&str>, place: Option<&std::panic::Location<'_>>) {
    if IN_AGENT.try_with(|()| ()).is_err() {
        return;
    }
    let panic = AgentPanic {
        place_hash: place
            .map(|p| afklink_core::run_state::place_hash(p.file(), p.line(), p.column())),
        thread: thread.map(str::to_string),
    };
    match AGENT_PANIC.try_lock() {
        Ok(mut note) => *note = Some(panic),
        Err(std::sync::TryLockError::Poisoned(p)) => *p.into_inner() = Some(panic),
        Err(std::sync::TryLockError::WouldBlock) => {
            tracing::debug!("supervise: the orchestrator's panic not noted (its note was busy)");
        }
    }
}

/// The panic noted for the orchestrator, taken.
fn take_panic() -> Option<AgentPanic> {
    match AGENT_PANIC.lock() {
        Ok(mut note) => note.take(),
        Err(p) => p.into_inner().take(),
    }
}

/// `run` on `rt` as a task of its own, inside the orchestrator's scope ([`IN_AGENT`]).
pub(crate) fn spawn_agent<F, E>(
    rt: &tokio::runtime::Handle,
    run: F,
) -> tokio::task::JoinHandle<Result<(), E>>
where
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: Send + 'static,
{
    rt.spawn(IN_AGENT.scope((), run))
}

/// How the orchestrator's task ended, awaited. An error is said with its chain (`{:#}`).
pub(crate) async fn ended<E: std::fmt::Display>(
    task: tokio::task::JoinHandle<Result<(), E>>,
) -> AgentEnd {
    match task.await {
        Ok(Ok(())) => AgentEnd::Returned,
        Ok(Err(e)) => AgentEnd::Failed(format!("{e:#}")),
        Err(e) if e.is_panic() => AgentEnd::Panicked(take_panic()),
        Err(e) => {
            tracing::debug!("supervise: the orchestrator's task did not finish: {e}");
            AgentEnd::Cancelled
        }
    }
}

/// Run the orchestrator (`run`) on Tauri's runtime and supervise it (the module's docs). `injector`
/// is the one the orchestrator's sessions inject through, released here should the orchestrator end.
pub(crate) fn spawn<R, F, E>(
    app: AppHandle<R>,
    control: AgentControl,
    injector: Arc<dyn InputInjector>,
    run: F,
) where
    R: Runtime,
    F: std::future::Future<Output = Result<(), E>> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let rt = tauri::async_runtime::handle().inner().clone();
    let task = spawn_agent(&rt, run);
    tracing::debug!(
        max_relaunches = MAX_RELAUNCHES,
        window_s = RELAUNCH_WINDOW.as_secs(),
        "supervise: the orchestrator runs; its end is watched"
    );
    rt.spawn(async move {
        let end = ended(task).await;
        // Off the runtime: the judgment reads and writes files and waits (bounded) for threads.
        let kind = end.kind();
        let spawned = std::thread::Builder::new()
            .name("afklink-supervise".into())
            .spawn(move || {
                let host = TauriHost {
                    app,
                    control,
                    injector,
                };
                let outcome = on_end_with(&host, end);
                tracing::debug!(?outcome, "supervise: the orchestrator's end handled");
            });
        if let Err(e) = spawned {
            tracing::error!(
                target: SYSTEM_TARGET,
                end = kind,
                "supervise: the orchestrator ended and the thread to judge it did not start ({e}); \
                 the app stays up with no link to the server"
            );
        }
    });
}

/// What says whether the app is leaving ([`leaving_from`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LeavingFacts {
    /// Its exit was requested ([`leaving`]).
    pub(crate) exit_requested: bool,
    /// Windows is ending the session (`system_events`).
    pub(crate) shutdown: bool,
    /// The exit this process recorded so far (`run_state`).
    pub(crate) recorded: Option<AgentExitKind>,
    /// An update is being applied (`updater::applying`).
    pub(crate) applying: bool,
}

/// [`leaving_from`]'s word for an update being applied.
const APPLYING_WHY: &str = "an update is being applied";

/// Why the app is leaving, if it is: its exit requested, Windows ending the session, an update
/// being applied (from before the exe's swap: a relaunch would start the new exe without the
/// watchdog), or an exit already recorded (an update's, a shutdown's, a quit's).
pub(crate) fn leaving_from(facts: &LeavingFacts) -> Option<&'static str> {
    if facts.exit_requested {
        return Some("the app's exit was requested");
    }
    if facts.shutdown {
        return Some("Windows is ending the session");
    }
    if facts.applying {
        return Some(APPLYING_WHY);
    }
    match facts.recorded {
        Some(AgentExitKind::UpdateExit) => Some("the app is exiting for an update"),
        Some(AgentExitKind::OsShutdown) => Some("Windows is ending the session (recorded)"),
        Some(AgentExitKind::AppExit) => Some("the app's exit is recorded"),
        Some(_) | None => None,
    }
}

/// [`leaving_from`] with this process's facts now.
fn leaving_why() -> Option<&'static str> {
    leaving_from(&LeavingFacts {
        exit_requested: LEAVING.load(Ordering::SeqCst),
        shutdown: matches!(
            crate::system_events::exit_reason(),
            afklink_core::GoodbyeReason::Shutdown
        ),
        recorded: afklink_core::run_state::recorded_exit(),
        applying: crate::updater::applying(),
    })
}

/// What to do about `end`: nothing while the app is `leaving`; else a relaunch, unless
/// [`MAX_RELAUNCHES`] happened within [`RELAUNCH_WINDOW`] before `now_ms` (`history`: the relaunches'
/// times, Unix ms).
pub(crate) fn decide(
    end: &AgentEnd,
    leaving: Option<&'static str>,
    history: &[u64],
    now_ms: u64,
) -> Verdict {
    if let Some(why) = leaving {
        return Verdict::Leaving(why);
    }
    if *end == AgentEnd::Cancelled {
        return Verdict::Leaving("the runtime is shutting down");
    }
    let recent = recent(history, now_ms);
    if recent.len() < MAX_RELAUNCHES {
        Verdict::Relaunch {
            recent: recent.len(),
        }
    } else {
        let oldest = recent.iter().copied().min().unwrap_or(now_ms);
        Verdict::StayDown {
            recent: recent.len(),
            again_at_ms: oldest.saturating_add(window_ms()),
        }
    }
}

fn window_ms() -> u64 {
    u64::try_from(RELAUNCH_WINDOW.as_millis()).unwrap_or(u64::MAX)
}

/// The relaunches within the window before `now_ms`. One dated after `now_ms` (the clock moved back)
/// counts too, for as long as it is within a window of `now_ms`: a clock set back must not reopen the
/// limit, nor close it for longer than a window.
fn recent(history: &[u64], now_ms: u64) -> Vec<u64> {
    let window = window_ms();
    history
        .iter()
        .copied()
        .filter(|&at| now_ms.abs_diff(at) < window)
        .collect()
}

/// The relaunches' record.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Record {
    /// When each relaunch was made, Unix ms.
    #[serde(default)]
    pub(crate) at: Vec<u64>,
}

/// The record at `path`: none yet is an empty one; anything else that cannot be read is an error.
/// Blocking.
pub(crate) fn load(path: &Path) -> Result<Record, String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Record::default()),
        Err(e) => return Err(format!("not read: {e}")),
    };
    if !meta.is_file() {
        return Err("not a file".to_string());
    }
    if meta.len() > FILE_MAX_BYTES {
        return Err(format!("{} bytes, over {FILE_MAX_BYTES}", meta.len()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("not read: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("garbled: {e}"))
}

/// Write the record to `path`: a `.tmp` beside it, then a rename. Blocking.
pub(crate) fn save(path: &Path, record: &Record) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path))
}

/// The record with a relaunch at `now_ms` added, and those out of the window dropped.
pub(crate) fn with_relaunch(record: &Record, now_ms: u64) -> Record {
    let mut at = recent(&record.at, now_ms);
    at.push(now_ms);
    Record { at }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// What [`on_end_with`] needs of the app: its side effects, so the judgment is tested without one.
/// Every method runs on `afklink-supervise`.
pub(crate) trait Host {
    /// Why the app is leaving, if it is ([`leaving_from`] with the facts now).
    fn leaving(&self) -> Option<&'static str>;
    /// The link marked down and the live sessions taken off the list ([`mark_down`]): the tray and
    /// the window say «Нет связи», and nobody is shown in control.
    fn mark_link_down(&self);
    /// Every key and button the injector holds released (bounded).
    fn release_input(&self);
    /// The pause written to config.json when in force.
    fn keep_pause(&self) -> PauseKept;
    /// A new version on probation whose update's watchdog is alive.
    fn watchdog_decides(&self) -> bool;
    /// Where the relaunches' record is.
    fn record_path(&self) -> Result<PathBuf, String>;
    fn now_ms(&self) -> u64;
    /// Whether the main window is hidden (asked of the main thread, bounded).
    fn window_hidden(&self) -> bool;
    /// Start the app's exe again: its pid.
    fn start_again(&self, hidden: bool, paused: bool) -> Result<u32, String>;
    /// The end recorded as this process's exit (`run_state`).
    fn record_exit(&self, end: &AgentEnd);
    /// The process exits ([`EXIT_AGENT_ENDED`]), no clean exit; ended outright after
    /// [`EXIT_FALLBACK`] if it has not.
    fn exit(&self, why: &'static str);
}

/// What [`on_end_with`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Handled {
    /// The app is leaving: nothing.
    Leaving(&'static str),
    /// Handed to the update's watchdog: the process exits, no relaunch.
    ToWatchdog,
    /// The app stays up offline (why).
    StaysDown(&'static str),
    /// The new process started (its pid); this one exits.
    Relaunched(u32),
}

/// The supervisor stood down because the app is leaving (`why`). When that is an update's apply, an
/// apply that fails from here leaves the app with no link: said at `error` by the apply's end (or
/// here, if it is over already; `updater::orchestrator_ended_during_apply`). No relaunch either
/// way: the update may yet hand over to its watchdog.
fn stood_down_for(why: &'static str) {
    if why != APPLYING_WHY {
        return;
    }
    let said = crate::updater::orchestrator_ended_during_apply();
    tracing::warn!(
        target: SYSTEM_TARGET,
        apply_failed_already = said,
        "supervise: the orchestrator ended during an update's apply; no relaunch — if the apply \
         fails, the app stays up with no link to the server"
    );
}

/// The orchestrator ended (`end`): judge it and act (the module's docs). On `afklink-supervise`.
///
/// "Leaving" covers the exit requested, Windows ending the session, an exit already recorded (an
/// update's), and an update being applied. The pause is written here because the orchestrator's
/// own save may be pending or have failed; the probation case records the exit and reports no clean
/// exit through `updater::on_exit`.
///
/// A relaunch, in order: the time is recorded first (a record that cannot be read or written means
/// no relaunch: the limit cannot be held without it); the main window's visibility is read on the
/// main thread (bounded); whether the app is leaving is looked at again; the exe is started with
/// `--relaunched-from <this pid>` (plus `--hidden` when the main window is hidden, `--paused` when
/// the pause could not be written). Only once it started is the exit recorded in the run state
/// (`panic` with its place, or `crash`: the next start reports it and its automatic report sends
/// the log), and this process exits through `app.exit`, with a hard exit after [`EXIT_FALLBACK`]
/// should the event loop not let it go. A start that fails takes its time back out of the record
/// and records no exit: the app stays up, offline, and says so. The new process waits (bounded) for
/// this one to be gone before the single-instance lock (`updater::early`) and ends it if it is
/// still there, through the one handle it waited on, and only when it runs this exe and was created
/// before the new process.
pub(crate) fn on_end_with(host: &impl Host, end: AgentEnd) -> Handled {
    if let Some(why) = host.leaving() {
        tracing::info!(
            target: SYSTEM_TARGET,
            end = end.kind(),
            why,
            "supervise: the orchestrator ended while the app leaves; nothing to do"
        );
        stood_down_for(why);
        return Handled::Leaving(why);
    }
    match &end {
        AgentEnd::Panicked(panic) => tracing::error!(
            target: SYSTEM_TARGET,
            end = end.kind(),
            place_hash = panic.as_ref().and_then(|p| p.place_hash.as_deref()).unwrap_or("-"),
            thread = panic.as_ref().and_then(|p| p.thread.as_deref()).unwrap_or("-"),
            "supervise: the orchestrator panicked (the panic's line is above): no link to the \
             server any more"
        ),
        AgentEnd::Failed(cause) => tracing::error!(
            target: SYSTEM_TARGET,
            end = end.kind(),
            "supervise: the orchestrator stopped with an error: {cause}; no link to the server any \
             more"
        ),
        AgentEnd::Returned | AgentEnd::Cancelled => tracing::error!(
            target: SYSTEM_TARGET,
            end = end.kind(),
            "supervise: the orchestrator stopped while the app was not leaving: no link to the \
             server any more"
        ),
    }
    // Whatever follows: «Нет связи», no key left held, the pause kept.
    host.mark_link_down();
    host.release_input();
    let pause = host.keep_pause();
    let paused_unsaved = matches!(pause, PauseKept::NotSaved(_));

    if host.watchdog_decides() {
        tracing::warn!(
            target: SYSTEM_TARGET,
            end = end.kind(),
            "supervise: a new version on probation lost its orchestrator: no relaunch — the \
             process exits as failed and the update's watchdog rolls it back"
        );
        host.record_exit(&end);
        host.exit("handed to the update's watchdog");
        return Handled::ToWatchdog;
    }

    let path = match host.record_path() {
        Ok(path) => path,
        Err(e) => {
            tracing::error!(
                target: SYSTEM_TARGET,
                "supervise: no data directory for the relaunches' record ({e}); no relaunch — the \
                 limit cannot be held without it; the app stays up with no link"
            );
            return Handled::StaysDown("no data directory");
        }
    };
    let record = match load(&path) {
        Ok(record) => record,
        Err(e) => {
            tracing::error!(
                target: SYSTEM_TARGET,
                file = %path.display(),
                "supervise: the relaunches' record cannot be read ({e}); no relaunch — the limit \
                 cannot be held without it; the app stays up with no link"
            );
            return Handled::StaysDown("the relaunches' record unreadable");
        }
    };
    let now = host.now_ms();
    let recent = match decide(&end, None, &record.at, now) {
        Verdict::Leaving(why) => {
            tracing::info!(
                target: SYSTEM_TARGET,
                why,
                "supervise: the orchestrator ended while the app leaves; nothing to do"
            );
            return Handled::Leaving(why);
        }
        Verdict::StayDown {
            recent,
            again_at_ms,
        } => {
            tracing::error!(
                target: SYSTEM_TARGET,
                recent,
                max = MAX_RELAUNCHES,
                window_s = RELAUNCH_WINDOW.as_secs(),
                again_in_s = again_at_ms.saturating_sub(now) / 1000,
                "supervise: the app relaunched itself {recent} times within the hour already: no \
                 more relaunches; it stays up with no link to the server («Нет связи») until it is \
                 started again"
            );
            return Handled::StaysDown("the relaunch limit");
        }
        Verdict::Relaunch { recent } => recent,
    };
    // Counted before the start: a count that cannot be kept is no relaunch (the limit).
    if let Err(e) = save(&path, &with_relaunch(&record, now)) {
        tracing::error!(
            target: SYSTEM_TARGET,
            file = %path.display(),
            "supervise: the relaunch could not be recorded ({e}); no relaunch — the limit cannot \
             be held without it; the app stays up with no link"
        );
        return Handled::StaysDown("the relaunch not recorded");
    }
    let hidden = host.window_hidden();
    // The owner may have quit meanwhile (the window's answer took a while): no relaunch then.
    if let Some(why) = host.leaving() {
        take_back(&path, &record, "the app is leaving after all");
        tracing::info!(
            target: SYSTEM_TARGET,
            why,
            "supervise: the app started leaving before the relaunch; no relaunch"
        );
        stood_down_for(why);
        return Handled::Leaving(why);
    }
    tracing::warn!(
        target: SYSTEM_TARGET,
        recent,
        max = MAX_RELAUNCHES,
        end = end.kind(),
        hidden,
        paused_unsaved,
        "supervise: relaunching the app to get the link to the server back"
    );
    match host.start_again(hidden, paused_unsaved) {
        Ok(pid) => {
            tracing::info!(
                target: SYSTEM_TARGET,
                new_pid = pid,
                "supervise: the new process started; it waits for this one to exit — exiting"
            );
            host.record_exit(&end);
            host.exit("relaunched");
            Handled::Relaunched(pid)
        }
        Err(e) => {
            take_back(&path, &record, "the new process did not start");
            tracing::error!(
                target: SYSTEM_TARGET,
                "supervise: the new process did not start ({e}); the app stays up with no link"
            );
            Handled::StaysDown("the new process did not start")
        }
    }
}

/// Put the relaunches' record back as it was (`record`): the relaunch counted did not happen.
fn take_back(path: &Path, record: &Record, why: &str) {
    match save(path, record) {
        Ok(()) => tracing::debug!(why, "supervise: the relaunch taken back out of its record"),
        Err(e) => tracing::warn!(
            file = %path.display(),
            why,
            "supervise: the relaunch could not be taken back out of its record ({e}); it counts \
             against the limit for an hour"
        ),
    }
}

/// The link marked down in the agent's state and its session list emptied, as a normal session end
/// takes each one off it (`Agent::end_session_with`): the window (`get_status`) and the tray's
/// watcher read the list on their next poll — no viewer shown as connected, «Нет связи» where
/// «Готов к подключению» would be, and the ended toast for whoever was announced. Whether the link
/// was up, and the sessions taken off (their ids). Holds the state's lock for the two writes only.
fn mark_down(state: &Mutex<afklink_core::AgentState>) -> (bool, Vec<String>) {
    let mut s = afklink_core::lock(state);
    let was_connected = std::mem::replace(&mut s.connected, false);
    let sessions = std::mem::take(&mut s.sessions);
    drop(s);
    (
        was_connected,
        sessions.into_iter().map(|x| x.session_id).collect(),
    )
}

/// The app's side of [`Host`].
struct TauriHost<R: Runtime> {
    app: AppHandle<R>,
    control: AgentControl,
    injector: Arc<dyn InputInjector>,
}

impl<R: Runtime> Host for TauriHost<R> {
    fn leaving(&self) -> Option<&'static str> {
        leaving_why()
    }

    fn mark_link_down(&self) {
        // The state's lock only for the two writes: nothing else is waited on under it.
        let (was_connected, sessions) = mark_down(&self.control.state);
        tracing::debug!(
            was_connected,
            sessions_cleared = sessions.len(),
            "supervise: the link marked down; the window's and the tray's session list cleared"
        );
        for id in &sessions {
            // The orchestrator's live sessions ended with it (`LiveSessions`' drop): no
            // `session_end` of the orchestrator's will take them off the list.
            tracing::info!(
                target: SYSTEM_TARGET,
                session = %id,
                "supervise: session taken off the list: it ended with the orchestrator"
            );
        }
    }

    fn release_input(&self) {
        let injector = Arc::clone(&self.injector);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);
        // A thread of its own: the driver's release may wait on its slot lock without a bound.
        let spawned = std::thread::Builder::new()
            .name("afklink-supervise-release".into())
            .spawn(move || {
                injector.release_all();
                // Nobody waiting any more (the wait ran out): nothing to tell.
                let _ = done_tx.send(());
            });
        match spawned {
            Ok(_) => match done_rx.recv_timeout(RELEASE_WAIT) {
                Ok(()) => tracing::info!(
                    target: SYSTEM_TARGET,
                    "supervise: every key and button the injector held released"
                ),
                Err(e) => tracing::warn!(
                    target: SYSTEM_TARGET,
                    wait_ms = RELEASE_WAIT.as_millis() as u64,
                    "supervise: the injector's release did not finish in time ({e}); going on \
                     without it (it carries on on its thread)"
                ),
            },
            Err(e) => tracing::warn!(
                target: SYSTEM_TARGET,
                "supervise: no thread for the injector's release ({e}); keys held stay held"
            ),
        }
    }

    fn keep_pause(&self) -> PauseKept {
        self.control.keep_pause_blocking("the orchestrator ended")
    }

    fn watchdog_decides(&self) -> bool {
        let on_probation = crate::updater::on_probation();
        let watchdog = on_probation && crate::updater::watchdog_alive();
        tracing::debug!(
            on_probation,
            watchdog,
            "supervise: is an update's watchdog deciding for this process"
        );
        watchdog
    }

    fn record_path(&self) -> Result<PathBuf, String> {
        afklink_core::paths::afklink_dir()
            .map(|dir| dir.join(FILE_NAME))
            .map_err(|e| format!("{e:#}"))
    }

    fn now_ms(&self) -> u64 {
        now_ms()
    }

    fn window_hidden(&self) -> bool {
        let (tx, rx) = std::sync::mpsc::sync_channel::<bool>(1);
        let main = self.app.clone();
        let handed = self.app.run_on_main_thread(move || {
            let hidden = match main.get_webview_window("main") {
                None => {
                    tracing::debug!("supervise: no main window; the relaunch starts hidden");
                    true
                }
                Some(window) => match window.is_visible() {
                    Ok(visible) => !visible,
                    Err(e) => {
                        tracing::warn!(
                            "supervise: the main window's visibility not read ({e}); the \
                             relaunch starts hidden"
                        );
                        true
                    }
                },
            };
            // Nobody waiting any more (the wait ran out): nothing to tell.
            let _ = tx.send(hidden);
        });
        if let Err(e) = handed {
            tracing::warn!(
                "supervise: the window's visibility not asked of the main thread ({e}); the \
                 relaunch starts hidden"
            );
            return true;
        }
        match rx.recv_timeout(MAIN_THREAD_WAIT) {
            Ok(hidden) => hidden,
            Err(e) => {
                tracing::warn!(
                    wait_ms = MAIN_THREAD_WAIT.as_millis() as u64,
                    "supervise: the main thread did not say whether the window is visible ({e}); \
                     the relaunch starts hidden"
                );
                true
            }
        }
    }

    fn start_again(&self, hidden: bool, paused: bool) -> Result<u32, String> {
        let exe =
            std::env::current_exe().map_err(|e| format!("this exe's path is unknown: {e}"))?;
        let mut command = std::process::Command::new(&exe);
        command
            .arg(crate::updater::RELAUNCHED_FROM_ARG)
            .arg(std::process::id().to_string());
        if hidden {
            command.arg(crate::updater::HIDDEN_ARG);
        }
        if paused {
            command.arg(crate::updater::PAUSED_ARG);
        }
        let child = command
            .spawn()
            .map_err(|e| format!("{} not started: {e}", exe.display()))?;
        tracing::debug!(
            pid = child.id(),
            exe = %exe.display(),
            hidden,
            paused,
            "supervise: the app's exe started again"
        );
        // Dropped: its handles close; the process runs on.
        Ok(child.id())
    }

    fn record_exit(&self, end: &AgentEnd) {
        match end {
            AgentEnd::Panicked(panic) => {
                let (place, thread) = panic
                    .clone()
                    .map_or((None, None), |p| (p.place_hash, p.thread));
                afklink_core::run_state::record_agent_panic(place, thread.as_deref());
            }
            AgentEnd::Failed(_) | AgentEnd::Returned | AgentEnd::Cancelled => {
                afklink_core::run_state::record_exit(
                    afklink_core::run_state::ExitKind::AgentFailed,
                    "the orchestrator stopped; the app exits without it",
                );
            }
        }
    }

    fn exit(&self, why: &'static str) {
        ABNORMAL_EXIT.store(true, Ordering::SeqCst);
        leaving(why);
        let fallback = std::thread::Builder::new()
            .name("afklink-supervise-exit".into())
            .spawn(move || {
                std::thread::sleep(EXIT_FALLBACK);
                tracing::warn!(
                    target: SYSTEM_TARGET,
                    why,
                    fallback_s = EXIT_FALLBACK.as_secs(),
                    "supervise: still running {} s after the exit was asked; exiting now",
                    EXIT_FALLBACK.as_secs()
                );
                crate::flush_log("agent_ended_exit");
                std::process::exit(EXIT_AGENT_ENDED);
            });
        if let Err(e) = fallback {
            tracing::warn!(
                "supervise: no thread for the exit's fallback ({e}); the exit relies on the event \
                 loop alone"
            );
        }
        tracing::debug!(
            why,
            exit_code = EXIT_AGENT_ENDED,
            "supervise: the app's exit asked"
        );
        self.app.exit(EXIT_AGENT_ENDED);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const HOUR: u64 = 3_600_000;
    const NOW: u64 = 1_789_600_000_000;

    /// The orchestrator gone: the link is down and nobody is left on the session list the window and
    /// the tray read — its sessions ended with it, and no `session_end` will take them off.
    #[test]
    fn the_link_marked_down_takes_every_session_off_the_list() {
        let session = |id: &str| afklink_core::SessionInfo {
            session_id: id.into(),
            telegram_user_id: 7,
            username: None,
            first_name: None,
            connected: true,
            connected_at: Some(std::time::Instant::now()),
        };
        let state = Mutex::new(afklink_core::AgentState {
            connected: true,
            sessions: vec![session("a"), session("b")],
            ..Default::default()
        });
        assert_eq!(mark_down(&state), (true, vec!["a".into(), "b".into()]));
        let after = afklink_core::lock(&state);
        assert!(!after.connected && after.sessions.is_empty());
        drop(after);
        assert_eq!(mark_down(&state), (false, Vec::<String>::new()));
    }

    /// Up to three relaunches within the hour, then none until the oldest is an hour old; nothing at
    /// all while the app leaves or the runtime shuts down.
    #[test]
    fn three_relaunches_an_hour_then_the_app_stays_down() {
        let failed = AgentEnd::Failed("the signaling relay stopped".into());
        assert_eq!(
            decide(&failed, None, &[], NOW),
            Verdict::Relaunch { recent: 0 }
        );
        let two = [NOW - 50 * 60_000, NOW - 10 * 60_000];
        assert_eq!(
            decide(&AgentEnd::Panicked(None), None, &two, NOW),
            Verdict::Relaunch { recent: 2 }
        );
        let three = [NOW - 50 * 60_000, NOW - 10 * 60_000, NOW - 60_000];
        assert_eq!(
            decide(&failed, None, &three, NOW),
            Verdict::StayDown {
                recent: 3,
                again_at_ms: NOW - 50 * 60_000 + HOUR
            }
        );
        // An hour after the oldest, one is allowed again.
        assert_eq!(
            decide(&failed, None, &three, NOW + 10 * 60_000),
            Verdict::Relaunch { recent: 2 }
        );
        // Old ones do not count.
        assert_eq!(
            decide(&failed, None, &[NOW - 2 * HOUR, NOW - HOUR], NOW),
            Verdict::Relaunch { recent: 0 }
        );
        assert_eq!(
            decide(&failed, Some("the app's exit was requested"), &[], NOW),
            Verdict::Leaving("the app's exit was requested")
        );
        assert!(matches!(
            decide(&AgentEnd::Cancelled, None, &[], NOW),
            Verdict::Leaving(_)
        ));
    }

    /// A clock set back keeps the relaunches it now dates in the future, for an hour of the new
    /// clock: the limit is neither reopened nor closed for longer than a window.
    #[test]
    fn a_clock_set_back_neither_reopens_the_limit_nor_closes_it_for_good() {
        let ahead = [NOW + 10 * 60_000, NOW + 20 * 60_000, NOW + 30 * 60_000];
        assert!(matches!(
            decide(&AgentEnd::Returned, None, &ahead, NOW),
            Verdict::StayDown { recent: 3, .. }
        ));
        let far_ahead = [NOW + 5 * HOUR, NOW + 6 * HOUR, NOW + 7 * HOUR];
        assert_eq!(
            decide(&AgentEnd::Returned, None, &far_ahead, NOW),
            Verdict::Relaunch { recent: 0 }
        );
    }

    /// The record: none is empty; written and read back; a relaunch added drops the old ones;
    /// garbled or oversized is an error (and so no relaunch).
    #[test]
    fn the_relaunches_record_is_kept_on_disk() {
        let dir = scratch("record");
        let path = dir.join(FILE_NAME);
        assert_eq!(load(&path), Ok(Record::default()));
        let record = with_relaunch(
            &Record {
                at: vec![NOW - 2 * HOUR, NOW - 60_000],
            },
            NOW,
        );
        assert_eq!(record.at, vec![NOW - 60_000, NOW]);
        save(&path, &record).expect("saved");
        assert_eq!(load(&path), Ok(record));
        std::fs::write(&path, b"{\"at\":[1,").expect("garble");
        assert!(load(&path).is_err());
        std::fs::write(&path, vec![b' '; 5000]).expect("oversize");
        assert!(load(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The leaving paths: an exit requested, Windows ending the session, an update being
    /// applied (from before the swap), an update's exit, a shutdown or a quit recorded — each is a
    /// leaving; a crash or a panic recorded, or nothing, is not.
    #[test]
    fn the_app_is_leaving_on_an_exit_a_shutdown_or_an_update() {
        let none = LeavingFacts::default();
        assert_eq!(leaving_from(&none), None);
        let with = |f: &dyn Fn(&mut LeavingFacts)| {
            let mut facts = none;
            f(&mut facts);
            leaving_from(&facts)
        };
        assert!(with(&|f| f.exit_requested = true).is_some());
        assert!(with(&|f| f.shutdown = true).is_some());
        assert_eq!(
            with(&|f| f.applying = true),
            Some("an update is being applied")
        );
        for kind in [
            AgentExitKind::UpdateExit,
            AgentExitKind::OsShutdown,
            AgentExitKind::AppExit,
        ] {
            assert!(with(&|f| f.recorded = Some(kind)).is_some(), "{kind:?}");
        }
        for kind in [AgentExitKind::Crash, AgentExitKind::Panic] {
            assert_eq!(with(&|f| f.recorded = Some(kind)), None, "{kind:?}");
        }
    }

    /// The exit's fallback is well inside the new process's wait for this one.
    #[test]
    fn the_exit_fallback_comes_before_the_new_process_stops_waiting() {
        assert!(EXIT_FALLBACK * 2 <= Duration::from_secs(30));
        assert!(RELEASE_WAIT + MAIN_THREAD_WAIT < Duration::from_secs(30));
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("afklink-supervise-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// A host that records what was done.
    struct Fake {
        /// What `leaving` answers, call by call (the last one repeats).
        leaving: RefCell<Vec<Option<&'static str>>>,
        pause: PauseKept,
        watchdog: bool,
        path: Result<PathBuf, String>,
        start: Result<u32, String>,
        calls: RefCell<Vec<String>>,
        started: Cell<Option<(bool, bool)>>,
    }

    impl Fake {
        fn new(path: PathBuf) -> Self {
            Self {
                leaving: RefCell::new(vec![None]),
                pause: PauseKept::NotPaused,
                watchdog: false,
                path: Ok(path),
                start: Ok(4242),
                calls: RefCell::new(Vec::new()),
                started: Cell::new(None),
            }
        }
        fn did(&self, what: &str) -> bool {
            self.calls.borrow().iter().any(|c| c == what)
        }
        fn note(&self, what: &str) {
            self.calls.borrow_mut().push(what.to_string());
        }
    }

    impl Host for Fake {
        fn leaving(&self) -> Option<&'static str> {
            let mut answers = self.leaving.borrow_mut();
            if answers.len() > 1 {
                answers.remove(0)
            } else {
                answers[0]
            }
        }
        fn mark_link_down(&self) {
            self.note("link_down");
        }
        fn release_input(&self) {
            self.note("release");
        }
        fn keep_pause(&self) -> PauseKept {
            self.note("pause");
            self.pause.clone()
        }
        fn watchdog_decides(&self) -> bool {
            self.watchdog
        }
        fn record_path(&self) -> Result<PathBuf, String> {
            self.path.clone()
        }
        fn now_ms(&self) -> u64 {
            NOW
        }
        fn window_hidden(&self) -> bool {
            true
        }
        fn start_again(&self, hidden: bool, paused: bool) -> Result<u32, String> {
            self.started.set(Some((hidden, paused)));
            self.start.clone()
        }
        fn record_exit(&self, _end: &AgentEnd) {
            self.note("record_exit");
        }
        fn exit(&self, _why: &'static str) {
            self.note("exit");
        }
    }

    fn failed() -> AgentEnd {
        AgentEnd::Failed("the relay stopped".into())
    }

    /// The usual end: link down, keys released, pause kept, the relaunch counted, the new process
    /// started (hidden as the window is), then the exit recorded and asked.
    #[test]
    fn an_end_relaunches_after_releasing_and_recording() {
        let dir = scratch("relaunch");
        let host = Fake::new(dir.join(FILE_NAME));
        assert_eq!(on_end_with(&host, failed()), Handled::Relaunched(4242));
        for what in ["link_down", "release", "pause", "record_exit", "exit"] {
            assert!(host.did(what), "{what}: {:?}", host.calls.borrow());
        }
        assert_eq!(host.started.get(), Some((true, false)));
        assert_eq!(load(&dir.join(FILE_NAME)).expect("read").at, vec![NOW]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Leaving: nothing at all — no release, no record, no relaunch, no exit.
    #[test]
    fn an_end_while_leaving_does_nothing() {
        let dir = scratch("leaving");
        let host = Fake::new(dir.join(FILE_NAME));
        *host.leaving.borrow_mut() = vec![Some("the app's exit was requested")];
        assert!(matches!(on_end_with(&host, failed()), Handled::Leaving(_)));
        assert!(host.calls.borrow().is_empty(), "{:?}", host.calls.borrow());
        assert_eq!(host.started.get(), None);
        assert!(!dir.join(FILE_NAME).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The app starts leaving while the window's answer is awaited: no start, and the count
    /// taken back.
    #[test]
    fn an_exit_asked_before_the_start_stops_the_relaunch() {
        let dir = scratch("late-leaving");
        let host = Fake::new(dir.join(FILE_NAME));
        *host.leaving.borrow_mut() = vec![None, Some("the app's exit was requested")];
        assert!(matches!(on_end_with(&host, failed()), Handled::Leaving(_)));
        assert_eq!(host.started.get(), None);
        assert!(!host.did("record_exit") && !host.did("exit"));
        assert_eq!(
            load(&dir.join(FILE_NAME)).expect("read").at,
            Vec::<u64>::new()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No data directory, a record that cannot be read or one that cannot be written: no
    /// relaunch, no exit recorded, no exit — but the keys released and the pause kept.
    #[test]
    fn a_record_that_cannot_be_kept_is_no_relaunch_and_no_exit() {
        let dir = scratch("unkept");
        let mut host = Fake::new(dir.join(FILE_NAME));
        host.path = Err("no %APPDATA%".into());
        assert!(matches!(
            on_end_with(&host, failed()),
            Handled::StaysDown(_)
        ));

        let garbled = Fake::new(dir.join(FILE_NAME));
        std::fs::write(dir.join(FILE_NAME), b"{\"at\":[1,").expect("garble");
        assert!(matches!(
            on_end_with(&garbled, failed()),
            Handled::StaysDown(_)
        ));

        // A record whose folder is gone cannot be written.
        let unsaved = Fake::new(dir.join("gone").join(FILE_NAME));
        assert!(matches!(
            on_end_with(&unsaved, failed()),
            Handled::StaysDown(_)
        ));
        for h in [&host, &garbled, &unsaved] {
            assert!(h.did("release") && h.did("pause"), "{:?}", h.calls.borrow());
            assert!(
                !h.did("record_exit") && !h.did("exit"),
                "{:?}",
                h.calls.borrow()
            );
            assert_eq!(h.started.get(), None);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A start that fails leaves a truthful record — the count taken back, no exit recorded —
    /// and the app up.
    #[test]
    fn a_start_that_fails_takes_its_count_back_and_records_no_exit() {
        let dir = scratch("start-failed");
        let mut host = Fake::new(dir.join(FILE_NAME));
        host.start = Err("access denied".into());
        save(
            &dir.join(FILE_NAME),
            &Record {
                at: vec![NOW - 60_000],
            },
        )
        .expect("seed");
        assert!(matches!(
            on_end_with(&host, failed()),
            Handled::StaysDown(_)
        ));
        assert!(!host.did("record_exit") && !host.did("exit"));
        assert_eq!(
            load(&dir.join(FILE_NAME)).expect("read").at,
            vec![NOW - 60_000]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On probation with the update's watchdog alive, no relaunch: the exit recorded and asked
    /// (abnormal: no quit reported), for the watchdog to roll back.
    #[test]
    fn on_probation_the_watchdog_decides_and_nothing_is_relaunched() {
        let dir = scratch("probation");
        let mut host = Fake::new(dir.join(FILE_NAME));
        host.watchdog = true;
        assert_eq!(
            on_end_with(&host, AgentEnd::Panicked(None)),
            Handled::ToWatchdog
        );
        assert!(host.did("record_exit") && host.did("exit") && host.did("release"));
        assert_eq!(host.started.get(), None);
        assert!(!dir.join(FILE_NAME).exists(), "no relaunch counted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pause that could not be written goes with the relaunch as `--paused`.
    #[test]
    fn a_pause_not_on_disk_goes_with_the_relaunch() {
        let dir = scratch("paused");
        let mut host = Fake::new(dir.join(FILE_NAME));
        host.pause = PauseKept::NotSaved("access denied".into());
        assert_eq!(on_end_with(&host, failed()), Handled::Relaunched(4242));
        assert_eq!(host.started.get(), Some((true, true)));
        let mut saved = Fake::new(dir.join("other.json"));
        saved.pause = PauseKept::Saved;
        assert_eq!(on_end_with(&saved, failed()), Handled::Relaunched(4242));
        assert_eq!(saved.started.get(), Some((true, false)), "on disk: no flag");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On a multi-thread runtime: a panic inside the orchestrator's task is seen as a panic, with
    /// what the hook noted inside the task's scope; an error as a failure with its chain; a return
    /// as a return. A panic outside the scope is not noted. Each wait bounded.
    #[test]
    fn the_orchestrators_end_is_told_apart() {
        fn within<F: std::future::Future>(rt: &tokio::runtime::Runtime, f: F) -> F::Output {
            rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), f).await })
                .expect("in time")
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let handle = rt.handle().clone();
        // Outside the scope: not the orchestrator's.
        note_panic(Some("main"), Some(std::panic::Location::caller()));
        assert_eq!(take_panic(), None);

        let panicking = spawn_agent(&handle, async {
            // What the panic hook does, inside the task's scope.
            note_panic(
                Some("tokio-runtime-worker"),
                Some(std::panic::Location::caller()),
            );
            if std::hint::black_box(true) {
                panic!("the orchestrator panics (a test)");
            }
            Ok::<(), String>(())
        });
        match within(&rt, ended(panicking)) {
            AgentEnd::Panicked(Some(p)) => {
                assert_eq!(p.thread.as_deref(), Some("tokio-runtime-worker"));
                assert_eq!(p.place_hash.as_deref().map(str::len), Some(16));
            }
            other => panic!("expected the panic, noted: {other:?}"),
        }
        let failing = spawn_agent(&handle, async { Err::<(), _>("relay gone".to_string()) });
        assert_eq!(
            within(&rt, ended(failing)),
            AgentEnd::Failed("relay gone".into())
        );
        let returning = spawn_agent(&handle, async { Ok::<(), String>(()) });
        assert_eq!(within(&rt, ended(returning)), AgentEnd::Returned);
        rt.shutdown_timeout(Duration::from_secs(1));
    }
}
