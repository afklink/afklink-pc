//! The watchdog: a copy of the old version (the backup it runs from), started with
//! `--update-watchdog`, that sees the new version through its first minutes and puts the old one back
//! if it does not make it.
//!
//! It never starts Tauri or the single-instance lock — it is not the app. It logs to its own file,
//! `afklink-watchdog.<UTC date>.log`, beside the app's.
//!
//! 1. Takes the watchdog lock (a second watchdog stands down) and answers «ready» on its stdout.
//! 2. Launch mode: waits for the old version (`--parent`) to exit — ending it after
//!    [`PARENT_EXIT_TIMEOUT`] — checks the exe is the update, and starts it with `--after-update`.
//!    Adopt mode (`--adopt`): the new version is already running; it is supervised as it is.
//! 3. Supervises ([`step`]): the new version must report health (`health.json`: its first connection
//!    to the server, with its window thread answering) within `--timeout`, and then stay up for
//!    [`PROBATION`] with its heartbeat going (a stale one for [`BEAT_STALE`] is a hang). Then the
//!    update is confirmed in `state.json`.
//! 4. Otherwise — it exited, or hung, or never connected — rolls back: ends it if it still runs,
//!    restores the exe from its own image (hash-checked), records the failure in `state.json`, and
//!    starts the restored exe with `--rolled-back-from`. If the exe's path cannot be restored, it
//!    starts the backup itself as a last resort: the PC must not be left without an agent.
//!
//! A clean exit of the new version (the owner's «Выход», Windows shutting down: `quit` in
//! `health.json`) is not a failure: after health it confirms the update, before it the attempt is
//! left for the next start of the new version to supervise again.

#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the watchdog runs on Windows only; its rules are tested everywhere"
    )
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::apply::{self, Dirs, RESTORE_DEADLINE, WATCHDOG_READY};
use super::launch::{self, WatchTarget, WatchdogArgs};
use super::state;

/// How long the new version has, after its first connection, to stay up before the update counts.
pub(crate) const PROBATION: Duration = Duration::from_secs(60);
/// A heartbeat unchanged this long during the probation is a hang (the new version beats every
/// few seconds, `task::BEAT_EVERY`).
pub(crate) const BEAT_STALE: Duration = Duration::from_secs(20);
/// How long the old version may take to exit before the watchdog ends it.
pub(crate) const PARENT_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an ended process may take to be gone.
const KILL_WAIT: Duration = Duration::from_secs(10);
/// A pause between one version's exit and the next one's start: the WebView2 browser processes of
/// the one that exited let go of the shared user data folder (`%LOCALAPPDATA%\com.afklink.agent`)
/// shortly after their host, and a new host attaching to one that is shutting down can fail.
const LAUNCH_GRACE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(500);
const LOG_PREFIX: &str = "afklink-watchdog";

pub(crate) const EXIT_OK: i32 = 0;
pub(crate) const EXIT_BAD_ARGS: i32 = 2;
/// Another watchdog holds the lock.
pub(crate) const EXIT_BUSY: i32 = 3;
pub(crate) const EXIT_FAILED: i32 = 4;

/// Why the new version is rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RollbackReason {
    /// Running, but no health within the timeout: hung, or never reached the server.
    NoHealth,
    /// Exited before reporting health (a crash at start included); its exit code when known.
    Exited(Option<u32>),
    /// Exited during the probation, after health.
    ExitedOnProbation(Option<u32>),
    /// Reported health, then its heartbeat stopped during the probation: hung.
    Hung,
    /// Could not be started.
    LaunchFailed,
    /// The exe at the path is not the update the old version put there.
    ExeMismatch,
}

impl RollbackReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoHealth => "no_health",
            Self::Exited(_) => "exited",
            Self::ExitedOnProbation(_) => "exited_on_probation",
            Self::Hung => "hung",
            Self::LaunchFailed => "launch_failed",
            Self::ExeMismatch => "exe_mismatch",
        }
    }

    /// Whether the strike waits for the restored version's verdict: only «no health», which a
    /// network down at the moment of the update also produces.
    pub(crate) fn unverified(self) -> bool {
        matches!(self, Self::NoHealth)
    }
}

/// What the watchdog sees at one look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Observation {
    pub(crate) since_launch: Duration,
    /// Since the new version reported health; `None` before.
    pub(crate) healthy_for: Option<Duration>,
    /// `Some(exit code)` once it has exited.
    pub(crate) exited: Option<Option<u32>>,
    /// It reported a clean exit.
    pub(crate) quit: bool,
    /// After health, its heartbeat has not changed for [`BEAT_STALE`].
    pub(crate) beat_stale: bool,
}

/// What to do after a look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Wait,
    /// The update counts.
    Succeed,
    /// It quit cleanly before proving itself: leave the attempt for its next start.
    LeaveUnconfirmed,
    RollBack(RollbackReason),
}

/// The supervision rule ([module docs](self)).
pub(crate) fn step(o: &Observation, timeout: Duration, probation: Duration) -> Step {
    match (o.exited, o.healthy_for) {
        (Some(_), Some(_)) if o.quit => Step::Succeed,
        (Some(_), None) if o.quit => Step::LeaveUnconfirmed,
        (Some(code), Some(_)) => Step::RollBack(RollbackReason::ExitedOnProbation(code)),
        (Some(code), None) => Step::RollBack(RollbackReason::Exited(code)),
        (None, Some(_)) if o.beat_stale => Step::RollBack(RollbackReason::Hung),
        (None, Some(healthy)) if healthy >= probation => Step::Succeed,
        (None, Some(_)) => Step::Wait,
        (None, None) if o.since_launch >= timeout => Step::RollBack(RollbackReason::NoHealth),
        (None, None) => Step::Wait,
    }
}

/// The watchdog's `main`: returns the process's exit code. `args` is the parsed command line, or why
/// it could not be parsed.
pub(crate) fn main(args: Result<WatchdogArgs, String>) -> i32 {
    init_logging();
    let code = match args {
        Ok(args) => run(&args),
        Err(e) => {
            tracing::error!(
                "watchdog: the command line is not one the app writes: {e}; not starting"
            );
            EXIT_BAD_ARGS
        }
    };
    // not-a-key-name: the process exit code
    tracing::info!(code, "watchdog exiting");
    code
}

/// The watchdog's own log: `%APPDATA%\AFKLink\logs\afklink-watchdog.<UTC date>.log`, at the level
/// config.json chooses (or the build's default, or `RUST_LOG`), like the app's.
fn init_logging() {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let build = crate::build_info();
    // Only read — parsed, never loaded through `Config::load_or_create`, which creates a missing
    // file (a new device) and may write one it repairs, while the app owns it.
    let config: Option<afklink_core::Config> = afklink_core::paths::afklink_dir()
        .ok()
        .and_then(|d| std::fs::read_to_string(d.join("config.json")).ok())
        .and_then(|text| serde_json::from_str(&text).ok());
    let startup = afklink_core::logging::StartupFilter::resolve(config.as_ref(), build.channel);
    let appender = crate::logs_dir().ok().and_then(|dir| {
        std::fs::create_dir_all(&dir).ok()?;
        RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix(LOG_PREFIX)
            .filename_suffix("log")
            .max_log_files(7)
            .build(&dir)
            .ok()
    });
    let file = appender.map(|a| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(a)
    });
    // Nowhere to write (no log folder): the watchdog still does its job, silently.
    let _ = tracing_subscriber::registry()
        .with(startup.filter())
        .with(file)
        .try_init();
    build.log_startup("afklink-watchdog");
    startup.log_summary();
}

fn run(args: &WatchdogArgs) -> i32 {
    tracing::info!(
        pid = std::process::id(),
        expect = %args.expect,
        from = %args.from,
        exe = %args.exe.display(),
        target = ?args.target,
        timeout_s = args.timeout.as_secs(),
        hidden = args.hidden,
        "watchdog started"
    );
    #[cfg(not(windows))]
    {
        tracing::error!("watchdog: Windows only");
        EXIT_FAILED
    }
    #[cfg(windows)]
    {
        windows_run(args)
    }
}

#[cfg(windows)]
fn windows_run(args: &WatchdogArgs) -> i32 {
    use super::process::{Process, WatchdogLock};

    let dirs = match Dirs::locate() {
        Ok(dirs) => dirs,
        Err(e) => {
            tracing::error!("watchdog: no updates folder ({e}); not starting");
            return EXIT_FAILED;
        }
    };
    let _lock = match WatchdogLock::acquire() {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            tracing::warn!("watchdog: another watchdog is running; standing down");
            return EXIT_BUSY;
        }
        Err(e) => {
            tracing::error!("watchdog: lock not taken ({e}); not starting");
            return EXIT_FAILED;
        }
    };
    let own = match std::env::current_exe() {
        Ok(own) => own,
        Err(e) => {
            tracing::error!("watchdog: own path unknown ({e}); not starting");
            return EXIT_FAILED;
        }
    };
    if same_file(&own, &args.exe) {
        tracing::error!(exe = %args.exe.display(), "watchdog: runs from the exe it would restore; not starting");
        return EXIT_FAILED;
    }
    let backup_sha = match crate::staged_file::sha256_of_file(&own) {
        Ok((hash, len)) => {
            tracing::info!(backup = %own.display(), sha256 = %hash, bytes = len, "watchdog: runs from the backup");
            hash
        }
        Err(e) => {
            tracing::error!(backup = %own.display(), "watchdog: own image not read ({e}); not starting");
            return EXIT_FAILED;
        }
    };
    let attempt = match state::load_state(&dirs.updates) {
        Ok(s) => s.attempt,
        Err(e) => {
            tracing::warn!("watchdog: {e}; going by the command line alone");
            None
        }
    };
    let new_sha = match &attempt {
        Some(a) if a.to == args.expect.to_string() => {
            if !a.backup_sha256.eq_ignore_ascii_case(&backup_sha) {
                tracing::warn!(recorded = %a.backup_sha256, own = %backup_sha, "watchdog: the backup is not the one recorded; restoring from it all the same");
            }
            Some(a.new_sha256.clone())
        }
        other => {
            tracing::warn!(attempt = ?other, "watchdog: state.json has no attempt to {}; the exe is not checked against it", args.expect);
            None
        }
    };
    let ctx = Ctx {
        args,
        dirs: &dirs,
        own: &own,
        backup_sha: &backup_sha,
    };

    let parent = match args.target {
        WatchTarget::Launch { parent } => match Process::open(parent) {
            // Opened before «ready»: the old version waits for that answer, so its id cannot have
            // been reused yet.
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    parent,
                    "watchdog: the old version not opened ({e}); not starting"
                );
                return EXIT_FAILED;
            }
        },
        WatchTarget::Adopt { .. } => None,
    };
    let mut stdout = std::io::stdout();
    match stdout
        .write_all(format!("{WATCHDOG_READY}\n").as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => tracing::info!("watchdog: ready (told the app)"),
        Err(e) => tracing::warn!("watchdog: «ready» not written ({e}); carrying on"),
    }

    let supervised = match args.target {
        WatchTarget::Launch { parent: parent_pid } => {
            if let Some(p) = &parent {
                wait_for_parent(p);
            } else {
                tracing::info!(
                    parent = parent_pid,
                    "watchdog: the old version was already gone"
                );
            }
            if let Some(expected) = &new_sha {
                match crate::staged_file::sha256_of_file(&args.exe) {
                    Ok((hash, _)) if hash.eq_ignore_ascii_case(expected) => {
                        tracing::debug!(exe = %args.exe.display(), "watchdog: the exe is the update");
                    }
                    other => {
                        tracing::error!(exe = %args.exe.display(), seen = ?other, expected = %expected, "watchdog: the exe is not the update");
                        return roll_back(&ctx, None, RollbackReason::ExeMismatch);
                    }
                }
            }
            std::thread::sleep(LAUNCH_GRACE);
            match launch_new(args, parent_pid) {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("watchdog: the new version did not start: {e}");
                    return roll_back(&ctx, None, RollbackReason::LaunchFailed);
                }
            }
        }
        WatchTarget::Adopt { pid } => match Process::open(pid) {
            Ok(Some(p)) => {
                tracing::info!(pid, "watchdog: supervising the running new version");
                p
            }
            Ok(None) => {
                // Gone before it could be watched: whatever health it left decides.
                tracing::warn!(pid, "watchdog: the version to supervise is already gone");
                return decide_without_process(&ctx, pid);
            }
            Err(e) => {
                tracing::error!(
                    pid,
                    "watchdog: the version to supervise not opened ({e}); leaving it be"
                );
                return EXIT_FAILED;
            }
        },
    };
    supervise(&ctx, &supervised)
}

/// What the watchdog works with.
struct Ctx<'a> {
    args: &'a WatchdogArgs,
    dirs: &'a Dirs,
    /// Its own image: the backup.
    own: &'a Path,
    backup_sha: &'a str,
}

#[cfg(windows)]
fn wait_for_parent(p: &super::process::Process) {
    let started = Instant::now();
    match p.wait(PARENT_EXIT_TIMEOUT) {
        Ok(true) => tracing::info!(
            parent = p.pid(),
            waited_ms = started.elapsed().as_millis() as u64,
            "watchdog: the old version exited"
        ),
        Ok(false) => {
            tracing::warn!(
                parent = p.pid(),
                "watchdog: the old version still running after {} s; ending it",
                PARENT_EXIT_TIMEOUT.as_secs()
            );
            if let Err(e) = p.kill(KILL_WAIT) {
                tracing::error!(parent = p.pid(), "watchdog: the old version not ended: {e}");
            }
        }
        Err(e) => tracing::warn!(
            parent = p.pid(),
            "watchdog: wait for the old version failed: {e}"
        ),
    }
}

/// Start the new exe with `--after-update <parent>`, and open it for supervision.
#[cfg(windows)]
fn launch_new(args: &WatchdogArgs, parent: u32) -> Result<super::process::Process, String> {
    let mut command = Command::new(&args.exe);
    command.arg(launch::AFTER_UPDATE).arg(parent.to_string());
    if args.hidden {
        command.arg(launch::HIDDEN);
    }
    if let Some(dir) = args.exe.parent() {
        command.current_dir(dir);
    }
    let child = command
        .spawn()
        .map_err(|e| format!("start {}: {e}", args.exe.display()))?;
    let pid = child.id();
    tracing::info!(pid, exe = %args.exe.display(), version = %args.expect, "watchdog: new version started");
    // Opened while `child` still holds its own handle, so the id is this process's. `child` is then
    // dropped: that closes its handles, it does not end the process.
    let opened = super::process::Process::open(pid);
    drop(child);
    match opened {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(format!("process {pid} vanished at once")),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn supervise(ctx: &Ctx<'_>, p: &super::process::Process) -> i32 {
    let expect = ctx.args.expect.to_string();
    let launched = Instant::now();
    let mut healthy_since: Option<Instant> = None;
    // The heartbeat's last value, and when (by this process's clock) it last changed.
    let mut beat: (Option<u64>, Instant) = (None, Instant::now());
    loop {
        // Exit first, health second: a report written just before exiting is seen.
        let exited = (!p.alive()).then(|| p.exit_code());
        let health = match state::load_health(&ctx.dirs.updates) {
            Ok(h) => h.filter(|h| h.is_from(&expect, p.pid())),
            Err(e) => {
                tracing::debug!("watchdog: health.json not read this time: {e}");
                None
            }
        };
        if healthy_since.is_none() && health.as_ref().is_some_and(|h| h.healthy_at_ms.is_some()) {
            healthy_since = Some(Instant::now());
            beat.1 = Instant::now();
            tracing::info!(
                pid = p.pid(),
                after_ms = launched.elapsed().as_millis() as u64,
                probation_s = PROBATION.as_secs(),
                "watchdog: the new version reports health (connected to the server)"
            );
        }
        if let Some(value) = health.as_ref().and_then(|h| h.beat_at_ms) {
            if beat.0 != Some(value) {
                tracing::trace!(value, "watchdog: heartbeat");
                beat = (Some(value), Instant::now());
            }
        }
        let o = Observation {
            since_launch: launched.elapsed(),
            healthy_for: healthy_since.map(|t| t.elapsed()),
            exited,
            quit: health.as_ref().is_some_and(|h| h.quit_at_ms.is_some()),
            beat_stale: healthy_since.is_some() && beat.1.elapsed() >= BEAT_STALE,
        };
        match step(&o, ctx.args.timeout, PROBATION) {
            Step::Wait => std::thread::sleep(POLL),
            Step::Succeed => return confirm(ctx, &o),
            Step::LeaveUnconfirmed => {
                tracing::info!(pid = p.pid(), "watchdog: the new version quit cleanly before proving itself; its next start is supervised again");
                return EXIT_OK;
            }
            Step::RollBack(reason) => {
                tracing::warn!(
                    pid = p.pid(),
                    ?o,
                    reason = reason.as_str(),
                    "watchdog: the new version failed"
                );
                return roll_back(ctx, Some(p as &dyn Kill), reason);
            }
        }
    }
}

/// Adopt mode, the process already gone: health decides between a confirmation and a rollback.
#[cfg(windows)]
fn decide_without_process(ctx: &Ctx<'_>, pid: u32) -> i32 {
    let health = state::load_health(&ctx.dirs.updates)
        .ok()
        .flatten()
        .filter(|h| h.is_from(&ctx.args.expect.to_string(), pid));
    let o = Observation {
        since_launch: Duration::ZERO,
        healthy_for: health
            .as_ref()
            .and_then(|h| h.healthy_at_ms)
            .map(|_| Duration::ZERO),
        exited: Some(None),
        quit: health.as_ref().is_some_and(|h| h.quit_at_ms.is_some()),
        beat_stale: false,
    };
    match step(&o, ctx.args.timeout, PROBATION) {
        Step::Succeed => confirm(ctx, &o),
        Step::RollBack(reason) => roll_back(ctx, None, reason),
        Step::Wait | Step::LeaveUnconfirmed => EXIT_OK,
    }
}

fn confirm(ctx: &Ctx<'_>, o: &Observation) -> i32 {
    let expect = ctx.args.expect.to_string();
    let result = apply::update_state(ctx.dirs, |s| {
        s.succeed(&expect);
        let pruned = s.prune(&ctx.args.expect);
        if !pruned.is_empty() {
            tracing::debug!(
                ?pruned,
                "watchdog: failure records of older versions removed"
            );
        }
    });
    match result {
        Ok(()) => tracing::info!(
            from = %ctx.args.from,
            to = %expect,
            ?o,
            "watchdog: update confirmed; {} stays as the previous version",
            ctx.own.display()
        ),
        // The update stands; the next start of the new version finds its health and records it.
        Err(e) => tracing::warn!("watchdog: update confirmed, but state.json not written: {e}"),
    }
    EXIT_OK
}

/// End the new version if it runs, put the backup back, record the failure, start the old version.
fn roll_back(ctx: &Ctx<'_>, running: Option<&dyn Kill>, reason: RollbackReason) -> i32 {
    let args = ctx.args;
    tracing::warn!(
        from = %args.expect,
        to = %args.from,
        reason = reason.as_str(),
        exe = %args.exe.display(),
        "watchdog: rolling back"
    );
    if let Some(p) = running {
        match p.end(KILL_WAIT) {
            Ok(true) => tracing::info!("watchdog: the new version ended"),
            Ok(false) => tracing::debug!("watchdog: the new version had already exited"),
            Err(e) => {
                tracing::error!("watchdog: the new version not ended ({e}); restoring all the same")
            }
        }
    }
    let restored = apply::restore_exe(
        ctx.own,
        &args.exe,
        ctx.backup_sha,
        RESTORE_DEADLINE,
        |a, b| std::fs::rename(a, b),
    );
    match &restored {
        Ok(()) => {
            tracing::info!(exe = %args.exe.display(), version = %args.from, "watchdog: the previous version is back in place")
        }
        Err(e) => {
            tracing::error!(exe = %args.exe.display(), "watchdog: the previous version could NOT be put back: {e}")
        }
    }
    let version = args.expect.to_string();
    let recorded = apply::update_state(ctx.dirs, |s| {
        s.attempt = None;
        let strikes = s.record_failure(
            &version,
            reason.as_str(),
            reason.unverified(),
            state::now_ms(),
        );
        tracing::info!(
            version = %version,
            strikes,
            unverified = reason.unverified(),
            retry = ?s.retry(&version, state::now_ms()),
            "watchdog: failure recorded"
        );
    });
    if let Err(e) = recorded {
        tracing::error!("watchdog: the failure not recorded in state.json: {e}");
    }

    // The app, restored — or, if the exe's path could not be restored, the backup itself.
    std::thread::sleep(LAUNCH_GRACE);
    let first: &Path = if restored.is_ok() { &args.exe } else { ctx.own };
    let mut candidates: Vec<&Path> = vec![first];
    if first != ctx.own {
        candidates.push(ctx.own);
    }
    for exe in candidates {
        match start_restored(exe, args) {
            Ok(pid) => {
                if exe == ctx.own {
                    tracing::error!(pid, exe = %exe.display(), "watchdog: the app runs from the backup (last resort); the exe's path needs the owner's attention");
                } else {
                    tracing::info!(pid, exe = %exe.display(), "watchdog: the previous version started");
                }
                return if restored.is_ok() {
                    EXIT_OK
                } else {
                    EXIT_FAILED
                };
            }
            Err(e) => tracing::error!(exe = %exe.display(), "watchdog: not started: {e}"),
        }
    }
    tracing::error!("watchdog: no version of AFKLink could be started");
    EXIT_FAILED
}

fn start_restored(exe: &Path, args: &WatchdogArgs) -> Result<u32, String> {
    let mut command = Command::new(exe);
    command
        .arg(launch::ROLLED_BACK_FROM)
        .arg(args.expect.to_string());
    if args.hidden {
        command.arg(launch::HIDDEN);
    }
    if let Some(dir) = args.exe.parent() {
        command.current_dir(dir);
    }
    command
        .spawn()
        .map(|child| child.id())
        .map_err(|e| format!("start {}: {e}", exe.display()))
}

/// Ending the supervised process, as [`roll_back`] needs it.
trait Kill {
    /// End it: `Ok(true)` ended now, `Ok(false)` it had already exited.
    fn end(&self, wait: Duration) -> Result<bool, String>;
}

#[cfg(windows)]
impl Kill for super::process::Process {
    fn end(&self, wait: Duration) -> Result<bool, String> {
        if !self.alive() {
            return Ok(false);
        }
        self.kill(wait).map(|()| true)
    }
}

/// Whether two paths name the same file (case-insensitively, after resolving what can be).
fn same_file(a: &Path, b: &Path) -> bool {
    let canon =
        |p: &Path| -> PathBuf { std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()) };
    canon(a).to_string_lossy().to_lowercase() == canon(b).to_string_lossy().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(180);
    const S: fn(u64) -> Duration = Duration::from_secs;

    fn look(since: u64, healthy_for: Option<u64>, exited: Option<Option<u32>>, quit: bool) -> Step {
        step(
            &Observation {
                since_launch: S(since),
                healthy_for: healthy_for.map(S),
                exited,
                quit,
                beat_stale: false,
            },
            TIMEOUT,
            PROBATION,
        )
    }

    #[test]
    fn a_hang_after_the_first_connection_is_rolled_back() {
        // Case c) once connected: its heartbeat (window thread answering) stops during the probation.
        let hung = Observation {
            since_launch: S(40),
            healthy_for: Some(S(30)),
            exited: None,
            quit: false,
            beat_stale: true,
        };
        assert_eq!(
            step(&hung, TIMEOUT, PROBATION),
            Step::RollBack(RollbackReason::Hung)
        );
        // Stale at the end of the probation too: not confirmed.
        let at_the_end = Observation {
            healthy_for: Some(PROBATION),
            ..hung
        };
        assert_eq!(
            step(&at_the_end, TIMEOUT, PROBATION),
            Step::RollBack(RollbackReason::Hung)
        );
        assert!(!RollbackReason::Hung.unverified());
    }

    #[test]
    fn a_healthy_version_is_confirmed_after_the_probation() {
        assert_eq!(look(5, None, None, false), Step::Wait);
        assert_eq!(look(8, Some(0), None, false), Step::Wait);
        assert_eq!(look(60, Some(59), None, false), Step::Wait);
        assert_eq!(look(70, Some(60), None, false), Step::Succeed);
    }

    #[test]
    fn a_crash_at_start_is_rolled_back_at_once() {
        // Case a): our code never ran — the process is simply gone, whatever its code.
        assert_eq!(
            look(1, None, Some(Some(0xC000_0135)), false),
            Step::RollBack(RollbackReason::Exited(Some(0xC000_0135)))
        );
        assert_eq!(
            look(1, None, Some(None), false),
            Step::RollBack(RollbackReason::Exited(None))
        );
    }

    #[test]
    fn no_connection_or_a_hang_is_rolled_back_at_the_timeout() {
        // Cases b) and c): alive, but never reports health.
        assert_eq!(look(179, None, None, false), Step::Wait);
        assert_eq!(
            look(180, None, None, false),
            Step::RollBack(RollbackReason::NoHealth)
        );
        assert!(RollbackReason::NoHealth.unverified());
        assert!(!RollbackReason::Exited(None).unverified());
    }

    #[test]
    fn a_crash_during_the_probation_is_rolled_back() {
        assert_eq!(
            look(30, Some(20), Some(Some(3)), false),
            Step::RollBack(RollbackReason::ExitedOnProbation(Some(3)))
        );
    }

    #[test]
    fn a_clean_quit_is_not_a_failure() {
        // After health: the update counts.
        assert_eq!(look(30, Some(20), Some(Some(0)), true), Step::Succeed);
        // Before health: nothing is decided; its next start is supervised again.
        assert_eq!(look(10, None, Some(Some(0)), true), Step::LeaveUnconfirmed);
        // A quit flag while still running means nothing yet.
        assert_eq!(look(10, None, None, true), Step::Wait);
    }

    #[test]
    fn reasons_have_stable_names() {
        for (reason, name) in [
            (RollbackReason::NoHealth, "no_health"),
            (RollbackReason::Exited(None), "exited"),
            (
                RollbackReason::ExitedOnProbation(Some(1)),
                "exited_on_probation",
            ),
            (RollbackReason::Hung, "hung"),
            (RollbackReason::LaunchFailed, "launch_failed"),
            (RollbackReason::ExeMismatch, "exe_mismatch"),
        ] {
            assert_eq!(reason.as_str(), name);
        }
    }

    #[test]
    fn a_path_is_the_same_file_whatever_its_case() {
        let exe = std::env::current_exe().unwrap();
        let upper = PathBuf::from(exe.to_string_lossy().to_uppercase());
        assert!(same_file(&exe, &upper));
        assert!(!same_file(&exe, &exe.with_file_name("other.exe")));
    }
}
