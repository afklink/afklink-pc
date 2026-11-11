//! Self-update of the portable exe: release builds check `latest.json` on our server, download a
//! newer version signed with the key in `updater.pub`, and swap it in when nobody is connected; a
//! watchdog puts the old version back if the new one does not start, connect or stay up.
//!
//! # The pieces
//!
//! - [`fetch`]: the check and the download, this module's own bounded requests (not
//!   tauri-plugin-updater, which is not in the app: no dependency, no registration, no
//!   `plugins.updater` in `tauri.conf.json`; a test holds all three, so no second key can come
//!   back with it). [`manifest`]: parsing, signature, `sha256`/`size`, the signed file and version.
//! - [`policy`]: when an update may be applied (nobody connected, no pairing, no driver operation,
//!   online, the PC not paused, automatic updates on or «Установить» pressed), and at once then.
//! - [`apply`]: backup of the running exe, staging (hash-checked, held read-only), `self_replace`,
//!   the watchdog's start. Any failure puts the old exe back before this process carries on.
//! - [`watchdog`]: the old version (the backup) started with `--update-watchdog`; starts the new
//!   one, waits for its health, rolls back when it does not come.
//! - [`state`] (`state.json`: attempt in flight, failures per version; `health.json`;
//!   `check.json`: the last check's answer), [`task`] (the check/download/apply loop and the
//!   health watcher), [`launch`] (the flags that tie the processes together).
//!
//! # Trust
//!
//! - One pinned key ([`pubkey`]): `updater.pub`, embedded at build time. A test-key build (cargo
//!   feature `updater-test-key`) embeds `updater-test.pub` *instead*, so broken rollback-test
//!   builds can never be installed by a production copy, nor a production release by a test build.
//! - The manifest only from our own API hosts over https, every redirect hop included; the exe from
//!   any https host, because the signature, not the host, is trusted ([`fetch`]).
//! - Only a newer version, never a downgrade ([`policy::is_newer`]).
//! - Nothing is installed while the PC is paused: a failed update rolls back to the previous exe,
//!   and one built before the pause was kept in config.json would start unpaused ([`policy`]).
//!
//! # The window, the files, who updates
//!
//! Settings polls [`get_update_status`] every second and listens to [`STATUS_EVENT`], sent on every
//! change and, thinned out, during a download; a sequence number drops stale answers.
//! Files: `%LOCALAPPDATA%\AFKLink\updates\` (`state.json`, `health.json`, `check.json`,
//! `previous\AFKLink-<version>.exe` kept for a manual rollback too, `staging-<uuid>\` while
//! applying); the watchdog logs to `%APPDATA%\AFKLink\logs\afklink-watchdog.<UTC date>.log`.
//! Only a release build (`AFKLINK_BUILD_CHANNEL=release`) with a key in `updater.pub`, on Windows
//! x64, updates. A development build says «Недоступно в dev-сборке» and never touches `state.json`.

use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use semver::Version;
use serde::Serialize;
use tauri::{AppHandle, Runtime, State, Url};
use tokio::sync::{broadcast, mpsc};

use afklink_core::build_info::{BuildInfo, Channel};
use afklink_core::{AgentControl, AgentEvent};
use afklink_i18n::Locale;

mod apply;
mod fetch;
mod launch;
/// The flag the sign-in entry starts the app with (`crate::autostart`).
pub(crate) use launch::AUTOSTART as AUTOSTART_ARG;
/// The flags a relaunch starts the app with (`crate::supervise`).
pub(crate) use launch::{
    HIDDEN as HIDDEN_ARG, PAUSED as PAUSED_ARG, RELAUNCHED_FROM as RELAUNCHED_FROM_ARG,
};
/// A process's exe, and whether two paths are one file (`crate::instance_probe`).
pub(crate) use process::{image_of as process_image, same_file};
mod manifest;
mod policy;
mod process;
mod pubkey;
mod state;
mod task;
mod watchdog;

pub(crate) use launch::Launch;

/// For `tests/updater_http.rs` only, not an API: the check and the download as the app runs them,
/// against local servers (the async runtime is Tauri's, which those tests share with the app).
#[doc(hidden)]
pub mod testing {
    pub use super::fetch::{
        check, check_any, download, download_any, Checked, DownloadError, Downloaded, Limits,
        Release, CHECK_TIMEOUT, LIMITS, MAX_EXE_BYTES, MAX_MANIFEST_BYTES,
    };
    /// The key file this build embeds (`updater.pub`, or `updater-test.pub` in a test-key build).
    pub const KEY_FILE: &str = super::pubkey::KEY_FILE;
    /// Whether this is a test-key build (the feature `updater-test-key`).
    pub const TEST_SIGNING_KEY: bool = super::pubkey::TEST_SIGNING_KEY;
}

/// Whether this build trusts the TEST signing key instead of the production one (`pubkey`, «The
/// test key»): `build_info` names it in the `User-Agent`.
pub(crate) const TEST_SIGNING_KEY: bool = pubkey::TEST_SIGNING_KEY;
use policy::Defer;

/// Where the manifest is: `release-build.ts` writes it, CI publishes it there — the agents' own
/// hostname, `api.afklink.app` (`DOWNLOAD_BASE_URL` of `scripts/lib/common.ts` + `latest.json`,
/// which a scripts test checks), where the exe URLs inside it point too. The same directory is
/// served on the RU entry's, `api.ru.afklink.app` (`afklink_core::entry`): the check and the
/// download try it too, first when the signaling socket goes that way.
pub(crate) const ENDPOINT: &str = "https://api.afklink.app/download/latest.json";
/// Another manifest, for a test against a test release (kept in release
/// builds): read at start, taken only on our own hosts over https ([`override_allowed`]), with a
/// warning on every start that uses it. The key is still the embedded one, so this can point only at
/// our own signed builds; redirects stay https only (`fetch`). The test manifest
/// (`/download/test-latest.json`) carries the marker `afklink_test_key: true` and its builds are
/// signed with the TEST key, which only a test-key build trusts (`pubkey`, «The test key»): a
/// production copy pointed at it refuses it at the check (`manifest::check_world`).
pub(crate) const ENDPOINT_VAR: &str = "AFKLINK_UPDATE_ENDPOINT";
/// How long the new version waits for the one it replaces to exit before it starts anyway.
const AFTER_UPDATE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a relaunched process (`--relaunched-from`, `crate::supervise`) waits for the one that
/// relaunched it to exit before it starts anyway: the same as after an update, for the same exit.
const RELAUNCH_WAIT: std::time::Duration = AFTER_UPDATE_WAIT;

/// Why updates are off in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// A development build: the owner's own builds are never replaced.
    Dev,
    /// No usable key in `updater.pub`, no updates folder, or not Windows x64.
    Off,
}

/// The event the loop sends the window with an [`UpdateStatusDto`] on every change, and, thinned
/// out, while a download runs (its percent): a download of a second would otherwise go unseen
/// between two of the window's once-a-second polls. Every status carries a sequence number, so an
/// answer older than one the window has is dropped.
pub(crate) const STATUS_EVENT: &str = "update-status";

/// What the Settings section shows, kept by the updater's loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Nothing checked yet in this run (and the last run's check says nothing about this version).
    Idle,
    Checking,
    UpToDate,
    /// Newer, not downloaded: automatic updates are off.
    Available {
        version: String,
    },
    Downloading {
        version: String,
    },
    /// Downloaded and verified, and something is in the way of installing it. Never shown without
    /// a reason: the moment a download is ready the loop decides, and installs when nothing is.
    Ready {
        version: String,
        defer: Defer,
    },
    Installing {
        version: String,
    },
    CheckFailed,
    DownloadFailed {
        version: String,
    },
    /// This version failed before and is not retried yet.
    Blocked {
        version: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Shared {
    pub(crate) phase: Phase,
    /// While downloading: the whole percent received, when the server announced the size.
    pub(crate) progress: Option<u8>,
    /// When this version's last check got an answer, Unix ms (kept in `check.json` across starts).
    pub(crate) checked_at_ms: Option<u64>,
    /// This run is the new version the update watchdog started: «Обновлено до X» for this run.
    pub(crate) updated: bool,
    /// Bumped with every change the window is told of, so it can drop an answer older than one it
    /// already has (a poll that was on its way while an event overtook it).
    pub(crate) seq: u64,
}

impl Shared {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Idle,
            progress: None,
            checked_at_ms: None,
            updated: false,
            seq: 0,
        }
    }
}

/// What the window asks the loop for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Request {
    /// «Проверить», and «Повторить» after a failed check. With an update already downloaded, not
    /// a new check: a look whether it may be installed now.
    Check,
    /// «Установить», and «Повторить» after a failed download or update: download if needed,
    /// install once nobody is connected (whatever the switch says), retry a failed version.
    ApplyNow,
    AutoChanged(bool),
}

/// This process's part in an update in flight: set while it has not proved itself, read on exit.
static PROBATION: Mutex<Option<task::Probation>> = Mutex::new(None);

/// What the start of `run()` found on the command line.
pub(crate) struct Early {
    parsed: launch::Parsed,
    /// `--after-update`: how the wait for the replaced process ended.
    waited: Option<(u32, process::WaitOutcome)>,
    /// `--relaunched-from`: how the wait for the process that relaunched this one ended.
    relaunch_waited: Option<(u32, RelaunchWait)>,
}

/// How long the process that relaunched this one, still running after [`RELAUNCH_WAIT`], has to be
/// gone once it is ended.
const RELAUNCH_END_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// How the wait for the process that relaunched this one (`--relaunched-from`) ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelaunchWait {
    /// The id is this process's own (a command line nobody here writes): nothing waited for.
    OwnPid,
    /// The process with that id was created after this one, so it cannot be the one that started
    /// this one (its id reused, or given by hand): neither waited for nor ended.
    Newer,
    /// It was gone, or went, within the wait.
    Gone(process::WaitOutcome),
    /// Still running after the wait — stuck past its own hard exit (`supervise`) — so ended: it
    /// runs this exe, was created before this process, and it asked for this launch.
    Ended,
    /// It could not be waited for, or was still running and could not be ended (why): the
    /// single-instance lock may hand this launch to it.
    NotEnded {
        outcome: process::WaitOutcome,
        why: String,
    },
}

/// What [`wait_for_relauncher`] needs of the process it waits for, all through one handle opened
/// once: the wait, the checks and the end act on the same process, so an id reused in between is
/// never the one ended.
pub(crate) trait Relauncher {
    /// Wait up to `timeout` for it to exit: `true` if it has.
    fn wait(&self, timeout: std::time::Duration) -> Result<bool, String>;
    /// When it was created (any monotonic scale shared with [`This::created`]).
    fn created(&self) -> Result<u64, String>;
    /// Its exe.
    fn image(&self) -> Result<std::path::PathBuf, String>;
    /// End it and wait up to `timeout` for it to be gone.
    fn kill(&self, timeout: std::time::Duration) -> Result<(), String>;
}

#[cfg(windows)]
impl Relauncher for process::Process {
    fn wait(&self, timeout: std::time::Duration) -> Result<bool, String> {
        process::Process::wait(self, timeout)
    }
    fn created(&self) -> Result<u64, String> {
        process::Process::created(self)
    }
    fn image(&self) -> Result<std::path::PathBuf, String> {
        process::Process::image(self)
    }
    fn kill(&self, timeout: std::time::Duration) -> Result<(), String> {
        process::Process::kill(self, timeout)
    }
}

/// This process, as [`wait_for_relauncher`] compares the other one with it.
pub(crate) struct This {
    pub(crate) pid: u32,
    /// When it was created (`process::this_process_created`).
    pub(crate) created: Result<u64, String>,
    /// Its exe.
    pub(crate) exe: Result<std::path::PathBuf, String>,
}

/// Wait (bounded by `wait`) for `pid`, the process that relaunched this one, to exit; if it is
/// still running then, end it — only when it runs this exe and was created before this process
/// (the relauncher started this one, so it is older: a newer process with that id is not it). One
/// handle (`open`) for all of it. Never this process itself.
pub(crate) fn wait_for_relauncher<P: Relauncher>(
    pid: u32,
    this: &This,
    open: impl FnOnce(u32) -> Result<Option<P>, String>,
    wait: std::time::Duration,
    end_wait: std::time::Duration,
) -> RelaunchWait {
    use process::WaitOutcome;
    if pid == this.pid {
        return RelaunchWait::OwnPid;
    }
    let target = match open(pid) {
        Ok(Some(target)) => target,
        Ok(None) => return RelaunchWait::Gone(WaitOutcome::NotRunning),
        Err(e) => {
            return RelaunchWait::NotEnded {
                outcome: WaitOutcome::Failed(e),
                why: "it could not be opened".to_string(),
            }
        }
    };
    // Compared before the wait: a newer process is not waited for either. When a time cannot be
    // read the wait still happens (it ends nothing), the end does not.
    let end_refused = match (target.created(), &this.created) {
        (Ok(its), Ok(ours)) if its >= *ours => return RelaunchWait::Newer,
        (Ok(_), Ok(_)) => None,
        (Err(e), _) => Some(format!("its creation time is unknown ({e})")),
        (_, Err(e)) => Some(format!("this process's creation time is unknown ({e})")),
    };
    let started = std::time::Instant::now();
    match target.wait(wait) {
        Ok(true) => {
            return RelaunchWait::Gone(WaitOutcome::Exited {
                waited: started.elapsed(),
            })
        }
        Ok(false) => {}
        Err(e) => {
            return RelaunchWait::NotEnded {
                outcome: WaitOutcome::Failed(e),
                why: "it could not be waited for".to_string(),
            }
        }
    }
    let not_ended = |why: String| RelaunchWait::NotEnded {
        outcome: WaitOutcome::TimedOut,
        why,
    };
    if let Some(why) = end_refused {
        return not_ended(why);
    }
    let exe = match &this.exe {
        Ok(exe) => exe,
        Err(e) => return not_ended(format!("this exe's path is unknown ({e})")),
    };
    match target.image() {
        Ok(its) if process::same_file(&its, exe) => {}
        Ok(its) => return not_ended(format!("it runs {}, not {}", its.display(), exe.display())),
        Err(e) => return not_ended(e),
    }
    match target.kill(end_wait) {
        Ok(()) => RelaunchWait::Ended,
        Err(e) => not_ended(e),
    }
}

/// [`wait_for_relauncher`] for real: this process, the relauncher opened to wait for it, read it
/// and end it.
#[cfg(windows)]
fn relaunch_wait(pid: u32) -> RelaunchWait {
    let this = This {
        pid: std::process::id(),
        created: process::this_process_created(),
        exe: std::env::current_exe().map_err(|e| e.to_string()),
    };
    wait_for_relauncher(
        pid,
        &this,
        process::Process::open,
        RELAUNCH_WAIT,
        RELAUNCH_END_WAIT,
    )
}

#[cfg(not(windows))]
fn relaunch_wait(pid: u32) -> RelaunchWait {
    if pid == std::process::id() {
        return RelaunchWait::OwnPid;
    }
    RelaunchWait::NotEnded {
        outcome: process::WaitOutcome::Failed("implemented on Windows only".into()),
        why: "waiting for a process is implemented on Windows only".to_string(),
    }
}

impl Early {
    pub(crate) fn launch(&self) -> &Launch {
        &self.parsed.launch
    }

    /// Windows started this process at sign-in (`--autostart`, the `Run` entry's flag).
    pub(crate) fn autostart(&self) -> bool {
        self.parsed.autostart
    }

    /// `--paused`: the process that relaunched this one was paused («Прервать все сеансы») and could
    /// not write it to config.json (`crate::supervise`): this start is paused too.
    pub(crate) fn paused(&self) -> bool {
        self.parsed.paused
    }

    /// Say it, once the log exists.
    pub(crate) fn log(&self) {
        self.parsed.log();
        match &self.waited {
            Some((pid, outcome)) if outcome.gone() => tracing::info!(
                old_pid = pid,
                ?outcome,
                "started by the update watchdog; the replaced version is gone"
            ),
            Some((pid, outcome)) => tracing::warn!(
                old_pid = pid,
                ?outcome,
                wait_s = AFTER_UPDATE_WAIT.as_secs(),
                "started by the update watchdog, but the replaced version may still be running"
            ),
            None => {}
        }
        match &self.relaunch_waited {
            Some((pid, RelaunchWait::Gone(outcome))) => tracing::info!(
                old_pid = pid,
                ?outcome,
                "relaunched by the previous process after its orchestrator stopped; that process \
                 is gone"
            ),
            Some((pid, RelaunchWait::OwnPid)) => tracing::warn!(
                old_pid = pid,
                "--relaunched-from names this process itself: not waited for; an ordinary start"
            ),
            Some((pid, RelaunchWait::Newer)) => tracing::warn!(
                old_pid = pid,
                "--relaunched-from names a process created after this one (its id reused, or \
                 given by hand): it cannot be the one that started this one, so it is neither \
                 waited for nor ended; an ordinary start"
            ),
            Some((pid, RelaunchWait::Ended)) => tracing::warn!(
                old_pid = pid,
                wait_s = RELAUNCH_WAIT.as_secs(),
                "relaunched by the previous process, which was still running {} s later (stuck on \
                 its way out): ended, being this exe and older than this process",
                RELAUNCH_WAIT.as_secs()
            ),
            Some((pid, RelaunchWait::NotEnded { outcome, why })) => tracing::error!(
                old_pid = pid,
                ?outcome,
                wait_s = RELAUNCH_WAIT.as_secs(),
                "relaunched by the previous process, which may still be running and was not ended \
                 ({why}): the single-instance lock may hand this launch to it"
            ),
            None => {}
        }
        if let Launch::RolledBack { from, .. } = self.launch() {
            // The warning, with what follows, is the health watcher's (`task::watch_health`).
            tracing::info!(failed = %from, "started by the update watchdog after a rollback");
        }
    }
}

/// The first thing `run()` does, before logging, config, Tauri and its single-instance lock: read the
/// command line; as the watchdog, run it and exit; after an update, wait (bounded) for the replaced
/// version to be gone.
pub(crate) fn early(args: impl IntoIterator<Item = OsString>) -> Early {
    let parsed = match launch::parse(args) {
        Ok(parsed) => parsed,
        Err(e) => std::process::exit(watchdog::main(Err(e))),
    };
    let waited = match &parsed.launch {
        Launch::Watchdog(args) => std::process::exit(watchdog::main(Ok(args.clone()))),
        Launch::AfterUpdate { old_pid, .. } => Some((
            *old_pid,
            process::wait_for_exit(*old_pid, AFTER_UPDATE_WAIT),
        )),
        Launch::Normal { .. } | Launch::RolledBack { .. } => None,
    };
    // Before the single-instance lock: the relaunching process still holds it while it exits, and a
    // second instance would hand it our launch and end (`crate::supervise`).
    let relaunch_waited = parsed.relaunched_from.map(|pid| (pid, relaunch_wait(pid)));
    Early {
        parsed,
        waited,
        relaunch_waited,
    }
}

/// Managed state behind the Settings commands.
pub(crate) struct UpdaterHandle {
    version: String,
    unavailable: Option<Unavailable>,
    shared: Arc<Mutex<Shared>>,
    tx: Option<mpsc::UnboundedSender<Request>>,
}

impl UpdaterHandle {
    fn send(&self, request: Request) -> Result<(), String> {
        let Some(tx) = &self.tx else {
            tracing::debug!(?request, unavailable = ?self.unavailable, "updates: request ignored, updates are off in this build");
            return Err("updates are not available in this build".to_string());
        };
        tx.send(request).map_err(|e| {
            tracing::warn!(request = ?e.0, "updates: request not delivered, the loop has stopped");
            "the updater has stopped".to_string()
        })
    }
}

/// Start the health watcher and, where updates are on, the updater's loop. Called from `setup`;
/// `events` is subscribed before the agent runs, so its first connection is not missed. `entry`: the
/// way to the server the signaling socket uses, which the check and the download try first
/// (`afklink_core::entry`).
pub(crate) fn start<R: Runtime>(
    app: &AppHandle<R>,
    control: AgentControl,
    build: &BuildInfo,
    launch: Launch,
    events: broadcast::Receiver<AgentEvent>,
    locale: Locale,
    entry: Arc<afklink_core::entry::Entry>,
) -> UpdaterHandle {
    let shared = Arc::new(Mutex::new(Shared::new()));
    let off = |unavailable: Unavailable| UpdaterHandle {
        version: build.version.clone(),
        unavailable: Some(unavailable),
        shared: Arc::clone(&shared),
        tx: None,
    };
    // Which key, first: a test-key build warns on every start, whatever turns the updates off below.
    pubkey::announce();
    if build.channel != Channel::Release {
        tracing::info!(channel = %build.channel, "updates: off in a development build");
        return off(Unavailable::Dev);
    }
    let current = match Version::parse(&build.version) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(version = %build.version, "updates: off, this build's version is not SemVer: {e}");
            return off(Unavailable::Off);
        }
    };
    let dirs = match apply::Dirs::locate() {
        Ok(dirs) => dirs,
        Err(e) => {
            tracing::warn!("updates: off, no updates folder: {e}");
            return off(Unavailable::Off);
        }
    };
    tracing::debug!(dir = %dirs.updates.display(), "updates: folder");
    // What the loop's first status is depends on how this run started (right after an update, the
    // last run's check is not this version's); the health watcher takes `launch` itself.
    let start = launch.clone();
    // Health first, whatever the key says: a new version must report in even if it cannot update
    // itself further.
    tauri::async_runtime::spawn(task::watch_health(
        app.clone(),
        control.clone(),
        dirs.clone(),
        current.clone(),
        launch,
        events,
        locale,
        &PROBATION,
    ));
    // The watchdog's last resort — the app started from the backup because the exe's own path could
    // not be restored — must not update itself: the backup would be swapped for the update.
    if let Ok(exe) = std::env::current_exe() {
        let exe_lower = exe.to_string_lossy().to_lowercase();
        let dir_lower = dirs.updates.to_string_lossy().to_lowercase();
        if exe_lower.starts_with(&dir_lower) {
            tracing::warn!(exe = %exe.display(), "updates: off, this is the backup copy running (a rollback's last resort); put AFKLink back in its place (README, «Обновления»)");
            return off(Unavailable::Off);
        }
    }
    if !cfg!(all(windows, target_arch = "x86_64")) {
        tracing::info!("updates: off, the manifest has Windows x64 builds only");
        return off(Unavailable::Off);
    }
    // The only key the check and the download are given (`task::TauriIo::key`): `tauri.conf.json`
    // has none. `updater.pub`'s, or in a test-key build `updater-test.pub`'s alone.
    let Some(key) = pubkey::embedded() else {
        return off(Unavailable::Off);
    };
    let endpoint = endpoint(std::env::var(ENDPOINT_VAR).ok().as_deref());
    let auto = afklink_core::lock(&control.config).auto_update;
    let user_agent = build.user_agent();
    tracing::info!(
        current = %current,
        auto,
        endpoint = %endpoint,
        ru_alternative = afklink_core::entry::ru_alternative(endpoint.as_str()).as_deref().unwrap_or("-"),
        %user_agent,
        "updates: on"
    );
    let (tx, rx) = mpsc::unbounded_channel();
    let io = task::TauriIo {
        app: app.clone(),
        control,
        key,
        endpoint,
        user_agent,
        dirs: dirs.clone(),
        current: current.clone(),
        entry,
        manifest_from: Mutex::new(None),
    };
    let updater = task::Updater::new(io, dirs, current, &start, Arc::clone(&shared), rx);
    tauri::async_runtime::spawn(updater.run());
    UpdaterHandle {
        version: build.version.clone(),
        unavailable: None,
        shared,
        tx: Some(tx),
    }
}

/// The manifest's address: [`ENDPOINT`], or an override from [`ENDPOINT_VAR`] that
/// [`override_allowed`] takes — with a warning either way, so a start that does not read the
/// default manifest always says so.
fn endpoint(override_value: Option<&str>) -> Url {
    #[allow(clippy::expect_used, reason = "a constant, checked by a test")]
    let default = Url::parse(ENDPOINT).expect("ENDPOINT is a URL");
    let Some(raw) = override_value.map(str::trim).filter(|v| !v.is_empty()) else {
        tracing::debug!(
            endpoint = ENDPOINT,
            "updates: no {ENDPOINT_VAR}; the default manifest address"
        );
        return default;
    };
    match override_allowed(raw) {
        Ok(url) => {
            tracing::warn!(
                %url,
                default = ENDPOINT,
                "updates: manifest address overridden by {ENDPOINT_VAR}: {url} instead of the default {ENDPOINT}"
            );
            url
        }
        Err(why) => {
            tracing::warn!(
                value = %shown(raw),
                default = ENDPOINT,
                "updates: {ENDPOINT_VAR} ignored ({why}); the default address {ENDPOINT} is used"
            );
            default
        }
    }
}

/// The directory the override's manifest must be in: where releases and the test-key manifest are
/// (`/download/latest.json`, `/download/test-latest.json` — flat: caddy serves no subdirectories
/// there, `release-build.ts --test-key` names its files `test-*`).
const OVERRIDE_DIR: &str = "/download/";

/// Whether an [`ENDPOINT_VAR`] value may replace [`ENDPOINT`]: a URL (WHATWG parsing, as reqwest
/// will read it — and connect to: the host checked is the host asked) on one of our two hosts over
/// https ([`fetch::our_api_host`]: exactly `api.afklink.app` or `api.ru.afklink.app`, any case, no
/// credentials, no port but 443, no IP address, no trailing dot or longer name), with a path under
/// [`OVERRIDE_DIR`] as the parser leaves it (`..` and `%2e%2e` segments already resolved) and no
/// encoded dot, slash or backslash left in it (`%2e`, `%2f`, `%5c`) that a server could resolve
/// otherwise. The URL, or why not.
pub(crate) fn override_allowed(raw: &str) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|e| format!("not a URL: {e}"))?;
    fetch::our_api_host(&url)?;
    let path = url.path();
    if !path.starts_with(OVERRIDE_DIR) {
        return Err(format!(
            "path {} is not under {OVERRIDE_DIR}",
            manifest::quoted(path, 80)
        ));
    }
    let lower = path.to_ascii_lowercase();
    if ["%2e", "%2f", "%5c"].iter().any(|e| lower.contains(e)) {
        return Err(format!(
            "path {} carries an encoded dot, slash or backslash",
            manifest::quoted(path, 80)
        ));
    }
    Ok(url)
}

/// `raw` as the log may show it: never credentials — a URL's are dropped; in anything else, only
/// what follows the last `@` is shown — on one line (control characters escaped) and at most 200
/// characters.
fn shown(raw: &str) -> String {
    let text = match Url::parse(raw) {
        Ok(mut url) if !url.username().is_empty() || url.password().is_some() => {
            // Neither fails for a URL with a host, which one with credentials has.
            let _ = url.set_username("");
            let _ = url.set_password(None);
            format!("{url} (credentials not shown)")
        }
        _ => match raw.rsplit_once('@') {
            Some((_, after)) => format!("(credentials not shown)@{after}"),
            None => raw.to_string(),
        },
    };
    manifest::quoted(&text, 200)
}

/// `RunEvent::Exit`: on probation, tell the watchdog this was a clean exit, not a crash — unless it
/// is not one (`abnormal`): the supervisor ends the process because its orchestrator ended
/// (`crate::supervise`), and the watchdog must see a failed exit (it rolls the update back) rather
/// than take it for the owner's quit (which, after health, confirms the update).
pub(crate) fn on_exit(abnormal: bool) {
    on_exit_in(&PROBATION, abnormal);
}

fn on_exit_in(probation: &Mutex<Option<task::Probation>>, abnormal: bool) {
    let Ok(slot) = probation.try_lock() else {
        tracing::debug!("updates: probation busy at exit; no clean exit reported");
        return;
    };
    let Some(p) = slot.as_ref() else {
        return;
    };
    if abnormal {
        tracing::warn!(
            version = %p.version,
            "updates: on probation, exiting because the orchestrator ended: no clean exit \
             reported — the watchdog takes it for a failure"
        );
        return;
    }
    task::report_quit(p);
}

/// This process is a new version on probation (an update's attempt it has not settled): its
/// watchdog may still be deciding.
pub(crate) fn on_probation() -> bool {
    afklink_core::lock(&PROBATION).is_some()
}

/// Whether an update's watchdog holds its lock now (`process::watchdog_alive`).
pub(crate) fn watchdog_alive() -> bool {
    process::watchdog_alive()
}

/// An update is being applied: from the moment the exe is about to be swapped until this process
/// exits for the watchdog — or the apply fails, which clears it ([`Applying`]). The supervisor
/// takes an end of the orchestrator meanwhile for part of a leaving (`crate::supervise`): a relaunch
/// then would start the new exe without `--after-update`, behind the watchdog's back.
static APPLYING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether an update is being applied ([`APPLYING`]).
pub(crate) fn applying() -> bool {
    APPLYING.load(std::sync::atomic::Ordering::SeqCst)
}

/// Marks an update's apply in progress ([`APPLYING`]) while it lives; [`Applying::handed_over`]
/// keeps the mark for good (the process exits for the watchdog), a drop otherwise clears it.
pub(crate) struct Applying {
    kept: bool,
}

impl Applying {
    pub(crate) fn begin() -> Self {
        APPLYING.store(true, std::sync::atomic::Ordering::SeqCst);
        tracing::debug!(
            "updates: apply in progress (an end of the orchestrator now is no failure)"
        );
        Self { kept: false }
    }

    /// The update was handed to its watchdog: the process exits, the mark stays.
    pub(crate) fn handed_over(mut self) {
        self.kept = true;
    }
}

impl Drop for Applying {
    fn drop(&mut self) {
        if !self.kept {
            APPLYING.store(false, std::sync::atomic::Ordering::SeqCst);
            tracing::debug!("updates: apply over without a hand-over; the mark cleared");
            say_stranded();
        }
    }
}

/// The orchestrator ended while an update was being applied, and the supervisor stood down for the
/// update ([`orchestrator_ended_during_apply`]); taken by whoever says it ([`say_stranded`]).
static ENDED_DURING_APPLY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// From the supervisor (`crate::supervise`), on its thread: the orchestrator ended while an update
/// was being applied, so it relaunched nothing. Should that apply fail — now or later — the app is
/// left with no link, and that is said ([`say_stranded`]). True when it was said here (the apply
/// already over).
pub(crate) fn orchestrator_ended_during_apply() -> bool {
    ENDED_DURING_APPLY.store(true, std::sync::atomic::Ordering::SeqCst);
    // The apply may have failed between the supervisor's look and now: then its drop found nothing
    // to say, and it is said here.
    !applying() && say_stranded()
}

/// An apply ended without a hand-over after the orchestrator had ended during it: said once, at
/// `error`. True when said.
fn say_stranded() -> bool {
    if !ENDED_DURING_APPLY.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return false;
    }
    tracing::error!(
        target: crate::log_route::SYSTEM_TARGET,
        "updates: the update failed after the orchestrator had ended during it: the app stays up \
         with no link to the server — the supervisor did not relaunch it, the update being under \
         way then, and nothing relaunches it now; restarting AFKLink brings the link back"
    );
    true
}

// ---------- Settings → «Обновления» ----------

/// The section's one button, by what it does (the window names it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// «Проверить»: [`check_for_updates`].
    Check,
    /// «Повторить» after a failed check: [`check_for_updates`].
    RetryCheck,
    /// «Установить» (automatic updates off): [`apply_update`].
    Install,
    /// «Повторить» after a failed download or update: [`apply_update`].
    RetryUpdate,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::RetryCheck => "retry_check",
            Self::Install => "install",
            Self::RetryUpdate => "retry_update",
        }
    }
}

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateStatusDto {
    /// This build's version.
    version: String,
    /// `"dev"` or `"off"` when updates are unavailable in this build; `null` otherwise.
    unavailable: Option<&'static str>,
    /// `config.auto_update`.
    auto: bool,
    /// `idle`, `checking`, `up_to_date`, `available`, `downloading`, `after_session`, `later`,
    /// `installing`, `check_failed`, `download_failed` or `rolled_back`.
    state: &'static str,
    /// The version the state is about, when it is about one.
    latest: Option<String>,
    /// The button under the status line ([`Action`]): `check`, `retry_check`, `install`,
    /// `retry_update`, or `null` for none (a download, an install, an update that waits, a build
    /// without updates — and «Установить» while someone is connected).
    action: Option<&'static str>,
    /// A check, download or install is running: the button waits.
    busy: bool,
    /// `downloading` only: the whole percent received, `null` while the size is unknown.
    progress: Option<u8>,
    /// When this version's last check got an answer, Unix ms: «проверено в 16:50» beside
    /// `up_to_date`.
    checked_at_ms: Option<u64>,
    /// This run started right after an update to `version`: «Обновлено до 0.1.1».
    updated: bool,
    /// Grows with every change; the window drops a status older than the one it shows.
    seq: u64,
}

/// What the section shows for `shared`: one status per moment, always something true to say. With
/// the switch and whether someone is connected, which only decides whether «Установить» is offered
/// (an install waits for the session to end anyway, and a button that does nothing now confuses).
fn status_dto(
    version: &str,
    unavailable: Option<Unavailable>,
    auto: bool,
    session: bool,
    shared: &Shared,
) -> UpdateStatusDto {
    let (state, latest, action, busy) = match &shared.phase {
        Phase::Idle => ("idle", None, Some(Action::Check), false),
        Phase::Checking => ("checking", None, Some(Action::Check), true),
        Phase::UpToDate => ("up_to_date", None, Some(Action::Check), false),
        Phase::Available { version }
        | Phase::Ready {
            version,
            defer: Defer::AutoOff,
        } => (
            "available",
            Some(version),
            (!session).then_some(Action::Install),
            false,
        ),
        Phase::Downloading { version } => ("downloading", Some(version), None, true),
        // «После сеанса» only when there is one, never with nobody connected.
        Phase::Ready {
            version,
            defer: Defer::Session,
        } => ("after_session", Some(version), None, false),
        // Offline, a driver operation, a pairing prompt, another update's watchdog, the PC paused.
        Phase::Ready { version, .. } => ("later", Some(version), None, false),
        Phase::Installing { version } => ("installing", Some(version), None, true),
        Phase::CheckFailed => ("check_failed", None, Some(Action::RetryCheck), false),
        Phase::DownloadFailed { version } => (
            "download_failed",
            Some(version),
            Some(Action::RetryUpdate),
            false,
        ),
        Phase::Blocked { version } => (
            "rolled_back",
            Some(version),
            Some(Action::RetryUpdate),
            false,
        ),
    };
    let downloading = matches!(shared.phase, Phase::Downloading { .. });
    UpdateStatusDto {
        version: version.to_string(),
        unavailable: unavailable.map(|u| match u {
            Unavailable::Dev => "dev",
            Unavailable::Off => "off",
        }),
        auto,
        state,
        latest: latest.cloned(),
        action: action.filter(|_| unavailable.is_none()).map(Action::as_str),
        busy,
        progress: shared.progress.filter(|_| downloading),
        checked_at_ms: shared.checked_at_ms,
        updated: shared.updated,
        seq: shared.seq,
    }
}

/// The section's state, polled while Settings is open (the loop's [`STATUS_EVENT`] besides).
#[tauri::command]
pub(crate) fn get_update_status(
    handle: State<'_, UpdaterHandle>,
    control: State<'_, AgentControl>,
) -> UpdateStatusDto {
    // One lock at a time, never nested: the loop takes them in its own order.
    let auto = afklink_core::lock(&control.config).auto_update;
    let session = !afklink_core::lock(&control.state).sessions.is_empty();
    let shared = afklink_core::lock(&handle.shared).clone();
    status_dto(&handle.version, handle.unavailable, auto, session, &shared)
}

/// «Проверить», and «Повторить» after a failed check.
#[tauri::command]
pub(crate) fn check_for_updates(handle: State<'_, UpdaterHandle>) -> Result<(), String> {
    let phase = afklink_core::lock(&handle.shared).phase.clone();
    tracing::info!(?phase, "owner pressed «Проверить» (updates)");
    handle.send(Request::Check)
}

/// «Установить», and «Повторить» after a failed download or update: install now, or once the
/// session ends.
#[tauri::command]
pub(crate) fn apply_update(handle: State<'_, UpdaterHandle>) -> Result<(), String> {
    let phase = afklink_core::lock(&handle.shared).phase.clone();
    tracing::info!(?phase, "owner pressed «Установить» / «Повторить» (updates)");
    handle.send(Request::ApplyNow)
}

/// «Обновлять автоматически». Applied at once, then saved to config.json (as `set_autostart` does).
#[tauri::command]
pub(crate) fn set_auto_update(
    handle: State<'_, UpdaterHandle>,
    control: State<'_, AgentControl>,
    enabled: bool,
) -> Result<(), String> {
    let (saved, changed) = {
        let mut cfg = afklink_core::lock(&control.config);
        tracing::info!(
            from = cfg.auto_update,
            to = enabled,
            "automatic updates changed from Settings"
        );
        let changed = cfg.auto_update != enabled;
        cfg.auto_update = enabled;
        (cfg.save(), changed)
    };
    // `pc_setting_changed` (`afklink_core::agent_events`): in force whether or not the disk took it.
    if changed {
        afklink_core::agent_events::setting_changed(
            afklink_protocol::metrics::PcSettingKey::AutoUpdate,
            afklink_protocol::metrics::PcSettingValue::Flag(enabled),
        );
    }
    if handle.tx.is_some() {
        if let Err(e) = handle.send(Request::AutoChanged(enabled)) {
            tracing::warn!("automatic updates: the loop not told: {e}");
        }
    }
    saved.map_err(|e| {
        tracing::warn!(
            enabled,
            "automatic updates choice not saved to config.json: {e:#}"
        );
        e.to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On probation, an exit because the orchestrator ended (the supervisor's) reports no clean
    /// exit — the watchdog sees a failed one and rolls back — while the owner's quit still does.
    #[test]
    fn an_abnormal_exit_on_probation_reports_no_quit() {
        let dir =
            std::env::temp_dir().join(format!("afklink-probation-quit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let dirs = apply::Dirs {
            updates: dir.clone(),
        };
        let slot = Mutex::new(Some(task::Probation {
            dirs: dirs.clone(),
            version: "0.8.0".into(),
            from: None,
        }));
        on_exit_in(&slot, true);
        let health = state::load_health(&dirs.updates).expect("read");
        assert!(
            health.as_ref().is_none_or(|h| h.quit_at_ms.is_none()),
            "no quit after the orchestrator's end: {health:?}"
        );
        on_exit_in(&slot, false);
        let health = state::load_health(&dirs.updates)
            .expect("read")
            .expect("written");
        assert!(health.quit_at_ms.is_some(), "the owner's quit is reported");
        // Not on probation: nothing either way.
        on_exit_in(&Mutex::new(None), false);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relauncher as [`wait_for_relauncher`] sees it: what it answers, and what was done to it.
    struct FakeRelauncher<'a> {
        created: Result<u64, String>,
        image: &'static str,
        exits: bool,
        waited: &'a std::cell::Cell<bool>,
        killed: &'a std::cell::Cell<bool>,
    }

    impl Relauncher for FakeRelauncher<'_> {
        fn wait(&self, _timeout: std::time::Duration) -> Result<bool, String> {
            self.waited.set(true);
            Ok(self.exits)
        }
        fn created(&self) -> Result<u64, String> {
            self.created.clone()
        }
        fn image(&self) -> Result<std::path::PathBuf, String> {
            Ok(self.image.into())
        }
        fn kill(&self, _timeout: std::time::Duration) -> Result<(), String> {
            self.killed.set(true);
            Ok(())
        }
    }

    /// The relaunching process is waited for and, still running after the wait,
    /// ended — through the one handle opened, only when it runs this exe and was created before
    /// this process; never this process itself, nor a process created after it (not waited for
    /// either).
    #[test]
    fn the_relauncher_is_waited_for_then_ended_never_this_process_nor_a_newer_one() {
        use process::WaitOutcome;
        const EXE: &str = r"C:\AFKLink\afklink-app.exe";
        let this = This {
            pid: 7,
            created: Ok(1_000),
            exe: Ok(EXE.into()),
        };
        let wait = std::time::Duration::from_millis(1);
        let (waited, killed) = (&std::cell::Cell::new(false), &std::cell::Cell::new(false));
        let target = |created: Result<u64, String>, image: &'static str, exits: bool| {
            waited.set(false);
            killed.set(false);
            move |_: u32| {
                Ok(Some(FakeRelauncher {
                    created,
                    image,
                    exits,
                    waited,
                    killed,
                }))
            }
        };
        let never = |_: u32| -> Result<Option<FakeRelauncher<'static>>, String> {
            panic!("must not be opened")
        };

        assert_eq!(
            wait_for_relauncher(7, &this, never, wait, wait),
            RelaunchWait::OwnPid
        );
        assert_eq!(
            wait_for_relauncher(
                8,
                &this,
                |_| Ok(None::<FakeRelauncher<'static>>),
                wait,
                wait
            ),
            RelaunchWait::Gone(WaitOutcome::NotRunning)
        );
        // Gone within the wait: nothing ended.
        let got = wait_for_relauncher(8, &this, target(Ok(900), EXE, true), wait, wait);
        assert!(
            matches!(got, RelaunchWait::Gone(WaitOutcome::Exited { .. })),
            "{got:?}"
        );
        assert!(waited.get() && !killed.get());
        // Stuck, this exe, older: ended.
        assert_eq!(
            wait_for_relauncher(8, &this, target(Ok(900), EXE, false), wait, wait),
            RelaunchWait::Ended
        );
        assert!(killed.get());
        // Created after this process (or at the same time): neither waited for nor ended.
        for created in [1_000, 1_001] {
            assert_eq!(
                wait_for_relauncher(8, &this, target(Ok(created), EXE, false), wait, wait),
                RelaunchWait::Newer
            );
            assert!(!waited.get() && !killed.get(), "created {created}");
        }
        // Another exe: waited for, not ended.
        let got = wait_for_relauncher(
            8,
            &this,
            target(Ok(900), r"C:\Windows\notepad.exe", false),
            wait,
            wait,
        );
        assert!(
            matches!(&got, RelaunchWait::NotEnded { outcome: WaitOutcome::TimedOut, why } if why.contains("notepad")),
            "{got:?}"
        );
        assert!(waited.get() && !killed.get());
        // Its creation time unknown: waited for, not ended.
        let got = wait_for_relauncher(
            8,
            &this,
            target(Err("denied".into()), EXE, false),
            wait,
            wait,
        );
        assert!(matches!(got, RelaunchWait::NotEnded { .. }), "{got:?}");
        assert!(waited.get() && !killed.get());
        // Not to be opened: nothing waited for.
        assert!(matches!(
            wait_for_relauncher(
                8,
                &this,
                |_| Err::<Option<FakeRelauncher<'static>>, _>("denied".into()),
                wait,
                wait
            ),
            RelaunchWait::NotEnded {
                outcome: WaitOutcome::Failed(_),
                ..
            }
        ));
    }

    /// The same for real (one handle each): a stuck process running the exe named and older than
    /// "this process" is ended; a process of another exe, or one created after this process, is
    /// left running; this process's own id is never touched.
    #[cfg(windows)]
    #[test]
    fn a_relauncher_is_ended_only_when_it_is_this_exe_and_older() {
        let spawn = || {
            std::process::Command::new("ping")
                .args(["-n", "30", "127.0.0.1"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("ping")
        };
        let wait = std::time::Duration::from_millis(100);
        let end_wait = std::time::Duration::from_secs(10);
        let running = |pid: u32| {
            process::wait_for_exit(pid, std::time::Duration::from_millis(50))
                == process::WaitOutcome::TimedOut
        };
        let mut child = spawn();
        let pid = child.id();
        let opened = process::Process::open(pid).expect("open").expect("running");
        let image = opened.image().expect("its image");
        let after_it = opened.created().expect("its creation time") + 1;
        drop(opened);
        let own = std::process::id();

        // This process's own id.
        let this = This {
            pid: own,
            created: process::this_process_created(),
            exe: std::env::current_exe().map_err(|e| e.to_string()),
        };
        assert_eq!(
            wait_for_relauncher(own, &this, process::Process::open, wait, end_wait),
            RelaunchWait::OwnPid
        );
        // Created after this process (the test binary): left running, not even waited for.
        assert_eq!(
            wait_for_relauncher(pid, &this, process::Process::open, wait, end_wait),
            RelaunchWait::Newer
        );
        assert!(running(pid), "a newer process is not ended");
        // Older than "this process", but another exe (this one is the test binary): left running.
        let other_exe = This {
            created: Ok(after_it),
            ..this
        };
        let got = wait_for_relauncher(pid, &other_exe, process::Process::open, wait, end_wait);
        assert!(
            matches!(
                got,
                RelaunchWait::NotEnded {
                    outcome: process::WaitOutcome::TimedOut,
                    ..
                }
            ),
            "{got:?}"
        );
        assert!(running(pid), "another exe's process is not ended");
        // Older and this exe: ended.
        let same_exe = This {
            pid: own,
            created: Ok(after_it),
            exe: Ok(image),
        };
        assert_eq!(
            wait_for_relauncher(pid, &same_exe, process::Process::open, wait, end_wait),
            RelaunchWait::Ended
        );
        assert!(process::wait_for_exit(pid, std::time::Duration::from_secs(1)).gone());
        let _ = child.wait();
    }

    /// An update's apply marks itself until it is handed over (the mark stays: the process
    /// exits for the watchdog) or fails (cleared).
    #[test]
    fn an_apply_in_progress_is_marked_until_it_fails() {
        // The only test that touches the mark.
        assert!(!applying());
        let failed = Applying::begin();
        assert!(applying());
        drop(failed);
        assert!(!applying());
        Applying::begin().handed_over();
        assert!(applying(), "handed over: kept until the process exits");
        APPLYING.store(false, std::sync::atomic::Ordering::SeqCst);

        // Item 4: the orchestrator ended during an apply that then failed — said once, by the
        // apply's end; or by the supervisor, when the apply was over before it looked again.
        let failed = Applying::begin();
        assert!(!orchestrator_ended_during_apply(), "the apply goes on");
        drop(failed);
        assert!(!say_stranded(), "said by the drop, once");
        assert!(orchestrator_ended_during_apply(), "the apply already over");
        assert!(!say_stranded(), "said once");
        // Handed over: nothing to say, ever.
        let handed = Applying::begin();
        assert!(!orchestrator_ended_during_apply());
        handed.handed_over();
        APPLYING.store(false, std::sync::atomic::Ordering::SeqCst);
        ENDED_DURING_APPLY.store(false, std::sync::atomic::Ordering::SeqCst);
        // No apply when the orchestrator ended: none of this is for it.
        assert!(!say_stranded());
    }

    /// What `f` logs at every level, as text.
    fn logged<T>(f: impl FnOnce() -> T) -> (T, String) {
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                afklink_core::lock(&self.0).extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let out = tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8_lossy(&afklink_core::lock(&buf.0)).into_owned();
        (out, text)
    }

    #[test]
    fn the_endpoint_is_ours_unless_an_override_names_our_own_hosts() {
        assert_eq!(ENDPOINT, "https://api.afklink.app/download/latest.json");
        assert_eq!(override_allowed(ENDPOINT).unwrap().as_str(), ENDPOINT);
        let (url, log) = logged(|| endpoint(None));
        assert_eq!(url.as_str(), ENDPOINT);
        assert!(!log.contains("WARN"), "{log}");
        assert_eq!(endpoint(Some("  ")).as_str(), ENDPOINT);
    }

    /// Our two hosts over https, any case, any path (the test-key manifest's shape among
    /// them): taken, with a warning that names the address and the default it replaces.
    #[test]
    fn an_override_on_our_hosts_is_taken_with_a_warning() {
        for (raw, taken) in [
            (
                "https://api.afklink.app/download/test/latest.json",
                "https://api.afklink.app/download/test/latest.json",
            ),
            (
                "https://api.ru.afklink.app/download/test/latest.json",
                "https://api.ru.afklink.app/download/test/latest.json",
            ),
            (
                "  HTTPS://API.AFKLINK.APP/download/latest.json  ",
                "https://api.afklink.app/download/latest.json",
            ),
            (
                "https://Api.Ru.AfkLink.App:443/download/test/latest.json?x=1",
                "https://api.ru.afklink.app/download/test/latest.json?x=1",
            ),
            // Percent-encoded dots in the host: the parser decodes them, and the host reqwest
            // connects to is the one checked, ours.
            (
                "https://api%2Eafklink%2Eapp/download/latest.json",
                "https://api.afklink.app/download/latest.json",
            ),
            // `..` resolved by the parser and still under /download/.
            (
                "https://api.afklink.app/download/x/../test/latest.json",
                "https://api.afklink.app/download/test/latest.json",
            ),
        ] {
            let (url, log) = logged(|| endpoint(Some(raw)));
            assert_eq!(url.as_str(), taken, "{raw}");
            assert!(
                log.contains("WARN")
                    && log.contains(&format!("overridden by {ENDPOINT_VAR}: {taken}"))
                    && log.contains(ENDPOINT),
                "{raw}: {log}"
            );
        }
    }

    /// Anything else is refused with a warning and the default is used: another scheme, another
    /// host however it is dressed up, credentials, an IP address, another port, not a URL.
    #[test]
    fn an_override_off_our_hosts_is_refused_and_the_default_used() {
        for (raw, why) in [
            ("http://api.afklink.app/download/latest.json", "not https"),
            ("ftp://api.afklink.app/latest.json", "not https"),
            (
                "https://api.afklink.app.evil.com/latest.json",
                "is not api.afklink.app",
            ),
            ("https://evil.com/latest.json", "is not api.afklink.app"),
            (
                "https://evil.api.afklink.app/latest.json",
                "is not api.afklink.app",
            ),
            (
                "https://afklink.app/download/latest.json",
                "is not api.afklink.app",
            ),
            (
                "https://api.afklink.app./latest.json",
                "is not api.afklink.app",
            ),
            // A Cyrillic «а»: punycode, another name.
            (
                "https://\u{430}pi.afklink.app/latest.json",
                "is not api.afklink.app",
            ),
            (
                "https://api.afklink.app@evil.com/latest.json",
                "credentials",
            ),
            (
                "https://user:secret@api.afklink.app/latest.json",
                "credentials",
            ),
            ("https://192.0.2.10/download/latest.json", "IP address"),
            ("https://[2001:db8::10]/download/latest.json", "IP address"),
            (
                "https://api.afklink.app:8443/download/latest.json",
                "port 8443",
            ),
            ("https://api.afklink.app:80/download/latest.json", "port 80"),
            ("api.afklink.app/download/latest.json", "not a URL"),
            ("not a url", "not a URL"),
            // A backslash is a slash to the parser (and to reqwest): our host, the path
            // `/@evil.com/x` — outside /download/.
            (
                "https://api.afklink.app\\@evil.com/x",
                "is not under /download/",
            ),
            // 0x7f.1 is 127.0.0.1 to the parser.
            ("https://0x7f.1/", "IP address"),
            ("https://api.afklink.app/x", "is not under /download/"),
            ("https://api.afklink.app/", "is not under /download/"),
            (
                "https://api.afklink.app/download",
                "is not under /download/",
            ),
            (
                "https://api.afklink.app/api/latest.json",
                "is not under /download/",
            ),
            (
                "https://api.afklink.app/download/../api/x",
                "is not under /download/",
            ),
            (
                "https://api.afklink.app/download/%2e%2e/api/x",
                "is not under /download/",
            ),
            (
                "https://api.afklink.app/download/%2E%2e/api/x",
                "is not under /download/",
            ),
            (
                "https://api.afklink.app/download/.%2e/api/x",
                "is not under /download/",
            ),
            (
                "https://api.afklink.app/download/..%2f..%2fapi/x",
                "encoded dot, slash",
            ),
            (
                "https://api.afklink.app/download/x%5c..%5c..%5capi",
                "encoded dot, slash",
            ),
            (
                "https://api.afklink.app/download/%2e%2e%2fapi/x",
                "encoded dot, slash",
            ),
        ] {
            let refused = override_allowed(raw).unwrap_err();
            assert!(refused.contains(why), "{raw}: {refused}");
            let (url, log) = logged(|| endpoint(Some(raw)));
            assert_eq!(url.as_str(), ENDPOINT, "{raw}");
            assert!(
                log.contains("WARN") && log.contains(&format!("{ENDPOINT_VAR} ignored")),
                "{raw}: {log}"
            );
            assert!(!log.contains("secret"), "credentials never logged: {log}");
        }
    }

    /// What the log shows of a refused value: no credentials, whether the value is a URL or not;
    /// one line; 200 characters at most.
    #[test]
    fn a_refused_value_is_shown_without_credentials_on_one_line() {
        // Not a URL to the parser's mind (a scheme `user`, no host): everything up to the last `@`
        // is dropped.
        for raw in ["user:pw@api.afklink.app/x", "a@b:pw@api.afklink.app/x"] {
            let s = shown(raw);
            assert!(!s.contains("pw") && !s.contains("user:"), "{s}");
            assert!(s.contains("api.afklink.app/x"), "{s}");
            let (_, log) = logged(|| endpoint(Some(raw)));
            assert!(!log.contains("pw@"), "{log}");
        }
        let s = shown("https://u:pw@api.afklink.app/x");
        assert!(
            !s.contains("pw") && s.contains("credentials not shown"),
            "{s}"
        );
        let s = shown("bad\nINFO fake line\u{1b}[0m");
        assert!(
            !s.contains('\n') && !s.contains('\u{1b}') && s.contains("\\n"),
            "{s}"
        );
        assert!(shown(&"x".repeat(1000)).chars().count() <= 203);
    }

    fn with(phase: Phase) -> Shared {
        Shared {
            phase,
            ..Shared::new()
        }
    }

    #[test]
    fn the_window_gets_one_state_and_the_one_button_it_may_show() {
        let dto = |phase: Phase| status_dto("0.1.0", None, true, false, &with(phase));
        let v = || "0.1.1".to_string();
        let idle = dto(Phase::Idle);
        assert_eq!((idle.state, idle.action), ("idle", Some("check")));
        let checking = dto(Phase::Checking);
        // The button stays where it was through the check, waiting: nothing jumps.
        assert_eq!(
            (checking.state, checking.action, checking.busy),
            ("checking", Some("check"), true)
        );
        assert_eq!(dto(Phase::UpToDate).action, Some("check"));
        let available = dto(Phase::Available { version: v() });
        assert_eq!(
            (
                available.state,
                available.latest.as_deref(),
                available.action
            ),
            ("available", Some("0.1.1"), Some("install"))
        );
        for (defer, state, action) in [
            (Defer::Session, "after_session", None),
            // Pairing is not a session: «после сеанса» would not be true.
            (Defer::Pairing, "later", None),
            (Defer::Offline, "later", None),
            (Defer::Maintenance, "later", None),
            (Defer::InFlight, "later", None),
            // Paused: «Установить» would not help, so it is not offered.
            (Defer::Paused, "later", None),
            (Defer::AutoOff, "available", Some("install")),
        ] {
            let d = dto(Phase::Ready {
                version: v(),
                defer,
            });
            assert_eq!((d.state, d.action), (state, action), "{defer:?}");
        }
        let installing = dto(Phase::Installing { version: v() });
        assert_eq!(
            (installing.state, installing.action, installing.busy),
            ("installing", None, true)
        );
        let check_failed = dto(Phase::CheckFailed);
        assert_eq!(
            (check_failed.state, check_failed.action),
            ("check_failed", Some("retry_check"))
        );
        let failed = dto(Phase::DownloadFailed { version: v() });
        assert_eq!(
            (failed.state, failed.action),
            ("download_failed", Some("retry_update"))
        );
        let blocked = dto(Phase::Blocked { version: v() });
        assert_eq!(
            (blocked.state, blocked.action),
            ("rolled_back", Some("retry_update"))
        );
    }

    #[test]
    fn install_is_not_offered_while_someone_is_connected() {
        for phase in [
            Phase::Available {
                version: "0.1.1".into(),
            },
            Phase::Ready {
                version: "0.1.1".into(),
                defer: Defer::AutoOff,
            },
        ] {
            let free = status_dto("0.1.0", None, false, false, &with(phase.clone()));
            let live = status_dto("0.1.0", None, false, true, &with(phase));
            assert_eq!((free.state, free.action), ("available", Some("install")));
            assert_eq!((live.state, live.action), ("available", None));
        }
    }

    #[test]
    fn the_percent_the_check_time_and_the_update_flag_reach_the_window() {
        let shared = Shared {
            phase: Phase::Downloading {
                version: "0.1.1".into(),
            },
            progress: Some(45),
            checked_at_ms: Some(1_790_000_000_000),
            updated: true,
            seq: 7,
        };
        let d = status_dto("0.1.0", None, true, false, &shared);
        assert_eq!(
            (d.state, d.progress, d.checked_at_ms, d.updated, d.seq),
            ("downloading", Some(45), Some(1_790_000_000_000), true, 7)
        );
        // A percent left over from a download is never shown with another state.
        let after = Shared {
            phase: Phase::Installing {
                version: "0.1.1".into(),
            },
            ..shared
        };
        assert_eq!(
            status_dto("0.1.0", None, true, false, &after).progress,
            None
        );
    }

    #[test]
    fn an_unavailable_build_offers_no_button() {
        let d = status_dto(
            "0.1.0",
            Some(Unavailable::Dev),
            true,
            false,
            &with(Phase::Idle),
        );
        assert_eq!((d.unavailable, d.action), (Some("dev"), None));
        let d = status_dto(
            "0.1.0",
            Some(Unavailable::Off),
            true,
            false,
            &with(Phase::Available {
                version: "0.1.1".into(),
            }),
        );
        assert_eq!((d.unavailable, d.action), (Some("off"), None));
    }
}
