//! The two tasks the app runs for updates.
//!
//! [`Updater::run`] checks (a random 5–15 s after start, then every 6 hours; an hour after a failed
//! check; at once on «Проверить»), downloads what is newer, and installs it the moment
//! [`policy::decide`] finds nothing in the way: right after the download, and then on every
//! [`TICK`] while something is (a session that ends is seen within seconds). Everything it does
//! outside itself goes through [`UpdateIo`] — [`TauriIo`] in the app, a fake in the tests — so its
//! decisions are tested as the app makes them.
//!
//! What the window shows is the loop's [`Phase`], sent on every change ([`UpdateIo::publish`]) and
//! read by the section's poll. The owner's check shows «Проверка…»; a scheduled one does only when
//! there is nothing else on screen yet (every six hours it would flash over «Последняя версия»),
//! and never over an update that is already downloaded. «Проверить» with an update downloaded is
//! not a check at all: it looks whether the update may be installed now.
//!
//! [`watch_health`] settles what the last run left in `state.json` ([`state::resolve_startup`]);
//! on probation, reports this version's health on its first connection to the server (once the
//! window thread answers too) and keeps a heartbeat going while that thread answers, so a hang is
//! seen; and after a rollback gives the verdict on the failed version: did this, the restored
//! version, reach the server within [`VERIFY_WINDOW`]? It is separate from the updater's loop so a
//! check or a download in progress can never delay what the watchdog is waiting for.

use std::collections::VecDeque;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use semver::Version;
use tauri::{AppHandle, Emitter, Manager, Runtime, Url};
use tokio::sync::{broadcast, mpsc};

use afklink_core::{AgentControl, AgentEvent};
use afklink_i18n::{Locale, NativeText};

use super::apply::{self, Applied, Dirs};
use super::fetch::{self, DownloadError, Downloaded};
use super::launch::{self, Launch, WatchTarget, WatchdogArgs};
use super::manifest::short;
use super::policy::{self, Conditions, Defer};
use super::process;
use super::state::{self, LastCheck, Retry, Settled, StartupResolution};
use super::{Phase, Request, Shared, UpdateStatusDto};

/// How often the loop wakes: runs a check when one is due, and looks whether a downloaded update
/// may be installed now.
const TICK: Duration = Duration::from_secs(5);
/// Between checks.
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// After a failed check.
const CHECK_RETRY: Duration = Duration::from_secs(3600);
/// The first check, this long after start: soon, so the section has something true to say, and at
/// a random point in the range, so PCs that start together (a power cut) do not ask the server
/// together.
const FIRST_CHECK: (u64, u64) = (5, 15);
/// The window hears of a download's progress at most this often ([`ProgressGate`]).
const PROGRESS_EVERY: Duration = Duration::from_millis(100);
/// How long the version put back after a rollback has to reach the server for the failure to count.
pub(crate) const VERIFY_WINDOW: Duration = Duration::from_secs(120);
/// How many rejected manifest entries the loop remembers ([`Rejected`]).
const REJECTED_KEEP: usize = 8;
/// How long a rejected manifest entry is not downloaded again ([`Rejected`]).
const REJECTED_FOR: Duration = Duration::from_secs(24 * 3600);
/// If the app has not exited this long after handing over to the watchdog, it ends itself.
const EXIT_FALLBACK: Duration = Duration::from_secs(20);
/// On probation, after the health report: a heartbeat this often while the window thread answers —
/// well inside the watchdog's `BEAT_STALE` — for this long (the probation and a margin).
pub(crate) const BEAT_EVERY: Duration = Duration::from_secs(5);
const BEAT_FOR: Duration = Duration::from_secs(150);
/// How long the window thread has to run a closure to count as answering.
const MAIN_THREAD_ANSWER: Duration = Duration::from_secs(3);

/// This process recorded how an update ended (`update_finished`): once, whichever of its ways to
/// learn it comes first.
static UPDATE_FINISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The time an update's outcome is dated by (`update_finished.at`), and where it came from (for the
/// log): a time on disk, the same for every process and path that learns of the outcome, so the
/// same fact is recorded with the same `at` and the queue and the server count it once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutcomeAt {
    at: u64,
    source: &'static str,
}

/// `update_finished confirmed`'s time for `me`: when this version first proved itself —
/// `health.json`'s `healthy_at_ms`, written by its first health report and read alike by this
/// process (its health report, the end of its probation, its clean exit) and by the next start that
/// settles the attempt. Now only when the file has none for this version.
fn confirmed_at(health: Option<&state::Health>, me: &str) -> OutcomeAt {
    match health
        .filter(|h| h.version == me)
        .and_then(|h| h.healthy_at_ms)
    {
        Some(at) => OutcomeAt {
            at,
            source: "health_json_healthy_at",
        },
        None => OutcomeAt {
            at: state::now_ms(),
            source: "now_no_health_on_disk",
        },
    }
}

/// How the update `from` → `to` ended, for the server (`update_finished`,
/// `afklink_core::agent_events`), at `at` — the outcome's own time on disk ([`OutcomeAt`]: a
/// rollback's strike, the new version's first health), so a resend after a restart, or the same
/// outcome learned another way, is the same fact. `reason` is a rollback's, as a short id. Once per
/// process; `why` says how this process learned it.
fn update_finished(
    from: &str,
    to: &str,
    outcome: afklink_protocol::metrics::UpdateOutcome,
    reason: Option<&str>,
    at: OutcomeAt,
    why: &'static str,
) {
    let OutcomeAt { at, source } = at;
    if UPDATE_FINISHED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        tracing::debug!(
            from,
            to,
            outcome = outcome.as_str(),
            why,
            "updates: the update's outcome was recorded by this process already"
        );
        return;
    }
    let reason = reason.and_then(|r| {
        let id = afklink_protocol::metrics::short_id(r);
        if id.is_none() {
            tracing::debug!(
                reason = r,
                "updates: the rollback's reason is not a short id; left out"
            );
        }
        id
    });
    tracing::info!(
        from,
        to,
        outcome = outcome.as_str(),
        reason = reason.as_deref().unwrap_or("-"),
        at,
        at_source = source,
        why,
        "updates: the update's outcome recorded for the server (update_finished)"
    );
    afklink_core::agent_events::record_at(
        at,
        afklink_protocol::metrics::AgentEventKind::UpdateFinished {
            from: from.to_string(),
            to: to.to_string(),
            outcome,
            reason,
        },
    );
}

/// Why a check runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// Its time came: the first after start, then every six hours (an hour after a failure).
    Scheduled,
    /// «Проверить», «Повторить» after a failed check, or «Установить» with nothing found yet.
    Owner,
}

impl Why {
    fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Owner => "owner",
        }
    }
}

/// A check's answer, as the loop needs it.
pub(crate) struct Answer<F> {
    /// A newer version, when there is one.
    pub(crate) found: Option<F>,
    /// The version the manifest names, newer or not (for the log and `check.json`).
    pub(crate) remote: Option<Version>,
}

/// How installing ended, as the loop needs it.
#[derive(Debug)]
pub(crate) enum ApplyOutcome {
    /// The watchdog took over: exit so it can start the new version.
    HandedOver { watchdog_pid: u32 },
    /// Nothing changed on disk and nothing failed: wait again (`defer`: what was in the way).
    NotNow { defer: Defer, why: String },
    /// Not installed, and it counts against the version; `strike` is the reason recorded.
    Failed { why: String, strike: &'static str },
    /// The task that installs died; the download it held is gone.
    Lost(String),
}

/// Everything the updater's loop does outside itself: the server, the agent's state, installing,
/// the window. [`TauriIo`] is the app's; the tests drive the loop with a fake.
pub(crate) trait UpdateIo: Send + Sync + 'static {
    /// A newer version a check found ([`fetch::Release`]), downloaded from as is.
    type Found: Send + Sync + 'static;

    fn found_version(found: &Self::Found) -> &str;

    /// What identifies `found`'s manifest entry — version, exe address, signature, hash, size
    /// ([`super::manifest::identity`]) — for [`Rejected`].
    fn found_identity(found: &Self::Found) -> &str;

    fn check(&self) -> impl Future<Output = Result<Answer<Self::Found>, String>> + Send;

    /// Download `found`, verified; `progress(received, total)` as bytes arrive.
    fn download(
        &self,
        found: &Self::Found,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> impl Future<Output = Result<Downloaded, DownloadError>> + Send;

    /// «Обновлять автоматически».
    fn auto_update(&self) -> bool;

    /// Sessions, connecting ones included.
    fn sessions(&self) -> usize;

    /// What [`policy::decide`] looks at, sampled now.
    fn conditions(&self, owner_asked: bool) -> Conditions;

    /// Put `ready` in place of the running exe. It comes back unless the task that installs lost it.
    fn apply(
        &self,
        ready: Downloaded,
    ) -> impl Future<Output = (ApplyOutcome, Option<Downloaded>)> + Send;

    /// The watchdog has taken over: exit.
    fn exit_for_update(&self);

    /// Tell the window ([`super::STATUS_EVENT`]).
    fn publish(&self, status: &UpdateStatusDto);
}

/// The manifest entries whose download was rejected ([`DownloadError::Rejected`]: signature, size,
/// hash, signed name — bytes that are not the release's) in this run, so the same entry is not
/// downloaded again at every check: a hostile or broken server could otherwise have some 35 MB
/// fetched every six hours, and every «Проверить». A rejection adds no strike (nothing was
/// installed), so this is the only thing that stops the repeat.
///
/// An entry is its [`super::manifest::identity`]: any change to the manifest's version, exe
/// address, signature, `sha256` or `size` — a corrected release of the same version, a newer one —
/// is another entry and is downloaded at once. In memory only, for this run: `state.json` is read
/// by the watchdog and by the version a rollback puts back, and the memory must never outlive a
/// mistake (a cache that served a broken exe once); a restart forgets it, [`REJECTED_FOR`] ends it,
/// and «Установить» / «Повторить» clears it. At most [`REJECTED_KEEP`] entries, the oldest dropped.
#[derive(Debug)]
pub(crate) struct Rejected {
    entries: VecDeque<(String, Instant)>,
    /// How long an entry is kept: [`REJECTED_FOR`] (shorter in a test of the loop).
    keep_for: Duration,
}

impl Default for Rejected {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            keep_for: REJECTED_FOR,
        }
    }
}

impl Rejected {
    /// Whether `identity` was rejected within [`REJECTED_FOR`] of `now`: how long ago. Entries past
    /// it are dropped.
    pub(crate) fn remembers(&mut self, identity: &str, now: Instant) -> Option<Duration> {
        let before = self.entries.len();
        let keep_for = self.keep_for;
        self.entries
            .retain(|(_, at)| now.saturating_duration_since(*at) < keep_for);
        if self.entries.len() != before {
            tracing::debug!(
                expired = before - self.entries.len(),
                kept = self.entries.len(),
                for_s = keep_for.as_secs(),
                "updates: rejected manifest entries past their time forgotten"
            );
        }
        self.entries
            .iter()
            .find(|(id, _)| id == identity)
            .map(|(_, at)| now.saturating_duration_since(*at))
    }

    /// Remember `identity` as rejected at `now` (once; the oldest goes past [`REJECTED_KEEP`]).
    pub(crate) fn remember(&mut self, identity: &str, now: Instant) {
        self.entries.retain(|(id, _)| id != identity);
        self.entries.push_back((identity.to_string(), now));
        while self.entries.len() > REJECTED_KEEP {
            if let Some((dropped, _)) = self.entries.pop_front() {
                tracing::debug!(
                    entry = short(&dropped),
                    keep = REJECTED_KEEP,
                    "updates: oldest rejected manifest entry forgotten, room for a new one"
                );
            }
        }
    }

    /// Forget every entry; how many there were.
    pub(crate) fn clear(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        n
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The updater's loop and what it knows.
pub(crate) struct Updater<I: UpdateIo> {
    io: I,
    dirs: Dirs,
    current: Version,
    shared: Arc<Mutex<Shared>>,
    rx: mpsc::UnboundedReceiver<Request>,
    /// Found and not downloaded (automatic updates off, a failed download, a blocked version).
    known: Option<I::Found>,
    ready: Option<Downloaded>,
    /// The owner pressed «Установить» (or «Повторить»): install as soon as nobody is connected,
    /// whatever the switch says.
    owner_asked: bool,
    next_check: Instant,
    /// The last decision logged, so only changes are.
    last_decision: Option<Result<(), Defer>>,
    /// The last retry verdict logged for a blocked version.
    last_blocked: Option<(Version, Retry)>,
    /// Manifest entries whose download was rejected: not downloaded again until they change.
    rejected: Rejected,
}

impl<I: UpdateIo> Updater<I> {
    pub(crate) fn new(
        io: I,
        dirs: Dirs,
        current: Version,
        launch: &Launch,
        shared: Arc<Mutex<Shared>>,
        rx: mpsc::UnboundedReceiver<Request>,
    ) -> Self {
        let first = first_check_delay();
        tracing::info!(
            first_check_s = first.as_secs(),
            every_h = CHECK_EVERY.as_secs() / 3600,
            "updates: checks scheduled"
        );
        let this = Self {
            io,
            dirs,
            current,
            shared,
            rx,
            known: None,
            ready: None,
            owner_asked: false,
            next_check: Instant::now() + first,
            last_decision: None,
            last_blocked: None,
            rejected: Rejected::default(),
        };
        this.show_start(launch);
        this
    }

    /// The status before this run's first check: «Обновлено до X» for the run right after an
    /// update; «Последняя версия» with its time when the last run's check was this version's and
    /// found nothing newer; nothing otherwise (the first check comes within seconds).
    fn show_start(&self, launch: &Launch) {
        let me = self.current.to_string();
        let last = state::load_check(&self.dirs.updates).unwrap_or_else(|e| {
            tracing::warn!("updates: {e}; the last check is taken as unknown");
            None
        });
        let updated = matches!(launch, Launch::AfterUpdate { .. });
        // An ordinary start only: after an update or a rollback the last check was another
        // version's, or found the very version that just failed.
        let kept = last
            .as_ref()
            .filter(|l| matches!(launch, Launch::Normal { .. }) && l.says_up_to_date(&me))
            .map(|l| l.at_ms);
        let shows = if kept.is_some() {
            "up to date, as the last check said"
        } else if updated {
            "updated to this version"
        } else {
            "nothing until the first check"
        };
        tracing::debug!(
            launch = launch.kind(),
            updated,
            ?last,
            shows,
            "updates: status at start"
        );
        let mut s = afklink_core::lock(&self.shared);
        s.updated = updated;
        s.checked_at_ms = kept;
        if kept.is_some() {
            s.phase = Phase::UpToDate;
        }
        s.seq += 1;
    }

    pub(crate) async fn run(mut self) {
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => self.on_tick().await,
                request = self.rx.recv() => match request {
                    Some(request) => self.on_request(request).await,
                    None => {
                        tracing::debug!("updates: command channel closed; the loop stops");
                        return;
                    }
                },
            }
        }
    }

    /// Show `phase`; `why` goes to the log with the change (each status is a decision). Whether it
    /// changed (and so was sent to the window).
    fn set_phase(&self, phase: Phase, why: &str) -> bool {
        let changed = {
            let mut s = afklink_core::lock(&self.shared);
            if s.phase == phase {
                false
            } else {
                tracing::debug!(from = ?s.phase, to = ?phase, why, "updates: status");
                s.phase = phase;
                s.progress = None;
                s.seq += 1;
                true
            }
        };
        if changed {
            self.publish();
        } else {
            tracing::trace!(why, "updates: status unchanged");
        }
        changed
    }

    /// Send the window what it should show now.
    fn publish(&self) {
        let auto = self.io.auto_update();
        let session = self.io.sessions() > 0;
        let dto = status_for(
            &self.current,
            auto,
            session,
            &afklink_core::lock(&self.shared),
        );
        self.io.publish(&dto);
    }

    async fn on_tick(&mut self) {
        if Instant::now() >= self.next_check {
            self.check(Why::Scheduled).await;
        }
        if self.ready.is_some() {
            self.maybe_apply().await;
        }
    }

    async fn on_request(&mut self, request: Request) {
        tracing::debug!(?request, "updates: request from the window");
        match request {
            Request::Check => {
                if let Some(ready) = &self.ready {
                    // «Проверить» with an update downloaded must not check again, flash
                    // «Установится позже» and go back to «Установится после сеанса». There is
                    // nothing to find: the answer is whether it may be installed now.
                    tracing::info!(
                        version = %ready.version,
                        "updates: «Проверить» with an update downloaded: no new check; looking whether it may be installed now"
                    );
                    self.maybe_apply().await;
                } else {
                    self.check(Why::Owner).await;
                }
            }
            Request::AutoChanged(true) => {
                if let Some(found) = self.known.take() {
                    tracing::info!(
                        version = I::found_version(&found),
                        "updates: automatic updates on; downloading the version found"
                    );
                    self.consider(found).await;
                } else if self.ready.is_some() {
                    tracing::debug!(
                        "updates: automatic updates on; looking at the downloaded update"
                    );
                    self.maybe_apply().await;
                }
            }
            Request::AutoChanged(false) => {
                if let Some(ready) = &self.ready {
                    tracing::info!(version = %ready.version, owner_asked = self.owner_asked, "updates: automatic updates off; the downloaded version waits for «Установить» unless it was pressed");
                    self.maybe_apply().await;
                }
            }
            Request::ApplyNow => {
                self.owner_asked = true;
                // The owner's explicit «Установить» / «Повторить»: one more download of an entry
                // rejected before is theirs to ask for.
                if !self.rejected.is_empty() {
                    let forgotten = self.rejected.clear();
                    tracing::info!(
                        forgotten,
                        "updates: the owner asked to install; rejected manifest entries forgotten, they may be downloaded again"
                    );
                }
                // The owner's explicit retry of a version that failed before: its record goes.
                let failed = match &afklink_core::lock(&self.shared).phase {
                    Phase::Blocked { version } | Phase::DownloadFailed { version } => {
                        Some(version.clone())
                    }
                    _ => None,
                };
                if let Some(version) = failed {
                    let forgotten = apply::update_state(&self.dirs, |s| {
                        if let Some(f) = s.forget(&version) {
                            tracing::info!(%version, strikes = f.strikes, reason = %f.reason, "updates: the owner retries a version that failed; its record is cleared");
                        }
                    });
                    if let Err(e) = forgotten {
                        tracing::warn!("updates: failure record not cleared: {e}");
                    }
                    self.last_blocked = None;
                }
                if let Some(ready) = &self.ready {
                    tracing::info!(version = %ready.version, "updates: the owner asked to install now");
                    self.maybe_apply().await;
                } else if let Some(found) = self.known.take() {
                    tracing::info!(
                        version = I::found_version(&found),
                        "updates: the owner asked to install now; downloading"
                    );
                    self.consider(found).await;
                } else {
                    tracing::info!("updates: the owner asked to install now; checking first");
                    self.check(Why::Owner).await;
                }
            }
        }
    }

    async fn check(&mut self, why: Why) {
        let loud = {
            let s = afklink_core::lock(&self.shared);
            why == Why::Owner || (s.phase == Phase::Idle && !s.updated)
        };
        if loud {
            self.set_phase(
                Phase::Checking,
                match why {
                    Why::Owner => "the owner asked for a check",
                    Why::Scheduled => "the first check; nothing on screen before it",
                },
            );
        } else {
            tracing::debug!(
                why = why.as_str(),
                "updates: checking without «Проверка…»: the status on screen stays until the answer"
            );
        }
        tracing::info!(why = why.as_str(), current = %self.current, "update check");
        let answer = self.io.check().await;
        let now = Instant::now();
        match answer {
            Err(e) => {
                self.next_check = now + CHECK_RETRY;
                tracing::warn!(
                    retry_in_min = CHECK_RETRY.as_secs() / 60,
                    "update check failed: {e}"
                );
                // A failed check replaces only a status that says there is nothing new: a version
                // found before — downloaded, offered, failed — is still what there is to say.
                let shown = afklink_core::lock(&self.shared).phase.clone();
                if matches!(
                    shown,
                    Phase::Idle | Phase::Checking | Phase::UpToDate | Phase::CheckFailed
                ) {
                    self.set_phase(Phase::CheckFailed, "the check failed");
                } else {
                    tracing::debug!(
                        ?shown,
                        "updates: the check failed; the status about the version found before stays"
                    );
                }
            }
            Ok(answer) => {
                self.next_check = now + CHECK_EVERY;
                self.remember_check(answer.remote.as_ref(), answer.found.is_none());
                match answer.found {
                    None => {
                        tracing::info!(
                            current = %self.current,
                            latest = answer.remote.as_ref().map_or_else(|| "?".to_string(), ToString::to_string),
                            "update check: up to date"
                        );
                        if let Some(ready) = self.ready.take() {
                            tracing::info!(version = %ready.version, "updates: the downloaded version is no longer offered; dropped");
                        }
                        self.known = None;
                        if !self.set_phase(Phase::UpToDate, "no newer version") {
                            // Still «Последняя версия»: the window gets the new check time.
                            self.publish();
                        }
                    }
                    Some(found) => {
                        tracing::info!(
                            current = %self.current,
                            available = I::found_version(&found),
                            "update check: a newer version is available"
                        );
                        self.consider(found).await;
                    }
                }
            }
        }
    }

    /// A check got an answer: its time for the section («проверено в 16:50»), and in `check.json`
    /// for the next start. The window hears of it with the status that follows.
    fn remember_check(&self, remote: Option<&Version>, up_to_date: bool) {
        let last = LastCheck {
            at_ms: state::now_ms(),
            version: self.current.to_string(),
            latest: remote.map(ToString::to_string),
            up_to_date,
        };
        match state::save_check(&self.dirs.updates, &last) {
            Ok(()) => tracing::debug!(?last, "updates: last check kept in check.json"),
            Err(e) => tracing::warn!(
                "updates: last check not kept ({e}); the next start shows nothing until its own check"
            ),
        }
        let mut s = afklink_core::lock(&self.shared);
        s.checked_at_ms = Some(last.at_ms);
        s.seq += 1;
    }

    /// A newer version was found: skip it if its failures say so, else download it (automatic
    /// updates on, or the owner asked) and install it, or offer it.
    async fn consider(&mut self, found: I::Found) {
        let raw = I::found_version(&found).to_string();
        let version = match Version::parse(&raw) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(version = %raw, "updates: the manifest's version is not SemVer ({e}); ignored");
                self.set_phase(Phase::CheckFailed, "the manifest's version is not SemVer");
                return;
            }
        };
        let st = self.load_state();
        let retry = st.retry(&raw, state::now_ms());
        if retry != Retry::Now {
            if self.last_blocked.as_ref() != Some(&(version.clone(), retry)) {
                let failure = st.failures.get(&raw);
                tracing::info!(
                    %version,
                    ?retry,
                    strikes = failure.map_or(0, |f| f.strikes),
                    reason = failure.map_or("-", |f| f.reason.as_str()),
                    "updates: this version failed before; not retried yet («Повторить» retries it now)"
                );
                self.last_blocked = Some((version.clone(), retry));
            }
            self.ready = None;
            self.known = Some(found);
            self.set_phase(
                Phase::Blocked {
                    version: version.to_string(),
                },
                "this version failed before and is not retried yet",
            );
            return;
        }
        if let Some(stale) = self.ready.take_if(|r| r.version != version) {
            tracing::info!(downloaded = %stale.version, newer = %version, "updates: a newer version replaces the one downloaded");
        }
        if self.ready.is_some() {
            tracing::debug!(%version, "updates: already downloaded; looking whether it may be installed");
            self.maybe_apply().await;
            return;
        }
        if !self.io.auto_update() && !self.owner_asked {
            tracing::info!(%version, "updates: automatic updates are off; offered, not downloaded");
            self.known = Some(found);
            self.set_phase(
                Phase::Available {
                    version: version.to_string(),
                },
                "automatic updates are off: offered with «Установить»",
            );
            return;
        }
        let identity = I::found_identity(&found).to_string();
        if let Some(ago) = self.rejected.remembers(&identity, Instant::now()) {
            tracing::warn!(
                %version,
                entry = short(&identity),
                rejected_min_ago = ago.as_secs() / 60,
                forgotten_after_h = REJECTED_FOR.as_secs() / 3600,
                "updates: this manifest entry's download was rejected before; not downloaded again until the manifest changes («Повторить» downloads it now)"
            );
            self.known = Some(found);
            self.set_phase(
                Phase::DownloadFailed {
                    version: version.to_string(),
                },
                "the same manifest entry was rejected before",
            );
            return;
        }
        tracing::debug!(
            %version,
            entry = short(&identity),
            rejected_kept = self.rejected.len(),
            "updates: this manifest entry was not rejected before; downloading"
        );
        self.set_phase(
            Phase::Downloading {
                version: version.to_string(),
            },
            if self.owner_asked {
                "the owner asked to install: downloading"
            } else {
                "a newer version: downloading"
            },
        );
        match download(&self.io, &self.shared, &self.current, &found).await {
            Ok(downloaded) => {
                self.known = None;
                self.ready = Some(downloaded);
                self.last_decision = None;
                // Installed at once when nothing is in the way; the status says what is otherwise.
                self.maybe_apply().await;
            }
            Err(e) => {
                match &e {
                    DownloadError::Transfer(_) => {
                        tracing::warn!(%version, "update: {e}; retried at the next check");
                        tracing::debug!(
                            %version,
                            entry = short(&identity),
                            "updates: a transfer failure is not remembered against the entry"
                        );
                    }
                    DownloadError::Unconfirmed(_) => {
                        // Not installed, but nothing broken for good: the next check tries again.
                        tracing::warn!(%version, "update: {e}; not installed");
                        tracing::info!(
                            %version,
                            entry = short(&identity),
                            "updates: not remembered against the manifest entry: nothing was learnt about its bytes (a short body or a check that did not finish); retried at the next check"
                        );
                    }
                    DownloadError::Rejected(_) => {
                        tracing::error!(%version, "update: {e}; not installed");
                        self.rejected.remember(&identity, Instant::now());
                        tracing::info!(
                            %version,
                            entry = short(&identity),
                            kept = self.rejected.len(),
                            for_h = REJECTED_FOR.as_secs() / 3600,
                            "updates: rejected manifest entry remembered; not downloaded again until the manifest changes"
                        );
                    }
                }
                self.known = Some(found);
                self.set_phase(
                    Phase::DownloadFailed {
                        version: version.to_string(),
                    },
                    "the download failed",
                );
            }
        }
    }

    fn load_state(&self) -> state::UpdateState {
        load_state(&self.dirs)
    }

    /// Install the downloaded update if nothing is in the way; else show what is.
    async fn maybe_apply(&mut self) {
        let Some(version) = self.ready.as_ref().map(|r| r.version.clone()) else {
            return;
        };
        let c = self.io.conditions(self.owner_asked);
        let decision = policy::decide(&c);
        if self.last_decision != Some(decision) {
            match decision {
                Ok(()) => tracing::info!(%version, ?c, "updates: nothing in the way; applying"),
                Err(defer) => {
                    tracing::info!(%version, reason = defer.as_str(), ?c, "updates: applying deferred")
                }
            }
            self.last_decision = Some(decision);
        } else {
            tracing::trace!(%version, ?decision, "updates: apply looked again");
        }
        match decision {
            Err(defer) => {
                self.set_phase(
                    Phase::Ready {
                        version: version.to_string(),
                        defer,
                    },
                    defer.as_str(),
                );
            }
            Ok(()) => self.apply().await,
        }
    }

    async fn apply(&mut self) {
        let Some(ready) = self.ready.take() else {
            return;
        };
        let version = ready.version.clone();
        self.set_phase(
            Phase::Installing {
                version: version.to_string(),
            },
            "nothing in the way: installing",
        );
        let (outcome, back) = self.io.apply(ready).await;
        match outcome {
            ApplyOutcome::HandedOver { watchdog_pid } => {
                tracing::info!(watchdog_pid, to = %version, "updates: the watchdog took over; exiting so it can start {version}");
                self.io.exit_for_update();
            }
            ApplyOutcome::NotNow { defer, why } => {
                // What is in the way now, as the decision sees it (a session or a pairing prompt
                // that appeared at the last moment); the reason `apply` gave if it sees nothing.
                let defer = policy::decide(&self.io.conditions(self.owner_asked))
                    .err()
                    .unwrap_or(defer);
                tracing::info!(%version, reason = defer.as_str(), "updates: not installed at the last moment: {why}; waiting again");
                self.last_decision = None;
                match back {
                    Some(ready) => {
                        self.ready = Some(ready);
                        self.set_phase(
                            Phase::Ready {
                                version: version.to_string(),
                                defer,
                            },
                            "installing stopped at the last moment",
                        );
                    }
                    None => {
                        tracing::error!(%version, "updates: the download did not come back from a stop; retried at the next check");
                        self.next_check = Instant::now() + CHECK_RETRY;
                        self.set_phase(
                            Phase::Blocked {
                                version: version.to_string(),
                            },
                            "the download was lost",
                        );
                    }
                }
            }
            ApplyOutcome::Failed { why, strike } => {
                tracing::error!(%version, strike, "updates: not applied: {why}");
                self.record_strike(&version, strike);
                self.owner_asked = false;
                self.set_phase(
                    Phase::Blocked {
                        version: version.to_string(),
                    },
                    "installing failed",
                );
            }
            ApplyOutcome::Lost(why) => {
                // A start of the new version, if the exe was swapped, is supervised then
                // (`resolve_startup`: an attempt with no watchdog).
                tracing::error!(
                    %version,
                    "updates: the apply task failed: {why}; the downloaded update is dropped"
                );
                self.next_check = Instant::now() + CHECK_RETRY;
                self.owner_asked = false;
                self.set_phase(
                    Phase::Blocked {
                        version: version.to_string(),
                    },
                    "the apply task failed",
                );
            }
        }
    }

    fn record_strike(&mut self, version: &Version, reason: &str) {
        let v = version.to_string();
        let result = apply::update_state(&self.dirs, |s| {
            let strikes = s.record_failure(&v, reason, false, state::now_ms());
            tracing::info!(version = %v, strikes, reason, "updates: failure recorded");
        });
        if let Err(e) = result {
            tracing::warn!("updates: failure not recorded: {e}");
        }
        self.last_blocked = None;
    }
}

/// The status the window gets from the loop (updates are on wherever the loop runs).
fn status_for(current: &Version, auto: bool, session: bool, shared: &Shared) -> UpdateStatusDto {
    super::status_dto(&current.to_string(), None, auto, session, shared)
}

/// Download `found`, telling the window its percent as it goes ([`ProgressGate`]).
async fn download<I: UpdateIo>(
    io: &I,
    shared: &Arc<Mutex<Shared>>,
    current: &Version,
    found: &I::Found,
) -> Result<Downloaded, DownloadError> {
    let mut gate = ProgressGate::default();
    let mut sent = 0u32;
    let mut on_progress = |received: u64, total: Option<u64>| {
        let Some(percent) = gate.offer(received, total, Instant::now()) else {
            return;
        };
        let auto = io.auto_update();
        let session = io.sessions() > 0;
        let dto = {
            let mut s = afklink_core::lock(shared);
            s.progress = Some(percent);
            s.seq += 1;
            status_for(current, auto, session, &s)
        };
        sent += 1;
        tracing::trace!(
            percent,
            received,
            ?total,
            "updates: download progress sent to the window"
        );
        io.publish(&dto);
    };
    let result = io.download(found, &mut on_progress).await;
    tracing::debug!(
        sent,
        ok = result.is_ok(),
        "updates: download over; progress updates sent to the window"
    );
    result
}

fn load_state(dirs: &Dirs) -> state::UpdateState {
    state::load_state(&dirs.updates).unwrap_or_else(|e| {
        tracing::warn!("updates: {e}; taken as empty");
        state::UpdateState::default()
    })
}

/// A download's progress, thinned out for the window: a new whole percent at most every
/// [`PROGRESS_EVERY`], and the first and the last (100 %) always — a fast line does not send an
/// event per chunk, a slow one still moves. Nothing while the size is unknown: the window then says
/// «Загрузка…» without a number.
#[derive(Debug, Default)]
pub(crate) struct ProgressGate {
    /// The last percent let through, and when.
    last: Option<(u8, Instant)>,
}

impl ProgressGate {
    /// The percent to send now, if any.
    pub(crate) fn offer(&mut self, received: u64, total: Option<u64>, now: Instant) -> Option<u8> {
        let total = total.filter(|t| *t > 0)?;
        let percent = u8::try_from(received.min(total).saturating_mul(100) / total).unwrap_or(100);
        let due = match self.last {
            None => true,
            Some((last, _)) if last == percent => false,
            Some(_) if percent == 100 => true,
            Some((_, at)) => now.saturating_duration_since(at) >= PROGRESS_EVERY,
        };
        if due {
            self.last = Some((percent, now));
            Some(percent)
        } else {
            None
        }
    }
}

/// The app's side of [`UpdateIo`]: the server ([`fetch`]), the agent's state, the files, the window.
pub(crate) struct TauriIo<R: Runtime> {
    pub(crate) app: AppHandle<R>,
    pub(crate) control: AgentControl,
    /// `updater.pub`'s key line.
    pub(crate) key: String,
    pub(crate) endpoint: Url,
    /// This build's `User-Agent` (`AFKLink/<version> (<channel>)`), on the check and the download.
    pub(crate) user_agent: String,
    pub(crate) dirs: Dirs,
    pub(crate) current: Version,
    /// The way to the server the signaling socket uses: tried first (`afklink_core::entry`).
    pub(crate) entry: Arc<afklink_core::entry::Entry>,
    /// The way the last manifest came: the exe is fetched that way first.
    pub(crate) manifest_from: Mutex<Option<afklink_core::entry::Endpoint>>,
}

/// The last look before the exe is swapped (`apply::apply`'s `still_clear`): what is in the way now,
/// as the [`Defer`] the window says it by, and why for the log — the PC paused at the last moment
/// a session started, a pairing began. In this order, as [`policy::decide`] reports.
pub(crate) fn last_moment_check(s: &afklink_core::AgentState) -> Result<(), (Defer, String)> {
    if s.paused {
        return Err((Defer::Paused, "connections were paused".to_string()));
    }
    if !s.sessions.is_empty() {
        return Err((Defer::Session, "a session started".to_string()));
    }
    if s.pending_pair.is_some() || s.pairing_panel.kind() != "closed" {
        return Err((Defer::Pairing, "pairing started".to_string()));
    }
    Ok(())
}

/// The addresses of the exe `url` names, the way the manifest came (`from`) first: the manifest's
/// own URL on the primary, the RU entry's when there is one ([`afklink_core::entry::ru_alternative`]).
/// A URL with no RU alternative (an override's test release elsewhere): itself only.
pub(crate) fn exe_order(url: &Url, from: Option<afklink_core::entry::Endpoint>) -> Vec<Url> {
    let Some(ru) =
        afklink_core::entry::ru_alternative(url.as_str()).and_then(|ru| Url::parse(&ru).ok())
    else {
        return vec![url.clone()];
    };
    match from {
        Some(afklink_core::entry::Endpoint::Ru) => vec![ru, url.clone()],
        _ => vec![url.clone(), ru],
    }
}

impl<R: Runtime> UpdateIo for TauriIo<R> {
    type Found = fetch::Release;

    fn found_version(found: &fetch::Release) -> &str {
        &found.version
    }

    fn found_identity(found: &fetch::Release) -> &str {
        found.identity()
    }

    async fn check(&self) -> Result<Answer<fetch::Release>, String> {
        let order = self.entry.http_order(self.endpoint.as_str());
        let mut endpoints: Vec<(afklink_core::entry::Endpoint, Url)> = Vec::new();
        for (way, url) in order {
            match Url::parse(&url) {
                Ok(parsed) => endpoints.push((way, parsed)),
                Err(e) => {
                    tracing::warn!(%url, "update check: an address that is not a URL ({e}); skipped")
                }
            }
        }
        tracing::debug!(
            endpoints = %endpoints
                .iter()
                .map(|(way, url)| format!("{}={url}", way.as_str()))
                .collect::<Vec<_>>()
                .join(" "),
            "update check: asking the server"
        );
        let urls: Vec<Url> = endpoints.iter().map(|(_, url)| url.clone()).collect();
        let (checked, used) = fetch::check_any(
            &self.key,
            &urls,
            &self.current,
            &self.user_agent,
            fetch::LIMITS,
        )
        .await?;
        let way = endpoints.get(used).map(|(way, _)| *way);
        tracing::debug!(
            way = way.map_or("-", |w| w.as_str()),
            "update check: the manifest's way, for the exe"
        );
        *afklink_core::lock(&self.manifest_from) = way;
        Ok(Answer {
            found: checked.update,
            remote: checked.remote,
        })
    }

    async fn download(
        &self,
        found: &fetch::Release,
        progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
    ) -> Result<Downloaded, DownloadError> {
        let from = *afklink_core::lock(&self.manifest_from);
        let urls = exe_order(&found.download_url, from);
        tracing::debug!(
            manifest_from = from.map_or("-", afklink_core::entry::Endpoint::as_str),
            urls = %urls.iter().map(Url::as_str).collect::<Vec<_>>().join(" "),
            "update: the exe's addresses, the manifest's way first"
        );
        fetch::download_any(found, &self.key, &urls, fetch::LIMITS, progress).await
    }

    fn auto_update(&self) -> bool {
        afklink_core::lock(&self.control.config).auto_update
    }

    fn sessions(&self) -> usize {
        afklink_core::lock(&self.control.state).sessions.len()
    }

    fn conditions(&self, owner_asked: bool) -> Conditions {
        let (sessions, pairing, online, paused) = {
            let s = afklink_core::lock(&self.control.state);
            (
                s.sessions.len(),
                s.pending_pair.is_some() || s.pairing_panel.kind() != "closed",
                s.connected || s.refused.as_ref().is_some_and(|r| r.kind() == "outdated"),
                s.paused,
            )
        };
        let in_flight = process::watchdog_alive() || load_state(&self.dirs).attempt.is_some();
        Conditions {
            auto_update: self.auto_update(),
            owner_asked,
            in_flight,
            paused,
            maintenance: crate::fakerinput_setup::maintenance_running(),
            pairing,
            sessions,
            online,
        }
    }

    async fn apply(&self, ready: Downloaded) -> (ApplyOutcome, Option<Downloaded>) {
        let guard = match crate::fakerinput_setup::MaintenanceGuard::acquire() {
            Ok(guard) => guard,
            Err(why) => {
                return (
                    ApplyOutcome::NotNow {
                        defer: Defer::Maintenance,
                        why,
                    },
                    Some(ready),
                )
            }
        };
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                return (
                    ApplyOutcome::Failed {
                        why: format!("this exe's path is unknown ({e}); cannot apply"),
                        strike: "exe_unknown",
                    },
                    Some(ready),
                )
            }
        };
        let hidden = self
            .app
            .get_webview_window("main")
            .and_then(|w| w.is_visible().ok())
            .is_some_and(|visible| !visible);
        let control = self.control.clone();
        let dirs = self.dirs.clone();
        let from = self.current.clone();
        tracing::info!(
            from = %from,
            to = %ready.version,
            exe = %exe.display(),
            hidden,
            "updates: applying"
        );
        // From before the swap until this process exits for the watchdog (or the apply fails): an
        // end of the orchestrator meanwhile is part of the update, not one to relaunch for
        // (`crate::supervise`).
        let applying = super::Applying::begin();
        let joined = tauri::async_runtime::spawn_blocking(move || {
            let _guard = guard;
            let still_clear = || last_moment_check(&afklink_core::lock(&control.state));
            let plan = apply::Plan {
                from: &from,
                to: &ready.version,
                bytes: &ready.bytes,
                sha256: &ready.sha256,
                exe,
                dirs: &dirs,
                hidden,
                timeout: launch::DEFAULT_HEALTH_TIMEOUT,
            };
            let applied = apply::apply(&plan, &still_clear);
            (applied, ready)
        })
        .await;
        match joined {
            Ok((Applied::HandedOver { watchdog_pid }, ready)) => {
                applying.handed_over();
                (ApplyOutcome::HandedOver { watchdog_pid }, Some(ready))
            }
            Ok((Applied::Refused { defer, why }, ready)) => {
                (ApplyOutcome::NotNow { defer, why }, Some(ready))
            }
            Ok((
                Applied::Aborted {
                    reason,
                    before_swap,
                },
                ready,
            )) => (
                ApplyOutcome::Failed {
                    why: reason,
                    strike: if before_swap {
                        "prepare_failed"
                    } else {
                        "swap_failed"
                    },
                },
                Some(ready),
            ),
            Err(e) => (ApplyOutcome::Lost(e.to_string()), None),
        }
    }

    /// Exit so the watchdog can start the new version; end the process outright if the event loop
    /// has not let it go within [`EXIT_FALLBACK`] (the watchdog would end it after 30 s anyway).
    ///
    /// First the goodbye to the backend, `update` — the backend keeps the PC listed a few seconds
    /// for it, so the new version's quick return does not flicker in «Мои ПК» — on a thread of its
    /// own, since this runs on an async task and the goodbye's wait blocks (at most
    /// [`afklink_core::GOODBYE_BUDGET`]); then the exit. The exit's own goodbye finds it said.
    fn exit_for_update(&self) {
        // The next start's `last_exit` (`afklink_core::run_state`): an update's, whichever way this
        // process goes from here — the app's exit that follows finds it recorded and keeps it.
        afklink_core::run_state::record_exit(
            afklink_core::run_state::ExitKind::Update,
            "exiting for the update's watchdog",
        );
        std::thread::spawn(|| {
            std::thread::sleep(EXIT_FALLBACK);
            tracing::warn!(
                "updates: still running {} s after handing over; exiting now",
                EXIT_FALLBACK.as_secs()
            );
            crate::flush_log("update_exit");
            std::process::exit(0);
        });
        let control = self.control.clone();
        let app = self.app.clone();
        let spawned = std::thread::Builder::new()
            .name("afklink-update-goodbye".into())
            .spawn(move || {
                // Every live session ended first (an update waits for none, but one may have come
                // between the decision and now), then the goodbye.
                let outcome = control.leave_blocking(
                    afklink_core::GoodbyeReason::Update,
                    afklink_core::GOODBYE_BUDGET,
                );
                tracing::debug!(outcome = outcome.kind(), "updates: goodbye said; exiting");
                app.exit(0);
            });
        if let Err(e) = spawned {
            tracing::warn!(
                "updates: no thread for the goodbye ({e}); exiting without it (the exit says \
                 «quit» instead)"
            );
            self.app.exit(0);
        }
    }

    fn publish(&self, status: &UpdateStatusDto) {
        match self.app.emit(super::STATUS_EVENT, status) {
            Ok(()) => tracing::trace!(
                state = status.state,
                seq = status.seq,
                "updates: status sent to the window"
            ),
            Err(e) => tracing::debug!("updates: status not sent to the window: {e}"),
        }
    }
}

/// A random delay in [`FIRST_CHECK`], from a fresh UUID's random bits.
fn first_check_delay() -> Duration {
    let (lo, hi) = FIRST_CHECK;
    let random = (uuid::Uuid::new_v4().as_u128() % u128::from(hi - lo + 1)) as u64;
    Duration::from_secs(lo + random)
}

/// This process's part in an update in flight, for [`on_exit`](super::on_exit).
pub(crate) struct Probation {
    pub(crate) dirs: Dirs,
    pub(crate) version: String,
    /// The version the update came from (the attempt's `from`), for `update_finished`; `None` when
    /// `state.json` did not say.
    pub(crate) from: Option<String>,
}

/// Settle what the last run left, report health when on probation, and after a rollback give the
/// verdict on the failed version.
#[allow(clippy::too_many_arguments, reason = "one task, started once")]
pub(crate) async fn watch_health<R: Runtime>(
    app: AppHandle<R>,
    control: AgentControl,
    dirs: Dirs,
    current: Version,
    launch: Launch,
    mut events: broadcast::Receiver<AgentEvent>,
    locale: Locale,
    probation_slot: &'static Mutex<Option<Probation>>,
) {
    let me = current.to_string();
    let settle_dirs = dirs.clone();
    let rolled_back = matches!(launch, Launch::RolledBack { .. });
    let (on_probation, came_from) = match tauri::async_runtime::spawn_blocking(move || {
        settle_startup(&settle_dirs, &me, rolled_back)
    })
    .await
    {
        Ok(settled) => settled,
        Err(e) => {
            tracing::error!("updates: startup settling failed: {e}");
            (false, None)
        }
    };
    if on_probation {
        *afklink_core::lock(probation_slot) = Some(Probation {
            dirs: dirs.clone(),
            version: current.to_string(),
            from: came_from.clone(),
        });
    }
    // Put back by the watchdog: the update is over, rolled back — the strike the watchdog recorded
    // says why, and when (the event's `at`, the same however often this start is repeated).
    if let Launch::RolledBack { from, .. } = &launch {
        let failed = from.to_string();
        let failure = state::load_state(&dirs.updates)
            .map_err(|e| tracing::warn!("updates: {e}; the rollback's reason is unknown"))
            .ok()
            .and_then(|st| st.failures.get(&failed).cloned());
        update_finished(
            &current.to_string(),
            &failed,
            afklink_protocol::metrics::UpdateOutcome::RolledBack,
            failure.as_ref().map(|f| f.reason.as_str()),
            failure.as_ref().map_or_else(
                || OutcomeAt {
                    at: state::now_ms(),
                    source: "now_no_strike_on_disk",
                },
                |f| OutcomeAt {
                    at: f.last_at_ms,
                    source: "state_json_strike",
                },
            ),
            "started by the watchdog after a rollback",
        );
    }
    let mut verifying = match &launch {
        Launch::RolledBack { from, .. } => {
            tracing::warn!(failed = %from, running = %current, "updates: rolled back from {from}; this is the previous version");
            toast(
                &app,
                locale,
                NativeText::NotifyUpdateRolledBack,
                &from.to_string(),
            );
            Some((from.to_string(), Instant::now() + VERIFY_WINDOW))
        }
        _ => None,
    };
    if !on_probation && verifying.is_none() {
        tracing::debug!("updates: no probation and nothing to verify; the health watcher stops");
        return;
    }
    let mut reported = !on_probation;
    // After the report: the heartbeat until this time, the next beat, and whether a missed answer
    // from the window thread has been logged.
    let mut beating_until: Option<Instant> = None;
    let mut next_beat = Instant::now();
    let mut silent_logged = false;
    // Settling may have taken a while (starting a watchdog waits for it): the agent may be connected
    // already, and its event, if the channel overflowed meanwhile, lost — the state says it too.
    let connected_now = || afklink_core::lock(&control.state).connected;
    let mut connected = connected_now();
    loop {
        let now = Instant::now();
        if connected {
            if let Some((failed, _)) = verifying.take() {
                settle_verdict(&dirs, &failed, true);
            }
        }
        if connected && !reported && now >= next_beat {
            // Health is the server reached *and* the window thread answering: a new version whose
            // event loop hangs must not pass for a working one.
            if main_thread_answers(&app).await {
                report_health(&app, &dirs, &current, locale, came_from.as_deref());
                reported = true;
                beating_until = Some(now + BEAT_FOR);
            } else if !silent_logged {
                tracing::warn!("updates: connected on probation, but the window thread does not answer; health not reported yet");
                silent_logged = true;
            }
            next_beat = now + BEAT_EVERY;
        } else if let Some(until) = beating_until {
            if now >= until {
                tracing::debug!("updates: probation heartbeat ends");
                beating_until = None;
                // Past the watchdog's probation: it has decided — and this process still runs, so
                // not a rollback. `state.json` says whether it recorded the success.
                confirmed_after_probation(&dirs, &current, came_from.as_deref());
            } else if now >= next_beat {
                if main_thread_answers(&app).await {
                    beat(&dirs, &current);
                } else if !silent_logged {
                    tracing::warn!("updates: the window thread does not answer on probation; no heartbeat (the watchdog rolls back if it stays so)");
                    silent_logged = true;
                }
                next_beat = now + BEAT_EVERY;
            }
        }
        if reported && verifying.is_none() && beating_until.is_none() {
            tracing::debug!(
                "updates: health reported and nothing to verify; the health watcher stops"
            );
            return;
        }
        let verify_at = verifying.as_ref().map(|(_, at)| *at);
        let beat_at = (beating_until.is_some() || (connected && !reported)).then_some(next_beat);
        let wake = [verify_at, beat_at].into_iter().flatten().min();
        let event = tokio::select! {
            event = events.recv() => Some(event),
            () = sleep_until(wake) => None,
        };
        match event {
            None => {
                if verifying
                    .as_ref()
                    .is_some_and(|(_, at)| Instant::now() >= *at)
                {
                    if let Some((failed, _)) = verifying.take() {
                        settle_verdict(&dirs, &failed, false);
                    }
                }
            }
            Some(Ok(AgentEvent::SignalingConnected { .. })) => connected = true,
            Some(Ok(_)) => {}
            Some(Err(broadcast::error::RecvError::Lagged(missed))) => {
                connected = connected_now();
                tracing::debug!(
                    missed,
                    connected,
                    "updates: health watcher missed agent events; the state decides"
                );
            }
            Some(Err(broadcast::error::RecvError::Closed)) => {
                tracing::debug!("updates: agent events closed; the health watcher stops");
                return;
            }
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

/// Whether the window thread (Tauri's event loop) runs a closure within [`MAIN_THREAD_ANSWER`].
async fn main_thread_answers<R: Runtime>(app: &AppHandle<R>) -> bool {
    let (tx, rx) = tokio::sync::oneshot::channel();
    if let Err(e) = app.run_on_main_thread(move || {
        let _ = tx.send(());
    }) {
        tracing::warn!("updates: the window thread not reached: {e}");
        return false;
    }
    match tokio::time::timeout(MAIN_THREAD_ANSWER, rx).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => {
            tracing::debug!("updates: the window thread dropped the check unanswered");
            false
        }
        Err(_) => {
            tracing::debug!(
                timeout_ms = MAIN_THREAD_ANSWER.as_millis() as u64,
                "updates: the window thread did not answer in time"
            );
            false
        }
    }
}

/// A heartbeat on probation: `health.json` rewritten with a new `beat_at_ms`.
fn beat(dirs: &Dirs, current: &Version) {
    let me = current.to_string();
    let pid = std::process::id();
    let mut health = match state::load_health(&dirs.updates) {
        Ok(Some(h)) if h.is_from(&me, pid) => h,
        other => {
            tracing::warn!(found = ?other, "updates: health.json is not this process's; heartbeat rewrites it");
            state::Health {
                version: me.clone(),
                pid,
                healthy_at_ms: Some(state::now_ms()),
                beat_at_ms: None,
                quit_at_ms: None,
            }
        }
    };
    health.beat_at_ms = Some(state::now_ms());
    match state::save_health(&dirs.updates, &health) {
        Ok(()) => tracing::trace!("updates: heartbeat"),
        Err(e) => tracing::warn!("updates: heartbeat not written: {e}"),
    }
}

/// The heartbeat window after the health report is over: the watchdog's probation ended inside it.
/// The attempt gone from `state.json` (or now another version's) is the watchdog's success:
/// `update_finished confirmed`. Still there, it did not record it (gone?): the next start's settling
/// does (`StartupResolution::Confirmed`).
fn confirmed_after_probation(dirs: &Dirs, current: &Version, from: Option<&str>) {
    let me = current.to_string();
    let st = match state::load_state(&dirs.updates) {
        Ok(st) => st,
        Err(e) => {
            tracing::warn!("updates: {e}; whether the update was confirmed is not known yet");
            return;
        }
    };
    if st.attempt.as_ref().is_some_and(|a| a.to == me) {
        tracing::debug!(
            version = %me,
            "updates: the attempt is still in state.json after the probation; the next start \
             settles it"
        );
        return;
    }
    match from {
        Some(from) => {
            let health = state::load_health(&dirs.updates).unwrap_or_else(|e| {
                tracing::warn!("updates: {e}; the confirmation is dated now");
                None
            });
            update_finished(
                from,
                &me,
                afklink_protocol::metrics::UpdateOutcome::Confirmed,
                None,
                confirmed_at(health.as_ref(), &me),
                "the watchdog confirmed it during this run",
            );
        }
        None => tracing::debug!(
            version = %me,
            "updates: confirmed, but the version it came from is not known; no update_finished"
        ),
    }
}

/// Clean up after a crashed run, and settle an attempt found in `state.json`. Returns whether this
/// process is on probation (must report health), and the version the attempt came from.
fn settle_startup(dirs: &Dirs, me: &str, rolled_back: bool) -> (bool, Option<String>) {
    apply::remove_stale_staging(dirs);
    let exe = std::env::current_exe().ok();
    if let Some(exe) = &exe {
        apply::remove_restore_leftovers(exe);
    }
    let mut st = state::load_state(&dirs.updates).unwrap_or_else(|e| {
        tracing::warn!("updates: {e}; taken as empty");
        state::UpdateState::default()
    });
    let health = state::load_health(&dirs.updates).unwrap_or_else(|e| {
        tracing::warn!("updates: {e}; taken as none");
        None
    });
    let watchdog = process::watchdog_alive();
    let resolution = state::resolve_startup(
        st.attempt.as_ref(),
        me,
        health.as_ref(),
        watchdog,
        rolled_back,
    );
    tracing::info!(
        ?resolution,
        attempt = ?st.attempt.as_ref().map(|a| (&a.from, &a.to)),
        watchdog_alive = watchdog,
        failures = st.failures.len(),
        "updates: startup state"
    );
    let mut on_probation = false;
    let mut changed = false;
    let came_from = st.attempt.as_ref().map(|a| a.from.clone());
    match resolution {
        StartupResolution::Nothing => {}
        StartupResolution::OnProbation { need_watchdog } => {
            on_probation = true;
            if need_watchdog {
                if let (Some(attempt), Some(exe)) = (&st.attempt, &exe) {
                    adopt_watchdog(dirs, attempt, exe, me);
                }
            }
        }
        StartupResolution::Confirmed => {
            tracing::info!(
                version = me,
                "updates: this version proved itself before a restart; update confirmed"
            );
            if let Some(from) = &came_from {
                update_finished(
                    from,
                    me,
                    afklink_protocol::metrics::UpdateOutcome::Confirmed,
                    None,
                    confirmed_at(health.as_ref(), me),
                    "proved itself before a restart (settled at this start)",
                );
            }
            st.succeed(me);
            changed = true;
        }
        StartupResolution::Interrupted => {
            if let Some(a) = st.attempt.take() {
                let now = state::now_ms();
                let strikes = st.record_failure(&a.to, "interrupted", false, now);
                tracing::warn!(to = %a.to, strikes, "updates: an update to {} was interrupted and did not stay; recorded as a failure", a.to);
                update_finished(
                    me,
                    &a.to,
                    afklink_protocol::metrics::UpdateOutcome::RolledBack,
                    Some("interrupted"),
                    // The strike just recorded carries this time: the attempt is gone from the
                    // file with it, so no later start learns this outcome again.
                    OutcomeAt {
                        at: now,
                        source: "state_json_strike",
                    },
                    "interrupted: this, the old version, runs again without a watchdog",
                );
            }
            changed = true;
        }
        StartupResolution::Stale => {
            tracing::info!(attempt = ?st.attempt, "updates: a stale attempt cleared");
            st.attempt = None;
            changed = true;
        }
    }
    if let Ok(current) = Version::parse(me) {
        let pruned = st.prune(&current);
        if !pruned.is_empty() {
            tracing::debug!(
                ?pruned,
                "updates: failure records of versions not newer than this removed"
            );
            changed = true;
        }
    }
    if changed {
        if let Err(e) = state::save_state(&dirs.updates, &st) {
            tracing::warn!("updates: state.json not written: {e}");
        }
    }
    (on_probation, came_from)
}

/// Start a watchdog for this process (the new version, started without one — sign-in after a reboot
/// in the middle of an update), from the backup the attempt names.
fn adopt_watchdog(dirs: &Dirs, attempt: &state::Attempt, exe: &Path, me: &str) {
    let same = std::fs::canonicalize(exe).ok() == std::fs::canonicalize(&attempt.exe).ok();
    if !same {
        tracing::warn!(running = %exe.display(), attempt = %attempt.exe.display(), "updates: this exe is not the one the update replaced; no watchdog, health settles it");
        return;
    }
    match crate::staged_file::sha256_of_file(&attempt.backup) {
        Ok((hash, _)) if hash.eq_ignore_ascii_case(&attempt.backup_sha256) => {}
        other => {
            tracing::warn!(backup = %attempt.backup.display(), seen = ?other, "updates: the backup is not the one recorded; no watchdog, health settles it");
            return;
        }
    }
    let (Ok(expect), Ok(from)) = (Version::parse(me), Version::parse(&attempt.from)) else {
        tracing::warn!(from = %attempt.from, to = me, "updates: the attempt's versions are not SemVer; no watchdog");
        return;
    };
    let args = WatchdogArgs {
        expect,
        from,
        exe: attempt.exe.clone(),
        target: WatchTarget::Adopt {
            pid: std::process::id(),
        },
        timeout: launch::DEFAULT_HEALTH_TIMEOUT,
        hidden: false,
    };
    match apply::start_watchdog(&attempt.backup, &args, &dirs.updates) {
        Ok(pid) => tracing::info!(pid, "updates: a watchdog now supervises this version"),
        Err(e) => tracing::warn!("updates: no watchdog for this version ({e}); health settles it"),
    }
}

/// First connection on probation: tell the watchdog (health.json), tell the owner, and when no
/// watchdog is left to record it, record the success here (and `update_finished`, when `from` — the
/// version the update came from — is known).
fn report_health<R: Runtime>(
    app: &AppHandle<R>,
    dirs: &Dirs,
    current: &Version,
    locale: Locale,
    from: Option<&str>,
) {
    let me = current.to_string();
    let pid = std::process::id();
    let now = state::now_ms();
    let health = state::Health {
        version: me.clone(),
        pid,
        healthy_at_ms: Some(now),
        beat_at_ms: Some(now),
        quit_at_ms: None,
    };
    match state::save_health(&dirs.updates, &health) {
        Ok(()) => {
            tracing::info!(version = %me, pid, "updates: connected to the server on probation; health reported")
        }
        Err(e) => {
            tracing::error!(version = %me, "updates: health NOT reported ({e}); the watchdog will roll back")
        }
    }
    toast(app, locale, NativeText::NotifyUpdated, &me);
    if !process::watchdog_alive() {
        let mut confirmed = false;
        let result = apply::update_state(dirs, |s| {
            if s.attempt.as_ref().is_some_and(|a| a.to == me) {
                s.succeed(&me);
                confirmed = true;
                tracing::info!(version = %me, "updates: no watchdog left; update confirmed here");
            }
        });
        if let Err(e) = result {
            tracing::warn!("updates: confirmation not written: {e}");
        }
        if let (true, Some(from)) = (confirmed, from) {
            update_finished(
                from,
                &me,
                afklink_protocol::metrics::UpdateOutcome::Confirmed,
                None,
                confirmed_at(Some(&health), &me),
                "no watchdog left; confirmed by this version's first connection",
            );
        }
    }
}

/// The restored version's verdict on the failed one.
fn settle_verdict(dirs: &Dirs, failed: &str, reachable: bool) {
    let result = apply::update_state(dirs, |s| {
        let settled = s.settle(failed, reachable, state::now_ms());
        match settled {
            Some(Settled::Confirmed { strikes }) => tracing::info!(
                failed,
                strikes,
                "updates: this version reached the server, so the failed one was at fault; \
                 the failure stands"
            ),
            Some(Settled::Inconclusive { strikes }) => tracing::info!(
                failed,
                strikes,
                window_s = VERIFY_WINDOW.as_secs(),
                "updates: this version could not reach the server either; the failed one is \
                 not blamed and is retried within the hour"
            ),
            None => tracing::debug!(failed, reachable, "updates: nothing to settle"),
        }
    });
    if let Err(e) = result {
        tracing::warn!("updates: verdict not written: {e}");
    }
}

/// A Windows notification, «AFKLink обновлён до 0.1.2» and the like: that one bold line, no
/// «AFKLink» title over it (`crate::toast`; it would name the app three times), no full stop.
fn toast<R: Runtime>(app: &AppHandle<R>, locale: Locale, text: NativeText, version: &str) {
    let lines = text.toast(locale, &[("version", version)]);
    let under = lines.detail.as_deref().unwrap_or("-");
    match crate::toast::show(app, &lines) {
        Ok(()) => tracing::debug!(
            bold = %lines.event,
            under,
            "updates: toast handed to Windows"
        ),
        Err(e) => tracing::warn!(bold = %lines.event, under, "updates: toast not shown: {e}"),
    }
}

/// `health.json` gets `quit` when this process, on probation, exits cleanly.
pub(crate) fn report_quit(p: &Probation) {
    let pid = std::process::id();
    let mut health = match state::load_health(&p.dirs.updates) {
        Ok(Some(h)) if h.is_from(&p.version, pid) => h,
        _ => state::Health {
            version: p.version.clone(),
            pid,
            healthy_at_ms: None,
            beat_at_ms: None,
            quit_at_ms: None,
        },
    };
    health.quit_at_ms = Some(state::now_ms());
    match state::save_health(&p.dirs.updates, &health) {
        Ok(()) => {
            tracing::info!(version = %p.version, healthy = health.healthy_at_ms.is_some(), "updates: clean exit on probation reported");
            // The watchdog's rule: a clean exit after health is the update's success
            // (`watchdog::step`). This process will not see it recorded, so it records it here —
            // in the event queue on disk, sent by the next start.
            if health.healthy_at_ms.is_some() {
                if let Some(from) = &p.from {
                    update_finished(
                        from,
                        &p.version,
                        afklink_protocol::metrics::UpdateOutcome::Confirmed,
                        None,
                        confirmed_at(Some(&health), &p.version),
                        "a clean exit after health on probation: the watchdog confirms it",
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!("updates: clean exit not reported ({e}); the watchdog may roll back")
        }
    }
}

/// `update_finished`: once a process, its `at` the outcome's, the reason a short id.
#[cfg(test)]
mod update_finished_tests {
    use super::*;
    use afklink_protocol::metrics::{AgentEventKind, UpdateOutcome};

    #[test]
    fn an_updates_outcome_is_recorded_once_with_its_reason_as_a_short_id() {
        let queue = crate::test_event_queue();
        update_finished(
            "0.5.0",
            "0.6.0",
            UpdateOutcome::RolledBack,
            Some("no_health"),
            OutcomeAt {
                at: 1_789_600_100_000,
                source: "state_json_strike",
            },
            "a test: the watchdog's rollback",
        );
        // A second way to learn it, in the same process: not a second event.
        update_finished(
            "0.5.0",
            "0.6.0",
            UpdateOutcome::Confirmed,
            None,
            OutcomeAt {
                at: 1_789_600_200_000,
                source: "health_json_healthy_at",
            },
            "a test: never recorded",
        );
        let ours: Vec<_> = queue
            .waiting()
            .into_iter()
            .filter(|e| matches!(e.event, AgentEventKind::UpdateFinished { .. }))
            .collect();
        assert_eq!(ours.len(), 1, "{ours:?}");
        let wire =
            serde_json::to_value(afklink_protocol::AgentToServer::AgentEvent(ours[0].clone()))
                .expect("serialises");
        assert_eq!(
            wire,
            serde_json::json!({
                "type": "agent_event",
                "kind": "update_finished",
                "at": 1_789_600_100_000u64,
                "from": "0.5.0",
                "to": "0.6.0",
                "outcome": "rolled_back",
                "reason": "no_health"
            })
        );
    }

    /// Every way to learn of a confirmation dates it alike — the new version's first health, from
    /// `health.json` — whichever process learns it (its own health report, the end of its
    /// probation, its clean exit, the next start's settling): the same fact, counted once.
    #[test]
    fn a_confirmation_is_dated_by_the_versions_first_health() {
        let health = state::Health {
            version: "0.6.0".into(),
            pid: 4_242,
            healthy_at_ms: Some(1_789_600_150_000),
            beat_at_ms: Some(1_789_600_190_000),
            quit_at_ms: Some(1_789_600_200_000),
        };
        let at = confirmed_at(Some(&health), "0.6.0");
        assert_eq!(
            at,
            OutcomeAt {
                at: 1_789_600_150_000,
                source: "health_json_healthy_at"
            }
        );
        // Another process of the same version (the next start, another pid): the same time.
        let next_start = state::Health {
            pid: 7,
            beat_at_ms: None,
            quit_at_ms: None,
            ..health.clone()
        };
        assert_eq!(confirmed_at(Some(&next_start), "0.6.0"), at);
        // Another version's health, or none, says nothing of this one: now.
        let before = state::now_ms();
        for other in [
            None,
            Some(&state::Health {
                version: "0.5.0".into(),
                ..health.clone()
            }),
            Some(&state::Health {
                healthy_at_ms: None,
                ..health.clone()
            }),
        ] {
            let now = confirmed_at(other, "0.6.0");
            assert_eq!(now.source, "now_no_health_on_disk");
            assert!(now.at >= before);
        }
    }
}

/// The exe's addresses: the way the manifest came first, the other second — only ours have two.
#[cfg(test)]
mod exe_order_tests {
    use super::*;
    use afklink_core::entry::Endpoint;

    #[test]
    fn the_exe_is_fetched_the_way_the_manifest_came_first() {
        let exe = Url::parse("https://api.afklink.app/download/AFKLink-0.6.0.exe").expect("url");
        let ru = "https://api.ru.afklink.app/download/AFKLink-0.6.0.exe";
        let order = |from| {
            exe_order(&exe, from)
                .iter()
                .map(Url::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(order(Some(Endpoint::Primary)), [exe.as_str(), ru]);
        assert_eq!(order(None), [exe.as_str(), ru]);
        assert_eq!(order(Some(Endpoint::Ru)), [ru, exe.as_str()]);
        // A test release elsewhere (the override): only where the manifest says.
        let elsewhere = Url::parse("https://example.test/AFKLink-0.6.0.exe").expect("url");
        assert_eq!(
            exe_order(&elsewhere, Some(Endpoint::Ru)),
            vec![elsewhere.clone()]
        );
    }
}

/// The loop's decisions, driven through a fake [`UpdateIo`]: what the window is told, and when an
/// update is installed.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering::SeqCst};

    /// [`Fake::fail`]'s modes.
    const OK: u8 = 0;
    const REJECTED: u8 = 1;
    const UNCONFIRMED: u8 = 2;
    const TRANSFER: u8 = 3;

    /// A version a fake check found: `.0` the version, `.1` its manifest entry's identity.
    struct FakeFound(String, String);

    struct Fake {
        /// What the checks answer, in turn: `Ok(Some(v))` — `v` is newer (`"0.1.1#b"`: the version
        /// 0.1.1 from another manifest entry, `b`); `Ok(None)` — up to date; `Err` — failed. None
        /// left: up to date.
        answers: Mutex<VecDeque<Result<Option<&'static str>, String>>>,
        checks: AtomicUsize,
        downloads: AtomicUsize,
        /// How every download ends: [`OK`], [`REJECTED`] (bytes that are not the release's),
        /// [`UNCONFIRMED`] (a short body, a check that did not finish), [`TRANSFER`].
        fail: AtomicU8,
        /// What each download reports as it goes: (received, total).
        chunks: Vec<(u64, Option<u64>)>,
        auto: AtomicBool,
        sessions: AtomicUsize,
        /// The kill switch's pause (`AgentState::paused`).
        paused: AtomicBool,
        /// What the next `apply`'s last-moment look finds in the way, once.
        last_moment: Mutex<Option<Defer>>,
        /// The versions handed to `apply`.
        applied: Mutex<Vec<String>>,
        exited: AtomicBool,
        published: Mutex<Vec<UpdateStatusDto>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                answers: Mutex::new(VecDeque::new()),
                checks: AtomicUsize::new(0),
                downloads: AtomicUsize::new(0),
                fail: AtomicU8::new(OK),
                chunks: vec![(512, Some(1024)), (1024, Some(1024))],
                auto: AtomicBool::new(true),
                sessions: AtomicUsize::new(0),
                paused: AtomicBool::new(false),
                last_moment: Mutex::new(None),
                applied: Mutex::new(Vec::new()),
                exited: AtomicBool::new(false),
                published: Mutex::new(Vec::new()),
            }
        }

        fn answer(&self, a: Result<Option<&'static str>, String>) {
            afklink_core::lock(&self.answers).push_back(a);
        }

        fn applied(&self) -> Vec<String> {
            afklink_core::lock(&self.applied).clone()
        }

        /// What the window was told since `from`, as its states.
        fn states_since(&self, from: usize) -> Vec<&'static str> {
            afklink_core::lock(&self.published)[from..]
                .iter()
                .map(|d| d.state)
                .collect()
        }

        fn published(&self) -> usize {
            afklink_core::lock(&self.published).len()
        }
    }

    impl UpdateIo for Fake {
        type Found = FakeFound;

        fn found_version(found: &FakeFound) -> &str {
            &found.0
        }

        fn found_identity(found: &FakeFound) -> &str {
            &found.1
        }

        async fn check(&self) -> Result<Answer<FakeFound>, String> {
            self.checks.fetch_add(1, SeqCst);
            let next = afklink_core::lock(&self.answers).pop_front();
            match next.unwrap_or(Ok(None)) {
                Ok(Some(entry)) => {
                    let v = entry.split_once('#').map_or(entry, |(v, _)| v);
                    Ok(Answer {
                        found: Some(FakeFound(v.to_string(), entry.to_string())),
                        remote: Version::parse(v).ok(),
                    })
                }
                Ok(None) => Ok(Answer {
                    found: None,
                    remote: Some(Version::new(0, 1, 0)),
                }),
                Err(e) => Err(e),
            }
        }

        async fn download(
            &self,
            found: &FakeFound,
            progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
        ) -> Result<Downloaded, DownloadError> {
            self.downloads.fetch_add(1, SeqCst);
            for &(received, total) in &self.chunks {
                progress(received, total);
            }
            match self.fail.load(SeqCst) {
                REJECTED => {
                    return Err(DownloadError::Rejected(
                        "signature: does not verify (the test's)".into(),
                    ))
                }
                UNCONFIRMED => {
                    return Err(DownloadError::Unconfirmed(
                        "the body ended after 512 of the manifest's 1024 bytes (the test's)".into(),
                    ))
                }
                TRANSFER => {
                    return Err(DownloadError::Transfer(
                        "connection reset (the test's)".into(),
                    ))
                }
                _ => {}
            }
            Ok(Downloaded {
                version: Version::parse(&found.0).unwrap(),
                bytes: b"MZ".to_vec(),
                sha256: "AA".into(),
            })
        }

        fn auto_update(&self) -> bool {
            self.auto.load(SeqCst)
        }

        fn sessions(&self) -> usize {
            self.sessions.load(SeqCst)
        }

        fn conditions(&self, owner_asked: bool) -> Conditions {
            Conditions {
                auto_update: self.auto_update(),
                owner_asked,
                in_flight: false,
                paused: self.paused.load(SeqCst),
                maintenance: false,
                pairing: false,
                sessions: self.sessions(),
                online: true,
            }
        }

        async fn apply(&self, ready: Downloaded) -> (ApplyOutcome, Option<Downloaded>) {
            if let Some(defer) = afklink_core::lock(&self.last_moment).take() {
                return (
                    ApplyOutcome::NotNow {
                        defer,
                        why: "the test's last-moment look".into(),
                    },
                    Some(ready),
                );
            }
            afklink_core::lock(&self.applied).push(ready.version.to_string());
            (ApplyOutcome::HandedOver { watchdog_pid: 42 }, Some(ready))
        }

        fn exit_for_update(&self) {
            self.exited.store(true, SeqCst);
        }

        fn publish(&self, status: &UpdateStatusDto) {
            afklink_core::lock(&self.published).push(status.clone());
        }
    }

    fn normal() -> Launch {
        Launch::Normal { hidden: false }
    }

    fn temp_dir() -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("afklink-updater-loop-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A loop of `version` over `dir`, as `launch` started it; the sender keeps its channel open.
    fn updater_in(
        fake: Fake,
        launch: &Launch,
        dir: &Path,
        version: &str,
    ) -> (Updater<Fake>, mpsc::UnboundedSender<Request>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let updater = Updater::new(
            fake,
            Dirs {
                updates: dir.to_path_buf(),
            },
            Version::parse(version).unwrap(),
            launch,
            Arc::new(Mutex::new(Shared::new())),
            rx,
        );
        (updater, tx)
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn phase(u: &Updater<Fake>) -> Phase {
        afklink_core::lock(&u.shared).phase.clone()
    }

    fn ready(defer: Defer) -> Phase {
        Phase::Ready {
            version: "0.1.1".into(),
            defer,
        }
    }

    /// A rejected download is not repeated for the same manifest entry; a corrected entry of the
    /// same version (another signature or hash) and a newer version are downloaded at once; the
    /// owner's «Повторить» downloads the remembered one; no strike is recorded for any of it.
    #[test]
    fn a_rejected_entry_is_not_downloaded_again_until_the_manifest_changes() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.fail.store(REJECTED, SeqCst);
        for entry in ["0.1.1#a", "0.1.1#a", "0.1.1#b", "0.1.2#c", "0.1.2#c"] {
            fake.answer(Ok(Some(entry)));
        }
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        let failed = |v: &str| Phase::DownloadFailed { version: v.into() };

        block_on(u.check(Why::Scheduled));
        assert_eq!(
            u.io.downloads.load(SeqCst),
            1,
            "the first time it is downloaded"
        );
        assert_eq!(phase(&u), failed("0.1.1"));

        block_on(u.check(Why::Owner));
        assert_eq!(u.io.downloads.load(SeqCst), 1, "the same entry: not again");
        assert_eq!(phase(&u), failed("0.1.1"));

        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.downloads.load(SeqCst), 2, "a corrected 0.1.1: tried");

        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.downloads.load(SeqCst), 3, "a newer version: tried");
        assert_eq!(phase(&u), failed("0.1.2"));

        // The server mends the exe behind the same entry: the loop does not know until the
        // owner asks (or the memory's day is over, or the app restarts).
        u.io.fail.store(OK, SeqCst);
        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.downloads.load(SeqCst), 3, "0.1.2#c is remembered");
        assert!(u.io.applied().is_empty());

        block_on(u.on_request(Request::ApplyNow));
        assert_eq!(u.io.downloads.load(SeqCst), 4, "«Повторить» downloads it");
        assert_eq!(u.io.applied(), ["0.1.2"]);
        assert!(u.rejected.is_empty());

        let st = load_state(&Dirs {
            updates: dir.clone(),
        });
        assert!(st.failures.is_empty(), "no strike: {:?}", st.failures);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A transfer failure and an unconfirmed download (a short body, a check that did not finish)
    /// say nothing about the entry's bytes: not remembered, the same entry is downloaded at the next
    /// check; the status and the strikes are as for a rejection (none).
    #[test]
    fn a_transfer_failure_or_an_unconfirmed_download_is_not_remembered() {
        for mode in [TRANSFER, UNCONFIRMED] {
            let dir = temp_dir();
            let fake = Fake::new();
            fake.fail.store(mode, SeqCst);
            fake.answer(Ok(Some("0.1.1#a")));
            fake.answer(Ok(Some("0.1.1#a")));
            let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
            block_on(u.check(Why::Scheduled));
            assert_eq!(
                phase(&u),
                Phase::DownloadFailed {
                    version: "0.1.1".into()
                },
                "mode {mode}"
            );
            assert!(u.rejected.is_empty(), "mode {mode}");
            block_on(u.check(Why::Scheduled));
            assert_eq!(u.io.downloads.load(SeqCst), 2, "mode {mode}: tried again");
            let st = load_state(&Dirs {
                updates: dir.clone(),
            });
            assert!(st.failures.is_empty(), "mode {mode}: no strike");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// In the loop: an entry rejected more than [`REJECTED_FOR`] ago is downloaded again.
    #[test]
    fn a_rejected_entry_is_downloaded_again_once_its_day_is_over() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.fail.store(REJECTED, SeqCst);
        fake.answer(Ok(Some("0.1.1#a")));
        fake.answer(Ok(Some("0.1.1#a")));
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.downloads.load(SeqCst), 1);
        // Its time over: the memory's day shortened to nothing (no Instant a day back is needed,
        // which a PC up for less than a day does not have).
        u.rejected.keep_for = Duration::ZERO;
        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.downloads.load(SeqCst), 2, "past its day: tried again");
        assert_eq!(u.rejected.len(), 1, "and remembered anew");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The memory forgets an entry after [`REJECTED_FOR`] and holds at most [`REJECTED_KEEP`].
    #[test]
    fn rejected_entries_are_forgotten_after_a_day_and_bounded() {
        let t0 = Instant::now();
        let mut r = Rejected::default();
        r.remember("A", t0);
        assert_eq!(
            r.remembers("A", t0 + Duration::from_secs(60)),
            Some(Duration::from_secs(60))
        );
        assert_eq!(r.remembers("B", t0), None);
        assert!(r
            .remembers("A", t0 + REJECTED_FOR - Duration::from_secs(1))
            .is_some());
        assert_eq!(r.remembers("A", t0 + REJECTED_FOR), None);
        assert!(r.is_empty(), "past its time: dropped");

        for i in 0..REJECTED_KEEP + 3 {
            r.remember(&format!("E{i}"), t0);
        }
        assert_eq!(r.len(), REJECTED_KEEP);
        assert_eq!(r.remembers("E0", t0), None, "the oldest went");
        assert!(r
            .remembers(&format!("E{}", REJECTED_KEEP + 2), t0)
            .is_some());
        // Remembered again: counted once, its time renewed.
        r.remember("E5", t0 + Duration::from_secs(10));
        assert_eq!(r.len(), REJECTED_KEEP);
        assert_eq!(
            r.remembers("E5", t0 + Duration::from_secs(10)),
            Some(Duration::ZERO)
        );
        assert_eq!(r.clear(), REJECTED_KEEP);
    }

    #[test]
    fn with_nobody_connected_a_new_version_installs_right_after_the_download() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.answer(Ok(Some("0.1.1")));
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.applied(), ["0.1.1"]);
        assert!(u.io.exited.load(SeqCst));
        assert_eq!(
            phase(&u),
            Phase::Installing {
                version: "0.1.1".into()
            }
        );
        // What the window was told: the check, the download, the install — never «после сеанса» or
        // «позже» with nobody connected.
        let states = u.io.states_since(0);
        assert!(
            !states
                .iter()
                .any(|s| *s == "after_session" || *s == "later"),
            "{states:?}"
        );
        assert_eq!(states.first(), Some(&"checking"), "{states:?}");
        assert!(states.contains(&"downloading"), "{states:?}");
        assert_eq!(states.last(), Some(&"installing"), "{states:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn during_a_session_it_waits_and_installs_the_moment_the_session_ends() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.answer(Ok(Some("0.1.1")));
        fake.sessions.store(1, SeqCst);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(phase(&u), ready(Defer::Session));
        assert_eq!(u.io.states_since(0).last(), Some(&"after_session"));
        // Ticks while it lasts install nothing.
        block_on(u.on_tick());
        block_on(u.on_tick());
        assert!(u.io.applied().is_empty());
        // The next tick after it ends installs it: no pause after a session.
        u.io.sessions.store(0, SeqCst);
        block_on(u.on_tick());
        assert_eq!(u.io.applied(), ["0.1.1"]);
        assert_eq!(
            phase(&u),
            Phase::Installing {
                version: "0.1.1".into()
            }
        );
        assert_eq!(u.io.checks.load(SeqCst), 1, "the ticks did not check again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// While the PC is paused the downloaded update waits — «Установить» included — and says
    /// «позже»; it installs at the first look after the owner resumes.
    #[test]
    fn while_paused_it_waits_and_installs_once_the_owner_resumes() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.answer(Ok(Some("0.1.1")));
        fake.paused.store(true, SeqCst);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(phase(&u), ready(Defer::Paused));
        assert_eq!(u.io.states_since(0).last(), Some(&"later"));
        block_on(u.on_tick());
        block_on(u.on_request(Request::ApplyNow));
        assert!(u.io.applied().is_empty(), "nothing installed while paused");
        assert_eq!(phase(&u), ready(Defer::Paused));
        u.io.paused.store(false, SeqCst);
        block_on(u.on_tick());
        assert_eq!(u.io.applied(), ["0.1.1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The last look before the swap says what is in the way as the window says it: the PC paused
    /// at the last moment is «позже» for the pause, not «после сеанса».
    #[test]
    fn the_last_moment_check_says_what_is_in_the_way() {
        let mut s = afklink_core::AgentState::default();
        assert_eq!(last_moment_check(&s), Ok(()));
        s.pairing_panel = afklink_core::PairingPanel::Open;
        assert_eq!(last_moment_check(&s).map_err(|e| e.0), Err(Defer::Pairing));
        s.sessions.push(afklink_core::SessionInfo {
            session_id: "s1".into(),
            telegram_user_id: 42,
            username: None,
            first_name: None,
            connected: false,
            connected_at: None,
        });
        assert_eq!(last_moment_check(&s).map_err(|e| e.0), Err(Defer::Session));
        s.paused = true;
        assert_eq!(
            last_moment_check(&s).map_err(|e| e.0),
            Err(Defer::Paused),
            "the pause first, as decide() orders it"
        );
    }

    /// A pause the last-moment look found (after the decision let the update go) is what the window
    /// is told, and the update waits; it installs once nothing is in the way.
    #[test]
    fn a_last_moment_pause_is_shown_as_the_pause() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.answer(Ok(Some("0.1.1")));
        *afklink_core::lock(&fake.last_moment) = Some(Defer::Paused);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(phase(&u), ready(Defer::Paused));
        assert_eq!(u.io.states_since(0).last(), Some(&"later"));
        assert!(u.io.applied().is_empty());
        block_on(u.on_tick());
        assert_eq!(u.io.applied(), ["0.1.1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_with_an_update_downloaded_does_not_check_again_nor_flip_the_status() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.answer(Ok(Some("0.1.1")));
        fake.sessions.store(1, SeqCst);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(phase(&u), ready(Defer::Session));
        let before = u.io.published();
        block_on(u.on_request(Request::Check));
        assert_eq!(u.io.checks.load(SeqCst), 1, "no second check");
        assert_eq!(phase(&u), ready(Defer::Session));
        // No «Проверка…», no «Установится позже» on the way back: nothing new at all.
        let states = u.io.states_since(before);
        assert!(states.iter().all(|s| *s == "after_session"), "{states:?}");
        // With the session over, «Проверить» is what installs it, at once.
        u.io.sessions.store(0, SeqCst);
        block_on(u.on_request(Request::Check));
        assert_eq!(u.io.checks.load(SeqCst), 1);
        assert_eq!(u.io.applied(), ["0.1.1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scheduled_check_leaves_a_waiting_update_on_screen_even_when_it_fails() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.answer(Ok(Some("0.1.1")));
        fake.answer(Err("offline".into()));
        fake.answer(Ok(Some("0.1.1")));
        fake.sessions.store(1, SeqCst);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        let before = u.io.published();
        block_on(u.check(Why::Scheduled));
        block_on(u.check(Why::Scheduled));
        assert_eq!(u.io.checks.load(SeqCst), 3);
        assert_eq!(u.io.downloads.load(SeqCst), 1, "downloaded once");
        assert_eq!(phase(&u), ready(Defer::Session));
        let states = u.io.states_since(before);
        assert!(states.iter().all(|s| *s == "after_session"), "{states:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_owners_check_says_checking_a_scheduled_one_over_up_to_date_does_not() {
        let dir = temp_dir();
        let (mut u, _tx) = updater_in(Fake::new(), &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(phase(&u), Phase::UpToDate);
        let before = u.io.published();
        block_on(u.check(Why::Scheduled));
        // Only the new check time, under the same «Последняя версия».
        assert_eq!(u.io.states_since(before), ["up_to_date"]);
        let before = u.io.published();
        block_on(u.on_request(Request::Check));
        assert_eq!(u.io.states_since(before), ["checking", "up_to_date"]);
        // A failed check after «Последняя версия» says so, with «Повторить».
        u.io.answer(Err("offline".into()));
        block_on(u.check(Why::Scheduled));
        assert_eq!(phase(&u), Phase::CheckFailed);
        let last = afklink_core::lock(&u.io.published).last().cloned().unwrap();
        assert_eq!(
            (last.state, last.action),
            ("check_failed", Some("retry_check"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn with_automatic_updates_off_it_offers_install_and_installs_when_pressed() {
        let dir = temp_dir();
        let fake = Fake::new();
        fake.auto.store(false, SeqCst);
        fake.answer(Ok(Some("0.1.1")));
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        assert_eq!(
            phase(&u),
            Phase::Available {
                version: "0.1.1".into()
            }
        );
        assert_eq!(u.io.downloads.load(SeqCst), 0);
        let last = afklink_core::lock(&u.io.published).last().cloned().unwrap();
        assert_eq!((last.state, last.action), ("available", Some("install")));
        block_on(u.on_request(Request::ApplyNow));
        assert_eq!(u.io.downloads.load(SeqCst), 1);
        assert_eq!(u.io.applied(), ["0.1.1"]);
        assert_eq!(
            u.io.checks.load(SeqCst),
            1,
            "the version found is downloaded, not checked again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_last_check_is_kept_and_shown_at_the_next_start_of_that_version() {
        let dir = temp_dir();
        let (mut u, _tx) = updater_in(Fake::new(), &normal(), &dir, "0.1.0");
        assert_eq!(phase(&u), Phase::Idle, "nothing checked before");
        block_on(u.check(Why::Scheduled));
        let at = afklink_core::lock(&u.shared).checked_at_ms.unwrap();
        let kept = state::load_check(&dir).unwrap().unwrap();
        assert_eq!(kept.at_ms, at);
        assert!(kept.says_up_to_date("0.1.0"));
        let told = afklink_core::lock(&u.io.published).last().cloned().unwrap();
        assert_eq!((told.state, told.checked_at_ms), ("up_to_date", Some(at)));

        // The next start of 0.1.0: «Последняя версия · проверено в …» before its own first check.
        let (again, _tx) = updater_in(Fake::new(), &normal(), &dir, "0.1.0");
        let s = afklink_core::lock(&again.shared).clone();
        assert_eq!(
            (s.phase, s.checked_at_ms, s.updated),
            (Phase::UpToDate, Some(at), false)
        );

        // The run right after an update to 0.1.1: «Обновлено до 0.1.1», not 0.1.0's answer.
        let after = Launch::AfterUpdate {
            old_pid: 7,
            hidden: false,
        };
        let (updated, _tx) = updater_in(Fake::new(), &after, &dir, "0.1.1");
        let s = afklink_core::lock(&updated.shared).clone();
        assert_eq!(
            (s.phase, s.checked_at_ms, s.updated),
            (Phase::Idle, None, true)
        );
        // …whose first scheduled check does not cover that with «Проверка…».
        let mut updated = updated;
        block_on(updated.check(Why::Scheduled));
        assert_eq!(updated.io.states_since(0), ["up_to_date"]);
        let told = afklink_core::lock(&updated.io.published)
            .last()
            .cloned()
            .unwrap();
        assert!(told.updated && told.checked_at_ms.is_some());

        // Another version on an ordinary start: nothing until its own check.
        let (other, _tx) = updater_in(Fake::new(), &normal(), &dir, "0.1.2");
        assert_eq!(phase(&other), Phase::Idle);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_download_progress_reaches_the_window_thinned_out_and_in_order() {
        let dir = temp_dir();
        let mut fake = Fake::new();
        // A thousand chunks of a megabyte-sized download.
        let total = 1_000_000u64;
        fake.chunks = (1..=1000u64).map(|i| (i * 1000, Some(total))).collect();
        fake.answer(Ok(Some("0.1.1")));
        fake.sessions.store(1, SeqCst);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        let published = afklink_core::lock(&u.io.published).clone();
        let percents: Vec<u8> = published
            .iter()
            .filter(|d| d.state == "downloading")
            .filter_map(|d| d.progress)
            .collect();
        assert_eq!(percents.first(), Some(&0), "{percents:?}");
        assert_eq!(percents.last(), Some(&100), "{percents:?}");
        assert!(percents.windows(2).all(|w| w[0] < w[1]), "{percents:?}");
        assert!(percents.len() < 1000 / 5, "thinned out: {}", percents.len());
        // Every status carries a larger number than the one before: the window can order them.
        assert!(published.windows(2).all(|w| w[0].seq < w[1].seq));
        // The percent goes with the download: the status after it has none.
        assert_eq!(
            published.last().map(|d| (d.state, d.progress)),
            Some(("after_session", None))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_download_of_unknown_size_says_downloading_without_a_number() {
        let dir = temp_dir();
        let mut fake = Fake::new();
        fake.chunks = vec![(1000, None), (2000, None)];
        fake.answer(Ok(Some("0.1.1")));
        fake.sessions.store(1, SeqCst);
        let (mut u, _tx) = updater_in(fake, &normal(), &dir, "0.1.0");
        block_on(u.check(Why::Scheduled));
        let published = afklink_core::lock(&u.io.published).clone();
        let downloading: Vec<_> = published
            .iter()
            .filter(|d| d.state == "downloading")
            .collect();
        assert_eq!(downloading.len(), 1);
        assert_eq!(downloading[0].progress, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_progress_gate_lets_a_new_percent_through_every_100_ms_and_the_last_always() {
        let t0 = Instant::now();
        let ms = |n: u64| t0 + Duration::from_millis(n);
        let mut g = ProgressGate::default();
        assert_eq!(g.offer(0, None, t0), None, "no size, no percent");
        assert_eq!(g.offer(10, Some(1000), t0), Some(1), "the first");
        assert_eq!(g.offer(20, Some(1000), ms(10)), None, "too soon");
        assert_eq!(g.offer(30, Some(1000), ms(100)), Some(3));
        assert_eq!(g.offer(35, Some(1000), ms(300)), None, "the same percent");
        assert_eq!(
            g.offer(1000, Some(1000), ms(301)),
            Some(100),
            "the last, however soon"
        );
        assert_eq!(g.offer(1000, Some(1000), ms(900)), None, "once");
        // More than announced still reads as done, not past it.
        let mut g = ProgressGate::default();
        assert_eq!(g.offer(2000, Some(1000), t0), Some(100));
    }
}
