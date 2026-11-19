//! The PC's input on another Windows desktop — a UAC prompt, the lock screen — watched, measured
//! and told: the viewer through the heartbeat, the server through `secure_desktop_ongoing` and the
//! `agent_event` `secure_desktop_ended` (`afklink_protocol::secure_desktop`, the contract's
//! `secure-desktop.ts`).
//!
//! While Windows shows a secure desktop the capture sees only the ordinary one: no frame comes and
//! the viewer's picture stays on the last one. Input does not reach the PC either — the injector
//! refuses a desktop it cannot open on purpose (`afklink_input`), so a guest can never answer
//! someone else's UAC prompt. This module changes neither; it only observes and reports.
//!
//! # One observation, one decision point
//!
//! One watcher per process ([`start`]), whatever the mode («Только игра» or not), on a thread of its
//! own. Every [`POLL_EVERY`] it makes the cheap look ([`Probe::desktop`]): does the input desktop
//! open, and is it named `Default`? That is the ordinary desktop, and all an episode's end needs; on
//! it nothing more runs. Otherwise the input is on a secure desktop, and its kind comes from
//! [`classify`] over [`Probe::facts`] — on leaving the ordinary desktop at once, then at most every
//! [`RECLASSIFY_EVERY`] while it lasts:
//!
//! - `uac` — `consent.exe` runs in our Windows session;
//! - `lock` — else our session's lock flag (`WTSSessionInfoEx`) says locked;
//! - `other` — else: Ctrl+Alt+Del, signing out, restarting, changing the password (LogonUI on the
//!   Winlogon desktop with the session not locked), another program's desktop, and a lock state
//!   Windows would not tell.
//!
//! Everything else here follows from these observations through [`Tracker`], which is pure: it is
//! given the clock and the observations, and it decides.
//!
//! # Episodes
//!
//! An episode runs from leaving the ordinary desktop until coming back to it, as the contract has
//! it, and the agent measures it on its monotonic clock. The first look that finds the ordinary
//! desktop again ends it at that moment. Two episodes back to back (an installer that asks for
//! administrator rights twice, the lock screen giving way to the desktop for a moment) are two
//! rows; the analytics may join them by `at` and `duration_ms`.
//!
//! - **Kinds.** One episode whatever kinds it goes through (lock → other, other → uac). The heartbeat
//!   says the current kind; the finished episode's event says the most telling one it saw
//!   (`uac` > `lock` > `other`): a UAC prompt over the lock screen is a prompt somebody had to answer.
//! - **Heartbeat.** `secure_desktop` is the current kind while the input is on a secure desktop and
//!   absent otherwise.
//! - **`session_id`.** A session live during the episode: one live when it started, else the first
//!   seen live during it. None when no session was live at any moment of it. The orchestrator tells
//!   the live sessions ([`SecureDesktop::sync_sessions`]) at the top of each turn of its loop.
//! - **`game_only`.** «Только игра» as config.json had it when the episode started.
//! - **`secure_desktop_ongoing`.** Once per episode, when it has lasted
//!   [`SECURE_DESKTOP_ONGOING_AFTER_MS`] from its start, with a session live then; a session that
//!   begins during an older episode that has not sent one gets it at once. The orchestrator's loop
//!   turns at least every half second (its pairing tick), so the cue goes within that of falling
//!   due. Sent only on a connection whose `agent_ready` said `secure_desktop`; counted as sent only
//!   once handed to such a connection, so one that was due while no connection was up goes on the
//!   next, if the episode and a session are still there. Never held for another connection.
//! - **`secure_desktop_ended`.** Recorded into the agent's event queue (`crate::agent_events`) when
//!   the episode ends, in a session or not; the queue's delivery and the server's dedup do the
//!   rest. `at` the episode's start (Unix ms on the PC's clock), `duration_ms` capped at
//!   [`SECURE_DESKTOP_DURATION_MAX_MS`]. The queue sends it only to a server that takes it and drops
//!   it on one that does not (`EventQueue::due`), so an older server never sees it; a full queue
//!   lets the oldest of these go before any other kind.
//! - **The agent exiting** cuts an episode, and it is recorded all the same with its duration so
//!   far, and said at info ([`process_exiting`], from `crate::run_state::record_exit`): a PC left
//!   locked overnight and restarted by Windows Update still counts. An exit Windows takes back (a
//!   cancelled logoff, `crate::run_state::take_back_exit`) resumes the watch from a fresh start; a
//!   secure desktop still up then is a new episode.
//!
//! # Threads and locks
//!
//! The watcher thread makes the Windows calls with no lock held, then takes the tracker's mutex for
//! the pure step only. The orchestrator takes the same mutex for [`SecureDesktop::sync_sessions`],
//! and an exit for [`process_exiting`]. The mutex is a leaf: nothing else is locked while it is held,
//! and nothing waits under it. The event queue's write (file I/O) happens after the mutex is let go —
//! on the watcher thread, or on the exiting thread for an episode an exit cuts; «Только игра» is
//! read from the config (its own mutex) before it is taken. The current kind is published on a
//! `tokio::sync::watch` channel, which the heartbeat tasks and the encode thread read without
//! touching the mutex. A Windows call that never returns stops only the watcher: the last published
//! kind stands, and nothing else waits for it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use afklink_protocol::metrics::AgentEventKind;
use afklink_protocol::{
    SecureDesktopKind, SECURE_DESKTOP_DURATION_MAX_MS, SECURE_DESKTOP_ONGOING_AFTER_MS,
};
use tokio::sync::watch;

use crate::sync::lock;

#[cfg(windows)]
mod win;

/// How often the watcher makes the cheap look.
pub const POLL_EVERY: Duration = Duration::from_millis(250);

/// While the input stays on a secure desktop, its kind is told again from the processes and the
/// session at most this often; between those looks the last kind stands.
pub const RECLASSIFY_EVERY: Duration = Duration::from_secs(2);

/// [`SECURE_DESKTOP_ONGOING_AFTER_MS`] as a duration.
pub const ONGOING_AFTER: Duration = Duration::from_millis(SECURE_DESKTOP_ONGOING_AFTER_MS);

/* --- the pure part ---------------------------------------------------------------------------- */

/// What the processes and the session say, on a secure desktop ([`Probe::facts`]); `None`: the call
/// that would tell failed (or Windows does not know).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Our Windows session, for the log.
    pub session: u32,
    /// `consent.exe` runs in our session.
    pub consent: Option<bool>,
    /// Our session is locked (`WTSSessionInfoEx`'s flag).
    pub locked: Option<bool>,
    /// Windows calls that failed: (call, error). Each said at warn once a process.
    pub failures: Vec<(&'static str, String)>,
}

/// The secure desktop's kind from `facts`, and what decided it (module doc).
pub fn classify(facts: &Facts) -> (SecureDesktopKind, String) {
    let s = facts.session;
    match (facts.consent, facts.locked) {
        (Some(true), _) => (
            SecureDesktopKind::Uac,
            format!("consent.exe in session {s}"),
        ),
        (_, Some(true)) => (SecureDesktopKind::Lock, format!("session {s} locked")),
        (_, Some(false)) => (
            SecureDesktopKind::Other,
            format!("session {s} not locked, no consent.exe in it"),
        ),
        (_, None) => (
            SecureDesktopKind::Other,
            format!("session {s}'s lock state not known, no consent.exe seen"),
        ),
    }
}

/// Whether the kind is to be told from the processes again at `now`: on leaving the ordinary
/// desktop (`shown` — the heartbeat says no kind yet — false), and every [`RECLASSIFY_EVERY`].
pub fn needs_facts(last: Option<Instant>, now: Instant, shown: bool) -> bool {
    !shown || last.is_none_or(|at| now.saturating_duration_since(at) >= RECLASSIFY_EVERY)
}

/// `uac` > `lock` > `other`: the one the finished episode says.
fn rank(k: SecureDesktopKind) -> u8 {
    match k {
        SecureDesktopKind::Uac => 2,
        SecureDesktopKind::Lock => 1,
        SecureDesktopKind::Other => 0,
    }
}

/// One episode, from leaving the ordinary desktop.
#[derive(Debug, Clone)]
struct Episode {
    started: Instant,
    /// The start, Unix ms on the PC's clock: the event's `at` and the cue's.
    started_ms: u64,
    current: SecureDesktopKind,
    /// The most telling kind seen ([`rank`]).
    most: SecureDesktopKind,
    /// The session it is told with (module doc, `session_id`).
    session: Option<String>,
    game_only: bool,
    /// `secure_desktop_ongoing` went for this episode.
    ongoing_sent: bool,
}

/// A finished episode, as `secure_desktop_ended` tells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// The start, Unix ms on the PC's clock.
    pub at_ms: u64,
    /// The most telling kind the episode saw.
    pub desktop: SecureDesktopKind,
    /// At most [`SECURE_DESKTOP_DURATION_MAX_MS`].
    pub duration_ms: u64,
    pub session_id: Option<String>,
    pub game_only: bool,
}

impl Finished {
    /// The `agent_event`'s kind and props.
    pub fn event(&self) -> AgentEventKind {
        AgentEventKind::SecureDesktopEnded {
            desktop: self.desktop,
            duration_ms: self.duration_ms,
            session_id: self.session_id.clone(),
            game_only: Some(self.game_only),
        }
    }
}

/// A `secure_desktop_ongoing` to send now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OngoingCue {
    pub session_id: String,
    pub desktop: SecureDesktopKind,
    /// The episode's start, Unix ms on the PC's clock.
    pub at: u64,
    /// How long the episode has lasted, for the log.
    pub age_ms: u64,
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The episodes, from the observations and the live sessions; pure (module doc).
#[derive(Debug, Default)]
pub struct Tracker {
    episode: Option<Episode>,
    /// The live sessions as last told.
    live: Vec<String>,
    /// The process is exiting: nothing more is observed.
    exiting: bool,
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// The kind the heartbeat says now: the input on a secure desktop, `None` otherwise.
    pub fn current(&self) -> Option<SecureDesktopKind> {
        self.episode.as_ref().map(|e| e.current)
    }

    /// One observation at `now` (`now_ms` on the PC's clock): `obs` the secure desktop's kind, or
    /// `None` for the ordinary desktop; `game_only` «Только игра» now, kept only by a start. The
    /// episode that ended, if one did.
    pub fn observe(
        &mut self,
        now: Instant,
        now_ms: u64,
        obs: Option<SecureDesktopKind>,
        game_only: bool,
    ) -> Option<Finished> {
        if self.exiting {
            return None;
        }
        match (self.episode.as_mut(), obs) {
            (None, None) => None,
            (None, Some(kind)) => {
                let session = self.live.first().cloned();
                tracing::info!(
                    kind = kind.as_str(),
                    session_live = session.is_some(),
                    session = session.as_deref().unwrap_or("-"),
                    game_only,
                    "secure desktop episode started: the PC's input is on a Windows secure desktop \
                     (a UAC prompt, the lock screen or another); the picture stays on its last \
                     frame and input does not reach the PC until it is back"
                );
                self.episode = Some(Episode {
                    started: now,
                    started_ms: now_ms,
                    current: kind,
                    most: kind,
                    session,
                    game_only,
                    ongoing_sent: false,
                });
                None
            }
            (Some(e), Some(kind)) => {
                if kind != e.current {
                    tracing::debug!(
                        from = e.current.as_str(),
                        to = kind.as_str(),
                        for_ms = ms(now.saturating_duration_since(e.started)),
                        "secure desktop: the input moved to another secure desktop; the same \
                         episode goes on"
                    );
                    e.current = kind;
                    if rank(kind) > rank(e.most) {
                        e.most = kind;
                    }
                }
                None
            }
            (Some(_), None) => self
                .episode
                .take()
                .map(|e| finish(e, now, "ended: the input is back on the ordinary desktop")),
        }
    }

    /// The live sessions now (`live`, in any order) and the cue due at `now`; `capable`: the
    /// connection served now takes it (`agent_ready.secure_desktop`). The cue is marked sent only
    /// when returned.
    pub fn sessions(&mut self, live: &[&str], now: Instant, capable: bool) -> Option<OngoingCue> {
        self.live = live.iter().map(|s| (*s).to_string()).collect();
        let e = self.episode.as_mut()?;
        let first = self.live.first()?;
        if e.session.is_none() {
            tracing::debug!(
                session = %first,
                for_ms = ms(now.saturating_duration_since(e.started)),
                "secure desktop: a session became live during the episode; the episode is told \
                 with it"
            );
            e.session = Some(first.clone());
        }
        if e.ongoing_sent || !capable || now < e.started + ONGOING_AFTER {
            return None;
        }
        e.ongoing_sent = true;
        Some(OngoingCue {
            session_id: first.clone(),
            desktop: e.current,
            at: e.started_ms,
            age_ms: ms(now.saturating_duration_since(e.started)),
        })
    }

    /// The process is exiting at `now` (`why`): an episode that runs ends here and is returned.
    /// Nothing more is observed until [`Self::exit_taken_back`].
    pub fn exiting(&mut self, now: Instant, why: &str) -> Option<Finished> {
        if std::mem::replace(&mut self.exiting, true) {
            return None;
        }
        let e = self.episode.take()?;
        tracing::info!(why, "secure desktop: the agent exits during an episode");
        Some(finish(e, now, "cut by the agent exiting"))
    }

    /// The exit was taken back (Windows cancelled the end of its session): observing again, from
    /// a fresh start — a secure desktop still up begins a new episode at the next look.
    pub fn exit_taken_back(&mut self, why: &str) {
        if std::mem::replace(&mut self.exiting, false) {
            tracing::info!(
                why,
                "secure desktop watch: the exit was taken back; observing again"
            );
        }
    }
}

/// The episode `e` ends at `end` (`how`, for the log).
fn finish(e: Episode, end: Instant, how: &str) -> Finished {
    let lasted = ms(end.saturating_duration_since(e.started));
    let duration_ms = lasted.min(SECURE_DESKTOP_DURATION_MAX_MS);
    tracing::info!(
        kind = e.most.as_str(),
        last_kind = e.current.as_str(),
        duration_ms = lasted,
        capped = lasted > duration_ms,
        session_live = e.session.is_some(),
        session = e.session.as_deref().unwrap_or("-"),
        owner_cue = e.ongoing_sent,
        game_only = e.game_only,
        "secure desktop episode {how}; reported to the server as secure_desktop_ended"
    );
    Finished {
        at_ms: e.started_ms,
        desktop: e.most,
        duration_ms,
        session_id: e.session,
        game_only: e.game_only,
    }
}

/* --- the shared part -------------------------------------------------------------------------- */

/// «Только игра» now, for an episode's start.
type GameOnly = Box<dyn Fn() -> bool + Send + Sync>;

/// The process's secure-desktop state: the tracker behind its leaf mutex and the current kind on a
/// watch channel (module doc, «Threads and locks»).
pub struct SecureDesktop {
    tracker: Mutex<Tracker>,
    kind: watch::Sender<Option<SecureDesktopKind>>,
    game_only: GameOnly,
    stop: AtomicBool,
}

impl std::fmt::Debug for SecureDesktop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureDesktop")
            .field("current", &*self.kind.borrow())
            .finish_non_exhaustive()
    }
}

/// Record a finished episode into the event queue; whatever happened is said.
fn record(f: &Finished) {
    match crate::agent_events::record_at(f.at_ms, f.event()) {
        Some(crate::agent_events::Recorded::Queued { .. }) | None => {}
        Some(other) => tracing::debug!(
            outcome = ?other,
            "secure desktop: the finished episode's event was not queued"
        ),
    }
}

impl SecureDesktop {
    /// State with no watcher yet ([`start`] adds one; tests observe by hand).
    pub fn new(game_only: impl Fn() -> bool + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            tracker: Mutex::new(Tracker::new()),
            kind: watch::channel(None).0,
            game_only: Box::new(game_only),
            stop: AtomicBool::new(false),
        })
    }

    /// The current kind, for a heartbeat task or the encode thread.
    pub fn view(&self) -> View {
        View(self.kind.subscribe())
    }

    /// One observation, as the watcher makes it: the step under the mutex, then the kind published
    /// and a finished episode recorded into the event queue — after the mutex is let go.
    pub fn observe(
        &self,
        now: Instant,
        now_ms: u64,
        obs: Option<SecureDesktopKind>,
    ) -> Option<Finished> {
        // Read before the mutex is taken (the config has its own); only a start keeps it.
        let starting = obs.is_some() && self.current().is_none();
        let game_only = starting && (self.game_only)();
        let (ended, current) = {
            let mut t = lock(&self.tracker);
            let ended = t.observe(now, now_ms, obs, game_only);
            (ended, t.current())
        };
        self.kind.send_if_modified(|k| {
            let differs = *k != current;
            *k = current;
            differs
        });
        if let Some(f) = &ended {
            record(f);
        }
        ended
    }

    /// The orchestrator's turn: the live sessions and the cue due, `capable` the connection served
    /// now takes it.
    pub fn sync_sessions(&self, live: &[&str], now: Instant, capable: bool) -> Option<OngoingCue> {
        lock(&self.tracker).sessions(live, now, capable)
    }

    /// The current kind, read off the watch channel (no mutex).
    pub fn current(&self) -> Option<SecureDesktopKind> {
        *self.kind.borrow()
    }

    /// The process is exiting: an episode that runs ends here and is recorded, on this thread,
    /// after the mutex is let go. The watcher thread goes on looking (the exit may be taken back)
    /// but changes nothing until then.
    pub fn exiting(&self, why: &str) -> Option<Finished> {
        let cut = lock(&self.tracker).exiting(Instant::now(), why);
        self.kind.send_replace(None);
        if let Some(f) = &cut {
            record(f);
        }
        cut
    }

    /// The exit was taken back: observing again.
    pub fn exit_taken_back(&self, why: &str) {
        lock(&self.tracker).exit_taken_back(why);
    }

    /// Stop the watcher thread at its next look (tests; a process's watcher lives as long as the
    /// process).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// The current kind, as the heartbeat and the encode thread read it.
#[derive(Debug, Clone)]
pub struct View(watch::Receiver<Option<SecureDesktopKind>>);

impl View {
    /// A view that always says the ordinary desktop: no watcher in this process (tests, the bench).
    pub fn detached() -> Self {
        static DETACHED: OnceLock<watch::Sender<Option<SecureDesktopKind>>> = OnceLock::new();
        Self(DETACHED.get_or_init(|| watch::channel(None).0).subscribe())
    }

    /// The kind now.
    pub fn current(&self) -> Option<SecureDesktopKind> {
        *self.0.borrow()
    }

    /// The kind now, marking it seen for [`Self::changed`].
    pub fn take(&mut self) -> Option<SecureDesktopKind> {
        *self.0.borrow_and_update()
    }

    /// Resolves when the kind changes since the last [`Self::take`]; never, once the state is gone.
    pub async fn changed(&mut self) {
        if self.0.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// The state this process watches with ([`start`]).
static INSTALLED: OnceLock<Arc<SecureDesktop>> = OnceLock::new();

/// The installed state.
pub fn installed() -> Option<&'static Arc<SecureDesktop>> {
    INSTALLED.get()
}

/// The current kind's view: the installed watcher's, or one that always says the ordinary desktop.
pub fn view() -> View {
    INSTALLED.get().map_or_else(View::detached, |s| s.view())
}

/// The process is exiting (`why`): an episode that runs is recorded and said once.
pub fn process_exiting(why: &str) {
    if let Some(s) = INSTALLED.get() {
        s.exiting(why);
    }
}

/// The exit was taken back (`why`): the watch observes again.
pub fn process_exit_taken_back(why: &str) {
    if let Some(s) = INSTALLED.get() {
        s.exit_taken_back(why);
    }
}

/// What the cheap look found ([`Probe::desktop`]).
#[derive(Debug, Clone, Default)]
pub struct Look {
    /// The input desktop opens and is named `Default`.
    pub default: bool,
    /// How it showed, for the log (the desktop's name, or that it does not open).
    pub why: String,
    /// Windows calls that failed: (call, error). Each said at warn once a process.
    pub failures: Vec<(&'static str, String)>,
}

/// The watcher's two looks. The Windows one is `win::WinProbe`.
pub trait Probe: Send {
    /// Which desktop has the input: cheap, every [`POLL_EVERY`].
    fn desktop(&mut self) -> Look;
    /// The processes and the session, for [`classify`]: only on a secure desktop.
    fn facts(&mut self) -> Facts;
}

/// Start the process's watcher and install its state: «Только игра» read through `game_only` at an
/// episode's start. `None` where there is nothing to watch: not Windows, Windows' session 0 (a
/// service or an SSH login, with no desktop of a person), or a thread that would not start.
pub fn start(game_only: impl Fn() -> bool + Send + Sync + 'static) -> Option<Arc<SecureDesktop>> {
    #[cfg(windows)]
    {
        let probe = match win::WinProbe::new() {
            Ok(p) => p,
            Err(why) => {
                tracing::info!("secure desktop watch not started: {why}");
                return None;
            }
        };
        spawn(SecureDesktop::new(game_only), Box::new(probe))
    }
    #[cfg(not(windows))]
    {
        let _ = game_only;
        tracing::debug!("secure desktop watch not started: not Windows");
        None
    }
}

/// Run `probe` for `state` on a thread of its own, a look every `every`.
fn run(
    state: &Arc<SecureDesktop>,
    probe: Box<dyn Probe>,
    every: Duration,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    let watched = Arc::clone(state);
    std::thread::Builder::new()
        .name("secure-desktop".into())
        .spawn(move || watch_loop(&watched, probe, every))
}

/// Run `probe` for `state` on a thread of its own and install `state`.
pub fn spawn(state: Arc<SecureDesktop>, probe: Box<dyn Probe>) -> Option<Arc<SecureDesktop>> {
    match run(&state, probe, POLL_EVERY) {
        Ok(_) => {
            if INSTALLED.set(Arc::clone(&state)).is_err() {
                tracing::warn!("secure desktop: a watcher was installed already; that one stays");
            }
            tracing::info!(
                every_ms = ms(POLL_EVERY),
                reclassify_ms = ms(RECLASSIFY_EVERY),
                "secure desktop watch started"
            );
            Some(state)
        }
        Err(e) => {
            tracing::warn!("secure desktop watch not started: no thread ({e})");
            None
        }
    }
}

/// The watcher thread: the cheap look every `every`, the kind from the processes on a secure
/// desktop ([`needs_facts`]), until the state says stop.
fn watch_loop(state: &SecureDesktop, mut probe: Box<dyn Probe>, every: Duration) {
    let mut last: Option<(Option<SecureDesktopKind>, String)> = None;
    // The last kind told from the processes, when, and what decided it.
    let mut told: Option<(Instant, SecureDesktopKind, String)> = None;
    let mut warned: Vec<&'static str> = Vec::new();
    while !state.stop.load(Ordering::SeqCst) {
        let began = Instant::now();
        let look = probe.desktop();
        let mut failures = look.failures;
        let (kind, why) = if look.default {
            told = None;
            (None, look.why)
        } else {
            let shown = state.current().is_some();
            let (kind, decided) = match told.take() {
                Some(t) if !needs_facts(Some(t.0), began, shown) => {
                    told = Some(t.clone());
                    (t.1, t.2)
                }
                _ => {
                    let facts = probe.facts();
                    failures.extend(facts.failures.iter().cloned());
                    let (kind, decided) = classify(&facts);
                    told = Some((began, kind, decided.clone()));
                    (kind, decided)
                }
            };
            (Some(kind), format!("{}; {decided}", look.why))
        };
        for (call, error) in &failures {
            if warned.contains(call) {
                tracing::trace!(call, %error, "secure desktop watch: a Windows call failed again");
            } else {
                warned.push(call);
                tracing::warn!(
                    call,
                    %error,
                    "secure desktop watch: a Windows call failed; the kind is told without it \
                     (said once per call)"
                );
            }
        }
        let seen = (kind, why);
        if last.as_ref() != Some(&seen) {
            tracing::debug!(
                kind = seen.0.map_or("none", SecureDesktopKind::as_str),
                why = %seen.1,
                took_ms = ms(began.elapsed()),
                "secure desktop watch: the input desktop as seen now"
            );
            last = Some(seen.clone());
        }
        state.observe(Instant::now(), crate::agent_events::now_ms(), seen.0);
        std::thread::sleep(every);
    }
    tracing::debug!("secure desktop watch stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_protocol::SecureDesktopKind::{Lock, Other, Uac};

    const T0_MS: u64 = 1_789_600_400_000;
    const SID: &str = "3fa85f64-5717-4562-b3fc-2c963f66afa6";
    const SID2: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";

    /// A fake clock: milliseconds from a fixed start.
    struct Clock(Instant);
    impl Clock {
        fn new() -> Self {
            Self(Instant::now())
        }
        fn at(&self, ms: u64) -> Instant {
            self.0 + Duration::from_millis(ms)
        }
    }

    fn see(
        t: &mut Tracker,
        c: &Clock,
        at: u64,
        obs: Option<SecureDesktopKind>,
    ) -> Option<Finished> {
        t.observe(c.at(at), T0_MS + at, obs, false)
    }

    fn facts(consent: Option<bool>, locked: Option<bool>) -> Facts {
        Facts {
            session: 1,
            consent,
            locked,
            failures: Vec::new(),
        }
    }

    /// The module doc's rules, row by row.
    #[test]
    fn the_kind_is_told_by_the_rules() {
        let kind = |f: Facts| classify(&f).0;
        // A UAC prompt, whatever else is up.
        assert_eq!(kind(facts(Some(true), Some(false))), Uac);
        assert_eq!(kind(facts(Some(true), Some(true))), Uac);
        assert_eq!(kind(facts(Some(true), None)), Uac);
        // The lock screen: the session's flag.
        assert_eq!(kind(facts(Some(false), Some(true))), Lock);
        assert_eq!(kind(facts(None, Some(true))), Lock);
        // Ctrl+Alt+Del, signing out, restarting: the session not locked.
        assert_eq!(kind(facts(Some(false), Some(false))), Other);
        // The flag not known (accepted: `other`), and nothing known.
        assert_eq!(kind(facts(Some(false), None)), Other);
        assert_eq!(kind(facts(None, None)), Other);
        // What decided it, for the log line the live run looks for.
        assert_eq!(
            classify(&facts(Some(true), None)).1,
            "consent.exe in session 1"
        );
    }

    /// The processes are looked at on leaving the ordinary desktop and every two seconds while it
    /// lasts.
    #[test]
    fn the_kind_is_told_again_at_most_every_two_seconds() {
        let c = Clock::new();
        assert!(needs_facts(None, c.at(0), false), "leaving: at once");
        assert!(
            needs_facts(Some(c.at(0)), c.at(250), false),
            "not shown yet"
        );
        assert!(!needs_facts(Some(c.at(0)), c.at(250), true));
        assert!(!needs_facts(Some(c.at(0)), c.at(1_999), true));
        assert!(needs_facts(Some(c.at(0)), c.at(2_000), true));
    }

    /// A lock held 30 s, then the ordinary desktop: one episode, ended at the first look that finds
    /// the ordinary desktop, with nobody's session; a return and a new secure desktop at once are
    /// two episodes.
    #[test]
    fn an_episode_runs_from_leaving_to_coming_back() {
        let c = Clock::new();
        let mut t = Tracker::new();
        assert_eq!(see(&mut t, &c, 0, None), None);
        assert_eq!(see(&mut t, &c, 250, Some(Lock)), None);
        assert_eq!(t.current(), Some(Lock));
        for at in (500..30_250).step_by(250) {
            assert_eq!(see(&mut t, &c, at, Some(Lock)), None);
        }
        let ended = see(&mut t, &c, 30_250, None).expect("ended");
        assert_eq!(
            ended,
            Finished {
                at_ms: T0_MS + 250,
                desktop: Lock,
                duration_ms: 30_000,
                session_id: None,
                game_only: false,
            }
        );
        assert_eq!(t.current(), None);
        assert_eq!(
            ended.event(),
            AgentEventKind::SecureDesktopEnded {
                desktop: Lock,
                duration_ms: 30_000,
                session_id: None,
                game_only: Some(false),
            }
        );
        assert_eq!(see(&mut t, &c, 30_500, Some(Uac)), None);
        let second = see(&mut t, &c, 31_000, None).expect("a second row");
        assert_eq!((second.at_ms, second.duration_ms), (T0_MS + 30_500, 500));
    }

    /// The heartbeat says the current kind; the event the most telling one the episode saw.
    #[test]
    fn the_event_says_the_most_telling_kind_and_the_heartbeat_the_current() {
        let c = Clock::new();
        let mut t = Tracker::new();
        see(&mut t, &c, 0, Some(Lock));
        see(&mut t, &c, 250, Some(Uac));
        assert_eq!(t.current(), Some(Uac));
        see(&mut t, &c, 500, Some(Other));
        assert_eq!(t.current(), Some(Other));
        assert_eq!(see(&mut t, &c, 750, None).expect("ended").desktop, Uac);

        see(&mut t, &c, 1_000, Some(Other));
        see(&mut t, &c, 1_250, Some(Lock));
        see(&mut t, &c, 1_500, Some(Other));
        assert_eq!(see(&mut t, &c, 1_750, None).expect("ended").desktop, Lock);
    }

    /// A session live at the start: the cue once, at 10 s, with the episode's start and the current
    /// kind; never again in the episode, whatever the sessions; and the event carries the session
    /// and «Только игра».
    #[test]
    fn the_cue_goes_once_per_episode_at_ten_seconds() {
        let c = Clock::new();
        let mut t = Tracker::new();
        assert_eq!(t.sessions(&[SID], c.at(0), true), None);
        t.observe(c.at(1_000), T0_MS + 1_000, Some(Uac), true);
        assert_eq!(t.sessions(&[SID], c.at(1_000), true), None);
        assert_eq!(t.sessions(&[SID], c.at(10_999), true), None);
        assert_eq!(
            t.sessions(&[SID], c.at(11_000), true),
            Some(OngoingCue {
                session_id: SID.into(),
                desktop: Uac,
                at: T0_MS + 1_000,
                age_ms: 10_000,
            })
        );
        assert_eq!(t.sessions(&[SID], c.at(20_000), true), None);
        assert_eq!(
            t.sessions(&[SID, SID2], c.at(21_000), true),
            None,
            "once per episode"
        );
        let ended = see(&mut t, &c, 30_000, None).expect("ended");
        assert_eq!(ended.session_id.as_deref(), Some(SID));
        assert!(ended.game_only);

        // A new episode: a cue again.
        see(&mut t, &c, 40_000, Some(Lock));
        assert!(t.sessions(&[SID], c.at(50_000), true).is_some());
    }

    /// A session that begins during an older episode: the cue at once, and the episode told with it.
    #[test]
    fn a_session_that_begins_mid_episode_gets_the_cue_at_once() {
        let c = Clock::new();
        let mut t = Tracker::new();
        see(&mut t, &c, 0, Some(Lock));
        assert_eq!(t.sessions(&[], c.at(30_000), true), None);
        let cue = t.sessions(&[SID], c.at(60_000), true).expect("at once");
        assert_eq!(cue.age_ms, 60_000);
        let ended = see(&mut t, &c, 70_000, None).expect("ended");
        assert_eq!(ended.session_id.as_deref(), Some(SID));
    }

    /// The session told stays told after it ended, and the cue goes with one live when it falls due.
    #[test]
    fn the_session_told_is_one_live_during_the_episode() {
        let c = Clock::new();
        let mut t = Tracker::new();
        t.sessions(&[SID], c.at(0), true);
        see(&mut t, &c, 0, Some(Uac));
        let cue = t.sessions(&[SID2], c.at(10_000), true).expect("due");
        assert_eq!(cue.session_id, SID2, "the one live now");
        let ended = see(&mut t, &c, 12_000, None).expect("ended");
        assert_eq!(
            ended.session_id.as_deref(),
            Some(SID),
            "the one live at the start"
        );
    }

    /// No cue to a connection that does not take it — which does not count as sent: the next one
    /// that takes it gets it.
    #[test]
    fn the_cue_waits_for_a_connection_that_takes_it() {
        let c = Clock::new();
        let mut t = Tracker::new();
        t.sessions(&[SID], c.at(0), true);
        see(&mut t, &c, 0, Some(Uac));
        assert_eq!(t.sessions(&[SID], c.at(12_000), false), None);
        assert_eq!(t.sessions(&[SID], c.at(13_000), false), None);
        assert!(t.sessions(&[SID], c.at(14_000), true).is_some());
    }

    /// An episode longer than the contract's bound is reported at it.
    #[test]
    fn a_duration_past_the_bound_is_reported_at_it() {
        let c = Clock::new();
        let mut t = Tracker::new();
        see(&mut t, &c, 0, Some(Lock));
        let long = SECURE_DESKTOP_DURATION_MAX_MS + 3_600_000;
        let ended = see(&mut t, &c, long, None).expect("ended");
        assert_eq!(ended.duration_ms, SECURE_DESKTOP_DURATION_MAX_MS);
        let event = afklink_protocol::metrics::AgentEvent {
            at: ended.at_ms,
            event: ended.event(),
        };
        assert_eq!(event.check(), Ok(()));
    }

    /// The agent exiting ends an episode that runs, and it is reported to the exit; once; nothing
    /// is observed after it until the exit is taken back, and then a secure desktop still up is a
    /// new episode.
    #[test]
    fn an_exit_reports_the_episode_it_cuts() {
        let c = Clock::new();
        let mut t = Tracker::new();
        t.sessions(&[SID], c.at(0), true);
        see(&mut t, &c, 0, Some(Uac));
        let cut = t.exiting(c.at(5_000), "quit").expect("reported");
        assert_eq!(
            (cut.desktop, cut.duration_ms, cut.session_id.as_deref()),
            (Uac, 5_000, Some(SID))
        );
        assert_eq!(t.exiting(c.at(5_100), "quit"), None, "said once");
        assert_eq!(see(&mut t, &c, 6_000, Some(Uac)), None);
        assert_eq!(t.current(), None);
        t.exit_taken_back("logoff cancelled");
        see(&mut t, &c, 10_000, Some(Lock));
        assert_eq!(t.current(), Some(Lock));

        let mut idle = Tracker::new();
        assert_eq!(idle.exiting(c.at(0), "quit"), None, "nothing to report");
    }

    /// The shared state: the view follows the observations, a finished episode lands in the event
    /// queue, and «Только игра» is read only for a start; an exit records the episode it cuts.
    #[test]
    fn the_shared_state_publishes_the_kind_and_queues_the_event() {
        let queue = Arc::new(crate::agent_events::EventQueue::in_memory());
        crate::agent_events::record_on_this_thread(Some(Arc::clone(&queue)));
        let reads = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counted = Arc::clone(&reads);
        let state = SecureDesktop::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            true
        });
        let mut view = state.view();
        let c = Clock::new();
        state.observe(c.at(0), T0_MS, None);
        assert_eq!(view.take(), None);
        state.observe(c.at(250), T0_MS + 250, Some(Uac));
        state.observe(c.at(500), T0_MS + 500, Some(Uac));
        assert_eq!(view.take(), Some(Uac));
        assert_eq!(state.current(), Some(Uac));
        assert_eq!(reads.load(Ordering::SeqCst), 1, "read for the start only");
        assert!(state.observe(c.at(5_250), T0_MS + 5_250, None).is_some());
        assert_eq!(view.current(), None);
        state.observe(c.at(8_000), T0_MS + 8_000, Some(Lock));
        assert!(state.exiting("quit").is_some());
        assert_eq!(view.current(), None);
        let waiting = queue.waiting();
        crate::agent_events::record_on_this_thread(None);
        assert_eq!(waiting.len(), 2, "{waiting:?}");
        assert_eq!(
            waiting[0],
            afklink_protocol::metrics::AgentEvent {
                at: T0_MS + 250,
                event: AgentEventKind::SecureDesktopEnded {
                    desktop: Uac,
                    duration_ms: 5_000,
                    session_id: None,
                    game_only: Some(true),
                },
            }
        );
        assert_eq!(waiting[1].at, T0_MS + 8_000, "the one the exit cut");
    }

    /// The thread, on a short tick: a fake probe's looks reach the view; on a secure desktop the
    /// processes are asked for the kind and not again within two seconds; it stops when told.
    #[test]
    fn the_watcher_thread_looks_and_stops() {
        #[derive(Default)]
        struct World {
            secure: Option<Facts>,
            facts_asked: u32,
        }
        struct Fake(Arc<Mutex<World>>);
        impl Probe for Fake {
            fn desktop(&mut self) -> Look {
                let w = lock(&self.0);
                Look {
                    default: w.secure.is_none(),
                    why: "fake".into(),
                    failures: vec![("FakeCall", "denied".into())],
                }
            }
            fn facts(&mut self) -> Facts {
                let mut w = lock(&self.0);
                w.facts_asked += 1;
                w.secure.clone().unwrap_or_default()
            }
        }
        let world = Arc::new(Mutex::new(World::default()));
        let state = SecureDesktop::new(|| false);
        let thread = run(
            &state,
            Box::new(Fake(Arc::clone(&world))),
            Duration::from_millis(10),
        )
        .expect("a thread");
        let wait_for = |want: Option<SecureDesktopKind>| {
            let until = Instant::now() + Duration::from_secs(5);
            while state.current() != want {
                assert!(Instant::now() < until, "the watcher did not see {want:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        lock(&world).secure = Some(facts(Some(false), Some(true)));
        wait_for(Some(Lock));
        // Many looks within the two seconds: the kind stands, the processes asked once.
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(lock(&world).facts_asked, 1);
        assert_eq!(state.current(), Some(Lock));
        lock(&world).secure = None;
        wait_for(None);
        state.stop();
        thread.join().expect("the watcher stops");
    }
}
