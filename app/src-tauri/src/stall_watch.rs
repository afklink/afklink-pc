//! Whether the main thread and the async runtime still answer: a watch that writes to the log only
//! when one of them does not. A main thread (Tauri's event loop — the windows, the tray, every
//! command the window calls without `async`) waiting for a lock that another thread holds while it
//! waits for the main thread (`capture_guard`) leaves the window «Не отвечает» and the PC off the
//! server's list, with nothing in the log. Whatever hangs one of them, the log says when it began,
//! how long it lasted and when it ended.
//!
//! A thread of its own, `afklink-stall-watch`, looks every [`LOOK_EVERY`]:
//!
//! - **The main thread**: a closure handed to it (`run_on_main_thread`) notes when it ran. One at a
//!   time, so a stuck main thread does not get them piled up in its queue (Windows refuses a
//!   thread's 10 000th waiting message, and the app's own would then be refused too).
//! - **The async runtime** (Tauri's tokio runtime, the orchestrator's): a task on it notes the time
//!   every [`RUNTIME_TICK`].
//! - **The orchestrator's step** (`afklink_core::step_watch`: a server message, a command, a
//!   session's signal, a tick — and since when), `side=orchestrator`: the runtime may run on while
//!   the orchestrator is stuck in one step, and everything behind it waits, the reconnect too. A
//!   step with a budget (`afklink_core::START_STEP_BUDGET`) gets the `warn` only past it.
//! - **A worker stuck in one poll** (`side=async_worker`), from tokio's stable per-worker metrics:
//!   a worker not parked whose park count and busy time (handed in at each park and every 61 polls)
//!   have not moved since a look has been inside one poll since about then. Many short polls never
//!   look like one; a `block_in_place` hands its core to another thread, which goes on counting.
//!
//! The watch never waits for either side: a closure is only posted to the event loop, a note is
//! read with an atomic load, and no lock is shared. Its lines are queued for the log's own thread,
//! `afklink-log-writer` (`log_file`), and go to the system log and a live session's file
//! (`SYSTEM_TARGET`).
//!
//! **What is said** ([`judge`]): one `debug` line at the start with the cadence and the thresholds;
//! for each side a `warn` after [`WARN_AFTER`] of silence, an `error` at [`ERROR_AFTER`] and every
//! [`ERROR_EVERY`] while it lasts, an `info` when it answers again. Logging only; an `error` also
//! notes the automatic report (`diagnostics::auto::stall_seen`: a `try_send`, no wait, no lock). A
//! look far later than due ([`AWAY_AFTER`]: the PC asleep, the process paused) restarts the silence
//! from that look. The app's exit stops the watch ([`stop`]).
//!
//! **The nudge** ([`Nudge`], every [`NUDGE_EVERY`]): tokio's multi-thread runtime (1.53) drives its
//! I/O and timers only from an idle worker parked on the driver, and a worker woken with one task
//! runs it without waking another (`Context::park_internal`). When that task blocks its thread,
//! nobody drives the sockets and timers and the PC leaves the server's list. A task spawned from
//! outside goes through the inject queue, which unparks a sleeping worker; one at a time.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_core::step_watch::{Step, StepWatch};
use tauri::{AppHandle, Runtime};

use crate::log_route::SYSTEM_TARGET;

/// How often the watch looks, and so how often a closure is handed to the main thread.
pub(crate) const LOOK_EVERY: Duration = Duration::from_secs(2);

/// How often the runtime is handed a task from outside ([`Nudge`]): twice a look.
pub(crate) const NUDGE_EVERY: Duration = Duration::from_secs(1);

/// How often the runtime's task notes the time.
pub(crate) const RUNTIME_TICK: Duration = Duration::from_secs(1);

/// Silent this long: a `warn`. Far longer than anything either side does between two answers.
pub(crate) const WARN_AFTER: Duration = Duration::from_secs(5);

/// Silent this long: an `error` — what Windows calls «Не отвечает» set in long before.
pub(crate) const ERROR_AFTER: Duration = Duration::from_secs(30);

/// While it lasts, the `error` again this often.
pub(crate) const ERROR_EVERY: Duration = Duration::from_secs(5 * 60);

/// A look this long after the last (instead of [`LOOK_EVERY`]): the watch itself was away.
pub(crate) const AWAY_AFTER: Duration = Duration::from_secs(10);

/// Set by [`stop`]: the watch looks no more.
static STOPPED: AtomicBool = AtomicBool::new(false);

const fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

/// What has been said of a side's silence now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Said {
    /// Nothing: it answers, or has been silent less than [`WARN_AFTER`].
    #[default]
    Nothing,
    /// The `warn`.
    Warned,
    /// The `error`, the last one when it had been silent this long (ms).
    Errored { at_ms: u64 },
}

/// One look at a side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Look {
    /// It has not answered for this long (ms).
    Silent { for_ms: u64 },
    /// It answered since the last look; the wait for that answer was this long (ms).
    Answered { after_ms: u64 },
}

impl Look {
    /// How long it has been silent now: nothing once it answered.
    fn silent_ms(self) -> u64 {
        match self {
            Look::Silent { for_ms } => for_ms,
            Look::Answered { .. } => 0,
        }
    }
}

/// What to write about a side after a look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Say {
    Nothing,
    /// Silent [`WARN_AFTER`]: `warn`.
    Stalled {
        for_ms: u64,
    },
    /// Silent [`ERROR_AFTER`]: `error`.
    Hung {
        for_ms: u64,
    },
    /// Still silent, [`ERROR_EVERY`] after the last `error`: `error` again.
    StillHung {
        for_ms: u64,
    },
    /// It answered after something was said: `info`.
    Back {
        after_ms: u64,
    },
}

/// What to say of a side after a look, given what was said of it so far; and what has been said
/// then. A silence said is said once at each stage — the `warn`, the first `error`, an `error` every
/// [`ERROR_EVERY`] — and its end once; one that reaches [`ERROR_AFTER`] before a look saw it at
/// [`WARN_AFTER`] gets the `error` straight away.
pub(crate) fn judge(said: Said, look: Look) -> (Said, Say) {
    judge_with(said, look, ms(WARN_AFTER))
}

/// [`judge`] with the `warn` at `warn_ms` instead of [`WARN_AFTER`] (a step with a budget); the
/// `error` stays at [`ERROR_AFTER`].
pub(crate) fn judge_with(said: Said, look: Look, warn_ms: u64) -> (Said, Say) {
    match look {
        Look::Answered { after_ms } => match said {
            Said::Nothing => (Said::Nothing, Say::Nothing),
            Said::Warned | Said::Errored { .. } => (Said::Nothing, Say::Back { after_ms }),
        },
        Look::Silent { for_ms } => match said {
            Said::Nothing | Said::Warned if for_ms >= ms(ERROR_AFTER) => {
                (Said::Errored { at_ms: for_ms }, Say::Hung { for_ms })
            }
            Said::Nothing if for_ms >= warn_ms => (Said::Warned, Say::Stalled { for_ms }),
            Said::Errored { at_ms } if for_ms >= at_ms.saturating_add(ms(ERROR_EVERY)) => {
                (Said::Errored { at_ms: for_ms }, Say::StillHung { for_ms })
            }
            Said::Nothing | Said::Warned | Said::Errored { .. } => (said, Say::Nothing),
        },
    }
}

/// How long since `at` (ms on the watch's clock), counted from `floor` at the earliest: the look
/// after the watch was away ([`AWAY_AFTER`]).
fn since(now_ms: u64, at_ms: u64, floor_ms: u64) -> u64 {
    now_ms.saturating_sub(at_ms.max(floor_ms))
}

/// A look `late_ms` after the last one: the watch itself was away.
fn was_away(late_ms: u64) -> bool {
    late_ms >= ms(AWAY_AFTER)
}

/// What the main thread's closures and the runtime's task note, and the watch reads.
struct Notes {
    /// The watch's clock: every time here is ms since this.
    epoch: Instant,
    /// The number of the last closure the main thread ran.
    main_ran: AtomicU64,
    /// When it ran it.
    main_ran_at_ms: AtomicU64,
    /// When the runtime's task last noted the time.
    runtime_at_ms: AtomicU64,
}

impl Notes {
    fn now_ms(&self) -> u64 {
        ms(self.epoch.elapsed())
    }
}

/// The watch's account of the main thread.
#[derive(Debug, Default)]
struct MainSide {
    said: Said,
    /// The number of the closure handed over last (0: none yet, which counts as run), and when.
    handed: u64,
    handed_at_ms: u64,
    /// The closure numbered `handed` is still to be handed over: its last try was refused.
    to_hand: bool,
    /// A refusal was said; said again only after one goes through.
    refusal_said: bool,
}

impl MainSide {
    /// A look at `now_ms`: the main thread has run closure `ran`, at `ran_at_ms`. When it ran the
    /// last one handed over, the next is numbered and due to be handed over ([`Self::to_hand`]).
    fn look(&mut self, ran: u64, ran_at_ms: u64, now_ms: u64, floor_ms: u64) -> Look {
        if ran == self.handed && !self.to_hand {
            let look = Look::Answered {
                after_ms: since(ran_at_ms, self.handed_at_ms, floor_ms),
            };
            self.handed += 1;
            self.handed_at_ms = now_ms;
            self.to_hand = true;
            look
        } else {
            Look::Silent {
                for_ms: since(now_ms, self.handed_at_ms, floor_ms),
            }
        }
    }

    /// Hand closure [`Self::handed`] to the main thread. Never waits: it is posted to the event loop.
    /// A refusal is said once (`warn`), until one goes through; the main thread's silence counts
    /// meanwhile, from when the closure was due.
    fn hand_over<R: Runtime>(&mut self, app: &AppHandle<R>, notes: &Arc<Notes>) {
        let number = self.handed;
        let noted = Arc::clone(notes);
        match app.run_on_main_thread(move || {
            noted.main_ran_at_ms.store(noted.now_ms(), Ordering::SeqCst);
            noted.main_ran.store(number, Ordering::SeqCst);
        }) {
            Ok(()) => {
                self.to_hand = false;
                if std::mem::take(&mut self.refusal_said) {
                    tracing::debug!(
                        target: SYSTEM_TARGET,
                        number,
                        "stall watch: the main thread takes its closures again"
                    );
                }
            }
            Err(e) => {
                if STOPPED.load(Ordering::SeqCst) {
                    tracing::trace!(number, "stall watch: closure refused on the way out: {e}");
                } else if !std::mem::replace(&mut self.refusal_said, true) {
                    tracing::warn!(
                        target: SYSTEM_TARGET,
                        number,
                        "stall watch: a closure not handed to the main thread ({e}); tried again at \
                         each look, its silence counted meanwhile (said once, until one goes through)"
                    );
                }
            }
        }
    }
}

/// The watch's account of the async runtime.
#[derive(Debug, Default)]
struct RuntimeSide {
    said: Said,
    /// The runtime's note as of the last look.
    seen_ms: u64,
}

impl RuntimeSide {
    /// A look at `now_ms`, the runtime's note being `noted_ms`: it answered when the note moved.
    fn look(&mut self, noted_ms: u64, now_ms: u64, floor_ms: u64) -> Look {
        if noted_ms == self.seen_ms {
            Look::Silent {
                for_ms: since(now_ms, noted_ms, floor_ms),
            }
        } else {
            let look = Look::Answered {
                after_ms: since(noted_ms, self.seen_ms, floor_ms),
            };
            self.seen_ms = noted_ms;
            look
        }
    }
}

/// The watch's account of the orchestrator's step.
#[derive(Debug, Default)]
struct StepSide {
    said: Said,
    /// The step judged last, while it lasts.
    step: Option<Step>,
}

impl StepSide {
    /// A look at `now_ms` with `current` the orchestrator's step now; `started_ms` turns a step's
    /// start into the watch's clock. What to say: of the step judged last when it ended (its end,
    /// when something was said of it), then of the step now (its age).
    fn look(
        &mut self,
        current: Option<Step>,
        now_ms: u64,
        floor_ms: u64,
        started_ms: impl Fn(&Step) -> u64,
    ) -> Vec<(Step, Say)> {
        let mut says = Vec::new();
        let same = matches!((&self.step, &current), (Some(a), Some(b)) if a.seq == b.seq);
        if !same {
            if let Some(ended) = self.step.take() {
                let after_ms = since(now_ms, started_ms(&ended), floor_ms);
                let (said, say) = judge(self.said, Look::Answered { after_ms });
                self.said = said;
                if say != Say::Nothing {
                    says.push((ended, say));
                }
            }
            self.said = Said::Nothing;
            self.step = current;
        }
        if let Some(step) = &self.step {
            let for_ms = since(now_ms, started_ms(step), floor_ms);
            // A step with a budget is said only past it.
            let warn_ms = ms(WARN_AFTER).max(ms(step.budget));
            let (said, say) = judge_with(self.said, Look::Silent { for_ms }, warn_ms);
            self.said = said;
            if say != Say::Nothing {
                says.push((step.clone(), say));
            }
        }
        says
    }

    /// How long the step judged now has lasted (0: none), for the other sides' lines.
    fn age_ms(&self, now_ms: u64, floor_ms: u64, started_ms: impl Fn(&Step) -> u64) -> u64 {
        self.step
            .as_ref()
            .map_or(0, |s| since(now_ms, started_ms(s), floor_ms))
    }
}

/// Write what [`judge`] said of the orchestrator's `step`.
fn report_step(step: &Step, say: Say, main_silent_ms: u64, runtime_silent_ms: u64) {
    let side = "orchestrator";
    let session = step.session.as_deref().unwrap_or("-");
    let (what, kind, seq) = (step.what, step.kind, step.seq);
    match say {
        Say::Nothing => {}
        Say::Stalled { for_ms } => tracing::warn!(
            target: SYSTEM_TARGET,
            side,
            what,
            kind,
            session,
            seq,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the orchestrator has been in one step for {for_ms} ms ({what} {kind}): \
             server messages, commands and the reconnect wait behind it (an error at {} s if it \
             lasts)",
            ERROR_AFTER.as_secs()
        ),
        Say::Hung { for_ms } => tracing::error!(
            target: SYSTEM_TARGET,
            side,
            what,
            kind,
            session,
            seq,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the orchestrator has been in one step for {} s ({what} {kind}): it is \
             stuck — the link to the server and the sessions with it (said again every {} min \
             until it ends)",
            for_ms / 1000,
            ERROR_EVERY.as_secs() / 60
        ),
        Say::StillHung { for_ms } => tracing::error!(
            target: SYSTEM_TARGET,
            side,
            what,
            kind,
            session,
            seq,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the orchestrator is still in one step, for {} s now ({what} {kind})",
            for_ms / 1000
        ),
        Say::Back { after_ms } => tracing::info!(
            target: SYSTEM_TARGET,
            side,
            what,
            kind,
            session,
            seq,
            after_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the orchestrator's step ({what} {kind}) ended, after about {after_ms} ms"
        ),
    }
    if matches!(say, Say::Hung { .. } | Say::StillHung { .. }) {
        crate::diagnostics::auto::stall_seen(side);
    }
}

/// One worker's counters at a look: how often it parked and unparked (odd: parked now), and its busy
/// time (ns) as it last handed it in (the module's docs, «A worker stuck in one poll»).
pub(crate) type WorkerSample = (u64, u64);

/// Every worker's counters now (tokio's stable runtime metrics: atomics read, nothing waited for).
pub(crate) fn sample_workers(handle: &tokio::runtime::Handle) -> Vec<WorkerSample> {
    let metrics = handle.metrics();
    (0..metrics.num_workers())
        .map(|worker| {
            (
                metrics.worker_park_unpark_count(worker),
                u64::try_from(metrics.worker_total_busy_duration(worker).as_nanos())
                    .unwrap_or(u64::MAX),
            )
        })
        .collect()
}

/// The watch's account of one worker.
#[derive(Debug, Default)]
struct WorkerState {
    said: Said,
    /// Its counters as last seen changed (or parked), and when (the watch's clock).
    seen: Option<WorkerSample>,
    since_ms: u64,
}

/// The watch's account of the runtime's workers.
#[derive(Debug, Default)]
pub(crate) struct WorkerSide {
    workers: Vec<WorkerState>,
}

impl WorkerSide {
    /// A look at `now_ms` with every worker's counters (`samples`): what to say of each worker
    /// (`(index, say)`, nothing said left out), and the longest any is in one poll now (ms).
    pub(crate) fn look(
        &mut self,
        samples: &[WorkerSample],
        now_ms: u64,
        floor_ms: u64,
    ) -> (Vec<(usize, Say)>, u64) {
        if self.workers.len() != samples.len() {
            self.workers
                .resize_with(samples.len(), WorkerState::default);
        }
        let mut says = Vec::new();
        let mut longest_ms = 0;
        for (index, (&sample, worker)) in samples.iter().zip(&mut self.workers).enumerate() {
            let parked = sample.0 % 2 == 1;
            let look = if parked || worker.seen != Some(sample) {
                let after_ms = since(now_ms, worker.since_ms, floor_ms);
                worker.seen = Some(sample);
                worker.since_ms = now_ms;
                Look::Answered { after_ms }
            } else {
                Look::Silent {
                    for_ms: since(now_ms, worker.since_ms, floor_ms),
                }
            };
            longest_ms = longest_ms.max(look.silent_ms());
            let (said, say) = judge(worker.said, look);
            worker.said = said;
            if say != Say::Nothing {
                says.push((index, say));
            }
        }
        (says, longest_ms)
    }
}

/// Write what [`judge`] said of runtime worker `worker`.
fn report_worker(worker: usize, say: Say, main_silent_ms: u64, runtime_silent_ms: u64) {
    let side = "async_worker";
    match say {
        Say::Nothing => {}
        Say::Stalled { for_ms } => tracing::warn!(
            target: SYSTEM_TARGET,
            side,
            worker,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: async runtime worker {worker} has been inside one poll for about \
             {for_ms} ms: a task blocks its thread (whatever it was due to run waits; an error at \
             {} s if it lasts)",
            ERROR_AFTER.as_secs()
        ),
        Say::Hung { for_ms } => tracing::error!(
            target: SYSTEM_TARGET,
            side,
            worker,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: async runtime worker {worker} has been inside one poll for {} s: a task \
             is stuck on it (said again every {} min until it moves)",
            for_ms / 1000,
            ERROR_EVERY.as_secs() / 60
        ),
        Say::StillHung { for_ms } => tracing::error!(
            target: SYSTEM_TARGET,
            side,
            worker,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: async runtime worker {worker} is still inside one poll, for {} s now",
            for_ms / 1000
        ),
        Say::Back { after_ms } => tracing::info!(
            target: SYSTEM_TARGET,
            side,
            worker,
            after_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: async runtime worker {worker} moves again, after about {after_ms} ms in \
             one poll"
        ),
    }
    if matches!(say, Say::Hung { .. } | Say::StillHung { .. }) {
        crate::diagnostics::auto::stall_seen(side);
    }
}

/// Hands the async runtime a trivial task from outside it, one at a time (the module's docs, «The
/// nudge»): what gets an idle worker back onto the I/O and timer driver when the worker that held it
/// blocks in the one task the driver woke.
pub(crate) struct Nudge {
    handle: tokio::runtime::Handle,
    /// The number of the last nudge handed over (0: none yet).
    handed: u64,
    /// The number of the last nudge that ran, noted by the nudge itself.
    ran: Arc<AtomicU64>,
    /// When the nudge still waiting was handed over, for the line that says it ran late.
    handed_at: Option<Instant>,
    /// A nudge left waiting was said; said again only after one runs.
    waiting_said: bool,
}

/// What [`Nudge::nudge`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nudged {
    /// A new nudge handed over.
    Handed,
    /// None: the last one has not run yet.
    Waiting,
}

impl Nudge {
    pub(crate) fn new(handle: tokio::runtime::Handle) -> Self {
        Self {
            handle,
            handed: 0,
            ran: Arc::new(AtomicU64::new(0)),
            handed_at: None,
            waiting_said: false,
        }
    }

    /// Hand the runtime one trivial task — unless the last one has not run yet. Never waits: a
    /// spawn from outside the runtime is a push onto its inject queue and an unpark.
    pub(crate) fn nudge(&mut self) -> Nudged {
        let ran = self.ran.load(Ordering::SeqCst);
        if ran < self.handed {
            if !std::mem::replace(&mut self.waiting_said, true) {
                tracing::debug!(
                    target: SYSTEM_TARGET,
                    handed = self.handed,
                    ran,
                    waited_ms = self.handed_at.map(|t| t.elapsed().as_millis() as u64),
                    "stall watch: the runtime has not run the last nudge yet (no worker free even \
                     for a task from outside); none more until it does"
                );
            }
            return Nudged::Waiting;
        }
        if std::mem::take(&mut self.waiting_said) {
            tracing::debug!(
                target: SYSTEM_TARGET,
                ran,
                waited_ms = self.handed_at.map(|t| t.elapsed().as_millis() as u64),
                "stall watch: the runtime ran the nudge it had left waiting; nudged again"
            );
        }
        self.handed += 1;
        self.handed_at = Some(Instant::now());
        let (number, noted) = (self.handed, Arc::clone(&self.ran));
        // Detached: the task notes that it ran, and nothing waits for it.
        drop(self.handle.spawn(async move {
            noted.store(number, Ordering::SeqCst);
        }));
        Nudged::Handed
    }
}

/// Which side a line is about.
#[derive(Debug, Clone, Copy)]
enum Side {
    Main,
    Runtime,
}

impl Side {
    fn as_str(self) -> &'static str {
        match self {
            Side::Main => "main_thread",
            Side::Runtime => "async_runtime",
        }
    }
}

/// Write what [`judge`] said of `side`, with both sides' silence now.
fn report(side: Side, say: Say, main_silent_ms: u64, runtime_silent_ms: u64) {
    let side_name = side.as_str();
    match (side, say) {
        (_, Say::Nothing) => {}
        (Side::Main, Say::Stalled { for_ms }) => tracing::warn!(
            target: SYSTEM_TARGET,
            side = side_name,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the main thread has not answered for {for_ms} ms: the windows, the tray \
             and the window's commands wait for it (an error at {} s if it lasts)",
            ERROR_AFTER.as_secs()
        ),
        (Side::Main, Say::Hung { for_ms }) => tracing::error!(
            target: SYSTEM_TARGET,
            side = side_name,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the main thread has not answered for {} s: the window is hung (said again \
             every {} min until it answers)",
            for_ms / 1000,
            ERROR_EVERY.as_secs() / 60
        ),
        (Side::Main, Say::StillHung { for_ms }) => tracing::error!(
            target: SYSTEM_TARGET,
            side = side_name,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the main thread still has not answered, for {} s now: the window is hung",
            for_ms / 1000
        ),
        (Side::Main, Say::Back { after_ms }) => tracing::info!(
            target: SYSTEM_TARGET,
            side = side_name,
            after_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the main thread answered again after {after_ms} ms"
        ),
        (Side::Runtime, Say::Stalled { for_ms }) => tracing::warn!(
            target: SYSTEM_TARGET,
            side = side_name,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the async runtime has not run its ticker for {for_ms} ms: the agent's \
             tasks — signaling, sessions, the state watcher — are held up (an error at {} s if it \
             lasts)",
            ERROR_AFTER.as_secs()
        ),
        (Side::Runtime, Say::Hung { for_ms }) => tracing::error!(
            target: SYSTEM_TARGET,
            side = side_name,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the async runtime has not run its ticker for {} s: the agent's tasks are \
             stuck — the link to the server and the sessions with them (said again every {} min \
             until it runs)",
            for_ms / 1000,
            ERROR_EVERY.as_secs() / 60
        ),
        (Side::Runtime, Say::StillHung { for_ms }) => tracing::error!(
            target: SYSTEM_TARGET,
            side = side_name,
            silent_ms = for_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the async runtime still has not run its ticker, for {} s now: the agent's \
             tasks are stuck",
            for_ms / 1000
        ),
        (Side::Runtime, Say::Back { after_ms }) => tracing::info!(
            target: SYSTEM_TARGET,
            side = side_name,
            after_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: the async runtime runs its ticker again, after {after_ms} ms"
        ),
    }
    // An `error` is an automatic report's trigger (`diagnostics::auto`): a note posted, never waited
    // on — the watch stays free of the two sides it watches.
    if matches!(say, Say::Hung { .. } | Say::StillHung { .. }) {
        crate::diagnostics::auto::stall_seen(side_name);
    }
}

/// Start the watch: the runtime's ticker, and the watch's thread — which also reads the
/// orchestrator's `steps` and nudges the runtime ([`Nudge`]). Called at the end of `setup`. A thread
/// that cannot be had is said (`warn`) and costs only the watch.
pub(crate) fn start<R: Runtime>(app: &AppHandle<R>, steps: Arc<StepWatch>) {
    let notes = Arc::new(Notes {
        epoch: Instant::now(),
        main_ran: AtomicU64::new(0),
        main_ran_at_ms: AtomicU64::new(0),
        runtime_at_ms: AtomicU64::new(0),
    });
    let ticker = Arc::clone(&notes);
    tauri::async_runtime::spawn(async move {
        loop {
            ticker
                .runtime_at_ms
                .store(ticker.now_ms(), Ordering::SeqCst);
            tokio::time::sleep(RUNTIME_TICK).await;
            if STOPPED.load(Ordering::SeqCst) {
                tracing::trace!("stall watch: the runtime's ticker stops");
                return;
            }
        }
    });
    let app = app.clone();
    // Tauri's shared runtime: the one the orchestrator, the pump and the sessions run on.
    let nudge = Nudge::new(tauri::async_runtime::handle().inner().clone());
    let spawned = std::thread::Builder::new()
        .name("afklink-stall-watch".into())
        .spawn(move || watch(&app, &notes, &steps, nudge));
    if let Err(e) = spawned {
        tracing::warn!(
            target: SYSTEM_TARGET,
            "stall watch: its thread did not start ({e}); a hung window, runtime or orchestrator \
             goes unsaid in the log, and the runtime is not nudged"
        );
    }
}

/// The watch stops looking (the app's exit: the event loop's last work, and what follows it, is no
/// stall). `why` is for the log.
pub(crate) fn stop(why: &'static str) {
    if !STOPPED.swap(true, Ordering::SeqCst) {
        tracing::debug!(target: SYSTEM_TARGET, why, "stall watch stops");
    }
}

/// The watch's thread: a nudge every [`NUDGE_EVERY`], a look every [`LOOK_EVERY`], until [`stop`].
fn watch<R: Runtime>(app: &AppHandle<R>, notes: &Arc<Notes>, steps: &StepWatch, mut nudge: Nudge) {
    tracing::debug!(
        target: SYSTEM_TARGET,
        look_every_ms = ms(LOOK_EVERY),
        nudge_every_ms = ms(NUDGE_EVERY),
        runtime_tick_ms = ms(RUNTIME_TICK),
        warn_after_ms = ms(WARN_AFTER),
        error_after_ms = ms(ERROR_AFTER),
        error_every_s = ERROR_EVERY.as_secs(),
        away_after_ms = ms(AWAY_AFTER),
        "stall watch started: the main thread, the async runtime, its workers and the \
         orchestrator's step are looked at, said only when one does not answer; the runtime is \
         nudged from outside"
    );
    let mut main = MainSide::default();
    let mut runtime = RuntimeSide::default();
    let mut step_side = StepSide::default();
    let mut workers = WorkerSide::default();
    let runtime_handle = nudge.handle.clone();
    let mut floor_ms = 0;
    let mut last_look_ms = notes.now_ms();
    let nudges_per_look = (LOOK_EVERY.as_millis() / NUDGE_EVERY.as_millis()).max(1);
    let mut nudges = 0u128;
    loop {
        std::thread::sleep(NUDGE_EVERY);
        if STOPPED.load(Ordering::SeqCst) {
            tracing::trace!("stall watch: its thread stops");
            return;
        }
        nudge.nudge();
        nudges += 1;
        if !nudges.is_multiple_of(nudges_per_look) {
            continue;
        }
        let now_ms = notes.now_ms();
        let late_ms = now_ms.saturating_sub(last_look_ms);
        last_look_ms = now_ms;
        if was_away(late_ms) {
            floor_ms = now_ms;
            tracing::debug!(
                target: SYSTEM_TARGET,
                late_ms,
                look_every_ms = ms(LOOK_EVERY),
                main_said = ?main.said,
                runtime_said = ?runtime.said,
                "stall watch: this look comes {late_ms} ms after the last — the PC slept, or the \
                 process was starved or paused; both sides' silence counts from now"
            );
        }
        // Both read before either is judged, so each line has both.
        let ran = notes.main_ran.load(Ordering::SeqCst);
        let ran_at_ms = notes.main_ran_at_ms.load(Ordering::SeqCst);
        let main_look = main.look(ran, ran_at_ms, now_ms, floor_ms);
        let runtime_look =
            runtime.look(notes.runtime_at_ms.load(Ordering::SeqCst), now_ms, floor_ms);
        let (main_silent_ms, runtime_silent_ms) = (main_look.silent_ms(), runtime_look.silent_ms());
        let (said, say) = judge(main.said, main_look);
        main.said = said;
        report(Side::Main, say, main_silent_ms, runtime_silent_ms);
        let (said, say) = judge(runtime.said, runtime_look);
        runtime.said = said;
        report(Side::Runtime, say, main_silent_ms, runtime_silent_ms);
        // The orchestrator's step: read under its lock and nothing else, judged on the watch's clock.
        let started_ms = |s: &Step| ms(s.since.saturating_duration_since(notes.epoch));
        for (step, say) in step_side.look(steps.current(), now_ms, floor_ms, started_ms) {
            report_step(&step, say, main_silent_ms, runtime_silent_ms);
        }
        // Each worker: inside one poll since when (atomics read, nothing waited for).
        let (worker_says, worker_ms) =
            workers.look(&sample_workers(&runtime_handle), now_ms, floor_ms);
        for (worker, say) in worker_says {
            report_worker(worker, say, main_silent_ms, runtime_silent_ms);
        }
        tracing::trace!(
            step_ms = step_side.age_ms(now_ms, floor_ms, started_ms),
            worker_ms,
            main_silent_ms,
            runtime_silent_ms,
            "stall watch: look"
        );
        if main.to_hand {
            main.hand_over(app, notes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WARN: u64 = ms(WARN_AFTER);
    const ERROR: u64 = ms(ERROR_AFTER);
    const EVERY: u64 = ms(ERROR_EVERY);

    fn silent(for_ms: u64) -> Look {
        Look::Silent { for_ms }
    }

    /// Run `looks` through [`judge`] from nothing said; what was to be said at each.
    fn run(looks: &[Look]) -> Vec<Say> {
        let mut said = Said::Nothing;
        looks
            .iter()
            .map(|&look| {
                let (next, say) = judge(said, look);
                said = next;
                say
            })
            .collect()
    }

    /// The thresholds as the owner's hotfix asked: a warn at 5 s, an error at 30 s, the error again
    /// every 5 minutes; looked at every 2 s, the runtime ticking every second.
    #[test]
    fn the_thresholds_are_five_and_thirty_seconds_then_every_five_minutes() {
        assert_eq!(WARN_AFTER, Duration::from_secs(5));
        assert_eq!(ERROR_AFTER, Duration::from_secs(30));
        assert_eq!(ERROR_EVERY, Duration::from_secs(300));
        assert_eq!(LOOK_EVERY, Duration::from_secs(2));
        assert_eq!(RUNTIME_TICK, Duration::from_secs(1));
        assert!(
            WARN_AFTER > LOOK_EVERY * 2,
            "a healthy side never reaches the warn"
        );
        assert!(
            AWAY_AFTER > LOOK_EVERY * 4,
            "a late look is not taken for the watch away"
        );
    }

    /// Answering, or silent less than the warn's threshold: nothing is said.
    #[test]
    fn nothing_is_said_while_a_side_answers() {
        let says = run(&[
            Look::Answered { after_ms: 3 },
            silent(1_999),
            silent(WARN - 1),
            Look::Answered { after_ms: WARN - 1 },
            silent(0),
        ]);
        assert!(says.iter().all(|s| *s == Say::Nothing), "{says:?}");
    }

    /// A stall is said once at each stage: the warn at 5 s, the error at 30 s, the error again every
    /// 5 minutes, and its end with how long it was.
    #[test]
    fn a_stall_is_warned_then_an_error_then_again_every_five_minutes_then_its_end() {
        let says = run(&[
            silent(4_000),
            silent(WARN),
            silent(WARN + 2_000),
            silent(ERROR - 1),
            silent(ERROR + 1_000),
            silent(ERROR + 3_000),
            silent(ERROR + 1_000 + EVERY - 1),
            silent(ERROR + 1_000 + EVERY),
            silent(ERROR + 1_000 + EVERY + 2_000),
            silent(ERROR + 1_000 + 2 * EVERY),
            Look::Answered { after_ms: 700_000 },
            Look::Answered { after_ms: 2 },
        ]);
        assert_eq!(
            says,
            vec![
                Say::Nothing,
                Say::Stalled { for_ms: WARN },
                Say::Nothing,
                Say::Nothing,
                Say::Hung {
                    for_ms: ERROR + 1_000
                },
                Say::Nothing,
                Say::Nothing,
                Say::StillHung {
                    for_ms: ERROR + 1_000 + EVERY
                },
                Say::Nothing,
                Say::StillHung {
                    for_ms: ERROR + 1_000 + 2 * EVERY
                },
                Say::Back { after_ms: 700_000 },
                Say::Nothing,
            ]
        );
    }

    /// A stall first seen past 30 s is an error at once, not a warn; one that ends after the warn
    /// says its end; the next stall is said afresh.
    #[test]
    fn a_long_first_look_is_an_error_and_each_stall_is_said_afresh() {
        let says = run(&[
            silent(45_000),
            Look::Answered { after_ms: 46_000 },
            silent(WARN + 500),
            Look::Answered { after_ms: 7_000 },
            silent(WARN),
        ]);
        assert_eq!(
            says,
            vec![
                Say::Hung { for_ms: 45_000 },
                Say::Back { after_ms: 46_000 },
                Say::Stalled { for_ms: WARN + 500 },
                Say::Back { after_ms: 7_000 },
                Say::Stalled { for_ms: WARN },
            ]
        );
    }

    /// The main thread: answered when it ran the closure handed over last; silent, from when that
    /// one was due, until it does — a refused hand-over included.
    #[test]
    fn the_main_thread_is_silent_from_the_closure_it_has_not_run() {
        let mut main = MainSide::default();
        // Closure 0 counts as run: the first look hands over closure 1.
        assert_eq!(main.look(0, 0, 2_000, 0), Look::Answered { after_ms: 0 });
        assert!(main.to_hand);
        assert_eq!((main.handed, main.handed_at_ms), (1, 2_000));
        main.to_hand = false; // handed over
        assert_eq!(
            main.look(1, 2_010, 4_000, 0),
            Look::Answered { after_ms: 10 }
        );
        main.to_hand = false;
        assert_eq!(main.look(1, 2_010, 6_000, 0), silent(2_000));
        assert_eq!(main.look(1, 2_010, 9_000, 0), silent(5_000));
        assert!(!main.to_hand, "nothing more is handed over while one waits");
        assert_eq!(
            main.look(2, 9_500, 10_000, 0),
            Look::Answered { after_ms: 5_500 }
        );
        // Closure 3 refused: still to hand over, and silent from when it was due.
        assert!(main.to_hand);
        assert_eq!(main.look(2, 9_500, 12_000, 0), silent(2_000));
        assert_eq!(main.look(2, 9_500, 16_000, 0), silent(6_000));
    }

    /// The runtime: answered when its note moved, with the gap between the notes; silent for as
    /// long as its note is old.
    #[test]
    fn the_runtime_is_silent_while_its_note_stays() {
        let mut runtime = RuntimeSide::default();
        assert_eq!(
            runtime.look(1_000, 2_000, 0),
            Look::Answered { after_ms: 1_000 }
        );
        assert_eq!(
            runtime.look(3_000, 4_000, 0),
            Look::Answered { after_ms: 2_000 }
        );
        assert_eq!(runtime.look(3_000, 6_000, 0), silent(3_000));
        assert_eq!(runtime.look(3_000, 9_000, 0), silent(6_000));
        assert_eq!(
            runtime.look(9_500, 10_000, 0),
            Look::Answered { after_ms: 6_500 }
        );
    }

    /// After the watch was away (the PC asleep), silence counts from the look that saw it: what went
    /// unanswered meanwhile is not taken for a stall.
    #[test]
    fn silence_counts_from_the_look_after_the_watch_was_away() {
        assert!(!was_away(ms(LOOK_EVERY) + 3_000));
        assert!(was_away(ms(AWAY_AFTER)));
        assert!(was_away(3_600_000));
        assert_eq!(since(20_000, 1_000, 0), 19_000);
        assert_eq!(since(20_000, 1_000, 18_000), 2_000);
        assert_eq!(since(20_000, 19_000, 18_000), 1_000);
        assert_eq!(since(1_000, 2_000, 0), 0, "never below nothing");

        let mut main = MainSide::default();
        main.look(0, 0, 2_000, 0);
        main.to_hand = false;
        // Asleep with closure 1 waiting; the first look after it is the floor.
        assert_eq!(main.look(0, 0, 3_602_000, 3_602_000), silent(0));
        assert_eq!(main.look(0, 0, 3_604_000, 3_602_000), silent(2_000));
        let mut runtime = RuntimeSide::default();
        runtime.look(2_000, 2_000, 0);
        assert_eq!(runtime.look(2_000, 3_602_000, 3_602_000), silent(0));
    }

    fn step(seq: u64, what: &'static str, kind: &'static str, since_ms: u64) -> (Step, u64) {
        let s = Step {
            seq,
            what,
            kind,
            session: Some("s1".into()),
            since: Instant::now(),
            budget: Duration::ZERO,
        };
        (s, since_ms)
    }

    /// The orchestrator's step: nothing while steps are short; one that lasts gets the warn at 5 s,
    /// the error at 30 s, and its end once it is over; the next step is judged afresh.
    #[test]
    fn a_step_that_lasts_is_warned_then_an_error_then_its_end() {
        let (long, long_at) = step(7, "server_message", "session_end", 1_000);
        let (next, next_at) = step(8, "command", "kill_switch", 40_000);
        let starts = |s: &Step| if s.seq == 7 { long_at } else { next_at };
        let mut side = StepSide::default();
        let kinds = |says: Vec<(Step, Say)>| -> Vec<(u64, Say)> {
            says.into_iter().map(|(s, say)| (s.seq, say)).collect()
        };
        assert!(side.look(None, 500, 0, starts).is_empty());
        assert!(side.look(Some(long.clone()), 2_000, 0, starts).is_empty());
        assert_eq!(
            kinds(side.look(Some(long.clone()), 6_000, 0, starts)),
            vec![(7, Say::Stalled { for_ms: 5_000 })]
        );
        assert!(side.look(Some(long.clone()), 8_000, 0, starts).is_empty());
        assert_eq!(
            kinds(side.look(Some(long.clone()), 32_000, 0, starts)),
            vec![(7, Say::Hung { for_ms: 31_000 })]
        );
        assert_eq!(side.age_ms(32_000, 0, starts), 31_000);
        // It ended and the next began between two looks: the end of the one, nothing yet of the
        // other (it is young).
        assert_eq!(
            kinds(side.look(Some(next.clone()), 41_000, 0, starts)),
            vec![(7, Say::Back { after_ms: 40_000 })]
        );
        assert_eq!(
            kinds(side.look(Some(next.clone()), 46_000, 0, starts)),
            vec![(8, Say::Stalled { for_ms: 6_000 })]
        );
        assert_eq!(
            kinds(side.look(None, 47_000, 0, starts)),
            vec![(8, Say::Back { after_ms: 7_000 })]
        );
        assert!(side.look(None, 49_000, 0, starts).is_empty());
        assert_eq!(side.age_ms(49_000, 0, starts), 0);
        // A short step that ends between two looks is never said.
        let (short, short_at) = step(9, "pairing_tick", "-", 50_000);
        let starts = |_: &Step| short_at;
        assert!(side.look(Some(short), 51_000, 0, starts).is_empty());
        assert!(side.look(None, 53_000, 0, starts).is_empty());
    }

    /// After the watch was away (the PC asleep), a step's age counts from the look that saw it.
    #[test]
    fn a_steps_age_counts_from_the_look_after_the_watch_was_away() {
        let (s, at) = step(3, "server_message", "session_request", 1_000);
        let starts = |_: &Step| at;
        let mut side = StepSide::default();
        assert!(side
            .look(Some(s.clone()), 3_601_000, 3_601_000, starts)
            .is_empty());
        assert_eq!(
            side.look(Some(s), 3_607_000, 3_601_000, starts)
                .into_iter()
                .map(|(_, say)| say)
                .collect::<Vec<_>>(),
            vec![Say::Stalled { for_ms: 6_000 }]
        );
    }

    /// The nudge hands over one task at a time: none more while the last has not run.
    #[test]
    fn the_nudge_hands_over_one_task_at_a_time() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let (busy_tx, busy_rx) = std::sync::mpsc::channel::<()>();
        // The one worker blocked: nothing spawned can run.
        rt.spawn(async move {
            busy_tx.send(()).expect("busy");
            let _ = gate_rx.recv_timeout(Duration::from_secs(10));
        });
        busy_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the worker is busy");
        let mut nudge = Nudge::new(rt.handle().clone());
        assert_eq!(nudge.nudge(), Nudged::Handed);
        assert_eq!(nudge.nudge(), Nudged::Waiting);
        assert_eq!(nudge.nudge(), Nudged::Waiting);
        gate_tx.send(()).expect("free the worker");
        let deadline = Instant::now() + Duration::from_secs(10);
        while nudge.ran.load(Ordering::SeqCst) < 1 {
            assert!(Instant::now() < deadline, "the nudge never ran");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(nudge.nudge(), Nudged::Handed);
        assert_eq!(nudge.handed, 2);
        rt.shutdown_timeout(Duration::from_secs(1));
    }

    /// What [`freeze`] saw.
    struct Freeze {
        /// How many times the timer task ticked during [`FREEZE_WATCHED`].
        ticks: u64,
        /// What the worker side said at a look as late as [`WARN_AFTER`] after the block began,
        /// its counters read [`FREEZE_WATCHED`] apart in real time.
        worker_says: Vec<(usize, Say)>,
    }

    /// How many times a timer task ticked (every [`FREEZE_TICK`]) during [`FREEZE_WATCHED`] while
    /// another task — woken by its socket, as the driver wakes the pump — blocked its worker
    /// synchronously, on a two-worker runtime nudged from outside every [`FREEZE_NUDGE`] or not;
    /// and what the worker side said of it. Every wait is bounded: a regression fails, it does not
    /// hang.
    fn freeze(nudged: bool) -> Freeze {
        use std::io::Write as _;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        let ticks = Arc::new(AtomicU64::new(0));
        let ticker = Arc::clone(&ticks);
        rt.spawn(async move {
            loop {
                tokio::time::sleep(FREEZE_TICK).await;
                ticker.fetch_add(1, Ordering::SeqCst);
            }
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (blocked_tx, blocked_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        rt.spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
            // Woken by the I/O driver: the task in the woken worker's LIFO slot.
            let _ = stream.readable().await;
            let _ = blocked_tx.send(());
            // A synchronous wait on a runtime worker, as a lock held across a main-thread call
            // does.
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });
        // The accept bounded: a connect that never comes fails the test, it does not hang it.
        listener.set_nonblocking(true).expect("nonblocking");
        let accept_by = Instant::now() + Duration::from_secs(10);
        let mut peer = loop {
            match listener.accept() {
                Ok((peer, _)) => break peer,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < accept_by, "the task never connected");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("accept: {e}"),
            }
        };
        peer.set_nonblocking(false).expect("blocking");
        // Everything idle a while, then the byte right after a tick, so no timer is due with it.
        std::thread::sleep(Duration::from_millis(300));
        let seen = ticks.load(Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while ticks.load(Ordering::SeqCst) == seen && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(FREEZE_TICK / 4);
        peer.write_all(&[1]).expect("write");
        blocked_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the socket's task woke and blocked");
        let stop = Arc::new(AtomicBool::new(false));
        let nudger = nudged.then(|| {
            let stop = Arc::clone(&stop);
            let mut nudge = Nudge::new(rt.handle().clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    nudge.nudge();
                    std::thread::sleep(FREEZE_NUDGE);
                }
            })
        });
        let before = ticks.load(Ordering::SeqCst);
        // The worker side, as the watch's thread reads it: a look now, and one after the watched
        // time — dated as late as the warn, so what it says is what the watch would say then.
        let mut workers = WorkerSide::default();
        let _ = workers.look(&sample_workers(rt.handle()), 0, 0);
        std::thread::sleep(FREEZE_WATCHED);
        let during = ticks.load(Ordering::SeqCst) - before;
        let (worker_says, _) = workers.look(&sample_workers(rt.handle()), WARN, 0);
        stop.store(true, Ordering::SeqCst);
        let _ = release_tx.send(());
        if let Some(nudger) = nudger {
            nudger.join().expect("nudger");
        }
        rt.shutdown_timeout(Duration::from_secs(1));
        Freeze {
            ticks: during,
            worker_says,
        }
    }

    const FREEZE_TICK: Duration = Duration::from_millis(100);
    const FREEZE_NUDGE: Duration = Duration::from_millis(100);
    const FREEZE_WATCHED: Duration = Duration::from_millis(1_000);

    /// The nudge keeps the runtime's timers served while a worker woken by its I/O driver blocks in
    /// the task it woke for: about one tick in every [`FREEZE_TICK`] of [`FREEZE_WATCHED`].
    #[test]
    fn the_nudge_keeps_timers_served_while_a_worker_blocks_in_a_task_the_driver_woke() {
        let seen = freeze(true);
        assert!(
            seen.ticks >= 4,
            "a nudged runtime keeps ticking while one worker blocks: {} tick(s) in {} ms",
            seen.ticks,
            FREEZE_WATCHED.as_millis()
        );
        // With the runtime kept going, the block is still said — of its worker.
        assert_eq!(
            seen.worker_says.len(),
            1,
            "the one blocked worker, and only it: {:?}",
            seen.worker_says
        );
        assert!(
            matches!(seen.worker_says[0].1, Say::Stalled { for_ms } if for_ms >= WARN),
            "{:?}",
            seen.worker_says
        );
    }

    /// Without the nudge the same block stops the timers of the whole runtime — tokio 1.53 wakes no
    /// other worker for the one task the driver woke, and the other worker sleeps on its condition
    /// variable, not on the driver. A canary of tokio's behaviour, weaker than the test above: it
    /// needs the freeze in at least one of five tries, since a timer that falls due in the same turn
    /// as the socket (more likely on a loaded machine, where the byte's write is late) gets the
    /// other worker woken and so hides it. Its failure says the freeze was not reproduced, not that
    /// the nudge is broken.
    #[test]
    fn without_the_nudge_a_worker_blocked_in_a_task_the_driver_woke_stops_the_timers() {
        let mut tries = Vec::new();
        for _ in 0..5 {
            let ticks = freeze(false).ticks;
            tries.push(ticks);
            if ticks <= 1 {
                break;
            }
        }
        assert!(
            tries.iter().any(|&t| t <= 1),
            "the freeze the nudge is for was not seen (tokio may have changed: eager driver \
             handoff?): ticks per try {tries:?}"
        );
    }

    /// A worker is in one poll while it is not parked and its counters stand; parked, or its
    /// counters moving (a busy worker hands its busy time in at every maintenance), it is not.
    #[test]
    fn a_worker_is_stuck_while_unparked_and_its_counters_stand() {
        let mut side = WorkerSide::default();
        // Worker 0 active (even count), worker 1 parked (odd).
        let (says, longest) = side.look(&[(4, 100), (7, 50)], 1_000, 0);
        assert!(says.is_empty() && longest == 0);
        let (says, longest) = side.look(&[(4, 100), (7, 50)], 6_000, 0);
        assert_eq!(says, vec![(0, Say::Stalled { for_ms: 5_000 })]);
        assert_eq!(longest, 5_000, "the parked one is idle, not stuck");
        let (says, _) = side.look(&[(4, 100), (7, 50)], 31_000, 0);
        assert_eq!(says, vec![(0, Say::Hung { for_ms: 30_000 })]);
        // It moves again: its end, once.
        let (says, _) = side.look(&[(4, 900), (7, 50)], 33_000, 0);
        assert_eq!(says, vec![(0, Say::Back { after_ms: 32_000 })]);
        // Busy with many polls: the busy time moves at every look, never said.
        for (i, busy) in [1_000u64, 2_000, 3_000, 4_000].into_iter().enumerate() {
            let at = 40_000 + 5_000 * i as u64;
            assert!(side.look(&[(4, busy), (9, 60)], at, 0).0.is_empty());
        }
        // A worker more (the runtime's count read anew) is taken in.
        assert!(side
            .look(&[(4, 5_000), (9, 60), (1, 0)], 70_000, 0)
            .0
            .is_empty());
    }

    /// A step with a budget (a session's start) gets the warn only past it, and the error still
    /// at 30 s; a session's start's budget is under the error.
    #[test]
    fn a_step_with_a_budget_is_warned_only_past_it() {
        assert!(afklink_core::START_STEP_BUDGET + WARN_AFTER <= ERROR_AFTER);
        let budget = afklink_core::START_STEP_BUDGET;
        let start = Step {
            seq: 1,
            what: "server_message",
            kind: "sdp",
            session: Some("s1".into()),
            since: Instant::now(),
            budget,
        };
        let starts = |_: &Step| 0;
        let mut side = StepSide::default();
        assert!(side.look(Some(start.clone()), 6_000, 0, starts).is_empty());
        assert!(side
            .look(Some(start.clone()), ms(budget) - 1, 0, starts)
            .is_empty());
        assert_eq!(
            side.look(Some(start.clone()), ms(budget), 0, starts)
                .into_iter()
                .map(|(_, say)| say)
                .collect::<Vec<_>>(),
            vec![Say::Stalled { for_ms: ms(budget) }]
        );
        assert_eq!(
            side.look(Some(start), ERROR, 0, starts)
                .into_iter()
                .map(|(_, say)| say)
                .collect::<Vec<_>>(),
            vec![Say::Hung { for_ms: ERROR }]
        );
    }
}
