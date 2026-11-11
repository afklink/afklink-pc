//! Platform work that may block, kept off the async runtime's workers.
//!
//! A session's start and end touch things that can wait on another thread without bound: the WGC
//! capture's thread (start waits for it to come up, stop joins it), the game capture's director
//! thread, the input driver's slot lock (`hid` in `afklink_input`, held by the game-focus watch and
//! by every injection across Win32 calls), the encoder's library. Run directly on a tokio worker,
//! any of these can freeze the whole runtime: a worker woken from the I/O driver keeps it while it
//! runs its task, and a task woken into the worker's LIFO slot cannot be stolen by another worker
//! (tokio 1.53, `runtime/scheduler/multi_thread/worker.rs`), so a stuck call there stops pings,
//! timers, the relay and reconnect for everyone. Seen in production: a session was superseded in
//! game-only mode, the next one's answer never left, the link went silent and the agent never
//! reconnected.
//!
//! So each such call runs on a thread of its own:
//!
//! * [`detach`] — the caller does not need the result (a session's teardown): the work goes to a
//!   thread and the caller carries on at once. A watcher says when the work is late
//!   ([`STUCK_WARN_AFTER`], [`STUCK_ERROR_AFTER`]), naming what and whose; the thread says when it
//!   finishes and how long it took.
//! * [`run_bounded`] — the caller needs the result (a session's start): it awaits the thread under
//!   a time limit. Awaiting yields the worker, so whatever the caller queued just before (the SDP
//!   answer) goes out while the work runs. Past the limit the caller gets [`Bounded::TimedOut`] and
//!   decides; the work's late result is handed to an `on_late` that undoes it (stops a capture
//!   that came up after all, closes an input session) on the work's own thread.
//!
//! Threads, not `spawn_blocking`: a call that never returns would keep a blocking-pool thread
//! forever, and these are a few per session start or end.

use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};

/// How long a session's start waits for its blocking steps together — the encoder, the capture's
/// start, the input's opening — before it gives the session up.
///
/// The steps are quick on a PC at rest: a WGC start takes 50–300 ms (`D3D11CreateDevice`,
/// `CreateForMonitor`, `StartCapture` on the capture thread), and the first input session probes
/// and opens the driver in well under a second. But all three can be slow for reasons that are not
/// a fault: on a laptop with two GPUs `D3D11CreateDevice` wakes the discrete one from its power-down
/// (one to several seconds); a game holding the GPU at 100% queues the capture's device and its
/// first frame pool behind its own work; the first SetupDi enumeration of the input driver after a
/// boot or a driver install walks the whole device tree; and the input driver's slot lock may be
/// held a moment by the game-focus watch or a release in progress. Giving such a start up costs the
/// viewer the session for nothing, so the bound is ten seconds: a few times the slowest of these
/// together. Still short enough that a start that cannot come up ends with a reason the viewer is
/// told (`capture_error`, `encoder_error`, `internal_error`) instead of leaving it waiting, and the
/// orchestrator — which serves nothing else while it awaits the steps — is back within it. Each
/// step's time is said at info when it passes [`SLOW_STEP_AFTER`], to learn the real spread in the
/// beta and narrow this.
pub(crate) const START_LIMIT: Duration = Duration::from_secs(10);

/// A start step with less than this left of the start's budget is not started: none of them comes
/// up that fast with any certainty (a WGC start alone takes 50–300 ms), and a step started only to
/// be given up must then be undone on its own thread.
pub(crate) const STEP_MIN_TIME: Duration = Duration::from_millis(50);

/// A start step that takes this long is said at info (its time), not only at debug.
pub(crate) const SLOW_STEP_AFTER: Duration = Duration::from_secs(1);

/// A detached job not done after this is said at warn: something it waits on is stuck.
pub(crate) const STUCK_WARN_AFTER: Duration = Duration::from_secs(5);

/// Still not done after this: said at error, and the thread is left to it — nothing can cancel a
/// blocked Win32 call. The process stays up and serves everything else.
pub(crate) const STUCK_ERROR_AFTER: Duration = Duration::from_secs(30);

/// Jobs past [`STUCK_ERROR_AFTER`] and still not done, process-wide: threads left to a call that
/// does not return. Said in the error line of each new one, and when one finishes after all.
static ABANDONED: AtomicUsize = AtomicUsize::new(0);

/// Jobs running now by `what`, process-wide (detached and bounded alike, until their work
/// returns): who still holds what — for the line of a later step that waits on the same lock.
static RUNNING: Mutex<Vec<(&'static str, usize)>> = Mutex::new(Vec::new());

/// The abandoned ones of [`ABANDONED`] by `what`: a stuck capture stop is not a stuck input
/// driver (`agent`'s refusal of new starts counts only the input's).
static ABANDONED_BY: Mutex<Vec<(&'static str, usize)>> = Mutex::new(Vec::new());

/// `what`'s count in `table`.
fn count_of(table: &Mutex<Vec<(&'static str, usize)>>, what: &str) -> usize {
    crate::sync::lock(table)
        .iter()
        .find(|(w, _)| *w == what)
        .map_or(0, |(_, n)| *n)
}

/// `what`'s count in `table`, one up (`up`) or one down (never below zero). The lock is held for
/// this only.
fn count(table: &Mutex<Vec<(&'static str, usize)>>, what: &'static str, up: bool) {
    let mut table = crate::sync::lock(table);
    match table.iter_mut().find(|(w, _)| *w == what) {
        Some((_, n)) if up => *n += 1,
        Some((_, n)) => *n = n.saturating_sub(1),
        None if up => table.push((what, 1)),
        None => {}
    }
}

/// How many jobs named `what` are running now (their work not returned), process-wide.
pub(crate) fn running(what: &str) -> usize {
    count_of(&RUNNING, what)
}

/// How many jobs are abandoned now: past [`STUCK_ERROR_AFTER`], still not done.
pub(crate) fn abandoned() -> usize {
    ABANDONED.load(Ordering::SeqCst)
}

/// How many jobs named `what` are abandoned now.
pub(crate) fn abandoned_of(what: &str) -> usize {
    count_of(&ABANDONED_BY, what)
}

/// Counts one job of `what` as running from its making until it is dropped (its work returned,
/// or the work was dropped unrun).
struct Running(&'static str);

impl Running {
    fn new(what: &'static str) -> Self {
        count(&RUNNING, what, true);
        Self(what)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        count(&RUNNING, self.0, false);
    }
}

/// A job's life between its thread and its watcher: running, abandoned (the watcher's error bound
/// passed), done. Kept exact for [`ABANDONED`] whichever of the two moves first.
#[derive(Clone, Default)]
struct Life(Arc<AtomicU8>);

const LIFE_RUNNING: u8 = 0;
const LIFE_ABANDONED: u8 = 1;
const LIFE_DONE: u8 = 2;

impl Life {
    /// The watcher's error bound passed: true when the job was still running, and it is counted
    /// abandoned now.
    fn abandon(&self, what: &'static str) -> bool {
        // Counted first, so the count never goes below zero when the job finishes right now.
        ABANDONED.fetch_add(1, Ordering::SeqCst);
        count(&ABANDONED_BY, what, true);
        if self
            .0
            .compare_exchange(
                LIFE_RUNNING,
                LIFE_ABANDONED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            true
        } else {
            count(&ABANDONED_BY, what, false);
            ABANDONED.fetch_sub(1, Ordering::SeqCst);
            false
        }
    }

    /// The work returned: true when it had been counted abandoned (and is not any more).
    fn finish(&self, what: &'static str) -> bool {
        if self.0.swap(LIFE_DONE, Ordering::SeqCst) == LIFE_ABANDONED {
            count(&ABANDONED_BY, what, false);
            ABANDONED.fetch_sub(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}

/// What a job's lines name it by: what it does, whose session it is for (`-`: none), and why it
/// runs when it is for no session (the kill switch, the exit; `-` otherwise).
#[derive(Clone)]
struct Name {
    what: &'static str,
    session: String,
    why: &'static str,
}

/// A detached job's completion, for whoever wants to wait for it (the exit, before the process
/// leaves; the tests).
#[derive(Clone)]
pub(crate) struct JobDone {
    done: watch::Receiver<bool>,
    name: Arc<Name>,
}

impl JobDone {
    /// The work has returned (or its thread ended by a panic).
    pub(crate) fn is_done(&self) -> bool {
        *self.done.borrow()
    }

    /// What the job is, for a line about the ones left: `what` and whose (`session` or why).
    pub(crate) fn describe(&self) -> String {
        let name = &self.name;
        if name.session == "-" {
            format!("{} ({})", name.what, name.why)
        } else {
            format!("{} ({})", name.what, name.session)
        }
    }

    /// Wait for the work to return; never longer than `limit`. True when it did.
    #[cfg(test)]
    pub(crate) async fn wait(self, limit: Duration) -> bool {
        tokio::time::timeout(limit, self.finished()).await.is_ok()
    }

    /// Wait for the work to return, without a bound of its own: for a caller that bounds it (one
    /// timeout around several jobs).
    pub(crate) async fn finished(mut self) {
        // A dropped sender (the thread gone without saying so) ends the wait as done: there is
        // nothing left to wait for.
        let _ = self.done.wait_for(|done| *done).await;
    }
}

/// Says the job finished when dropped, so a panic in the work counts as finished too (the panic
/// itself is logged by the process's panic hook).
struct Finish {
    done: watch::Sender<bool>,
    name: Arc<Name>,
    life: Life,
    started: Instant,
    running: Option<Running>,
}

impl Drop for Finish {
    fn drop(&mut self) {
        let took = self.started.elapsed();
        let took_ms = took.as_millis() as u64;
        let was_abandoned = self.life.finish(self.name.what);
        let Name { what, session, why } = &*self.name;
        if std::thread::panicking() {
            tracing::warn!(session = %session, what, why, took_ms, "blocking job panicked");
        } else if was_abandoned {
            tracing::warn!(
                session = %session,
                what,
                why,
                took_ms,
                abandoned = abandoned(),
                "blocking job finished after all, after it was given up as stuck (its thread is \
                 free again)"
            );
        } else if took >= STUCK_WARN_AFTER {
            tracing::warn!(
                session = %session,
                what,
                why,
                took_ms,
                "blocking job finished late (it was said stuck)"
            );
        } else {
            tracing::debug!(session = %session, what, why, took_ms, "blocking job done");
        }
        // Not running any more before anyone waiting hears it is done.
        drop(self.running.take());
        // No receiver left (no watcher, nobody waiting): nothing to tell.
        let _ = self.done.send(true);
    }
}

/// Run `work` on a thread of its own and return at once: the caller does not wait. `what` and
/// `session` name it in every line about it. The returned [`JobDone`] may be waited on, bounded,
/// or dropped.
///
/// A thread that cannot be made (the process is out of threads) runs the work here instead, through
/// [`crate::input_session::blocking`] — on a multi-thread runtime its worker is handed to another
/// thread first — and says so at warn: the work must happen (keys released, a capture stopped).
pub(crate) fn detach(
    what: &'static str,
    session: &str,
    work: impl FnOnce() + Send + 'static,
) -> JobDone {
    detach_named(
        Name {
            what,
            session: session.to_owned(),
            why: "-",
        },
        work,
    )
}

/// [`detach`] for work that is for no one session: `why` names what asked (the kill switch, the
/// exit) in every line about it.
pub(crate) fn detach_for(
    what: &'static str,
    why: &'static str,
    work: impl FnOnce() + Send + 'static,
) -> JobDone {
    detach_named(
        Name {
            what,
            session: "-".to_owned(),
            why,
        },
        work,
    )
}

fn detach_named(name: Name, work: impl FnOnce() + Send + 'static) -> JobDone {
    detach_watched(
        name,
        (STUCK_WARN_AFTER, STUCK_ERROR_AFTER),
        Life::default(),
        work,
    )
}

/// [`detach_named`] with the watcher's bounds (`warn`, `error`) and the job's [`Life`] given: the
/// tests' seam, with short bounds and the life to look at.
fn detach_watched(
    name: Name,
    (warn_after, error_after): (Duration, Duration),
    life: Life,
    work: impl FnOnce() + Send + 'static,
) -> JobDone {
    let started = Instant::now();
    let (done_tx, done_rx) = watch::channel(false);
    let name = Arc::new(name);
    let finish = Finish {
        done: done_tx,
        name: name.clone(),
        life: life.clone(),
        started,
        running: Some(Running::new(name.what)),
    };
    let (what, session, why) = (name.what, name.session.as_str(), name.why);
    // `std::thread::Builder::spawn` drops the closure when it fails, so the work waits in a slot the
    // fallback below can still take it from.
    let slot = Arc::new(Mutex::new(Some((work, finish))));
    let thread_slot = slot.clone();
    let spawned = std::thread::Builder::new()
        .name(format!("afk-{what}"))
        .spawn(move || {
            let job = crate::sync::lock(&thread_slot).take();
            if let Some((work, finish)) = job {
                work();
                drop(finish);
            }
        });
    match spawned {
        Ok(_) => {
            tracing::debug!(session, what, why, "blocking job handed to its own thread");
            watch_job(
                name.clone(),
                done_rx.clone(),
                life,
                started,
                warn_after,
                error_after,
            );
        }
        Err(e) => {
            tracing::warn!(
                session,
                what,
                why,
                "blocking job: no thread could be made ({e}); running it here, off the worker"
            );
            let job = crate::sync::lock(&slot).take();
            if let Some((work, finish)) = job {
                crate::input_session::blocking(work);
                drop(finish);
            }
        }
    }
    JobDone {
        done: done_rx,
        name,
    }
}

/// Say when a job is late: at warn once `warn_after` has passed since `started` (skipped when
/// `warn_after` is not before `error_after`), at error once `error_after` has — then the job counts
/// as abandoned ([`abandoned`]) until its work returns. A task on the current runtime — two timers,
/// nothing blocking; without a runtime (a synchronous caller in a test) nothing watches, and the
/// job's own end line is all there is.
fn watch_job(
    name: Arc<Name>,
    mut done: watch::Receiver<bool>,
    life: Life,
    started: Instant,
    warn_after: Duration,
    error_after: Duration,
) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::debug!(
            session = %name.session,
            what = name.what,
            why = name.why,
            "blocking job: no async runtime here to watch it; its own line says when it ends"
        );
        return;
    };
    runtime.spawn(async move {
        let Name { what, session, why } = &*name;
        if warn_after < error_after {
            let left = warn_after.saturating_sub(started.elapsed());
            if tokio::time::timeout(left, done.wait_for(|d| *d))
                .await
                .is_ok()
            {
                return;
            }
            tracing::warn!(
                session = %session,
                what,
                why,
                waited_ms = started.elapsed().as_millis() as u64,
                running = running(what),
                "blocking job still not done: something it waits on is stuck (its thread is left to \
                 it; everything else carries on)"
            );
        }
        let left = error_after.saturating_sub(started.elapsed());
        if tokio::time::timeout(left, done.wait_for(|d| *d))
            .await
            .is_ok()
        {
            return;
        }
        if !life.abandon(name.what) {
            tracing::debug!(
                session = %session,
                what,
                why,
                "blocking job finished just at its error bound"
            );
            return;
        }
        tracing::error!(
            session = %session,
            what,
            why,
            waited_ms = started.elapsed().as_millis() as u64,
            running = running(what),
            abandoned = abandoned(),
            "blocking job stuck: still not done; its thread is abandoned to it (a restart of the app \
             frees it; `abandoned`: such threads in the process now)"
        );
    });
}

/// What [`run_bounded`] came back with.
#[derive(Debug)]
pub(crate) enum Bounded<T> {
    /// The work returned in time.
    Done(T),
    /// The limit passed first. The work goes on on its thread; its result, when it comes, goes to
    /// `on_late`.
    TimedOut,
    /// The work could not run (no thread) or its thread ended without a result (a panic).
    Failed(String),
}

impl<T> Bounded<T> {
    /// Why there is no result, for the caller's line: `"done"` when there is one.
    pub(crate) fn why_not(&self) -> String {
        match self {
            Self::Done(_) => "done".to_owned(),
            Self::TimedOut => "timed out".to_owned(),
            Self::Failed(why) => why.clone(),
        }
    }
}

/// Run `work` on a thread of its own and await it, at most `limit`. See the module documentation.
///
/// `on_late` gets the work's result when it arrives after the caller stopped waiting, on the work's
/// thread: it must undo whatever the work set up. Logs the outcome with the time taken (debug in
/// time, warn past the limit); a timed-out job is then watched like a detached one.
pub(crate) async fn run_bounded<T: Send + 'static>(
    what: &'static str,
    session: &str,
    limit: Duration,
    work: impl FnOnce() -> T + Send + 'static,
    on_late: impl FnOnce(T) + Send + 'static,
) -> Bounded<T> {
    run_bounded_watched(
        what,
        session,
        limit,
        (STUCK_ERROR_AFTER, Life::default()),
        work,
        on_late,
    )
    .await
}

/// [`run_bounded`] with the watcher's error bound and the job's [`Life`] given: the tests' seam.
async fn run_bounded_watched<T: Send + 'static>(
    what: &'static str,
    session: &str,
    limit: Duration,
    (error_after, life): (Duration, Life),
    work: impl FnOnce() -> T + Send + 'static,
    on_late: impl FnOnce(T) + Send + 'static,
) -> Bounded<T> {
    // (Almost) no time left — an earlier step used the budget: not started at all. Started, it
    // could not come up in time and would only have to undo whatever it set up.
    if limit < STEP_MIN_TIME {
        tracing::warn!(
            session,
            what,
            left_ms = limit.as_millis() as u64,
            min_ms = STEP_MIN_TIME.as_millis() as u64,
            "blocking step skipped: the start's time budget is used up by the steps before it"
        );
        return Bounded::Failed(format!("{what}: no time left in the start's budget"));
    }
    let started = Instant::now();
    let (tx, mut rx) = oneshot::channel::<T>();
    let (done_tx, done_rx) = watch::channel(false);
    let name = Arc::new(Name {
        what,
        session: session.to_owned(),
        why: "-",
    });
    let (thread_life, thread_name) = (life.clone(), name.clone());
    let running = Running::new(what);
    let spawned = std::thread::Builder::new()
        .name(format!("afk-{what}"))
        .spawn(move || {
            let out = work();
            if let Err(out) = tx.send(out) {
                tracing::warn!(
                    session = %thread_name.session,
                    what,
                    took_ms = started.elapsed().as_millis() as u64,
                    "blocking step finished after its caller gave up waiting; undoing it"
                );
                // The undo is part of the job: a hanging one is watched, and counted abandoned at
                // the error bound, like hanging work.
                on_late(out);
            }
            if thread_life.finish(what) {
                tracing::warn!(
                    session = %thread_name.session,
                    what,
                    took_ms = started.elapsed().as_millis() as u64,
                    abandoned = abandoned(),
                    "blocking step (and its undo) finished after all, after it was given up as \
                     stuck (its thread is free again)"
                );
            }
            drop(running);
            // Watched only once the caller timed out; nobody may be listening.
            let _ = done_tx.send(true);
        });
    if let Err(e) = spawned {
        tracing::warn!(
            session,
            what,
            "blocking step: no thread could be made ({e})"
        );
        return Bounded::Failed(format!("no thread for {what}: {e}"));
    }
    match tokio::time::timeout(limit, &mut rx).await {
        Ok(Ok(out)) => {
            let took = started.elapsed();
            if took >= SLOW_STEP_AFTER {
                tracing::info!(
                    session,
                    what,
                    took_ms = took.as_millis() as u64,
                    limit_ms = limit.as_millis() as u64,
                    "blocking step done, slowly"
                );
            } else {
                tracing::debug!(
                    session,
                    what,
                    took_ms = took.as_millis() as u64,
                    "blocking step done"
                );
            }
            Bounded::Done(out)
        }
        Ok(Err(_)) => {
            tracing::error!(
                session,
                what,
                took_ms = started.elapsed().as_millis() as u64,
                "blocking step: its thread ended without a result (a panic)"
            );
            Bounded::Failed(format!("{what}: its thread ended without a result"))
        }
        Err(_) => {
            // The result may have landed between the timer and here: taken, not thrown away
            // unstopped. After `close` the thread's `send` fails and `on_late` gets it instead.
            rx.close();
            if let Ok(out) = rx.try_recv() {
                tracing::info!(
                    session,
                    what,
                    took_ms = started.elapsed().as_millis() as u64,
                    limit_ms = limit.as_millis() as u64,
                    "blocking step done just at its limit"
                );
                return Bounded::Done(out);
            }
            tracing::warn!(
                session,
                what,
                limit_ms = limit.as_millis() as u64,
                waited_ms = started.elapsed().as_millis() as u64,
                "blocking step did not return in time; given up (its thread is left to it, and \
                 undoes its result if one comes)"
            );
            // The time limit's warn stands for the first warn; the error bound is still watched.
            watch_job(name, done_rx, life, started, error_after, error_after);
            Bounded::TimedOut
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Condvar, Mutex};

    /// A gate a fake platform call waits at until the test opens it: a call that "never returns".
    #[derive(Default)]
    pub(crate) struct Gate {
        open: Mutex<bool>,
        cv: Condvar,
        /// Calls waiting at it now.
        pub(crate) waiting: AtomicU32,
    }

    impl Gate {
        pub(crate) fn wait(&self) {
            self.waiting.fetch_add(1, Ordering::SeqCst);
            let mut open = crate::sync::lock(&self.open);
            while !*open {
                open = self.cv.wait(open).unwrap_or_else(|p| p.into_inner());
            }
            drop(open);
            self.waiting.fetch_sub(1, Ordering::SeqCst);
        }

        pub(crate) fn open(&self) {
            *crate::sync::lock(&self.open) = true;
            self.cv.notify_all();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_detached_job_does_not_hold_the_caller_and_says_when_it_is_done() {
        let gate = Arc::new(Gate::default());
        let g = gate.clone();
        let t0 = Instant::now();
        let done = detach("test-stuck", "s1", move || g.wait());
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "returned at once"
        );
        assert!(!done.is_done());
        assert!(
            !done.clone().wait(Duration::from_millis(100)).await,
            "still stuck"
        );
        gate.open();
        assert!(done.wait(Duration::from_secs(5)).await, "done once let go");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_bounded_step_times_out_and_its_late_result_is_undone() {
        let gate = Arc::new(Gate::default());
        let undone = Arc::new(AtomicU32::new(0));
        let (g, u) = (gate.clone(), undone.clone());
        let t0 = Instant::now();
        let out = run_bounded(
            "test-start",
            "s1",
            Duration::from_millis(200),
            move || {
                g.wait();
                7u32
            },
            move |late| {
                u.fetch_add(late, Ordering::SeqCst);
            },
        )
        .await;
        assert!(matches!(out, Bounded::TimedOut), "{out:?}");
        assert!(t0.elapsed() < Duration::from_secs(2));
        gate.open();
        let deadline = Instant::now() + Duration::from_secs(5);
        while undone.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            undone.load(Ordering::SeqCst),
            7,
            "the late result is undone"
        );

        let quick = run_bounded("test-quick", "s1", Duration::from_secs(5), || 3u32, |_| {}).await;
        assert!(matches!(quick, Bounded::Done(3)), "{quick:?}");
    }

    /// No time left in the budget: the step is not started at all, so there is nothing to undo.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_step_with_no_time_left_is_skipped_unstarted() {
        let ran = Arc::new(AtomicU32::new(0));
        let undone = Arc::new(AtomicU32::new(0));
        let (r, u) = (ran.clone(), undone.clone());
        let out = run_bounded(
            "test-skipped",
            "s1",
            Duration::ZERO,
            move || {
                r.fetch_add(1, Ordering::SeqCst);
            },
            move |()| {
                u.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(matches!(out, Bounded::Failed(_)), "{out:?}");
        assert!(out.why_not().contains("no time left"), "{}", out.why_not());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(ran.load(Ordering::SeqCst), 0, "never started");
        assert_eq!(undone.load(Ordering::SeqCst), 0, "nothing to undo");
        assert_eq!(running("test-skipped"), 0);
    }

    /// A job past its error bound counts as abandoned until its work returns; a running job counts
    /// by its name until then. (The bounds are the watcher's own, short here.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_past_its_error_bound_counts_abandoned_until_it_returns() {
        let gate = Arc::new(Gate::default());
        let g = gate.clone();
        // `detach`'s own path and its own watcher, with short bounds.
        let life = Life::default();
        let done = detach_watched(
            Name {
                what: "test-abandon",
                session: "s1".into(),
                why: "-",
            },
            (Duration::from_millis(20), Duration::from_millis(60)),
            life.clone(),
            move || g.wait(),
        );
        assert_eq!(running("test-abandon"), 1, "running while its work waits");
        wait_for_life(&life, LIFE_ABANDONED, "said abandoned at its bound").await;
        // Other tests may abandon jobs of their own: at least this one is counted.
        assert!(abandoned() >= 1);
        assert_eq!(abandoned_of("test-abandon"), 1, "counted by its name");
        assert!(!done.is_done());

        gate.open();
        assert!(done.wait(Duration::from_secs(5)).await);
        assert_eq!(
            life.0.load(Ordering::SeqCst),
            LIFE_DONE,
            "no longer abandoned once it returned"
        );
        assert_eq!(abandoned_of("test-abandon"), 0);
        assert_eq!(
            running("test-abandon"),
            0,
            "no longer running once returned"
        );

        // A job that finished first is never counted.
        let quick = Life::default();
        assert!(!quick.finish("test-quick"));
        assert!(
            !quick.abandon("test-quick"),
            "too late to abandon a finished job"
        );
    }

    /// A detached job named `what`, stuck at `gate` and already abandoned (its watcher's bounds
    /// short): for the tests of what the abandoned counts decide.
    pub(crate) async fn abandoned_job(what: &'static str, gate: Arc<Gate>) -> JobDone {
        let life = Life::default();
        let done = detach_watched(
            Name {
                what,
                session: "test".into(),
                why: "-",
            },
            (Duration::from_millis(10), Duration::from_millis(30)),
            life.clone(),
            move || gate.wait(),
        );
        wait_for_life(&life, LIFE_ABANDONED, "the job abandoned").await;
        done
    }

    /// Wait until `life` is `want`, at most five seconds.
    async fn wait_for_life(life: &Life, want: u8, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while life.0.load(Ordering::SeqCst) != want {
            assert!(Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// A step that timed out and whose undo then hangs is still the job's: watched, counted
    /// abandoned at its error bound, and done only once the undo returns.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hanging_undo_counts_as_a_stuck_job() {
        let (work_gate, undo_gate) = (Arc::new(Gate::default()), Arc::new(Gate::default()));
        let (w, u) = (work_gate.clone(), undo_gate.clone());
        let life = Life::default();
        let out = tokio::time::timeout(
            Duration::from_secs(5),
            run_bounded_watched(
                "test-undo",
                "s1",
                Duration::from_millis(60),
                (Duration::from_millis(150), life.clone()),
                move || w.wait(),
                move |()| u.wait(),
            ),
        )
        .await
        .expect("the bounded step returns at its limit");
        assert!(matches!(out, Bounded::TimedOut), "{out:?}");
        // The work comes back late: its undo hangs.
        work_gate.open();
        let deadline = Instant::now() + Duration::from_secs(5);
        while undo_gate.waiting.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "the undo started");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        wait_for_life(
            &life,
            LIFE_ABANDONED,
            "a hanging undo is abandoned at the bound",
        )
        .await;
        assert_eq!(running("test-undo"), 1);
        undo_gate.open();
        wait_for_life(&life, LIFE_DONE, "done once the undo returns").await;
        let deadline = Instant::now() + Duration::from_secs(5);
        while running("test-undo") != 0 {
            assert!(Instant::now() < deadline, "no longer running");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
