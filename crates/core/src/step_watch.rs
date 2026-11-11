//! Which step the orchestrator is in, and since when: for a watcher outside the async runtime (the
//! desktop app's stall watch) to name a step that does not end.
//!
//! The orchestrator (`Agent::run`) is one task that does one thing at a time: a server message, a
//! command from the window, a session's signal, a tick. A step that blocks — a synchronous wait on a
//! runtime worker, an await that never ends — holds up everything behind it, the reconnect included
//! (seen in production: a superseded session left the link silent for seven minutes, and the log
//! said nothing of where the orchestrator was). The stall watch's runtime ticker cannot say it: the rest of the
//! runtime may run on.
//!
//! # How
//!
//! [`StepWatch::begin`] notes the step — what (`server_message`, `command`, `session_signal`, a
//! tick), its kind (the message's or command's), the session when there is one — and when it began;
//! the [`StepGuard`] it returns clears it when dropped, at the step's end. A step that may
//! legitimately take a while (a session's start, bounded by `offload::START_LIMIT`) is begun with
//! [`StepWatch::begin_with_budget`]: the watcher says nothing of it within its budget. A watcher
//! reads the step with [`StepWatch::current`] and judges its age.
//!
//! The note is behind a `std` mutex held only to copy or change it: never across an await or any
//! other wait, on either side, so the watcher can always read it while the orchestrator is stuck,
//! and the orchestrator never waits for the watcher. Steps begun inside others (none is today) are
//! kept as a stack: the innermost is the current one, and each guard removes its own step wherever
//! it is — so a guard dropped out of order (a defect: said at `warn`, and a `debug_assert`) never puts
//! back a step that already ended.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::sync::lock;

/// One step of the orchestrator's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Its number: a new step has a new one, so a watcher tells a step that lasts from two in a row.
    pub seq: u64,
    /// What the orchestrator is doing: `server_message`, `command`, `session_signal`, a tick.
    pub what: &'static str,
    /// The message's or command's kind (`session_request`, `kill_switch`, …); `-` for a tick.
    pub kind: &'static str,
    /// The session it is about, when it is about one.
    pub session: Option<String>,
    /// When it began.
    pub since: Instant,
    /// How long it may legitimately last (zero: no more than any step): a watcher says nothing of
    /// it before.
    pub budget: Duration,
}

/// The orchestrator's current step ([`Self::begin`]), for a watcher ([`Self::current`]).
#[derive(Debug, Default)]
pub struct StepWatch {
    seq: AtomicU64,
    /// The steps in progress, outermost first.
    steps: Mutex<Vec<Step>>,
}

impl StepWatch {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// A step begins now; it ends when the guard is dropped.
    pub fn begin(
        self: &Arc<Self>,
        what: &'static str,
        kind: &'static str,
        session: Option<&str>,
    ) -> StepGuard {
        self.begin_with_budget(what, kind, session, Duration::ZERO)
    }

    /// [`Self::begin`] for a step that may legitimately last `budget`.
    pub fn begin_with_budget(
        self: &Arc<Self>,
        what: &'static str,
        kind: &'static str,
        session: Option<&str>,
        budget: Duration,
    ) -> StepGuard {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let step = Step {
            seq,
            what,
            kind,
            session: session.map(str::to_string),
            since: Instant::now(),
            budget,
        };
        let mut steps = lock(&self.steps);
        if let Some(outer) = steps.last() {
            tracing::trace!(
                seq,
                what,
                kind,
                outer = outer.what,
                outer_kind = outer.kind,
                "orchestrator step begun inside another; the outer one is current again at its end"
            );
        }
        steps.push(step);
        drop(steps);
        StepGuard {
            watch: Arc::clone(self),
            seq,
        }
    }

    /// The step in progress (the innermost), if any: a copy, taken under the lock and nothing else.
    pub fn current(&self) -> Option<Step> {
        lock(&self.steps).last().cloned()
    }
}

/// Ends its step when dropped ([`StepWatch::begin`]).
#[derive(Debug)]
pub struct StepGuard {
    watch: Arc<StepWatch>,
    seq: u64,
}

impl Drop for StepGuard {
    fn drop(&mut self) {
        // Changed under the lock, said (and asserted) after it is let go.
        let out_of_order = {
            let mut steps = lock(&self.watch.steps);
            match steps.iter().rposition(|s| s.seq == self.seq) {
                Some(at) if at + 1 == steps.len() => {
                    steps.pop();
                    None
                }
                // An outer step ends while one begun inside it lasts: a defect (guards are
                // scoped). Removed where it is, so it is never made current again; the inner one
                // stays.
                Some(at) => {
                    let ended = steps.remove(at);
                    Some((Some(ended), steps.last().map_or("-", |s| s.what)))
                }
                None => Some((None, "-")),
            }
        };
        match out_of_order {
            None => {}
            Some((Some(ended), inner)) => {
                tracing::warn!(
                    seq = self.seq,
                    what = ended.what,
                    kind = ended.kind,
                    inner,
                    "orchestrator step ended before a step begun inside it (out of order); removed, \
                     the inner one stays current"
                );
                // Not while unwinding: a second panic in a drop aborts the process, and the
                // orchestrator's panic would take the app down instead of being supervised.
                if std::thread::panicking() {
                    tracing::debug!(
                        seq = self.seq,
                        "out-of-order step end while unwinding a panic: not asserted"
                    );
                } else {
                    debug_assert!(false, "orchestrator step guards dropped out of order");
                }
            }
            Some((None, _)) => tracing::warn!(
                seq = self.seq,
                "orchestrator step ended that was not noted (a defect); nothing changed"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_step_is_seen_while_it_lasts_and_gone_at_its_end() {
        let watch = StepWatch::new();
        assert_eq!(watch.current(), None);
        let first = {
            let _step = watch.begin("server_message", "session_request", Some("s1"));
            let seen = watch.current().expect("in a step");
            assert_eq!(
                (seen.what, seen.kind, seen.session.as_deref()),
                ("server_message", "session_request", Some("s1"))
            );
            assert_eq!(seen.budget, Duration::ZERO);
            seen.seq
        };
        assert_eq!(watch.current(), None, "ended with its guard");
        let _step = watch.begin_with_budget("server_message", "sdp", None, Duration::from_secs(15));
        let next = watch.current().expect("in a step");
        assert!(next.seq > first, "a new step has a new number");
        assert_eq!(next.session, None);
        assert_eq!(next.budget, Duration::from_secs(15));
    }

    #[test]
    fn a_step_inside_another_puts_the_outer_back() {
        let watch = StepWatch::new();
        let outer = watch.begin("command", "end_for_exit", None);
        let outer_seq = watch.current().expect("outer").seq;
        {
            let _inner = watch.begin("session_signal", "closed", Some("s2"));
            assert_eq!(watch.current().expect("inner").what, "session_signal");
        }
        assert_eq!(watch.current().expect("outer again").seq, outer_seq);
        drop(outer);
        assert_eq!(watch.current(), None);
    }

    /// Guards dropped out of order (a defect, asserted in debug builds): the outer step is removed
    /// where it is and never made current again once the inner one ends.
    #[test]
    #[cfg(not(debug_assertions))]
    fn guards_dropped_out_of_order_never_bring_back_an_ended_step() {
        let watch = StepWatch::new();
        let outer = watch.begin("command", "end_for_exit", None);
        let inner = watch.begin("session_signal", "closed", Some("s2"));
        drop(outer);
        assert_eq!(watch.current().expect("inner stays").what, "session_signal");
        drop(inner);
        assert_eq!(
            watch.current(),
            None,
            "the ended outer step is not put back"
        );
    }

    /// In a debug build the same out-of-order drop is caught by the assertion.
    #[test]
    #[cfg(debug_assertions)]
    fn guards_dropped_out_of_order_are_caught_in_a_debug_build() {
        let watch = StepWatch::new();
        let outer = watch.begin("command", "end_for_exit", None);
        let inner = watch.begin("session_signal", "closed", Some("s2"));
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(outer)));
        assert!(caught.is_err(), "the debug assertion fires");
        // The note was changed before the assertion: the outer step is gone, the inner stays.
        assert_eq!(watch.current().expect("inner stays").what, "session_signal");
        drop(inner);
        assert_eq!(
            watch.current(),
            None,
            "the ended outer step is not put back"
        );
    }

    /// Guards dropped out of order while a panic unwinds (a guard begun inside another, but dropped
    /// after it): said, never asserted — a second panic in a drop would abort the process.
    #[test]
    fn guards_dropped_out_of_order_while_unwinding_do_not_abort() {
        let watch = StepWatch::new();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Declared first, so dropped last: the inner step outlives the outer one.
            let mut inner = Vec::new();
            let _outer = watch.begin("command", "end_for_exit", None);
            inner.push(watch.begin("session_signal", "closed", Some("s2")));
            if std::hint::black_box(true) {
                panic!("a step panics (a test)");
            }
        }));
        assert!(caught.is_err(), "the test's own panic, not an abort");
        assert_eq!(watch.current(), None, "both steps are gone");
    }

    /// The watcher reads the step from another thread while the step's thread is stuck in it: the
    /// note's lock is never held across the step.
    #[test]
    fn the_step_is_read_from_another_thread_while_it_is_stuck() {
        let watch = StepWatch::new();
        let (stuck_tx, stuck_rx) = std::sync::mpsc::channel::<()>();
        let (began_tx, began_rx) = std::sync::mpsc::channel::<()>();
        let stepper = {
            let watch = Arc::clone(&watch);
            std::thread::spawn(move || {
                let _step = watch.begin("server_message", "session_end", Some("s3"));
                began_tx.send(()).expect("began");
                // Stuck until the test lets it go (bounded, so a failure cannot hang the run).
                let _ = stuck_rx.recv_timeout(std::time::Duration::from_secs(10));
            })
        };
        began_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the step began");
        let seen = watch.current().expect("read while it is stuck");
        assert_eq!((seen.what, seen.kind), ("server_message", "session_end"));
        stuck_tx.send(()).expect("let go");
        stepper.join().expect("stepper");
        assert_eq!(watch.current(), None);
    }
}
