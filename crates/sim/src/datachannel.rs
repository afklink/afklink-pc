//! The viewer's `vv` report over its data channel, as far as the agent's drain mode reads it.
//!
//! Once a second of its own clock the viewer reports how many frames it has received
//! (`framesReceived`) and its clock (`video.currentTime`, which a live stream's element advances in
//! real time — `d_ct_ms` 999-1001 straight through a recorded 2.3 s stall). The agent
//! reads the two against what it sent: see `afklink_core::quality::QualityController::note_viewer_frames`.
//!
//! ## What is modelled
//!
//! - The count: frames the viewer's str0m emitted so far — complete frames, as Chrome counts
//!   `framesReceived` — and the clock: virtual time since the session began, in ms.
//! - Delivery over the down link (viewer to agent), by that link's queue and delay at the moment the
//!   report is sent, in order. No datagram is put on the link: the run's packets are the ones it
//!   would have without the reports, so a run with the controller reading them differs from one
//!   without only where the controller decided differently.
//! - SCTP's window: at most [`SCTP_WINDOW`] reports unacknowledged. Each acknowledgement crosses the
//!   up link — behind our own media, by that link's queue and delay — as its report arrives, and a
//!   report made while the window is full waits for the acknowledgement that opens it, then goes
//!   with the others waiting. The bench's `3g-stall-100` shows that shape: whenever
//!   2-14 s of our data stood in the forward queue the reports came in bursts of four, 1-8 s late.
//!
//! Not modelled: SCTP's retransmission timer and congestion window beyond the count, the viewer's
//! other traffic on the association (input), loss of a report (a reliable channel delivers it
//! later). A sleeping page reports nothing ([`crate::scenario::AsleepViewer`]).

use std::collections::VecDeque;
use std::time::Duration;

use crate::link::Link;

/// The viewer's report cadence: `TELEMETRY_INTERVAL_MS`, once a second.
pub const REPORT_EVERY: Duration = Duration::from_secs(1);

/// When the first report goes out after the session starts: half a cadence in, so the reports and
/// the agent's once-a-second receiver reports are not in step (in one recorded session the `vv` reports arrived
/// at xx.42 and the stats events at xx.02).
pub const FIRST_REPORT_AFTER: Duration = Duration::from_millis(400);

/// Reports in flight at most before the viewer's SCTP waits for an acknowledgement: its initial
/// window, about four of these 0.6-0.9 kB messages (RFC 4960 `min(4*MTU, max(2*MTU, 4380))`). The
/// bench's bursts were of four.
pub const SCTP_WINDOW: usize = 4;

/// One report as made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// Frames the viewer had received when it made the report.
    pub received: u64,
    /// The viewer's clock then, ms.
    pub viewer_ms: u64,
    /// When it was made (virtual time).
    pub made_at: Duration,
}

/// The reports between the viewer and the agent. See the module documentation.
#[derive(Debug, Default)]
pub struct ViewerReports {
    next_report: Option<Duration>,
    /// Made, waiting for the window.
    waiting: VecDeque<Report>,
    /// Sent, with when each reaches the agent.
    to_agent: VecDeque<(Duration, Report)>,
    /// When each acknowledgement reaches the viewer.
    acks: VecDeque<Duration>,
    unacked: usize,
    last_arrival: Duration,
    last_ack: Duration,
    /// The latest report to reach the agent and when, not yet handed to the control task.
    arrived: Option<(Duration, Report)>,
    /// For the summary line: made, arrived, and the latest a report arrived after it was made.
    pub made: u64,
    pub delivered: u64,
    pub max_transit: Duration,
}

impl ViewerReports {
    /// The session began at `at`: the first report follows [`FIRST_REPORT_AFTER`] later.
    pub fn start(&mut self, at: Duration) {
        self.next_report = Some(at + FIRST_REPORT_AFTER);
    }

    /// When something next happens: a report made, one arriving, an acknowledgement arriving.
    #[must_use]
    pub fn next_event(&self) -> Option<Duration> {
        [
            self.next_report,
            self.to_agent.front().map(|(t, _)| *t),
            self.acks.front().copied(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Everything due at `now`. `received` is the viewer's count so far, `viewer_ms` its clock;
    /// `awake` false for a page that sleeps: it makes and sends nothing (an acknowledgement that
    /// reaches it still opens the window, for whenever it wakes).
    pub fn step(
        &mut self,
        now: Duration,
        received: u64,
        viewer_ms: u64,
        awake: bool,
        up: &Link,
        down: &Link,
    ) {
        // Arrivals at the agent first: each sends its acknowledgement back across the up link.
        while self.to_agent.front().is_some_and(|(t, _)| *t <= now) {
            let Some((at, r)) = self.to_agent.pop_front() else {
                break;
            };
            self.delivered += 1;
            self.max_transit = self.max_transit.max(at.saturating_sub(r.made_at));
            self.arrived = Some((at, r));
            let ack = (now + up.queue_delay(now) + up.config().delay).max(self.last_ack);
            self.last_ack = ack;
            self.acks.push_back(ack);
            tracing::trace!(
                at_s = now.as_secs_f64(),
                made_s = r.made_at.as_secs_f64(),
                received = r.received,
                ack_s = ack.as_secs_f64(),
                "viewer report reached the agent (simulated data channel)"
            );
        }
        while self.acks.front().is_some_and(|t| *t <= now) {
            self.acks.pop_front();
            self.unacked = self.unacked.saturating_sub(1);
        }
        if let Some(due) = self.next_report.filter(|t| *t <= now) {
            self.next_report = Some(due + REPORT_EVERY);
            if awake {
                self.made += 1;
                self.waiting.push_back(Report {
                    received,
                    viewer_ms,
                    made_at: now,
                });
            }
        }
        while awake && self.unacked < SCTP_WINDOW {
            let Some(r) = self.waiting.pop_front() else {
                break;
            };
            let at = (now + down.queue_delay(now) + down.config().delay).max(self.last_arrival);
            self.last_arrival = at;
            self.unacked += 1;
            self.to_agent.push_back((at, r));
        }
        if awake && !self.waiting.is_empty() {
            tracing::trace!(
                at_s = now.as_secs_f64(),
                waiting = self.waiting.len(),
                unacked = self.unacked,
                "viewer reports held: the data channel's window waits for acknowledgements"
            );
        }
    }

    /// The latest report to reach the agent since the last call, and when it did.
    pub fn take(&mut self) -> Option<(Duration, Report)> {
        self.arrived.take()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::{ViewerReports, FIRST_REPORT_AFTER, REPORT_EVERY, SCTP_WINDOW};
    use crate::link::{Capacity, Datagram, Link, LinkConfig, QueueLimit};
    use crate::rng::SimRng;

    fn link(name: &'static str, kbps: f64, delay_ms: u64) -> Link {
        let mut l = Link::new(
            name,
            LinkConfig {
                capacity: Capacity::Constant { kbps },
                delay: Duration::from_millis(delay_ms),
                queue: QueueLimit::Unlimited,
                ..LinkConfig::default()
            },
            SimRng::derive(1, 1),
        );
        l.set_ideal(false, Duration::ZERO);
        l
    }

    /// Run the reports to `until`, event by event; what reached the agent: (made, arrived).
    fn run(
        r: &mut ViewerReports,
        up: &Link,
        down: &Link,
        until: Duration,
    ) -> Vec<(Duration, Duration)> {
        let mut got = Vec::new();
        while let Some(t) = r.next_event().filter(|t| *t <= until) {
            r.step(
                t,
                0,
                u64::try_from(t.as_millis()).unwrap_or(0),
                true,
                up,
                down,
            );
            if let Some((at, rep)) = r.take() {
                got.push((rep.made_at, at));
            }
        }
        got
    }

    /// On a path with nothing queued a report reaches the agent a one-way trip after it is made,
    /// once a second.
    #[test]
    fn on_a_clear_path_reports_come_a_one_way_trip_late_once_a_second() {
        let (up, down) = (link("up", 10_000.0, 145), link("down", 10_000.0, 145));
        let mut r = ViewerReports::default();
        r.start(Duration::ZERO);
        let got = run(&mut r, &up, &down, Duration::from_secs(10));
        assert!(got.len() >= 9, "{got:?}");
        for (k, (made, at)) in got.iter().enumerate() {
            assert_eq!(*made, FIRST_REPORT_AFTER + REPORT_EVERY * k as u32);
            assert_eq!(at.saturating_sub(*made), Duration::from_millis(145));
        }
    }

    /// With twenty seconds of our data in the forward queue the acknowledgements wait behind it:
    /// four reports go, the rest wait for the window and then go together when it opens — the
    /// bench's late bursts.
    #[test]
    fn behind_a_forward_queue_reports_wait_for_the_window_and_come_in_a_burst() {
        let (mut up, down) = (link("up", 100.0, 145), link("down", 10_000.0, 145));
        let a: SocketAddr = ([10, 0, 0, 1], 1).into();
        // 250 kB into 100 kbit/s: twenty seconds of queue, our media ahead of every acknowledgement.
        for _ in 0..200 {
            up.send(
                Duration::ZERO,
                Datagram {
                    source: a,
                    destination: a,
                    contents: vec![0; 1_222],
                },
            );
        }
        let mut r = ViewerReports::default();
        r.start(Duration::ZERO);
        let got = run(&mut r, &up, &down, Duration::from_secs(15));
        assert_eq!(
            r.delivered, SCTP_WINDOW as u64,
            "only the window's worth arrived while the queue held the acknowledgements: {got:?}"
        );
        for (made, at) in &got {
            assert_eq!(at.saturating_sub(*made), Duration::from_millis(145));
        }
        run(&mut r, &up, &down, Duration::from_secs(25));
        assert!(r.delivered > 15, "the rest came once the window opened");
        assert!(
            r.max_transit > Duration::from_secs(10),
            "the fifth waited behind the queue: {:?}",
            r.max_transit
        );
    }
}
