//! The viewer's word for a running peer — its trickled ICE candidates and its re-offers — carried
//! from the orchestrator to the peer whole, and in the order the viewer sent it.
//!
//! ## A queue of their own
//!
//! Not the peer's control queue ([`crate::PeerControl`]): that one is sixteen deep and shared with
//! messages that are meant to be refused when it is full — the heartbeat and the cursor reports
//! (the next one supersedes them), the viewer's playout report (another follows in a second), the
//! bitrate ceiling the control task offers again on its next tick. A candidate is none of those: one
//! refused is a path ICE never tries, perhaps the only one there was.
//!
//! The bursts are real. Behind a slow VPN the answer waits its whole 1.5 s for a STUN reply; the
//! viewer trickles 26 candidates meanwhile, and the orchestrator — which serves one signaling
//! message at a time and is inside that wait — hands all of them over back to back the moment the
//! session exists, before the peer has taken any. In a sixteen-deep queue the last ten would be
//! dropped: every TCP and TLS relay of the viewer's four TURN servers, so a viewer that can reach
//! the PC only through TURN over TCP or TLS (common on restrictive networks) would never connect.
//!
//! A re-offer travels here too, for its place among the candidates. An ICE restart's candidates carry
//! the new generation's ufrag, and str0m rejects a candidate whose ufrag is not the current remote
//! one (`is-0.11.1/src/agent.rs`, `add_remote_candidate`), so they must reach it after the offer that
//! brings that ufrag: one FIFO for both. (A re-offer refused by a full queue would end the session
//! as `ice_restart_failed`.)
//!
//! ## Never waiting, bounded
//!
//! The orchestrator serves every session and the signaling socket from one task, so it never waits
//! on a peer: [`SignalSender::send`] does not block. What bounds the queue is [`SIGNAL_QUEUE_CAP`]
//! signals queued and not yet taken; past that a signal is refused, counted and handed back for the
//! caller to log, never held anywhere else. The peer takes one a turn of its run loop, hundreds of
//! turns a second, so only a peer that has stopped taking — or a viewer flooding it — gets near the
//! cap.
//!
//! What was queued, taken and refused, and the deepest the queue got, are counted ([`SignalCounts`])
//! and said on the peer's `ICE connected for the first time` and `webrtc peer loop ended` lines.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use afklink_protocol::IceCandidate;
use tokio::sync::mpsc;

/// How many of the viewer's signals a peer's queue holds, not yet taken, before it refuses more.
///
/// Four times the largest burst any one sender produces today. The Mini App's resume sends its offer
/// and then every local candidate it kept — at most 64 (`LOCAL_CANDIDATES_MAX`, `webrtc.ts`) — back
/// to back; the backend holds at most 64 frames for an agent whose socket went away
/// (`AGENT_BACKLOG_CAP`, `sessions.ts`) and flushes them the moment it is back; a first gathering
/// with four TURN servers is 26 to 40. So even two such bursts meeting
/// before the peer takes any fit, twice over. What it bounds is memory for a viewer that floods a
/// peer faster than it takes: at most this many candidates (a few hundred bytes each) or offers (a
/// few kilobytes each) waiting — a few megabytes at the very worst.
pub const SIGNAL_QUEUE_CAP: usize = 256;

/// The first depth worth a line of its own: a new deepest queue is said at this depth and at each
/// doubling of it (8, 16, 32, …), so a burst is a handful of lines whatever its size. Sixteen is
/// the depth of the whole control queue.
const DEPTH_WORTH_A_LINE: u32 = 8;

/// Orchestrator -> peer: what the viewer signalled for this session, in the order it signalled it.
/// See the module docs.
#[derive(Debug)]
pub enum PeerSignal {
    /// A trickle ICE candidate from the viewer.
    AddRemoteIce(IceCandidate),
    /// A new SDP offer from the viewer for this live session — in practice an ICE restart.
    ///
    /// `webrtc.ts` sends one (`createOffer({ iceRestart: true })`) when its connection fails, e.g.
    /// after the phone moved from Wi-Fi to LTE. It is applied to the running `Rtc`, answered with
    /// [`crate::PeerEvent::Answer`], and followed by a srflx discovery on the same socket: the one
    /// still running, continued into the new ICE generation, or a fresh one. A viewer that offers
    /// only relays gets the answer once that discovery has a mapping, within the relay-only answer
    /// budget (`stun::RELAY_ONLY_ANSWER_BUDGET`). A re-offer that cannot be applied ends the peer as
    /// [`crate::PeerEnd::RestartFailed`]. See `PeerLoop::renegotiate`.
    Renegotiate(String),
}

impl PeerSignal {
    /// What it is, for the log: `candidate` or `offer`.
    pub fn kind(&self) -> &'static str {
        match self {
            PeerSignal::AddRemoteIce(_) => "candidate",
            PeerSignal::Renegotiate(_) => "offer",
        }
    }
}

/// What became of the viewer's signals to one peer so far. See [`SignalSender::counts`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SignalCounts {
    /// Put in the queue: the orchestrator's, and the candidates the peer's own mDNS lookups feed
    /// back once resolved.
    pub queued: u32,
    /// Taken from the queue by the peer.
    pub taken: u32,
    /// Refused because the queue held [`SIGNAL_QUEUE_CAP`] signals the peer had not taken: lost.
    pub dropped: u32,
    /// The most signals the queue held at once.
    pub max_depth: u32,
}

/// The counters both ends share.
#[derive(Debug, Default)]
struct Tally {
    queued: AtomicU32,
    taken: AtomicU32,
    dropped: AtomicU32,
    max_depth: AtomicU32,
    /// Signals refused since the last one [`SignalSender::send`] queued.
    in_a_row: AtomicU32,
}

/// The orchestrator's end of a peer's signal queue ([`crate::Peer::signals`]).
#[derive(Debug, Clone)]
pub struct SignalSender {
    tx: mpsc::Sender<PeerSignal>,
    tally: Arc<Tally>,
}

/// The peer's end of its signal queue.
#[derive(Debug)]
pub struct SignalReceiver {
    rx: mpsc::Receiver<PeerSignal>,
    tally: Arc<Tally>,
}

/// What [`SignalSender::send`] did with a signal.
#[derive(Debug)]
pub enum SignalSent {
    /// Queued for the peer. `depth`: signals waiting now, this one among them. `new_high`: the
    /// queue was never this deep before, at a depth worth a line (8, and each doubling of it).
    /// `after_refusals`: how many signals in a row were refused right before this one — zero but
    /// after a run of [`SignalSent::Full`], which this one ends.
    Queued {
        depth: u32,
        new_high: bool,
        after_refusals: u32,
    },
    /// Refused and handed back: the queue holds [`SIGNAL_QUEUE_CAP`] signals the peer has not
    /// taken. `in_a_row`: refusals since the last signal queued, this one included; `dropped`:
    /// refusals over the peer's life.
    Full {
        signal: PeerSignal,
        in_a_row: u32,
        dropped: u32,
    },
    /// Refused and handed back: the peer has ended.
    Closed(PeerSignal),
}

/// A new peer's signal queue, [`SIGNAL_QUEUE_CAP`] deep: the orchestrator's end and the peer's.
/// Public so a test can stand in for a peer.
pub fn signal_queue() -> (SignalSender, SignalReceiver) {
    let (tx, rx) = mpsc::channel(SIGNAL_QUEUE_CAP);
    let tally = Arc::new(Tally::default());
    (
        SignalSender {
            tx,
            tally: tally.clone(),
        },
        SignalReceiver { rx, tally },
    )
}

impl SignalSender {
    /// Queue `signal` for the peer, never waiting: the orchestrator's way in. Says nothing itself —
    /// the caller knows the session and logs the outcome.
    pub fn send(&self, signal: PeerSignal) -> SignalSent {
        // Counted before it can be taken, and taken back if refused: on a multi-threaded runtime
        // the peer may take a signal before this returns, and `taken` must never read above
        // `queued`.
        self.tally.queued.fetch_add(1, Ordering::Relaxed);
        let sent = self.tx.try_send(signal);
        if sent.is_err() {
            self.tally.queued.fetch_sub(1, Ordering::Relaxed);
        }
        match sent {
            Ok(()) => {
                let depth = self.depth();
                let before = self.tally.max_depth.fetch_max(depth, Ordering::Relaxed);
                SignalSent::Queued {
                    depth,
                    new_high: depth > before
                        && depth >= DEPTH_WORTH_A_LINE
                        && depth.is_power_of_two(),
                    after_refusals: self.tally.in_a_row.swap(0, Ordering::Relaxed),
                }
            }
            Err(mpsc::error::TrySendError::Full(signal)) => SignalSent::Full {
                signal,
                in_a_row: self.tally.in_a_row.fetch_add(1, Ordering::Relaxed) + 1,
                dropped: self.tally.dropped.fetch_add(1, Ordering::Relaxed) + 1,
            },
            Err(mpsc::error::TrySendError::Closed(signal)) => SignalSent::Closed(signal),
        }
    }

    /// Queue `signal`, waiting for room: for a sender that may wait because it is not the
    /// orchestrator — the peer's own mDNS lookups, feeding a resolved candidate back from a task of
    /// their own. The queue's depth after it, or the signal back once the peer has ended.
    pub(crate) async fn send_waiting(&self, signal: PeerSignal) -> Result<u32, PeerSignal> {
        // As in `send`: counted before the peer can take it, taken back if the peer has ended.
        self.tally.queued.fetch_add(1, Ordering::Relaxed);
        if let Err(e) = self.tx.send(signal).await {
            self.tally.queued.fetch_sub(1, Ordering::Relaxed);
            return Err(e.0);
        }
        let depth = self.depth();
        self.tally.max_depth.fetch_max(depth, Ordering::Relaxed);
        Ok(depth)
    }

    /// Signals queued and not yet taken by the peer.
    pub fn depth(&self) -> u32 {
        u32::try_from(self.tx.max_capacity().saturating_sub(self.tx.capacity())).unwrap_or(u32::MAX)
    }

    /// How many the queue holds before it refuses: [`SIGNAL_QUEUE_CAP`].
    pub fn cap(&self) -> usize {
        self.tx.max_capacity()
    }

    /// What became of the signals so far.
    pub fn counts(&self) -> SignalCounts {
        SignalCounts {
            queued: self.tally.queued.load(Ordering::Relaxed),
            taken: self.tally.taken.load(Ordering::Relaxed),
            dropped: self.tally.dropped.load(Ordering::Relaxed),
            max_depth: self.tally.max_depth.load(Ordering::Relaxed),
        }
    }
}

impl SignalReceiver {
    /// The next signal, in order; `None` once every sender is gone. As cancel-safe as
    /// `mpsc::Receiver::recv`, which it wraps: the count moves in the same poll that takes the
    /// signal, so a `select!` that drops this future never loses one.
    pub async fn recv(&mut self) -> Option<PeerSignal> {
        let signal = self.rx.recv().await;
        if signal.is_some() {
            self.tally.taken.fetch_add(1, Ordering::Relaxed);
        }
        signal
    }

    /// The next signal if one is queued, without waiting. For a test standing in for a peer.
    pub fn try_recv(&mut self) -> Result<PeerSignal, mpsc::error::TryRecvError> {
        let signal = self.rx.try_recv()?;
        self.tally.taken.fetch_add(1, Ordering::Relaxed);
        Ok(signal)
    }
}

#[cfg(test)]
mod tests {
    use super::{signal_queue, PeerSignal, SignalCounts, SignalSent, SIGNAL_QUEUE_CAP};
    use afklink_protocol::IceCandidate;

    /// A relay candidate on its own port, so the order can be read back.
    fn relay(port: u16) -> PeerSignal {
        PeerSignal::AddRemoteIce(IceCandidate {
            candidate: format!(
                "candidate:3 1 udp 8959 203.0.113.9 {port} typ relay raddr 0.0.0.0 rport 0"
            ),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("abcd".into()),
        })
    }

    fn port_of(signal: &PeerSignal) -> u16 {
        match signal {
            PeerSignal::AddRemoteIce(c) => c
                .candidate
                .split_whitespace()
                .nth(5)
                .and_then(|p| p.parse().ok())
                .expect("a port"),
            PeerSignal::Renegotiate(_) => panic!("an offer, not a candidate"),
        }
    }

    /// A real burst and more: forty candidates and an offer handed over before the peer takes
    /// any are all kept, and come out in the order they went in, the offer in its place.
    #[test]
    fn a_burst_before_the_peer_takes_any_is_kept_whole_and_in_order() {
        let (tx, mut rx) = signal_queue();
        let mut highs = Vec::new();
        for port in 1..=40 {
            if port == 21 {
                assert!(matches!(
                    tx.send(PeerSignal::Renegotiate("v=0 a restart".into())),
                    SignalSent::Queued { depth: 21, .. }
                ));
                continue;
            }
            match tx.send(relay(port)) {
                SignalSent::Queued {
                    depth,
                    new_high,
                    after_refusals,
                } => {
                    assert_eq!(depth, u32::from(port), "nothing was taken yet");
                    assert_eq!(after_refusals, 0);
                    if new_high {
                        highs.push(depth);
                    }
                }
                other => panic!("candidate {port} not queued: {other:?}"),
            }
        }
        assert_eq!(
            highs,
            [8, 16, 32],
            "a new deepest queue said at 8 and each doubling"
        );
        assert_eq!(
            tx.counts(),
            SignalCounts {
                queued: 40,
                taken: 0,
                dropped: 0,
                max_depth: 40,
            }
        );
        for port in 1..=40 {
            let signal = rx.try_recv().expect("queued");
            if port == 21 {
                assert!(
                    matches!(signal, PeerSignal::Renegotiate(ref sdp) if sdp == "v=0 a restart")
                );
            } else {
                assert_eq!(port_of(&signal), port, "in the order sent");
            }
        }
        assert!(rx.try_recv().is_err(), "nothing else");
        assert_eq!(tx.counts().taken, 40);
        assert_eq!(tx.depth(), 0);
    }

    /// Past the cap a signal is refused, handed back and counted — nothing waits, nothing panics —
    /// and the first one queued after the peer takes again says how many in a row were refused.
    #[test]
    fn past_the_cap_signals_are_refused_counted_and_handed_back() {
        let (tx, mut rx) = signal_queue();
        assert_eq!(tx.cap(), SIGNAL_QUEUE_CAP);
        let cap = u16::try_from(SIGNAL_QUEUE_CAP).expect("small");
        for port in 1..=cap {
            assert!(matches!(tx.send(relay(port)), SignalSent::Queued { .. }));
        }
        for n in 1..=10u32 {
            match tx.send(relay(cap + u16::try_from(n).expect("small"))) {
                SignalSent::Full {
                    signal,
                    in_a_row,
                    dropped,
                } => {
                    assert_eq!((in_a_row, dropped), (n, n));
                    assert_eq!(port_of(&signal), cap + u16::try_from(n).expect("small"));
                }
                other => panic!("refusal {n} expected, got {other:?}"),
            }
        }
        assert_eq!(
            tx.counts(),
            SignalCounts {
                queued: 256,
                taken: 0,
                dropped: 10,
                max_depth: 256,
            }
        );

        // The peer takes one: there is room again, and the run of refusals is over.
        assert_eq!(port_of(&rx.try_recv().expect("queued")), 1);
        match tx.send(relay(1000)) {
            SignalSent::Queued {
                depth,
                after_refusals,
                ..
            } => assert_eq!((depth, after_refusals), (256, 10)),
            other => panic!("queued expected, got {other:?}"),
        }
        let rest: Vec<u16> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|s| port_of(&s))
            .collect();
        let expected: Vec<u16> = (2..=cap).chain([1000]).collect();
        assert_eq!(
            rest, expected,
            "the queued ones whole and in order, none of the refused"
        );
        assert_eq!(tx.counts().dropped, 10, "a refusal is not counted twice");
    }

    /// A peer that has ended takes nothing: the signal comes back, and is no drop.
    #[test]
    fn a_signal_for_an_ended_peer_is_handed_back_and_not_counted_as_dropped() {
        let (tx, rx) = signal_queue();
        drop(rx);
        assert!(matches!(tx.send(relay(1)), SignalSent::Closed(_)));
        assert_eq!(tx.counts(), SignalCounts::default());
    }

    /// The mDNS lookups' way in waits for room instead of being refused, and counts like any other.
    #[tokio::test]
    async fn a_lookups_signal_waits_for_room_and_is_counted() {
        let (tx, mut rx) = signal_queue();
        assert_eq!(tx.send_waiting(relay(7)).await.expect("open"), 1);
        assert_eq!(tx.counts().queued, 1);
        assert_eq!(port_of(&rx.recv().await.expect("queued")), 7);
        assert_eq!(tx.counts().taken, 1);
        drop(rx);
        assert!(
            tx.send_waiting(relay(8)).await.is_err(),
            "the peer has ended"
        );
    }
}
