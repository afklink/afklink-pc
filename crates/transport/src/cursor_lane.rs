//! The `cursor` channel against a viewer known to be out of reach: hold, newest only, and kick.
//!
//! ## The problem
//!
//! After a phone sleeps for half a minute and its ICE restart finds a path, video and input recover
//! at once, but nothing written on the `cursor` channel (heartbeats, cursor reports) can reach the
//! phone for up to a minute more. In sctp-proto (`sctp-proto-0.10.4/src/association/`), which str0m
//! runs the data channels on, while the viewer acknowledges nothing:
//!
//! - each T3-rtx expiry cuts the congestion window to one MTU (`on_retransmission_timeout`) and
//!   backs the timer off, 1 s doubling up to `RTO_MAX` 60 s; only a SACK of the earliest
//!   outstanding chunk resets it, and str0m's ICE restart does not touch SCTP;
//! - the channel's messages are unordered and never retransmitted, but stay counted in flight until
//!   the viewer acknowledges a FORWARD-TSN past them, so they fill the one-MTU window;
//! - a FORWARD-TSN goes out only when T3-rtx fires or a SACK arrives (`handle_sack`, RFC 3758
//!   C1–C3), and the viewer sends a SACK only for something it received.
//!
//! ## What this does
//!
//! While the channel's unacknowledged bytes (str0m's `buffered_amount`) have not gone down for
//! [`STALL_AFTER`] **and the viewer is known to be out of reach** ([`Gate`]: ICE lost the path, or
//! the page said it is hidden), the lane is **stalled**: heartbeats and cursor reports are held,
//! newest of each only, which keeps the window nearly empty. When the viewer is back — its data
//! arrives, or ICE restores the path — one held message (the smaller) is written at once as a
//! **kick**: it fits the window, the viewer's SACK of it makes sctp-proto send the FORWARD-TSN past
//! everything abandoned, and the next SACK frees the window and resets the timer. A round trip or
//! two instead of up to a minute. The stall ends on the first acknowledgement or when the gate
//! closes, and the held messages go out then.
//!
//! ## Why the gate
//!
//! Acknowledgements alone cannot tell a sleeping viewer from a congested one: behind a bloated 3G
//! queue holding heartbeats turns «Плохая связь» into «ПК не отвечает» (bench `3g-stall`:
//! heartbeats held 14.6 s). So silence alone writes straight through, and says so once. The page's
//! own `vis hidden` opens the gate, not the background hold's later "asleep": by then about 1 kB is
//! in flight and a kick would not fit. [`STALL_AFTER`] is under sctp-proto's least RTO (1 s); a
//! pointer moving fast as the phone falls asleep can still fill the window, and then the timer is
//! the way out. Pure logic and the clock it is handed; the peer loop (`crate::webrtc`) reads the channel, tells
//! the gate, logs and writes.

use std::time::{Duration, Instant};

/// Bytes outstanding on the `cursor` channel and none of them freed for this long: the viewer's
/// SCTP is not acknowledging. Above the slowest acknowledgement a working path gives — a round trip
/// of several hundred milliseconds over a TCP relay plus the receiver's 200 ms delayed SACK — and
/// under sctp-proto's least RTO, 1 s, after which the window is one MTU.
pub(crate) const STALL_AFTER: Duration = Duration::from_millis(800);

/// The least time between the first two kicks of one stall; it doubles with each kick after that,
/// up to [`KICK_GAP_MAX`]. A kick that went into a path still dead stays in flight and takes room,
/// so a viewer that keeps talking over a path that does not carry back gets a few, not one a
/// second.
pub(crate) const KICK_GAP: Duration = Duration::from_secs(1);

/// See [`KICK_GAP`].
pub(crate) const KICK_GAP_MAX: Duration = Duration::from_secs(8);

/// What rides the `cursor` channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Heartbeat,
    Cursor,
}

impl Kind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Heartbeat => "heartbeat",
            Kind::Cursor => "cursor_report",
        }
    }
}

/// What says the viewer is out of reach. Only while one of these holds may the lane hold anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Gate {
    /// ICE has lost the path, and it is not back yet.
    pub path_lost: bool,
    /// The viewer's page told us it is hidden (`vis hidden`), as the background hold has it.
    pub page_hidden: bool,
}

impl Gate {
    pub(crate) fn open(self) -> bool {
        self.path_lost || self.page_hidden
    }

    /// Why it is open, or "reachable".
    pub(crate) fn why(self) -> &'static str {
        match (self.path_lost, self.page_hidden) {
            (true, true) => "path_lost+page_hidden",
            (true, false) => "path_lost",
            (false, true) => "page_hidden",
            (false, false) => "reachable",
        }
    }
}

/// A stall that began, for its log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StallStarted {
    /// What says the viewer is out of reach.
    pub why: &'static str,
    /// Bytes written and not freed by a SACK.
    pub unacked: usize,
    /// Since the unacknowledged bytes last went down (or were none).
    pub silent: Duration,
    /// Stalls this session, this one included.
    pub stalls: u32,
}

/// A stall that ended, for its log line. Its held messages are in [`Step::write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StallEnded {
    pub stalled: Duration,
    pub unacked_at_start: usize,
    pub unacked: usize,
    /// "acknowledged" (bytes were freed), "nothing_outstanding", or "viewer_reachable" (the gate
    /// closed with the acknowledgements still silent: written straight through from here).
    pub how: &'static str,
    pub held_heartbeat: bool,
    pub held_cursor: bool,
    /// Messages a newer one of their kind replaced while held.
    pub superseded_heartbeats: u32,
    pub superseded_cursor: u32,
    pub kicks: u32,
}

/// Acknowledgements silent past [`STALL_AFTER`] while the viewer is not known to be out of reach:
/// nothing held. For its log line, once per silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnheldStarted {
    pub unacked: usize,
    pub silent: Duration,
}

/// That silence over: acknowledgements are back (or nothing is outstanding), or the gate opened and
/// a stall took over (`into_stall`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnheldEnded {
    /// From the last acknowledgement before it to now.
    pub silent: Duration,
    pub unacked: usize,
    pub into_stall: bool,
}

/// A kick, for its log line. Its message is the last of [`Step::write`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Kicked {
    /// What said the viewer is back: "viewer_data" or "path_restored".
    pub why: &'static str,
    pub kind: Kind,
    pub bytes: usize,
    pub unacked: usize,
    pub stalled: Duration,
    /// Kicks this stall, this one included.
    pub kicks: u32,
    /// The least wait before the next kick of this stall.
    pub next_gap: Duration,
}

/// What one look at the channel decided.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Step {
    pub started: Option<StallStarted>,
    pub ended: Option<StallEnded>,
    pub unheld_started: Option<UnheldStarted>,
    pub unheld_ended: Option<UnheldEnded>,
    pub kicked: Option<Kicked>,
    /// The message offered with this look was held, not written.
    pub held: bool,
    /// A held message of the same kind was replaced by the one offered.
    pub superseded: bool,
    /// To write now, in this order.
    pub write: Vec<(Kind, String)>,
}

#[derive(Debug)]
struct Stall {
    since: Instant,
    unacked_at_start: usize,
    heartbeat: Option<String>,
    cursor: Option<String>,
    superseded_heartbeats: u32,
    superseded_cursor: u32,
    /// A sign the viewer is back, not yet acted on.
    kick_wanted: Option<&'static str>,
    kicks: u32,
    last_kick: Option<Instant>,
}

impl Stall {
    fn held(&mut self, kind: Kind) -> &mut Option<String> {
        match kind {
            Kind::Heartbeat => &mut self.heartbeat,
            Kind::Cursor => &mut self.cursor,
        }
    }

    /// The least wait after the last kick before the next one.
    fn gap(&self) -> Duration {
        let doublings = self.kicks.saturating_sub(1).min(8);
        (KICK_GAP * 2u32.pow(doublings)).min(KICK_GAP_MAX)
    }
}

/// See the module docs.
#[derive(Debug)]
pub(crate) struct CursorLane {
    /// The unacknowledged bytes at the last look, plus what was written since.
    last_unacked: usize,
    /// When the unacknowledged bytes last went down, or were none.
    progress_at: Instant,
    gate: Gate,
    stall: Option<Stall>,
    /// A silence past [`STALL_AFTER`] written straight through: the last acknowledgement before it.
    unheld_since: Option<Instant>,
    stalls: u32,
}

impl CursorLane {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            last_unacked: 0,
            progress_at: now,
            gate: Gate::default(),
            stall: None,
            unheld_since: None,
            stalls: 0,
        }
    }

    pub(crate) fn stalled(&self) -> bool {
        self.stall.is_some()
    }

    pub(crate) fn gate(&self) -> Gate {
        self.gate
    }

    /// Stalled since, if stalled.
    pub(crate) fn stalled_for(&self, now: Instant) -> Option<Duration> {
        self.stall
            .as_ref()
            .map(|s| now.saturating_duration_since(s.since))
    }

    /// ICE lost the path, or has it back. `true` when that changed the gate; the caller looks at the
    /// channel next, which applies it.
    pub(crate) fn set_path_lost(&mut self, lost: bool) -> bool {
        let changed = self.gate.path_lost != lost;
        self.gate.path_lost = lost;
        changed
    }

    /// The viewer's page hidden, or visible again. As [`Self::set_path_lost`].
    pub(crate) fn set_page_hidden(&mut self, hidden: bool) -> bool {
        let changed = self.gate.page_hidden != hidden;
        self.gate.page_hidden = hidden;
        changed
    }

    /// Look at the channel — `unacked` is its `buffered_amount` now — with a message to send or
    /// none, and decide what to write.
    pub(crate) fn step(
        &mut self,
        unacked: usize,
        offered: Option<(Kind, String)>,
        now: Instant,
    ) -> Step {
        let mut step = Step::default();
        let freed = unacked < self.last_unacked;
        if unacked == 0 || freed {
            self.progress_at = now;
        }
        self.last_unacked = unacked;
        let silent = now.saturating_duration_since(self.progress_at);
        let ack_silent = unacked > 0 && silent >= STALL_AFTER;
        let hold = ack_silent && self.gate.open();

        if !hold {
            if let Some(stall) = self.stall.take() {
                let how = if ack_silent {
                    "viewer_reachable"
                } else if unacked == 0 {
                    "nothing_outstanding"
                } else {
                    "acknowledged"
                };
                step.ended = Some(StallEnded {
                    stalled: now.saturating_duration_since(stall.since),
                    unacked_at_start: stall.unacked_at_start,
                    unacked,
                    how,
                    held_heartbeat: stall.heartbeat.is_some(),
                    held_cursor: stall.cursor.is_some(),
                    superseded_heartbeats: stall.superseded_heartbeats,
                    superseded_cursor: stall.superseded_cursor,
                    kicks: stall.kicks,
                });
                let (first, second) = if ack_silent {
                    // Still unacknowledged: the smaller first, likelier to fit what is left.
                    (stall.cursor, stall.heartbeat)
                } else {
                    // Acknowledged: the heartbeat first, which tells the viewer the agent is alive.
                    (stall.heartbeat, stall.cursor)
                };
                let kinds = if ack_silent {
                    (Kind::Cursor, Kind::Heartbeat)
                } else {
                    (Kind::Heartbeat, Kind::Cursor)
                };
                if let Some(text) = first {
                    step.write.push((kinds.0, text));
                }
                if let Some(text) = second {
                    step.write.push((kinds.1, text));
                }
                if ack_silent {
                    // Written straight through from here; the stall's end line said so, and this
                    // silence's end gets its own.
                    self.unheld_since = Some(self.progress_at);
                }
            } else if ack_silent {
                if self.unheld_since.is_none() {
                    self.unheld_since = Some(self.progress_at);
                    step.unheld_started = Some(UnheldStarted { unacked, silent });
                }
            } else if let Some(since) = self.unheld_since.take() {
                step.unheld_ended = Some(UnheldEnded {
                    silent: now.saturating_duration_since(since),
                    unacked,
                    into_stall: false,
                });
            }
        } else if self.stall.is_none() {
            if let Some(since) = self.unheld_since.take() {
                step.unheld_ended = Some(UnheldEnded {
                    silent: now.saturating_duration_since(since),
                    unacked,
                    into_stall: true,
                });
            }
            self.stalls += 1;
            step.started = Some(StallStarted {
                why: self.gate.why(),
                unacked,
                silent,
                stalls: self.stalls,
            });
            self.stall = Some(Stall {
                since: now,
                unacked_at_start: unacked,
                heartbeat: None,
                cursor: None,
                superseded_heartbeats: 0,
                superseded_cursor: 0,
                kick_wanted: None,
                kicks: 0,
                last_kick: None,
            });
        }

        if let Some((kind, text)) = offered {
            match self.stall.as_mut() {
                Some(stall) => {
                    step.held = true;
                    if stall.held(kind).replace(text).is_some() {
                        step.superseded = true;
                        match kind {
                            Kind::Heartbeat => stall.superseded_heartbeats += 1,
                            Kind::Cursor => stall.superseded_cursor += 1,
                        }
                    }
                }
                None => {
                    // A held one just released is older than this: this one goes instead.
                    let before = step.write.len();
                    step.write.retain(|(k, _)| *k != kind);
                    step.superseded = step.write.len() < before;
                    step.write.push((kind, text));
                }
            }
        }

        if let Some(stall) = self.stall.as_mut() {
            let gap_ok = stall
                .last_kick
                .is_none_or(|at| now.saturating_duration_since(at) >= stall.gap());
            if let (Some(why), true) = (stall.kick_wanted, gap_ok) {
                // The smaller first: it is likelier to fit what is left of the window.
                let pick = if stall.cursor.is_some() {
                    Some(Kind::Cursor)
                } else if stall.heartbeat.is_some() {
                    Some(Kind::Heartbeat)
                } else {
                    None
                };
                if let Some(kind) = pick {
                    if let Some(text) = stall.held(kind).take() {
                        stall.kick_wanted = None;
                        stall.kicks += 1;
                        stall.last_kick = Some(now);
                        step.kicked = Some(Kicked {
                            why,
                            kind,
                            bytes: text.len(),
                            unacked,
                            stalled: now.saturating_duration_since(stall.since),
                            kicks: stall.kicks,
                            next_gap: stall.gap(),
                        });
                        step.write.push((kind, text));
                    }
                }
            }
        }
        step
    }

    /// A message of `bytes` was written: it is unacknowledged until a SACK frees it.
    pub(crate) fn wrote(&mut self, bytes: usize) {
        self.last_unacked += bytes;
    }

    /// The viewer shows it is back (`why`): while stalled, kick at the next look. `true` when that
    /// armed a kick that was not armed already.
    pub(crate) fn viewer_back(&mut self, why: &'static str) -> bool {
        match self.stall.as_mut() {
            Some(stall) if stall.kick_wanted.is_none() => {
                stall.kick_wanted = Some(why);
                true
            }
            _ => false,
        }
    }

    /// The channel closed or opened: forget the acknowledgements and the stall, held messages
    /// included (the gate stays: it is about the viewer, not the channel). What was held, for the
    /// log.
    pub(crate) fn reset(&mut self, now: Instant) -> Option<(Duration, bool, bool)> {
        self.last_unacked = 0;
        self.progress_at = now;
        self.unheld_since = None;
        self.stall.take().map(|s| {
            (
                now.saturating_duration_since(s.since),
                s.heartbeat.is_some(),
                s.cursor.is_some(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    fn hb(n: u32) -> Option<(Kind, String)> {
        Some((Kind::Heartbeat, format!("hb{n}")))
    }

    fn cp(n: u32) -> Option<(Kind, String)> {
        Some((Kind::Cursor, format!("cp{n}")))
    }

    fn texts(step: &Step) -> Vec<&str> {
        step.write.iter().map(|(_, t)| t.as_str()).collect()
    }

    /// A lane with a heartbeat written at `t0` and never acknowledged, and the gate as given.
    fn silent_lane(t0: Instant, gate: Gate) -> CursorLane {
        let mut lane = CursorLane::new(t0);
        lane.set_path_lost(gate.path_lost);
        lane.set_page_hidden(gate.page_hidden);
        assert_eq!(texts(&lane.step(0, hb(0), t0)), ["hb0"]);
        lane.wrote(300);
        lane
    }

    const LOST: Gate = Gate {
        path_lost: true,
        page_hidden: false,
    };
    const HIDDEN: Gate = Gate {
        path_lost: false,
        page_hidden: true,
    };

    #[test]
    fn the_gate_is_open_while_the_path_is_lost_or_the_page_hidden() {
        assert!(!Gate::default().open());
        assert_eq!(Gate::default().why(), "reachable");
        assert!(LOST.open() && HIDDEN.open());
        assert_eq!((LOST.why(), HIDDEN.why()), ("path_lost", "page_hidden"));
        let both = Gate {
            path_lost: true,
            page_hidden: true,
        };
        assert_eq!(both.why(), "path_lost+page_hidden");
        let mut lane = CursorLane::new(Instant::now());
        assert!(lane.set_page_hidden(true));
        assert!(!lane.set_page_hidden(true), "no change, no transition");
        assert!(lane.set_path_lost(true));
        assert_eq!(lane.gate(), both);
    }

    /// Acknowledgements that keep coming, however slowly, never stall the lane, gate open or not.
    #[test]
    fn a_viewer_that_acknowledges_never_stalls_the_lane() {
        let t0 = Instant::now();
        let mut lane = CursorLane::new(t0);
        lane.set_page_hidden(true);
        // 300 bytes written each 700 ms and freed 600 ms later: always something outstanding at
        // the look, never longer than STALL_AFTER without progress.
        let mut unacked = 0;
        for i in 0..20u32 {
            let now = t0 + MS(700) * i;
            let step = lane.step(unacked, hb(i), now);
            assert_eq!(texts(&step), [format!("hb{i}").as_str()], "{i}");
            assert!(step.started.is_none() && step.unheld_started.is_none() && !step.held);
            lane.wrote(300);
            unacked = 300;
        }
        assert!(!lane.stalled());
    }

    /// 3g-stall on the bench: a congested path whose acknowledgements stop for seconds while the
    /// viewer is visible and ICE has its path. Nothing is held — every message is written as it
    /// comes, as before the lane — and the silence is said once as it begins and once as it ends.
    #[test]
    fn acknowledgement_silence_alone_holds_nothing() {
        let t0 = Instant::now();
        let mut lane = silent_lane(t0, Gate::default());
        let step = lane.step(300, cp(1), t0 + MS(900));
        assert_eq!(
            step.unheld_started,
            Some(UnheldStarted {
                unacked: 300,
                silent: MS(900)
            })
        );
        assert!(step.started.is_none() && !step.held);
        assert_eq!(texts(&step), ["cp1"]);
        lane.wrote(90);
        for (i, at) in [(2, 5_000), (3, 9_000), (4, 14_000)] {
            let step = lane.step(390 + 90 * (i - 2), hb(i as u32), t0 + MS(at));
            assert_eq!(texts(&step), [format!("hb{i}").as_str()]);
            assert!(
                step.unheld_started.is_none() && step.started.is_none(),
                "said once"
            );
            lane.wrote(90);
        }
        assert!(!lane.stalled());
        // Acknowledged at last: the silence's end, with its length.
        let step = lane.step(100, None, t0 + MS(14_600));
        assert_eq!(
            step.unheld_ended,
            Some(UnheldEnded {
                silent: MS(14_600),
                unacked: 100,
                into_stall: false
            })
        );
        assert!(step.write.is_empty());
    }

    /// The same silence with ICE's path lost, or the page hidden: messages are held, newest of each
    /// kind only; the first acknowledgement writes them, the heartbeat first.
    #[test]
    fn a_silent_viewer_out_of_reach_stalls_the_lane_and_its_acknowledgement_releases_the_newest() {
        for gate in [LOST, HIDDEN] {
            let t0 = Instant::now();
            let mut lane = silent_lane(t0, gate);
            // Not freed yet, and not for long: written.
            assert_eq!(texts(&lane.step(300, cp(1), t0 + MS(500))), ["cp1"]);
            lane.wrote(90);
            // 800 ms with nothing freed: the stall starts, and this one is held.
            let step = lane.step(390, cp(2), t0 + MS(800));
            assert_eq!(
                step.started,
                Some(StallStarted {
                    why: gate.why(),
                    unacked: 390,
                    silent: MS(800),
                    stalls: 1
                })
            );
            assert!(step.held && step.write.is_empty() && step.unheld_started.is_none());
            assert!(lane.stalled());
            assert!(lane.step(390, cp(3), t0 + MS(1200)).superseded);
            let step = lane.step(390, hb(4), t0 + MS(1300));
            assert!(step.held && !step.superseded);
            assert!(lane.step(390, hb(5), t0 + MS(2300)).superseded);
            assert!(lane.step(390, None, t0 + MS(2400)).write.is_empty());
            // A SACK freed some bytes: over, the newest of each written, the heartbeat first.
            let step = lane.step(300, None, t0 + MS(3000));
            let ended = step.ended.expect("the stall ended");
            assert_eq!(ended.how, "acknowledged");
            assert_eq!(ended.stalled, MS(2200));
            assert_eq!(
                (ended.superseded_heartbeats, ended.superseded_cursor),
                (1, 1)
            );
            assert_eq!(texts(&step), ["hb5", "cp3"]);
            assert!(!lane.stalled());
        }
    }

    /// A silence written straight through becomes a stall the moment the gate opens: the lane looked
    /// at with nothing to send applies it.
    #[test]
    fn the_gate_opening_during_a_silence_starts_the_stall_at_once() {
        let t0 = Instant::now();
        let mut lane = silent_lane(t0, Gate::default());
        assert!(lane
            .step(300, hb(1), t0 + MS(1000))
            .unheld_started
            .is_some());
        lane.wrote(300);
        assert!(lane.set_path_lost(true));
        let step = lane.step(600, None, t0 + MS(1500));
        assert_eq!(
            step.unheld_ended,
            Some(UnheldEnded {
                silent: MS(1500),
                unacked: 600,
                into_stall: true
            })
        );
        assert_eq!(step.started.expect("stalled").why, "path_lost");
        assert!(lane.step(600, cp(2), t0 + MS(1600)).held);
    }

    /// The gate closing — the path back, the page visible — with the acknowledgements still silent
    /// ends the stall: what it held is written, the smaller first, and from there everything goes
    /// straight through until the acknowledgements come back.
    #[test]
    fn the_gate_closing_releases_the_stall_and_writes_straight_through() {
        let t0 = Instant::now();
        let mut lane = silent_lane(t0, HIDDEN);
        lane.step(300, hb(1), t0 + MS(900));
        lane.step(300, cp(2), t0 + MS(1000));
        assert!(lane.set_page_hidden(false));
        let step = lane.step(300, None, t0 + MS(1100));
        let ended = step.ended.expect("ended");
        assert_eq!(ended.how, "viewer_reachable");
        assert!(ended.held_heartbeat && ended.held_cursor);
        assert_eq!(texts(&step), ["cp2", "hb1"]);
        assert!(step.unheld_started.is_none(), "the end line says it");
        lane.wrote(300);
        let step = lane.step(600, cp(3), t0 + MS(1500));
        assert!(!step.held);
        assert_eq!(texts(&step), ["cp3"]);
        lane.wrote(90);
        // Acknowledged: the straight-through silence ends, counted from the last acknowledgement.
        let step = lane.step(0, None, t0 + MS(2000));
        assert_eq!(
            step.unheld_ended,
            Some(UnheldEnded {
                silent: MS(2000),
                unacked: 0,
                into_stall: false
            })
        );
    }

    /// The stall ends at a look that carries a message: the held one of that kind is older and is
    /// not written; the new one is.
    #[test]
    fn a_message_offered_as_the_stall_ends_replaces_the_held_one_of_its_kind() {
        let t0 = Instant::now();
        let mut lane = silent_lane(t0, LOST);
        lane.step(300, cp(1), t0 + MS(900));
        lane.step(300, hb(2), t0 + MS(1000));
        let step = lane.step(0, cp(3), t0 + MS(1500));
        assert_eq!(step.ended.expect("ended").how, "nothing_outstanding");
        assert!(step.superseded);
        assert_eq!(texts(&step), ["hb2", "cp3"]);
    }

    /// A sign the viewer is back kicks with one held message, the cursor report when there is one;
    /// later signs kick again only after a gap that doubles; none while not stalled.
    #[test]
    fn the_viewer_coming_back_kicks_with_one_held_message_and_the_kicks_space_out() {
        let t0 = Instant::now();
        let mut lane = silent_lane(t0, HIDDEN);
        assert!(
            !lane.viewer_back("viewer_data"),
            "nothing to kick: not stalled"
        );
        lane.step(300, hb(1), t0 + MS(900));
        lane.step(300, cp(2), t0 + MS(1000));
        assert!(lane.viewer_back("viewer_data"));
        assert!(!lane.viewer_back("path_restored"), "already armed");
        let step = lane.step(300, None, t0 + MS(1100));
        let kicked = step.kicked.expect("kicked");
        assert_eq!(kicked.why, "viewer_data");
        assert_eq!((kicked.kind, kicked.kicks), (Kind::Cursor, 1));
        assert_eq!(kicked.next_gap, KICK_GAP);
        assert_eq!(texts(&step), ["cp2"]);
        lane.wrote(3);
        // Still stalled (nothing freed yet); the heartbeat stays held. Another sign too soon: armed,
        // but no kick until the gap has passed.
        assert!(lane.stalled());
        assert!(lane.viewer_back("viewer_data"));
        assert!(lane.step(303, None, t0 + MS(1500)).kicked.is_none());
        let step = lane.step(303, None, t0 + MS(2100));
        let kicked = step.kicked.expect("kicked again");
        assert_eq!((kicked.kind, kicked.kicks), (Kind::Heartbeat, 2));
        assert_eq!(kicked.next_gap, KICK_GAP * 2);
        // Nothing held now: an armed kick waits for the next message and takes it.
        assert!(lane.viewer_back("viewer_data"));
        assert!(lane.step(306, None, t0 + MS(5000)).kicked.is_none());
        let step = lane.step(306, hb(3), t0 + MS(5100));
        assert_eq!(step.kicked.expect("kicked").kicks, 3);
        assert_eq!(texts(&step), ["hb3"]);
        // The gap stops doubling at its cap.
        let mut stall = Stall {
            since: t0,
            unacked_at_start: 0,
            heartbeat: None,
            cursor: None,
            superseded_heartbeats: 0,
            superseded_cursor: 0,
            kick_wanted: None,
            kicks: 30,
            last_kick: None,
        };
        assert_eq!(stall.gap(), KICK_GAP_MAX);
        stall.kicks = 0;
        assert_eq!(stall.gap(), KICK_GAP);
    }

    /// A closed channel forgets the stall and what it held; the gate, which is about the viewer,
    /// stays.
    #[test]
    fn a_reset_forgets_the_stall_and_keeps_the_gate() {
        let t0 = Instant::now();
        let mut lane = silent_lane(t0, LOST);
        lane.step(300, hb(1), t0 + MS(900));
        assert_eq!(lane.reset(t0 + MS(1000)), Some((MS(100), true, false)));
        assert!(!lane.stalled());
        assert_eq!(lane.gate(), LOST);
        assert_eq!(texts(&lane.step(0, cp(2), t0 + MS(1100))), ["cp2"]);
        assert_eq!(lane.reset(t0 + MS(1200)), None);
    }
}
