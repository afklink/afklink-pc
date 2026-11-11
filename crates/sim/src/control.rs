//! The control task: one `QualityController`, one fixed 200 ms clock, `Feedback` assembled exactly
//! as `core/src/agent.rs` assembles it, and the agent's `pipeline` line once a second.
//!
//! ## Restated from `agent.rs` (the control task, `:1202-1893`)
//!
//! | here | `agent.rs` |
//! |---|---|
//! | state: the `prev_*` differencers, the pipeline line's window counters, receiver-report bookkeeping, brake-line rate limit, frame-dropper warning timers | `:1229-1263` |
//! | spend ratio against the budget actually handed out; drain from the transport's decaying peak and the estimate; keyframe bytes excluded from production; egress differenced from the monotonic counter | `:1345-1398` |
//! | queue age read once and republished to the encode side, and the drain rate with it (the keyframe window's) | `:1411-1412`; `set_drain_kbps` |
//! | the "rate control is not holding the rate" warning | `:1427-1446` |
//! | exactly one `ReceiverReport` per stats event, NACKs since the last one | `:1454-1474` |
//! | the `Feedback` literal | `:1475-1514` |
//! | the probe target (`take_probe_target` -> `SetDesiredBitrate`, confirmed with `probe_target_sent`) after the tick | the control task, after `quality.tick` |
//! | `tick`, then `take_bwe_reanchor` -> `ResetBwe`, `take_brake_event`, a move -> `target.set` | `:1553-1723` |
//! | drain mode published to the encode side (`set_draining`), its events logged, a keyframe on its end | the control task, right after `quality.tick` |
//! | the `pipeline` line, field for field and in the same order and quoting | `:1736-1883` |
//! | the budget published every tick | `:1890-1892` |
//! | the background hold: `HoldControl::tick` first, the desired bitrate it offers sent at once, the controller not ticked while frozen, a re-anchor held back until the ceiling from before the hold is back, `bg_hold_ms` on the line | the control task, `hold` (`afklink_core::bg_hold::HoldControl`) |
//! | `kf_suppressed`, last on the line: the viewer's PLIs the encode loop's window held | the `pipeline` line, `crate::encode_loop::Counters::keyframe_requests_suppressed` |
//!
//! Left out: the calibration sweep (never armed in a simulation). The viewer's resolution pin is
//! applied once, at the start, when the scenario sets `[viewer] pin_height` ([`ControlTask::pin`]).
//! `jbuf_ms` and `jitter_ms` print `-`: the simulated viewer has no jitter buffer to report.

use std::time::{Duration, Instant};

use afklink_core::bg_hold::{BgHold, HoldControl, HoldStep};
use afklink_core::quality::{
    drain_kbps, opening_probe_target_kbps_with, BrakeCause, BrakeEvent, DrainEvent, Feedback,
    Quality, QualityController, QualityPolicy, QualityTarget, Reanchor, ReanchorTrigger,
    ReceiverReport, Rung, ViewerFrames, TICK,
};

use crate::encode_loop::Counters;

/// `agent.rs:2173`.
const FD_WARN_RATIO: f32 = 0.10;
/// `agent.rs:2175`.
const FD_WARN_AFTER: Duration = Duration::from_secs(3);
/// `agent.rs:2178`.
const FD_WARN_EVERY: Duration = Duration::from_secs(10);
/// `agent.rs:2183`.
const BRAKE_TIGHTEN_LOG_EVERY: Duration = Duration::from_secs(5);

/// What the control task reads from the transport, `Peer`'s gauges and the counters the event task
/// fills from `PeerEvent`s.
#[derive(Debug, Clone, Copy, Default)]
pub struct Gauges {
    pub drain_kbps: u32,
    pub queue_age_ms: u32,
    pub egress_kbps: u32,
    pub egress_bytes_total: u64,
    pub discarded_frames: u32,
    pub estimate_kbps: u32,
    pub rtt_ms: u32,
    pub loss_bp: u32,
    pub plis: u64,
    pub nacks: u64,
    pub link_reports: u64,
    pub outstanding_bytes: u32,
}

/// What the control task asks of the peer, `PeerControl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    SetDesiredBitrate(u32),
    ResetBwe(u32),
    ResetBweAtNextFrame(u32),
    /// `PeerControl::ResetBweProbing`: a re-anchor whose opening probes may reach `probe_cap_kbps`.
    ResetBweProbing {
        kbps: u32,
        probe_cap_kbps: u32,
    },
}

/// One second as the `pipeline` line saw it, in numbers rather than text.
#[derive(Debug, Clone, Copy)]
pub struct Second {
    pub estimate_kbps: u32,
    pub budget_kbps: u32,
    pub produced_kbps: u32,
    pub egress_kbps: u32,
    pub queue_age_ms: u32,
    pub avg_qp: Option<f32>,
    pub rung: Rung,
    pub capacity_kbps: u32,
    pub collapse: &'static str,
    pub brake: &'static str,
    pub spend_ratio: f32,
}

/// One log line, with its level; the caller stamps the time.
#[derive(Debug, Clone)]
pub struct Line {
    pub level: &'static str,
    pub target: &'static str,
    pub text: String,
}

impl Line {
    fn info(text: String) -> Self {
        Self {
            level: "INFO",
            target: "afklink_core::agent",
            text,
        }
    }
    fn warn(text: String) -> Self {
        Self {
            level: "WARN",
            target: "afklink_core::agent",
            text,
        }
    }
}

/// Everything one tick decided.
#[derive(Debug, Clone)]
pub struct TickOutput {
    pub feedback: Feedback,
    pub commands: Vec<Command>,
    pub moved: Option<(Rung, &'static str)>,
    pub reanchor: Option<(u32, Option<Reanchor>)>,
    pub brake: Option<BrakeEvent>,
    pub second: Option<Second>,
    pub lines: Vec<Line>,
    /// Drain mode ended on this tick: the encode loop's next frame is a keyframe, as the agent's
    /// control task sets `pending_kf` (`agent.rs`, the drain event after `quality.tick`).
    pub resume_keyframe: bool,
    /// What this tick was as far as the background hold goes.
    pub hold: HoldStep,
}

/// The control task's state. See the module documentation.
pub struct ControlTask {
    quality: QualityController,
    desired_kbps: u32,
    qp_ceiling: Option<f32>,
    prev_bytes: u64,
    prev_egress_bytes: u64,
    prev_attempts: u64,
    prev_encode_us: u64,
    prev_key_bytes: u64,
    prev_qp_sum: u64,
    prev_qp_n: u64,
    log_ticks: u32,
    log_captured: u64,
    log_encoded: u64,
    log_bytes: u64,
    log_stale: u64,
    log_skipped: u64,
    log_errors: u64,
    log_discarded: u64,
    log_dropped_rate: u64,
    log_skipped_queue: u64,
    log_skipped_drain: u64,
    log_plis: u64,
    log_nacks: u64,
    log_kf_suppressed: u64,
    prev_link_reports: u64,
    prev_report_nacks: u64,
    brake_tighten_logged_at: Option<Duration>,
    brake_suppressed: u32,
    fd_high_since: Option<Duration>,
    fd_warned_at: Option<Duration>,
    hold: HoldControl,
    /// The viewer's latest `vv` report since the last tick, handed to the controller on the next
    /// one. See [`Self::note_viewer`].
    viewer_pending: Option<ViewerFrames>,
}

impl std::fmt::Debug for ControlTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlTask")
            .field("rung", &self.quality.current())
            .field("desired_kbps", &self.desired_kbps)
            .finish()
    }
}

/// `v.map_or("-", to_string)`, the agent's spelling for an absent number.
fn opt_u32(v: Option<u32>) -> String {
    v.map_or_else(|| "-".to_string(), |v| v.to_string())
}

fn rung_str(r: Rung) -> String {
    format!("{}p@{}", r.max_h, r.fps)
}

impl ControlTask {
    /// `agent.rs:1229-1263`, and the session setup the orchestrator does before it
    /// (`agent.rs:775-818`): `Balanced`, a controller priced on a guessed 1920x1080, and the
    /// opening probe target that goes with that guess (`opening_probe_target_kbps`, what the
    /// controller's own target is with nothing measured: the ladder's ceiling, for the opening).
    /// Returns the task and the first `SetDesiredBitrate` the orchestrator sends right after
    /// spawning the peer.
    ///
    /// On `policy`, as the agent's controller is on its session's.
    #[must_use]
    pub fn new(qp_ceiling: Option<f32>, policy: QualityPolicy) -> (Self, Command) {
        let quality_pref = Quality::default();
        let desired = opening_probe_target_kbps_with(&policy, 1920, 1080, quality_pref);
        let mut quality = QualityController::with_policy(1920, 1080, quality_pref, policy);
        // As the agent does: the controller compares its first probe target against what the
        // orchestrator sent at session start.
        quality.probe_target_sent(desired);
        let task = Self {
            quality,
            desired_kbps: desired,
            qp_ceiling,
            prev_bytes: 0,
            prev_egress_bytes: 0,
            prev_attempts: 0,
            prev_encode_us: 0,
            prev_key_bytes: 0,
            prev_qp_sum: 0,
            prev_qp_n: 0,
            log_ticks: 0,
            log_captured: 0,
            log_encoded: 0,
            log_bytes: 0,
            log_stale: 0,
            log_skipped: 0,
            log_errors: 0,
            log_discarded: 0,
            log_dropped_rate: 0,
            log_skipped_queue: 0,
            log_skipped_drain: 0,
            log_plis: 0,
            log_nacks: 0,
            log_kf_suppressed: 0,
            prev_link_reports: 0,
            prev_report_nacks: 0,
            brake_tighten_logged_at: None,
            brake_suppressed: 0,
            fd_high_since: None,
            fd_warned_at: None,
            hold: HoldControl::new(),
            viewer_pending: None,
        };
        (task, Command::SetDesiredBitrate(desired))
    }

    /// The viewer's `vv` report of the frames it received, as the agent's event task stores it for
    /// the control task (`SessionCounters::viewer_frames_received`): handed to the controller on the
    /// next tick, with how long ago it arrived.
    pub fn note_viewer(&mut self, r: ViewerFrames) {
        self.viewer_pending = Some(r);
    }

    #[must_use]
    pub fn controller(&self) -> &QualityController {
        &self.quality
    }

    /// The viewer pins a resolution, as the agent applies a pin from the Mini App: the controller
    /// switches to that height's ladder and the target follows it (`agent.rs`, the pin handler).
    pub fn pin(&mut self, height: u32, target: &QualityTarget) {
        match self.quality.set_pinned_height(Some(height)) {
            Some(rung) => {
                tracing::debug!(height, rung = %rung_str(rung), "viewer pinned a resolution");
                target.set(rung);
            }
            None => tracing::debug!(height, "viewer pin unchanged"),
        }
    }

    /// One 200 ms tick at virtual time `now` (`at` as an `Instant` on the virtual clock).
    /// `agent.rs:1277-1893`. `bg` is the session's background-hold cell.
    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    pub fn tick(
        &mut self,
        now: Duration,
        at: Instant,
        counters: &Counters,
        g: &Gauges,
        target: &QualityTarget,
        bg: &BgHold,
    ) -> TickOutput {
        let dt = TICK;
        let secs = dt.as_secs_f32();
        let mut lines = Vec::new();
        let mut commands = Vec::new();

        // The background hold first, as the agent's control task does; the desired bitrate it
        // offers goes out at once (the simulated peer never refuses).
        let hold = self.hold.tick(
            bg,
            &mut self.quality,
            at,
            g.estimate_kbps,
            self.desired_kbps,
        );
        if let Some(kbps) = self.hold.desired_to_send() {
            commands.push(Command::SetDesiredBitrate(kbps));
            self.hold.desired_sent(kbps);
            self.desired_kbps = kbps;
        }
        let frozen = hold.frozen();
        match hold {
            HoldStep::Started => lines.push(Line::info(format!(
                "background hold started by=\"{}\" rung={} estimate_kbps={} capacity_kbps={} \
                 desired_kbps={}",
                self.hold.started_by().map_or("-", |b| b.as_str()),
                rung_str(self.quality.current()),
                g.estimate_kbps,
                self.quality.capacity_kbps(),
                self.desired_kbps,
            ))),
            HoldStep::Resumed { held } => lines.push(Line::info(format!(
                "background hold ended held_ms={} estimate_kbps={} rung={} reanchor=\"{}\"",
                held.as_millis(),
                g.estimate_kbps,
                rung_str(self.quality.current()),
                self.quality
                    .last_reanchor()
                    .map_or("-", |r| r.trigger.as_str()),
            ))),
            HoldStep::Live | HoldStep::Frozen => {}
        }

        let bytes = counters.bytes_sent;
        let attempts = counters.encode_attempts;
        let encode_us = counters.encode_us_total;
        let qp_sum = counters.qp_sum;
        let qp_n = counters.qp_samples;
        let estimate_kbps = g.estimate_kbps;

        let allowed_bits = target.target_kbps().unwrap_or(0) as f32 * 1000.0 * secs;
        let produced_bits = (bytes.saturating_sub(self.prev_bytes) as f32) * 8.0;
        let drain = drain_kbps(g.drain_kbps, estimate_kbps);
        let key_bytes = counters.keyframe_bytes_total;
        let inter_bits =
            (produced_bits - (key_bytes.saturating_sub(self.prev_key_bytes) as f32) * 8.0).max(0.0);
        let egress_bits =
            (g.egress_bytes_total.saturating_sub(self.prev_egress_bytes) as f32) * 8.0;
        let (fd_ratio, fd_fullness) = target.frame_dropper();
        let queue_age_ms = g.queue_age_ms;
        target.set_queue_age_ms(queue_age_ms);
        // agent.rs: the drain rate too, for the encode loop's keyframe window.
        target.set_drain_kbps(drain);

        if fd_ratio > FD_WARN_RATIO && !frozen {
            let since = *self.fd_high_since.get_or_insert(now);
            if now.saturating_sub(since) >= FD_WARN_AFTER
                && self
                    .fd_warned_at
                    .is_none_or(|t| now.saturating_sub(t) >= FD_WARN_EVERY)
            {
                self.fd_warned_at = Some(now);
                lines.push(Line::warn(format!(
                    "rate control is not holding the rate: the frame dropper is, by throwing \
                     frames away drop_ratio=\"{fd_ratio:.2}\" fullness=\"{fd_fullness:.2}\" \
                     budget_kbps={} produced_kbps={} rung={}",
                    target.target_kbps().unwrap_or(0),
                    (inter_bits / secs / 1000.0) as u32,
                    rung_str(Rung {
                        max_h: target.max_h(),
                        fps: target.fps()
                    }),
                )));
            }
        } else {
            self.fd_high_since = None;
        }

        let report = if g.link_reports == self.prev_link_reports {
            None
        } else {
            self.prev_link_reports = g.link_reports;
            let nacks =
                u32::try_from(g.nacks.saturating_sub(self.prev_report_nacks)).unwrap_or(u32::MAX);
            self.prev_report_nacks = g.nacks;
            Some(ReceiverReport {
                rtt_ms: match g.rtt_ms {
                    u32::MAX => None,
                    v => Some(v),
                },
                loss: match g.loss_bp {
                    u32::MAX => None,
                    bp => Some(bp as f32 / 10_000.0),
                },
                nacks,
            })
        };
        let fb = Feedback {
            estimate_kbps,
            drain_kbps: drain,
            produced_kbps: (inter_bits / secs / 1000.0) as u32,
            egress_kbps: (egress_bits / secs / 1000.0) as u32,
            qp_samples: u32::try_from(qp_n.saturating_sub(self.prev_qp_n)).unwrap_or(u32::MAX),
            queue_age_ms,
            avg_qp: (qp_n > self.prev_qp_n)
                .then(|| (qp_sum - self.prev_qp_sum) as f32 / (qp_n - self.prev_qp_n) as f32),
            encode_ms: if attempts > self.prev_attempts {
                (encode_us - self.prev_encode_us) as f32
                    / (attempts - self.prev_attempts) as f32
                    / 1000.0
            } else {
                0.0
            },
            spend_ratio: if allowed_bits > 0.0 {
                produced_bits / allowed_bits
            } else {
                0.0
            },
            rung_fps_hint: target.fps() as f32,
            qp_ceiling: self.qp_ceiling,
            drop_ratio: fd_ratio,
            report,
        };
        self.prev_bytes = bytes;
        self.prev_egress_bytes = g.egress_bytes_total;
        self.prev_key_bytes = key_bytes;
        self.prev_attempts = attempts;
        self.prev_encode_us = encode_us;
        self.prev_qp_sum = qp_sum;
        self.prev_qp_n = qp_n;

        if let Some((sw, sh)) = target.source() {
            self.quality.set_source(sw, sh);
        }

        // What has gone to the transport — frames encoded less those it discarded, and their bytes —
        // and the viewer's report since the last tick: drain mode's current evidence, handed over
        // every tick as the agent's control task does.
        self.quality.note_frames_sent(
            counters
                .frames_encoded
                .saturating_sub(u64::from(g.discarded_frames)),
            counters.bytes_sent,
        );
        if let Some(r) = self.viewer_pending.take() {
            self.quality.note_viewer_frames(r);
        }

        // Frozen through a background hold: not ticked, and the report built above is dropped.
        let moved = if frozen {
            None
        } else {
            self.quality.tick(fb, dt)
        };

        // Drain mode, published for the encode loop, and its events, as the agent's control task
        // does right after the tick (`agent.rs`, "Drain mode, published before anything reads the
        // target again").
        let draining = self.quality.draining();
        if target.set_draining(draining) {
            tracing::debug!(draining, "drain flag published to the encode loop");
        }
        let mut resume_keyframe = false;
        if let Some(event) = self.quality.take_drain_event() {
            match event {
                DrainEvent::Entered {
                    rtt_ms,
                    ref_ms,
                    enter_at_ms,
                    by_silence,
                    sent_kbps,
                    budget_kbps,
                } => lines.push(Line::info(format!(
                    "drain mode entered: the network path is holding a backlog of frames already \
                     sent, so nothing more is encoded until it drains rtt_ms={rtt_ms} \
                     rtt_base_ms=\"{}\" enter_at_ms={enter_at_ms} by_silence={by_silence} \
                     sent_kbps={sent_kbps} budget_kbps={budget_kbps} estimate_kbps={} \
                     queue_age_ms={} rung={}",
                    opt_u32(ref_ms),
                    fb.estimate_kbps,
                    fb.queue_age_ms,
                    rung_str(Rung {
                        max_h: target.max_h(),
                        fps: target.fps()
                    }),
                ))),
                DrainEvent::Left {
                    why,
                    rtt_ms,
                    exit_below_ms,
                    held_ms,
                    peak_rtt_ms,
                    reports,
                    resume_kbps,
                } => {
                    resume_keyframe = true;
                    lines.push(Line::info(format!(
                        "drain mode left: resuming with a keyframe at a conservative budget \
                         why=\"{why}\" rtt_ms=\"{}\" exit_below_ms={exit_below_ms} \
                         held_ms={held_ms} peak_rtt_ms={peak_rtt_ms} reports={reports} \
                         resume_kbps={resume_kbps} estimate_kbps={} rung={}",
                        opt_u32(rtt_ms),
                        fb.estimate_kbps,
                        rung_str(Rung {
                            max_h: target.max_h(),
                            fps: target.fps()
                        }),
                    )));
                }
            }
        }

        // The probe target, after the tick as the agent sends it; the simulated peer never refuses.
        if let Some(want) = self.quality.take_probe_target() {
            commands.push(Command::SetDesiredBitrate(want));
            self.quality.probe_target_sent(want);
            self.hold.desired_sent(want);
            self.desired_kbps = want;
        }

        let mut reanchor = None;
        let taken = if self.hold.reanchor_may_go() {
            self.quality.take_bwe_reanchor()
        } else {
            None
        };
        if let Some(kbps) = taken {
            let r = self.quality.last_reanchor();
            let trigger = r.map_or("-", |r| r.trigger.as_str());
            let at_next_frame = r.is_some_and(|r| r.trigger.at_next_frame());
            // As the agent does: a re-anchor with a probe cap goes out as `ResetBweProbing`.
            let probe_cap = r.and_then(|r| r.probe_cap_kbps);
            commands.push(match (at_next_frame, probe_cap) {
                (true, _) => Command::ResetBweAtNextFrame(kbps),
                (false, Some(probe_cap_kbps)) => Command::ResetBweProbing {
                    kbps,
                    probe_cap_kbps,
                },
                (false, None) => Command::ResetBwe(kbps),
            });
            reanchor = Some((kbps, r));
            let msg = match r.map(|r| r.trigger) {
                Some(ReanchorTrigger::CleanCollapse) => {
                    "bwe re-anchor requested: the estimate collapsed to under half the capacity \
                     evidence while the receiver reports the path clean"
                }
                Some(ReanchorTrigger::DrainResume) => {
                    "bwe re-anchor requested: drain mode is over and the estimate our silence left \
                     is under the resume budget"
                }
                Some(ReanchorTrigger::OutageResume) => {
                    "bwe re-anchor requested: the receiver is back after an outage and reports the \
                     path clean, and the estimate the outage left is under two thirds of the \
                     capacity evidence"
                }
                Some(ReanchorTrigger::IdleClimb) => {
                    "bwe re-anchor requested: the ladder climbs on an idle screen on the capacity \
                     evidence, and the estimate our silence left is under half of it"
                }
                Some(ReanchorTrigger::HoldResume) => {
                    "bwe re-anchor requested: a background hold is over; str0m is restarted right \
                     before the resumed video's first frame, at the capacity evidence from before \
                     the hold or its estimate, whichever is larger, so its acknowledged rate is the \
                     video's and not the hold's padding"
                }
                Some(ReanchorTrigger::PathChange) => {
                    "bwe re-anchor requested: the media moved to a more direct path; str0m's \
                     opening probes run again on it from the live estimate, up to twice the probe \
                     target (probe_cap_kbps)"
                }
                _ => {
                    "bwe re-anchor requested: motion resumed after an application-limited pause, \
                     and the estimate our silence collapsed is under half the capacity evidence"
                }
            };
            lines.push(Line::info(format!(
                "{msg} trigger=\"{trigger}\" kbps={kbps} at_next_frame={at_next_frame} \
                 probe_cap_kbps=\"{}\" estimate_kbps={} ratio=\"{:.2}\" capacity_kbps={} \
                 rtt_ms=\"{}\" rtt_base_ms=\"{}\" loss_pct=\"{}\" spend_ratio=\"{:.2}\" rung={}",
                opt_u32(probe_cap),
                fb.estimate_kbps,
                f64::from(kbps) / f64::from(fb.estimate_kbps.max(1)),
                r.map_or(0, |r| r.capacity_kbps),
                opt_u32(r.and_then(|r| r.rtt_ms)),
                opt_u32(r.and_then(|r| r.rtt_base_ms)),
                r.and_then(|r| r.loss_pct)
                    .map_or_else(|| "-".to_string(), |l| format!("{l:.2}")),
                fb.spend_ratio,
                rung_str(Rung {
                    max_h: target.max_h(),
                    fps: target.fps()
                }),
            )));
        }

        let brake = self.quality.take_brake_event();
        if let Some(event) = brake {
            let (what, d) = match event {
                BrakeEvent::Engaged(d) => ("engaged", d),
                BrakeEvent::Tightened(d) => ("tightened", d),
                BrakeEvent::Released(d) => ("released", d),
            };
            let tightening = matches!(event, BrakeEvent::Tightened(_));
            let print = !tightening
                || self
                    .brake_tighten_logged_at
                    .is_none_or(|t| now.saturating_sub(t) >= BRAKE_TIGHTEN_LOG_EVERY);
            if print {
                if tightening {
                    self.brake_tighten_logged_at = Some(now);
                }
                let msg = match event {
                    BrakeEvent::Engaged(d) if d.cause == BrakeCause::Drain => {
                        "brake engaged: drain mode is over, so the budget resumes at a conservative \
                         share of what the receiver last confirmed, and releases as it reports the \
                         path clean"
                    }
                    BrakeEvent::Engaged(_) => {
                        "brake engaged: the receiver reports the link is not carrying what we \
                         send, so the budget is cut below the estimate"
                    }
                    BrakeEvent::Tightened(_) => {
                        "brake tightened: the next report still says the link is not carrying it"
                    }
                    BrakeEvent::Released(d) if d.cause == BrakeCause::Resumed => {
                        "brake released: it was set by silence alone, and the receiver is back and \
                         reports the path clean; congestion control is re-anchored at the capacity \
                         evidence"
                    }
                    BrakeEvent::Released(_) => {
                        "brake released: the ceiling has grown back to what the estimate allows"
                    }
                };
                lines.push(Line::info(format!(
                    "{msg} brake=\"{what}\" cause=\"{}\" loss_pct=\"{}\" rtt_ms=\"{}\" \
                     rtt_base_ms=\"{}\" budget_before_kbps={} budget_after_kbps={} \
                     estimate_kbps={} rung={} suppressed={}",
                    d.cause.as_str(),
                    d.loss_pct
                        .map_or_else(|| "-".to_string(), |l| format!("{l:.2}")),
                    opt_u32(d.rtt_ms),
                    opt_u32(d.rtt_base_ms),
                    d.before_kbps,
                    d.after_kbps,
                    fb.estimate_kbps,
                    rung_str(Rung {
                        max_h: target.max_h(),
                        fps: target.fps()
                    }),
                    self.brake_suppressed,
                )));
                self.brake_suppressed = 0;
            } else {
                self.brake_suppressed = self.brake_suppressed.saturating_add(1);
            }
        }

        let mut moved_out = None;
        if let Some(rung) = moved {
            let reason = self.quality.last_move_reason();
            lines.push(Line::info(format!(
                "quality changed rung={} estimate_kbps={} avg_qp=\"{}\" queue_age_ms={} \
                 encode_ms=\"{:.1}\" spend_ratio=\"{:.2}\" reason=\"{reason}\"",
                rung_str(rung),
                fb.estimate_kbps,
                fb.avg_qp
                    .map_or_else(|| "-".to_string(), |qp| format!("{qp:.1}")),
                fb.queue_age_ms,
                fb.encode_ms,
                fb.spend_ratio,
            )));
            target.set(rung);
            moved_out = Some((rung, reason));
        }

        let mut second = None;
        self.log_ticks += 1;
        if self.log_ticks * dt >= Duration::from_secs(1) {
            let lsecs = (self.log_ticks * dt).as_secs_f64();
            self.log_ticks = 0;
            let (offered, early) = target.take_capture_counts();
            let d = |now: u64, prev: &mut u64| {
                let out = now.saturating_sub(*prev);
                *prev = now;
                out
            };
            let captured = d(counters.frames_captured, &mut self.log_captured);
            let encoded = d(counters.frames_encoded, &mut self.log_encoded);
            let discarded = d(u64::from(g.discarded_frames), &mut self.log_discarded);
            let dropped_rate = d(counters.frames_dropped_rate, &mut self.log_dropped_rate);
            let skipped_queue = d(counters.frames_skipped_queue, &mut self.log_skipped_queue);
            let skipped_drain = d(counters.frames_skipped_drain, &mut self.log_skipped_drain);
            let kbps_window = d(bytes, &mut self.log_bytes) as f64 * 8.0 / lsecs / 1000.0;
            let plis = d(g.plis, &mut self.log_plis);
            let nacks = d(g.nacks, &mut self.log_nacks);
            let kf_suppressed = d(
                counters.keyframe_requests_suppressed,
                &mut self.log_kf_suppressed,
            );
            let stale = d(counters.frames_dropped_stale, &mut self.log_stale);
            let skipped = d(counters.frames_skipped_encoder, &mut self.log_skipped);
            let errors = d(counters.encode_errors, &mut self.log_errors);
            let q = &self.quality;
            let rung = Rung {
                max_h: target.max_h(),
                fps: target.fps(),
            };
            let budget = target.target_kbps().unwrap_or(0);
            lines.push(Line::info(format!(
                "pipeline offered_fps=\"{:.1}\" early={early} capture_fps=\"{:.1}\" \
                 encode_fps=\"{:.1}\" encode_ms=\"{:.1}\" discarded={discarded} avg_qp=\"{}\" \
                 fd_full=\"{fd_fullness:.2}\" fd_ratio=\"{fd_ratio:.2}\" \
                 dropped_rate={dropped_rate} skipped_queue={skipped_queue} kbps=\"{kbps_window:.0}\" \
                 egress_kbps={} budget_kbps={budget} estimate_kbps={} queue_age_ms={} \
                 in_flight={} rtt_ms=\"{}\" loss_pct=\"{}\" report_age_ms=\"{}\" \
                 rtt_base_ms=\"{}\" brake=\"{}\" \
                 brake_kbps=\"{}\" capacity_kbps={} collapse=\"{}\" jbuf_ms=\"-\" \
                 jitter_ms=\"-\" plis={plis} nacks={nacks} spend_ratio=\"{:.2}\" rung={} \
                 idr_bytes={} dropped_stale={stale} skipped_by_encoder={skipped} \
                 errors={errors} source={}x{} desired_kbps={} skipped_drain={skipped_drain} \
                 drain_ms={} bg_hold_ms={} kf_suppressed={kf_suppressed}",
                f64::from(offered) / lsecs,
                captured as f64 / lsecs,
                encoded as f64 / lsecs,
                fb.encode_ms,
                fb.avg_qp
                    .map_or_else(|| "-".to_string(), |qp| format!("{qp:.1}")),
                g.egress_kbps,
                fb.estimate_kbps,
                fb.queue_age_ms,
                g.outstanding_bytes,
                // `agent.rs` `rtt_field`: `-` when the last stats interval carried no report.
                if g.rtt_ms == u32::MAX || g.loss_bp == u32::MAX {
                    "-".to_string()
                } else {
                    g.rtt_ms.to_string()
                },
                match g.loss_bp {
                    u32::MAX => "-".to_string(),
                    bp => format!("{:.2}", f64::from(bp) / 100.0),
                },
                q.report_age()
                    .map_or_else(|| "-".to_string(), |a| a.as_millis().to_string()),
                opt_u32(q.rtt_base_ms()),
                q.brake_state(),
                opt_u32(q.brake_kbps()),
                q.capacity_kbps(),
                q.collapse_state(),
                fb.spend_ratio,
                rung_str(rung),
                counters.last_keyframe_bytes,
                counters.encoded_w,
                counters.encoded_h,
                self.desired_kbps,
                q.drain_held()
                    .map_or_else(|| "-".to_string(), |h| h.as_millis().to_string()),
                bg.current(at)
                    .map_or_else(|| "-".to_string(), |h| h.as_millis().to_string()),
            )));
            second = Some(Second {
                estimate_kbps: fb.estimate_kbps,
                budget_kbps: budget,
                produced_kbps: kbps_window as u32,
                egress_kbps: g.egress_kbps,
                queue_age_ms: fb.queue_age_ms,
                avg_qp: fb.avg_qp,
                rung,
                capacity_kbps: q.capacity_kbps(),
                collapse: q.collapse_state(),
                brake: q.brake_state(),
                spend_ratio: fb.spend_ratio,
            });
        }

        target.set_target_kbps(self.quality.encoder_target_kbps());

        TickOutput {
            feedback: fb,
            commands,
            moved: moved_out,
            reanchor,
            brake,
            second,
            lines,
            resume_keyframe,
            hold,
        }
    }
}
