//! The quality controller's tuning: every number in [`crate::quality`] that is a judgement about
//! links, viewers and machines rather than a fact about the code around it.
//!
//! Here: the ladder and its pricing, the budget's shares, the dwells, the probe target's timings,
//! the re-anchor, brake and drain lines, the startup rules, the quantiser and processor lines. One
//! [`QualityPolicy`] per controller, handed over at construction
//! ([`crate::quality::QualityController::with_policy`]) and read on every tick.
//!
//! Compiled on purpose, and not here: values that size arrays (`EGRESS_WINDOW`,
//! `RTT_BASE_REPORTS`, `PATH_STEP_REPORTS`, `STARTUP_DRAIN_TICKS`, the delivery rings), filters
//! whose weights assume the 200 ms tick (`SIGNAL_ALPHA`, `LATE_ALPHA`), values that restate str0m,
//! the transport or the encoder (`PACING_FACTOR`, `STR0M_OPENING_KBPS`, `PROBE_QUIET_KBPS`,
//! `MIN_DESIRED_KBPS`/`MAX_DESIRED_KBPS`, `ABSOLUTE_FLOOR_KBPS`, `STARTUP_QUEUE_LIMIT_MS`), the
//! local queue guard (`QUEUE_GUARD_MS`), the pinnable heights, RustDesk's price table, and the
//! calibration sweep.
//!
//! Field docs name values in capitals: a capitalised name is the field (or, for a duration, the
//! field with `_ms` and the method without it) of the same name in lower case, so `DOWN_AFTER` is
//! [`QualityPolicy::down_after_ms`] / [`QualityPolicy::down_after`]. Names that stay compiled
//! (`QUEUE_GUARD_MS`, `LATE_ALPHA`, `LADDER`, ...) are constants of [`crate::quality`].
//!
//! Units: durations are whole milliseconds (`*_ms`, with a [`Duration`] accessor of the same name
//! less the suffix); rates are kbps; percentages are integers where the controller computes in
//! integers; shares and ratios are floats of the width the controller computes in, so the reference
//! values reproduce the controller's arithmetic bit for bit.

//!
//! ## The profile the server sends
//!
//! A session's policy comes with its `session_request` (`quality_profile`, contract
//! `quality-profile.ts`). [`QualityPolicy::from_wire`] checks it with the contract's bounds and
//! invariants, each failure at the contract's issue path, and any failure refuses the whole
//! profile, so a session never mixes the server's values with compiled ones.
//! [`SessionPolicy::for_session`] decides once per session and falls back to
//! [`QualityPolicy::fallback`]. Values are never logged: only the label (`"<id>.v<v>"`), the source
//! and the names of failed rules. The compiled fallback is a conservative profile
//! ([`QualityPolicy::safe`]); the tuned values ([`QualityPolicy::reference`]) are the server's and
//! the tests'.

use std::sync::Arc;
use std::time::Duration;

use afklink_protocol::metrics::QualityProfileSource;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[cfg(any(test, doc))]
use crate::quality::LADDER;
use crate::quality::{Quality, Rung, QUEUE_GUARD_MS};

/// Everything the quality controller is tuned by (see the module docs).
/// [`QualityPolicy::reference`] is the tuned profile; [`QualityPolicy::safe`] is compiled into the
/// agent for sessions without one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityPolicy {
    // ── ladder and pricing ────────────────────────────────────────────────────────────────────
    /// How bitrate scales when the frame rate drops, sub-linearly: the exponent on
    /// `fps / PRESET_FPS`.
    ///
    /// Not linear: with real content, twice the interval between frames means twice as much has
    /// changed, so each frame costs more (synthetic content with a fixed delta per frame suggests
    /// otherwise). Linear scaling promises savings that do not arrive and steps down into rungs the
    /// link still cannot carry. The square root matches LiveKit's measured `ScreenSharePresets`
    /// (720p at 30 fps 2.0 Mbps, at 5 fps 0.8 Mbps: six times fewer frames, 2.5 times fewer bits);
    /// per-step fits range 0.42 to 1.0, and 0.5 errs toward over-pricing a rung, the safe
    /// direction.
    pub fps_factor_exp: f64,
    /// [`Quality::Best`]'s share of what a resolution is "worth": RustDesk's `BR_BEST`.
    pub quality_ratio_best: f32,
    /// [`Quality::Balanced`]'s share, the default as in RustDesk (`BR_BALANCED`): two thirds keeps
    /// text crisp, and the third given back keeps a phone on a relay from being the bottleneck.
    pub quality_ratio_balanced: f32,
    /// [`Quality::Low`]'s share: RustDesk's `BR_SPEED`.
    pub quality_ratio_low: f32,
    /// The ladder, best first. The reference is [`LADDER`], whose comment is the argument for every
    /// rung and for the order.
    pub ladder: Vec<Rung>,
    /// Frame rates the ladder walks when the user has pinned a resolution.
    ///
    /// A pinned resolution still has to adapt, or the queue sits in front of the input packets; so
    /// the ladder becomes that resolution at falling frame rates, and smoothness gives way rather
    /// than responsiveness. Halving, like [`LADDER`]: a step saving less than its keyframe is worse
    /// than none. 60 is included so a pin on a fast link is not capped at half what it can carry.
    pub pinned_fps: Vec<u32>,
    /// The rung a session opens on, as an index into [`Self::ladder`]: the top (see [`LADDER`]).
    /// A link measured thin is handled later from measurements ([`STARTUP_DECIDE_AFTER`]), since
    /// nothing is measured at the opening.
    pub start_rung_index: usize,
    /// How far above the desktop price a rung may be pushed when the link allows. See
    /// [`Rung::absorbable_kbps`].
    ///
    /// Four: on a panning 1080p scene in camera mode (`afklink-encode/examples/usage_mode.rs`) the
    /// encoder sits at QP ~24 at 4000 kbps and hunts between 39 and 46 at 1500, so a game still
    /// buys quality well above three times the desktop price. A ceiling, not a target: a still or
    /// lightly scrolling screen produces a few hundred kbps whatever it is offered, so it costs a
    /// desktop nothing.
    pub absorb_ratio: f64,
    /// Headroom required before stepping up: the higher rung must fit with 25% to spare, or the
    /// controller oscillates around an estimate sitting on a rung's price, a keyframe each
    /// crossing.
    pub up_headroom: f64,

    // ── budget ────────────────────────────────────────────────────────────────────────────────
    /// The share of the measured estimate the encoder is allowed to target, as a percentage.
    ///
    /// Not all of it: a full link is a queue in front of the input packets. Ninety percent is the
    /// conventional margin (libwebrtc's pacer runs a comparable one) and covers the RTP, UDP and IP
    /// headers the encoder's byte count leaves out.
    pub spend_pct: u64,
    /// How far pushback may reduce the budget, as a fraction: a half, so the multiplier walks in
    /// `[0.5, 1.0]`. Wider than libwebrtc's `CongestionWindowPushbackController` (`[0.9, 1.0]`)
    /// because software encoding of screen content overshoots harder than a hardware encoder with a
    /// frame-level VBV. Bounded below: pushback reaching zero is a freeze.
    pub pushback_depth: f64,
    /// How much the budget may exceed a demonstrated-zero link, in kbps: the additive half of GCC's
    /// increase rule (`observed * 1.5 + 10 kbps` for the estimate). Larger than 10 because it also
    /// opens a session, before anything has left and while a 1080p keyframe must go out. 300 is
    /// about the bottom two rungs' price, and the multiplicative half reaches several megabits in
    /// four or five seconds.
    pub explore_margin_kbps: u32,
    /// The multiplicative half of the same bound, as a percentage of what the link has
    /// demonstrated: `demonstrated * 1.5 + EXPLORE_MARGIN_KBPS`, GCC's `observed * 1.5`, in integer
    /// arithmetic.
    pub explore_growth_pct: u64,
    /// How much of the estimate must actually be leaving before the estimate describes the link:
    /// str0m's ALR threshold (`bwe/alr_detector/`, 65%), below which throughput describes the
    /// application, not the path (libwebrtc reasons the same way).
    pub loaded_share_pct: u64,
    /// How far above the estimate egress may run and the estimate still be a measurement of the
    /// link, as a percentage.
    ///
    /// The lower bound alone has a hole: just after a pause the budget comes from the informative
    /// floor (say 4500) while the estimate is still a collapsed 700, and 4000 kbps leaving passes
    /// `4000 >= 0.65 x 700`, so the floor would drop to 700 before str0m re-measured anything.
    /// Sending four times the estimate is the estimate lagging, not confirmed.
    ///
    /// 110 is where the rates meet: the budget is [`SPEND_PCT`] of the estimate and the pacer
    /// drains at [`PACING_FACTOR`], 1.1x. Inside `[65%, 110%]` we sent what the estimate allowed
    /// and it went through; above, the estimate is behind us; below, we are application-limited.
    pub leading_share_pct: u64,
    /// How long the link must keep agreeing with the estimate before the agreement may lower
    /// [`QualityController::informative_kbps`].
    ///
    /// Testing the upper edge over [`EGRESS_WINDOW`] catches a quantity sweeping through the band,
    /// but a transition also lands in the band for a second or two, with the estimate collapsed and
    /// the ring flushed. Four recorded cases from one session:
    ///
    /// ```text
    /// 07:14:38-40  est 4752  egress 4544 / 4144 / 4435   the link carried 12712 ten seconds earlier;
    ///                                                    informative := 4752, decayed to 4367, and the
    ///                                                    re-anchor at 07:14:42 went out at that
    /// 07:15:48     est 3778  egress 4145 (110.0%)        exactly on the upper edge; informative := 3778
    ///                                                    and the 07:15:51 re-anchor fired at 3350
    /// 07:17:16     est 2118  egress 1387 (65.5%)         exactly on the lower edge; the 07:17:17
    ///                                                    re-anchor went out at 1820
    /// 07:15:53     est 1435  egress ~1600 over the second, one 200 ms tick inside the band
    ///                                                    -> informative 1435, and the 07:16:06 scroll
    ///                                                    was served a budget of 1344
    /// ```
    ///
    /// One window in the band is what a transition looks like; two seconds of windows is a link
    /// agreeing. Ten consecutive ticks, reset by one outside: a confirmation, not a dwell. Two
    /// seconds is [`DOWN_AFTER`] and [`MEASURED_WITHIN`], and costs at most 7% of the floor against
    /// [`INFORMATIVE_HALF_LIFE`]. Only lowering is gated: an estimate above the floor under load is
    /// evidence in the direction that cannot hurt, applied at once.
    pub loaded_confirm_ms: u32,
    /// Below this much egress the ALR ratio is noise, in kbps. A still desktop sends 5 to 15 kbps
    /// of keep-alive and padding and the estimate decays with it, so the ratio can cross 65% with
    /// nothing asked of the link. 300 kbps is [`EXPLORE_MARGIN_KBPS`], the bottom two rungs' price.
    pub loaded_floor_kbps: u32,
    /// How long a link measurement taken under load stays worth believing, once the load stops: a
    /// half-life, not an expiry (see [`QualityController::informative_kbps`]). Twenty seconds
    /// covers the reading pauses people take (7 to 26 s measured) without letting a half-minute-old
    /// measurement set the budget after the network has changed.
    pub informative_half_life_ms: u32,
    /// Below this share of [`QualityController::informative_kbps`] the sender is
    /// application-limited, as a percentage: both what the encoder produced and what left the
    /// socket in the window.
    ///
    /// Against the informative rate, not the estimate, which collapses with the silence (egress 48
    /// against an estimate already down to 1186 would not look like a pause). A quarter falls
    /// between the recorded populations, per second of the pipeline line (the larger of
    /// `egress_kbps` and `kbps`):
    ///
    /// ```text
    /// pauses        Wi-Fi, recording A: three pauses of 2-7 s           <= 7.2% of 10306
    ///               recording B: two pauses of 4-10 s                   <= 10% of ~10000
    ///               recording C: one pause of 7 s                       <= 11% of ~7100
    /// busy thin     3G, recording A: 108 s                              >= 34% of 941, except
    ///                                                                    one second at 17%
    /// ```
    ///
    /// The busy 3G link's one second under the line was a stall (7% loss, 539 ms) between ordinary
    /// traffic, which [`REANCHOR_AFTER_PAUSE`] does not count as a pause.
    pub app_limited_pct: u64,

    // ── dwells ────────────────────────────────────────────────────────────────────────────────
    /// How long a rung is left alone after the ladder moves to it.
    ///
    /// The first frame after a resolution change is an IDR (28 to 55 kB at 1080p, most of a second
    /// on a 500 kbps relay). Three seconds clears the largest measured keyframe on the slowest link
    /// the ladder serves, while a failing rung still goes within seconds.
    ///
    /// The queue filter ([`LATE_ALPHA`], five seconds) is not fed during the settle and starts from
    /// zero after it: otherwise it remembers the keyframe (a 63 kB keyframe behind a ~110 kbps
    /// pacer drained in 1.6 s and the filter still read 83 ms, so `queue_late` shed the rung four
    /// frames in). The faster filters are fed as usual: their memory of the keyframe is an eighth
    /// by the end, and `growing` excludes keyframe bytes. When the receiver reports trouble (loss,
    /// a queue at the brake's line, a brake) the ladder reads a filter fed through the settle
    /// ([`QualityController::late_for_ladder`]).
    pub settle_after_move_ms: u32,
    /// How long a descent condition must hold before the rung falls: two seconds, as dwell rather
    /// than unanimity (see `accumulate`). Short, because an undelivered rung costs the viewer now,
    /// and a step down is cheap: cadence holds across the first rungs, so only pixels change.
    pub down_after_ms: u32,
    /// How long a climb condition must hold before the rung rises.
    ///
    /// Slow to probe and quick to yield, but twice [`DOWN_AFTER`], not four times. Recovery costs
    /// `(UP_AFTER + SETTLE_AFTER_MOVE)` per rung; at eight seconds a recorded pinned ladder
    /// climbed:
    ///
    /// ```text
    /// 18:23:02 -> 1080p@8    the bottom
    /// 18:23:13 -> 1080p@15   +11 s
    /// 18:23:24 -> 1080p@30   +11 s
    /// ```
    ///
    /// Six rungs on the full ladder would be a minute. Waiting does not help: the estimate went
    /// 1107 -> 1640 -> 2185, 1.5x per climb, because it is bounded by acknowledged traffic and we
    /// send more only when the rung rises.
    ///
    /// Four seconds is the slowest signal the climb gate reads: `roomy` requires
    /// `late_smoothed * 3 < QUEUE_GUARD_MS`, and `late_smoothed` has a time constant of about five
    /// seconds ([`LATE_ALPHA`]); a shorter dwell decides before its own filter has settled. A wrong
    /// climb costs [`DOWN_AFTER`] plus one keyframe. A field, not derived from `LATE_ALPHA`, so a
    /// policy can make that trade knowingly.
    pub up_after_ms: u32,

    // ── probe target ──────────────────────────────────────────────────────────────────────────
    /// The probe target as a multiple of the capacity evidence and, before there is any, of the
    /// best estimate seen. See [`QualityController::probe_target_kbps`].
    ///
    /// str0m probes for at least 15 ms (`min_probe_duration`, `bwe/probe/control.rs:669`), so at a
    /// bottleneck of capacity `C` a probe at rate `P` puts `(P - C) x 15 ms` into its buffer, and a
    /// buffer of `B` ms holds that while `P <= C x (1 + B / 15 ms)`. The shallowest recorded
    /// buffer, a 3G link modelled at 60 ms (`crates/sim/scenarios/3g-0919.toml`), holds five times
    /// capacity. The periodic ALR probe is twice desired, so desired may be at most 2.5x; two
    /// leaves a fifth of that buffer for queued media.
    ///
    /// Two caps nothing str0m does on a healthy link: its exponential probing goes to twice the
    /// estimate (`further_exponential_probe_scale`), and the evidence is at least the estimate on
    /// every clean tick, so four times the evidence is above every exponential probe. Discovery
    /// stays geometric: a probe that goes through lifts the estimate, the evidence and the next
    /// probe.
    pub probe_capacity_multiple: u32,
    /// How far the probe target must have moved from what str0m was last told before it is told
    /// again, as a percentage. Twenty: evidence decaying at 3.4% a second
    /// ([`INFORMATIVE_HALF_LIFE`]) re-sends about once per periodic probe interval rather than
    /// every tick, and a probe within a fifth of the last is not a different measurement. A brake's
    /// cut or a probe's success moves it far more.
    pub probe_target_change_pct: u64,
    /// The least time between two probe-target updates.
    ///
    /// One second, str0m's stats interval here and so the cadence of the receiver reports that move
    /// the evidence. A rise while str0m is application-limited fires an allocation probe
    /// (`maybe_increase_alr`, bounded by twice the estimate), so this also bounds those.
    ///
    /// Three moves go out on the tick they are decided:
    ///
    /// - The end of the opening ([`PROBE_OPENING`]): it must reach the peer before str0m's first
    ///   periodic probe.
    /// - A rise before any capacity evidence: the target is twice the best estimate, raised by
    ///   str0m's own exponential probes, each held to twice the target (`queue_probe`); a target a
    ///   second behind would stall the climb.
    /// - A rise in the ramp ([`PROBE_RAMP`]): the first seconds of media on a path, while the
    ///   estimate is at its highest, with no brake and no real loss.
    pub probe_target_every_ms: u32,
    /// How long, in media time on a path, the probe target stays at the ladder's ceiling while
    /// str0m runs its opening: from the session's start, and from a path re-probe
    /// ([`ReanchorTrigger::PathChange`]), until this long after media first flows (`warm`; on a
    /// re-probe the clock starts at the re-probe).
    ///
    /// str0m 0.24.1's opening (`bwe/probe/control.rs`) queues clusters at 3x and 6x its estimate
    /// (1800 and 3600 from our 600, `maybe_initial`, 278-291), then one at twice the estimate each
    /// time the estimate returns at 70% of the last probe or more (`maybe_exponential`, 293-329).
    /// Each is held to twice desired when queued (`queue_probe`, 529-532), and one that would
    /// exceed it is dropped (320-323). We see results only through str0m's three-second smoother on
    /// our next tick, so a target that follows the estimate binds exactly when probing wants to go
    /// on. In the simulator's `smoke` (5 Mbps), at the ceiling probes went out at 1800, 3600 and
    /// 7006 kbps within 260 ms; at the floor the follow-up waited, measured under 70% of its rate,
    /// ended the exponential phase, and left an estimate of 1774 at one second against 2983 (on
    /// bench relayed links: 2090 against 3600 kbps sent in the first seven seconds).
    ///
    /// The ceiling costs a thin link nothing in these seconds: the only probes that ignore the
    /// estimate (periodic, `maybe_periodic_alr`, 374-396, and large-drop, `maybe_large_drop`,
    /// 482-527) wait five seconds after the last probe (`MIN_TIME_BETWEEN_ALR_PROBES`), and the
    /// rest are bounded by the estimate.
    ///
    /// Three seconds ends before those five: media flows within a tick of the opening probes (they
    /// are egress over [`MEDIA_EGRESS_KBPS`]), so the window ends at most 3.4 s after them, and its
    /// end goes out at once whatever [`PROBE_TARGET_EVERY`] says ([`PROBE_OPENING_LATEST`] if media
    /// never flows). It is long enough for the three doublings from 3600 to twice the ceiling, each
    /// a round trip and a feedback interval.
    pub probe_opening_ms: u32,
    /// The latest a session's opening ends when its media never flows. [`PROBE_OPENING`] runs on
    /// media time, and without this a session sending nothing (a capture that delivers nothing, the
    /// opening probes split across ticks under [`MEDIA_EGRESS_KBPS`]) would keep the ceiling while
    /// str0m sent periodic probes at twice it. Ten seconds, because ICE through a relay and a DTLS
    /// retransmit take seconds and the opening probes wait for DTLS.
    pub probe_opening_latest_ms: u32,

    // ── re-anchor ─────────────────────────────────────────────────────────────────────────────
    /// How long the sender must have been application-limited before its resume may re-anchor.
    ///
    /// Two seconds, [`DOWN_AFTER`]. A collapse in silence is str0m bounded by `acked * 1.5 + 10
    /// kbps` (`bwe/delay/rate_control.rs:191`) on padding, and takes seconds (recorded: 16168 ->
    /// 1866 over eight still seconds, 6694 -> 1039 over five). One still second cannot produce it;
    /// a burst after one is our own queue.
    pub reanchor_after_pause_ms: u32,
    /// How long after motion resumes a re-anchor may still fire.
    ///
    /// Two seconds: the estimate read here is str0m's three-second smoothed value
    /// (`bwe/smoother.rs`), emitted only on a 5% move, so the collapsed value can surface late
    /// (recorded 0.2 to 1.2 s after motion came back). Not longer: further into real traffic the
    /// estimate is congestion control reacting to it, and only the divergence and receiver gates
    /// ([`CLEAN_RTT_FOR`], [`REAL_LOSS_MEMORY`]) would stand between a reset and an overridden 3G
    /// link.
    pub reanchor_resume_window_ms: u32,
    /// How far the re-anchor value must be above the live estimate, as a percentage, after it has
    /// been clamped to what the rung can absorb.
    ///
    /// Two. str0m decreases to `0.85 x acked` (`bwe/delay/rate_control.rs:17,250`) and increases by
    /// up to `observed * 1.5 + 10 kbps` (`:191`), so a healthy estimate breathes by tens of
    /// percent. In one recorded set of nineteen re-anchors, fifteen were at ratios of 1.19 to 1.96
    /// (all eight on 3G, five followed within six seconds by 1.75-25.6% loss), while genuine
    /// pause-resumes were at 5.5, 6.3 and 94.
    ///
    /// Tested after the clamp, or a "re-anchor" can lower the estimate (clamped to 10306 against an
    /// estimate of 8690). A reset that does not raise the estimate clearly is a probe burst for
    /// nothing.
    pub reanchor_divergence_pct: u64,
    /// How long a report of real loss (at or above [`REAL_LOSS`]) keeps any re-anchor refused.
    ///
    /// A reset restarts the estimator at the re-anchor value and probes at 3x and 6x of it, fuel
    /// for a link already losing packets. Ten seconds matches the transport's `LOSS_MEMORY`
    /// (`transport/src/playout.rs`), which holds the playout delay for the same stretch.
    ///
    /// Real loss, not any: NACK-recovered loss of a few tenths of a percent is what a TURN relay
    /// does to a healthy stream (recorded in 141 of 350 seconds on one relay), and the brake
    /// already ignores it ([`BRAKE_LOSS`]); counting it blocked every needed correction on such a
    /// link. The line is [`BRAKE_CLEAR_LOSS`], 2%: relayed Wi-Fi and LTE recordings stay under it
    /// (maxima 1.26%, 1.35%, 1.18%), and a 3G link crossed it repeatedly (25.6%, 7.0%, 2.4%, 3.6%,
    /// 16.6%).
    pub real_loss_memory_ms: u32,
    /// How far above its baseline the round trip may sit and still describe a path with no queue on
    /// it, in milliseconds, or [`CLEAN_RTT_MARGIN_PCT`] of the baseline, whichever is larger.
    ///
    /// A path asked for more than it carries queues at the bottleneck, and the far end sees round
    /// trip. str0m sees it too and cuts, but to `0.85 x acked` (`bwe/delay/rate_control.rs:250`),
    /// and after an application-limited stretch "acked" is our own quiet. A relayed Wi-Fi recording
    /// (baseline 135-139 ms) collapsed five times mid-motion with the round trip on its baseline:
    ///
    /// ```text
    /// 18:57:31->32  1299 ->  483   fresh rtt 144, 140    loss 0
    /// 18:58:15->16  1228 ->   83   fresh rtt 149, 138    loss 0
    /// 18:58:30->31  3053 ->  722   fresh rtt 137, 139    loss 0.76% (2 NACKs)
    /// 18:58:44->45  4308 ->   46   fresh rtt 149, 136    loss 0.15% (2 NACKs)
    /// 18:59:37->38  3341 ->  217   fresh rtt 141, 139    loss 0
    /// ```
    ///
    /// The collapses not to override look different: 3G at 283, 283, 347 against ~210 (+35%, +65%)
    /// followed by 16.6% loss; LTE at 534 against 373 (+43%).
    ///
    /// Forty and thirty percent pass every path's ordinary jitter (Wi-Fi relay 136-165, other Wi-Fi
    /// 128-141, LTE 373-397) and call the 3G and LTE excursions queues. The absolute floor serves
    /// short paths; forty is under a third of [`RTT_MARGIN_MS`], so anything the brake calls a
    /// queue this calls unclean first. The cost: a single 187 ms report (+51) on a keyframe holds
    /// one collapse for [`CLEAN_RTT_FOR`]; a margin passing it would pass 3G's 283 on 210 too.
    ///
    /// Never more than [`QUEUE_GUARD_MS`]: thirty percent of a 373 ms LTE baseline is 112 ms, and
    /// two reports at 471 and 474 (a ~100 ms standing queue, then 1.35% loss) would pass. So
    /// `clamp(30% of base, 40, 75)`, binding only above a 250 ms baseline; on a 3G baseline of ~551
    /// the line is 626, above that link's ordinary 551-614.
    pub clean_rtt_margin_ms: u32,
    /// The proportional half of [`CLEAN_RTT_MARGIN_MS`], as a percentage of the baseline.
    pub clean_rtt_margin_pct: u32,
    /// How long every fresh report must have been inside the clean margin before the path counts as
    /// clean.
    ///
    /// Two seconds, two report intervals, looking backwards on purpose: a real narrowing queues
    /// before the estimate falls and drains within a second of the cut, so a clean report after a
    /// collapse proves nothing; the reports describing the traffic leading into it do, and they
    /// arrive up to a round trip plus an interval before the estimate moves. One spike blocks the
    /// path for two intervals: to override congestion control, one inflated report is enough to say
    /// "not yet" (the brake's "one is jitter, two are a queue", [`BRAKE_RTT_REPORTS`], turned
    /// round).
    pub clean_rtt_for_ms: u32,
    /// How long a clean collapse holds the network's descent arms off, waiting for the reset to
    /// bring the estimate back.
    ///
    /// Four seconds: str0m's `EstimateSmoother` (`bwe/smoother.rs`, `ESTIMATE_WINDOW`) emits the
    /// mean of the distinct values of the last three seconds, so the collapse's own values can
    /// outvote the restored one for the whole window; three seconds plus one stats interval sees
    /// the post-reset mean arrive. The pacer does not wait for the smoother (`reset` replaces
    /// `last_estimate` at once), so the budget is spendable immediately; this only bounds how long
    /// the controller believes the reset without seeing it. Still collapsed after that, str0m has
    /// re-measured the collapse under load, and the ordinary rules take over.
    pub clean_collapse_hold_ms: u32,
    /// How many times the spacing between clean-collapse re-anchors doubles after resets that did
    /// not hold. Three: 5, 10, 20, then 40 seconds.
    ///
    /// A hold ending with the estimate still collapsed after [`CLEAN_COLLAPSE_HOLD`], or with real
    /// loss or a brake meanwhile, means str0m re-measured the collapse under load or the reset's
    /// probes overfilled the path (a round-trip spike or missing report ending it is not counted).
    /// Repeated, that is overriding congestion control on a schedule. Doubling bounds it to one
    /// probe burst in forty seconds; a hold that recovers clears the count.
    pub reanchor_backoff_max: u32,
    /// Egress in one tick, in kbps, that no connection-setup exchange reaches: one of the two
    /// things that say media is flowing. See [`QualityController::warm`].
    ///
    /// [`LOADED_FLOOR_KBPS`]. A recorded session that never connected sent 0-22 kbps of ICE and
    /// TURN traffic for twenty seconds; connected openings read 16-62 kbps before their first media
    /// second; a 1080p opening keyframe of 40-80 kB puts megabits into its tick. A field of its own
    /// because it answers a different question from [`Self::loaded_floor_kbps`] (is media flowing,
    /// versus is the link asked enough to measure).
    pub media_egress_kbps: u32,
    /// How much of its allowance the encoder must be spending in a single window for the budget to
    /// be a real claim on the link.
    ///
    /// A half, a little above the 0.4 (`SPENDING_SHARE / 2`) that the smoothed readers use: they
    /// read a 1.6 s mean, this one 200 ms window, where one large frame or pacing gap moves the
    /// ratio by more than 0.1, and a re-anchor is costly (it discards str0m's state and fires a
    /// probe burst). The pause itself is stated by [`APP_LIMITED_PCT`] held for
    /// [`REANCHOR_AFTER_PAUSE`]; this checks that the budget the re-anchor makes spendable is being
    /// claimed on the tick it fires.
    pub reanchor_resume_spend: f32,
    /// The least time between two re-anchors.
    ///
    /// Five seconds. Each `reset` rebuilds the estimator, whose probe controller fires 3x and 6x of
    /// the init bitrate (str0m `bwe/probe/control.rs`): a deliberate burst of padding. Longer than
    /// the ramp a successful reset needs (a second or two), short enough that two separate pauses
    /// are each served.
    pub reanchor_every_ms: u32,

    // ── path change ───────────────────────────────────────────────────────────────────────────
    /// How long after a media path change its round trip is watched, for the "at most half the old
    /// one" test of [`ReanchorTrigger::PathChange`]. Five seconds: the first report after a change
    /// may still describe the old path (recorded: 122 ms, then 12 on the new one), and the new
    /// path's baseline needs three reports.
    pub path_judge_window_ms: u32,
    /// The least time between two path-change re-probes: a pair that flaps between two paths is
    /// probed once, not on every flap.
    pub path_reprobe_every_ms: u32,
    /// The "at most half the old one" of [`ReanchorTrigger::PathChange`], as the factor the new
    /// path's least fresh round trip is multiplied by before it is compared with the old path's:
    /// two.
    pub path_reprobe_rtt_factor: u32,

    // ── brake ─────────────────────────────────────────────────────────────────────────────────
    /// Loss in one receiver report at or above which the brake engages on that report alone.
    ///
    /// Ten percent, libwebrtc's line for the same decision (`SendSideBandwidthEstimation`,
    /// `kDefaultHighLossThreshold` 0.1: cut above, hold to 2%, grow below). The recordings separate
    /// cleanly there:
    ///
    /// ```text
    /// relayed WiFi, 1064 s over four sessions   max 5.88% (07:14:25), never two >= 5% in a row
    /// LTE, 08:10:16-23                          24.7%, then 92.6-94.2% on every report
    /// 3G, 08:10:36 / 08:11:56 / 08:12:17        25.6 / 16.6 / 12.9%, each with jbuf 900-1230 ms
    ///                                           within two seconds
    /// ```
    ///
    /// Low loss on a relay is held by retransmission, not congestion; that is the playout hold's
    /// job (`transport/src/playout.rs`).
    pub brake_loss: f32,
    /// Loss below which a report counts as clean, for releasing the brake: libwebrtc's
    /// `kDefaultLowLossThreshold`, 2%. Between this and [`BRAKE_LOSS`] the brake holds.
    pub brake_clear_loss: f32,
    /// What the brake cuts to: this share of what the receiver actually got.
    ///
    /// `0.85`, str0m's `BETA` (`bwe/delay/rate_control.rs:17`), applied as str0m applies it, to the
    /// delivered rate (`:250`): the decrease congestion control would have made had its feedback
    /// not stopped. Delivered is egress times `1 - loss`; at 94% loss anything else keeps pouring
    /// megabits into a link delivering 700 kbps.
    ///
    /// Egress is the larger of this report's interval and the one before: a report describes
    /// packets sent up to a round trip earlier (800 ms on a failing LTE link), so right after a cut
    /// its loss belongs to pre-cut traffic and would otherwise count twice. It also covers an
    /// interval in which the encoder sent little: the link was not asked.
    ///
    /// The cut is to an absolute confirmed rate, never a multiple of the current ceiling, so a
    /// later report lowers it only by showing less getting through; it cannot compound, hence no
    /// libwebrtc-style minimum interval between cuts (`kBweDecreaseInterval`). The round-trip arm
    /// has no delivered rate, so it cuts again only when the round trip has risen since the last
    /// cut, as GCC's overuse detector does.
    pub brake_backoff: f64,
    /// A round trip counts as inflated at this multiple of the session's baseline, or at the
    /// baseline plus [`RTT_MARGIN_MS`], whichever is larger, held for [`BRAKE_RTT_REPORTS`].
    ///
    /// Twice the minimum is a standing queue as long as the path itself; the margin makes that mean
    /// something on a short path, and consecutive reports keep single spikes out. Recorded:
    ///
    /// ```text
    /// WiFi, base ~128          threshold 278   single reports of 280 (08:06:48) and 303 (08:08:19),
    ///                                          each followed by 131-134: no brake
    /// 3G, base ~210            threshold 420   two-in-a-row at 08:11:16-17 (452, 444),
    ///                                          08:11:29-30 (749, 637), 08:11:44-45 (437, 470),
    ///                                          08:12:15-16 (500, 465); the eight singles (422, 431,
    ///                                          453, 491, 498, 524, 534, 539) do not count, and 539
    ///                                          printed again at 08:11:00 is the same report twice
    /// LTE, base ~247           threshold 494   801 at 08:10:17, after the loss arm had already fired
    /// ```
    ///
    /// The four 3G pairs coincide with a 330 ms send queue, loss with a growing jitter buffer, and
    /// 7-13% loss with the jitter buffer past a second.
    pub rtt_inflation: u32,
    /// The absolute half of [`RTT_INFLATION`], in milliseconds: twice [`QUEUE_GUARD_MS`]. A LAN at
    /// 2 ms doubles on a busy switch and nothing is wrong; 150 ms extra is the network holding
    /// twice the queue this product allows itself locally. A tuning of its own, not derived from
    /// the compiled guard.
    pub rtt_margin_ms: u32,
    /// How many consecutive fresh receiver reports must show an inflated round trip.
    ///
    /// Two. A fresh report carried a new RTCP receiver report (see [`ReceiverReport`]); str0m
    /// repeats the last round trip on intervals without one, and counting the repeat would double a
    /// spike. One spike is jitter on every recorded path (a 3G link had eight single reports past
    /// its threshold), while two in a row were a queue every time.
    pub brake_rtt_reports: u32,
    /// How many fresh round trips must exist before the round-trip arm may fire. A baseline of one
    /// sample is that sample.
    pub rtt_base_min_reports: usize,
    /// The spread, in milliseconds, three reports may have and still be one flat level. Twenty is
    /// the clean LTE and Wi-Fi paths' own jitter (7 and 14 ms) with room to spare; see
    /// [`PATH_STEP_FLAT_PCT`] for longer paths and `PATH_STEP_REPORTS` in [`crate::quality`] for
    /// the table.
    pub path_step_flat_ms: u32,
    /// The spread as a share of the level, in percent, when that is wider than
    /// [`PATH_STEP_FLAT_MS`]: a 3G path at 550 ms jitters by 20-30 ms with nothing queued.
    pub path_step_flat_pct: u32,
    /// The longest round trip a flat level may have and still be read as a path, in milliseconds.
    /// The longest recorded path is 3G at 551-585 ms; a geostationary satellite hop is 550-650. A
    /// flat 3.9 s is a stalled bottleneck holding our queue, not a route.
    pub path_step_max_ms: u32,
    /// How much a window may drift from its first report to its last and still be one level: half
    /// the flat band, or the step's height over the baseline divided by this, whichever is larger.
    ///
    /// A queue grows while the sender overshoots and drains after a cut, so its drift is a large
    /// share of its height; a longer path jumps once and then jitters. A recorded ramp (72-90 ms
    /// over a 153 baseline) drifted 16-19 ms, a fifth of its height; a bench 200 ms step (337, 341,
    /// 354 over 135) drifted 17, a twelfth. An eighth separates them; a flat stall is refused by
    /// [`PATH_STEP_MAX_MS`] whatever its drift.
    pub path_step_drift_div: u32,
    /// How many consecutive stats intervals may pass without a fresh receiver report, while we are
    /// sending, before the silence itself is a brake condition.
    ///
    /// str0m emits `MediaEgressStats` every stats interval whether or not a report arrived, and its
    /// `loss` is `None` exactly when none did (`streams/send_stats.rs:106-120`).
    ///
    /// Two. The interval is one second (`transport/src/webrtc.rs`, `set_stats_interval`), and
    /// Chrome sends a receiver report every second randomised between half and one and a half times
    /// that, so one empty interval is ordinary and two span more than that cadence produces. Across
    /// 287 recorded seconds of empty-interval lines, two in a row occurred only on links carrying
    /// nothing back (a bench blackout, and a session whose feedback never arrived). On the blackout
    /// a third interval cost a further second of 7.6-9.5 Mbps into a dead link; two engages 2.6 s
    /// after the cut, the earliest the stats clock can tell an outage from Chrome's jitter. A link
    /// that dies outright sends no reports, and the estimate freezes.
    pub brake_stale_reports: u32,
    /// After a background hold, how long a receiver report with a round trip past the drain line
    /// ([`QualityController::drain_enter_at`]) or with [`HOLD_WAKE_LOSS`] of its interval lost is
    /// read as the woken page's first word about the time it slept, not as the path, until the
    /// first report under both lines ends it.
    ///
    /// An iOS WebView sleeps when the page is hidden and its clock stops, so its first reports
    /// after waking read the sleep as round trip (recorded 10993 and 19668 ms, then 141 and 159 a
    /// second later). Two are [`DRAIN_EVIDENCE`]; one is half a round-trip brake. Over UDP what was
    /// sent to the sleeping page is lost and the first report's loss covers the sleep (100% in the
    /// simulator, a loss brake to 120 kbps). Four seconds is the receiver's one-second reports
    /// twice over with room; a real stall after a hold is judged from the first report past the
    /// window.
    pub hold_wake_window_ms: u32,
    /// The share of an interval lost at which a receiver report inside [`HOLD_WAKE_WINDOW`] is the
    /// woken page's: a page asleep behind UDP loses everything sent to it (100% in the simulator),
    /// while a merely lossy path reads [`REAL_LOSS`] to tens of percent and brakes as always.
    pub hold_wake_loss: f32,
    /// The least media an interval must have carried, in kbps, for a missing receiver report to
    /// count as silence on a link too thin to reach [`LOADED_FLOOR_KBPS`]. See
    /// [`SILENCE_MEDIA_SHARE_PCT`].
    ///
    /// A thin link never reaches 300 kbps of egress: a recorded 3G stall sent 160-290 kbps
    /// throughout, every empty interval was discarded, and the receiver went 3 to 13 seconds at a
    /// time without a word while the link held 40 seconds of our frames.
    ///
    /// Silence means something when the receiver had something to report on, that is when our media
    /// reached it. Egress is no guide on a still screen, since str0m pads to 50 kbps whenever its
    /// queue is empty (`pacer/control.rs`, `PADDING_TARGET`; recorded egress 79-94 kbps with the
    /// encoder at 14-29). So the test is on the smaller of egress and production, and fifty kbps is
    /// the padding it must beat.
    pub silence_media_floor_kbps: u32,
    /// ...and the share of the encoder's own budget that media must be, as a percentage.
    ///
    /// A half: the encoder trying to fill what it was given (`trying` elsewhere, [`SPENDING_SHARE`]
    /// halved is 0.4; this is a single interval, so a little above). Relative to the budget because
    /// on a thin link the budget is what we could ask (the 3G stall produced 160-290 kbps against
    /// budgets of 165-291). A still screen is under the floor; a blinking cursor on a fat link is
    /// under the share. Only ever added to the 300 kbps line: everything that counted before still
    /// counts.
    pub silence_media_share_pct: u64,
    /// What the brake cuts to when the receiver has gone silent: half of what we are sending.
    ///
    /// No delivered rate exists to scale, so this is the classic multiplicative decrease, repeated
    /// per further [`BRAKE_STALE_REPORTS`] of silence. Not evidence: it lowers the budget and
    /// nothing else, neither the capacity evidence nor the informative floor, and sheds no rung
    /// (see `silence_only` on the brake and [`OUTAGE_DIVERGENCE_PCT`]).
    pub brake_stale_backoff: f64,
    /// How far the capacity evidence must be above the live estimate for an outage's end to be
    /// re-anchored, as a percentage. See [`ReanchorTrigger::OutageResume`].
    ///
    /// After a bench blackout the estimate fell 10476 -> 2968: str0m's loss controller counted
    /// everything sent into the dead link as lost, and its acknowledged rate was what the silence
    /// brake let out. Neither is the link, and 1080p60 took 27 s to return on a path that had
    /// carried 8.4 Mbps and reported clean within two seconds. The clean-collapse trigger cannot
    /// serve it: the estimate was 50-75% of the evidence, not under half, and the brake held demand
    /// down.
    ///
    /// One and a half rather than [`REANCHOR_DIVERGENCE_PCT`]'s two: after an outage the estimate
    /// is recovering at str0m's multiplicative increase, about 8-10% a second, which closes `1.08^5
    /// = 1.47` over [`REANCHOR_EVERY`] by itself. Below that a reset buys less than its spacing. On
    /// the blackout the ratio two seconds after the first clean report was 1.58.
    pub outage_divergence_pct: u64,
    /// How fast a released brake gives the budget back, per second: a quarter, doubling the ceiling
    /// in about three seconds. Slower than the exploration bound in
    /// [`QualityController::unpushed_kbps`] (`x 1.5`), so the confirmed loss-free rate stays the
    /// binding ceiling rather than an estimate that may be frozen; and small enough that each step
    /// is covered by about one receiver report, so returning loss is seen within a step.
    pub brake_release_per_sec: f64,

    // ── drain mode and the viewer's delivery ──────────────────────────────────────────────────
    /// A fresh receiver report's round trip at or above which the path is holding a backlog of ours
    /// rather than carrying it, in milliseconds. One piece of evidence for drain mode; see
    /// [`QualityController::draining`].
    ///
    /// A path that drops shows loss and the brake answers it. A path that buffers (a 3G RNC's
    /// queue, a phone's VPN tunnel) shows only a growing round trip. Recorded, at 0.00% loss
    /// throughout:
    ///
    /// ```text
    /// 09:13:22-23   870, 599 ms      the path's own jitter over a 560 ms baseline
    /// 09:13:28      4752             then 6607, 7105, 6408, 13618, 14835, 21773, 31897, 39351
    /// ```
    ///
    /// with the viewer receiving 30 frames a second, 20-40 seconds old. Two seconds is under half
    /// the stall's first report and over five times any recorded Wi-Fi or LTE path (3G at 551-614
    /// ms, bench 130-380, an LTE queue at worst 801); a 3G link's worst report, 749, is under it.
    /// Absolute rather than a multiple of the baseline, as for [`PATH_STEP_MAX_MS`]: a baseline
    /// learned on a bloated path is itself the queue (a bench stall link learned 1318 ms).
    pub drain_enter_rtt_ms: u32,
    /// How many pieces of evidence enter drain mode, with no report under the line between them: a
    /// fresh report past [`DRAIN_ENTER_RTT_MS`], or a silence of [`BRAKE_STALE_REPORTS`] intervals
    /// while sending, at least one of them a report.
    ///
    /// Two, the brake's reading: one report is jitter, two are a queue ([`BRAKE_RTT_REPORTS`]); a
    /// lone 52495 ms report from the path ICE had just left never enters. Silence counts because a
    /// backlog holding our media holds the receiver's reports too, but never alone: after a
    /// blackout the first report reads the path's own round trip (126 ms after eleven silent
    /// seconds), because nothing was queued. Silence plus a report past the line is a stall;
    /// silence plus an ordinary report is an outage, for the outage brake.
    pub drain_evidence: u32,
    /// How many stats intervals in a row with no fresh receiver report end a drain as drained, once
    /// the silence has also outlasted the backlog the last fresh report showed (its round trip less
    /// the exit band).
    ///
    /// During a drain the receiver's highest sequence number moves only while our backlog is still
    /// arriving ([`ReceiverReport`]); when the last of it is in, reports stop being fresh. On a
    /// bench `3g-bloat` run the last fresh report read 1375 ms, the viewer's own pair round trip
    /// was back at 436, and every interval after was empty until [`DRAIN_MAX`] ended a
    /// twelve-second freeze.
    ///
    /// Two, as for [`BRAKE_STALE_REPORTS`]. The time condition covers reports that are delayed
    /// rather than absent (a 3G stall's came in bursts after 3 to 13 silent seconds). A drain ended
    /// early resumes at the conservative budget, and a remaining backlog brings it back in two
    /// reports.
    pub drain_drained_stale: u32,
    /// The longest drain mode lasts without the receiver proving the backlog is still there (a
    /// fresh report past [`DRAIN_ENTER_RTT_MS`]).
    ///
    /// Fifteen seconds. During a drain the viewer's picture is frozen and its heartbeats carry
    /// `net_stall`, so none of its own deadlines runs: this and [`DRAIN_MAX_PROVEN`] are the only
    /// bounds. Fifteen seconds is three times a backlog measured to be drainable (4.2 s); past it
    /// the agent resumes at the conservative budget.
    ///
    /// Counted from the last proof, not the drain's start: resuming into a path just reported to
    /// hold seconds of our frames only adds to them (a bench stall at 30 kbps resumed three times
    /// on a plain fifteen-second bound and the round trip climbed 6.1 -> 29.5 s).
    pub drain_max_ms: u32,
    /// The longest drain mode lasts whatever the receiver says: forty-five seconds, past the worst
    /// report of a recorded 3G stall that grew for a minute (39 s). A path holding a backlog longer
    /// than this will not recover by waiting; the resume is one attempt and the reports decide
    /// next.
    pub drain_max_proven_ms: u32,
    /// What the budget resumes at after a drain, as a percentage of what the receiver last
    /// confirmed the path carrying: the capacity evidence, or without any, what we were sending
    /// when it began.
    ///
    /// A half: the stall says the path stopped carrying what it had (recorded: evidence of 280-320
    /// kbps, then round trips growing 0.6 s a second while we sent 250, a path draining about 150).
    /// Held as a brake ([`BrakePhase::Holding`], as ignorance: `Brake::silence_only`) that releases
    /// at [`BRAKE_RELEASE_PER_SEC`] on clean reports and cuts again on a queue.
    pub drain_resume_share_pct: u64,
    /// The viewer's own count of what reached it, read against what we sent: the drain's current
    /// evidence. See [`QualityController::note_viewer_frames`].
    ///
    /// A receiver report's round trip answers a sender report that waited in the queue it
    /// describes, so it arrives a whole round trip, queue included, after the moment it is about.
    /// Recorded behind two VPNs (base 290 ms): a 2.3 s stall, then reports of 2564 and 2661 ms, and
    /// drain mode for two seconds while the viewer reported 74 and 116 frames a second against our
    /// 60, the backlog already clearing; the picture froze 1.6 s for nothing. On a bench stall
    /// link, drain mode re-entered 2-6 s after the stall in 11 of 33 runs on round trips describing
    /// the resume's queue. Replayed with the viewer's reports (`ladder_replay`, 88 drains), three
    /// re-entries do not begin, four end 0.2-2.2 s sooner, and stall-phase drains are untouched.
    ///
    /// The `vv` report (`afklink_protocol::ViewerVideo`) comes once a second of the viewer's clock
    /// with cumulative `framesReceived`. Against our per-tick count of frames and bytes handed to
    /// the transport it gives our frames in flight and our bytes delivered over its last second. It
    /// travels the reverse direction, but its data channel can wait behind our queue for SCTP
    /// acknowledgements (on the bench, bursts of four, 1-8 s late). So a report counts only on time
    /// by the viewer's clock (`video.currentTime`, [`DELIVERY_FRESH_LATE_MS`]), recent
    /// ([`DELIVERY_REPORT_AGE`]), and once a clean-path reference exists
    /// ([`DELIVERY_FLOOR_WINDOW`]). Otherwise the round trip decides alone.
    pub delivery_fresh_late_ms: u32,
    /// The oldest a viewer report may be, as of the decision, to be the path now: its one-second
    /// cadence and half again for the jitter of its timer and `getStats` call (991-1016 ms measured
    /// between on-time reports).
    pub delivery_report_age_ms: u32,
    /// How long the reference for our frames in flight on a clean path is kept: the least shortfall
    /// (frames sent a base round trip before a report, less frames received) over the on-time
    /// reports of the last minute taken while nothing said the path was queueing (a fresh round
    /// trip under the exit band, our queue under [`QUEUE_GUARD_MS`], no drain or drain evidence).
    /// It absorbs what the two counts never agree on; a minute lets a lost frame age out, and it is
    /// never taken from a backlog (a session opening into a 30 s queue already lacked 118 frames).
    ///
    /// `DELIVERY_HISTORY_TICKS` in [`crate::quality`] (compiled, 64 s at the tick) must cover it.
    pub delivery_floor_window_ms: u32,
    /// A drain does not begin when the viewer's on-time count says what of ours is in flight
    /// reaches it within this, at the rate its report says ours reached it (frames at its frame
    /// rate, bytes at its byte rate, the longer), and that frame rate is at least ours
    /// ([`DELIVERY_RATE_WINDOW`]): the round trip that would begin it describes a queue that is
    /// gone. Half a second, the backlog [`DRAIN_EXIT_FALLBACK_MS`] already accepts at a drain's
    /// end. Replaying bench stall logs, the three re-entries this stops had 0.32 s or less of ours
    /// in flight, while every drain the viewer's count agreed with had 0.76-10.8 s.
    pub drain_veto_within_ms: u32,
    /// A drain ends when the viewer's on-time count says the rest of our backlog reaches it within
    /// this at the reported rate (as [`DRAIN_VETO_WITHIN_MS`]), or nothing is left, and the path
    /// has room for the resume: our frames arrive at least as fast as we sent before the drain over
    /// its last two reports (or [`DRAIN_LEAVE_ONE_REPORT`] times that on this one), and our bytes
    /// at least as fast as the resume budget. A resume sent then arrives as the backlog ends: a 200
    /// ms tick, a 130 kB 1080p keyframe at a 5 Mbit/s budget (0.2 s), a 145 ms one-way trip, a
    /// little to spare. The rate conditions keep a thin path's stall in drain mode: at 100 kbit/s
    /// the backlog arrives at a third to a half of what we sent, under the 120 kbit/s a resume
    /// would send.
    pub drain_leave_within_ms: u32,
    /// What the viewer's rate of receiving ours is compared against: what we handed the transport
    /// over this long, and its own last two reports. Two, because a frame counts in the second its
    /// last packet arrives, so one second can read up to a frame more than the path carried (in the
    /// simulator, 141-167 kbit/s on a 100 kbit/s path with a 360p keyframe completing).
    pub delivery_rate_window_ms: u32,
    /// On one report alone, the viewer's frames a second must be half again what we were sending
    /// before a drain for its count to end it ([`DRAIN_LEAVE_WITHIN_MS`]); over two, what we were
    /// sending. A recorded end-of-drain report said 116 against our 60 (1.9 times).
    pub drain_leave_one_report: f64,

    // ── startup ───────────────────────────────────────────────────────────────────────────────
    /// When, after media first leaves ([`QualityController::warm`]), the ladder decides whether the
    /// link is thin, which also needs the receiver to have said so (see
    /// [`QualityController::startup_jump`]).
    ///
    /// Every session opens at [`LADDER`]'s top, which on a recorded 3G link meant 1080p on ~500
    /// kbps for thirteen seconds while the ladder walked down a rung per dwell. But every link
    /// looks thin at first: str0m starts at a configured 600 kbps, and its early estimates describe
    /// the connection's startup. From the first second with egress:
    ///
    /// ```text
    ///          t=0    1     2     3     4     5     6     7     8   (s)
    /// WiFi    1122  1845  1938  1938  2036  2190  4902  ...          fat from the first second
    /// LTE      600   441   512   538   565   671  1355  3245  3245   indistinguishable from 3G until 6
    /// 3G       600   517   640   640   640   360   657   726   726   never above 929 in the session
    /// ```
    ///
    /// Nothing else the agent logs separates LTE from 3G before six seconds (both had failed
    /// initial probes, round trips of 210-350 ms, negligible loss; LTE's encoder simply was not
    /// asking). Eight seconds leaves 1.8 s of margin on the LTE recording; on 3G the jump lands
    /// near t=8 (later if a move's settle is pending), saving the second half of the walk.
    pub startup_decide_after_ms: u32,
    /// How much of the startup window the encoder must have spent trying to fill its budget: three
    /// seconds of [`SPENDING_SHARE`]`/2`, the usual "is the encoder spending?" test. A still screen
    /// at session start sends almost nothing and the estimate describes our silence; a jump on that
    /// would be hard to leave, since a still screen produces no evidence to climb on.
    pub startup_trying_ms: u32,
    /// The link is thin when the most it was measured at in the startup window cannot pay for this
    /// height at its desktop price, [`Rung::required_kbps`] times [`UP_HEADROOM`].
    ///
    /// 900p: 816 kbps on a 3:2 source, 1020 with headroom. Below it the best affordable rung is
    /// 720p or lower, two or more rungs from the opening, where one move saves a keyframe over
    /// walking. Recordings sit either side with a third to spare: 3G peaked at 726 in its window;
    /// LTE read 1355 at 6.2 s and 3245 at 7.2 s.
    pub startup_thin_below_h: u32,
    /// ...or a queue standing at this age, in milliseconds: the mean over `STARTUP_DRAIN_TICKS` of
    /// the queue the encode loop's guards are fighting, the startup queue jump's second line beside
    /// the transport breaker's limit (`STARTUP_QUEUE_LIMIT_MS` in [`crate::quality`]).
    ///
    /// The soft guard ([`crate::agent`]'s `skip_for_queue`, 150 ms) withholds frames, so a refused
    /// rung shows a saw (0 to 950 ms and back every second) rather than the limit: a bench 300 kbps
    /// path behind 5 s of buffer never reached 1000 and its two-second means read 512 ms.
    /// Good-network bench runs stay under 275 ms in their first twenty seconds (most under 100); a
    /// recorded 3G opening read 432-812. Four hundred sits between.
    pub startup_queue_standing_ms: u32,
    /// How long after media first leaves our own queue may still make the startup queue jump:
    /// twenty seconds of media (drain mode's not counted). See
    /// [`QualityController::startup_queue_jump`].
    ///
    /// Longer than [`STARTUP_DECIDE_AFTER`] because this evidence arrives later: on a recorded 3G
    /// path the queue hit the breaker's limit 12.6 s and 21.2 s into media, after the eight-second
    /// decision. Twenty covers the first and ends before the bench's good-network scripts disturb
    /// the link. A drain closes it early: afterwards what leaves is the resume's low budget.
    pub startup_queue_window_ms: u32,

    // ── quantiser and processor ───────────────────────────────────────────────────────────────
    /// Quantiser above which the resolution has to give way: rate control has run out of room.
    ///
    /// 42 rather than libwebrtc's camera-video `kHighH264QpThreshold` of 37, because a rung change
    /// here costs more than a keyframe: the IDR is 50 to 85 kB at 1080p whatever the budget
    /// (OpenH264 clips its quantiser at 40, `ratectl.cpp:414`), and the browser rebuilds its
    /// hardware decoder on the new SPS, freezing the picture for close to a second. The only lever
    /// is the number of rung changes. Five more steps of QP is about 1.8x less bitrate absorbed
    /// before shedding (rate halves per +6), so ordinary congestion is ridden out at a coarser
    /// picture. In camera mode the encoder holds its budget at QP 42, so the wait costs softness,
    /// not a growing queue.
    ///
    /// The encoder's configured range must contain it with room to spare or it can never be
    /// crossed; `encode/src/lib.rs` asserts that at compile time, including the four steps to
    /// `QP_MAX` that `starved` needs.
    pub qp_down: f32,
    /// Quantiser below which the current rung is judged to have quality to spare, for climbing.
    ///
    /// A rung's price ([`Rung::required_kbps`]) is RustDesk's text-desktop figure (about 1221 kbps
    /// for 1080p30 `Balanced` on 1620x1080), a third of what a game needs, so without this the
    /// climb gate opens 1080p, `coarse` sheds it two seconds later, and the cycle repeats every ten
    /// seconds with an IDR and a freeze each turn. If this rung already needs QP 38, the rung
    /// above, given the same bits, needs more than [`QP_DOWN`] and will come straight back.
    ///
    /// 32, more permissive than libwebrtc's `kLowH264QpThreshold` of 24: here it is one of four
    /// climb gates (with `quiet`, `affordable` and the dwell), and a wrong climb costs one keyframe
    /// answered within [`DOWN_AFTER`], while never climbing costs the whole session.
    ///
    /// Two readers: `has_headroom` (is the current rung comfortable) and the content term in
    /// `best_affordable` (the quantiser a candidate rung may reach). Ten below [`QP_DOWN`] leaves a
    /// hysteresis band where the ladder holds still.
    pub qp_up: f32,
    /// How many quantiser samples must agree before the ladder acts on them. At 8 fps a 200 ms tick
    /// holds 1.6 frames, and the mean is cleared on every rung change, so without a floor one frame
    /// decides the resolution (libwebrtc's `kMinFramesNeededToScale` is `2 * 30`).
    pub qp_min_samples: u32,
    /// How much of its allowance the encoder must be using before its quantiser means anything. On
    /// a still desktop frames are a few hundred bytes whatever the quantiser says, so it describes
    /// the content, not the pixel count (measured: six descents with the encoder at 3 to 16% of
    /// budget).
    pub spending_share: f32,
    /// The encoder trying to fill its budget, on the smoothed spend ratio: half of
    /// [`SPENDING_SHARE`], 0.4. Read by every smoothed "is the encoder spending?" test: the
    /// budget's exploration bound, the ladder's `spending`, the startup window's trying time.
    pub trying_share: f32,
    /// The share of offered frames the bit bucket may withhold before the rung is the wrong rung.
    ///
    /// A third. Dropping frames and shedding pixels both buy fewer bits; one rung down is a 1.5 to
    /// 1.8x pixel reduction, about what a third of the frames cost, so past this the same bits come
    /// back at full frame rate instead.
    pub drop_share: f32,
    /// The share of a frame's interval the encoder may spend before the processor is the limit:
    /// 12.5 ms a frame at 60 fps, 25 ms at 30.
    ///
    /// Above it the ladder gives up cadence or pixels whatever the network does: the arm for a weak
    /// processor, and the only one able to act before any network signal. Capture and scaling run
    /// in the capture callback (`capture/src/wgc.rs`) and the transport in its own loop, so
    /// `encode_ms` covers colour conversion and encoding only, and no reserve for them is needed.
    ///
    /// Measured on a Ryzen Z1 Extreme handheld running a game at 1080p@60, 13 182 seconds at that
    /// rung, every second by its encode time:
    ///
    /// ```text
    /// encode ms    seconds  capture fps  encoded >= captured - 1  superseded  transport timer late
    /// < 9           10 072      59.0           95.1%                    0         1.09 ms mean
    /// 9-10           1 824      59.3           97.2%                    0         1.10
    /// 10-11            894      59.2           95.6%                    0         1.10
    /// 11-11.7          237      59.4           95.8%                    0         1.09
    /// 11.7-12.5        117      58.1           95.7%                    0         1.09
    /// 12.5-13.5         14      60.1           85.7%                    0         1.10
    /// ```
    ///
    /// Capture held cadence in every band; frames not encoded were withheld on purpose (the bit
    /// bucket and the queue guard), none superseded (the capture-to-encode channel keeps only the
    /// newest frame, so a lagging encoder would show `dropped_stale`), and the transport timer was
    /// no later at 12.5 ms. Replayed (`ladder_replay`, with [`ENCODE_CLIMB_SHARE`] at 0.65 and the
    /// climb cooldown), `cpu_bound` descents fell from 23 at 0.70 to 6.
    ///
    /// The risk: one machine and one game. Encode time cannot see a processor starving other
    /// threads (capture, the transport, the game) while its own frames stay inside the line, and
    /// that signal (superseded frames, capture rate) is on the `pipeline` line, not in
    /// [`Feedback`]. The climb gate ([`ENCODE_CLIMB_SHARE`]) and the cooldown
    /// ([`CPU_CLIMB_DWELL_MAX`]) guard against a load hovering at the line.
    pub encode_budget_share: f32,
    /// The share of the target rung's frame interval the encoder may be measured to need before a
    /// climb into that rung is allowed: ten points under [`ENCODE_BUDGET_SHARE`], so a climb lands
    /// inside the line that would take it back down.
    ///
    /// `quiet` refuses a climb only while the current rung is `cpu_bound`, and after a 60 -> 30
    /// step the line is 25 ms, so a rung shed at 12-13 ms a frame was climbed straight back
    /// (recorded: nine such descents, each climbed back 7-27 s later). So the climb is priced
    /// against the processor: `encode_smoothed` at this rung, scaled by the candidate's pixels,
    /// against this share of the candidate's interval. Not scaled by cadence: across 18 recorded
    /// climbs from 1080p@30 to @60 a frame at 60 took 0.96 of a frame at 30 (median, 0.73-1.05),
    /// since a frame at 30 carries more motion; the 30 fps figure errs high, the safe side.
    ///
    /// 10.8 ms at 60 fps: in 20-second windows of the recording above, a mean under 10.5 ms had at
    /// most 0.8% of seconds over 12.5, under 11.0 at most 1.7%. The ten points absorb the 200 ms
    /// ticks' extra noise. Replayed through `ladder_replay` (re-trips are climbs followed by a
    /// `cpu_bound` descent within 20 s):
    ///
    /// ```text
    ///                                 descent 0.70,       0.70 / climb 0.60   0.75 / climb 0.65
    ///                                 no climb gate       + cooldown          + cooldown
    /// whole session  cpu_bound downs        23                  17                  6
    ///                rung changes          184                 172                146
    ///                re-trips                8                   4                  2
    ///                1080p@60 / @30 s   12 443 / 885       12 154 / 1 144      12 619 / 723
    /// 18:40-18:53    cpu_bound downs         5                   2                  2
    ///                re-trips                3                   0                  1
    ///                1080p@60 / @30 s      688 / 141           602 / 220          696 / 133
    /// ```
    pub encode_climb_share: f32,
    /// The most the climb dwell grows to after repeated `cpu_bound` descents. See
    /// [`QualityController::climb_dwell`].
    ///
    /// [`ENCODE_CLIMB_SHARE`] judges a few seconds, and a game's load can move slower: a lull
    /// passes the gate, the climb lands, the next scene takes the rung back. Each `cpu_bound`
    /// descent after the first since the processor last held the rung doubles the next climb's
    /// dwell ([`UP_AFTER`], then 8, 16, 32 s), so a returning load is answered by asking for longer
    /// lulls. Capped: room for 32 s is a change of scene, and the goal is the best picture the
    /// processor allows. A 60 -> 30 step costs no keyframe, so a wrong climb costs two seconds at
    /// the line, not an IDR.
    ///
    /// On the recording above the gate and line did the work (the same 6 descents with or without
    /// this); this is the backstop for faster-alternating loads, weaker processors, and machines
    /// whose frames at 30 fps cost less than at 60 (measured on another PC: 0.78-0.87), where the
    /// gate errs low.
    pub cpu_climb_dwell_max_ms: u32,
    /// How long the processor must hold the rung it last shed, or a better one, before the run of
    /// `cpu_bound` descents is forgotten and climbs need the ordinary [`UP_AFTER`] again.
    ///
    /// A minute at the rung itself: a ladder parked at 30 fps for lack of encoder room has not
    /// shown the processor can hold 60. The recorded failures came back down within 8 to 37 s,
    /// while climbs that held for minutes were followed by first-time descents.
    pub cpu_streak_forget_ms: u32,
    /// How far under [`QUEUE_GUARD_MS`] the smoothed queue age must sit for the climb gate's
    /// `quiet`: `late_smoothed * 3 < QUEUE_GUARD_MS`, a third of the guard. See [`UP_AFTER`].
    pub roomy_late_factor: f32,
}

/// A whole number of milliseconds as a [`Duration`].
fn ms(v: u32) -> Duration {
    Duration::from_millis(u64::from(v))
}

impl QualityPolicy {
    /// The profile used when the server sent none or it was refused, labelled [`FALLBACK_LABEL`]:
    /// the one place the compiled profile ([`Self::safe`]) is chosen.
    #[must_use]
    pub fn fallback() -> Self {
        Self::safe()
    }

    /// The conservative profile compiled into the agent: it works on any link and any machine, and
    /// is more careful than the tuning the server sends (a ladder topping out at 720p30, climbs
    /// needing twice the evidence, a brake at less loss and a deeper cut, fewer and later
    /// re-anchors, shorter drains). The tuned values live on the server
    /// (`backend/server/src/quality/profiles/`) and, for tests and tools, in the contract's
    /// reference vector; never in this binary.
    ///
    /// Each field's doc argues for its reference value. Here each line says what this profile does
    /// with it: kept where the value restates a library, a cadence or a measurement (`= ref`, and
    /// why), moved in the careful direction otherwise. `safe_*` tests in `quality.rs` hold it to
    /// climbing to its top on a good link, braking earlier than the reference, recovering from the
    /// brake and leaving drain mode.
    #[must_use]
    pub fn safe() -> Self {
        Self {
            // ── ladder and pricing ──
            fps_factor_exp: 0.5, // = ref: LiveKit-calibrated, already errs towards dearer rungs
            quality_ratio_best: 1.5, // = ref: RustDesk's BR_BEST (no session asks for Best)
            quality_ratio_balanced: 0.75, // rungs priced higher: climbs later, sheds sooner
            quality_ratio_low: 0.5, // = ref: RustDesk's BR_SPEED (no session asks for Low)
            ladder: vec![
                Rung {
                    max_h: 720,
                    fps: 30,
                },
                Rung {
                    max_h: 540,
                    fps: 30,
                },
                Rung {
                    max_h: 360,
                    fps: 30,
                },
                Rung {
                    max_h: 360,
                    fps: 15,
                },
                Rung { max_h: 360, fps: 8 },
            ],
            pinned_fps: vec![30, 15, 8], // the ladder's cadences: no 60 on a pin either
            start_rung_index: 0,         // the top: a weak machine or link sheds it in seconds
            // Under the reference's 4, not 3: at 3 a game pan sat at QP 40 at 720p (`coarse` shed
            // it) and 33-37 at 540p (no climb back) on a 15 Mbps link. 3.5 keeps 720p.
            absorb_ratio: 3.5,
            up_headroom: 1.5, // a rung climbs with half its price to spare

            // ── budget ──
            // = ref: coupled to the pacer's 1.1x drain and `leading_share_pct` (110). At 80, each
            // delay spike's cut to 0.85x acked was never regained (bench VPN Wi-Fi, 360-540p).
            spend_pct: 90,
            pushback_depth: 0.6,      // in-flight bytes may cut the budget to 0.4
            explore_margin_kbps: 200, // the opening bid: the 360p15 rung, not two rungs
            explore_growth_pct: 125,  // the budget outgrows what left by a quarter a step
            loaded_share_pct: 65,     // = ref: str0m's ALR threshold
            leading_share_pct: 110,   // = ref: the pacer's 1.1x drain
            loaded_confirm_ms: 2_000, // = ref: the descent window, two receiver reports
            loaded_floor_kbps: 300,   // = ref: padding and keep-alive stay under it
            informative_half_life_ms: 10_000, // a quiet link's last measurement fades twice as fast
            app_limited_pct: 20,      // further from the busy-thin population: fewer resumes

            // ── dwells ──
            settle_after_move_ms: 3_000, // = ref: a longer settle would slow descents too
            down_after_ms: 2_000,        // = ref: descents no slower than the reference
            up_after_ms: 8_000,          // twice the evidence before a climb

            // ── probe target: str0m's probing, kept as the reference reads it ──
            probe_capacity_multiple: 2, // = ref: str0m's 15 ms cluster against a 60 ms buffer
            probe_target_change_pct: 20, // = ref: neither direction is safer
            probe_target_every_ms: 1_000, // = ref: str0m's stats interval
            probe_opening_ms: 3_000,    // = ref: must end before str0m's 5 s periodic probe
            probe_opening_latest_ms: 10_000, // = ref: ICE through a relay and DTLS take seconds

            // ── re-anchor: overriding congestion control, so less of it ──
            reanchor_after_pause_ms: 3_000, // a longer pause before a resume may reset
            reanchor_resume_window_ms: 2_000, // = ref: str0m's smoother surfaces the collapse late
            reanchor_divergence_pct: 300,   // a reset must lift the estimate threefold
            real_loss_memory_ms: 10_000,    // = ref: the transport's LOSS_MEMORY
            clean_rtt_margin_ms: 30,        // a stricter clean path
            clean_rtt_margin_pct: 20,       // a stricter clean path
            clean_rtt_for_ms: 3_000,        // three clean reports, not two
            clean_collapse_hold_ms: 4_000,  // = ref: str0m's 3 s smoother plus a report
            reanchor_backoff_max: 3,        // = ref count; on the longer spacing: 10 to 80 s
            media_egress_kbps: 300,         // = ref: setup traffic stays under it
            reanchor_resume_spend: 0.6,     // the encoder must claim more of its budget
            reanchor_every_ms: 10_000,      // half as many resets

            // ── path change ──
            path_judge_window_ms: 5_000, // = ref: three reports on the new path
            path_reprobe_every_ms: 20_000, // half as many re-probes
            path_reprobe_rtt_factor: 3,  // only a much shorter path is re-probed

            // ── brake: earlier and deeper ──
            // Under 10%: the loss is one report's second, and on a thin rung one packet is 4-7%.
            brake_loss: 0.08,
            brake_clear_loss: 0.02, // = ref: under it a relay's NACK loss can release
            brake_backoff: 0.7,     // cut to 70% of what got through
            rtt_inflation: 2,       // = ref: twice the path
            rtt_margin_ms: 100,     // or 100 ms over it, not 150
            brake_rtt_reports: 2,   // = ref: one report is jitter
            rtt_base_min_reports: 3, // = ref: a baseline of one is that sample
            path_step_flat_ms: 20,  // = ref: measured path jitter; stricter brakes a longer path
            path_step_flat_pct: 10, // = ref: as above
            path_step_max_ms: 800,  // = ref: as above
            path_step_drift_div: 8, // = ref: as above
            brake_stale_reports: 2, // = ref: Chrome's report cadence
            hold_wake_window_ms: 4_000, // = ref: a woken page's first reports
            hold_wake_loss: 0.5,    // = ref: a sleeping page loses everything
            silence_media_floor_kbps: 50, // = ref: str0m's padding target
            silence_media_share_pct: 50, // = ref: one interval of trying
            brake_stale_backoff: 0.5, // = ref: halving with no measurement
            outage_divergence_pct: 200, // str0m's ~8%/s over the 10 s re-anchor spacing
            brake_release_per_sec: 1.15, // the budget back more slowly: doubled in five seconds

            // ── drain mode and the viewer's delivery ──
            drain_enter_rtt_ms: 1_500, // earlier: past every clean path's 800 ms
            drain_evidence: 2,         // = ref: one report is jitter
            drain_drained_stale: 2,    // = ref: Chrome's report cadence
            drain_max_ms: 10_000,      // a blind drain ends sooner
            drain_max_proven_ms: 30_000, // so does a proven one
            drain_resume_share_pct: 40, // the resume a little lower
            delivery_fresh_late_ms: 250, // = ref: the viewer's timer
            delivery_report_age_ms: 1_500, // = ref: the viewer's cadence
            delivery_floor_window_ms: 60_000, // = ref: a lost frame ages out
            drain_veto_within_ms: 500, // = ref: the backlog a drain's end accepts
            drain_leave_within_ms: 750, // = ref: a resume keyframe and a one-way trip
            delivery_rate_window_ms: 2_000, // = ref: a frame counts in its last packet's second
            drain_leave_one_report: 2.0, // one report must show twice our rate

            // ── startup ──
            startup_decide_after_ms: 8_000, // = ref: LTE and 3G differ only after six seconds
            startup_trying_ms: 3_000,       // = ref: three seconds of trying
            startup_thin_below_h: 540,      // the ladder's second height, as 900 is the reference's
            startup_queue_standing_ms: 300, // a lower standing queue jumps down
            startup_queue_window_ms: 20_000, // = ref: ends before anything else moves the link

            // ── quantiser and processor ──
            qp_down: 40.0,                  // pixels give way two steps sooner
            qp_up: 30.0,                    // the same ten-step band under it
            qp_min_samples: 60,             // = ref: libwebrtc's kMinFramesNeededToScale
            spending_share: 0.8,            // = ref: what makes a quantiser evidence
            trying_share: 0.4,              // = ref: half of it
            drop_share: 0.25, // a rung down sooner than a third of its frames withheld
            encode_budget_share: 0.7, // a reserve for the rest of the machine
            encode_climb_share: 0.55, // fifteen points under it
            cpu_climb_dwell_max_ms: 64_000, // one more doubling: 8, 16, 32, 64 s
            cpu_streak_forget_ms: 120_000, // two minutes at the rung before it is forgiven
            roomy_late_factor: 4.0, // a climb needs the queue under a quarter of the guard
        }
    }

    /// The reference tuning, whose rationale is on each field.
    ///
    /// In the tests only (and the docs): the release binary carries [`Self::safe`] and nothing
    /// else. The server sends this tuning as its `default` profile; the simulator, the replay and
    /// other crates' tests read it from the contract's reference vector ([`REFERENCE_VECTOR`],
    /// through [`load_profile_file`]), which `the_reference_vector_is_the_reference` holds to this.
    #[cfg(any(test, doc))]
    #[must_use]
    pub fn reference() -> Self {
        Self {
            fps_factor_exp: 0.5,
            quality_ratio_best: 1.5,
            quality_ratio_balanced: 0.67,
            quality_ratio_low: 0.5,
            ladder: LADDER.to_vec(),
            pinned_fps: vec![60, 30, 15, 8],
            start_rung_index: 0,
            absorb_ratio: 4.0,
            up_headroom: 1.25,

            spend_pct: 90,
            pushback_depth: 0.5,
            explore_margin_kbps: 300,
            explore_growth_pct: 150,
            loaded_share_pct: 65,
            leading_share_pct: 110,
            loaded_confirm_ms: 2_000,
            loaded_floor_kbps: 300,
            informative_half_life_ms: 20_000,
            app_limited_pct: 25,

            settle_after_move_ms: 3_000,
            down_after_ms: 2_000,
            up_after_ms: 4_000,

            probe_capacity_multiple: 2,
            probe_target_change_pct: 20,
            probe_target_every_ms: 1_000,
            probe_opening_ms: 3_000,
            probe_opening_latest_ms: 10_000,

            reanchor_after_pause_ms: 2_000,
            reanchor_resume_window_ms: 2_000,
            reanchor_divergence_pct: 200,
            real_loss_memory_ms: 10_000,
            clean_rtt_margin_ms: 40,
            clean_rtt_margin_pct: 30,
            clean_rtt_for_ms: 2_000,
            clean_collapse_hold_ms: 4_000,
            reanchor_backoff_max: 3,
            media_egress_kbps: 300,
            reanchor_resume_spend: 0.5,
            reanchor_every_ms: 5_000,

            path_judge_window_ms: 5_000,
            path_reprobe_every_ms: 10_000,
            path_reprobe_rtt_factor: 2,

            brake_loss: 0.10,
            brake_clear_loss: 0.02,
            brake_backoff: 0.85,
            rtt_inflation: 2,
            rtt_margin_ms: 2 * QUEUE_GUARD_MS,
            brake_rtt_reports: 2,
            rtt_base_min_reports: 3,
            path_step_flat_ms: 20,
            path_step_flat_pct: 10,
            path_step_max_ms: 800,
            path_step_drift_div: 8,
            brake_stale_reports: 2,
            hold_wake_window_ms: 4_000,
            hold_wake_loss: 0.5,
            silence_media_floor_kbps: 50,
            silence_media_share_pct: 50,
            brake_stale_backoff: 0.5,
            outage_divergence_pct: 150,
            brake_release_per_sec: 1.25,

            drain_enter_rtt_ms: 2_000,
            drain_evidence: 2,
            drain_drained_stale: 2,
            drain_max_ms: 15_000,
            drain_max_proven_ms: 45_000,
            drain_resume_share_pct: 50,
            delivery_fresh_late_ms: 250,
            delivery_report_age_ms: 1_500,
            delivery_floor_window_ms: 60_000,
            drain_veto_within_ms: 500,
            drain_leave_within_ms: 750,
            delivery_rate_window_ms: 2_000,
            drain_leave_one_report: 1.5,

            startup_decide_after_ms: 8_000,
            startup_trying_ms: 3_000,
            startup_thin_below_h: 900,
            startup_queue_standing_ms: 400,
            startup_queue_window_ms: 20_000,

            qp_down: 42.0,
            qp_up: 32.0,
            qp_min_samples: 60,
            spending_share: 0.8,
            // Half the spending share, as it was written inline: 0.8 / 2 in f32 is exactly 0.4f32.
            trying_share: 0.8 / 2.0,
            drop_share: 1.0 / 3.0,
            encode_budget_share: 0.75,
            encode_climb_share: 0.65,
            cpu_climb_dwell_max_ms: 32_000,
            cpu_streak_forget_ms: 60_000,
            roomy_late_factor: 3.0,
        }
    }

    // ── values derived from another field ─────────────────────────────────────────────────────

    /// How recently the link must have agreed with the estimate for a quantiser to be evidence:
    /// [`DOWN_AFTER`], since the dwell judges that window. See `measured` in
    /// [`QualityController::tick`].
    #[must_use]
    pub fn measured_within(&self) -> Duration {
        self.down_after()
    }

    /// How long, in media time on a path, a rise of the probe target goes out on the tick it is
    /// decided even once there is capacity evidence: while the estimate is at its highest on live
    /// feedback, no brake is in force and no real loss in [`REAL_LOSS_MEMORY`]. The startup
    /// window's length ([`STARTUP_DECIDE_AFTER`]), the seconds read as str0m's slow start.
    ///
    /// After [`PROBE_OPENING`] the target is twice the evidence, and a probe that comes back high
    /// lifts the estimate before the evidence; waiting a second would hold str0m's next exponential
    /// probe to twice the old target. A brake or real loss is the receiver saying no, and then
    /// waiting is free.
    #[must_use]
    pub fn probe_ramp(&self) -> Duration {
        self.startup_decide_after()
    }

    /// Loss in one report at or above which it is real loss, for [`REAL_LOSS_MEMORY`] and the
    /// startup rule: [`BRAKE_CLEAR_LOSS`], under which nothing treats loss as the network saying
    /// no.
    #[must_use]
    pub fn real_loss(&self) -> f32 {
        self.brake_clear_loss
    }

    /// The least a re-anchor may hand str0m, in kbps.
    ///
    /// Not a time-to-ramp argument: str0m's increase is multiplicative
    /// (`MULTIPLICATIVE_INCREASE_COEF` 1.08, `bwe/delay/rate_control.rs:19`, about 10% a second as
    /// logged), so recovery time depends on the ratio, not the absolute rate. Nor a probe-size one:
    /// the reset's clusters at 3x and 6x for 15 ms each (`bwe/probe/control.rs:285-289`,
    /// `bwe/probe/cluster.rs:70`) are `9 x 15 ms x init` of bytes, which drains in 135 ms when the
    /// init is the capacity. Harmful re-anchors are stopped by the divergence and receiver gates
    /// ([`CLEAN_RTT_MARGIN_MS`], [`REAL_LOSS_MEMORY`], the brake).
    ///
    /// The floor is [`LOADED_FLOOR_KBPS`]: below it the informative rate cannot have been set under
    /// load, so it measures nothing. The capacity evidence is held to the same floor (a recorded
    /// 100-400 kbps 3G link re-anchors at most once in replay).
    #[must_use]
    pub fn reanchor_min_kbps(&self) -> u32 {
        self.loaded_floor_kbps
    }

    /// How long the receiver must have been back, and calling the path clean, before an outage's
    /// end is re-anchored: [`CLEAN_RTT_FOR`], two seconds. The first report after an outage
    /// describes the interval that contained it, and a link that came back narrower (a Wi-Fi to
    /// cellular handover) shows its queue in the reports that follow.
    #[must_use]
    pub fn outage_confirm(&self) -> Duration {
        self.clean_rtt_for()
    }

    /// The most a report's round trip may be and end drain mode, in milliseconds: the exit band is
    /// the brake's inflation line over the pre-stall baseline, never above this, and this when
    /// there is no baseline (none yet, or the path changed during the drain).
    ///
    /// Half the entry line: at most about half a second of our backlog left in a 3G path, which the
    /// conservative resume budget ([`DRAIN_RESUME_SHARE_PCT`]) lets drain. A cap too, because the
    /// baseline can itself be the queue (see [`DRAIN_ENTER_RTT_MS`]): twice 1318 ms would end a
    /// drain with two seconds still waiting. On a 3G baseline of 557 the band is 1000; on relayed
    /// Wi-Fi (~130) the brake's 280.
    #[must_use]
    pub fn drain_exit_fallback_ms(&self) -> u32 {
        self.drain_enter_rtt_ms / 2
    }

    // ── other readings ────────────────────────────────────────────────────────────────────────

    /// The share of a resolution's worth a [`Quality`] spends: the policy's three presets, or a
    /// custom ratio as given.
    #[must_use]
    pub fn quality_ratio(&self, quality: Quality) -> f32 {
        match quality {
            Quality::Best => self.quality_ratio_best,
            Quality::Balanced => self.quality_ratio_balanced,
            Quality::Low => self.quality_ratio_low,
            Quality::Custom(r) => r,
        }
    }

    /// The rung a session opens on: [`Self::ladder`] at [`Self::start_rung_index`].
    #[must_use]
    pub fn start_rung(&self) -> Rung {
        self.ladder[self.start_rung_index]
    }

    // ── durations ─────────────────────────────────────────────────────────────────────────────

    /// [`Self::loaded_confirm_ms`].
    #[must_use]
    pub fn loaded_confirm(&self) -> Duration {
        ms(self.loaded_confirm_ms)
    }
    /// [`Self::informative_half_life_ms`].
    #[must_use]
    pub fn informative_half_life(&self) -> Duration {
        ms(self.informative_half_life_ms)
    }
    /// [`Self::settle_after_move_ms`].
    #[must_use]
    pub fn settle_after_move(&self) -> Duration {
        ms(self.settle_after_move_ms)
    }
    /// [`Self::down_after_ms`].
    #[must_use]
    pub fn down_after(&self) -> Duration {
        ms(self.down_after_ms)
    }
    /// [`Self::up_after_ms`].
    #[must_use]
    pub fn up_after(&self) -> Duration {
        ms(self.up_after_ms)
    }
    /// [`Self::probe_target_every_ms`].
    #[must_use]
    pub fn probe_target_every(&self) -> Duration {
        ms(self.probe_target_every_ms)
    }
    /// [`Self::probe_opening_ms`].
    #[must_use]
    pub fn probe_opening(&self) -> Duration {
        ms(self.probe_opening_ms)
    }
    /// [`Self::probe_opening_latest_ms`].
    #[must_use]
    pub fn probe_opening_latest(&self) -> Duration {
        ms(self.probe_opening_latest_ms)
    }
    /// [`Self::reanchor_after_pause_ms`].
    #[must_use]
    pub fn reanchor_after_pause(&self) -> Duration {
        ms(self.reanchor_after_pause_ms)
    }
    /// [`Self::reanchor_resume_window_ms`].
    #[must_use]
    pub fn reanchor_resume_window(&self) -> Duration {
        ms(self.reanchor_resume_window_ms)
    }
    /// [`Self::real_loss_memory_ms`].
    #[must_use]
    pub fn real_loss_memory(&self) -> Duration {
        ms(self.real_loss_memory_ms)
    }
    /// [`Self::clean_rtt_for_ms`].
    #[must_use]
    pub fn clean_rtt_for(&self) -> Duration {
        ms(self.clean_rtt_for_ms)
    }
    /// [`Self::clean_collapse_hold_ms`].
    #[must_use]
    pub fn clean_collapse_hold(&self) -> Duration {
        ms(self.clean_collapse_hold_ms)
    }
    /// [`Self::reanchor_every_ms`].
    #[must_use]
    pub fn reanchor_every(&self) -> Duration {
        ms(self.reanchor_every_ms)
    }
    /// [`Self::path_judge_window_ms`].
    #[must_use]
    pub fn path_judge_window(&self) -> Duration {
        ms(self.path_judge_window_ms)
    }
    /// [`Self::path_reprobe_every_ms`].
    #[must_use]
    pub fn path_reprobe_every(&self) -> Duration {
        ms(self.path_reprobe_every_ms)
    }
    /// [`Self::hold_wake_window_ms`].
    #[must_use]
    pub fn hold_wake_window(&self) -> Duration {
        ms(self.hold_wake_window_ms)
    }
    /// [`Self::drain_max_ms`].
    #[must_use]
    pub fn drain_max(&self) -> Duration {
        ms(self.drain_max_ms)
    }
    /// [`Self::drain_max_proven_ms`].
    #[must_use]
    pub fn drain_max_proven(&self) -> Duration {
        ms(self.drain_max_proven_ms)
    }
    /// [`Self::delivery_report_age_ms`].
    #[must_use]
    pub fn delivery_report_age(&self) -> Duration {
        ms(self.delivery_report_age_ms)
    }
    /// [`Self::delivery_floor_window_ms`].
    #[must_use]
    pub fn delivery_floor_window(&self) -> Duration {
        ms(self.delivery_floor_window_ms)
    }
    /// [`Self::delivery_rate_window_ms`].
    #[must_use]
    pub fn delivery_rate_window(&self) -> Duration {
        ms(self.delivery_rate_window_ms)
    }
    /// [`Self::startup_decide_after_ms`].
    #[must_use]
    pub fn startup_decide_after(&self) -> Duration {
        ms(self.startup_decide_after_ms)
    }
    /// [`Self::startup_trying_ms`].
    #[must_use]
    pub fn startup_trying(&self) -> Duration {
        ms(self.startup_trying_ms)
    }
    /// [`Self::startup_queue_window_ms`].
    #[must_use]
    pub fn startup_queue_window(&self) -> Duration {
        ms(self.startup_queue_window_ms)
    }
    /// [`Self::cpu_climb_dwell_max_ms`].
    #[must_use]
    pub fn cpu_climb_dwell_max(&self) -> Duration {
        ms(self.cpu_climb_dwell_max_ms)
    }
    /// [`Self::cpu_streak_forget_ms`].
    #[must_use]
    pub fn cpu_streak_forget(&self) -> Duration {
        ms(self.cpu_streak_forget_ms)
    }
}

/// [`QualityPolicy::reference`], in the tests only: production names its policy.
#[cfg(any(test, doc))]
impl Default for QualityPolicy {
    /// [`QualityPolicy::reference`].
    fn default() -> Self {
        Self::reference()
    }
}

/// The contract's reference profile (`{id, v, values}`, the server's `default`), as a path from the
/// agent repository's root. Tools and other crates' tests read it at run time with
/// [`load_profile_file`] (`CARGO_MANIFEST_DIR/../..` from a crate under `crates/`); nothing
/// compiles it in.
pub const REFERENCE_VECTOR: &str =
    "contract/packages/protocol/vectors/quality-profile-reference.json";

/// A profile file (`{id, v, values}`), checked as a server's ([`QualityPolicy::from_wire`]), for
/// the tools and tests; a session never reads a file. Errors name the file and failing paths, never
/// a value.
pub fn load_profile_file(path: &std::path::Path) -> Result<WireProfile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let raw: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: not JSON: {e}", path.display()))?;
    let profile = QualityPolicy::from_wire(&raw)
        .map_err(|r| format!("{}: refused at {}", path.display(), r.paths()))?;
    tracing::debug!(
        path = %path.display(),
        profile = %profile.label(),
        unknown_fields = profile.unknown_count,
        "quality profile file read"
    );
    Ok(profile)
}

// ── the profile the server sends ──────────────────────────────────────────────────────────────

/// The label of the compiled profile, [`QualityPolicy::fallback`]: `"<id>.v<v>"` like a server's,
/// so a session's `quality_profile` always has the one shape. A new compiled profile is a new `v`.
pub const FALLBACK_LABEL: &str = "builtin.v1";

/// The longest profile id: `QUALITY_PROFILE_ID_PATTERN`, a letter and up to 31 more.
const PROFILE_ID_MAX: usize = 32;
/// The largest profile version, `QUALITY_PROFILE_MAX_V`.
const PROFILE_MAX_V: u64 = 1_000_000;

// The constants the bounds and invariants read, as the contract restates them
// (`contract/packages/protocol/src/quality-profile.ts`, same names with `QUALITY_` in front).

/// `QUALITY_TICK_MS`: [`crate::quality::TICK`] in milliseconds.
const TICK_MS: u32 = 200;
/// `QUALITY_DELIVERY_HISTORY_MS`: the delivery ring the delivery windows read
/// (`DELIVERY_HISTORY_TICKS` ticks of [`TICK_MS`]).
const DELIVERY_HISTORY_MS: f64 = (crate::quality::DELIVERY_HISTORY_TICKS as u32 * TICK_MS) as f64;
/// `QUALITY_RTT_BASE_REPORTS`: the ring of round trips the baseline is the least of.
const RTT_BASE_REPORTS: f64 = crate::quality::RTT_BASE_REPORTS as f64;
/// `QUALITY_MAX_DESIRED_KBPS`: no rate goes past the encoder's ceiling.
const MAX_KBPS: f64 = crate::quality::MAX_DESIRED_KBPS as f64;
/// `QUALITY_QUEUE_GUARD_MS`: `clean_rtt_margin_ms` is the floor of a clamp whose ceiling is this.
const QUEUE_GUARD: f64 = QUEUE_GUARD_MS as f64;
/// `QUALITY_ENCODER_QP_MIN` / `QUALITY_ENCODER_QP_MAX`: `QP_MIN` / `QP_MAX` in `afklink-encode`
/// (private there, so restated), and the steps `starved` needs between `qp_down` and `QP_MAX`.
const ENCODER_QP_MIN: f64 = 16.0;
const ENCODER_QP_MAX: f64 = 46.0;
const STARVED_QP_STEPS: f64 = 4.0;
/// `QUALITY_STR0M_ALR_PROBE_GAP_MS`: str0m 0.24.1's `MIN_TIME_BETWEEN_ALR_PROBES`, which the probe
/// opening must end before ([`QualityPolicy::probe_opening_ms`]). Recheck on every str0m bump.
const STR0M_ALR_PROBE_GAP_MS: u32 = 5_000;
/// `QUALITY_PROBE_OPENING_SLACK_MS`: how long after `probe_opening_ms` its end can reach str0m.
const PROBE_OPENING_SLACK_MS: u32 = 2 * TICK_MS;
/// `QUALITY_MAX_DURATION_MS`: the longest any duration may be.
const MAX_DURATION_MS: f64 = 120_000.0;
/// A rung's encoded height (and `startup_thin_below_h`): 144p to 4K.
const RUNG_MIN_H: f64 = 144.0;
const RUNG_MAX_H: f64 = 2_160.0;
/// The highest frame rate a rung or a pinned rate may ask for.
const RUNG_MAX_FPS: f64 = 120.0;
/// `QUALITY_MAX_RUNGS` / `QUALITY_MAX_PINNED_FPS`.
const MAX_RUNGS: f64 = 16.0;
const MAX_PINNED_FPS: f64 = 8.0;

/// What a field holds on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A whole number (`z.number().int()`), never negative here.
    Int,
    /// A float the controller keeps as `f32`: the bounds are checked on the wire's double, as zod
    /// checks them, and the value is then rounded to `f32`.
    F32,
    /// A float kept as `f64`.
    F64,
    /// `ladder`: `min..=max` rungs of `{max_h, fps}`.
    Ladder,
    /// `pinned_fps`: `min..=max` frame rates.
    Rates,
}

/// One field's sanity range (`qualityPolicyFields` in the contract): `min..=max`, or `min` itself
/// excluded (`.gt(min)`). For the two lists, the range is of their length.
#[derive(Debug, Clone, Copy)]
struct Bound {
    field: &'static str,
    kind: Kind,
    min: f64,
    max: f64,
    min_exclusive: bool,
}

const fn int(field: &'static str, min: f64, max: f64) -> Bound {
    Bound {
        field,
        kind: Kind::Int,
        min,
        max,
        min_exclusive: false,
    }
}
const fn f32_in(field: &'static str, min: f64, max: f64) -> Bound {
    Bound {
        field,
        kind: Kind::F32,
        min,
        max,
        min_exclusive: false,
    }
}
const fn f64_in(field: &'static str, min: f64, max: f64) -> Bound {
    Bound {
        field,
        kind: Kind::F64,
        min,
        max,
        min_exclusive: false,
    }
}
/// A float strictly above `min` (`z.number().gt(min)`).
const fn above(bound: Bound) -> Bound {
    Bound {
        min_exclusive: true,
        ..bound
    }
}
/// A duration in whole milliseconds, `min..=` two minutes.
const fn dur(field: &'static str, min: f64) -> Bound {
    int(field, min, MAX_DURATION_MS)
}
/// A rate in kbps, up to the encoder's ceiling.
const fn kbps(field: &'static str) -> Bound {
    int(field, 0.0, MAX_KBPS)
}
/// An integer percentage, `0..=100`.
const fn pct(field: &'static str) -> Bound {
    int(field, 0.0, 100.0)
}
/// A float share of one.
const fn share(field: &'static str) -> Bound {
    f32_in(field, 0.0, 1.0)
}
/// A count of reports or intervals, `1..=30`.
const fn reports(field: &'static str) -> Bound {
    int(field, 1.0, 30.0)
}

/// Every field of [`QualityPolicy`], in the struct's order, with the contract's sanity range. The
/// bounds also keep a server's value from panicking the controller: non-empty ladders, a valid
/// `start_rung_index`, no zero divisor or frame rate, no shift past 8 doublings, a fillable
/// baseline ring. `the_bounds_are_the_contracts_schema` holds this to
/// `schema/quality-profile.json`.
const BOUNDS: &[Bound] = &[
    // ── ladder and pricing ──
    f64_in("fps_factor_exp", 0.0, 2.0),
    f32_in("quality_ratio_best", 0.05, 8.0),
    f32_in("quality_ratio_balanced", 0.05, 8.0),
    f32_in("quality_ratio_low", 0.05, 8.0),
    // At least one rung: `ladder[0]` and `rungs().len() - 1` index it.
    Bound {
        field: "ladder",
        kind: Kind::Ladder,
        min: 1.0,
        max: MAX_RUNGS,
        min_exclusive: false,
    },
    // At least one rate: a pinned ladder is `pinned_fps.len()` rungs, indexed the same way.
    Bound {
        field: "pinned_fps",
        kind: Kind::Rates,
        min: 1.0,
        max: MAX_PINNED_FPS,
        min_exclusive: false,
    },
    int("start_rung_index", 0.0, MAX_RUNGS - 1.0),
    f64_in("absorb_ratio", 1.0, 8.0),
    f64_in("up_headroom", 1.0, 4.0),
    // ── budget ──
    int("spend_pct", 10.0, 100.0),
    f64_in("pushback_depth", 0.0, 0.9),
    kbps("explore_margin_kbps"),
    int("explore_growth_pct", 100.0, 1_000.0),
    int("loaded_share_pct", 1.0, 100.0),
    int("leading_share_pct", 1.0, 1_000.0),
    dur("loaded_confirm_ms", 0.0),
    kbps("loaded_floor_kbps"),
    // A divisor of the decay's exponent (`dt / informative_half_life`).
    dur("informative_half_life_ms", 100.0),
    pct("app_limited_pct"),
    // ── dwells ──
    dur("settle_after_move_ms", 0.0),
    dur("down_after_ms", 0.0),
    dur("up_after_ms", 0.0),
    // ── probe target ──
    // A divisor in `probe_floor_kbps`.
    int("probe_capacity_multiple", 1.0, 10.0),
    pct("probe_target_change_pct"),
    dur("probe_target_every_ms", 0.0),
    dur("probe_opening_ms", 0.0),
    dur("probe_opening_latest_ms", 0.0),
    // ── re-anchor ──
    dur("reanchor_after_pause_ms", 0.0),
    dur("reanchor_resume_window_ms", 0.0),
    int("reanchor_divergence_pct", 100.0, 1_000.0),
    dur("real_loss_memory_ms", 0.0),
    // The floor of `clamp(.., clean_rtt_margin_ms, QUEUE_GUARD_MS)`, which panics above it.
    int("clean_rtt_margin_ms", 0.0, QUEUE_GUARD),
    pct("clean_rtt_margin_pct"),
    dur("clean_rtt_for_ms", 0.0),
    dur("clean_collapse_hold_ms", 0.0),
    // `1 << reanchor_backoff` (a u32 shift) times a Duration: eight doublings at most.
    int("reanchor_backoff_max", 0.0, 8.0),
    kbps("media_egress_kbps"),
    share("reanchor_resume_spend"),
    dur("reanchor_every_ms", 1_000.0),
    // ── path change ──
    dur("path_judge_window_ms", 0.0),
    dur("path_reprobe_every_ms", 1_000.0),
    int("path_reprobe_rtt_factor", 1.0, 10.0),
    // ── brake ──
    f32_in("brake_loss", 0.01, 1.0),
    share("brake_clear_loss"),
    f64_in("brake_backoff", 0.1, 1.0),
    int("rtt_inflation", 1.0, 10.0),
    dur("rtt_margin_ms", 0.0),
    reports("brake_rtt_reports"),
    // Above the ring it is never reached, which silently disables the baseline.
    int("rtt_base_min_reports", 1.0, RTT_BASE_REPORTS),
    dur("path_step_flat_ms", 0.0),
    pct("path_step_flat_pct"),
    dur("path_step_max_ms", 0.0),
    // A divisor in `path_step_refusal`.
    int("path_step_drift_div", 1.0, 100.0),
    reports("brake_stale_reports"),
    dur("hold_wake_window_ms", 0.0),
    share("hold_wake_loss"),
    kbps("silence_media_floor_kbps"),
    pct("silence_media_share_pct"),
    f64_in("brake_stale_backoff", 0.1, 1.0),
    int("outage_divergence_pct", 100.0, 1_000.0),
    // Above one: at 1.0 `held * rate^dt` never grows and a released brake holds all session.
    above(f64_in("brake_release_per_sec", 1.0, 10.0)),
    // ── drain mode and the viewer's delivery ──
    dur("drain_enter_rtt_ms", 200.0),
    reports("drain_evidence"),
    reports("drain_drained_stale"),
    dur("drain_max_ms", 0.0),
    dur("drain_max_proven_ms", 0.0),
    int("drain_resume_share_pct", 1.0, 100.0),
    dur("delivery_fresh_late_ms", 0.0),
    dur("delivery_report_age_ms", 0.0),
    // The delivery ring must cover it.
    int("delivery_floor_window_ms", 0.0, DELIVERY_HISTORY_MS),
    dur("drain_veto_within_ms", 0.0),
    dur("drain_leave_within_ms", 0.0),
    int(
        "delivery_rate_window_ms",
        TICK_MS as f64,
        DELIVERY_HISTORY_MS,
    ),
    f64_in("drain_leave_one_report", 1.0, 10.0),
    // ── startup ──
    dur("startup_decide_after_ms", 0.0),
    dur("startup_trying_ms", 0.0),
    int("startup_thin_below_h", RUNG_MIN_H, RUNG_MAX_H),
    dur("startup_queue_standing_ms", 0.0),
    dur("startup_queue_window_ms", 0.0),
    // ── quantiser and processor ──
    above(f32_in(
        "qp_down",
        ENCODER_QP_MIN,
        ENCODER_QP_MAX - STARVED_QP_STEPS,
    )),
    above(f32_in(
        "qp_up",
        ENCODER_QP_MIN,
        ENCODER_QP_MAX - STARVED_QP_STEPS,
    )),
    int("qp_min_samples", 1.0, 600.0),
    share("spending_share"),
    share("trying_share"),
    share("drop_share"),
    // Divided into a frame interval's milliseconds for the encode-time lines.
    f32_in("encode_budget_share", 0.05, 1.0),
    f32_in("encode_climb_share", 0.05, 1.0),
    dur("cpu_climb_dwell_max_ms", 0.0),
    dur("cpu_streak_forget_ms", 0.0),
    f32_in("roomy_late_factor", 1.0, 10.0),
];

/// One reason a profile was refused: the contract's issue path (`values.ladder.3`) and a fixed
/// description of the rule. Never the value — a [`Rejection`] goes to the log by its paths only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub path: String,
    pub rule: &'static str,
}

/// At most this many issues are kept in a [`Rejection`] (the rest only counted): a profile built to
/// fail everywhere cannot make a long log line or a large allocation of its failures.
pub const ISSUES_KEPT: usize = 32;

/// Why a profile was refused: every failing path, not just the first — up to [`ISSUES_KEPT`] of
/// them, with the total in `count`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// The first [`ISSUES_KEPT`] failures, in the order they were found.
    pub issues: Vec<Issue>,
    /// How many failures there were in all.
    pub count: usize,
}

impl Rejection {
    fn one(path: &str, rule: &'static str) -> Self {
        Self::of(vec![Issue {
            path: path.to_string(),
            rule,
        }])
    }

    /// `issues`, the first [`ISSUES_KEPT`] kept and all counted.
    fn of(mut issues: Vec<Issue>) -> Self {
        let count = issues.len();
        issues.truncate(ISSUES_KEPT);
        Self { issues, count }
    }

    /// The failing paths, comma-separated: the log's `rules=`. Paths are this file's own words
    /// and indices, never a value; an unknown key never makes an issue.
    #[must_use]
    pub fn paths(&self) -> String {
        self.issues
            .iter()
            .map(|i| i.path.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// A profile that passed every bound and invariant.
#[derive(Debug, Clone, PartialEq)]
pub struct WireProfile {
    pub id: String,
    pub v: u32,
    pub policy: QualityPolicy,
    /// Unknown keys (`values.<name>` inside the values, `<name>` beside them), ignored so a newer
    /// server can talk to an older agent: the first [`UNKNOWN_NAMES_LOGGED`] names, all counted.
    pub unknown_fields: Vec<String>,
    /// How many unknown keys there were in all.
    pub unknown_count: usize,
}

/// The unknown keys of a profile as they are found: the first [`UNKNOWN_NAMES_LOGGED`] names, and
/// a count of all — a flood of keys costs one counter, not a list of names.
#[derive(Debug, Default)]
struct UnknownFields {
    names: Vec<String>,
    count: usize,
}

impl UnknownFields {
    fn push(&mut self, name: impl FnOnce() -> String) {
        self.count += 1;
        if self.names.len() < UNKNOWN_NAMES_LOGGED {
            self.names.push(name());
        }
    }
}

impl WireProfile {
    /// `"<id>.v<v>"`, the session's `quality_profile`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}.v{}", self.id, self.v)
    }
}

/// `^[a-z][a-z0-9-]{0,31}$`, the contract's `QUALITY_PROFILE_ID_PATTERN`.
fn is_profile_id(id: &str) -> bool {
    let mut chars = id.chars();
    id.len() <= PROFILE_ID_MAX
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether `x` is inside `b`'s range.
fn in_range(b: &Bound, x: f64) -> bool {
    let above_min = if b.min_exclusive {
        x > b.min
    } else {
        x >= b.min
    };
    x.is_finite() && above_min && x <= b.max
}

/// A whole number in `min..=max`, as an `f64` for the comparison (every bound is far inside
/// 2^53, so nothing rounds).
fn int_in(v: &Value, min: f64, max: f64) -> bool {
    v.as_u64()
        .is_some_and(|n| (min..=max).contains(&(n as f64)))
}

/// One field's value against its bound, each failure at its own path.
fn check_field(b: &Bound, v: &Value, path: &str, issues: &mut Vec<Issue>) {
    let mut fail = |path: String, rule: &'static str| issues.push(Issue { path, rule });
    match b.kind {
        Kind::Int => {
            // A JSON integer only: `2000.0` or `2e3` is refused where zod's `.int()` takes them.
            // Harmless: the server sends `JSON.stringify` of a zod-parsed profile, which writes
            // whole numbers below 1e21 without fraction or exponent.
            if !v.as_u64().is_some_and(|n| in_range(b, n as f64)) {
                fail(path.to_string(), "a whole number in its range");
            }
        }
        Kind::F32 | Kind::F64 => {
            // The wire's own double against the bound, as zod checks it: `brake_loss = 0.01` is the
            // contract's inclusive minimum and its `f32` (0.0099999998) must not refuse it. No
            // bound guards a division or shift, so the `f32` rounding is harmless.
            if !v.as_f64().is_some_and(|x| in_range(b, x)) {
                fail(path.to_string(), "a number in its range");
            }
        }
        Kind::Ladder | Kind::Rates => {
            let Some(items) = v.as_array() else {
                fail(path.to_string(), "a list");
                return;
            };
            if !in_range(b, items.len() as f64) {
                // Nothing per item past a wrong length: a list of millions would otherwise be
                // millions of issues (the length alone refuses it).
                fail(path.to_string(), "a list of the allowed length");
                return;
            }
            for (i, item) in items.iter().enumerate() {
                if b.kind == Kind::Rates {
                    if !int_in(item, 1.0, RUNG_MAX_FPS) {
                        fail(format!("{path}.{i}"), "a frame rate of 1 to 120");
                    }
                    continue;
                }
                let Some(rung) = item.as_object() else {
                    fail(format!("{path}.{i}"), "a rung {max_h, fps}");
                    continue;
                };
                if !rung
                    .get("max_h")
                    .is_some_and(|h| int_in(h, RUNG_MIN_H, RUNG_MAX_H))
                {
                    fail(format!("{path}.{i}.max_h"), "a height of 144 to 2160");
                }
                if !rung
                    .get("fps")
                    .is_some_and(|f| int_in(f, 1.0, RUNG_MAX_FPS))
                {
                    fail(format!("{path}.{i}.fps"), "a frame rate of 1 to 120");
                }
            }
        }
    }
}

/// Every field present and in its range; unknown keys collected as `values.<name>`.
fn check_fields(values: &Map<String, Value>, issues: &mut Vec<Issue>, unknown: &mut UnknownFields) {
    for b in BOUNDS {
        let path = format!("values.{}", b.field);
        match values.get(b.field) {
            Some(v) => check_field(b, v, &path, issues),
            None => issues.push(Issue {
                path,
                rule: "a required field",
            }),
        }
    }
    for key in values.keys() {
        if !BOUNDS.iter().any(|b| b.field == key) {
            unknown.push(|| format!("values.{key}"));
        }
    }
}

// ── the cross-field invariants (`.superRefine` in the contract), one function per rule ─────────

/// `values.brake_clear_loss`: between it and `brake_loss` a report neither cuts nor releases.
fn brake_clear_loss_under_brake_loss(p: &QualityPolicy) -> bool {
    p.brake_clear_loss < p.brake_loss
}
/// `values.hold_wake_loss`: under `brake_loss` it would excuse a loss the brake acts on alone.
fn hold_wake_loss_at_least_brake_loss(p: &QualityPolicy) -> bool {
    p.hold_wake_loss >= p.brake_loss
}
/// `values.probe_opening_latest_ms`: the latest the opening ends.
fn probe_opening_latest_after_opening(p: &QualityPolicy) -> bool {
    p.probe_opening_ms <= p.probe_opening_latest_ms
}
/// `values.probe_opening_ms`: the opening ends before str0m's first periodic probe.
fn probe_opening_before_str0m_probe(p: &QualityPolicy) -> bool {
    p.probe_opening_ms + PROBE_OPENING_SLACK_MS < STR0M_ALR_PROBE_GAP_MS
}
/// `values.qp_up`: a band where the ladder holds still.
fn qp_up_under_qp_down(p: &QualityPolicy) -> bool {
    p.qp_up < p.qp_down
}
/// `values.drain_max_proven_ms`: the bound with proof is not shorter than the one without.
fn drain_max_within_proven(p: &QualityPolicy) -> bool {
    p.drain_max_ms <= p.drain_max_proven_ms
}
/// `values.leading_share_pct`: the band `[loaded_share_pct, leading_share_pct]` is not empty.
fn leading_share_above_loaded_share(p: &QualityPolicy) -> bool {
    p.loaded_share_pct < p.leading_share_pct
}
/// `values.trying_share`: trying is the weaker test.
fn trying_share_within_spending_share(p: &QualityPolicy) -> bool {
    p.trying_share <= p.spending_share
}
/// `values.encode_climb_share`: a climb lands inside the line that would take it back down.
fn encode_climb_under_budget(p: &QualityPolicy) -> bool {
    p.encode_climb_share < p.encode_budget_share
}
/// `values.cpu_climb_dwell_max_ms`: the dwell doubles from `up_after_ms` up to it.
fn cpu_climb_dwell_max_from_up_after(p: &QualityPolicy) -> bool {
    p.up_after_ms <= p.cpu_climb_dwell_max_ms
}
/// `values.startup_trying_ms`: part of the startup window.
fn startup_trying_within_window(p: &QualityPolicy) -> bool {
    p.startup_trying_ms <= p.startup_decide_after_ms
}
/// `values.clean_rtt_margin_ms`: what the brake calls a queue this calls unclean first.
fn clean_rtt_margin_within_brake_margin(p: &QualityPolicy) -> bool {
    p.clean_rtt_margin_ms <= p.rtt_margin_ms
}
/// `values.start_rung_index`: a rung of the ladder (`start_rung` indexes it).
fn start_rung_in_ladder(p: &QualityPolicy) -> bool {
    p.start_rung_index < p.ladder.len()
}

/// The ordering rules: each a path, its check and its description, in the contract's order.
type OrderRule = (&'static str, fn(&QualityPolicy) -> bool, &'static str);
const ORDER_RULES: &[OrderRule] = &[
    (
        "values.brake_clear_loss",
        brake_clear_loss_under_brake_loss,
        "brake_clear_loss must be under brake_loss",
    ),
    (
        "values.hold_wake_loss",
        hold_wake_loss_at_least_brake_loss,
        "hold_wake_loss must be at least brake_loss",
    ),
    (
        "values.probe_opening_latest_ms",
        probe_opening_latest_after_opening,
        "probe_opening_latest_ms must be at least probe_opening_ms",
    ),
    (
        "values.probe_opening_ms",
        probe_opening_before_str0m_probe,
        "probe_opening_ms must end before str0m's periodic probe",
    ),
    (
        "values.qp_up",
        qp_up_under_qp_down,
        "qp_up must be under qp_down",
    ),
    (
        "values.drain_max_proven_ms",
        drain_max_within_proven,
        "drain_max_proven_ms must be at least drain_max_ms",
    ),
    (
        "values.leading_share_pct",
        leading_share_above_loaded_share,
        "leading_share_pct must be above loaded_share_pct",
    ),
    (
        "values.trying_share",
        trying_share_within_spending_share,
        "trying_share must be at most spending_share",
    ),
    (
        "values.encode_climb_share",
        encode_climb_under_budget,
        "encode_climb_share must be under encode_budget_share",
    ),
    (
        "values.cpu_climb_dwell_max_ms",
        cpu_climb_dwell_max_from_up_after,
        "cpu_climb_dwell_max_ms must be at least up_after_ms",
    ),
    (
        "values.startup_trying_ms",
        startup_trying_within_window,
        "startup_trying_ms must fit in startup_decide_after_ms",
    ),
    (
        "values.clean_rtt_margin_ms",
        clean_rtt_margin_within_brake_margin,
        "clean_rtt_margin_ms must be at most rtt_margin_ms",
    ),
    (
        "values.start_rung_index",
        start_rung_in_ladder,
        "start_rung_index must be a rung of the ladder",
    ),
];

/// `values.ladder.<i>`: best first — heights never rise, and at one height the frame rate falls, so
/// no rung repeats. A lower height may have a higher frame rate (1080p30 then 720p60).
fn ladder_best_first(p: &QualityPolicy, issues: &mut Vec<Issue>) {
    for (i, pair) in p.ladder.windows(2).enumerate() {
        let (prev, cur) = (pair[0], pair[1]);
        let ok = cur.max_h < prev.max_h || (cur.max_h == prev.max_h && cur.fps < prev.fps);
        if !ok {
            issues.push(Issue {
                path: format!("values.ladder.{}", i + 1),
                rule: "the ladder goes best first: heights fall, fps falls within one",
            });
        }
    }
}

/// `values.pinned_fps.<i>`: the pinned ladder walks falling frame rates.
fn pinned_fps_falling(p: &QualityPolicy, issues: &mut Vec<Issue>) {
    for (i, pair) in p.pinned_fps.windows(2).enumerate() {
        if pair[1] >= pair[0] {
            issues.push(Issue {
                path: format!("values.pinned_fps.{}", i + 1),
                rule: "pinned frame rates fall, best first",
            });
        }
    }
}

/// `values.quality_ratio_<preset>`: every rung absorbs at least what it is worth, or the budget's
/// `spend.clamp(floor, ceiling)` crosses — `absorb_ratio >= f64::from(quality_ratio_*)`.
fn ratios_within_absorb(p: &QualityPolicy, issues: &mut Vec<Issue>) {
    for (path, ratio, rule) in [
        (
            "values.quality_ratio_low",
            p.quality_ratio_low,
            "absorb_ratio must be at least quality_ratio_low",
        ),
        (
            "values.quality_ratio_balanced",
            p.quality_ratio_balanced,
            "absorb_ratio must be at least quality_ratio_balanced",
        ),
        (
            "values.quality_ratio_best",
            p.quality_ratio_best,
            "absorb_ratio must be at least quality_ratio_best",
        ),
    ] {
        if p.absorb_ratio < f64::from(ratio) {
            issues.push(Issue {
                path: path.to_string(),
                rule,
            });
        }
    }
}

impl QualityPolicy {
    /// The server's `quality_profile`, checked: `{id, v, values}` with every field present, typed
    /// and in range, then every cross-field rule; any failure refuses the whole profile with every
    /// failing path. Unknown keys are ignored and named in [`WireProfile::unknown_fields`]. Pure:
    /// no I/O, lock or log (the caller logs, [`SessionPolicy::for_session`]).
    pub fn from_wire(raw: &Value) -> Result<WireProfile, Rejection> {
        let Some(obj) = raw.as_object() else {
            return Err(Rejection::one("profile", "an object {id, v, values}"));
        };
        let mut issues = Vec::new();
        let mut unknown = UnknownFields::default();
        let id = obj
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_profile_id(id));
        if id.is_none() {
            issues.push(Issue {
                path: "id".into(),
                rule: "a lowercase slug",
            });
        }
        let v = obj
            .get("v")
            .and_then(Value::as_u64)
            .filter(|v| (1..=PROFILE_MAX_V).contains(v))
            .and_then(|v| u32::try_from(v).ok());
        if v.is_none() {
            issues.push(Issue {
                path: "v".into(),
                rule: "a version of 1 to 1000000",
            });
        }
        for key in obj.keys() {
            if !matches!(key.as_str(), "id" | "v" | "values") {
                unknown.push(|| key.clone());
            }
        }
        let values = obj.get("values");
        match values.and_then(Value::as_object) {
            Some(map) => check_fields(map, &mut issues, &mut unknown),
            None => issues.push(Issue {
                path: "values".into(),
                rule: "an object of every field",
            }),
        }
        if !issues.is_empty() {
            return Err(Rejection::of(issues));
        }
        let (Some(id), Some(v), Some(values)) = (id, v, values) else {
            // Unreachable: each `None` above pushed an issue.
            return Err(Rejection::one("profile", "an object {id, v, values}"));
        };
        // Every field is present and in a range its type holds, so this cannot fail; if it ever
        // does, the profile is refused like any other.
        let policy = QualityPolicy::deserialize(values)
            .map_err(|_| Rejection::one("values", "fields of their types"))?;
        policy.check_invariants(&mut issues);
        if !issues.is_empty() {
            return Err(Rejection::of(issues));
        }
        Ok(WireProfile {
            id: id.to_string(),
            v,
            policy,
            unknown_fields: unknown.names,
            unknown_count: unknown.count,
        })
    }

    /// This policy against the same bounds and rules as [`Self::from_wire`] — for a policy made in
    /// code (the fallback, a test's), which never went through the wire.
    pub fn validate(&self) -> Result<(), Rejection> {
        let mut issues = Vec::new();
        // Through the text, as the wire carries it: an `f32` prints as its shortest decimal
        // (`0.01`), while `to_value` would widen it to 0.009999999776482582 and refuse a bound
        // value.
        let wire = serde_json::to_string(self)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
        match wire {
            Some(Value::Object(map)) => {
                check_fields(&map, &mut issues, &mut UnknownFields::default());
            }
            _ => return Err(Rejection::one("values", "fields of their types")),
        }
        if issues.is_empty() {
            self.check_invariants(&mut issues);
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(Rejection::of(issues))
        }
    }

    /// Every cross-field rule, in the contract's order. Run only on fields that passed their bounds
    /// (as zod runs `.superRefine` only on a parsed object).
    fn check_invariants(&self, issues: &mut Vec<Issue>) {
        for &(path, ok, rule) in ORDER_RULES {
            if !ok(self) {
                issues.push(Issue {
                    path: path.to_string(),
                    rule,
                });
            }
        }
        ladder_best_first(self, issues);
        pinned_fps_falling(self, issues);
        ratios_within_absorb(self, issues);
    }
}

/// Why a session runs on the fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// The server sent no profile (a server older than the field, or one that chose none).
    Absent,
    /// It sent one and [`QualityPolicy::from_wire`] refused it.
    Invalid,
}

impl FallbackReason {
    /// The log's `reason=`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Invalid => "invalid",
        }
    }
}

/// The policy one session runs on, decided once at its `session_request` and kept for its life
/// (an ICE restart's re-offer keeps it): the server's profile, or the fallback.
#[derive(Debug, Clone)]
pub struct SessionPolicy {
    pub policy: Arc<QualityPolicy>,
    /// `"<id>.v<v>"`, the summary's `quality_profile`.
    pub label: String,
    pub source: QualityProfileSource,
    /// Why the fallback, when it is.
    pub reason: Option<FallbackReason>,
}

/// At most this many unknown field names go into the log line, each at most this long.
const UNKNOWN_NAMES_LOGGED: usize = 16;
const UNKNOWN_NAME_CHARS: usize = 48;

/// Unknown key names for a log line: the first [`UNKNOWN_NAMES_LOGGED`], each cut to
/// [`UNKNOWN_NAME_CHARS`], anything outside `[A-Za-z0-9_.-]` as `?` (server text must not forge
/// lines).
fn loggable_names(names: &[String]) -> String {
    names
        .iter()
        .take(UNKNOWN_NAMES_LOGGED)
        .map(|n| {
            n.chars()
                .take(UNKNOWN_NAME_CHARS)
                .map(|c| {
                    if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                        c
                    } else {
                        '?'
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(",")
}

impl SessionPolicy {
    /// The fallback, for `reason`.
    #[must_use]
    pub fn fallback(reason: FallbackReason) -> Self {
        Self {
            policy: Arc::new(QualityPolicy::fallback()),
            label: FALLBACK_LABEL.to_string(),
            source: QualityProfileSource::Fallback,
            reason: Some(reason),
        }
    }

    /// The policy for session `session_id` from its raw `quality_profile`, and the lines that say
    /// which: `info` `quality profile session=.. profile=.. source=..` (`reason=` on fallback), and
    /// at `debug` the refused rules or ignored names, never a value. Pure CPU: no I/O, no lock.
    #[must_use]
    pub fn for_session(session_id: &str, raw: Option<&Value>) -> Self {
        let chosen = match raw {
            None => Self::fallback(FallbackReason::Absent),
            Some(raw) => match QualityPolicy::from_wire(raw) {
                Ok(profile) => {
                    if profile.unknown_count > 0 {
                        tracing::debug!(
                            session = %session_id,
                            count = profile.unknown_count,
                            fields = %loggable_names(&profile.unknown_fields),
                            "quality profile: fields this agent does not know, ignored"
                        );
                    }
                    Self {
                        label: profile.label(),
                        policy: Arc::new(profile.policy),
                        source: QualityProfileSource::Server,
                        reason: None,
                    }
                }
                Err(rejection) => {
                    tracing::debug!(
                        session = %session_id,
                        count = rejection.count,
                        rules = %rejection.paths(),
                        "quality profile refused; the session runs on the fallback"
                    );
                    Self::fallback(FallbackReason::Invalid)
                }
            },
        };
        let reason = chosen
            .reason
            .map(|r| format!(" reason={}", r.as_str()))
            .unwrap_or_default();
        tracing::info!(
            "quality profile session={session_id} profile={} source={}{reason}",
            chosen.label,
            chosen.source.as_str()
        );
        chosen
    }
}

/// For tests: a profile at a corner of the contract (every field at its minimum, or maximum; an
/// exclusive minimum a hair above), moved only where a cross-field rule asks, and accepted by
/// [`QualityPolicy::from_wire`]. A bounds change that invalidates a corner fails here.
#[cfg(test)]
pub(crate) fn corner_profile(at_max: bool) -> QualityPolicy {
    let mut values = Map::new();
    for b in BOUNDS {
        let value = match b.kind {
            Kind::Int if at_max => serde_json::json!(b.max as u64),
            Kind::Int => serde_json::json!(b.min as u64),
            Kind::F32 | Kind::F64 if at_max => serde_json::json!(b.max),
            Kind::F32 | Kind::F64 if b.min_exclusive => serde_json::json!(b.min + 0.001),
            Kind::F32 | Kind::F64 => serde_json::json!(b.min),
            // Best first: heights falling by a hundred from the top, all at the top frame rate.
            Kind::Ladder if at_max => Value::Array(
                (0..b.max as u32)
                    .map(|i| serde_json::json!({"max_h": RUNG_MAX_H as u32 - 100 * i, "fps": 120}))
                    .collect(),
            ),
            Kind::Ladder => serde_json::json!([{"max_h": RUNG_MIN_H as u32, "fps": 1}]),
            Kind::Rates if at_max => Value::Array(
                (0..b.max as u32)
                    .map(|i| serde_json::json!(120 - 10 * i))
                    .collect(),
            ),
            Kind::Rates => serde_json::json!([1]),
        };
        values.insert(b.field.to_string(), value);
    }
    let get = |values: &Map<String, Value>, k: &str| values[k].as_f64().unwrap_or(0.0);
    // Off the corner by the least each rule needs.
    if at_max {
        values.insert("brake_clear_loss".into(), serde_json::json!(0.99));
        values.insert("probe_opening_ms".into(), serde_json::json!(4_000));
        let qp_down = get(&values, "qp_down");
        values.insert("qp_up".into(), serde_json::json!(qp_down - 1.0));
        let budget = get(&values, "encode_budget_share");
        values.insert(
            "encode_climb_share".into(),
            serde_json::json!(budget - 0.05),
        );
    } else {
        let brake = get(&values, "brake_loss");
        values.insert("hold_wake_loss".into(), serde_json::json!(brake));
        let qp_up = get(&values, "qp_up");
        values.insert("qp_down".into(), serde_json::json!(qp_up + 1.0));
        let loaded = get(&values, "loaded_share_pct");
        values.insert(
            "leading_share_pct".into(),
            serde_json::json!(loaded as u64 + 1),
        );
        let climb = get(&values, "encode_climb_share");
        values.insert(
            "encode_budget_share".into(),
            serde_json::json!(climb + 0.05),
        );
    }
    let raw = serde_json::json!({"id": "corner", "v": 1, "values": values});
    match QualityPolicy::from_wire(&raw) {
        Ok(p) => p.policy,
        Err(r) => panic!(
            "the {} corner is refused: {}",
            if at_max { "max" } else { "min" },
            r.paths()
        ),
    }
}

/// For tests: what the code under test logs on this thread, at `debug` and above, while the
/// capture lives — a sync test or a current-thread `#[tokio::test]` (which polls on this thread).
#[cfg(test)]
pub(crate) mod log_capture {
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub(crate) struct Capture {
        buffer: Buffer,
        _guard: tracing::subscriber::DefaultGuard,
        // A second live dispatcher makes tracing ask every one of them rather than cache "off"
        // for a call site another test's subscriber saw first.
        _second: tracing::Dispatch,
    }

    impl Capture {
        /// Everything logged so far.
        pub(crate) fn text(&self) -> String {
            let bytes = self
                .buffer
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            String::from_utf8_lossy(&bytes).into_owned()
        }
    }

    pub(crate) fn start() -> Capture {
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        let _second = tracing::Dispatch::new(tracing_subscriber::registry());
        let _guard = tracing::subscriber::set_default(subscriber);
        Capture {
            buffer,
            _guard,
            _second,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reference_round_trips_through_json_unchanged() {
        let reference = QualityPolicy::reference();
        let json = serde_json::to_string(&reference).expect("the reference policy serializes");
        let back: QualityPolicy =
            serde_json::from_str(&json).expect("the reference policy deserializes");
        assert_eq!(back, reference, "{json}");
        // And the floats bit for bit, which `PartialEq` on f32/f64 would also pass for -0.0 == 0.0.
        assert_eq!(
            serde_json::to_string(&back).expect("serializes again"),
            json,
            "a second round trip prints the same text"
        );
    }

    #[test]
    fn the_derived_values_are_their_bases() {
        let p = QualityPolicy::reference();
        assert_eq!(p.measured_within(), p.down_after());
        assert_eq!(p.probe_ramp(), p.startup_decide_after());
        assert_eq!(p.real_loss().to_bits(), p.brake_clear_loss.to_bits());
        assert_eq!(p.reanchor_min_kbps(), p.loaded_floor_kbps);
        assert_eq!(p.outage_confirm(), p.clean_rtt_for());
        assert_eq!(p.drain_exit_fallback_ms(), 1_000);
        assert_eq!(p.rtt_margin_ms, 2 * QUEUE_GUARD_MS);
        assert_eq!(p.start_rung(), LADDER[0]);
        assert_eq!(QualityPolicy::default(), p);
    }

    #[test]
    fn the_inline_shares_kept_their_bits() {
        let p = QualityPolicy::reference();
        // Written as `SPENDING_SHARE / 2.0` and `1.0 / 3.0` on f32 constants before: the same bits.
        assert_eq!(p.trying_share.to_bits(), (0.8f32 / 2.0).to_bits());
        assert_eq!(p.trying_share.to_bits(), 0.4f32.to_bits());
        assert_eq!(p.drop_share.to_bits(), (1.0f32 / 3.0).to_bits());
    }

    // ── the wire profile ──────────────────────────────────────────────────────────────────────

    fn protocol_file(rel: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol")
            .join(rel);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{path:?}: {e} (the contract submodule checked out?)"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
    }

    fn reference_vector() -> Value {
        protocol_file("vectors/quality-profile-reference.json")
    }

    fn paths(r: &Rejection) -> Vec<&str> {
        r.issues.iter().map(|i| i.path.as_str()).collect()
    }

    #[test]
    fn the_reference_vector_is_the_reference() {
        let profile = QualityPolicy::from_wire(&reference_vector()).expect("the reference passes");
        assert_eq!(profile.policy, QualityPolicy::reference());
        assert_eq!(profile.label(), "default.v1");
        assert!(
            profile.unknown_fields.is_empty(),
            "{:?}",
            profile.unknown_fields
        );
        // Bit for bit, floats included (`PartialEq` would pass -0.0 for 0.0): the same text.
        assert_eq!(
            serde_json::to_string(&profile.policy).expect("serializes"),
            serde_json::to_string(&QualityPolicy::reference()).expect("serializes")
        );
        assert_eq!(QualityPolicy::reference().validate(), Ok(()));
        assert_eq!(QualityPolicy::fallback().validate(), Ok(()));

        // And through the tools' path: the file at `REFERENCE_VECTOR`, read at run time.
        let read = load_profile_file(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(REFERENCE_VECTOR),
        )
        .expect("the reference vector reads");
        assert_eq!(read.label(), "default.v1");
        assert_eq!(
            serde_json::to_string(&read.policy).expect("serializes"),
            serde_json::to_string(&QualityPolicy::reference()).expect("serializes")
        );
    }

    /// A file that is not there, not JSON or refused is an error naming the file (and the failing
    /// paths), never a profile.
    #[test]
    fn a_profile_file_is_read_whole_or_not_at_all() {
        let dir = std::env::temp_dir().join(format!("afk-profile-file-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let missing = dir.join("missing.json");
        let e = load_profile_file(&missing).expect_err("no file");
        assert!(e.contains("missing.json"), "{e}");

        let not_json = dir.join("not-json.json");
        std::fs::write(&not_json, "{ id: ").expect("write");
        let e = load_profile_file(&not_json).expect_err("not JSON");
        assert!(e.contains("not JSON"), "{e}");

        let mut bad = reference_vector();
        bad["values"]["qp_up"] = serde_json::json!(50);
        let refused = dir.join("refused.json");
        std::fs::write(&refused, bad.to_string()).expect("write");
        let e = load_profile_file(&refused).expect_err("refused");
        assert!(
            e.contains("refused at") && e.contains("values.qp_up"),
            "{e}"
        );
        assert!(!e.contains("50"), "no value in the error: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── the compiled profile ──────────────────────────────────────────────────────────────────

    /// The compiled profile is the safe one, and it passes every bound and rule a server's profile
    /// must — checked on the struct and through its wire text, as the server would send it.
    #[test]
    fn the_fallback_is_the_safe_profile_and_passes_the_contracts_checks() {
        let safe = QualityPolicy::safe();
        assert_eq!(QualityPolicy::fallback(), safe);
        assert_ne!(safe, QualityPolicy::reference());
        assert_eq!(safe.validate(), Ok(()));
        let wire = serde_json::json!({
            "id": "builtin",
            "v": 1,
            "values": serde_json::to_value(&safe).expect("serializes"),
        });
        let back =
            QualityPolicy::from_wire(&wire).expect("the safe profile passes the wire checks");
        assert_eq!(back.label(), FALLBACK_LABEL);
        assert_eq!(
            serde_json::to_string(&back.policy).expect("serializes"),
            serde_json::to_string(&safe).expect("serializes"),
            "the same bits after the wire"
        );
    }

    /// What makes it the careful one, field by field against the reference: a lower top without 60
    /// fps, stricter and slower climbs, descents no slower, an earlier, deeper and slower-releasing
    /// brake, fewer re-anchors, earlier and shorter drains, a smaller opening bid.
    #[test]
    fn the_safe_profile_is_more_careful_where_it_says() {
        let s = QualityPolicy::safe();
        let r = QualityPolicy::reference();
        let top = s.start_rung();
        assert_eq!((top.max_h, top.fps), (720, 30));
        assert!(s.ladder.iter().all(|x| x.max_h <= 720 && x.fps <= 30));
        assert!(s.pinned_fps.iter().all(|&f| f <= 30));
        assert_eq!(s.start_rung_index, 0);
        // Climbs.
        assert!(s.up_after_ms >= 2 * r.up_after_ms);
        assert!(s.up_headroom > r.up_headroom);
        assert!(s.quality_ratio_balanced > r.quality_ratio_balanced);
        assert!(s.qp_up < r.qp_up);
        assert!(s.roomy_late_factor > r.roomy_late_factor);
        assert!(s.encode_climb_share < r.encode_climb_share);
        assert!(s.cpu_climb_dwell_max_ms > r.cpu_climb_dwell_max_ms);
        // Descents no slower.
        assert!(s.down_after_ms <= r.down_after_ms);
        assert!(s.settle_after_move_ms <= r.settle_after_move_ms);
        assert!(s.qp_down < r.qp_down);
        assert!(s.drop_share < r.drop_share);
        assert!(s.encode_budget_share < r.encode_budget_share);
        // The budget. Not lower: the spend share is coupled to the 1.1x pacer and
        // `leading_share_pct`, and 80 turned every delay spike into a cut never regained.
        assert!(s.spend_pct <= r.spend_pct);
        assert!(s.absorb_ratio < r.absorb_ratio);
        assert!(s.explore_margin_kbps < r.explore_margin_kbps);
        assert!(s.explore_growth_pct < r.explore_growth_pct);
        assert!(s.pushback_depth > r.pushback_depth);
        assert!(s.informative_half_life_ms < r.informative_half_life_ms);
        // The brake.
        assert!(s.brake_loss < r.brake_loss);
        assert!(s.brake_backoff < r.brake_backoff);
        assert!(s.rtt_margin_ms < r.rtt_margin_ms);
        assert!(s.brake_release_per_sec < r.brake_release_per_sec);
        // Re-anchors and re-probes.
        assert!(s.reanchor_every_ms > r.reanchor_every_ms);
        assert!(s.reanchor_divergence_pct > r.reanchor_divergence_pct);
        assert!(s.outage_divergence_pct > r.outage_divergence_pct);
        assert!(s.reanchor_after_pause_ms > r.reanchor_after_pause_ms);
        assert!(s.clean_rtt_margin_ms < r.clean_rtt_margin_ms);
        assert!(s.path_reprobe_every_ms > r.path_reprobe_every_ms);
        // Drains.
        assert!(s.drain_enter_rtt_ms < r.drain_enter_rtt_ms);
        assert!(s.drain_max_ms < r.drain_max_ms);
        assert!(s.drain_max_proven_ms < r.drain_max_proven_ms);
        assert!(s.drain_resume_share_pct < r.drain_resume_share_pct);
        // The thin line is the ladder's second height, as the reference's (900) is.
        assert_eq!(s.startup_thin_below_h, s.ladder[1].max_h);
        assert_eq!(r.startup_thin_below_h, r.ladder[2].max_h);
    }

    #[test]
    fn every_invalid_vector_is_refused_at_its_path() {
        let cases = protocol_file("vectors/quality-profile-invalid.json");
        let cases = cases.as_array().expect("a list of cases");
        assert!(cases.len() >= 40, "{} cases", cases.len());
        for case in cases {
            let name = case["name"].as_str().expect("a name");
            let expect: Vec<String> = case["expect_path"]
                .as_array()
                .expect("a path")
                .iter()
                .map(|p| match p {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            let expect = expect.join(".");
            let rejection = QualityPolicy::from_wire(&case["profile"])
                .err()
                .unwrap_or_else(|| panic!("{name}: accepted"));
            assert!(
                paths(&rejection).contains(&expect.as_str()),
                "{name}: refused at {:?}, not at {expect}",
                paths(&rejection)
            );
        }
    }

    /// Each field's range here is the contract's: its JSON Schema, field by field, so the two sides
    /// cannot drift apart. And the fields are the struct's, all of them, in its order.
    #[test]
    fn the_bounds_are_the_contracts_schema() {
        let schema = protocol_file("schema/quality-profile.json");
        let values = &schema["properties"]["values"];
        let props = values["properties"].as_object().expect("the fields");
        let names: Vec<&str> = BOUNDS.iter().map(|b| b.field).collect();
        let required: Vec<&str> = values["required"]
            .as_array()
            .expect("required")
            .iter()
            .map(|v| v.as_str().expect("a name"))
            .collect();
        assert_eq!(
            names, required,
            "every field required, in the struct's order"
        );
        assert_eq!(props.len(), BOUNDS.len());
        let wire = serde_json::to_value(QualityPolicy::reference()).expect("serializes");
        let mut fields: Vec<&str> = wire
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        let mut sorted = names.clone();
        fields.sort_unstable();
        sorted.sort_unstable();
        assert_eq!(fields, sorted, "the table has every field of the struct");

        let min_of = |s: &Value, exclusive: bool| {
            let key = if exclusive {
                "exclusiveMinimum"
            } else {
                "minimum"
            };
            s[key].as_f64()
        };
        for b in BOUNDS {
            let s = &props[b.field];
            let f = b.field;
            match b.kind {
                Kind::Int | Kind::F32 | Kind::F64 => {
                    let ty = if b.kind == Kind::Int {
                        "integer"
                    } else {
                        "number"
                    };
                    assert_eq!(s["type"], ty, "{f}: type");
                    assert_eq!(min_of(s, b.min_exclusive), Some(b.min), "{f}: min");
                    assert!(
                        s[if b.min_exclusive {
                            "minimum"
                        } else {
                            "exclusiveMinimum"
                        }]
                        .is_null(),
                        "{f}: the other kind of minimum"
                    );
                    assert_eq!(s["maximum"].as_f64(), Some(b.max), "{f}: max");
                    // And the struct holds it as that kind: integers print as integers.
                    assert_eq!(
                        wire[f].is_u64(),
                        b.kind == Kind::Int,
                        "{f}: integer or float"
                    );
                }
                Kind::Ladder | Kind::Rates => {
                    assert_eq!(s["type"], "array", "{f}");
                    assert_eq!(s["minItems"].as_f64(), Some(b.min), "{f}: min items");
                    assert_eq!(s["maxItems"].as_f64(), Some(b.max), "{f}: max items");
                    let items = &s["items"];
                    if b.kind == Kind::Rates {
                        assert_eq!(items["type"], "integer", "{f}");
                        assert_eq!(items["minimum"].as_f64(), Some(1.0), "{f}");
                        assert_eq!(items["maximum"].as_f64(), Some(RUNG_MAX_FPS), "{f}");
                    } else {
                        let rung = &items["properties"];
                        assert_eq!(rung["max_h"]["minimum"].as_f64(), Some(RUNG_MIN_H));
                        assert_eq!(rung["max_h"]["maximum"].as_f64(), Some(RUNG_MAX_H));
                        assert_eq!(rung["fps"]["minimum"].as_f64(), Some(1.0));
                        assert_eq!(rung["fps"]["maximum"].as_f64(), Some(RUNG_MAX_FPS));
                    }
                }
            }
        }
        // The profile's own two fields.
        let top = &schema["properties"];
        assert_eq!(top["id"]["pattern"], "^[a-z][a-z0-9-]{0,31}$");
        assert_eq!(top["v"]["minimum"].as_u64(), Some(1));
        assert_eq!(top["v"]["maximum"].as_u64(), Some(PROFILE_MAX_V));
    }

    /// The constants the bounds and rules restate, against the contract's source and this crate.
    #[test]
    fn the_restated_constants_are_the_contracts() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol/src/quality-profile.ts");
        let ts = std::fs::read_to_string(&path).expect("quality-profile.ts");
        for line in [
            format!("QUALITY_QUEUE_GUARD_MS = {QUEUE_GUARD_MS};"),
            format!("QUALITY_TICK_MS = {TICK_MS};"),
            format!(
                "QUALITY_DELIVERY_HISTORY_MS = {} * QUALITY_TICK_MS;",
                crate::quality::DELIVERY_HISTORY_TICKS
            ),
            format!(
                "QUALITY_RTT_BASE_REPORTS = {};",
                crate::quality::RTT_BASE_REPORTS
            ),
            "QUALITY_MAX_DESIRED_KBPS = 12_000;".to_string(),
            "QUALITY_ENCODER_QP_MIN = 16;".to_string(),
            "QUALITY_ENCODER_QP_MAX = 46;".to_string(),
            "QUALITY_STARVED_QP_STEPS = 4;".to_string(),
            "QUALITY_STR0M_ALR_PROBE_GAP_MS = 5_000;".to_string(),
            "QUALITY_PROBE_OPENING_SLACK_MS = 2 * QUALITY_TICK_MS;".to_string(),
            "QUALITY_MAX_DURATION_MS = 120_000;".to_string(),
        ] {
            assert!(
                ts.contains(&line),
                "quality-profile.ts no longer says `{line}`"
            );
        }
        assert_eq!(
            u128::from(TICK_MS),
            crate::quality::TICK.as_millis(),
            "TICK_MS"
        );
        assert_eq!(
            MAX_KBPS.to_bits(),
            f64::from(crate::quality::MAX_DESIRED_KBPS).to_bits()
        );
        assert_eq!(STR0M_ALR_PROBE_GAP_MS, 5_000);
    }

    #[test]
    fn an_unknown_field_is_ignored_and_named() {
        let mut raw = reference_vector();
        raw["values"]["tomorrows_knob"] = serde_json::json!(7);
        raw["hash"] = serde_json::json!("abc");
        let profile = QualityPolicy::from_wire(&raw).expect("an unknown key is not an error");
        assert_eq!(profile.policy, QualityPolicy::reference());
        assert_eq!(
            profile.unknown_fields,
            vec!["hash".to_string(), "values.tomorrows_knob".to_string()]
        );
    }

    #[test]
    fn a_missing_field_refuses_the_whole_profile() {
        let mut raw = reference_vector();
        raw["values"]
            .as_object_mut()
            .expect("values")
            .remove("down_after_ms");
        let r = QualityPolicy::from_wire(&raw).expect_err("refused");
        assert_eq!(paths(&r), vec!["values.down_after_ms"]);
    }

    /// Every failing path, not only the first; and nothing of the server's in a path.
    #[test]
    fn a_rejection_lists_every_failure() {
        let mut raw = reference_vector();
        raw["id"] = serde_json::json!("Not A Slug\nsession_request x");
        raw["values"]["path_step_drift_div"] = serde_json::json!(0);
        raw["values"]["ladder"][2]["fps"] = serde_json::json!(0);
        raw["values"]["pinned_fps"] = serde_json::json!([]);
        let r = QualityPolicy::from_wire(&raw).expect_err("refused");
        assert_eq!(
            paths(&r),
            vec![
                "id",
                "values.ladder.2.fps",
                "values.pinned_fps",
                "values.path_step_drift_div"
            ]
        );
        assert_eq!(
            r.paths(),
            "id,values.ladder.2.fps,values.pinned_fps,values.path_step_drift_div"
        );
        // Not an object at all, or no values.
        for raw in [serde_json::json!("x"), serde_json::json!([1]), Value::Null] {
            assert_eq!(
                paths(&QualityPolicy::from_wire(&raw).expect_err("refused")),
                vec!["profile"]
            );
        }
        let r = QualityPolicy::from_wire(&serde_json::json!({"id": "a", "v": 1})).expect_err("no");
        assert_eq!(paths(&r), vec!["values"]);
    }

    /// The values that would panic or overflow the controller, each refused: a zero divisor, a zero
    /// multiple, a shift past eight doublings, a ring that cannot fill, an empty ladder or pinned
    /// ladder, a rung at zero frames, a start past the ladder, a clamp whose bounds cross, a
    /// negative or fractional integer, a number too large for its type.
    #[test]
    fn values_that_would_break_the_controller_are_refused() {
        let cases: &[(&str, Value, &str)] = &[
            (
                "path_step_drift_div",
                serde_json::json!(0),
                "values.path_step_drift_div",
            ),
            (
                "probe_capacity_multiple",
                serde_json::json!(0),
                "values.probe_capacity_multiple",
            ),
            (
                "reanchor_backoff_max",
                serde_json::json!(32),
                "values.reanchor_backoff_max",
            ),
            (
                "rtt_base_min_reports",
                serde_json::json!(31),
                "values.rtt_base_min_reports",
            ),
            ("ladder", serde_json::json!([]), "values.ladder"),
            ("pinned_fps", serde_json::json!([]), "values.pinned_fps"),
            (
                "pinned_fps",
                serde_json::json!([60, 0]),
                "values.pinned_fps.1",
            ),
            (
                "start_rung_index",
                serde_json::json!(8),
                "values.start_rung_index",
            ),
            (
                "clean_rtt_margin_ms",
                serde_json::json!(76),
                "values.clean_rtt_margin_ms",
            ),
            (
                "informative_half_life_ms",
                serde_json::json!(0),
                "values.informative_half_life_ms",
            ),
            (
                "delivery_rate_window_ms",
                serde_json::json!(0),
                "values.delivery_rate_window_ms",
            ),
            (
                "down_after_ms",
                serde_json::json!(-1),
                "values.down_after_ms",
            ),
            (
                "down_after_ms",
                serde_json::json!(2000.5),
                "values.down_after_ms",
            ),
            (
                "down_after_ms",
                serde_json::json!(5_000_000_000u64),
                "values.down_after_ms",
            ),
            ("brake_loss", serde_json::json!("0.1"), "values.brake_loss"),
            ("brake_loss", serde_json::json!(1e300), "values.brake_loss"),
        ];
        for (field, value, path) in cases {
            let mut raw = reference_vector();
            raw["values"][*field] = value.clone();
            let r = QualityPolicy::from_wire(&raw)
                .err()
                .unwrap_or_else(|| panic!("{field} = {value}: accepted"));
            assert_eq!(paths(&r), vec![*path], "{field} = {value}");
        }
        let mut zero_fps = reference_vector();
        zero_fps["values"]["ladder"][0]["fps"] = serde_json::json!(0);
        assert_eq!(
            paths(&QualityPolicy::from_wire(&zero_fps).expect_err("refused")),
            vec!["values.ladder.0.fps"]
        );
    }

    /// The rules a field's own bound fails by (not a cross-field rule at the same path).
    const BOUND_RULES: &[&str] = &[
        "a whole number in its range",
        "a number in its range",
        "a list",
        "a list of the allowed length",
    ];

    /// Whether the reference vector with `field` set to `value` fails that field's own bound.
    fn bound_refuses(field: &str, value: Value) -> bool {
        let mut raw = reference_vector();
        raw["values"][field] = value;
        let path = format!("values.{field}");
        QualityPolicy::from_wire(&raw).is_err_and(|r| {
            r.issues
                .iter()
                .any(|i| i.path == path && BOUND_RULES.contains(&i.rule))
        })
    }

    /// Every field at the edges of its bound, from [`BOUNDS`], decided as zod decides on the wire's
    /// double: inclusive edges taken (`brake_loss = 0.01`), an exclusive minimum refused and just
    /// above it taken, just outside refused; lists at their shortest and longest taken, one beyond
    /// refused. Only the field's own bound is asked here.
    #[test]
    fn every_bound_holds_at_its_edges_as_zod_does() {
        let reference = reference_vector();
        for b in BOUNDS {
            let f = b.field;
            match b.kind {
                Kind::Int => {
                    let (min, max) = (b.min as i64, b.max as i64);
                    assert!(!b.min_exclusive, "{f}: no integer is bounded exclusively");
                    assert!(!bound_refuses(f, serde_json::json!(min)), "{f} = {min}");
                    assert!(!bound_refuses(f, serde_json::json!(max)), "{f} = {max}");
                    assert!(
                        bound_refuses(f, serde_json::json!(min - 1)),
                        "{f} = {min} - 1"
                    );
                    assert!(
                        bound_refuses(f, serde_json::json!(max + 1)),
                        "{f} = {max} + 1"
                    );
                }
                Kind::F32 | Kind::F64 => {
                    let step = |x: f64| x.abs().max(1.0) * 1e-9;
                    let (min, max) = (b.min, b.max);
                    if b.min_exclusive {
                        assert!(bound_refuses(f, serde_json::json!(min)), "{f} = {min}");
                        let above = min + step(min);
                        assert!(!bound_refuses(f, serde_json::json!(above)), "{f} = {above}");
                    } else {
                        assert!(!bound_refuses(f, serde_json::json!(min)), "{f} = {min}");
                        let under = min - step(min);
                        assert!(bound_refuses(f, serde_json::json!(under)), "{f} = {under}");
                    }
                    assert!(!bound_refuses(f, serde_json::json!(max)), "{f} = {max}");
                    let over = max + step(max);
                    assert!(bound_refuses(f, serde_json::json!(over)), "{f} = {over}");
                }
                Kind::Ladder | Kind::Rates => {
                    let item = if b.kind == Kind::Ladder {
                        reference["values"]["ladder"][0].clone()
                    } else {
                        serde_json::json!(30)
                    };
                    let list = |n: f64| Value::Array(vec![item.clone(); n as usize]);
                    assert!(!bound_refuses(f, list(b.min)), "{f}: {} items", b.min);
                    assert!(!bound_refuses(f, list(b.max)), "{f}: {} items", b.max);
                    assert!(bound_refuses(f, list(b.min - 1.0)), "{f}: {} - 1", b.min);
                    assert!(bound_refuses(f, list(b.max + 1.0)), "{f}: {} + 1", b.max);
                }
            }
        }
        // The case the review found, whole: at its minimum, with the brake's other losses below
        // and above it as the rules ask.
        let mut raw = reference;
        raw["values"]["brake_loss"] = serde_json::json!(0.01);
        raw["values"]["brake_clear_loss"] = serde_json::json!(0.005);
        let p = QualityPolicy::from_wire(&raw).expect("brake_loss at its inclusive minimum");
        assert_eq!(p.policy.brake_loss.to_bits(), 0.01f32.to_bits());
        assert_eq!(
            p.policy.validate(),
            Ok(()),
            "and the policy made of it validates"
        );
    }

    /// A profile built to be expensive to refuse costs little: a million-item list is refused by
    /// its length alone, a profile failing everywhere keeps [`ISSUES_KEPT`] issues and counts the
    /// rest, and a flood of unknown keys keeps sixteen names and a count.
    #[test]
    fn a_flood_of_items_issues_or_keys_stays_small() {
        const FLOOD: usize = 1_000_000;
        for field in ["ladder", "pinned_fps"] {
            let mut raw = reference_vector();
            // Each item invalid, so a walk over them would be a million issues.
            raw["values"][field] = Value::Array(vec![serde_json::json!(0); FLOOD]);
            let r = QualityPolicy::from_wire(&raw).expect_err("refused by its length");
            assert_eq!(paths(&r), vec![format!("values.{field}")], "{field}");
            assert_eq!(r.count, 1);
            assert!(r.paths().len() < 64, "{}", r.paths());
        }

        let mut raw = reference_vector();
        for b in BOUNDS {
            raw["values"][b.field] = serde_json::json!("x");
        }
        let r = QualityPolicy::from_wire(&raw).expect_err("refused everywhere");
        assert_eq!(r.count, BOUNDS.len());
        assert_eq!(r.issues.len(), ISSUES_KEPT);
        assert!(r.paths().len() < ISSUES_KEPT * 48, "{}", r.paths().len());

        let mut raw = reference_vector();
        let values = raw["values"].as_object_mut().expect("values");
        for i in 0..100_000 {
            values.insert(format!("knob_{i}"), serde_json::json!(i));
        }
        let p = QualityPolicy::from_wire(&raw).expect("unknown keys are no error");
        assert_eq!(p.policy, QualityPolicy::reference());
        assert_eq!(p.unknown_count, 100_000);
        assert_eq!(p.unknown_fields.len(), UNKNOWN_NAMES_LOGGED);
    }

    /// A tuning the contract allows, though no reference value: accepted whole.
    #[test]
    fn a_different_profile_is_taken_whole() {
        let mut raw = reference_vector();
        raw["id"] = serde_json::json!("relay-thin");
        raw["v"] = serde_json::json!(3);
        raw["values"]["down_after_ms"] = serde_json::json!(3_000);
        raw["values"]["ladder"] = serde_json::json!([
            {"max_h": 720, "fps": 30}, {"max_h": 540, "fps": 30}, {"max_h": 360, "fps": 15}
        ]);
        raw["values"]["start_rung_index"] = serde_json::json!(1);
        let p = QualityPolicy::from_wire(&raw).expect("valid");
        assert_eq!(p.label(), "relay-thin.v3");
        assert_eq!(p.policy.down_after_ms, 3_000);
        assert_eq!(p.policy.start_rung().max_h, 540);
        assert_eq!(p.policy.validate(), Ok(()));
    }

    #[test]
    fn a_session_policy_says_where_it_came_from() {
        let absent = SessionPolicy::for_session("s", None);
        assert_eq!(absent.source, QualityProfileSource::Fallback);
        assert_eq!(absent.reason, Some(FallbackReason::Absent));
        assert_eq!(absent.label, FALLBACK_LABEL);
        assert_eq!(*absent.policy, QualityPolicy::fallback());

        let mut bad = reference_vector();
        bad["values"]["qp_up"] = serde_json::json!(50);
        let invalid = SessionPolicy::for_session("s", Some(&bad));
        assert_eq!(invalid.source, QualityProfileSource::Fallback);
        assert_eq!(invalid.reason, Some(FallbackReason::Invalid));
        assert_eq!(
            *invalid.policy,
            QualityPolicy::fallback(),
            "nothing of the refused profile"
        );

        let mut good = reference_vector();
        good["values"]["down_after_ms"] = serde_json::json!(2_500);
        let server = SessionPolicy::for_session("s", Some(&good));
        assert_eq!(server.source, QualityProfileSource::Server);
        assert_eq!(server.reason, None);
        assert_eq!(server.label, "default.v1");
        assert_eq!(server.policy.down_after_ms, 2_500);
    }

    /// Labels the agent reports fit the contract's `QUALITY_PROFILE_LABEL_PATTERN`,
    /// `^[a-z][a-z0-9-]{0,31}\.v([1-9][0-9]{0,6})$`, and its 48 characters.
    #[test]
    fn the_labels_fit_the_contracts_pattern() {
        let fits = |label: &str| {
            let Some((id, v)) = label.rsplit_once(".v") else {
                return false;
            };
            is_profile_id(id)
                && !v.starts_with('0')
                && (1..=7).contains(&v.len())
                && v.chars().all(|c| c.is_ascii_digit())
                && label.len() <= afklink_protocol::metrics::QUALITY_PROFILE_LABEL_MAX
        };
        assert!(fits(FALLBACK_LABEL));
        let longest = WireProfile {
            id: "a".repeat(PROFILE_ID_MAX),
            v: 1_000_000,
            policy: QualityPolicy::reference(),
            unknown_fields: vec![],
            unknown_count: 0,
        };
        assert!(fits(&longest.label()), "{}", longest.label());
        assert!(!fits("Default.v1") && !fits("default.v0") && !fits("default"));
    }

    #[test]
    fn unknown_names_cannot_make_a_line_of_their_own() {
        let names = vec![
            "values.ok_name".to_string(),
            "x\nsession_request 1 from user 2".to_string(),
        ];
        let logged = loggable_names(&names);
        assert_eq!(logged, "values.ok_name,x?session_request?1?from?user?2");
        let many: Vec<String> = (0..40).map(|i| format!("{i}{}", "y".repeat(100))).collect();
        let logged = loggable_names(&many);
        assert_eq!(logged.split(',').count(), UNKNOWN_NAMES_LOGGED);
        assert!(logged
            .split(',')
            .all(|n| n.chars().count() <= UNKNOWN_NAME_CHARS));
    }

    /// The reference tuning is in no production source. It is compiled into the tests only
    /// (`#[cfg(any(test, doc))]`: [`QualityPolicy::reference`], `LADDER`, `QualityPolicy`'s and
    /// `QualityTarget`'s `Default`, and every shorthand that reads it), so a production call would
    /// not build; this scan checks the text as well, in every crate's `src` and the app's (the
    /// simulator included), outside test-only items, comments and literals: nothing names the
    /// reference (`QualityPolicy::reference()`/`default()`, `LADDER`) or one of its shorthands
    /// (`QualityController::new`, a bare `start_rung()`, the free functions without `_with`,
    /// `Rung::required_kbps`/`absorbable_kbps`, `Quality::ratio`, `QualityTarget::default()`).
    ///
    /// The reference is matched as a path too (`QualityPolicy::reference` passed as a function),
    /// and `QualityPolicy`'s `Default` when the line names the type; a `Default::default()` whose
    /// type is written elsewhere is beyond a text scan. `the_reference_scan_finds_a_misuse` holds
    /// the scanner to a planted misuse.
    #[test]
    fn a_session_reads_the_reference_only_through_the_fallback() {
        let agent = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut roots = vec![agent.join("app/src-tauri/src")];
        for e in std::fs::read_dir(agent.join("crates"))
            .expect("crates/")
            .flatten()
        {
            if e.path().join("src").is_dir() {
                roots.push(e.path().join("src"));
            }
        }
        assert!(roots.len() > 8, "found {} crates", roots.len());
        let mut files = Vec::new();
        for root in &roots {
            collect_rs(root, &mut files);
        }
        let test_only = test_only_module_files(&files);
        files.retain(|f| !test_only.iter().any(|t| f.starts_with(t)));
        assert!(files.len() > 40, "found {} files", files.len());

        let mut stray = Vec::new();
        let mut test_only_reads = 0;
        for file in &files {
            let text = std::fs::read_to_string(file).expect("readable");
            let name = file.to_string_lossy().replace('\\', "/");
            for read in reference_reads(&text) {
                stray.push(format!(
                    "{name}:{}: {} (`{}`, in fn {:?})",
                    read.n, read.line, read.what, read.within
                ));
            }
            if name.ends_with("/crates/core/src/quality.rs")
                || name.ends_with("/crates/core/src/quality_policy.rs")
            {
                // What the scan skipped there as test-only: the reference and its shorthands are
                // defined in these two files, so it is reading them and skipping exactly that.
                test_only_reads += reference_reads(&text.replace("#[cfg(any(test, doc))]", ""))
                    .iter()
                    .filter(|r| r.what == "QualityPolicy::reference" || r.what == "Self::reference")
                    .count();
            }
        }
        assert!(
            stray.is_empty(),
            "the reference policy named in production code: {stray:#?}"
        );
        assert!(
            test_only_reads >= 8,
            "{test_only_reads} test-only reads of the reference seen in quality.rs and \
             quality_policy.rs"
        );
    }

    /// The scanner finds a planted misuse in production code (a call, an import, after a test
    /// module) and nothing in a comment, a literal or a `#[cfg(test)]` item, even one with
    /// unbalanced braces in its literals.
    #[test]
    fn the_reference_scan_finds_a_misuse() {
        let source = r##"
use crate::quality::{start_rung, LADDER};
const NOTE: &str = "QualityPolicy::reference() is only a word here {";
fn session(policy: &QualityPolicy) {
    // QualityPolicy::reference() in a comment
    /* QualityController::new( in a block comment */
    let open = '{';
    let p = QualityPolicy::reference();
    let r = start_rung();
    let fine = policy.start_rung();
    let top = LADDER[0];
    let not_it = MY_LADDER_X;
    let raw = r#"desired_bitrate_kbps( {"#;
}
#[cfg(test)]
mod tests {
    fn t() {
        let brace = '{';
        let s = "{{";
        let p = QualityPolicy::reference();
    }
}
#[cfg(all(test, windows))]
fn probe() -> u32 { QualityPolicy::reference().spend_pct }
fn after() {
    let c = QualityController::new(1, 2, q);
}
fn later(cfg: Option<QualityPolicy>) {
    let q = cfg.unwrap_or_else(QualityPolicy::reference);
    let d: QualityPolicy = Default::default();
}
"##;
        let found: Vec<(usize, &str, Option<String>)> = reference_reads(source)
            .into_iter()
            .map(|r| (r.n, r.what, r.within))
            .collect();
        let session = Some("session".to_string());
        assert_eq!(
            found,
            vec![
                (2, "LADDER", None),
                (8, "QualityPolicy::reference", session.clone()),
                (9, "start_rung()", session.clone()),
                (11, "LADDER", session),
                (26, "QualityController::new(", Some("after".to_string())),
                (29, "QualityPolicy::reference", Some("later".to_string())),
                (30, "QualityPolicy's Default", Some("later".to_string())),
            ]
        );

        let dir = std::path::Path::new("x/src");
        let files = [dir.join("lib.rs"), dir.join("a.rs")];
        let declared = |path: &std::path::Path, text: &str| {
            test_only_modules_of(path, text)
                .into_iter()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            declared(&files[0], "#[cfg(test)]\nmod tests;\nmod a;\n"),
            vec!["x/src/tests.rs", "x/src/tests"]
        );
        assert_eq!(
            declared(
                &files[1],
                "#[cfg(test)]\n#[allow(dead_code)]\npub(crate) mod sim;\n"
            ),
            vec!["x/src/a/sim.rs", "x/src/a/sim"]
        );
    }

    /// One read of the reference [`reference_reads`] found.
    struct ReferenceRead {
        /// The line's number, from one.
        n: usize,
        /// The line, trimmed.
        line: String,
        /// The token that named the reference.
        what: &'static str,
        /// The function the line is in: the last `fn` declared before it outside tests.
        within: Option<String>,
    }

    /// The tokens that read the reference tuning, matched in code only (comments and literals
    /// blanked): calls of the reference and of its shorthands.
    const REFERENCE_TOKENS: &[&str] = &[
        "QualityController::new(",
        "QualityTarget::default()",
        "opening_probe_target_kbps(",
        "desired_bitrate_kbps(",
        "probe_floor_kbps(",
        ".required_kbps(",
        ".absorbable_kbps(",
        "Quality::ratio(",
        ".ratio()",
    ];

    /// Paths that name the reference, matched as whole identifiers, called or not.
    const REFERENCE_PATHS: &[&str] = &[
        "QualityPolicy::reference",
        "Self::reference",
        "QualityPolicy::default",
        "LADDER",
    ];

    /// Every production line of `text` (outside `#[cfg(test)]` items) reading the reference: a
    /// [`REFERENCE_TOKENS`] entry, a bare `start_rung()`, or `LADDER`. Definitions are skipped.
    fn reference_reads(text: &str) -> Vec<ReferenceRead> {
        let code = code_only(text);
        let original: Vec<&str> = text.lines().collect();
        let mut out = Vec::new();
        let mut within: Option<String> = None;
        for (n, line) in production_lines(&code) {
            let declared = declared_fn(line);
            let signature = declared.is_some();
            if let Some(f) = declared {
                within = Some(f);
            }
            if signature {
                continue;
            }
            let mut hits: Vec<&'static str> = REFERENCE_TOKENS
                .iter()
                .copied()
                .filter(|t| line.contains(t))
                .collect();
            if names_bare(line, "start_rung()") {
                hits.push("start_rung()");
            }
            // As paths too, not only as calls (`.unwrap_or_else(QualityPolicy::reference)`).
            for path in REFERENCE_PATHS {
                if names_ident(line, path) {
                    hits.push(path);
                }
            }
            // A `Default` that is the reference, by a line that names the type (a cheap
            // heuristic: a `Default::default()` of a field typed elsewhere goes unseen).
            if line.contains("QualityPolicy")
                && (line.contains("unwrap_or_default()") || line.contains("Default::default()"))
            {
                hits.push("QualityPolicy's Default");
            }
            for what in hits {
                out.push(ReferenceRead {
                    n,
                    line: original.get(n - 1).unwrap_or(&"").trim().to_string(),
                    what,
                    within: within.clone(),
                });
            }
        }
        out
    }

    /// The name of the function `line` declares, if it declares one.
    fn declared_fn(line: &str) -> Option<String> {
        let at = line.find("fn ")?;
        if at > 0 && is_ident_char(line[..at].chars().next_back()?) {
            return None;
        }
        let name: String = line[at + 3..]
            .trim_start()
            .chars()
            .take_while(|c| is_ident_char(*c))
            .collect();
        (!name.is_empty()).then_some(name)
    }

    fn is_ident_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }

    /// `token` called as a free function: not after `.`, `_` or a letter (`policy.start_rung()`,
    /// `opening_start_rung()`), `::` allowed (`quality::start_rung()`).
    fn names_bare(line: &str, token: &str) -> bool {
        line.match_indices(token).any(|(at, _)| {
            line[..at]
                .chars()
                .next_back()
                .is_none_or(|c| c != '.' && !is_ident_char(c))
        })
    }

    /// `ident` as a whole identifier, not a part of one (`LADDER`, not `MY_LADDER_X`).
    fn names_ident(line: &str, ident: &str) -> bool {
        line.match_indices(ident).any(|(at, _)| {
            let before = line[..at].chars().next_back();
            let after = line[at + ident.len()..].chars().next();
            before.is_none_or(|c| !is_ident_char(c)) && after.is_none_or(|c| !is_ident_char(c))
        })
    }

    /// `text` with comments and the insides of string and char literals blanked, newlines kept: a
    /// word in a message or a brace in a literal is no code.
    fn code_only(text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let blank = |c: char| if c == '\n' { '\n' } else { ' ' };
        let starts_token = |k: usize| k == 0 || !is_ident_char(chars[k - 1]);
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if c == '/' && next == Some('/') {
                while i < chars.len() && chars[i] != '\n' {
                    out.push(' ');
                    i += 1;
                }
            } else if c == '/' && next == Some('*') {
                let mut depth = 0;
                while i < chars.len() {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        out.push_str("  ");
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        out.push_str("  ");
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        out.push(blank(chars[i]));
                        i += 1;
                    }
                }
            } else if c == 'r'
                && matches!(next, Some('"' | '#'))
                && (starts_token(i) || (chars[i - 1] == 'b' && starts_token(i - 1)))
            {
                // A raw string, `r"…"` or `r#"…"#` (or `br`); `r#ident` is a raw identifier.
                let mut j = i + 1;
                while chars.get(j) == Some(&'#') {
                    j += 1;
                }
                if chars.get(j) != Some(&'"') {
                    out.push(c);
                    i += 1;
                    continue;
                }
                let hashes = j - i - 1;
                out.extend(&chars[i..=j]);
                i = j + 1;
                while i < chars.len() {
                    if chars[i] == '"' && (1..=hashes).all(|h| chars.get(i + h) == Some(&'#')) {
                        out.extend(&chars[i..=i + hashes]);
                        i += 1 + hashes;
                        break;
                    }
                    out.push(blank(chars[i]));
                    i += 1;
                }
            } else if c == '"' {
                out.push('"');
                i += 1;
                while i < chars.len() {
                    match chars[i] {
                        '\\' => {
                            out.push(' ');
                            i += 1;
                            if i < chars.len() {
                                out.push(blank(chars[i]));
                                i += 1;
                            }
                        }
                        '"' => {
                            out.push('"');
                            i += 1;
                            break;
                        }
                        other => {
                            out.push(blank(other));
                            i += 1;
                        }
                    }
                }
            } else if c == '\'' {
                // A char literal (`'x'`, `'\n'`, `'\''`, `'\u{2014}'`), or a lifetime or label
                // (`'a`), which stays code.
                let close = if next == Some('\\') {
                    (i + 3..chars.len().min(i + 13)).find(|&k| chars[k] == '\'')
                } else if chars.get(i + 2) == Some(&'\'') {
                    Some(i + 2)
                } else {
                    None
                };
                if let Some(end) = close {
                    out.push('\'');
                    out.extend(std::iter::repeat_n(' ', end - i - 1));
                    out.push('\'');
                    i = end + 1;
                } else {
                    out.push(c);
                    i += 1;
                }
            } else {
                out.push(c);
                i += 1;
            }
        }
        out
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                collect_rs(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// The files (and directories) of modules declared out of line under `#[cfg(test)]`
    /// (`#[cfg(test)] mod tests;`) anywhere in `files`: test code, though not inside an item.
    fn test_only_module_files(files: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
        files
            .iter()
            .flat_map(|f| {
                let text = std::fs::read_to_string(f).expect("readable");
                test_only_modules_of(f, &text)
            })
            .collect()
    }

    /// What `#[cfg(test)] mod name;` in `file` points at: `name.rs` and `name/` in its module
    /// directory (its own for `lib.rs`, `main.rs` and `mod.rs`, else `<stem>/`).
    fn test_only_modules_of(file: &std::path::Path, text: &str) -> Vec<std::path::PathBuf> {
        let dir = file.parent().unwrap_or(std::path::Path::new(""));
        let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let module_dir = if matches!(stem, "lib" | "main" | "mod") {
            dir.to_path_buf()
        } else {
            dir.join(stem)
        };
        let code = code_only(text);
        let mut out = Vec::new();
        let mut under_test = false;
        for line in code.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if is_test_cfg(line) {
                under_test = true;
                continue;
            }
            if under_test && line.starts_with("#[") {
                continue;
            }
            if under_test {
                let rest = line
                    .strip_prefix("pub(crate) ")
                    .or_else(|| line.strip_prefix("pub "))
                    .unwrap_or(line);
                if let Some(name) = rest.strip_prefix("mod ").and_then(|r| r.strip_suffix(';')) {
                    out.push(module_dir.join(format!("{}.rs", name.trim())));
                    out.push(module_dir.join(name.trim()));
                }
            }
            under_test = false;
        }
        out
    }

    /// An attribute that compiles its item into tests only: `#[cfg(test)]`, `#[cfg(all(test, …))]`,
    /// and `#[cfg(any(test, doc))]` (the tests and rustdoc, never a binary).
    fn is_test_cfg(trimmed: &str) -> bool {
        trimmed.starts_with("#[cfg(test)]")
            || trimmed.starts_with("#[cfg(all(test,")
            || trimmed.starts_with("#[cfg(any(test, doc))]")
    }

    /// Lines outside test-only items ([`is_test_cfg`]), numbered from one, skipping each such item
    /// to its closing brace or `;`. Give it [`code_only`] text so literal and comment braces don't
    /// count.
    fn production_lines(code: &str) -> Vec<(usize, &str)> {
        let mut out = Vec::new();
        let mut skipping = false;
        let mut depth = 0i64;
        let mut opened = false;
        let mut first = false;
        for (i, line) in code.lines().enumerate() {
            let trimmed = line.trim();
            if !skipping && is_test_cfg(trimmed) {
                skipping = true;
                depth = 0;
                opened = false;
                first = true;
                continue;
            }
            // Further attributes of the same item.
            if skipping && !opened && trimmed.starts_with("#[") {
                continue;
            }
            if skipping {
                if trimmed.is_empty() {
                    continue;
                }
                for c in line.chars() {
                    match c {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                // A one-line item: `use ..;`, or a field or variant (`name: T,`) under the
                // attribute.
                let ended = trimmed.ends_with(';') || (first && trimmed.ends_with(','));
                first = false;
                if (opened && depth <= 0) || (!opened && ended) {
                    skipping = false;
                }
                continue;
            }
            out.push((i + 1, line));
        }
        out
    }
}
