use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use super::super::macros::{log_trendline_estimate, log_trendline_modified_trend};

use super::super::BandwidthUsage;
use super::super::time::{TimeDelta, Timestamp};
use super::arrival_group::InterGroupDelayDelta;

const SMOOTHING_COEF: f64 = 0.9;
const OVER_USE_THRESHOLD_DEFAULT_MS: f64 = 12.5;
const OVER_USE_TIME_THRESHOLD: Duration = Duration::from_millis(10);
const MAX_ADOPT_OFFSET_MS: f64 = 15.0;
const THRESHOLD_GAIN: f64 = 4.0;

const K_UP: f64 = 0.0087;
const K_DOWN: f64 = 0.039;

const DELAY_COUNT_RANGE: RangeInclusive<usize> = 60..=1000;

// --- AFKLink patch: Wi-Fi stalls are not overuse (vendor/VENDORED.md) -------------------------
//
// A phone on Wi-Fi (iPhone/WebKit viewers, 8 and 25 Oct) stalls every 3-8 s: no loss, the one-way
// delay jumps by ~80-150 ms within one or a few arrival groups and collapses back when the held
// packets arrive in a burst. Upstream calls that overuse 10 ms after the trend crosses the
// threshold, the rate controller cuts to 0.85x of what was acked and climbs back at ~40 kbps/s,
// so the next stall comes before it recovers. While the delay rises a stall cannot be told from
// a link that suddenly carries far less than we send; what tells them apart is what follows: a
// stall collapses back by itself within ~100-200 ms, a queue keeps growing until we slow down.
// So a steep or jump-shaped rise is held back until it shows which it is, for at most
// STALL_MAX_HOLD_MS; one the trend sees only after it collapsed (a sparse stream) is ignored; the
// gentler rise of a queue behind a link we overrun by up to ~1.33x is declared as upstream does.
// An overuse that comes out of a hold is latched long enough for the rate controller to act on it
// (OVERUSE_LATCH_*), since by then the queue has often stopped growing and the trend is quiet.
//
// Whatever the shape rules get wrong, two bounds cap what ignoring can hide:
// - G1, STALL_COOLDOWN_MS: at most one stall is ignored per 2 s of arrival time. Wi-Fi stalls come
//   every 3-8 s; stall-shaped rises that repeat faster (our own big frames into a narrow link) are
//   overuse from the second one on, as upstream calls them, with no hold.
// - G2, FLOOR_HORIZON_MS: a stall counts as collapsed only once the delay is back near the path's
//   floor, the lowest delay of the last 5 s, not near the lowest of the 20-group window. A queue
//   that grows under a train of bursts climbs off that floor, so its bursts stop collapsing.

/// Log target of the patch's lines. It starts with `afklink`, so the agent's `debug` level (which
/// caps third-party targets at `warn`) writes them to the owner's session file.
const PATCH_LOG_TARGET: &str = "afklink_str0m::trendline";
/// Smallest rise above the window's lowest delay, at the moment upstream would declare overuse,
/// that may be a stall: above a Wi-Fi path's ordinary few-ms jitter. Smaller rises are declared as
/// upstream does.
const STALL_MIN_RISE_MS: f64 = 10.0;
/// Smallest peak a rise must reach to be ignored as a stall once it collapses. The stalls we
/// patch for are 80-150 ms; the bursts that briefly overrun a narrow link (a keyframe into
/// 4 Mbps) peak at 20-30 ms. Once both have collapsed within the hold, how fast they fell no
/// longer separates them; the size does (`wifi-0924-4m`: ignoring those doubled its queue
/// drops). A smaller rise that drains gets upstream's overuse...
const STALL_MIN_PEAK_MS: f64 = 40.0;
/// ... unless it came in one step: one step between consecutive groups carries this share of its
/// peak. Our pacer spreads a big frame over many groups, so a queue we build grows group by
/// group; a one-step rise is the path holding packets back. A ramp stall can look this small:
/// str0m's arrival grouping merges the group at its top with the burst queued behind it, and the
/// group's delay is that of its last packet, sent later (`iphone-wifi-1025`'s ramps of +80..+110
/// ms read 22-30 ms).
const STALL_ONE_STEP_SHARE: f64 = 0.9;
/// Smallest steepness of a rise that may be a stall: its rise per ms of arrival time since the
/// delay last sat at its low (`STALL_LOW_*`). For a queue the slope is 1 - C/R (C the link's rate,
/// R ours), read here twice as steep because the low ends half way up: 0.5 is sending 1.33x what
/// the link carries. A stall is a jump (close to 1), a jump in steps, or a ramp of +130 ms over
/// 120 ms of sending (~1). A queue behind a link we overrun by up to 1.33x is declared as upstream
/// does, with no delay at all.
const STALL_MIN_STEEPNESS: f64 = 0.5;
/// The delay still "sits at its low" within max(this, `STALL_LOW_FRACTION` x the rise) of the
/// window's lowest raw delay: where the rise starts. Half the rise, because a game's big frames
/// take several ms more to cross the link than small ones: with a few ms of slack the low is the
/// last small frame, ~100 ms before a stall's first step, and the stall reads as gradual
/// (25 Oct scenario, 20-30 ms first steps read at 0.23-0.35).
const STALL_LOW_SLACK_MS: f64 = 2.0;
const STALL_LOW_FRACTION: f64 = 0.5;
/// A rise is also stall-shaped when one step between consecutive groups carries at least this
/// share of it, however long the arrival gaps around it: a stall (or a stall's first step) lands
/// in one group, often right after a pause between frames that makes it read as gradual, while a
/// queue grows by a little with every group.
const STALL_MIN_JUMP_SHARE: f64 = 0.5;
/// On a falling edge (the trend signals after the peak), how fast the delay must be falling from
/// the rise's peak (ms of delay per ms of arrival) for the rise to be measured to that peak and
/// held. A queue at a narrow link drains at the link's headroom, C/R - 1 (`wifi-0924-4m`'s
/// keyframe queues mostly at 0.2-2.3); without this gate they are held and, drained within the
/// hold, ignored: 31.8 queue drops a run there against 23.4 (12 seeds); the cooldown and the floor
/// do not catch them, as they neither repeat within 2 s nor leave the floor. A stall's backlog
/// drains at the same C/R - 1, fast where the link has room (25 Oct: 25 Mbps for ~7 Mbps sent).
/// The cost: a stall the trend first sees on its falling edge, on a link with less than 3.5x our
/// rate, is called overuse; nearly all such cases are small short ramps (+50-60 ms over 80-120
/// ms; `afklink_a_stall_on_a_link_without_room_is_overuse_on_its_falling_edge`).
const STALL_MIN_FALL_STEEPNESS: f64 = 2.5;
/// A rise past this is overuse whatever its shape: more than any stall seen (+139 ms), and a cap
/// on the extra queue a real collapse of the link can build while the decision waits.
const STALL_MAX_RISE_MS: f64 = 200.0;
/// The longest a rise is held back, in remote arrival time. A stall of 100-150 ms plus the burst
/// that drains it has collapsed well within this; a queue still growing then is overuse.
const STALL_MAX_HOLD_MS: f64 = 250.0;
/// The rise has collapsed (a stall, ignored) once the delay is back within this fraction of its
/// peak of the path's floor (`FLOOR_HORIZON_MS`)...
const STALL_RETURN_FRACTION: f64 = 0.25;
/// ... or within this many ms of it (a path's jitter), as long as that is at most half the peak:
/// a rise always has to fall by half before it counts as collapsed.
const STALL_RETURN_MS: f64 = 20.0;
/// G1: the least arrival time between two ignored stalls. Within it, an overuse signal is
/// overuse, as upstream declares it (no hold, no ignore), unless it is the ignored stall's own
/// lagging trend (`TrendlineEstimator::ignored_stall_lingers`). Wi-Fi stalls come every 3-8 s
/// (25 Oct; the simulator's scenarios at least 3 s apart); stall-shaped rises closer together are
/// a queue our own bursts build (a big frame every 6-12 frames into a link we overrun by a few
/// percent: each burst collapsed as a stall would, while the queue's floor crept up 20-50 ms/s;
/// before this rule, 147 bursts in 15 s were ignored and the queue reached 776 ms).
const STALL_COOLDOWN_MS: f64 = 2_000.0;
/// G2: the path's floor, which a stall must return to (`collapsed_level_ms`), is the lowest raw
/// delay of this much arrival time, kept as minima of `FLOOR_BUCKET_MS` buckets. The 20-group
/// window (100-660 ms) climbs along with a queue that grows under a train of bursts, so each burst
/// looked collapsed against the window. Measured against this floor, ignored stalls cannot let the
/// delay floor rise by more than one collapse level (20 ms for peaks under 80 ms, at most 50 ms) per
/// 5 s: a queue growing faster stops collapsing once it is that far up. The cost: after the path
/// itself gets longer (a new route, a clock step forward), stalls within 5 s of it are overuse.
const FLOOR_HORIZON_MS: f64 = 5_000.0;
const FLOOR_BUCKET_MS: f64 = 250.0;
/// A receive time this far before the latest one is the far end's clock stepping back, not
/// reordering (which is tens of ms at most). The patch's clocks (a hold's, the latch's, the
/// cooldown's and the floor's) run on the latest receive time, a maximum that would otherwise
/// stand still until the arrivals pass the old one: a latched overuse would last as long as the
/// step.
const CLOCK_STEP_BACK_MS: f64 = 1_000.0;
/// An overuse declared when a held-back rise turns out to be a queue (or a stall-shaped rise
/// within the cooldown) stays overuse for at least this long (remote arrival time), whatever the
/// trend does meanwhile. The delay controller reads the hypothesis once per TWCC report (every
/// 50-100 ms), and the rate controller cuts only once a round trip (10-200 ms) has passed since
/// the estimate last changed, and an increase changes it at every report: an overuse seen by one
/// report is never acted on when the round trip exceeds the report interval. 200 ms spans two
/// reports at 100 ms (with 100 ms, one of 45 burst trains was never cut at the controller).
/// Upstream's own overuse on such a queue lasts 220-400 ms (the trend is still steep when it is
/// declared).
const OVERUSE_LATCH_MIN_MS: f64 = 200.0;
/// ... and after that until the queue has drained to the collapse level, but no longer than this:
/// a path that got longer for good never drains, and an overuse without end would cut the rate to
/// its floor. Past it the trend decides, as upstream.
const OVERUSE_LATCH_MAX_MS: f64 = 300.0;
/// Normal <-> underuse flips (no overuse involved) can come with every delay variation on a
/// jittery path, and a remote clock that flips between two offsets steps back with every other
/// one, so each is summed into one `debug` line per this much arrival time...
const QUIET_FLIPS_SUMMARY_MS: f64 = 1_000.0;
/// ... and at most one per this many delay variations, so arrival times the peer reports far
/// apart cannot turn every flip into a line (each flip is at `trace`).
const QUIET_FLIPS_SUMMARY_GROUPS: u64 = 100;

/// AFKLink patch: one of the patch's `debug` lines (target `PATCH_LOG_TARGET`), counted in tests
/// so a test can bound how many there are (counting through a tracing subscriber is unreliable
/// while other tests run on other threads: the callsite interest cache is shared).
macro_rules! patch_debug {
    ($self:ident, $($arg:tt)+) => {{
        #[cfg(test)]
        {
            $self.debug_lines += 1;
        }
        debug!(target: PATCH_LOG_TARGET, $($arg)+);
    }};
}

pub struct TrendlineEstimator {
    /// The window size in packets
    window_size: usize,

    /// The first instant we saw, used as zero point.
    zero_time: Option<Timestamp>,

    /// The history of observed delay variations.
    history: VecDeque<Timing>,

    /// The total number of observed delay variations.
    num_delay_variations: usize,

    /// Accumulated delay.
    accumulated_delay: f64,

    /// Last smoothed delay.
    smoothed_delay: f64,

    /// The adaptive delay threshold.
    delay_threshold: f64,

    /// Previous trend
    previous_trend: f64,

    /// If we are overusing, this contains data about the overuse.
    overuse: Option<Overuse>,

    /// The last time we updated the adaptive threshold.
    last_threshold_update: Option<Instant>,

    /// Our current hypothesis about the bandwidth usage.
    hypothesis: BandwidthUsage,

    /// AFKLink patch: a rise held back from being called overuse until it collapses (a stall) or
    /// does not (a queue).
    stall: Option<StallCandidate>,
    /// AFKLink patch: an overuse that came out of a hold, kept until the rate controller has
    /// surely seen it (`OVERUSE_LATCH_*`).
    overuse_latch: Option<OveruseLatch>,
    /// AFKLink patch: the latest remote arrival time (ms since `zero_time`) seen: the max, so a
    /// reordered variation cannot move the clock of a hold or a latch back.
    last_arrival_ms: f64,
    /// AFKLink patch: normal <-> underuse flips not yet in a `debug` summary, since when, and the
    /// delay variations since the last summary.
    quiet_flips: u64,
    quiet_flips_since_ms: f64,
    quiet_flips_groups: u64,
    /// AFKLink patch: stalls ignored so far, for the log.
    stalls_ignored: u64,
    /// AFKLink patch: arrival time of the last stall ignored (`STALL_COOLDOWN_MS`), and how high
    /// it peaked (its collapse level is what the delay must stay within for its lingering trend
    /// to be ignored too).
    last_ignore_ms: f64,
    last_ignore_peak_rise_ms: f64,
    /// AFKLink patch: the patch did not act on an overuse signal (a stall ignored, or its
    /// lingering trend), and the trend has stayed above the threshold since: upstream would still
    /// be overusing, so every variation re-checks that the delay is still back down.
    swallowed_overuse: bool,
    /// AFKLink patch: the lowest raw delay per `FLOOR_BUCKET_MS` of arrival time over the last
    /// `FLOOR_HORIZON_MS`, as (bucket start ms, lowest raw delay ms), oldest first.
    floor_buckets: VecDeque<(f64, f64)>,
    /// AFKLink patch: remote clock step-backs not yet in a `debug` summary, since when, the delay
    /// variations since, and whether any summary was written yet (the first step always is).
    clock_steps: u64,
    clock_steps_since_ms: f64,
    clock_steps_groups: u64,
    clock_steps_logged: bool,
    /// AFKLink patch: delay variations and arrival time since the hypothesis last changed, for
    /// the log.
    groups_in_state: u64,
    state_since_ms: f64,
    /// AFKLink patch, tests only: behave as upstream (every overuse signal is overuse), so a test
    /// can show that its input is one upstream calls overuse.
    #[cfg(test)]
    pub(crate) upstream_only: bool,
    /// AFKLink patch, tests only: `debug` lines written, and normal <-> underuse flips seen.
    #[cfg(test)]
    debug_lines: u64,
    #[cfg(test)]
    quiet_flips_total: u64,
}

/// AFKLink patch: an overuse declared after a hold, and the rise it came from.
#[derive(Debug)]
struct OveruseLatch {
    since_ms: f64,
    base_ms: f64,
    peak_rise_ms: f64,
}

/// AFKLink patch: a rise that might be a Wi-Fi stall, held back from being called overuse.
#[derive(Debug)]
struct StallCandidate {
    /// Remote arrival time (ms since `zero_time`) when it was held back.
    opened_ms: f64,
    /// The window's lowest raw delay then: what the delay returns to after a stall.
    base_ms: f64,
    rise_at_open_ms: f64,
    steepness: f64,
    peak_rise_ms: f64,
    /// The largest step between two consecutive groups of the rise when it was held.
    largest_step_ms: f64,
    /// Delay variations seen since it was held back.
    groups: u64,
}

/// AFKLink patch: how the current rise looks.
#[derive(Debug, Clone, Copy)]
struct RiseShape {
    base_ms: f64,
    rise_ms: f64,
    span_ms: f64,
    steepness: f64,
    /// The largest rise between two consecutive groups since the low, over the whole rise, and
    /// in ms.
    jump_share: f64,
    largest_step_ms: f64,
    /// The highest the delay got since the low, above `base_ms`: this rise's own peak, which
    /// is above `rise_ms` when the trend signals on a stall's falling edge.
    rise_peak_ms: f64,
    /// The window's highest raw delay above `base_ms`, and the largest step between two
    /// consecutive groups anywhere in the window over it: a stall that has already collapsed.
    peak_rise_ms: f64,
    peak_jump_share: f64,
    /// How steeply the delay rose to that peak, measured as `steepness` is (from where it last
    /// sat within max(`STALL_LOW_SLACK_MS`, `STALL_LOW_FRACTION` x the peak's rise) of its low):
    /// a ramp stall, whose steps are each a fraction of its peak.
    peak_steepness: f64,
    /// How fast the delay fell from that peak to now, per ms of arrival time: a stall's backlog
    /// arrives in a burst (the delay collapses within a few ms), a queue at a bottleneck drains
    /// at the link's rate (at most a few ms of delay per ms).
    fall_steepness: f64,
    /// Arrival time of the window's highest raw delay.
    peak_at_ms: f64,
    /// How far the window's lowest delay (`base_ms`) sits above the path's floor
    /// (`FLOOR_HORIZON_MS`): a queue the window has grown along with.
    floor_lift_ms: f64,
}

/// AFKLink patch: how far above the path's floor a rise that peaked at `peak_rise_ms` may still
/// be once it counts as collapsed.
fn collapsed_level_ms(peak_rise_ms: f64) -> f64 {
    (STALL_RETURN_FRACTION * peak_rise_ms).max(STALL_RETURN_MS.min(0.5 * peak_rise_ms))
}

impl RiseShape {
    /// Whether the window holds a stall that has already collapsed: a jump to a peak a stall
    /// reaches, and the delay back down. With a sparse stream (a few groups a second) upstream's
    /// trend crosses the threshold only after the burst has brought the delay back.
    fn collapsed_stall(&self) -> bool {
        (STALL_MIN_PEAK_MS..STALL_MAX_RISE_MS).contains(&self.peak_rise_ms)
            && (self.peak_jump_share >= STALL_MIN_JUMP_SHARE
                || self.peak_steepness >= STALL_MIN_STEEPNESS)
            && self.back_down()
    }

    /// How far the delay is now above the path's floor.
    fn above_floor_ms(&self) -> f64 {
        self.rise_ms + self.floor_lift_ms
    }

    /// Whether the delay is back down from the window's peak: within the collapse level of the
    /// path's floor (G2). A queue climbing behind a stall leaves it.
    fn back_down(&self) -> bool {
        self.above_floor_ms() <= collapsed_level_ms(self.peak_rise_ms)
    }

    /// Why this rise is not a stall, or `None` when it may be one.
    fn not_a_stall(&self) -> Option<&'static str> {
        if self.rise_ms < STALL_MIN_RISE_MS {
            Some("rise below the stall minimum")
        } else if self.rise_ms >= STALL_MAX_RISE_MS {
            Some("rise above the stall maximum")
        } else if self.steepness < STALL_MIN_STEEPNESS && self.jump_share < STALL_MIN_JUMP_SHARE {
            Some("rise too gradual for a stall")
        } else {
            None
        }
    }
}

impl TrendlineEstimator {
    pub fn new(window_size: usize) -> Self {
        Self {
            window_size,
            zero_time: None,
            history: VecDeque::default(),
            num_delay_variations: 0,
            accumulated_delay: 0.0,
            smoothed_delay: 0.0,
            delay_threshold: OVER_USE_THRESHOLD_DEFAULT_MS,
            previous_trend: 0.0,
            overuse: None,
            last_threshold_update: None,
            hypothesis: BandwidthUsage::Normal,
            stall: None,
            overuse_latch: None,
            last_arrival_ms: f64::NEG_INFINITY,
            quiet_flips: 0,
            quiet_flips_since_ms: 0.0,
            quiet_flips_groups: 0,
            stalls_ignored: 0,
            last_ignore_ms: f64::NEG_INFINITY,
            last_ignore_peak_rise_ms: 0.0,
            swallowed_overuse: false,
            floor_buckets: VecDeque::new(),
            clock_steps: 0,
            clock_steps_since_ms: 0.0,
            clock_steps_groups: 0,
            clock_steps_logged: false,
            groups_in_state: 0,
            state_since_ms: 0.0,
            #[cfg(test)]
            upstream_only: false,
            #[cfg(test)]
            debug_lines: 0,
            #[cfg(test)]
            quiet_flips_total: 0,
        }
    }

    pub fn add_delay_observation(&mut self, delay_variation: InterGroupDelayDelta, now: Instant) {
        if self.history.is_empty() {
            self.do_add_to_history(delay_variation, now);
            return;
        }

        self.do_add_to_history(delay_variation, now);
        while self.history.len() > self.window_size {
            let _ = self.history.pop_front();
        }

        if self.history.len() == self.window_size {
            assert!(
                self.history
                    .iter()
                    .zip(self.history.iter().skip(1))
                    .fold(true, |acc, (a, b)| {
                        acc && a.remote_recv_time_ms <= b.remote_recv_time_ms
                    }),
                "Out of order history {:?}",
                self.history
            );
            self.update_trendline(delay_variation, now);
        }
    }

    pub fn hypothesis(&self) -> BandwidthUsage {
        self.hypothesis
    }

    fn do_add_to_history(&mut self, variation: InterGroupDelayDelta, now: Instant) {
        let last_remote_recv_time = Timestamp::from(variation.last_remote_recv_time);

        let zero_time = *self.zero_time.get_or_insert(last_remote_recv_time);

        let delay_delta = variation.arrival_delta.as_secs_f64() * 1000.0
            - variation.send_delta.as_secs_f64() * 1000.0;

        self.num_delay_variations += 1;
        self.num_delay_variations = self.num_delay_variations.min(*DELAY_COUNT_RANGE.end());
        self.accumulated_delay += delay_delta;
        self.smoothed_delay =
            self.smoothed_delay * SMOOTHING_COEF + (1.0 - SMOOTHING_COEF) * self.accumulated_delay;

        let remote_recv_time = last_remote_recv_time - zero_time;
        let timing = Timing {
            at: now,
            remote_recv_time_ms: remote_recv_time.as_secs_f64() * 1000.0,
            smoothed_delay_ms: self.smoothed_delay,
            raw_delay_ms: self.accumulated_delay,
        };
        self.groups_in_state += 1;
        self.quiet_flips_groups += 1;
        self.clock_steps_groups += 1;
        if timing.remote_recv_time_ms < self.last_arrival_ms - CLOCK_STEP_BACK_MS {
            self.on_remote_clock_step_back(self.last_arrival_ms - timing.remote_recv_time_ms);
        }
        self.last_arrival_ms = self.last_arrival_ms.max(timing.remote_recv_time_ms);
        self.note_floor(timing.raw_delay_ms);

        let pos = self
            .history
            .iter()
            .rev()
            .position(|p| p.remote_recv_time_ms <= timing.remote_recv_time_ms)
            .unwrap_or(self.history.len());

        // we expect pos to be 0 more often than not
        self.history.insert(self.history.len() - pos, timing);
    }

    /// AFKLink patch: the far end's clock stepped back by `step_ms`: move the patch's clocks
    /// back with it, so a hold and a latch keep the time they have run and still end, and the
    /// cooldown and the floor keep their age. Each step at `trace`; summed into a `debug` line
    /// as normal <-> underuse flips are (a clock flipping between two offsets steps back with
    /// every other variation), the first one always.
    fn on_remote_clock_step_back(&mut self, step_ms: f64) {
        self.clock_steps += 1;
        self.last_arrival_ms -= step_ms;
        self.state_since_ms -= step_ms;
        self.quiet_flips_since_ms -= step_ms;
        self.clock_steps_since_ms -= step_ms;
        self.last_ignore_ms -= step_ms;
        for b in self.floor_buckets.iter_mut() {
            b.0 -= step_ms;
        }
        if let Some(c) = self.stall.as_mut() {
            c.opened_ms -= step_ms;
        }
        if let Some(l) = self.overuse_latch.as_mut() {
            l.since_ms -= step_ms;
        }
        trace!(
            target: PATCH_LOG_TARGET,
            step_ms,
            holding = self.stall.is_some(),
            latched = self.overuse_latch.is_some(),
            "remote receive clock stepped back"
        );
        let over_ms = self.last_arrival_ms - self.clock_steps_since_ms;
        if !self.clock_steps_logged
            || (over_ms >= QUIET_FLIPS_SUMMARY_MS
                && self.clock_steps_groups >= QUIET_FLIPS_SUMMARY_GROUPS)
        {
            patch_debug!(
                self,
                steps = self.clock_steps,
                last_step_ms = %format_args!("{:.0}", step_ms),
                over_ms = %format_args!("{:.0}", over_ms),
                groups = self.clock_steps_groups,
                holding = self.stall.is_some(),
                latched = self.overuse_latch.is_some(),
                "remote receive clock stepped back: the hold, latch, cooldown and floor clocks \
                 move with it"
            );
            self.clock_steps = 0;
            self.clock_steps_since_ms = self.last_arrival_ms;
            self.clock_steps_groups = 0;
            self.clock_steps_logged = true;
        }
    }

    /// AFKLink patch: one raw delay into the path's floor (`FLOOR_HORIZON_MS`), in the bucket of
    /// the latest arrival time; buckets older than the horizon are dropped.
    fn note_floor(&mut self, raw_delay_ms: f64) {
        let start_ms = (self.last_arrival_ms / FLOOR_BUCKET_MS).floor() * FLOOR_BUCKET_MS;
        match self.floor_buckets.back_mut() {
            Some((s, lowest)) if *s >= start_ms => *lowest = lowest.min(raw_delay_ms),
            _ => self.floor_buckets.push_back((start_ms, raw_delay_ms)),
        }
        let oldest_ms = self.last_arrival_ms - FLOOR_HORIZON_MS - FLOOR_BUCKET_MS;
        while self.floor_buckets.len() > 1
            && self.floor_buckets.front().is_some_and(|b| b.0 < oldest_ms)
        {
            let _ = self.floor_buckets.pop_front();
        }
    }

    /// AFKLink patch: the path's floor: the lowest raw delay of the last `FLOOR_HORIZON_MS` (to
    /// a bucket), or of the current delay when there is none yet.
    fn path_floor_ms(&self) -> f64 {
        self.floor_buckets
            .iter()
            .map(|b| b.1)
            .fold(self.accumulated_delay, f64::min)
    }

    fn update_trendline(&mut self, variation: InterGroupDelayDelta, now: Instant) -> Option<()> {
        let trend = self.linear_fit().unwrap_or(self.previous_trend);
        trace!("Computed trend {:?}", trend);
        log_trendline_estimate!(trend);

        self.detect(trend, variation, now);

        Some(())
    }

    fn linear_fit(&self) -> Option<f64> {
        // Simple linear regression to compute slope.
        assert!(self.history.len() > 2);

        let (sum_x, sum_y) = self.history.iter().fold((0.0, 0.0), |acc, t| {
            (acc.0 + t.remote_recv_time_ms, acc.1 + t.smoothed_delay_ms)
        });

        let avg_x = sum_x / self.history.len() as f64;
        let avg_y = sum_y / self.history.len() as f64;

        let (numerator, denomenator) = self.history.iter().fold((0.0, 0.0), |acc, t| {
            let x = t.remote_recv_time_ms;
            let y = t.smoothed_delay_ms;

            let numerator = acc.0 + (x - avg_x) * (y - avg_y);
            let denomenator = acc.1 + (x - avg_x).powi(2);

            (numerator, denomenator)
        });

        if denomenator == 0.0 {
            return None;
        }

        Some(numerator / denomenator)
    }

    fn detect(&mut self, trend: f64, variation: InterGroupDelayDelta, now: Instant) {
        if self.num_delay_variations < 2 {
            self.update_hypothesis(BandwidthUsage::Normal, trend, 0.0, "too few variations");
            return;
        }

        let modified_trend = self.num_delay_variations.min(*DELAY_COUNT_RANGE.start()) as f64
            * trend
            * THRESHOLD_GAIN;

        log_trendline_modified_trend!(modified_trend, self.delay_threshold);

        if modified_trend > self.delay_threshold {
            let overuse = match &mut self.overuse {
                Some(o) => {
                    o.time_overusing += variation.send_delta;
                    o
                }
                None => {
                    let new_overuse = Overuse {
                        count: 0,
                        // Initialize the timer. Assume that we've been
                        // over-using half of the time since the previous
                        // sample.
                        time_overusing: variation.send_delta / 2,
                    };
                    self.overuse = Some(new_overuse);

                    self.overuse.as_mut().unwrap()
                }
            };

            overuse.count += 1;
            trace!(
                timeoverusing = ?overuse.time_overusing,
                trend,
                previous_trend = self.previous_trend,
                "Trendline Estimator: Maybe overusing"
            );

            if overuse.time_overusing > OVER_USE_TIME_THRESHOLD
                && overuse.count > 1
                && trend > self.previous_trend
            {
                let time_overusing = overuse.time_overusing;
                self.overuse = None;

                // AFKLink patch: upstream declares overuse here; a stall-shaped rise is held back.
                self.on_overuse_signal(trend, modified_trend, time_overusing);
            } else if self.swallowed_overuse {
                // AFKLink patch: upstream would still be overusing here.
                self.recheck_swallowed_overuse(trend, modified_trend);
            }
        } else if modified_trend < -self.delay_threshold {
            self.overuse = None;
            // AFKLink patch: upstream's overuse would end here.
            self.swallowed_overuse = false;
            self.update_hypothesis(
                BandwidthUsage::Underuse,
                trend,
                modified_trend,
                "trend below the threshold",
            );
        } else {
            self.overuse = None;
            self.swallowed_overuse = false;
            self.update_hypothesis(
                BandwidthUsage::Normal,
                trend,
                modified_trend,
                "trend within the threshold",
            );
        }

        // AFKLink patch: a held-back rise is settled on every delay variation.
        self.settle_stall(trend, modified_trend);

        self.previous_trend = trend;
        self.update_threshold(modified_trend, now);
    }

    /// AFKLink patch: the window's lowest raw delay, and how far and how steeply the delay has
    /// risen above it since it last sat at its low (`STALL_LOW_SLACK_MS`, `STALL_LOW_FRACTION`).
    fn rise_shape(&self) -> RiseShape {
        let base_ms = self
            .history
            .iter()
            .map(|t| t.raw_delay_ms)
            .fold(self.accumulated_delay, f64::min);
        let rise_ms = self.accumulated_delay - base_ms;
        // Where a rise that reached `top_rise_ms` started: the latest entry before `before_ms`
        // with the delay still within max(STALL_LOW_SLACK_MS, STALL_LOW_FRACTION x the rise) of
        // the base, as (arrival ms, raw delay ms).
        let low_point = |top_rise_ms: f64, before_ms: f64| -> Option<(f64, f64)> {
            let slack_ms = STALL_LOW_SLACK_MS.max(STALL_LOW_FRACTION * top_rise_ms);
            self.history
                .iter()
                .filter(|t| t.remote_recv_time_ms < before_ms)
                .filter(|t| t.raw_delay_ms <= base_ms + slack_ms)
                .map(|t| (t.remote_recv_time_ms, t.raw_delay_ms))
                .fold(None, |latest: Option<(f64, f64)>, p| match latest {
                    Some(l) if l.0 >= p.0 => Some(l),
                    _ => Some(p),
                })
        };
        // How steep a climb from `low` to (`top_at_ms`, `top_raw_ms`) was: twice its slope
        // (ms of delay per ms of arrival), so that a low exactly half way up gives the rise over
        // its span, and one sampled lower, as with a group per 30 fps frame, does not make a
        // steep climb read gradual (a ramp of +80 ms over 150 ms at 33 ms groups read 0.47).
        // At least 1 ms of span: a jump within one group (or reordering) must not divide by
        // zero.
        let climb = |low: Option<(f64, f64)>, top_at_ms: f64, top_raw_ms: f64| match low {
            Some((at, raw)) => 2.0 * (top_raw_ms - raw).max(0.0) / (top_at_ms - at).max(1.0),
            None => 0.0,
        };
        let low = low_point(rise_ms, f64::INFINITY);
        let low_ms = low.map_or(f64::NEG_INFINITY, |l| l.0);
        let span_ms = (self.last_arrival_ms - low_ms).max(1.0);
        // The largest step up between consecutive groups from the low on (the history is in
        // arrival order).
        let largest_step_ms = self
            .history
            .iter()
            .zip(self.history.iter().skip(1))
            .filter(|(_, b)| b.remote_recv_time_ms > low_ms)
            .map(|(a, b)| b.raw_delay_ms - a.raw_delay_ms)
            .fold(0.0, f64::max);
        // The highest the delay got since the low: this rise's own peak. On the falling edge of
        // a stall (the trend lags and signals there) it is the stall's peak, not the current,
        // already falling rise; after a collapse and a new climb it is the new climb's.
        let (rise_peak_at_ms, rise_peak_raw_ms) = self
            .history
            .iter()
            .filter(|t| t.remote_recv_time_ms > low_ms)
            .fold(
                (self.last_arrival_ms, self.accumulated_delay),
                |(at, peak), t| {
                    if t.raw_delay_ms > peak {
                        (t.remote_recv_time_ms, t.raw_delay_ms)
                    } else {
                        (at, peak)
                    }
                },
            );
        let rise_peak_ms = rise_peak_raw_ms - base_ms;
        // Steepness up to that peak as well, measured as on the rising edge (from where the
        // delay last sat within half of the peak): on the falling edge the current rise over the
        // whole span reads gradual though the climb was steep (20.8 ms groups, a ramp of +100 ms
        // over 120 ms read 0.43-0.49 and was called overuse).
        // Only when the delay is falling from that peak the way a stall's backlog arrives, in a
        // burst (`STALL_MIN_FALL_STEEPNESS`): a queue at a narrow link drains at the link's rate,
        // and measured to its peak a keyframe's queue at 4 Mbps read as steep as a stall
        // (`wifi-0924-4m`'s queue drops 21 -> 46 a run).
        let rise_peak_fall = (rise_peak_raw_ms - self.accumulated_delay)
            / (self.last_arrival_ms - rise_peak_at_ms).max(1.0);
        let rise_peak_steepness = if rise_peak_fall >= STALL_MIN_FALL_STEEPNESS {
            climb(
                low_point(rise_peak_ms, rise_peak_at_ms),
                rise_peak_at_ms,
                rise_peak_raw_ms,
            )
        } else {
            0.0
        };
        let (peak_at_ms, peak_ms) = self.history.iter().fold(
            (self.last_arrival_ms, self.accumulated_delay),
            |(at, peak), t| {
                if t.raw_delay_ms > peak {
                    (t.remote_recv_time_ms, t.raw_delay_ms)
                } else {
                    (at, peak)
                }
            },
        );
        let peak_rise_ms = peak_ms - base_ms;
        let peak_steepness = climb(low_point(peak_rise_ms, peak_at_ms), peak_at_ms, peak_ms);
        let largest_step_anywhere_ms = self
            .history
            .iter()
            .zip(self.history.iter().skip(1))
            .map(|(a, b)| b.raw_delay_ms - a.raw_delay_ms)
            .fold(0.0, f64::max);
        let share = |step: f64, of: f64| if of > 0.0 { step / of } else { 0.0 };
        RiseShape {
            base_ms,
            rise_ms,
            span_ms,
            steepness: climb(low, self.last_arrival_ms, self.accumulated_delay)
                .max(rise_peak_steepness),
            jump_share: share(largest_step_ms, rise_ms),
            largest_step_ms,
            rise_peak_ms,
            peak_rise_ms,
            peak_jump_share: share(largest_step_anywhere_ms, peak_rise_ms),
            peak_steepness,
            fall_steepness: (peak_ms - self.accumulated_delay)
                / (self.last_arrival_ms - peak_at_ms).max(1.0),
            peak_at_ms,
            floor_lift_ms: (base_ms - self.path_floor_ms()).max(0.0),
        }
    }

    /// AFKLink patch: upstream's overuse condition has just held. Declare overuse, as upstream
    /// does, unless the rise is stall-shaped; then hold it back (`settle_stall` decides).
    fn on_overuse_signal(&mut self, trend: f64, modified_trend: f64, time_overusing: TimeDelta) {
        if self.hypothesis == BandwidthUsage::Overuse {
            // Already overusing: nothing to hold back, as upstream.
            return;
        }
        #[cfg(test)]
        if self.upstream_only {
            self.update_hypothesis(BandwidthUsage::Overuse, trend, modified_trend, "upstream");
            return;
        }
        if let Some(c) = &self.stall {
            trace!(
                target: PATCH_LOG_TARGET,
                opened_ms = c.opened_ms,
                "overuse condition again while a rise is held back; it decides"
            );
            return;
        }
        let shape = self.rise_shape();
        trace!(
            target: PATCH_LOG_TARGET,
            window = ?self
                .history
                .iter()
                .map(|t| (t.remote_recv_time_ms.round(), t.raw_delay_ms.round()))
                .collect::<Vec<_>>(),
            now_ms = self.last_arrival_ms.round(),
            raw_ms = self.accumulated_delay.round(),
            "overuse signal: the window (arrival ms, raw delay ms) it is judged on"
        );
        // A stall already ignored (by a hold that saw it collapse, or below), whatever its shape:
        // the trend lags it, and with one group per frame it crosses the threshold again after
        // the collapse. While the window's peak is still from before that ignore (or the trend
        // has not dropped since) and the delay sits back down near the path's floor, the signal
        // is that stall's. A delay climbing off the floor again is a new rise.
        if self.ignored_stall_lingers(&shape) {
            trace!(
                target: PATCH_LOG_TARGET,
                peak_at_ms = shape.peak_at_ms,
                last_ignore_ms = self.last_ignore_ms,
                rise_ms = shape.rise_ms,
                above_floor_ms = shape.above_floor_ms(),
                "overuse condition again on a stall already ignored"
            );
            self.swallowed_overuse = true;
            return;
        }
        self.swallowed_overuse = false;
        let collapsed_stall = shape.collapsed_stall();
        let not_a_stall = if collapsed_stall {
            None
        } else {
            shape.not_a_stall()
        };
        if let Some(why) = not_a_stall {
            self.update_hypothesis(BandwidthUsage::Overuse, trend, modified_trend, why);
            return;
        }
        // G1: within the cooldown of an ignored stall, a stall-shaped rise is neither held nor
        // ignored: it is overuse at once, latched as a held rise's overuse is.
        let since_ignore_ms = self.last_arrival_ms - self.last_ignore_ms;
        if since_ignore_ms < STALL_COOLDOWN_MS {
            patch_debug!(
                self,
                since_ignore_ms = %format_args!("{:.0}", since_ignore_ms),
                cooldown_ms = STALL_COOLDOWN_MS,
                collapsed = collapsed_stall,
                rise_ms = %format_args!("{:.1}", shape.rise_ms),
                above_floor_ms = %format_args!("{:.1}", shape.above_floor_ms()),
                rise_peak_ms = %format_args!("{:.1}", shape.rise_peak_ms),
                peak_rise_ms = %format_args!("{:.1}", shape.peak_rise_ms),
                steepness = %format_args!("{:.2}", shape.steepness),
                jump_share = %format_args!("{:.2}", shape.jump_share),
                trend = %format_args!("{:.4}", trend),
                modified_trend = %format_args!("{:.1}", modified_trend),
                threshold = %format_args!("{:.1}", self.delay_threshold),
                ignored_total = self.stalls_ignored,
                "stall-shaped delay rise within the cooldown of an ignored stall: overuse \
                 (stalls do not come this close together)"
            );
            let peak_rise_ms = if collapsed_stall {
                shape.peak_rise_ms
            } else {
                shape.rise_peak_ms.max(shape.rise_ms)
            };
            self.declare_latched_overuse(
                trend,
                modified_trend,
                "a stall-shaped rise within the cooldown of an ignored stall",
                shape.base_ms,
                peak_rise_ms,
            );
            return;
        }
        if collapsed_stall {
            self.last_ignore_ms = self.last_arrival_ms;
            self.last_ignore_peak_rise_ms = shape.peak_rise_ms;
            self.swallowed_overuse = true;
            self.stalls_ignored += 1;
            patch_debug!(
                self,
                peak_rise_ms = %format_args!("{:.1}", shape.peak_rise_ms),
                rise_ms = %format_args!("{:.1}", shape.rise_ms),
                above_floor_ms = %format_args!("{:.1}", shape.above_floor_ms()),
                peak_jump_share = %format_args!("{:.2}", shape.peak_jump_share),
                peak_steepness = %format_args!("{:.2}", shape.peak_steepness),
                fall_steepness = %format_args!("{:.2}", shape.fall_steepness),
                since_previous_ms = %format_args!("{:.0}", since_ignore_ms),
                trend = %format_args!("{:.4}", trend),
                modified_trend = %format_args!("{:.1}", modified_trend),
                threshold = %format_args!("{:.1}", self.delay_threshold),
                time_overusing_ms = %format_args!("{:.1}", time_overusing.as_secs_f64() * 1000.0),
                ignored_total = self.stalls_ignored,
                "delay spike ignored as a Wi-Fi stall: the trend saw it only after it collapsed"
            );
            return;
        }
        patch_debug!(
            self,
            rise_ms = %format_args!("{:.1}", shape.rise_ms),
            span_ms = %format_args!("{:.1}", shape.span_ms),
            steepness = %format_args!("{:.2}", shape.steepness),
            jump_share = %format_args!("{:.2}", shape.jump_share),
            rise_peak_ms = %format_args!("{:.1}", shape.rise_peak_ms),
            floor_lift_ms = %format_args!("{:.1}", shape.floor_lift_ms),
            trend = %format_args!("{:.4}", trend),
            modified_trend = %format_args!("{:.1}", modified_trend),
            threshold = %format_args!("{:.1}", self.delay_threshold),
            time_overusing_ms = %format_args!("{:.1}", time_overusing.as_secs_f64() * 1000.0),
            hold_max_ms = STALL_MAX_HOLD_MS,
            "delay rise held back as a possible Wi-Fi stall"
        );
        self.stall = Some(StallCandidate {
            opened_ms: self.last_arrival_ms,
            base_ms: shape.base_ms,
            rise_at_open_ms: shape.rise_ms,
            steepness: shape.steepness,
            // The rise's own peak so far, not the current rise: opened on a stall's falling edge
            // the current rise understates the stall, and a stall would then count as "peaked
            // below a stall's size" when it drains (STALL_MIN_PEAK_MS).
            peak_rise_ms: shape.rise_peak_ms.max(shape.rise_ms),
            largest_step_ms: shape.largest_step_ms,
            groups: 0,
        });
    }

    /// AFKLink patch: whether an overuse signal (or, within a swallowed overuse, the trend still
    /// above the threshold) is the last ignored stall's lingering trend: the window's peak is from
    /// before that ignore, or the trend has not dropped since, and the delay is still within that
    /// stall's collapse level of the path's floor.
    /// Within a swallowed overuse the delay may be a rise (`STALL_MIN_RISE_MS`) above that level
    /// (`recheck_swallowed_overuse`).
    fn ignored_stall_lingers(&self, shape: &RiseShape) -> bool {
        let level_ms = collapsed_level_ms(self.last_ignore_peak_rise_ms);
        if self.swallowed_overuse {
            shape.above_floor_ms() <= level_ms + STALL_MIN_RISE_MS
        } else {
            shape.peak_at_ms <= self.last_ignore_ms && shape.above_floor_ms() <= level_ms
        }
    }

    /// AFKLink patch: the trend has stayed above the threshold since the patch swallowed an
    /// overuse signal, where upstream would still be overusing; no new signal comes while the
    /// trend is not rising. Once the delay is a rise (`STALL_MIN_RISE_MS`) above the collapse
    /// level of the path's floor (a queue starting right behind the ignored stall), it is judged as
    /// a signal now. Not at the collapse level itself: checked on every variation, one sample of
    /// 20 ms jitter above a floor at the bottom of its band crossed it, and the cooldown then
    /// latched overuse on that jitter (2 of 1120 stalls of +60 ms at 20 ms of jitter, 20.8 ms
    /// groups). A queue behind the stall builds at most those 10 ms more before it is judged.
    fn recheck_swallowed_overuse(&mut self, trend: f64, modified_trend: f64) {
        if self.stall.is_some() || self.hypothesis == BandwidthUsage::Overuse {
            self.swallowed_overuse = false;
            return;
        }
        let shape = self.rise_shape();
        if self.ignored_stall_lingers(&shape) {
            return;
        }
        let limit_ms = collapsed_level_ms(self.last_ignore_peak_rise_ms) + STALL_MIN_RISE_MS;
        patch_debug!(
            self,
            above_floor_ms = %format_args!("{:.1}", shape.above_floor_ms()),
            limit_ms = %format_args!("{:.1}", limit_ms),
            since_ignore_ms = %format_args!("{:.0}", self.last_arrival_ms - self.last_ignore_ms),
            rise_ms = %format_args!("{:.1}", shape.rise_ms),
            trend = %format_args!("{:.4}", trend),
            modified_trend = %format_args!("{:.1}", modified_trend),
            threshold = %format_args!("{:.1}", self.delay_threshold),
            "delay climbed off the path's floor while the trend stayed above the threshold since \
             an ignored stall: judged as an overuse signal"
        );
        self.swallowed_overuse = false;
        let time_overusing = self
            .overuse
            .as_ref()
            .map_or(TimeDelta::ZERO, |o| o.time_overusing);
        self.on_overuse_signal(trend, modified_trend, time_overusing);
    }

    /// AFKLink patch: settle a held-back rise. It collapsed to the path's floor: a stall, ignored.
    /// It rose past what a stall does, or has not collapsed when the hold runs out: overuse, as
    /// upstream would have declared it (a path that got longer for good gets the one cut upstream
    /// gives it too; a release there would let a growing queue be held again and again).
    fn settle_stall(&mut self, trend: f64, modified_trend: f64) {
        if self.stall.is_none() {
            return;
        }
        let path_floor_ms = self.path_floor_ms();
        let Some(c) = self.stall.as_mut() else {
            return;
        };
        let rise_ms = self.accumulated_delay - c.base_ms;
        c.peak_rise_ms = c.peak_rise_ms.max(rise_ms);
        c.groups += 1;
        let held_ms = self.last_arrival_ms - c.opened_ms;
        let back_ms = collapsed_level_ms(c.peak_rise_ms);
        // G2: back near the path's floor, not only near where the window's low sat when the rise
        // was held: a queue that grows under a train of bursts takes the window's low along.
        let above_floor_ms = self.accumulated_delay - path_floor_ms.min(c.base_ms);
        let collapsed = above_floor_ms <= back_ms;

        let overuse_cause = if rise_ms >= STALL_MAX_RISE_MS {
            Some("held-back rise grew past the stall maximum")
        } else if held_ms >= STALL_MAX_HOLD_MS && rise_ms <= back_ms && !collapsed {
            // It came back to where it rose from, but that sits above the path's floor.
            Some("held-back rise fell back, but not to the path's floor (a growing queue)")
        } else if held_ms >= STALL_MAX_HOLD_MS {
            // Also when this variation, the first after the hold ran out (the stream had a
            // gap), shows the delay back down: when it collapsed is unknown, so upstream's call.
            Some("held-back rise did not collapse within the hold")
        } else if collapsed
            && c.peak_rise_ms < STALL_MIN_PEAK_MS
            && c.largest_step_ms < STALL_ONE_STEP_SHARE * c.peak_rise_ms
        {
            Some("held-back rise drained but peaked below a stall's size (a small queue)")
        } else if collapsed {
            self.stalls_ignored += 1;
            // A lingering trend may signal again on this stall: it is the one ignored.
            self.last_ignore_ms = self.last_arrival_ms;
            self.last_ignore_peak_rise_ms = c.peak_rise_ms;
            self.swallowed_overuse = true;
            patch_debug!(
                self,
                peak_rise_ms = %format_args!("{:.1}", c.peak_rise_ms),
                rise_ms = %format_args!("{:.1}", rise_ms),
                above_floor_ms = %format_args!("{:.1}", above_floor_ms),
                rise_at_open_ms = %format_args!("{:.1}", c.rise_at_open_ms),
                steepness = %format_args!("{:.2}", c.steepness),
                held_ms = %format_args!("{:.1}", held_ms),
                groups = c.groups,
                trend = %format_args!("{:.4}", trend),
                modified_trend = %format_args!("{:.1}", modified_trend),
                threshold = %format_args!("{:.1}", self.delay_threshold),
                ignored_total = self.stalls_ignored,
                "delay spike ignored as a Wi-Fi stall: it collapsed back to the path's floor"
            );
            self.stall = None;
            return;
        } else {
            None
        };

        if let Some(cause) = overuse_cause {
            patch_debug!(
                self,
                peak_rise_ms = %format_args!("{:.1}", c.peak_rise_ms),
                rise_ms = %format_args!("{:.1}", rise_ms),
                above_floor_ms = %format_args!("{:.1}", above_floor_ms),
                back_ms = %format_args!("{:.1}", back_ms),
                rise_at_open_ms = %format_args!("{:.1}", c.rise_at_open_ms),
                held_ms = %format_args!("{:.1}", held_ms),
                groups = c.groups,
                modified_trend = %format_args!("{:.1}", modified_trend),
                threshold = %format_args!("{:.1}", self.delay_threshold),
                "held-back delay rise is a queue, not a stall: {cause}"
            );
            let (base_ms, peak_rise_ms) = (c.base_ms, c.peak_rise_ms);
            self.stall = None;
            self.declare_latched_overuse(trend, modified_trend, cause, base_ms, peak_rise_ms);
        }
    }

    /// AFKLink patch: declare overuse and latch it (`OVERUSE_LATCH_*`) on a rise from `base_ms`
    /// that peaked `peak_rise_ms` above it.
    fn declare_latched_overuse(
        &mut self,
        trend: f64,
        modified_trend: f64,
        cause: &'static str,
        base_ms: f64,
        peak_rise_ms: f64,
    ) {
        self.update_hypothesis(BandwidthUsage::Overuse, trend, modified_trend, cause);
        self.overuse_latch = Some(OveruseLatch {
            since_ms: self.last_arrival_ms,
            base_ms,
            peak_rise_ms,
        });
    }

    /// AFKLink patch: whether a latched overuse (`OVERUSE_LATCH_*`) still holds against a trend
    /// that would end it; releases the latch, with a line, once it may end.
    fn overuse_latched(&mut self, to: BandwidthUsage, modified_trend: f64) -> bool {
        let Some(l) = &self.overuse_latch else {
            return false;
        };
        let held_ms = self.last_arrival_ms - l.since_ms;
        let rise_ms = self.accumulated_delay - l.base_ms;
        let drained = rise_ms <= collapsed_level_ms(l.peak_rise_ms);
        if held_ms < OVERUSE_LATCH_MAX_MS && (held_ms < OVERUSE_LATCH_MIN_MS || !drained) {
            trace!(
                target: PATCH_LOG_TARGET,
                to = %to,
                held_ms,
                rise_ms,
                modified_trend,
                "latched overuse kept against the trend"
            );
            return true;
        }
        patch_debug!(
            self,
            held_ms = %format_args!("{:.1}", held_ms),
            rise_ms = %format_args!("{:.1}", rise_ms),
            peak_rise_ms = %format_args!("{:.1}", l.peak_rise_ms),
            drained,
            to = %to,
            modified_trend = %format_args!("{:.1}", modified_trend),
            threshold = %format_args!("{:.1}", self.delay_threshold),
            "latched overuse released"
        );
        self.overuse_latch = None;
        false
    }

    fn update_threshold(&mut self, modified_trend: f64, now: Instant) {
        if self.last_threshold_update.is_none() {
            self.last_threshold_update = Some(now);
        }
        let abs_modified_trend = modified_trend.abs();

        if abs_modified_trend > self.delay_threshold + MAX_ADOPT_OFFSET_MS {
            // Avoid adapting the threshold to big latency spikes, caused e.g.,
            // by a sudden capacity drop.
            self.last_threshold_update = Some(now);
            return;
        }

        let k = if abs_modified_trend < self.delay_threshold {
            K_DOWN
        } else {
            K_UP
        };
        let time_delta = now
            .saturating_duration_since(
                self.last_threshold_update
                    .expect("last_threshold_update must have been set"),
            )
            .as_millis() as f64;
        self.delay_threshold +=
            k * (abs_modified_trend - self.delay_threshold) * time_delta.min(100.0);
        self.last_threshold_update = Some(now);
        self.delay_threshold = self.delay_threshold.clamp(6.0, 600.0);

        trace!(
            "Adaptive delay variation threshold changed to: {}",
            self.delay_threshold
        );
    }

    fn update_hypothesis(
        &mut self,
        new_hypothesis: BandwidthUsage,
        trend: f64,
        modified_trend: f64,
        cause: &'static str,
    ) {
        if self.hypothesis == new_hypothesis {
            return;
        }
        // AFKLink patch: an overuse that came out of a hold is not ended by the trend at once.
        if self.hypothesis == BandwidthUsage::Overuse
            && self.overuse_latched(new_hypothesis, modified_trend)
        {
            return;
        }

        trace!("TrendLineEstimator: Setting hypothesis to {new_hypothesis}");
        // AFKLink patch: every transition, with the numbers that made it. Into and out of
        // overuse at `debug`, each; normal <-> underuse at `trace`, summed into a `debug` line
        // at most every `QUIET_FLIPS_SUMMARY_MS` and `QUIET_FLIPS_SUMMARY_GROUPS`.
        let shape = self.rise_shape();
        let ms_in_state = self.last_arrival_ms - self.state_since_ms;
        if self.hypothesis != BandwidthUsage::Overuse && new_hypothesis != BandwidthUsage::Overuse {
            trace!(
                target: PATCH_LOG_TARGET,
                from = %self.hypothesis,
                to = %new_hypothesis,
                cause,
                trend,
                modified_trend,
                threshold = self.delay_threshold,
                rise_ms = shape.rise_ms,
                groups_in_state = self.groups_in_state,
                ms_in_state,
                "delay detector state change"
            );
            self.quiet_flips += 1;
            #[cfg(test)]
            {
                self.quiet_flips_total += 1;
            }
            if self.last_arrival_ms - self.quiet_flips_since_ms >= QUIET_FLIPS_SUMMARY_MS
                && self.quiet_flips_groups >= QUIET_FLIPS_SUMMARY_GROUPS
            {
                patch_debug!(
                    self,
                    flips = self.quiet_flips,
                    over_ms = %format_args!("{:.0}", self.last_arrival_ms - self.quiet_flips_since_ms),
                    groups = self.quiet_flips_groups,
                    last_to = %new_hypothesis,
                    cause,
                    trend = %format_args!("{:.4}", trend),
                    modified_trend = %format_args!("{:.1}", modified_trend),
                    threshold = %format_args!("{:.1}", self.delay_threshold),
                    rise_ms = %format_args!("{:.1}", shape.rise_ms),
                    "delay detector normal/underuse flips"
                );
                self.quiet_flips = 0;
                self.quiet_flips_since_ms = self.last_arrival_ms;
                self.quiet_flips_groups = 0;
            }
        } else {
            patch_debug!(
                self,
                from = %self.hypothesis,
                to = %new_hypothesis,
                cause,
                trend = %format_args!("{:.4}", trend),
                modified_trend = %format_args!("{:.1}", modified_trend),
                threshold = %format_args!("{:.1}", self.delay_threshold),
                rise_ms = %format_args!("{:.1}", shape.rise_ms),
                steepness = %format_args!("{:.2}", shape.steepness),
                groups_in_state = self.groups_in_state,
                ms_in_state = %format_args!("{:.0}", ms_in_state),
                quiet_flips_unsummed = self.quiet_flips,
                "delay detector state change"
            );
        }
        self.groups_in_state = 0;
        self.state_since_ms = self.last_arrival_ms;
        self.hypothesis = new_hypothesis;
    }
}

#[derive(Debug)]
struct Timing {
    #[allow(unused)]
    at: Instant,
    remote_recv_time_ms: f64,
    smoothed_delay_ms: f64,
    /// AFKLink patch: the accumulated (unsmoothed) delay after this variation.
    raw_delay_ms: f64,
}

struct Overuse {
    count: usize,
    time_overusing: TimeDelta,
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_window_size_limit() {
        let now = Instant::now();
        let remote_recv_time_base = Instant::now();
        let mut estimator = TrendlineEstimator::new(20);

        estimator.add_delay_observation(
            delay_variation(duration_ms(1), duration_ms(1), remote_recv_time_base),
            now,
        );

        for _ in 0..25 {
            estimator.add_delay_observation(
                delay_variation(
                    duration_ms(11),
                    duration_ms(1),
                    remote_recv_time_base + duration_ms(350),
                ),
                now + duration_ms(500),
            );
        }

        assert_eq!(estimator.history.len(), 20);
    }

    #[test]
    fn test_overuse() {
        let now = Instant::now();
        let remote_recv_time_base = Instant::now();
        let mut estimator = TrendlineEstimator::new(20);
        // AFKLink patch: this input is a 39 ms jump within 0.25 ms of arrival, a stall's shape,
        // which the patch holds back; the test checks upstream's detector, so it runs as upstream.
        estimator.upstream_only = true;

        for g in 0..5 {
            for i in 0..5 {
                estimator.add_delay_observation(
                    delay_variation(
                        duration_ms(1),
                        duration_ms(1),
                        remote_recv_time_base + Duration::from_micros(5_000 * g + i * 40),
                    ),
                    now + duration_ms(g * 100),
                );
            }
        }

        assert_eq!(estimator.hypothesis(), BandwidthUsage::Normal);
        assert_eq!(estimator.history.len(), 20);

        estimator.add_delay_observation(
            delay_variation(
                duration_ms(17),
                duration_ms(5),
                remote_recv_time_base + Duration::from_micros(25_000),
            ),
            now + duration_ms(600),
        );
        assert_eq!(
            estimator.hypothesis(),
            BandwidthUsage::Normal,
            "After getting an initial increasing delay the hypothesis should remain at normal"
        );

        estimator.add_delay_observation(
            delay_variation(
                duration_ms(18),
                duration_ms(5),
                remote_recv_time_base + Duration::from_micros(25_140),
            ),
            now + duration_ms(600),
        );
        assert_eq!(
            estimator.hypothesis(),
            BandwidthUsage::Normal,
            "After getting an a second increasing delay the hypothesis should remain at normal \
            because we the time overusing threshold hasn't been reached yet"
        );

        estimator.add_delay_observation(
            delay_variation(
                duration_ms(22),
                duration_ms(8),
                remote_recv_time_base + Duration::from_micros(25_250),
            ),
            now + duration_ms(600),
        );
        assert_eq!(
            estimator.hypothesis(),
            BandwidthUsage::Overuse,
            "After getting a third increasing delay the hypothesis should move to over because \
            we have been overusing for more than 10ms"
        );
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn delay_variation(
        recv_delta: Duration,
        send_delta: Duration,
        last_remote_recv_time: Instant,
    ) -> InterGroupDelayDelta {
        InterGroupDelayDelta {
            send_delta: send_delta.into(),
            arrival_delta: recv_delta.into(),
            last_remote_recv_time,
        }
    }

    #[test]
    fn test_history_insertion_regression_out_of_order() {
        // Test for algesten/str0m#698
        //
        // This test reproduces the scenario where a sample with a remote receive time
        // earlier than all existing history entries is added.
        // Prior to the fix, this appended the smallest (negative) element to the end
        // causing the monotonicity assert to fail when the window is full.

        let now = Instant::now();
        let zero_time_base = Instant::now();
        let mut estimator = TrendlineEstimator::new(8);

        // Add a few normal monotonically increasing values
        for offset_ms in [100, 200, 300, 400] {
            estimator.add_delay_observation(
                delay_variation(
                    duration_ms(10),
                    duration_ms(1),
                    zero_time_base + duration_ms(offset_ms),
                ),
                now,
            );
        }

        // Add some out-of-order samples that are earlier than the zero_time
        // (packet reordering is fun).
        for offset_ms in [50, 100, 25, 300] {
            estimator.add_delay_observation(
                delay_variation(
                    duration_ms(10),
                    duration_ms(1),
                    zero_time_base - duration_ms(offset_ms),
                ),
                now,
            );
        }

        // History should remain sorted.
        let ordered = estimator
            .history
            .iter()
            .zip(estimator.history.iter().skip(1))
            .all(|(a, b)| a.remote_recv_time_ms <= b.remote_recv_time_ms);
        assert!(
            ordered,
            "history should remain sorted by remote_recv_time_ms"
        );
    }

    // --- AFKLink patch: Wi-Fi stalls are not overuse -------------------------------------------

    /// Groups sent every `GROUP_MS`, as a paced 1080p stream's are; each arrives `delay` after it
    /// was sent, but never before the previous group has (packets do not overtake), and a link
    /// of `service` ms per group serialises them (a queue builds when `service > GROUP_MS`).
    const GROUP_MS: f64 = 5.0;

    struct Feed {
        base: Instant,
        /// Time between groups: `GROUP_MS`, or a frame interval for a sparse stream.
        group_ms: f64,
        /// The bottleneck's buffer in ms of queueing: a group that would wait longer is dropped
        /// (tail drop) and never reported. Unlimited by default.
        buffer_ms: f64,
        /// Up to this much extra one-way delay per group, uniform (a path's jitter; packets
        /// still never overtake each other), from a seeded generator.
        jitter_ms: f64,
        rng: u32,
        /// The far end's clock, which reports the receive times: ours plus this; a step in it
        /// is a step of the remote clock. And the last receive time it reported.
        remote_offset_ms: f64,
        remote_ms: f64,
        send_ms: f64,
        /// Send and arrival time of the last group that arrived.
        fed_send_ms: f64,
        arrival_ms: f64,
        /// (arrival ms, hypothesis) after every group that arrived.
        seen: Vec<(f64, BandwidthUsage)>,
    }

    impl Feed {
        fn new() -> Self {
            Self::every(GROUP_MS)
        }

        fn every(group_ms: f64) -> Self {
            Self {
                base: Instant::now(),
                group_ms,
                buffer_ms: f64::INFINITY,
                jitter_ms: 0.0,
                rng: 1,
                remote_offset_ms: 0.0,
                remote_ms: 0.0,
                send_ms: 0.0,
                fed_send_ms: 0.0,
                arrival_ms: 0.0,
                seen: Vec::new(),
            }
        }

        fn at(&self, ms: f64) -> Instant {
            self.base + Duration::from_micros((ms * 1000.0) as u64)
        }

        /// Send groups until `until_ms`, each with the one-way `delay(send_ms)` and `service`.
        fn run(
            &mut self,
            e: &mut TrendlineEstimator,
            until_ms: f64,
            service: f64,
            delay: impl Fn(f64) -> f64,
        ) {
            while self.send_ms < until_ms {
                let send = self.send_ms + self.group_ms;
                self.send_ms = send;
                self.rng = self.rng.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let jitter = self.jitter_ms * f64::from((self.rng >> 16) & 0x7fff) / 32_768.0;
                let unqueued = send + delay(send) + jitter;
                let arrival = unqueued.max(self.arrival_ms + service);
                if arrival - unqueued > self.buffer_ms {
                    continue;
                }
                self.feed(e, send, arrival);
            }
        }

        /// One group sent at `send` (ms) arrives at `arrival` (ms).
        fn feed(&mut self, e: &mut TrendlineEstimator, send: f64, arrival: f64) {
            let ms = |d: f64| Duration::from_micros((d.max(0.0) * 1000.0) as u64);
            let remote = arrival + self.remote_offset_ms;
            let variation = InterGroupDelayDelta {
                send_delta: ms(send - self.fed_send_ms).into(),
                arrival_delta: ms(remote - self.remote_ms).into(),
                last_remote_recv_time: self.at(remote),
            };
            e.add_delay_observation(variation, self.at(remote));
            self.fed_send_ms = send;
            self.arrival_ms = arrival;
            self.remote_ms = remote;
            self.seen.push((arrival, e.hypothesis()));
        }

        /// The first arrival time at or after `from_ms` with the hypothesis at overuse.
        fn first_overuse(&self, from_ms: f64) -> Option<f64> {
            self.seen
                .iter()
                .find(|(t, h)| *t >= from_ms && *h == BandwidthUsage::Overuse)
                .map(|(t, _)| *t)
        }

        /// The arrival times at which the hypothesis went into overuse.
        fn overuse_onsets(&self) -> Vec<f64> {
            let mut was = false;
            let mut out = Vec::new();
            for &(t, h) in &self.seen {
                let is = h == BandwidthUsage::Overuse;
                if is && !was {
                    out.push(t);
                }
                was = is;
            }
            out
        }

        /// The longest stretch of arrival time the hypothesis stayed at overuse: from the first
        /// group that saw it to the first that did not.
        fn longest_overuse_ms(&self) -> f64 {
            let mut longest: f64 = 0.0;
            let mut since = None;
            for &(t, h) in &self.seen {
                match (h == BandwidthUsage::Overuse, since) {
                    (true, None) => since = Some(t),
                    (false, Some(s)) => {
                        longest = longest.max(t - s);
                        since = None;
                    }
                    _ => {}
                }
            }
            if let (Some(s), Some(&(t, _))) = (since, self.seen.last()) {
                longest = longest.max(t - s);
            }
            longest
        }
    }

    const BASE_DELAY_MS: f64 = 20.0;
    /// Serialisation of one group on a link with room to spare.
    const FAST_SERVICE_MS: f64 = 0.5;

    fn estimator(upstream_only: bool) -> TrendlineEstimator {
        let mut e = TrendlineEstimator::new(20);
        e.upstream_only = upstream_only;
        e
    }

    /// The step shape (the simulator's `lan-wifi-spikes`): what is sent for 150 ms takes 100 ms
    /// longer, and what follows piles up behind it and arrives in a burst.
    fn step_stall(at: f64) -> impl Fn(f64) -> f64 {
        move |s| {
            if (at..at + 150.0).contains(&s) {
                BASE_DELAY_MS + 100.0
            } else {
                BASE_DELAY_MS
            }
        }
    }

    /// The ramp shape: the delay grows to +130 ms over 120 ms of sending, then collapses.
    fn ramp_stall(at: f64) -> impl Fn(f64) -> f64 {
        move |s| {
            if (at..at + 120.0).contains(&s) {
                BASE_DELAY_MS + 130.0 * (s - at) / 120.0
            } else {
                BASE_DELAY_MS
            }
        }
    }

    /// Group spacings the stall tests run at: a paced stream (5 ms) and one group per frame at
    /// 60 and 30 fps (the agent's real case: ~48 fps, the pacer at 1.1x under the estimate).
    const SPACINGS: [f64; 4] = [5.0, 16.7, 20.8, 33.0];
    /// Path jitter the stall tests run with: ms of extra one-way delay, uniform in [0, J), so
    /// J ms peak to peak.
    const JITTERS: [f64; 5] = [0.0, 3.0, 10.0, 15.0, 20.0];

    /// The stall shapes: (name, delay as a function of send time for a stall starting at `at`).
    fn shaped_stall(ramp: bool, at: f64) -> impl Fn(f64) -> f64 {
        move |s| {
            if ramp {
                ramp_stall(at)(s)
            } else {
                step_stall(at)(s)
            }
        }
    }

    /// The overuse onsets of the patched build on a path of one group per `spacing` ms with
    /// `jitter`, seeded `seed`, until `until_ms`, with `delay` as the path's delay.
    fn onsets(
        spacing: f64,
        jitter: f64,
        seed: u32,
        until_ms: f64,
        delay: impl Fn(f64) -> f64,
    ) -> (Vec<f64>, u64) {
        let mut e = estimator(false);
        let mut f = Feed::every(spacing);
        f.jitter_ms = jitter;
        f.rng = seed;
        f.run(&mut e, until_ms, FAST_SERVICE_MS, delay);
        (f.overuse_onsets(), e.stalls_ignored)
    }

    #[test]
    fn afklink_a_stall_is_not_overuse() {
        // Each shape at each spacing and jitter, starting at four offsets within a group (the
        // stall's first step lands in a different group each time). Upstream calls it overuse
        // (checked without jitter); the patched build gives it no overuse onset that the same
        // path without the stall (same jitter, same seed) does not have.
        for spacing in SPACINGS {
            for jitter in JITTERS {
                for ramp in [false, true] {
                    for k in 0..4u32 {
                        let at = 3_000.0 + spacing * f64::from(k) / 4.0;
                        let case =
                            format!("{spacing} ms groups, {jitter} ms jitter, ramp {ramp}, +{k}/4");
                        if jitter == 0.0 {
                            let mut e = estimator(true);
                            let mut f = Feed::every(spacing);
                            f.run(&mut e, 6_000.0, FAST_SERVICE_MS, shaped_stall(ramp, at));
                            assert!(f.first_overuse(0.0).is_some(), "{case}: upstream");
                        }
                        let (steady, _) =
                            onsets(spacing, jitter, 1 + k, 6_000.0, |_| BASE_DELAY_MS);
                        let (stalled, ignored) =
                            onsets(spacing, jitter, 1 + k, 6_000.0, shaped_stall(ramp, at));
                        assert!(
                            stalled.len() <= steady.len(),
                            "{case}: overuse at {stalled:?}, without the stall {steady:?}"
                        );
                        if jitter == 0.0 {
                            assert!(stalled.is_empty(), "{case}: overuse at {stalled:?}");
                            if spacing == GROUP_MS {
                                assert_eq!(ignored, 1, "{case}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// A stall of `extra` ms for `len` ms of sending, as a step or a ramp, starting at `at`.
    fn sized_stall(ramp: bool, at: f64, extra: f64, len: f64) -> impl Fn(f64) -> f64 {
        move |s| {
            if !(at..at + len).contains(&s) {
                BASE_DELAY_MS
            } else if ramp {
                BASE_DELAY_MS + extra * (s - at) / len
            } else {
                BASE_DELAY_MS + extra
            }
        }
    }

    #[test]
    fn afklink_a_remote_clock_stepping_back_does_not_freeze_a_latch() {
        // The far end's clock (TWCC's receive times) steps back by 10 s while an overuse that
        // came out of a hold is latched (a path that got 100 ms longer for good). The latch's
        // clock is moved back with it, so it still ends within OVERUSE_LATCH_MAX_MS (plus a few
        // groups) instead of holding until the arrivals pass the old maximum, 10 s later.
        let mut e = estimator(false);
        let mut f = Feed::new();
        f.remote_offset_ms = 20_000.0;
        f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        let longer = |s: f64| BASE_DELAY_MS + if s >= 3_000.0 { 100.0 } else { 0.0 };
        while e.overuse_latch.is_none() && f.send_ms < 4_000.0 {
            let n = f.send_ms + GROUP_MS;
            f.run(&mut e, n, FAST_SERVICE_MS, longer);
        }
        assert!(
            e.overuse_latch.is_some(),
            "the longer path's overuse is latched"
        );
        let latched_at = f.arrival_ms;
        f.remote_offset_ms -= 10_000.0;
        f.run(&mut e, 6_000.0, FAST_SERVICE_MS, longer);
        let ended = f
            .seen
            .iter()
            .find(|(t, h)| *t > latched_at && *h != BandwidthUsage::Overuse)
            .map(|(t, _)| *t - latched_at)
            .expect("the overuse ends");
        println!("latched overuse ended {ended} ms after it began, across a 10 s step back");
        assert!(
            ended <= OVERUSE_LATCH_MAX_MS + 4.0 * GROUP_MS,
            "ended after {ended} ms"
        );
        assert!(e.overuse_latch.is_none());
    }

    #[test]
    fn afklink_a_stall_sweep_gives_no_overuse_the_steady_path_lacks() {
        // The review's sweep: every group spacing, both shapes, +40..+140 ms for 80-200 ms of
        // sending, four offsets within a group, with and without 10 ms of jitter. A stall the
        // trend first signals on its falling edge (sparse groups, short stalls) is the case the
        // hold's peak and steepness once got wrong (`RiseShape::rise_peak_ms`).
        //
        // The stalls the patch is for must never be cut: peaking at 50 ms or more (above
        // STALL_MIN_PEAK_MS with jitter to spare), a step or a ramp rising at least 0.5 ms per
        // ms of sending (gentler, it is a queue at up to ~1.5x overrun while it rises, called as
        // upstream calls one), and over within the hold (its rise lasts `len + extra` ms of
        // arrival). Outside that the cuts are counted and printed: they are the documented cost.
        let targeted = |ramp: bool, extra: f64, len: f64| {
            extra >= 50.0 && (!ramp || extra / len >= 0.5) && len + extra <= 230.0
        };
        let mut cut = Vec::new();
        let mut cut_outside = 0;
        let mut total = 0;
        for spacing in SPACINGS {
            for ramp in [false, true] {
                for extra in [40.0, 50.0, 60.0, 70.0, 80.0, 100.0, 120.0, 140.0] {
                    for len in [80.0, 120.0, 150.0, 200.0] {
                        for k in 0..4u32 {
                            for jitter in [0.0, 10.0] {
                                let at = 3_000.0 + spacing * f64::from(k) / 4.0;
                                let seed = 1 + k;
                                let (steady, _) =
                                    onsets(spacing, jitter, seed, 6_000.0, |_| BASE_DELAY_MS);
                                let (stalled, _) = onsets(
                                    spacing,
                                    jitter,
                                    seed,
                                    6_000.0,
                                    sized_stall(ramp, at, extra, len),
                                );
                                total += 1;
                                if stalled.len() > steady.len() && !targeted(ramp, extra, len) {
                                    cut_outside += 1;
                                } else if stalled.len() > steady.len() {
                                    cut.push(format!(
                                        "{spacing} ms, ramp {ramp}, +{extra} for {len} ms, +{k}/4, \
                                         jitter {jitter}: overuse at {stalled:?}"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        println!(
            "stall sweep: {} targeted and {cut_outside} other cases cut, of {total}",
            cut.len()
        );
        assert!(
            cut.is_empty(),
            "{} of {total} targeted stalls cut:\n{}",
            cut.len(),
            cut.join("\n")
        );
    }

    #[test]
    fn afklink_stalls_every_few_seconds_are_never_overuse() {
        // The 25 Oct viewer: +80..+130 ms every 3-8 s for a minute, both shapes taking turns,
        // at each spacing and jitter.
        let gaps = [
            4_000.0, 6_500.0, 3_000.0, 7_500.0, 5_000.0, 3_500.0, 8_000.0,
        ];
        let mut starts = Vec::new();
        let mut at = 2_000.0;
        while at < 60_000.0 {
            starts.push(at);
            at += gaps[starts.len() % gaps.len()];
        }
        let stalls = |s: f64| {
            starts
                .iter()
                .enumerate()
                .map(|(n, &at)| shaped_stall(n % 2 == 1, at)(s))
                .fold(BASE_DELAY_MS, f64::max)
        };
        for spacing in SPACINGS {
            for jitter in JITTERS {
                let case = format!("{spacing} ms groups, {jitter} ms jitter");
                let (steady, _) = onsets(spacing, jitter, 1, 62_000.0, |_| BASE_DELAY_MS);
                let (stalled, ignored) = onsets(spacing, jitter, 1, 62_000.0, stalls);
                println!(
                    "{case}: {} stalls, {ignored} ignored, overuse onsets {} (without stalls {})",
                    starts.len(),
                    stalled.len(),
                    steady.len()
                );
                assert!(
                    stalled.len() <= steady.len(),
                    "{case}: overuse at {stalled:?}, without the stalls {steady:?}"
                );
                if jitter == 0.0 {
                    assert!(stalled.is_empty(), "{case}: overuse at {stalled:?}");
                    if spacing == GROUP_MS {
                        assert_eq!(ignored, starts.len() as u64, "{case}");
                    }
                }
            }
        }
        // Smaller stalls (+60..+80 ms) on the jitteriest paths: their collapse level is the
        // 20 ms floor, as large as the jitter, so a single jitter sample once ended the ignored
        // stall's episode (`recheck_swallowed_overuse`) and the cooldown cut on it (the review:
        // 2 of 1120 at 20.8 ms groups). Four seeds, each with its own stall times.
        let gaps = [
            4_000.0, 6_500.0, 3_000.0, 7_500.0, 5_000.0, 3_500.0, 8_000.0, 3_200.0,
        ];
        for spacing in SPACINGS {
            for jitter in [15.0, 20.0] {
                for (extra, len) in [(60.0, 80.0), (60.0, 120.0), (80.0, 100.0)] {
                    for seed in 1..=4u32 {
                        let mut starts = Vec::new();
                        let mut at = 2_000.0 + f64::from(seed) * 3.3;
                        while at < 40_000.0 {
                            starts.push(at);
                            at += gaps[(starts.len() + seed as usize) % gaps.len()];
                        }
                        let stalls = |s: f64| {
                            starts
                                .iter()
                                .enumerate()
                                .map(|(n, &at)| sized_stall(n % 2 == 1, at, extra, len)(s))
                                .fold(BASE_DELAY_MS, f64::max)
                        };
                        let case = format!(
                            "{spacing} ms groups, {jitter} ms jitter, +{extra} ms for {len} ms, seed {seed}"
                        );
                        let (steady, _) =
                            onsets(spacing, jitter, seed, 41_000.0, |_| BASE_DELAY_MS);
                        let (stalled, _) = onsets(spacing, jitter, seed, 41_000.0, stalls);
                        assert!(
                            stalled.len() <= steady.len(),
                            "{case}: overuse at {stalled:?}, without the stalls {steady:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn afklink_a_small_burst_queue_that_drains_is_overuse_as_upstream() {
        // A keyframe into a narrow link: for 30 ms we send 2x what it carries, the queue peaks
        // short of a stall's size, then drains. Each spacing is called as upstream calls it
        // (STALL_MIN_PEAK_MS): overuse at 5 ms groups; at a group per frame the 30 ms burst is
        // one or two groups and upstream's trend does not cross its threshold, so neither does
        // the patched build's. (A burst whose queue peaks at a stall's size and drains within
        // the hold looks like one and is ignored: vendor/VENDORED.md, "What it costs".)
        for (spacing, upstream_calls) in [(5.0, true), (16.7, false), (20.8, false), (33.0, false)]
        {
            let mut called = [false; 2];
            for (i, upstream_only) in [true, false].into_iter().enumerate() {
                let mut e = estimator(upstream_only);
                let mut f = Feed::every(spacing);
                f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
                f.run(&mut e, 3_030.0, spacing * 2.0, |_| BASE_DELAY_MS);
                f.run(&mut e, 5_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
                called[i] = f.first_overuse(0.0).is_some();
            }
            assert_eq!(called[0], upstream_calls, "{spacing} ms groups: upstream");
            assert_eq!(called[1], upstream_calls, "{spacing} ms groups: patched");
        }
    }

    /// When a queue at 1/`ratio` of our rate, starting `start_after` ms after a stall (`stall`:
    /// a step or a ramp) or on the same path without one, is first called overuse, from when
    /// the link narrowed.
    fn queue_after(
        stall: Option<bool>,
        spacing: f64,
        jitter: f64,
        start_after: f64,
        ratio: f64,
    ) -> Option<f64> {
        let mut e = estimator(false);
        let mut f = Feed::every(spacing);
        f.jitter_ms = jitter;
        f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        let until = 3_150.0 + start_after;
        match stall {
            Some(ramp) => f.run(&mut e, until, FAST_SERVICE_MS, shaped_stall(ramp, 3_000.0)),
            None => f.run(&mut e, until, FAST_SERVICE_MS, |_| BASE_DELAY_MS),
        }
        let at = f.arrival_ms;
        f.run(&mut e, 9_000.0, spacing * ratio, |_| BASE_DELAY_MS);
        f.first_overuse(at).map(|t| t - at)
    }

    /// The most later than on a path without the stall a queue right behind an ignored stall
    /// is called overuse, per group spacing: measured over the cases of
    /// `afklink_a_queue_behind_an_ignored_stall_is_overuse` and two more seeds (184, 421, 371 and
    /// 450 ms at 5, 16.7, 20.8 and 33 ms groups, all at 1.05x with 20 ms of jitter: 10-25 ms more
    /// queue), plus ~15% (vendor/VENDORED.md, "What it costs").
    fn queue_after_stall_bound_ms(spacing: f64) -> f64 {
        match spacing {
            s if s <= 5.0 => 215.0,
            s if s <= 16.7 => 485.0,
            s if s <= 20.8 => 430.0,
            _ => 520.0,
        }
    }

    #[test]
    fn afklink_a_queue_behind_an_ignored_stall_is_overuse() {
        // The dedupe of an ignored stall must not swallow a real queue behind it: once the
        // delay climbs off the path's floor it is a new rise, judged at once while the trend has
        // stayed up since the ignore (`recheck_swallowed_overuse`). Both shapes, every spacing,
        // starting right at the stall's end and up to 500 ms after it, 1.05-3x, with up to 20 ms
        // of jitter: always called, and at most `queue_after_stall_bound_ms` later than without
        // the stall.
        for spacing in SPACINGS {
            let mut worst: f64 = 0.0;
            for ramp in [false, true] {
                for start_after in [0.0, 60.0, 120.0, 200.0, 300.0, 500.0] {
                    for ratio in [1.05, 1.1, 1.2, 1.35, 1.5, 2.0, 3.0] {
                        for jitter in [0.0, 10.0, 20.0] {
                            let case = format!(
                                "{spacing} ms, ramp {ramp}, +{start_after} ms, {ratio}x, jitter {jitter}"
                            );
                            let alone = queue_after(None, spacing, jitter, start_after, ratio)
                                .expect("a growing queue is overuse");
                            let behind =
                                queue_after(Some(ramp), spacing, jitter, start_after, ratio)
                                    .unwrap_or_else(|| {
                                        unreachable!("{case}: the queue behind the stall is hidden")
                                    });
                            worst = worst.max(behind - alone);
                            assert!(
                                behind - alone <= queue_after_stall_bound_ms(spacing),
                                "{case}: {behind} ms behind the stall, {alone} ms without"
                            );
                        }
                    }
                }
            }
            println!(
                "{spacing} ms groups: a queue behind a stall is called at most {worst:.0} ms later"
            );
        }
    }

    /// The link narrows at 2 s to `GROUP_MS / service` of our rate; returns when each build first
    /// called it overuse (arrival ms).
    fn narrowing(service: f64) -> (f64, f64) {
        let mut out = [0.0; 2];
        for (i, upstream_only) in [true, false].into_iter().enumerate() {
            let mut e = estimator(upstream_only);
            let mut f = Feed::new();
            f.run(&mut e, 2_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
            let narrowed_at = f.arrival_ms;
            f.run(&mut e, 5_000.0, service, |_| BASE_DELAY_MS);
            out[i] = f
                .first_overuse(narrowed_at)
                .expect("a growing queue is overuse")
                - narrowed_at;
        }
        (out[0], out[1])
    }

    #[test]
    fn afklink_a_queue_at_a_narrowing_link_is_overuse_as_upstream() {
        // We send 1.1x, 1.2x and 1.3x what the link carries: the rise is too gradual for a
        // stall, so the patch changes nothing.
        for ratio in [1.1, 1.2, 1.3] {
            let (upstream, patched) = narrowing(GROUP_MS * ratio);
            assert_eq!(
                upstream, patched,
                "{ratio}x: upstream {upstream} ms, patched {patched} ms"
            );
            assert!(patched <= 300.0, "{ratio}x: overuse after {patched} ms");
        }
    }

    #[test]
    fn afklink_a_collapsed_link_is_overuse_within_the_hold() {
        // We send 1.5x, 2x, 3x, 5x and 10x what the link carries: the queue grows about as
        // steeply as a stall's. It is held back for at most STALL_MAX_HOLD_MS, less when it
        // passes STALL_MAX_RISE_MS first.
        for ratio in [1.5, 2.0, 3.0, 5.0, 10.0] {
            let (upstream, patched) = narrowing(GROUP_MS * ratio);
            println!("{ratio}x: overuse after {upstream} ms upstream, {patched} ms patched");
            // The hold is settled on the first group arriving after it ran out.
            assert!(
                patched <= upstream + STALL_MAX_HOLD_MS + GROUP_MS * ratio,
                "{ratio}x: upstream {upstream} ms, patched {patched} ms"
            );
        }
    }

    #[test]
    fn afklink_a_longer_path_is_overuse_after_the_hold() {
        // The path gets 100 ms longer for good (a relay changes its route): a jump that does not
        // collapse. Held back, then called overuse when the hold runs out, as upstream calls it
        // at once.
        let mut first = [0.0; 2];
        for (i, upstream_only) in [true, false].into_iter().enumerate() {
            let mut e = estimator(upstream_only);
            let mut f = Feed::new();
            f.run(&mut e, 2_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
            f.run(&mut e, 5_000.0, FAST_SERVICE_MS, |s| {
                BASE_DELAY_MS + if s >= 2_000.0 { 100.0 } else { 0.0 }
            });
            first[i] = f.first_overuse(0.0).expect("a longer path is overuse");
            assert!(e.stall.is_none());
            assert_eq!(e.stalls_ignored, 0);
        }
        let [upstream, patched] = first;
        assert!(
            patched <= upstream + STALL_MAX_HOLD_MS + GROUP_MS,
            "upstream {upstream} ms, patched {patched} ms"
        );
    }

    /// Held-back rises that turn out to be a queue which soon stops growing, so the trend falls
    /// back inside the threshold right when the hold runs out: a link that narrows behind a
    /// shallow buffer (the queue fills, then tail drop) and a path that gets longer for good.
    /// (label, overrun, buffer ms, extra path delay ms)
    const STOPS_GROWING: [(&str, f64, f64, f64); 7] = [
        ("1.5x, 40 ms buffer", 1.5, 40.0, 0.0),
        ("2x, 40 ms buffer", 2.0, 40.0, 0.0),
        ("2x, 80 ms buffer", 2.0, 80.0, 0.0),
        ("3x, 40 ms buffer", 3.0, 40.0, 0.0),
        ("3x, 60 ms buffer", 3.0, 60.0, 0.0),
        ("3x, 80 ms buffer", 3.0, 80.0, 0.0),
        ("path +100 ms for good", 1.0, f64::INFINITY, 100.0),
    ];

    fn stops_growing(upstream_only: bool, ratio: f64, buffer_ms: f64, extra_ms: f64) -> Feed {
        let mut e = estimator(upstream_only);
        let mut f = Feed::new();
        f.run(&mut e, 2_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        f.buffer_ms = buffer_ms;
        let service = if ratio > 1.0 {
            GROUP_MS * ratio
        } else {
            FAST_SERVICE_MS
        };
        f.run(&mut e, 4_000.0, service, |_| BASE_DELAY_MS + extra_ms);
        f
    }

    #[test]
    fn afklink_an_overuse_after_the_hold_lasts_long_enough_to_act_on() {
        // The delay controller reads the hypothesis once per TWCC report: an overuse of one
        // group is never acted on. Out of a hold it lasts at least OVERUSE_LATCH_MIN_MS (or as
        // long as upstream's, if that is shorter).
        for (label, ratio, buffer, extra) in STOPS_GROWING {
            let upstream = stops_growing(true, ratio, buffer, extra).longest_overuse_ms();
            let patched = stops_growing(false, ratio, buffer, extra).longest_overuse_ms();
            println!("{label}: overuse lasts {upstream} ms upstream, {patched} ms patched");
            assert!(upstream > 0.0, "{label}: upstream calls it overuse");
            assert!(
                patched >= OVERUSE_LATCH_MIN_MS.min(upstream),
                "{label}: upstream {upstream} ms, patched {patched} ms"
            );
            // The latch's cap: a queue that never drains (a path longer for good) gets no more
            // than OVERUSE_LATCH_MAX_MS of overuse once the trend is quiet, plus the group that
            // ends it.
            if extra > 0.0 {
                assert!(
                    patched <= OVERUSE_LATCH_MAX_MS + GROUP_MS,
                    "{label}: overuse lasts {patched} ms"
                );
            }
        }
    }

    #[test]
    fn afklink_a_queue_right_after_a_stall_is_overuse() {
        let mut e = estimator(false);
        let mut f = Feed::new();
        f.run(&mut e, 2_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        f.run(&mut e, 2_300.0, FAST_SERVICE_MS, step_stall(2_000.0));
        let queue_at = f.arrival_ms;
        f.run(&mut e, 4_000.0, GROUP_MS * 1.5, |_| BASE_DELAY_MS);
        let after = f.first_overuse(queue_at).expect("the queue is overuse") - queue_at;
        println!("queue right after a stall: overuse after {after} ms");
        // The trend's window (20 groups, 150 ms at 1.5x) still holds the stall when the queue
        // starts; once the queue's rise is held back, it is settled within the hold.
        assert!(
            after <= 20.0 * GROUP_MS * 1.5 + STALL_MAX_HOLD_MS + GROUP_MS * 1.5,
            "after {after} ms"
        );
    }

    /// When each build first calls a queue in a sparse stream (one group per 30 fps frame)
    /// overuse, from when the link narrowed; with a step stall just before it, or not.
    fn sparse_queue(upstream_only: bool, ratio: f64, stall_before: bool) -> f64 {
        let mut e = estimator(upstream_only);
        let mut f = Feed::every(33.0);
        f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        if stall_before {
            f.run(&mut e, 3_400.0, FAST_SERVICE_MS, step_stall(3_000.0));
        }
        let at = f.arrival_ms;
        f.run(&mut e, 9_000.0, 33.0 * ratio, |_| BASE_DELAY_MS);
        f.first_overuse(at).expect("a growing queue is overuse") - at
    }

    #[test]
    fn afklink_a_queue_in_a_sparse_stream_is_overuse() {
        for ratio in [1.2, 1.5, 2.0] {
            let upstream = sparse_queue(true, ratio, false);
            let patched = sparse_queue(false, ratio, false);
            println!("sparse {ratio}x: overuse after {upstream} ms upstream, {patched} ms patched");
            assert!(
                patched <= upstream + STALL_MAX_HOLD_MS + 33.0 * ratio,
                "{ratio}x: upstream {upstream} ms, patched {patched} ms"
            );
        }
    }

    #[test]
    fn afklink_a_queue_behind_a_collapsed_stall_in_a_sparse_stream_is_overuse() {
        // The stall is still in the window (20 groups, ~660 ms) when the queue starts: it must
        // not be taken for that stall once the delay climbs again.
        for ratio in [1.2, 1.5, 2.0] {
            let alone = sparse_queue(false, ratio, false);
            let behind = sparse_queue(false, ratio, true);
            println!("sparse {ratio}x: overuse after {alone} ms alone, {behind} ms behind a stall");
            assert!(
                behind <= alone + STALL_MAX_HOLD_MS + 33.0 * ratio,
                "{ratio}x: alone {alone} ms, behind a stall {behind} ms"
            );
        }
    }

    #[test]
    fn afklink_upstreams_overuse_input_is_overuse_after_the_hold() {
        // `test_overuse`'s input, then the delay keeps growing by 10 ms a group: held back as a
        // possible stall, then overuse.
        let now = Instant::now();
        let base = Instant::now();
        let mut e = TrendlineEstimator::new(20);
        for g in 0..5 {
            for i in 0..5 {
                e.add_delay_observation(
                    delay_variation(
                        duration_ms(1),
                        duration_ms(1),
                        base + Duration::from_micros(5_000 * g + i * 40),
                    ),
                    now + duration_ms(g * 100),
                );
            }
        }
        for (recv, send, at) in [(17, 5, 25_000), (18, 5, 25_140), (22, 8, 25_250)] {
            e.add_delay_observation(
                delay_variation(
                    duration_ms(recv),
                    duration_ms(send),
                    base + Duration::from_micros(at),
                ),
                now + duration_ms(600),
            );
        }
        assert!(e.stall.is_some(), "held back as a possible stall");
        let mut overuse_at = None;
        for k in 1..=40u64 {
            e.add_delay_observation(
                delay_variation(
                    duration_ms(15),
                    duration_ms(5),
                    base + Duration::from_micros(25_250 + k * 15_000),
                ),
                now + duration_ms(600),
            );
            if e.hypothesis() == BandwidthUsage::Overuse {
                overuse_at = Some(k);
                break;
            }
        }
        let k = overuse_at.expect("overuse once the hold is settled");
        assert!(
            k * 15 <= STALL_MAX_HOLD_MS as u64 + 15,
            "overuse after {k} groups"
        );
    }

    #[test]
    fn afklink_a_reordered_variation_or_a_pause_does_not_move_a_hold_back() {
        let mut e = estimator(false);
        let mut f = Feed::new();
        f.run(&mut e, 2_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        f.run(&mut e, 2_060.0, FAST_SERVICE_MS, step_stall(2_000.0));
        let opened = e.stall.as_ref().expect("the stall is held").opened_ms;
        let latest = e.last_arrival_ms;
        // A variation reported 50 ms before the latest one.
        let back = f.arrival_ms - 50.0;
        e.add_delay_observation(
            InterGroupDelayDelta {
                send_delta: duration_ms(5).into(),
                arrival_delta: duration_ms(0).into(),
                last_remote_recv_time: f.at(back),
            },
            f.at(back),
        );
        assert_eq!(e.last_arrival_ms, latest, "the clock does not go back");
        let c = e
            .stall
            .as_ref()
            .expect("still held after the reordered variation");
        assert_eq!(c.opened_ms, opened);
        // The stream pauses for a second inside the stall and comes back at the base delay: the
        // collapse is first seen after the hold ran out, when it happened is unknown, so it is
        // settled as upstream would have called it: overuse, once.
        let resumed_at = f.arrival_ms;
        f.send_ms += 1_000.0;
        f.run(&mut e, 5_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        assert!(e.stall.is_none(), "the hold is settled");
        assert_eq!(f.overuse_onsets().len(), 1, "one overuse, after the pause");
        assert!(f.first_overuse(0.0).is_some_and(|t| t > resumed_at));
        assert_eq!(e.stalls_ignored, 0);
    }

    #[test]
    fn afklink_debug_lines_stay_few_under_a_flapping_trend() {
        let mut e = estimator(false);
        let mut f = Feed::new();
        f.run(&mut e, 2_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        let before = e.debug_lines;
        // A group a second, and the peer reports the next one's arrival either 1 s or only
        // 0.4 s later, in runs of 1-4: the delay keeps falling in steps of 600 ms and pausing,
        // so the trend crosses the underuse threshold back and forth all the time.
        let mut variations = 0u64;
        let mut state: u32 = 7;
        while variations < 20_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let run = 1 + (state >> 16) % 4;
            for gap in [1_000.0, 400.0] {
                for _ in 0..run {
                    let send = f.fed_send_ms + 1_000.0;
                    let arrival = f.arrival_ms + gap;
                    f.feed(&mut e, send, arrival);
                    variations += 1;
                }
            }
        }
        let (debug, flips) = (e.debug_lines - before, e.quiet_flips_total);
        println!("flapping: {debug} debug lines and {flips} flips for {variations} variations");
        assert!(flips > 2_000, "the trend did flap ({flips} flips)");
        // One summary per QUIET_FLIPS_SUMMARY_GROUPS variations at most, plus a few others.
        assert!(
            debug <= variations / QUIET_FLIPS_SUMMARY_GROUPS + 20,
            "{debug} debug lines"
        );
    }

    #[test]
    fn afklink_a_flapping_remote_clock_logs_few_debug_lines() {
        // The far end's receive clock flips between two offsets 1.5 s apart with every group, so
        // it steps back with every other variation (the review: one debug line per step, 1001 for
        // 2000 groups). The steps are summed as normal <-> underuse flips are.
        for spacing in [5.0, 33.0] {
            let mut e = estimator(false);
            let mut f = Feed::every(spacing);
            f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
            let before = e.debug_lines;
            let longer = |s: f64| BASE_DELAY_MS + if s >= 3_000.0 { 100.0 } else { 0.0 };
            let mut groups = 0u64;
            while f.send_ms < 13_000.0 {
                f.remote_offset_ms = if groups % 2 == 0 { 0.0 } else { -1_500.0 };
                let n = f.send_ms + spacing;
                f.run(&mut e, n, FAST_SERVICE_MS, longer);
                groups += 1;
            }
            let debug = e.debug_lines - before;
            println!(
                "{spacing} ms groups, a flapping remote clock: {debug} debug lines, {groups} groups"
            );
            assert!(
                debug <= groups / QUIET_FLIPS_SUMMARY_GROUPS + 10,
                "{spacing} ms groups: {debug} debug lines for {groups} groups"
            );
        }
    }

    /// What a build makes of a train of big frames, from when it starts.
    struct Train {
        /// When it was first called overuse (ms of arrival time), the queue then (ms), and the
        /// stalls ignored by then.
        first_ms: Option<f64>,
        queue_at_first_ms: f64,
        ignored_before_first: u64,
        /// Stalls ignored and overuse onsets over the whole train.
        ignored: u64,
        onsets: usize,
    }

    /// A train of big frames for `secs` after 3 s of a quiet path: every `k`-th group takes
    /// `beta` group intervals of link time and the others share the rest of `rho(s)` intervals
    /// each (`s`: seconds into the train), so the link carries 1/rho of what we send. Each big
    /// frame's queue jumps and drains like a short stall; with rho above 1 its floor creeps up.
    fn burst_train(
        upstream_only: bool,
        spacing: f64,
        k: u32,
        beta: f64,
        rho: impl Fn(f64) -> f64,
        secs: f64,
    ) -> Train {
        let mut e = estimator(upstream_only);
        let mut f = Feed::every(spacing);
        f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
        let (start_arrival, start_send) = (f.arrival_ms, f.send_ms);
        let big = beta * spacing;
        let mut t = Train {
            first_ms: None,
            queue_at_first_ms: f64::NAN,
            ignored_before_first: 0,
            ignored: 0,
            onsets: 0,
        };
        let mut n = 0u32;
        while f.send_ms < start_send + secs * 1_000.0 {
            let r = rho((f.send_ms - start_send) / 1_000.0);
            let small = ((f64::from(k) * r * spacing - big) / f64::from(k - 1)).max(0.1);
            let service = if n % k == 0 { big } else { small };
            let until = f.send_ms + spacing;
            f.run(&mut e, until, service, |_| BASE_DELAY_MS);
            if t.first_ms.is_none() && e.hypothesis() == BandwidthUsage::Overuse {
                t.first_ms = Some(f.arrival_ms - start_arrival);
                t.queue_at_first_ms = f.arrival_ms - f.fed_send_ms - BASE_DELAY_MS;
                t.ignored_before_first = e.stalls_ignored;
            }
            n += 1;
        }
        t.ignored = e.stalls_ignored;
        t.onsets = f.overuse_onsets().len();
        t
    }

    /// Whether the train's small frames still get some link time (`burst_train`).
    fn train_fits(k: u32, beta: f64, rho: f64) -> bool {
        f64::from(k) * rho - beta >= 0.1 * f64::from(k - 1)
    }

    /// At most one stall ignored per STALL_COOLDOWN_MS, plus the first.
    fn most_ignores(secs: f64) -> u64 {
        1 + (secs * 1_000.0 / STALL_COOLDOWN_MS) as u64
    }

    #[test]
    fn afklink_a_burst_train_on_a_growing_queue_is_overuse() {
        // The review's escape of round 4: a big frame every 6 or 12 groups into a link we overrun
        // by 2-5%. Each big frame's queue jumped and drained back to the window's low like a
        // short stall while the floor under them crept up 20-50 ms/s, and every one was ignored
        // (147 in 15 s, 776 ms of queue). Now at most one is (G1), and the next big frame is
        // overuse at its signal: called at most one burst cycle and a hold after upstream.
        let mut worst = (f64::NEG_INFINITY, String::new());
        for spacing in SPACINGS {
            for k in [6u32, 12] {
                for beta in [3.0, 5.0, 8.0] {
                    for rho in [1.02, 1.05] {
                        if !train_fits(k, beta, rho) {
                            continue;
                        }
                        let case = format!("{spacing} ms, a big frame of {beta} every {k}, {rho}x");
                        let up = burst_train(true, spacing, k, beta, |_| rho, 15.0);
                        let pat = burst_train(false, spacing, k, beta, |_| rho, 15.0);
                        let u = up.first_ms.unwrap_or_else(|| panic!("{case}: upstream"));
                        let p = pat.first_ms.unwrap_or_else(|| {
                            panic!("{case}: never called, {} ignored", pat.ignored)
                        });
                        assert!(
                            pat.ignored_before_first <= 1,
                            "{case}: {} ignored before the first overuse",
                            pat.ignored_before_first
                        );
                        assert!(
                            p <= u + f64::from(k) * spacing + STALL_MAX_HOLD_MS,
                            "{case}: upstream {u:.0} ms, patched {p:.0} ms"
                        );
                        assert!(
                            pat.ignored <= most_ignores(15.0),
                            "{case}: {} ignored",
                            pat.ignored
                        );
                        if p - u > worst.0 {
                            worst = (
                                p - u,
                                format!(
                                    "{case}: upstream {u:.0} ms at {:.0} ms of queue, patched \
                                     {p:.0} ms at {:.0}",
                                    up.queue_at_first_ms, pat.queue_at_first_ms
                                ),
                            );
                        }
                    }
                }
            }
        }
        println!(
            "burst trains on a growing queue: called at most {:.0} ms after upstream ({})",
            worst.0, worst.1
        );
    }

    #[test]
    fn afklink_a_burst_train_on_a_slowly_growing_overrun_is_overuse() {
        // The same trains while the overrun grows from nothing by 1% or 3% a second (the review:
        // round 4 first called them after 3-8.7 s, at 116-527 ms of queue).
        let mut worst = (f64::NEG_INFINITY, String::new());
        for spacing in SPACINGS {
            for k in [6u32, 12] {
                for beta in [3.0, 5.0, 8.0] {
                    if !train_fits(k, beta, 1.0) {
                        continue;
                    }
                    for per_s in [0.01, 0.03] {
                        let case =
                            format!("{spacing} ms, a big frame of {beta} every {k}, +{per_s}/s");
                        let rho = |s: f64| 1.0 + per_s * s;
                        let up = burst_train(true, spacing, k, beta, rho, 15.0);
                        let pat = burst_train(false, spacing, k, beta, rho, 15.0);
                        let u = up.first_ms.unwrap_or_else(|| panic!("{case}: upstream"));
                        let p = pat
                            .first_ms
                            .unwrap_or_else(|| panic!("{case}: never called"));
                        assert!(pat.ignored_before_first <= 1, "{case}");
                        assert!(
                            p <= u + f64::from(k) * spacing + STALL_MAX_HOLD_MS,
                            "{case}: upstream {u:.0} ms, patched {p:.0} ms"
                        );
                        if p - u > worst.0 {
                            worst = (
                                p - u,
                                format!(
                                    "{case}: upstream {u:.0} ms at {:.0} ms of queue, patched \
                                     {p:.0} ms at {:.0}",
                                    up.queue_at_first_ms, pat.queue_at_first_ms
                                ),
                            );
                        }
                    }
                }
            }
        }
        println!(
            "burst trains on a growing overrun: called at most {:.0} ms after upstream ({})",
            worst.0, worst.1
        );
    }

    #[test]
    fn afklink_stall_shaped_bursts_closer_than_the_cooldown_are_overuse() {
        // G1 on its own: big frames every 6-12 groups into a link with room on average (we send
        // 0.8-0.9x what it carries), so each burst's queue (67-230 ms) drains fully: no floor
        // creeps, and each looks like a short stall. Upstream calls them overuse. Stalls never
        // repeat this fast: at most one per STALL_COOLDOWN_MS is ignored, the rest are overuse.
        for spacing in [16.7, 33.0] {
            for k in [6u32, 12] {
                for beta in [5.0, 8.0] {
                    for rho in [0.8, 0.9] {
                        if !train_fits(k, beta, rho) {
                            continue;
                        }
                        let case = format!("{spacing} ms, a big frame of {beta} every {k}, {rho}x");
                        let up = burst_train(true, spacing, k, beta, |_| rho, 15.0);
                        let pat = burst_train(false, spacing, k, beta, |_| rho, 15.0);
                        println!(
                            "{case}: upstream {} overuse onsets; patched {}, {} ignored",
                            up.onsets, pat.onsets, pat.ignored
                        );
                        assert!(up.onsets > 0, "{case}: upstream");
                        assert!(pat.onsets > 0, "{case}: patched never calls it");
                        assert!(
                            pat.ignored <= most_ignores(15.0),
                            "{case}: {} ignored",
                            pat.ignored
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn afklink_slow_bursts_cannot_hide_a_creeping_floor() {
        // G2 on its own: a stall-like burst (+80 ms in one group, drained within a few back to
        // where it rose from) every 2.5 s, longer than the cooldown, while between the bursts we
        // send 1.015x what the link carries: the floor creeps ~15 ms/s, too gently for the trend
        // (upstream calls only the bursts). Every burst comes back to where it rose from, so
        // against the window's low each one is a stall and the queue grows uncalled. Against the
        // lowest delay of the last FLOOR_HORIZON_MS, the second has not come back (~37 ms above
        // it, the collapse level is 20): overuse. Where upstream does not see the bursts either
        // (33 ms groups), there is nothing the patch could hide.
        let (cycle_ms, jump_ms) = (2_500.0, 80.0);
        let mut called_by_upstream = 0;
        for spacing in SPACINGS {
            let run = |upstream_only: bool| {
                let mut e = estimator(upstream_only);
                let mut f = Feed::every(spacing);
                f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
                let (start, start_send) = (f.arrival_ms, f.send_ms);
                let per_cycle = (cycle_ms / spacing).round() as u32;
                let mut to_drain: f64 = 0.0;
                let mut n = 0u32;
                while f.send_ms < start_send + 4.0 * cycle_ms {
                    let burst = n % per_cycle == 0;
                    n += 1;
                    let service = if burst {
                        to_drain = jump_ms;
                        spacing + jump_ms
                    } else if to_drain > 0.0 {
                        let d = to_drain.min(0.9 * spacing);
                        to_drain -= d;
                        spacing - d
                    } else {
                        spacing * 1.015
                    };
                    let until = f.send_ms + spacing;
                    f.run(&mut e, until, service, |_| BASE_DELAY_MS);
                }
                (f.first_overuse(start).map(|t| t - start), e.stalls_ignored)
            };
            let (up, _) = run(true);
            let (pat, ignored) = run(false);
            println!(
                "{spacing} ms groups, a burst every 2.5 s on a creeping floor: overuse after \
                 {up:?} ms upstream, {pat:?} ms patched, {ignored} ignored"
            );
            if up.is_none() {
                continue;
            }
            called_by_upstream += 1;
            let pat = pat.unwrap_or_else(|| panic!("{spacing} ms groups: never called"));
            assert!(
                pat <= 2.0 * cycle_ms + STALL_MAX_HOLD_MS + 2.0 * spacing,
                "{spacing} ms groups: called after {pat:.0} ms"
            );
        }
        assert!(called_by_upstream >= 3, "upstream calls the bursts");
    }

    #[test]
    fn afklink_a_steep_queue_right_behind_an_ignored_stall_is_called_within_the_hold() {
        // The stall is ignored while the trend is still above the threshold, and a 2-3x queue
        // starts at once: upstream would still be overusing, but no new signal comes while the
        // trend is not rising. The episode's re-check judges the queue once it leaves the
        // floor (without it, a 3x queue reached 267 ms before it was called, 400 ms in).
        for spacing in [16.7, 20.8, 33.0] {
            for ramp in [false, true] {
                for start_after in [0.0, 60.0] {
                    for ratio in [2.0, 3.0] {
                        let case =
                            format!("{spacing} ms, ramp {ramp}, +{start_after} ms, {ratio}x");
                        let after = queue_after(Some(ramp), spacing, 0.0, start_after, ratio)
                            .unwrap_or_else(|| panic!("{case}: never called"));
                        assert!(
                            after <= STALL_MAX_HOLD_MS + 3.0 * spacing,
                            "{case}: called {after:.0} ms after the queue started"
                        );
                    }
                }
            }
        }
    }

    /// Overuse onsets of upstream and of the patched build on a path of one group per `spacing`
    /// ms, `service` ms of link time per group and `delay`, and the stalls the patch ignored.
    fn onsets_both(spacing: f64, service: f64, delay: impl Fn(f64) -> f64) -> (usize, usize, u64) {
        let (mut up, mut e) = (estimator(true), estimator(false));
        let (mut fu, mut fp) = (Feed::every(spacing), Feed::every(spacing));
        fu.run(&mut up, 6_000.0, service, &delay);
        fp.run(&mut e, 6_000.0, service, &delay);
        (
            fu.overuse_onsets().len(),
            fp.overuse_onsets().len(),
            e.stalls_ignored,
        )
    }

    #[test]
    fn afklink_a_small_stall_in_one_step_is_ignored_and_a_small_ramp_is_not() {
        // STALL_ONE_STEP_SHARE: +22 ms held for 80 ms is under STALL_MIN_PEAK_MS, but it came in
        // one step, which no queue of ours does (the pacer spreads a frame over many groups):
        // ignored, where upstream calls it overuse. The same +22 ms reached in four steps over
        // the 80 ms is a small queue: overuse, as upstream. Four offsets within a group each.
        for k in 0..4u32 {
            let at = 3_000.0 + GROUP_MS * f64::from(k) / 4.0;
            let step = |s: f64| {
                BASE_DELAY_MS
                    + if (at..at + 80.0).contains(&s) {
                        22.0
                    } else {
                        0.0
                    }
            };
            let ramp = |s: f64| {
                let into = s - at;
                BASE_DELAY_MS
                    + if (0.0..80.0).contains(&into) {
                        5.5 * (1.0 + (into / 20.0).floor())
                    } else {
                        0.0
                    }
            };
            let (up, pat, ignored) = onsets_both(GROUP_MS, FAST_SERVICE_MS, step);
            assert!(up > 0, "+{k}/4: upstream calls the one-step stall");
            assert!(
                pat == 0 && ignored > 0,
                "+{k}/4: the one-step stall, {pat} onsets"
            );
            let (up, pat, ignored) = onsets_both(GROUP_MS, FAST_SERVICE_MS, ramp);
            assert!(up > 0, "+{k}/4: upstream calls the ramp");
            assert!(
                pat > 0 && ignored == 0,
                "+{k}/4: the four-step ramp, {pat} onsets, {ignored} ignored"
            );
        }
    }

    #[test]
    fn afklink_a_stall_on_a_link_without_room_is_overuse_on_its_falling_edge() {
        // STALL_MIN_FALL_STEEPNESS: a ramp of +60 ms over 80 ms at 16.7 ms groups, which the trend
        // first sees on its falling edge. Its backlog drains at the link's room over our rate:
        // at 5 ms per ms (a link of 6x our rate) it reads as a stall and is ignored; at 1 ms per
        // ms (2x) it drains as a keyframe's queue at a narrow link does and is called, as
        // upstream calls it (`wifi-0924-4m`: 31.8 queue drops a run without the gate, 23.4 with
        // it). Four offsets within a group each.
        let spacing = 16.7;
        let mut called = 0;
        for k in 0..4u32 {
            let at = 3_000.0 + spacing * f64::from(k) / 4.0;
            let fast = onsets_both(spacing, spacing / 6.0, sized_stall(true, at, 60.0, 80.0));
            assert!(fast.0 > 0, "+{k}/4: upstream calls the stall");
            assert_eq!(fast.1, 0, "+{k}/4: draining at 5 ms/ms, overuse");
            let slow = onsets_both(spacing, spacing / 2.0, sized_stall(true, at, 60.0, 80.0));
            if slow.1 > 0 {
                called += 1;
            }
        }
        assert!(
            called >= 2,
            "draining at 1 ms/ms, called at {called} of 4 offsets"
        );
    }

    #[test]
    fn afklink_a_gentle_queue_on_a_jittery_path_is_called_within_the_hold() {
        // 1.1-1.3x on a path with 5-20 ms of jitter. On a quiet path such a rise is too gradual
        // for a stall (`afklink_a_queue_at_a_narrowing_link_is_overuse_as_upstream`); with jitter
        // as large as the rise its low point can be a jitter dip, so it can read steep and be
        // held (the review: up to 254 ms after upstream at 5 ms groups). Held, it is called at
        // most the hold later.
        let mut worst = (f64::NEG_INFINITY, String::new());
        for spacing in SPACINGS {
            for jitter in [5.0, 10.0, 20.0] {
                for ratio in [1.1, 1.2, 1.3] {
                    for seed in 1..=5u32 {
                        let mut first = [0.0; 2];
                        for (i, upstream_only) in [true, false].into_iter().enumerate() {
                            let mut e = estimator(upstream_only);
                            let mut f = Feed::every(spacing);
                            f.jitter_ms = jitter;
                            f.rng = seed;
                            f.run(&mut e, 3_000.0, FAST_SERVICE_MS, |_| BASE_DELAY_MS);
                            let at = f.arrival_ms;
                            f.run(&mut e, 10_000.0, spacing * ratio, |_| BASE_DELAY_MS);
                            first[i] =
                                f.first_overuse(at).expect("a growing queue is overuse") - at;
                        }
                        let case =
                            format!("{spacing} ms, {jitter} ms jitter, {ratio}x, seed {seed}");
                        let [u, p] = first;
                        assert!(
                            p <= u + STALL_MAX_HOLD_MS + 2.0 * spacing * ratio,
                            "{case}: upstream {u:.0} ms, patched {p:.0} ms"
                        );
                        if p - u > worst.0 {
                            worst = (p - u, case);
                        }
                    }
                }
            }
        }
        println!(
            "a gentle queue on a jittery path: called at most {:.0} ms after upstream ({})",
            worst.0, worst.1
        );
    }
}
