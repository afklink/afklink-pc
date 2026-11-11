//! libwebrtc's `FrameDropper`, ported exactly.
//!
//! ## Why a port
//!
//! Home-grown versions of this component fail in ways only visible on real links: a byte credit
//! that amplifies (12× fewer frames, 28× larger, more bytes overall), an admission gate with an
//! inverted sign, a produced-versus-drained ratio measured against a budget derived from the very
//! estimate it tries to correct. libwebrtc's is about 270 lines of readable C++ with published
//! constants and known behaviour, so this is a transliteration, not an adaptation: the constants,
//! the filter bases, the order of operations inside `update_ratio`, and the two odd-looking
//! `update_base` calls around a single `apply` are as in
//! `modules/video_coding/utility/frame_dropper.cc`. Where the C++ looks wrong it is reproduced
//! anyway and noted.
//!
//! ## What it measures
//!
//! A leaky bucket in *bits*. Encoded frames fill it; each frame the capturer offers drains one
//! frame's worth of the allowance. Above half a second of allowance the producer is outrunning what
//! the link was given, by conservation and with no estimate anywhere in the arithmetic. How it
//! differs from a produced-over-sent ratio in one 200 ms window is on [`FrameDropper`].
//!
//! ## The encoder's brake
//!
//! Asked for 1000 kbps on continuously panning content, OpenH264 produces 4949 (the bench in
//! `afklink-encode`), whatever the quantiser ceiling between 37 and H.264's maximum of 51, and its
//! own frame skip is broken (26 to 46 skips out of 46), so nothing else enforces the rate.
//! libwebrtc runs this component between capture and encode in `VideoStreamEncoder` for that
//! reason. It is a **duty cycle**, not a gate: `drop_frame` alternates keeps and drops to hold a
//! ratio, its longest run bounded (tested at three frames), so output never stops. Dropping a
//! fraction of frames cuts the byte rate by that fraction: on decorrelated data bytes per frame fit
//! `interval^0.013 ± 0.34`.
//!
//! The ladder reads [`FrameDropper::drop_ratio`] as its network signal; nothing here gates capture.

// Exact float comparison is deliberate here and an epsilon would be a behaviour change, not a
// tidy-up. Two places rely on it:
//
//   * `ExpFilter::UNDEFINED` is a sentinel, assigned as exactly -1.0 and compared as exactly -1.0,
//     in both of its roles (an unset filter and an absent maximum). `FrameDropper::fill` asks
//     `!= UNDEFINED` to mean "I have never seen a delta frame", and an epsilon there would make a
//     genuine filtered value of -1.0 ± ε indistinguishable from "unset".
//   * `exp == 1.0` is libwebrtc's own branch. The exponent is a literal at every call site, and the
//     branch exists to skip a `powf` — replacing the test changes which arithmetic runs.
//
// The tests compare against 0.0, which is exactly representable and reached by exact assignment.
#![allow(clippy::float_cmp)]

/// `rtc::ExpFilter`, from `rtc_base/numerics/exp_filter.{h,cc}`.
///
/// An exponential filter with two properties that are load-bearing for `FrameDropper` and easy to
/// lose in a rewrite. First, it is *undefined* until the first sample rather than starting at
/// zero, and the first sample is taken verbatim — which is why `FrameDropper::fill` can ask
/// `delta_frame_size_avg_kbits.filtered() != UNDEFINED` to mean "I have never seen a delta frame".
/// Second, `apply` takes an exponent, so one call can stand for several intervals.
#[derive(Debug, Clone, Copy)]
struct ExpFilter {
    alpha: f32,
    filtered: f32,
    max: f32,
}

impl ExpFilter {
    /// `ExpFilter::kValueUndefined`. A sentinel rather than an `Option` because it is also the
    /// "no maximum" value of `max`, and the C++ compares against it directly in both roles.
    const UNDEFINED: f32 = -1.0;

    fn new(alpha: f32) -> Self {
        Self {
            alpha,
            filtered: Self::UNDEFINED,
            max: Self::UNDEFINED,
        }
    }

    fn with_max(alpha: f32, max: f32) -> Self {
        Self {
            alpha,
            filtered: Self::UNDEFINED,
            max,
        }
    }

    fn reset(&mut self, alpha: f32) {
        self.alpha = alpha;
        self.filtered = Self::UNDEFINED;
    }

    fn apply(&mut self, exp: f32, sample: f32) -> f32 {
        if self.filtered == Self::UNDEFINED {
            self.filtered = sample;
        } else if exp == 1.0 {
            self.filtered = self.alpha * self.filtered + (1.0 - self.alpha) * sample;
        } else {
            let alpha = self.alpha.powf(exp);
            self.filtered = alpha * self.filtered + (1.0 - alpha) * sample;
        }
        if self.max != Self::UNDEFINED && self.filtered > self.max {
            self.filtered = self.max;
        }
        self.filtered
    }

    fn filtered(&self) -> f32 {
        self.filtered
    }

    fn update_base(&mut self, alpha: f32) {
        self.alpha = alpha;
    }
}

/* ── the constants, from frame_dropper.cc's anonymous namespace ──────────────────────────────── */

const DEFAULT_FRAME_SIZE_ALPHA: f32 = 0.9;
const DEFAULT_KEY_FRAME_RATIO_ALPHA: f32 = 0.99;
/// One keyframe every tenth second at 30 fps.
const DEFAULT_KEY_FRAME_RATIO_VALUE: f32 = 1.0 / 300.0;

const DEFAULT_DROP_RATIO_ALPHA: f32 = 0.9;
/// Also the filter's *maximum*, which bounds `drop_frame`'s computed limit to 24 frames.
const DEFAULT_DROP_RATIO_VALUE: f32 = 0.96;
/// Longest stretch over which frames are continuously dropped.
const DEFAULT_MAX_DROP_DURATION_SECS: f32 = 4.0;

const DEFAULT_TARGET_BITRATE_KBPS: f32 = 300.0;
const DEFAULT_INCOMING_FRAME_RATE: f32 = 30.0;
const LEAKY_BUCKET_SIZE_SECONDS: f32 = 0.5;

/// A delta frame bigger than this many times the average delta frame is spread for accumulation.
const LARGE_DELTA_FACTOR: f32 = 3.0;

/// Cap on the accumulator, to prevent excessive drops. In seconds of target bitrate.
const ACCUMULATOR_CAP_BUFFER_SIZE_SECS: f32 = 3.0;

/// The bit bucket. Against produced bits over bits that left the socket in one 200 ms window, it
/// differs in four details:
///
/// | | the window ratio | this |
/// |---|---|---|
/// | integration | one 200 ms window | 0.5 s of allowance, so a gap after a burst pays it back |
/// | keyframes | excluded from the numerator, so an IDR is invisible | spread over `max(0.5·fps, 5)` frames, so it is counted where it was actually spent |
/// | large P-frames | charged whole to one window | above `3×` the filtered mean, spread the same way |
/// | debt ceiling | none | 3 s of target, so a burst cannot create an unpayable debt |
///
/// The third row is "after a still moment, sudden motion lags": the first big frame after a quiet
/// stretch is a large delta frame, and charging it whole to a 200 ms window reads as a collapse.
///
/// Units throughout: `accumulator` and every `*_kbits` quantity are **kilobits**; `target_bitrate`
/// is **kilobits per second**; so `target_bitrate / input_framerate` is kilobits per frame and the
/// subtraction in [`Self::leak`] is dimensionally sound. Getting this wrong by a factor of 1000 is
/// the obvious way to port this file incorrectly, so the unit is named on every field.
#[derive(Debug, Clone)]
pub struct FrameDropper {
    /// Fraction of frames that are keyframes. Drives how widely a keyframe is spread.
    key_frame_ratio: ExpFilter,
    /// Filtered size of a delta frame, kilobits. `UNDEFINED` until the first delta frame.
    delta_frame_size_avg_kbits: ExpFilter,
    /// The smoothed duty cycle: what fraction of frames would have to be dropped to hold the
    /// allowance. **This is the reading used for control.** Capped at 0.96 by its own filter.
    drop_ratio: ExpFilter,
    enabled: bool,
    max_drop_duration_secs: f32,
    /// Bucket level, kilobits.
    accumulator: f32,
    /// Half a second of allowance, kilobits. Above this, production is outrunning the link.
    accumulator_max: f32,
    /// The allowance, kbps. Negative means unlimited, as in the C++.
    target_bitrate: f32,
    /// Frames per second the capturer is offering.
    incoming_frame_rate: f32,
    large_frame_accumulation_count: i32,
    /// Kilobits of a spread frame still to be charged, per remaining frame.
    large_frame_accumulation_chunk_size: f32,
    large_frame_accumulation_spread: f32,
    drop_next: bool,
    drop_count: i32,
    was_below_max: bool,
}

impl Default for FrameDropper {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDropper {
    pub fn new() -> Self {
        let mut d = Self {
            key_frame_ratio: ExpFilter::new(DEFAULT_KEY_FRAME_RATIO_ALPHA),
            delta_frame_size_avg_kbits: ExpFilter::new(DEFAULT_FRAME_SIZE_ALPHA),
            drop_ratio: ExpFilter::with_max(DEFAULT_DROP_RATIO_ALPHA, DEFAULT_DROP_RATIO_VALUE),
            enabled: true,
            max_drop_duration_secs: DEFAULT_MAX_DROP_DURATION_SECS,
            accumulator: 0.0,
            accumulator_max: 0.0,
            target_bitrate: 0.0,
            incoming_frame_rate: 0.0,
            large_frame_accumulation_count: 0,
            large_frame_accumulation_chunk_size: 0.0,
            large_frame_accumulation_spread: 0.0,
            drop_next: false,
            drop_count: 0,
            was_below_max: true,
        };
        d.reset();
        d
    }

    pub fn reset(&mut self) {
        self.key_frame_ratio.reset(DEFAULT_KEY_FRAME_RATIO_ALPHA);
        self.key_frame_ratio
            .apply(1.0, DEFAULT_KEY_FRAME_RATIO_VALUE);
        self.delta_frame_size_avg_kbits
            .reset(DEFAULT_FRAME_SIZE_ALPHA);

        self.accumulator = 0.0;
        self.accumulator_max = DEFAULT_TARGET_BITRATE_KBPS / 2.0;
        self.target_bitrate = DEFAULT_TARGET_BITRATE_KBPS;
        self.incoming_frame_rate = DEFAULT_INCOMING_FRAME_RATE;

        self.large_frame_accumulation_count = 0;
        self.large_frame_accumulation_chunk_size = 0.0;
        self.large_frame_accumulation_spread = 0.5 * DEFAULT_INCOMING_FRAME_RATE;

        self.drop_next = false;
        self.drop_ratio.reset(0.9);
        self.drop_ratio.apply(0.0, 0.0);
        self.drop_count = 0;
        self.was_below_max = true;
    }

    /// Charge one encoded frame to the bucket.
    ///
    /// `delta_frame` is `!is_keyframe`, matching the C++ argument. Keyframes, and delta frames more
    /// than [`LARGE_DELTA_FACTOR`] times the filtered mean, are *spread*: their cost is divided
    /// over the next several frames instead of landing in one instant, so a keyframe cannot move a
    /// rung on an otherwise idle desktop.
    pub fn fill(&mut self, framesize_bytes: usize, delta_frame: bool) {
        if !self.enabled {
            return;
        }
        // Not a rate: kilobits, hence 8/1000 and not 8/1024.
        let mut framesize_kbits = 8.0 * framesize_bytes as f32 / 1000.0;
        if !delta_frame {
            self.key_frame_ratio.apply(1.0, 1.0);
            // Do not spread if we are already spreading, or we risk dropping bits that need
            // accumulation. Given the spread is computed from the keyframe ratio, this should not
            // normally happen.
            if self.large_frame_accumulation_count == 0 {
                if self.key_frame_ratio.filtered() > 1e-5
                    && 1.0 / self.key_frame_ratio.filtered() < self.large_frame_accumulation_spread
                {
                    self.large_frame_accumulation_count =
                        (1.0 / self.key_frame_ratio.filtered() + 0.5) as i32;
                } else {
                    self.large_frame_accumulation_count =
                        (self.large_frame_accumulation_spread + 0.5) as i32;
                }
                self.large_frame_accumulation_chunk_size =
                    framesize_kbits / self.large_frame_accumulation_count as f32;
                framesize_kbits = 0.0;
            }
        } else {
            // An unusually large delta frame is spread the same way.
            if self.delta_frame_size_avg_kbits.filtered() != ExpFilter::UNDEFINED
                && framesize_kbits > LARGE_DELTA_FACTOR * self.delta_frame_size_avg_kbits.filtered()
                && self.large_frame_accumulation_count == 0
            {
                self.large_frame_accumulation_count =
                    (self.large_frame_accumulation_spread + 0.5) as i32;
                self.large_frame_accumulation_chunk_size =
                    framesize_kbits / self.large_frame_accumulation_count as f32;
                framesize_kbits = 0.0;
            } else {
                self.delta_frame_size_avg_kbits.apply(1.0, framesize_kbits);
            }
            self.key_frame_ratio.apply(1.0, 0.0);
        }
        self.accumulator += framesize_kbits;
        self.cap_accumulator();
    }

    /// Drain one frame's worth of the allowance.
    ///
    /// Called **once per frame the capturer offers**, with the rate at which those frames are
    /// arriving. That is what makes the drain per wall-clock second equal the allowance regardless
    /// of how many frames were encoded: each call removes `target / input_framerate`, and there are
    /// `input_framerate` calls a second.
    ///
    /// Calling it once per *encoded* frame instead would be the classic mistake — the bucket would
    /// then drain more slowly exactly when the encoder is falling behind, which is when it needs to
    /// drain at full rate.
    pub fn leak(&mut self, input_framerate: u32) {
        if !self.enabled {
            return;
        }
        if input_framerate < 1 {
            return;
        }
        if self.target_bitrate < 0.0 {
            return;
        }
        let fps = input_framerate as f32;
        // Lower bound on the spread, so a 2 fps screen does not spread a keyframe over one frame.
        self.large_frame_accumulation_spread = (0.5 * fps).max(5.0);
        let mut expected_bits_per_frame = self.target_bitrate / fps;
        if self.large_frame_accumulation_count > 0 {
            expected_bits_per_frame -= self.large_frame_accumulation_chunk_size;
            self.large_frame_accumulation_count -= 1;
        }
        self.accumulator -= expected_bits_per_frame;
        if self.accumulator < 0.0 {
            self.accumulator = 0.0;
        }
        self.update_ratio();
    }

    fn update_ratio(&mut self) {
        if self.accumulator > 1.3 * self.accumulator_max {
            // Too far above the maximum: react faster. This base applies to the single `apply`
            // below and is then put back, which is why both calls are here.
            self.drop_ratio.update_base(0.8);
        } else {
            self.drop_ratio.update_base(0.9);
        }
        if self.accumulator > self.accumulator_max {
            // Above the maximum, so a frame should ideally be dropped. Raise the ratio and drop
            // later rather than now.
            if self.was_below_max {
                self.drop_next = true;
            }
            self.drop_ratio.apply(1.0, 1.0);
            self.drop_ratio.update_base(0.9);
        } else {
            self.drop_ratio.apply(1.0, 0.0);
        }
        self.was_below_max = self.accumulator < self.accumulator_max;
    }

    /// libwebrtc's actuator, ported for checkability. **Not used for control here** — see the
    /// module documentation. It spreads the drops implied by [`Self::drop_ratio`] over time rather
    /// than dropping a run of consecutive frames.
    pub fn drop_frame(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        if self.drop_next {
            self.drop_next = false;
            self.drop_count = 0;
        }

        let filtered = self.drop_ratio.filtered();
        if filtered >= 0.5 {
            // Drops per keep. `limit` is how many frames to drop between kept frames.
            let mut denom = 1.0 - filtered;
            if denom < 1e-5 {
                denom = 1e-5;
            }
            let mut limit = (1.0 / denom - 1.0 + 0.5) as i32;
            // Bound the run of dropped frames by frame rate and window size.
            let max_limit = (self.incoming_frame_rate * self.max_drop_duration_secs) as i32;
            if limit > max_limit {
                limit = max_limit;
            }
            if self.drop_count < 0 {
                self.drop_count = -self.drop_count;
            }
            if self.drop_count < limit {
                self.drop_count += 1;
                return true;
            }
            self.drop_count = 0;
            return false;
        } else if filtered > 0.0 && filtered < 0.5 {
            // Keeps per drop. `limit` and `drop_count` are both negative in this branch.
            let mut denom = filtered;
            if denom < 1e-5 {
                denom = 1e-5;
            }
            let limit = -((1.0 / denom - 1.0 + 0.5) as i32);
            if self.drop_count > 0 {
                self.drop_count = -self.drop_count;
            }
            if self.drop_count > limit {
                if self.drop_count == 0 {
                    self.drop_count -= 1;
                    return true;
                }
                self.drop_count -= 1;
                return false;
            }
            self.drop_count = 0;
            return false;
        }
        self.drop_count = 0;
        false
    }

    /// Set the allowance and the offered frame rate.
    ///
    /// `bitrate` is this tree's own budget in kbps, the one deliberate deviation from the C++:
    /// libwebrtc passes the loss-based target from goog-cc, and here the
    /// equivalent number is what the ladder decided to spend. Negative means unlimited.
    pub fn set_rates(&mut self, bitrate: f32, incoming_frame_rate: f32) {
        self.accumulator_max = bitrate * LEAKY_BUCKET_SIZE_SECONDS;
        if self.target_bitrate > 0.0
            && bitrate < self.target_bitrate
            && self.accumulator > self.accumulator_max
        {
            // Rescale the level when the maximum shrinks, so a bucket that was 80% full of a large
            // allowance does not read as overflowing a small one.
            //
            // The C++ writes this as `accumulator_ = bitrate / target_bitrate_ * accumulator_`.
            // Multiplication is commutative in IEEE 754 for the same pair of operands, so this
            // form is bit-identical and not a deviation.
            self.accumulator *= bitrate / self.target_bitrate;
        }
        self.target_bitrate = bitrate;
        self.cap_accumulator();
        self.incoming_frame_rate = incoming_frame_rate;
    }

    /// The smoothed duty cycle, 0.0 to 0.96.
    ///
    /// Zero means production fits the allowance. Rising means it does not.
    ///
    /// ## It is proportional because the loop is closed, and it was not always
    ///
    /// This number is the fraction of frames that must disappear for production to fit, and it is
    /// that *only* while [`Self::drop_frame`]'s answer is obeyed: a dropped frame is never encoded,
    /// so it is never filled, and the loop settles at the true excess. At 1.5× the allowance it
    /// converges near 0.33.
    ///
    /// The encode loop obeys it as of the commit that gave the encoder back a brake. For one
    /// commit before that it did not, and the difference is worth keeping in view because the
    /// number means something different in each case: open, `update_ratio` applies a 1.0 sample on
    /// every leak for as long as the bucket is above its maximum, so sustained overproduction
    /// **saturates** this at its 0.96 cap instead of scaling. That behaviour is still pinned by
    /// `sustained_overproduction_saturates_in_an_open_loop`, because anything that reads this
    /// without dropping — a replay, a future diagnostic — is back in the open case.
    ///
    /// The unsmoothed, always-proportional companion is [`Self::fullness`].
    pub fn drop_ratio(&self) -> f32 {
        let f = self.drop_ratio.filtered();
        if f == ExpFilter::UNDEFINED {
            0.0
        } else {
            f
        }
    }

    /// How full the bucket is, as a multiple of half a second of allowance.
    ///
    /// Above 1.0, production has outrun the link within the last half second. Reported alongside
    /// [`Self::drop_ratio`] because it is the unsmoothed quantity: it crosses immediately where the
    /// ratio takes a few frames, which is the difference between noticing a burst and noticing a
    /// trend.
    pub fn fullness(&self) -> f32 {
        if self.accumulator_max <= 0.0 {
            return 0.0;
        }
        self.accumulator / self.accumulator_max
    }

    /// Bucket level in kilobits, for the log.
    pub fn accumulator_kbits(&self) -> f32 {
        self.accumulator
    }

    /// Don't let the bucket grow beyond a few seconds of target.
    ///
    /// The C++ calls this "a temporary fix for screencasting where very large frames from the
    /// encoder will cause very slow response (too many frame drops)", with a TODO asking whether
    /// it is still needed now that large delta frames are spread. Screencasting is exactly what
    /// this project does, so it stays.
    fn cap_accumulator(&mut self) {
        let max_accumulator = self.target_bitrate * ACCUMULATOR_CAP_BUFFER_SIZE_SECS;
        if self.accumulator > max_accumulator {
            self.accumulator = max_accumulator;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes per frame that exactly spends a budget at a frame rate.
    fn bytes_for(kbps: f32, fps: f32) -> usize {
        (kbps * 1000.0 / 8.0 / fps) as usize
    }

    /// Run `seconds` of a steady state: `fps` frames a second, each `bytes` big.
    fn run(d: &mut FrameDropper, seconds: u32, fps: u32, bytes: usize) {
        for _ in 0..(seconds * fps) {
            d.leak(fps);
            d.fill(bytes, true);
        }
    }

    /// The property the whole component exists for: production that fits the allowance is not
    /// flagged, however long it runs.
    ///
    /// This is also a falsification criterion for the port, stated as a test: if a
    /// well-behaved producer makes the ratio rise, the component would cause descents on a healthy
    /// link and must not be wired to the ladder.
    #[test]
    fn production_that_fits_the_allowance_is_never_flagged() {
        let mut d = FrameDropper::new();
        d.set_rates(4000.0, 30.0);
        run(&mut d, 20, 30, bytes_for(4000.0, 30.0));
        assert_eq!(d.drop_ratio(), 0.0, "fullness was {}", d.fullness());
        assert!(d.fullness() < 1.0);
    }

    /// A still screen is the case that breaks a naive version of this signal. The frames are
    /// a few hundred bytes whatever the budget is, so the bucket must stay empty.
    #[test]
    fn a_still_screen_does_not_look_like_congestion() {
        let mut d = FrameDropper::new();
        // Measured from a recorded static-desktop session: 5 fps, ~300 bytes a frame, against a
        // budget in the hundreds of kbps.
        d.set_rates(800.0, 5.0);
        run(&mut d, 60, 5, 300);
        assert_eq!(d.drop_ratio(), 0.0);
        // Not zero: `run` ends on a `fill`, so the bucket holds the last frame until the next leak. The invariant is that it does not *integrate* — after a
        // minute it holds one frame, not sixty.
        assert!(
            d.accumulator_kbits() <= 8.0 * 300.0 / 1000.0,
            "a minute of still screen accumulated {} kbits",
            d.accumulator_kbits()
        );
    }

    /// Sustained overproduction must be detected, and detected quickly enough to matter against a
    /// one-second latency budget.
    #[test]
    fn sustained_overproduction_is_detected_within_the_latency_budget() {
        let mut d = FrameDropper::new();
        d.set_rates(1000.0, 30.0);
        // Twice the allowance.
        let bytes = bytes_for(2000.0, 30.0);
        let mut frames_until_flagged = None;
        for n in 1..=90 {
            d.leak(30);
            d.fill(bytes, true);
            if frames_until_flagged.is_none() && d.drop_ratio() > 0.0 {
                frames_until_flagged = Some(n);
            }
        }
        let n = frames_until_flagged.expect("twice the allowance must be noticed");
        // 30 fps, so 30 frames is one second. Half a second of allowance has to accumulate first,
        // which at twice the rate takes half a second.
        assert!(n <= 30, "took {n} frames to notice twice the allowance");
        // And it keeps saying so rather than decaying back.
        assert!(d.drop_ratio() > 0.4, "ratio settled at {}", d.drop_ratio());
    }

    /// The debt ceiling. Without it a burst can put the bucket so far into deficit that the
    /// component keeps flagging long after the burst is over.
    ///
    /// A falsification criterion for the port, stated as a test: the port fails if it cannot bound
    /// the accumulator below 3 s of target on forced-budget calibration recordings.
    #[test]
    fn a_burst_cannot_create_an_unpayable_debt() {
        let mut d = FrameDropper::new();
        d.set_rates(1000.0, 30.0);
        // Twenty frames of a megabyte each: far beyond anything the encoder can really produce.
        for _ in 0..20 {
            d.leak(30);
            d.fill(1_000_000, true);
        }
        assert!(
            d.accumulator_kbits() <= 1000.0 * ACCUMULATOR_CAP_BUFFER_SIZE_SECS + 1.0,
            "accumulator reached {} kbits, cap is {}",
            d.accumulator_kbits(),
            1000.0 * ACCUMULATOR_CAP_BUFFER_SIZE_SECS
        );
        // And it recovers in about the cap's worth of time once production stops, rather than
        // taking minutes.
        for _ in 0..(30 * 4) {
            d.leak(30);
        }
        assert_eq!(d.accumulator_kbits(), 0.0);
    }

    /// The row that matters for "after a still moment, sudden motion lags": one large frame must
    /// not read as a link collapse.
    #[test]
    fn a_single_large_frame_is_spread_rather_than_charged_at_once() {
        let mut d = FrameDropper::new();
        d.set_rates(2000.0, 30.0);
        let ordinary = bytes_for(2000.0, 30.0);
        // Establish the mean of a delta frame.
        run(&mut d, 2, 30, ordinary);
        let before = d.accumulator_kbits();

        // One frame ten times the mean — a scroll starting after a still moment.
        d.leak(30);
        d.fill(ordinary * 10, true);
        let after_the_big_frame = d.accumulator_kbits();

        // Charged whole, this frame alone would be 10/30 of a second of allowance = 666 kbits,
        // against a bucket whose maximum is 1000 kbits. Spread, it adds nothing on arrival.
        assert!(
            after_the_big_frame <= before,
            "a large frame landed whole: {before} -> {after_the_big_frame} kbits"
        );
        assert_eq!(
            d.drop_ratio(),
            0.0,
            "a single large frame flagged congestion"
        );
    }

    /// A keyframe is the largest thing this pipeline emits: one per rung change, plus a periodic
    /// backstop every 3000 frames. It must be spread too, and must not on its own move the reading.
    #[test]
    fn a_keyframe_does_not_move_the_reading() {
        let mut d = FrameDropper::new();
        d.set_rates(2000.0, 30.0);
        run(&mut d, 2, 30, bytes_for(2000.0, 30.0));
        assert_eq!(d.drop_ratio(), 0.0);

        // 40 kB, measured from this project's own logs.
        d.leak(30);
        d.fill(40_000, false);
        assert_eq!(
            d.drop_ratio(),
            0.0,
            "a keyframe flagged congestion; fullness {}",
            d.fullness()
        );

        // And the spreading pays it off over the following second rather than forgetting it.
        run(&mut d, 1, 30, bytes_for(2000.0, 30.0));
        assert!(
            d.drop_ratio() < 0.5,
            "ratio after a keyframe: {}",
            d.drop_ratio()
        );
    }

    /// The drain must be a rate in wall-clock time, not per encoded frame. This is the invariant
    /// that makes the bucket mean anything when the encoder is falling behind.
    #[test]
    fn the_drain_is_denominated_in_wall_clock_seconds() {
        for fps in [5u32, 15, 30, 60] {
            let mut d = FrameDropper::new();
            d.set_rates(1000.0, fps as f32);
            // Fill with exactly one second of allowance, then leak for one second.
            d.fill(1000 * 1000 / 8, true);
            let filled = d.accumulator_kbits();
            assert!(
                (filled - 1000.0).abs() < 1.0,
                "filled {filled} kbits at {fps} fps"
            );
            for _ in 0..fps {
                d.leak(fps);
            }
            assert!(
                d.accumulator_kbits() < 1.0,
                "one second of leaking at {fps} fps drained to {} kbits, not ~0",
                d.accumulator_kbits()
            );
        }
    }

    /// Lowering the allowance must not instantly read as overflow. The C++ rescales the level, and
    /// without that a rung change would flag congestion on its own.
    #[test]
    fn shrinking_the_allowance_rescales_the_level_rather_than_overflowing() {
        let mut d = FrameDropper::new();
        d.set_rates(4000.0, 30.0);
        // Fill to just under the maximum of the large allowance: 0.5 s of 4000 = 2000 kbits.
        d.fill(1900 * 1000 / 8, true);
        assert!(d.fullness() < 1.0);

        // The ladder steps down to a quarter of the budget.
        d.set_rates(1000.0, 30.0);
        assert!(
            d.fullness() <= 1.0,
            "a rung change alone put fullness at {}",
            d.fullness()
        );
    }

    /// `drop_frame` spreads its drops instead of dropping a run, which is the property that makes
    /// the ratio a duty cycle rather than a gate. Not used for control, tested because it is what
    /// makes the port checkable against the behaviour it is supposed to reproduce.
    ///
    /// The loop here is **closed**, as it is in libwebrtc: a dropped frame is not encoded, so it is
    /// not filled. Running it open — filling every frame regardless of the answer — saturates the
    /// ratio and produced a 24-frame run, which is what the first version of this test did and why
    /// it failed. That failure was worth having: it is exactly the difference between libwebrtc's
    /// use of this component and ours, and it is pinned separately in
    /// `sustained_overproduction_saturates_in_an_open_loop`.
    #[test]
    fn the_actuator_spreads_drops_instead_of_dropping_a_run() {
        let mut d = FrameDropper::new();
        d.set_rates(1000.0, 30.0);
        // The producer wants 1.5x the allowance, so about a third of the frames have to go.
        let bytes = bytes_for(1500.0, 30.0);
        let mut dropped = 0;
        let mut longest_run = 0;
        let mut run_len = 0;
        for _ in 0..300 {
            d.leak(30);
            if d.drop_frame() {
                dropped += 1;
                run_len += 1;
                longest_run = longest_run.max(run_len);
            } else {
                run_len = 0;
                d.fill(bytes, true);
            }
        }
        // Roughly a third. Loose bounds: the filter is smoothed and the exact count is not the
        // contract — "it converges on the excess instead of saturating" is.
        assert!(
            (45..=165).contains(&dropped),
            "dropped {dropped} of 300 at 1.5x the allowance"
        );
        // And never a long frozen stretch: this project's own circuit breaker froze the picture for
        // 366 ms by discarding 11 consecutive frames, and that report is why this matters.
        assert!(
            longest_run <= 3,
            "longest dropped run was {longest_run} frames"
        );
    }

    /// The measured defect, bounded: an encoder that overshoots its target fivefold, brought back
    /// to the target by dropping frames.
    ///
    /// This is the number the bench in `afklink-encode` produces and cannot fix, because it is a
    /// property of OpenH264 rather than of anything above it: asked for 1000 kbps on continuously
    /// panning content it produces 4949, and the quantiser ceiling changes nothing anywhere between
    /// 37 and H.264's own maximum of 51. `skip_frames(false)` removed the encoder's only
    /// enforcement path — its own frame skip, which is measurably broken — and nothing replaced it.
    ///
    /// So the replacement has to live above the encoder, and this is the arithmetic it must do: if
    /// every frame costs five times its share, keep one frame in five.
    #[test]
    fn an_encoder_that_overshoots_fivefold_is_brought_back_to_its_target() {
        let mut d = FrameDropper::new();
        let allowance = 1_000.0f32;
        d.set_rates(allowance, 30.0);
        // Each frame costs five times its share of the allowance, whatever it is told.
        let bytes = (allowance * 5.0 * 1000.0 / 8.0 / 30.0) as usize;

        let (mut kept, mut delivered_bits) = (0u32, 0f64);
        let seconds = 20;
        for _ in 0..(seconds * 30) {
            d.leak(30);
            if d.drop_frame() {
                continue;
            }
            kept += 1;
            d.fill(bytes, true);
            delivered_bits += bytes as f64 * 8.0;
        }
        let delivered_kbps = delivered_bits / f64::from(seconds) / 1000.0;

        // Within a factor of two of the allowance, from fivefold over. Loose because the filter is
        // smoothed and the bucket is allowed half a second of slack by design; the point is that
        // the overshoot is *bounded* rather than proportional to the encoder's appetite.
        assert!(
            delivered_kbps < f64::from(allowance as u32) * 2.0,
            "delivered {delivered_kbps:.0} kbps against an allowance of {allowance:.0}; \
             the brake is not braking"
        );
        // And it must not do it by stopping: a picture at a few frames a second is its own fault.
        let kept_fps = f64::from(kept) / f64::from(seconds);
        assert!(
            kept_fps >= 4.0,
            "kept only {kept_fps:.1} frames a second; withholding nearly everything is the \
             failure mode every previous gate in this project had"
        );
    }

    /// How this tree actually uses it: nothing is dropped, so the loop never closes.
    ///
    /// The consequence is that the ratio saturates at its 0.96 cap under sustained overproduction
    /// instead of settling at the excess fraction. That is not a defect, but it does mean the
    /// number is an indicator and not a magnitude, and a controller that read 0.96 as "96 percent
    /// too much data" would be wrong. Pinned here so the claim in [`FrameDropper::drop_ratio`]'s
    /// documentation is a test rather than a comment.
    #[test]
    fn sustained_overproduction_saturates_in_an_open_loop() {
        let mut d = FrameDropper::new();
        d.set_rates(1000.0, 30.0);
        // Only 1.2x the allowance — mild, and in a closed loop the ratio would settle near 0.17.
        let bytes = bytes_for(1200.0, 30.0);
        for _ in 0..300 {
            d.leak(30);
            d.fill(bytes, true);
        }
        assert!(
            d.drop_ratio() > 0.9,
            "open loop at 1.2x settled at {} rather than saturating",
            d.drop_ratio()
        );
        // The proportional reading is fullness, and the 3 s cap bounds it: 3 s of target over a
        // 0.5 s bucket is 6.
        assert!(
            d.fullness() > 1.0 && d.fullness() <= 6.0 + 1e-3,
            "fullness was {}",
            d.fullness()
        );
    }

    /// The filter's undefined-until-first-sample behaviour is load-bearing: `fill` uses it to ask
    /// whether it has ever seen a delta frame. A port that initialised it to zero would treat every
    /// first frame as unusually large.
    #[test]
    fn the_filter_is_undefined_until_its_first_sample() {
        let mut f = ExpFilter::new(0.9);
        assert_eq!(f.filtered(), ExpFilter::UNDEFINED);
        // The first sample is taken verbatim, not blended with the sentinel.
        assert_eq!(f.apply(1.0, 42.0), 42.0);
        // The second is blended.
        let second = f.apply(1.0, 0.0);
        assert!((second - 0.9 * 42.0).abs() < 1e-4, "second was {second}");
    }

    /// The drop ratio's filter has a maximum of 0.96, which is what bounds `drop_frame`'s computed
    /// limit to 24 frames. A port that dropped the maximum would allow unbounded runs.
    #[test]
    fn the_drop_ratio_is_capped_so_the_implied_run_is_bounded() {
        let mut d = FrameDropper::new();
        d.set_rates(100.0, 30.0);
        // Hugely over the allowance, for long enough for the filter to saturate.
        for _ in 0..600 {
            d.leak(30);
            d.fill(100_000, true);
        }
        assert!(
            d.drop_ratio() <= DEFAULT_DROP_RATIO_VALUE,
            "ratio reached {}",
            d.drop_ratio()
        );
    }
}
