//! Capture pacing and the encode loop, re-implemented with time injected.
//!
//! ## Why this is a copy, and what the copy is of
//!
//! The production versions live inside a real-time capture callback (`capture/src/wgc.rs`) and a
//! blocking thread function (`core/src/agent.rs`, `encode_loop`), both read `Instant::now()` and
//! both are being edited by others. Neither can be called from virtual time. So the *decisions* are
//! restated here, line for line, with the clock passed in, and each block names the lines it
//! restates. **The first refactor once `agent.rs` is free: extract a pure, time-injected
//! encode-loop core (arrival-rate tracking, deadband, frame dropper, queue gate, keyframe flag)
//! that both `encode_loop` and this module call.** `pace::admit` is already pure and could be
//! imported as soon as `afklink-capture` stops being Windows-only at the crate level.
//!
//! Copied (source lines as of this writing):
//!
//! | here                          | from                                                     |
//! |-------------------------------|----------------------------------------------------------|
//! | [`admit`], [`early_tolerance`], [`MAX_EARLY`] | `capture/src/pace.rs:13,42-81`           |
//! | [`Capturer::on_frame`]        | `capture/src/wgc.rs:150-187` (offered, pace, scale, source) |
//! | [`QUEUE_SKIP_MS`], [`MAX_QUEUE_SKIPS`], [`skip_for_queue`] | `core/src/agent.rs:2226-2247` |
//! | [`HARD_HOLD_MAX`], `HardHold` (the queue guard's hard hold past the breaker's limit) | `core/src/agent.rs`, `HardHold` |
//! | [`FPS_DEADBAND_PCT`]          | `core/src/agent.rs:2254`                                 |
//! | [`EncodeLoop::begin`]         | `core/src/agent.rs:2345-2582` (stale drain, offered window, arrival fps, deadband, `set_target`, dropper `set_rates`/`leak`, keyframe flag and the viewer's requests judged against the keyframe window, queue gate, dropper `drop_frame`, timestamp, encode) |
//! | [`EncodeLoop::complete`]      | `core/src/agent.rs:2583-2704` (counters, dropper `fill`, QP accounting, keyframe bytes, the keyframe's window opened) |
//! | [`Counters`]                  | `core/src/agent.rs:2724-2825` (`SessionCounters`, the fields the control task reads) |
//!
//! The keyframe window itself is not restated: it is `afklink_core::keyframe_window`, the type the
//! agent's encode loop holds.
//!
//! Left out on purpose: the pipeline supervisor (capture/encoder restarts), the heartbeat, the
//! calibration sweep and its per-frame line, the panic catch. None of them decides anything the
//! controller or the link sees in a healthy run.
//!
//! ## What is modelled rather than measured
//!
//! Encode *time*. The real encoder runs and its bytes, quantiser and frame type are the real ones,
//! but how long it took on this machine is not deterministic, and `Feedback::encode_ms` feeds the
//! ladder's `cpu_bound` arm. So virtual encode time is [`EncodeCost`]: a fixed cost plus a cost per
//! megapixel, keyframes dearer — defaults fitted to the agent's logged `encode_ms` (2.4-3.6 ms at
//! 1620x1080). The measured wall time is kept separately for the speed report.

use std::time::{Duration, Instant};

use afklink_core::frame_dropper::FrameDropper;
use afklink_core::keyframe_window::{KeyframeWindow, LinkNow, Verdict, ViewerAsks};
use afklink_core::quality::QualityTarget;
use afklink_core::scale::{fit_within, Scaler};
use afklink_core::traits::Encoder;
use afklink_core::types::{EncodedFrame, Frame};

/// `capture/src/pace.rs:13`.
pub const MAX_EARLY: Duration = Duration::from_millis(4);

/// `capture/src/pace.rs:17-22`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Admit,
    Early,
}

/// `capture/src/pace.rs:42-44`.
#[must_use]
pub fn early_tolerance(interval: Duration) -> Duration {
    (interval / 4).min(MAX_EARLY)
}

/// `capture/src/pace.rs:65-81`, with `Duration` since the start for `Instant`.
#[must_use]
pub fn admit(
    now: Duration,
    next_due: Option<Duration>,
    interval: Duration,
) -> (Admission, Duration) {
    let Some(due) = next_due else {
        return (Admission::Admit, now + interval);
    };
    if now >= due {
        if now - due < interval {
            (Admission::Admit, due + interval)
        } else {
            (Admission::Admit, now + interval)
        }
    } else if due - now <= early_tolerance(interval) {
        (Admission::Admit, due + interval)
    } else {
        (Admission::Early, due)
    }
}

/// What the capture thread does with a frame the OS delivered. `capture/src/wgc.rs:150-187`.
pub struct Capturer {
    scaler: Scaler,
    next_due: Option<Duration>,
}

impl std::fmt::Debug for Capturer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capturer")
            .field("next_due", &self.next_due)
            .finish()
    }
}

impl Default for Capturer {
    fn default() -> Self {
        Self::new()
    }
}

impl Capturer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            scaler: Scaler::new(),
            next_due: None,
        }
    }

    /// Pace, then scale to the rung. `None` when the frame arrived before its slot.
    pub fn on_frame(
        &mut self,
        now: Duration,
        frame: Frame,
        target: &QualityTarget,
    ) -> anyhow::Result<Option<Frame>> {
        target.note_offered();
        let interval = target.min_frame_interval();
        let (decision, due) = admit(now, self.next_due, interval);
        self.next_due = Some(due);
        if decision == Admission::Early {
            target.note_early();
            tracing::trace!(
                at_ms = now.as_secs_f64() * 1e3,
                "capture: frame early for its slot, held back"
            );
            return Ok(None);
        }
        let (width, height) = (frame.width, frame.height);
        target.set_source(width, height);
        let max_h = target.max_h();
        let (w, h) = fit_within(width, height, u32::MAX / 2, max_h);
        // Moved rather than copied when it already fits: the production path copies into an owned
        // buffer here because WGC's buffer is borrowed; ours is owned already.
        let data = if (w, h) == (width, height) {
            frame.data
        } else {
            let mut pixels = Vec::new();
            self.scaler
                .fit_into(&frame.data, width, height, u32::MAX / 2, max_h, &mut pixels)?;
            pixels
        };
        Ok(Some(Frame {
            data,
            width: w,
            height: h,
            timestamp_ms: now.as_millis() as u64,
        }))
    }
}

/// `core/src/agent.rs:2226`.
pub const QUEUE_SKIP_MS: u32 = 150;
/// `core/src/agent.rs:2235`.
pub const MAX_QUEUE_SKIPS: u32 = 6;
/// `core/src/agent.rs:2254`.
pub const FPS_DEADBAND_PCT: u64 = 15;

/// `core/src/agent.rs:2245-2247`.
#[must_use]
pub fn skip_for_queue(queue_age_ms: u32, consecutive_skips: u32, forced_keyframe: bool) -> bool {
    !forced_keyframe && queue_age_ms > QUEUE_SKIP_MS && consecutive_skips < MAX_QUEUE_SKIPS
}

/// `core/src/agent.rs`, `HARD_HOLD_MAX`.
pub const HARD_HOLD_MAX: Duration = Duration::from_secs(1);

/// `core/src/agent.rs`, `HardHold`, in virtual time: past the transport breaker's limit nothing
/// is encoded, until the gauge is back under the breaker's resume level or `HARD_HOLD_MAX` has
/// passed (and then not again until it is back under it).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum HardHold {
    #[default]
    Idle,
    Holding {
        since: Duration,
        withheld: u32,
    },
    GaveUp,
}

impl HardHold {
    /// Whether this frame is withheld. Every transition logged, as the agent does.
    fn step(&mut self, queue_age_ms: u32, now: Duration) -> bool {
        match *self {
            HardHold::Idle => {
                if queue_age_ms > afklink_transport::QUEUE_HARD_LIMIT_MS {
                    *self = HardHold::Holding {
                        since: now,
                        withheld: 1,
                    };
                    tracing::debug!(
                        queue_age_ms,
                        at_ms = now.as_secs_f64() * 1e3,
                        "queue guard: the send queue is past the transport's hard limit; \
                         withholding every frame before encoding until it drains"
                    );
                    true
                } else {
                    false
                }
            }
            HardHold::Holding { since, withheld } => {
                let held = now.saturating_sub(since);
                if queue_age_ms <= afklink_transport::QUEUE_RESUME_MS {
                    *self = HardHold::Idle;
                    tracing::debug!(
                        queue_age_ms,
                        held_ms = held.as_millis() as u64,
                        withheld,
                        "queue guard: hard hold released — the queue drained with nothing encoded \
                         into it"
                    );
                    false
                } else if held >= HARD_HOLD_MAX {
                    *self = HardHold::GaveUp;
                    tracing::debug!(
                        queue_age_ms,
                        held_ms = held.as_millis() as u64,
                        withheld,
                        "queue guard: hard hold gave up with the gauge still past the limit; frames \
                         go to the transport's breaker"
                    );
                    false
                } else {
                    *self = HardHold::Holding {
                        since,
                        withheld: withheld.saturating_add(1),
                    };
                    true
                }
            }
            HardHold::GaveUp => {
                if queue_age_ms <= afklink_transport::QUEUE_RESUME_MS {
                    *self = HardHold::Idle;
                    tracing::debug!(queue_age_ms, "queue guard: the hard hold is armed again");
                }
                false
            }
        }
    }
}

/// The session totals the control task reads. `core/src/agent.rs:2724-2825`, the fields that feed
/// anything, as plain integers because nothing here is shared between threads.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Counters {
    pub frames_captured: u64,
    pub frames_encoded: u64,
    pub frames_dropped_stale: u64,
    pub frames_skipped_encoder: u64,
    pub bytes_sent: u64,
    pub encode_errors: u64,
    pub encode_attempts: u64,
    /// Modelled microseconds. See [`EncodeCost`].
    pub encode_us_total: u64,
    pub encode_us_max: u64,
    pub qp_sum: u64,
    pub qp_samples: u64,
    pub last_keyframe_bytes: u32,
    pub keyframe_bytes_total: u64,
    pub keyframes: u64,
    pub encoded_w: u32,
    pub encoded_h: u32,
    pub frames_dropped_rate: u64,
    pub frames_skipped_queue: u64,
    /// `frames_skipped_drain`: withheld while drain mode was in force.
    pub frames_skipped_drain: u64,
    /// `keyframe_requests_suppressed`: the viewer's PLIs a keyframe already on its way answered.
    pub keyframe_requests_suppressed: u64,
    /// Not in the agent: what the real encoder cost on this machine, for the speed report.
    pub wall_encode_us_total: u64,
}

/// Virtual encode time. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncodeCost {
    pub base: Duration,
    pub per_mpx: Duration,
    pub keyframe_factor: f64,
}

impl Default for EncodeCost {
    /// 1.0 ms + 1.1 ms per megapixel, keyframes 1.8x: 2.9 ms for a 1620x1080 inter frame, which is
    /// the middle of the agent's logged 2.4-3.6 ms on this machine.
    fn default() -> Self {
        Self {
            base: Duration::from_micros(1_000),
            per_mpx: Duration::from_micros(1_100),
            keyframe_factor: 1.8,
        }
    }
}

impl EncodeCost {
    /// Never under a millisecond: the RTP timestamp is the encode start in whole milliseconds
    /// (`agent.rs:2568`), and two frames in one millisecond would share one.
    #[must_use]
    pub fn of(&self, w: u32, h: u32, keyframe: bool) -> Duration {
        let mpx = f64::from(w) * f64::from(h) / 1e6;
        let mut t = self.base.as_secs_f64() + self.per_mpx.as_secs_f64() * mpx;
        if keyframe {
            t *= self.keyframe_factor.max(1.0);
        }
        Duration::from_secs_f64(t).max(Duration::from_millis(1))
    }
}

/// An encode in progress: started at `started`, its result visible at `done_at`.
#[derive(Debug)]
pub struct EncodeJob {
    pub started: Duration,
    pub done_at: Duration,
    /// When the frame this job encodes was captured, for the latency metric.
    pub captured_at: Duration,
    pub result: EncodeResult,
    pub qp: Option<u32>,
    pub modelled_us: u64,
    pub w: u32,
    pub h: u32,
    /// A keyframe was asked of the encoder for this frame (the flag, or a viewer's PLI honoured).
    pub forced: bool,
}

#[derive(Debug)]
pub enum EncodeResult {
    Frame(EncodedFrame),
    /// The encoder declined the frame (`Ok(None)`).
    Declined,
    Failed(String),
}

/// Why [`EncodeLoop::begin`] did not encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withheld {
    /// The send queue was past [`QUEUE_SKIP_MS`].
    Queue,
    /// The frame dropper's bit bucket.
    Rate,
    /// Drain mode: the network path is holding a backlog of ours.
    Drain,
}

/// The encode loop's state. See the module documentation for what each part restates.
pub struct EncodeLoop {
    encoder: Box<dyn Encoder>,
    dropper: FrameDropper,
    cost: EncodeCost,
    offered_window: (Duration, u32),
    offered_fps: u32,
    arrival_fps: f32,
    fps_known: bool,
    committed_fps: u32,
    last_arrival: Option<Duration>,
    queue_skips: u32,
    /// The queue guard's hard hold. See [`HardHold`].
    hard_hold: HardHold,
    /// `pending_kf` in the agent: the transport's breaker, a drain's end, a capture started again,
    /// the viewer's `kf`, consumed by the next frame that reaches the keyframe check.
    pub keyframe_requested: bool,
    /// The window the last keyframe opened, against which the viewer's requests are judged
    /// (`afklink_core::keyframe_window`, the agent's own type).
    kf_window: KeyframeWindow,
    pub counters: Counters,
    source: (u32, u32),
    started_at: Duration,
}

impl std::fmt::Debug for EncodeLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncodeLoop")
            .field("offered_fps", &self.offered_fps)
            .field("committed_fps", &self.committed_fps)
            .field("counters", &self.counters)
            .finish()
    }
}

impl EncodeLoop {
    /// `started_at` is the loop's `start` (`agent.rs:2286`): frame timestamps count from it.
    #[must_use]
    pub fn new(encoder: Box<dyn Encoder>, cost: EncodeCost, started_at: Duration) -> Self {
        Self {
            encoder,
            dropper: FrameDropper::new(),
            cost,
            offered_window: (started_at, 0),
            offered_fps: 0,
            arrival_fps: 0.0,
            fps_known: false,
            committed_fps: 0,
            last_arrival: None,
            queue_skips: 0,
            hard_hold: HardHold::default(),
            keyframe_requested: false,
            kf_window: KeyframeWindow::new(),
            counters: Counters::default(),
            source: (0, 0),
            started_at,
        }
    }

    /// The encoder's quantiser ceiling, for `Feedback::qp_ceiling` (`agent.rs:752`).
    #[must_use]
    pub fn qp_ceiling(&self) -> Option<f32> {
        self.encoder.max_qp().map(|q| q as f32)
    }

    /// Take the newest frame at `now` (`at` on the virtual clock), `offered_now` of them having
    /// arrived since the last take (the rest were stale), and either withhold it or encode it.
    /// `viewer_asks` holds the viewer's PLIs not yet taken. `agent.rs:2345-2582`.
    ///
    /// The encoder is called here, on this machine's clock, and its result is held in the returned
    /// job until the modelled encode time has passed; [`Self::complete`] applies it then, which is
    /// when the agent's counters would have seen it.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self,
        now: Duration,
        at: Instant,
        mut frame: Frame,
        captured_at: Duration,
        offered_now: u32,
        target: &QualityTarget,
        viewer_asks: &ViewerAsks,
    ) -> Result<EncodeJob, Withheld> {
        let offered_now = offered_now.max(1);
        self.counters.frames_captured += u64::from(offered_now);
        self.counters.frames_dropped_stale += u64::from(offered_now - 1);

        // agent.rs:2390-2407: the offered rate over a sliding second.
        let gap = self
            .last_arrival
            .replace(now)
            .map(|prev| now.saturating_sub(prev));
        self.offered_window.1 += offered_now;
        let window = now.saturating_sub(self.offered_window.0);
        if window >= Duration::from_secs(1) {
            let secs = window.as_secs_f32();
            let windowed = self.offered_window.1 as f32 / secs;
            self.offered_fps = windowed.round() as u32;
            self.arrival_fps = if self.fps_known {
                self.arrival_fps.min(windowed)
            } else {
                windowed
            };
            self.fps_known = true;
            self.offered_window = (now, 0);
        }

        // agent.rs:2454-2479: fast to rise, slow to fall, floored at half the rung, deadbanded.
        let rung_fps = target.fps();
        let want_fps = if self.fps_known {
            if let Some(gap) = gap {
                let secs = gap.as_secs_f32().max(0.001);
                self.arrival_fps = self.arrival_fps.max(offered_now as f32 / secs);
            }
            (self.arrival_fps.round() as u32).clamp((rung_fps / 2).max(1), rung_fps)
        } else {
            rung_fps
        };
        if self.committed_fps == 0
            || u64::from(want_fps.abs_diff(self.committed_fps)) * 100
                >= u64::from(self.committed_fps) * FPS_DEADBAND_PCT
        {
            if self.committed_fps != want_fps {
                tracing::trace!(
                    from = self.committed_fps,
                    to = want_fps,
                    rung_fps,
                    arrival_fps = self.arrival_fps,
                    "encoder frame rate committed"
                );
            }
            self.committed_fps = want_fps;
        }
        if let Some(kbps) = target.target_kbps() {
            self.encoder.set_target(kbps, self.committed_fps);
        }

        // agent.rs:2481-2491: the bit bucket's rates and one leak per offered frame.
        if let Some(kbps) = target.target_kbps() {
            self.dropper
                .set_rates(kbps as f32, self.offered_fps.max(1) as f32);
        }
        for _ in 0..offered_now {
            self.dropper.leak(self.offered_fps.max(1));
        }
        target.set_frame_dropper(self.dropper.drop_ratio(), self.dropper.fullness());

        // agent.rs, drain mode: nothing encoded while the path drains, a keyframe request left in
        // its flag for the resume.
        if target.draining() {
            self.counters.frames_skipped_drain += 1;
            tracing::trace!(
                at_ms = now.as_secs_f64() * 1e3,
                "frame withheld: drain mode"
            );
            return Err(Withheld::Drain);
        }

        // agent.rs, the keyframe check: the flag always, the viewer's PLIs as the window judges
        // them.
        let own_keyframe = std::mem::take(&mut self.keyframe_requested);
        let viewer_keyframe = match viewer_asks.take() {
            None => false,
            Some(asked) => match self.kf_window.judge(at, asked, own_keyframe) {
                Verdict::Honour => true,
                Verdict::Suppressed => {
                    self.counters.keyframe_requests_suppressed += u64::from(asked.count);
                    false
                }
                Verdict::Joined => false,
            },
        };
        let forced_keyframe = own_keyframe || viewer_keyframe;
        if forced_keyframe {
            self.encoder.request_keyframe();
            tracing::debug!(
                at_ms = now.as_secs_f64() * 1e3,
                own = own_keyframe,
                viewer = viewer_keyframe,
                "keyframe requested of the encoder"
            );
        }

        // agent.rs, the hard hold before the soft guard; a viewer's keyframe request passes.
        let hard = self.hard_hold.step(target.queue_age_ms(), now);
        if hard && !forced_keyframe {
            self.counters.frames_skipped_queue += 1;
            tracing::trace!(
                queue_age_ms = target.queue_age_ms(),
                "frame withheld: the send queue is past the transport's hard limit"
            );
            return Err(Withheld::Queue);
        }

        // agent.rs:2517-2524.
        if skip_for_queue(target.queue_age_ms(), self.queue_skips, forced_keyframe) {
            self.queue_skips += 1;
            self.counters.frames_skipped_queue += 1;
            tracing::trace!(
                queue_age_ms = target.queue_age_ms(),
                consecutive = self.queue_skips,
                "frame withheld: the send queue is past the latency guard"
            );
            return Err(Withheld::Queue);
        }
        self.queue_skips = 0;

        // agent.rs:2563-2566.
        if !forced_keyframe && self.dropper.drop_frame() {
            self.counters.frames_dropped_rate += 1;
            tracing::trace!(
                drop_ratio = self.dropper.drop_ratio(),
                "frame withheld by the bit bucket"
            );
            return Err(Withheld::Rate);
        }

        // agent.rs:2568-2582.
        frame.timestamp_ms = now.saturating_sub(self.started_at).as_millis() as u64;
        if self.source != (frame.width, frame.height) {
            tracing::debug!(
                from = %format!("{}x{}", self.source.0, self.source.1),
                to = %format!("{}x{}", frame.width, frame.height),
                "encoded size changed"
            );
            self.source = (frame.width, frame.height);
            self.counters.encoded_w = frame.width;
            self.counters.encoded_h = frame.height;
        }
        let wall = Instant::now();
        let result = self.encoder.encode(&frame);
        let wall_us = wall.elapsed().as_micros() as u64;
        self.counters.wall_encode_us_total += wall_us;
        let (result, key) = match result {
            Ok(Some(ef)) => {
                let key = ef.is_keyframe;
                (EncodeResult::Frame(ef), key)
            }
            Ok(None) => (EncodeResult::Declined, false),
            Err(e) => (EncodeResult::Failed(format!("{e:#}")), false),
        };
        // Read now, on the encoder's own state: it reports the frame it just encoded.
        let qp = if matches!(result, EncodeResult::Frame(_)) {
            self.encoder.last_frame_qp()
        } else {
            None
        };
        let modelled = self.cost.of(frame.width, frame.height, key);
        Ok(EncodeJob {
            started: now,
            done_at: now + modelled,
            captured_at,
            result,
            qp,
            modelled_us: modelled.as_micros() as u64,
            w: frame.width,
            h: frame.height,
            forced: forced_keyframe,
        })
    }

    /// Apply a finished encode at `at` on the virtual clock, as the agent does when `encode`
    /// returns; `link` is what a keyframe's window is made of then (`LinkNow::from_gauges`).
    /// `agent.rs:2583-2704`. Returns the frame to hand to the transport.
    pub fn complete(
        &mut self,
        job: EncodeJob,
        at: Instant,
        link: LinkNow,
    ) -> Option<(EncodedFrame, Option<u32>)> {
        self.counters.encode_attempts += 1;
        self.counters.encode_us_total += job.modelled_us;
        self.counters.encode_us_max = self.counters.encode_us_max.max(job.modelled_us);
        match job.result {
            EncodeResult::Frame(ef) => {
                self.counters.frames_encoded += 1;
                self.counters.bytes_sent += ef.data.len() as u64;
                self.dropper.fill(ef.data.len(), !ef.is_keyframe);
                if ef.is_keyframe {
                    self.counters.keyframes += 1;
                    self.counters.last_keyframe_bytes =
                        u32::try_from(ef.data.len()).unwrap_or(u32::MAX);
                    self.counters.keyframe_bytes_total += ef.data.len() as u64;
                    // agent.rs: every keyframe opens the window.
                    let window = self
                        .kf_window
                        .keyframe_sent(at, ef.data.len(), link, job.forced);
                    tracing::debug!(
                        bytes = ef.data.len(),
                        size = %format!("{}x{}", job.w, job.h),
                        forced = job.forced,
                        window_ms = window.len.as_millis() as u64,
                        "keyframe encoded"
                    );
                } else if let Some(qp) = job.qp {
                    self.counters.qp_sum += u64::from(qp);
                    self.counters.qp_samples += 1;
                }
                Some((ef, job.qp))
            }
            EncodeResult::Declined => {
                self.counters.frames_skipped_encoder += 1;
                None
            }
            EncodeResult::Failed(e) => {
                self.counters.encode_errors += 1;
                tracing::warn!("encode error: {e}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{admit, skip_for_queue, Admission, EncodeCost, MAX_QUEUE_SKIPS};
    use std::time::Duration;

    fn us(v: u64) -> Duration {
        Duration::from_micros(v)
    }

    #[test]
    fn the_pacer_is_the_captures_own_arithmetic() {
        // Restates `capture/src/pace.rs`'s own cases: 30 fps on a 60 Hz source takes every
        // other frame, a still screen resyncs from now, and a frame just inside the tolerance
        // keeps the schedule's phase.
        let interval = us(1_000_000 / 30);
        let mut due = None;
        let mut taken = Vec::new();
        for k in 0..20u64 {
            let (d, next) = admit(us(k * 16_667), due, interval);
            due = Some(next);
            taken.push(d == Admission::Admit);
        }
        for (k, ok) in taken.iter().enumerate() {
            assert_eq!(*ok, k % 2 == 0, "frame {k}");
        }
        let (d, next) = admit(Duration::from_secs(10), due, interval);
        assert_eq!(d, Admission::Admit);
        assert_eq!(next, Duration::from_secs(10) + interval);
        let slot = us(100_000);
        assert_eq!(
            admit(slot - Duration::from_millis(4), Some(slot), us(16_666)),
            (Admission::Admit, slot + us(16_666))
        );
    }

    #[test]
    fn the_queue_gate_is_the_agents() {
        assert!(skip_for_queue(160, 0, false));
        assert!(!skip_for_queue(140, 0, false));
        assert!(!skip_for_queue(160, 0, true));
        assert!(!skip_for_queue(160, MAX_QUEUE_SKIPS, false));
    }

    #[test]
    fn modelled_encode_time_matches_the_logged_range() {
        let c = EncodeCost::default();
        let inter = c.of(1620, 1080, false);
        assert!(
            (Duration::from_micros(2_400)..=Duration::from_micros(3_600)).contains(&inter),
            "{inter:?}"
        );
        assert!(c.of(1620, 1080, true) > inter);
        // Never under a millisecond, so two frames cannot share an RTP timestamp.
        let free = EncodeCost {
            base: Duration::ZERO,
            per_mpx: Duration::ZERO,
            keyframe_factor: 1.0,
        };
        assert_eq!(free.of(16, 16, false), Duration::from_millis(1));
    }
}
