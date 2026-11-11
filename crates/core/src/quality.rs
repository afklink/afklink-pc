//! Choosing what to send: resolution, frame rate, and the bitrate they imply.
//!
//! The resolution→bitrate table and quality multipliers are RustDesk's (`libs/scrap`,
//! `common/codec.rs`: `base_bitrate`, `BR_BEST`/`BR_BALANCED`/`BR_SPEED`), tuned for H.264 over
//! a remote desktop, where most of the screen is still and legible text is what matters. WebRTC's
//! simulcast minimums and LiveKit's screen-share presets budget for camera or full-motion video.
//!
//! ## Two controllers
//!
//! - **rate**: the link estimate, less a margin, less a pushback for the queue, into the encoder's
//!   bitrate. Fast and free (retargeting costs no keyframe); all byte-rate authority lives here.
//! - **ladder**: the encoder's quantiser, its encode time and the measured queue, into pixels and
//!   cadence. Slow, expensive, hysteretic. Pixels give way before cadence (see [`LADDER`]).
//!
//! There is deliberately no capture gate on bytes in flight. A P-frame codes the delta from the
//! previous encoded frame, so refusing frames makes each surviving frame larger: fitted on a
//! recorded session, `log(bytes/frame) = c + 1.248 x log(interval_ms)` (R² = 0.74); at 2.4 fps the
//! frames were 28x larger than at 30 fps and more bytes went on the wire. Such a gate settles at
//! intra-only frames, and no credit both admits a ~98 kB 1080p IDR and bounds the queue.
//! libwebrtc, Sunshine, RustDesk, Chrome Remote Desktop and Steam all bound the capture→encode
//! seam by a frame count and leave bytes to the encoder's target bitrate.
//!
//! Wiring rule: no controller's input may be derived from another controller's output (see
//! [`QualityController::tick`]).
//!
//! ## Congestion control
//!
//! How much bandwidth exists is congestion control's job. This module decides how far padding may
//! lift the estimate ([`QualityController::probe_target_kbps`], capped by
//! [`desired_bitrate_kbps`]): too low and every idle moment leaves the estimate under what the
//! pipeline could use, too high and a thin link's buffer overflows. str0m's pacer drains at
//! `estimate * 1.1`, so a budget above the estimate is unspendable; when the estimate fell through
//! our own quiet the receiver's round trip and loss stay at baseline and the estimate is
//! re-anchored, when the receiver reports a queue or loss it is not
//! ([`QualityController::take_bwe_reanchor`]). If transport feedback stops, the estimate freezes;
//! the receiver's RTCP reports drive a brake instead ([`QualityController::take_brake_event`]).
//!
//! Judgement values are fields of [`QualityPolicy`] (`crate::quality_policy`); comments here use
//! their constant names, e.g. `DOWN_AFTER` is [`QualityPolicy::down_after_ms`].

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// One event at debug when `$debug` is true, else at trace, for a line whose signal can flap tick
/// by tick. Two calls because `tracing`'s level must be a constant in each.
macro_rules! debug_or_trace {
    ($debug:expr, $($event:tt)*) => {
        if $debug {
            tracing::debug!($($event)*);
        } else {
            tracing::trace!($($event)*);
        }
    };
}

/// RustDesk's preset table: resolution and the bitrate it is worth, in kbps.
///
/// Verbatim from `base_bitrate`, including the oddly precise 2073 for 1080p: a "tidied" table is
/// a different, untested table.
const PRESETS: &[(u32, u32, u32)] = &[
    (640, 480, 400),
    (800, 600, 500),
    (1024, 768, 800),
    (1280, 720, 1000),
    (1366, 768, 1100),
    (1440, 900, 1300),
    (1600, 900, 1500),
    (1920, 1080, 2073),
    (2048, 1080, 2200),
    (2560, 1440, 3000),
    (3440, 1440, 4000),
    (3840, 2160, 5000),
    (7680, 4320, 12000),
];

/// The frame rate the preset bitrates assume.
const PRESET_FPS: u32 = 30;

pub use crate::quality_policy::QualityPolicy;

/// How bitrate scales when the frame rate drops — sub-linearly, by
/// [`QualityPolicy::fps_factor_exp`] (where the argument for the exponent is).
#[cfg(test)]
fn fps_factor(fps: u32) -> f64 {
    fps_factor_with(&QualityPolicy::reference(), fps)
}

/// [`fps_factor`] under `policy`. The reference exponent, a half, is taken as a square root, which
/// is what it was written as and is exact; `powf(0.5)` need not round the same way.
fn fps_factor_with(policy: &QualityPolicy, fps: u32) -> f64 {
    let ratio = f64::from(fps) / f64::from(PRESET_FPS);
    if policy.fps_factor_exp.to_bits() == 0.5f64.to_bits() {
        ratio.sqrt()
    } else {
        ratio.powf(policy.fps_factor_exp)
    }
}

/// Bitrate a resolution is worth, in kbps: the preset closest in pixel count, scaled by the pixel
/// ratio, so a 1620x1080 panel lands between the table's entries rather than on one.
#[must_use]
pub fn base_bitrate_kbps(w: u32, h: u32) -> u32 {
    let pixels = u64::from(w) * u64::from(h);
    if pixels == 0 {
        return 0;
    }

    let (pw, ph, pkbps) = PRESETS
        .iter()
        .min_by_key(|(pw, ph, _)| {
            let p = u64::from(*pw) * u64::from(*ph);
            p.abs_diff(pixels)
        })
        .copied()
        .unwrap_or((1920, 1080, 2073));

    let preset_pixels = u64::from(pw) * u64::from(ph);
    if preset_pixels == 0 {
        return pkbps;
    }
    u32::try_from(u64::from(pkbps) * pixels / preset_pixels).unwrap_or(u32::MAX)
}

/// How much of the "worth it" bitrate to actually spend: RustDesk's three presets and multipliers.
/// The manual override: adaptation moves the rung, this moves the whole ladder.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Quality {
    Best,
    /// The default, as in RustDesk: two thirds keeps text crisp, and the third given back keeps a
    /// phone on a relay from being the bottleneck.
    #[default]
    Balanced,
    Low,
    Custom(f32),
}

impl Quality {
    /// The share under the reference policy, for the tests. See [`QualityPolicy::quality_ratio`].
    #[cfg(any(test, doc))]
    #[must_use]
    pub fn ratio(self) -> f32 {
        QualityPolicy::reference().quality_ratio(self)
    }
}

/// One rung: what the agent sends when the link supports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Rung {
    /// Longest edge of the encoded frame. The short edge follows from the source's aspect ratio,
    /// so an ultrawide and a 3:2 panel both get a sensible frame from the same rung.
    pub max_h: u32,
    pub fps: u32,
}

/// The ladder, best first; every session opens on the first rung.
///
/// ## Pixels give way before cadence
///
/// Rate control spends `budget / fps` on each frame whatever the resolution, so at a fixed budget:
///
/// - lowering fps raises bits per frame ([`fps_factor`] prices a halving at +41%): each frame
///   takes longer to serialize and arrivals get sparser and less even, which grows the receiver's
///   jitter buffer. Latency is paid twice.
/// - lowering pixels leaves frame size alone and buys quantiser immediately, at no latency cost.
///
/// At 500 kbps and 30 fps every frame is about 2 kB on any rung: QP at its ceiling at 1080p, an
/// ordinary frame at 360p. So cadence holds from 1080p30 down to 360p and only the last two rungs
/// trade it away. "A sharp 15 fps beats a smooth blur" still decides between options of equal
/// latency; it does not order a ladder whose job is to protect latency.
///
/// ## 1080p60 is a bonus rung above the standard
///
/// In `CameraVideoRealTime` a 1080p frame encodes in 2.3–2.7 ms on four threads
/// (`examples/pipeline_bench.rs`), well inside 16.7 ms, and halving the frame interval takes 16 ms
/// out of every round trip. 1080p30 stays the standard (text is readable there and the numbers in
/// this file are calibrated against it), so the step down from 60 is cadence, not pixels. Existing
/// guards shed the rung: `cpu_bound` above `0.75 * 1000/60` = 12.5 ms of encode
/// ([`ENCODE_BUDGET_SHARE`]), `coarse` above [`QP_DOWN`]; the climb back waits for encode under
/// 10.8 ms ([`ENCODE_CLIMB_SHARE`]).
///
/// ## Why a session opens at the top
///
/// The rung sets how many frames are paced and how large, not what they cost:
/// [`QualityController::encoder_target_kbps`] prices them from the measured link. Opening at
/// 1080p60 steps down within two seconds if the pipeline cannot deliver (`cpu_bound` does so from
/// encode times alone). Opening low and climbing slowly measured 75 s to reach the top of a link
/// that had room all along.
///
/// ## Spacing, and why 900p stays
///
/// [`PINNED_FPS`] says a step saving less than the keyframe it costs is worse than no step, and
/// 1080→900 saves only 31%:
///
/// ```text
/// 1080 -> 900   0.69x pixels   saves 31%    <- the step that looks wrong
///  900 -> 720   0.64x          saves 36%
///  720 -> 540   0.56x          saves 44%
///  540 -> 360   0.44x          saves 56%
/// ```
///
/// But a rung is also a landing place, and a climb is priced from the content's cost at the rung
/// above. Measured with 720p producing 3100 kbps at QP 28 and an estimate of 4083:
///
/// ```text
/// -> 900p   3100 * 1.44 * qp_room * UP_HEADROOM  = 3515   affordable
/// -> 1080p  3100 * 2.25 * qp_room * UP_HEADROOM  = 5493   not
/// ```
///
/// Without 900p that link sits at 720p while carrying four megabits. Climbs jump straight to the
/// highest affordable rung, so close spacing only adds a descent step. 540 rather than 480 because
/// it is exactly half of 1080: an integer 2:1 scale, cheaper and cleaner at edges.
///
/// ## The reference ladder
///
/// [`QualityPolicy::reference`]'s ladder, for the tests and docs. The controller reads its own
/// policy's ([`QualityPolicy::ladder`]): the server's profile or the compiled
/// [`QualityPolicy::safe`], which tops out at 720p30. Tools read it from the contract's reference
/// vector at run time.
#[cfg(any(test, doc))]
pub const LADDER: &[Rung] = &[
    Rung {
        max_h: 1080,
        fps: 60,
    },
    Rung {
        max_h: 1080,
        fps: 30,
    },
    Rung {
        max_h: 900,
        fps: 30,
    },
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
];

/// Resolutions a viewer may pin, as encoded heights, in UI order.
///
/// Only the steps people recognise; a list of every rung would be a worse control for the same
/// capability.
pub const PINNABLE_HEIGHTS: &[u32] = &[1080, 720, 540, 360];

/// The rung a session opens on under the reference policy, for the tests: the top of the ladder
/// (see [`QualityPolicy::start_rung_index`]). A session reads [`QualityPolicy::start_rung`].
#[cfg(any(test, doc))]
#[must_use]
pub fn start_rung() -> Rung {
    QualityPolicy::reference().start_rung()
}

/// The ceiling congestion control should probe towards, in kbps: the top rung's
/// [`Rung::absorbable_kbps`].
///
/// In str0m `desired_bitrate` bounds probing only (`probe/control.rs` sends padding up to twice
/// desired); the delay-based estimate grows by AIMD, `observed * 1.5 + 10 kbps`
/// (`bwe/delay/rate_control.rs:191`), uncapped. So this decides how far padding alone can lift the
/// estimate, which matters after an idle period when there is no real traffic to grow on. Beyond
/// that the estimate follows real traffic, which the budget bounds by `absorbable_kbps`.
///
/// The absorbable price, not the desktop [`Rung::required_kbps`]: probing towards a quarter of
/// what the budget may spend ([`ABSORB_RATIO`]) means that after an idle moment on a game the
/// estimate returns to a fraction of what the encoder may use, and the ladder sheds a rung it could
/// have kept. The padding is episodic: str0m fires probe clusters only while application-limited
/// (`bwe/alr_detector/`). Never fed from the estimate: that is a ratchet that tells congestion
/// control to stop probing, and makes every drop permanent.
///
/// This is the ceiling and the opening value. After the opening ([`PROBE_OPENING`]) the target is
/// [`QualityController::probe_target_kbps`]: twice the capacity evidence (or, before any, twice
/// the best estimate seen, never under [`probe_floor_kbps`]), never above this. str0m's periodic
/// ALR probe fires at twice desired every five seconds (`bwe/probe/control.rs:374-396`), 20.6 Mbps
/// against this ceiling; on a simulated 3G link (700 kbps behind a 60 ms buffer) those bursts
/// dropped 654 packets and caused a keyframe storm. Probing at twice the
/// ceiling with no evidence did the same (simulated 3G, five seeds: latency p95 954 → 8892 ms,
/// keyframes 19 → 41). Keeping the ceiling for the opening only preserves str0m's opening probes:
/// deriving the opening target from the estimate halved what good relayed links sent in their
/// first 7 s.
///
/// `quality` is unused on purpose: [`Rung::absorbable_kbps`] carries no quality multiplier, and a
/// viewer choosing `Low` should not be told their link is narrower than it is.
///
/// Under the reference policy, for the tests; production reads [`desired_bitrate_kbps_with`].
#[cfg(any(test, doc))]
#[must_use]
pub fn desired_bitrate_kbps(src_w: u32, src_h: u32, quality: Quality) -> u32 {
    desired_bitrate_kbps_with(&QualityPolicy::reference(), src_w, src_h, quality)
}

/// [`desired_bitrate_kbps`] under `policy`: the top of its ladder.
#[must_use]
pub fn desired_bitrate_kbps_with(
    policy: &QualityPolicy,
    src_w: u32,
    src_h: u32,
    _quality: Quality,
) -> u32 {
    policy.ladder[0]
        .absorbable_kbps_with(policy, src_w, src_h)
        .clamp(MIN_DESIRED_KBPS, MAX_DESIRED_KBPS)
}

/// Bounds on [`desired_bitrate_kbps`], as a guard against a degenerate source size.
///
/// The floor matters more: a zero or nonsense source would price the top rung at nothing and tell
/// congestion control never to probe, which looks exactly like a dead link. The ceiling binds on
/// the widest shapes (a 32:9 ultrawide at 1080p60 absorbs about 19 Mbps) and clips to 12 Mbps,
/// RustDesk's top entry and the encoder's `MAX_BITRATE_KBPS`, so the product has one ceiling. The
/// clamp must never cut below a rung's price; `the_probe_ceiling_can_actually_reach_the_top_rung`
/// asserts that for every supported shape and quality.
const MIN_DESIRED_KBPS: u32 = 600;
pub(crate) const MAX_DESIRED_KBPS: u32 = 12_000;

/// What str0m is told to probe towards while the receiver's reports say the path is full: a desired
/// bitrate under its probing minimum, so it queues no probe cluster (clusters are held to twice
/// desired and one under 5 kbps is not queued: `queue_probe`,
/// `str0m-0.24.1/src/bwe/probe/control.rs:529-537`). Same value as
/// [`crate::bg_hold::BG_HOLD_DESIRED_KBPS`]. Nothing else in str0m reads desired; pacing and
/// padding follow the estimate. See [`QualityController::probe_quiet`] for when.
///
/// str0m 0.24's ALR detector counts any 500 ms without a media packet as unused budget
/// (`bwe/alr_detector/detector.rs:76-84`, `bwe/mod.rs:301-305`). On a thin path those silences are
/// ours (drain mode, the brake, the queue gate, the bit bucket), and str0m then probes into a path
/// the receiver just reported full, applying the probe's result as its estimate
/// (`bwe/delay/rate_control.rs:177-185`) and undoing the brake. In the simulator's `3g-stall-100`
/// (300 kbps behind a 30 s queue, 100 kbps for 20 s; five seeds) 0.24 spent 18 s of 120 in ALR and
/// fired 3 large-drop probes a run; with that timeout off, 1.3 s and none. On the browser bench,
/// 0.24 without probe quiet took 6.2 s after the stall to hold frame age under 1.5 s (p 0.009
/// against 0.23), leaving drain mode about 5 s late; with probe quiet it matches 0.23.
///
/// str0m's public `Bwe` exposes `set_desired_bitrate` and `reset` and nothing that reaches the
/// detector, so the desired bitrate is the lever.
const PROBE_QUIET_KBPS: u32 = crate::bg_hold::BG_HOLD_DESIRED_KBPS;

/// The estimate str0m is configured to start from, in kbps: `INITIAL_BITRATE_KBPS` in
/// `afklink_transport::webrtc` (private there, so restated). An estimate of exactly this that has
/// never moved is our configuration echoed back. Read only by the pre-evidence probe bound
/// (`probe_best_kbps`); if the two drift apart, that bound counts the echo.
const STR0M_OPENING_KBPS: u32 = 600;

/// [`QualityController::probe_target_kbps`] of a session that has measured nothing yet, on a
/// source of `src_w` x `src_h`: the ladder's ceiling, [`desired_bitrate_kbps`], for the opening
/// ([`PROBE_OPENING`]). Sent as the peer is created, before the first tick: str0m 0.24 queues its
/// opening probes before the first media packet at 3x and 6x of 600, held to twice this
/// (`bwe/probe/control.rs:278-291,529-532`), so anything from 1800 up lets both through.
///
/// Under the reference policy, for the tests; the orchestrator sends
/// [`opening_probe_target_kbps_with`] on the session's policy.
#[cfg(any(test, doc))]
#[must_use]
pub fn opening_probe_target_kbps(src_w: u32, src_h: u32, quality: Quality) -> u32 {
    opening_probe_target_kbps_with(&QualityPolicy::reference(), src_w, src_h, quality)
}

/// [`opening_probe_target_kbps`] under `policy`.
#[must_use]
pub fn opening_probe_target_kbps_with(
    policy: &QualityPolicy,
    src_w: u32,
    src_h: u32,
    quality: Quality,
) -> u32 {
    desired_bitrate_kbps_with(policy, src_w, src_h, quality)
}

/// The least probe target after the opening ([`PROBE_OPENING`]), in kbps: half the rate at which
/// the climb gate opens the top rung on a desktop ([`Rung::required_kbps`] at the default
/// preference, times [`UP_HEADROOM`]), so a periodic probe (twice the target) can always lift the
/// estimate that far however far the evidence has decayed.
///
/// 1078 kbps on a 3:2 panel, 1227 on 16:9. On a recorded 700 kbps 3G link (estimates 500-900) the
/// evidence sets the probes; where the floor binds (simulated 3G, median estimate 257) a probe at
/// 2156 into its 60 ms buffer is inside what the buffer holds ([`PROBE_CAPACITY_MULTIPLE`]).
///
/// At the default preference, not the viewer's: how far the link is explored is not a matter of
/// taste.
///
/// Under the reference policy, for the tests; the controller reads [`probe_floor_kbps_with`].
#[cfg(any(test, doc))]
#[must_use]
pub fn probe_floor_kbps(src_w: u32, src_h: u32) -> u32 {
    probe_floor_kbps_with(&QualityPolicy::reference(), src_w, src_h)
}

/// [`probe_floor_kbps`] under `policy`.
#[must_use]
pub fn probe_floor_kbps_with(policy: &QualityPolicy, src_w: u32, src_h: u32) -> u32 {
    let top = policy.ladder[0];
    let climb_at = f64::from(top.required_kbps_with(policy, src_w, src_h, Quality::default()))
        * policy.up_headroom;
    ((climb_at / f64::from(policy.probe_capacity_multiple)) as u32).clamp(
        MIN_DESIRED_KBPS,
        desired_bitrate_kbps_with(policy, src_w, src_h, Quality::default()),
    )
}

impl Rung {
    /// Encoded size for this rung given the source, preserving aspect ratio.
    #[must_use]
    pub fn size_for(self, src_w: u32, src_h: u32) -> (u32, u32) {
        crate::scale::fit_within(src_w, src_h, u32::MAX / 2, self.max_h)
    }

    /// Bitrate this rung needs on a given source, in kbps, under the reference policy: for the
    /// tests ([`Self::required_kbps_with`] elsewhere).
    #[cfg(any(test, doc))]
    #[must_use]
    pub fn required_kbps(self, src_w: u32, src_h: u32, quality: Quality) -> u32 {
        self.required_kbps_with(&QualityPolicy::reference(), src_w, src_h, quality)
    }

    /// [`Self::required_kbps`] under `policy`.
    #[must_use]
    pub fn required_kbps_with(
        self,
        policy: &QualityPolicy,
        src_w: u32,
        src_h: u32,
        quality: Quality,
    ) -> u32 {
        let (w, h) = self.size_for(src_w, src_h);
        let base = base_bitrate_kbps(w, h);
        let scaled = f64::from(base)
            * fps_factor_with(policy, self.fps)
            * f64::from(policy.quality_ratio(quality));
        scaled as u32
    }

    /// The most this rung can usefully absorb, in kbps.
    ///
    /// [`Self::required_kbps`] is the right floor for a mostly still text desktop, and the wrong
    /// ceiling for a window playing video: measured at 1620x1080@30 with 60 fps video on screen,
    /// the encoder sat on its 1220 kbps budget and declined a third to a half of its frames while
    /// the link had room. [`ABSORB_RATIO`] (four, where the quantiser was measured to stop
    /// improving) puts 1080p30 near 7.3 Mbps, above LiveKit's screen-share figure for full-motion
    /// content and under [`MAX_DESIRED_KBPS`]. The measured link picks between floor and ceiling.
    ///
    /// No quality multiplier: this is what the pixels can hold, not what anyone prefers to spend.
    ///
    /// Under the reference policy, for the tests ([`Self::absorbable_kbps_with`] elsewhere).
    #[cfg(any(test, doc))]
    #[must_use]
    pub fn absorbable_kbps(self, src_w: u32, src_h: u32) -> u32 {
        self.absorbable_kbps_with(&QualityPolicy::reference(), src_w, src_h)
    }

    /// [`Self::absorbable_kbps`] under `policy`.
    #[must_use]
    pub fn absorbable_kbps_with(self, policy: &QualityPolicy, src_w: u32, src_h: u32) -> u32 {
        let (w, h) = self.size_for(src_w, src_h);
        let base = base_bitrate_kbps(w, h);
        (f64::from(base) * fps_factor_with(policy, self.fps) * policy.absorb_ratio) as u32
    }
}

/// The least this pipeline may be asked for under congestion, in kbps.
///
/// Global, not derived from the rung: the ladder settles where the rung's price meets the estimate,
/// so a rung-derived floor would cancel the [`SPEND_PCT`] margin that keeps the operating point off
/// the cliff. Matched to the bottom rung and the encoder's `MIN_BITRATE_KBPS`: below this OpenH264
/// produces a picture that looks broken rather than small, and discarding is the better answer.
const ABSOLUTE_FLOOR_KBPS: u32 = 120;

/// The local send queue this product is built around, in milliseconds.
///
/// A constant, not derived from traffic: a bound like `3 x mean_frame_bytes` grows with what it
/// limits, so a queue can never be too large by its own definition (measured: a "100 ms" bound
/// permitted 1311 ms).
///
/// The loop without this queue is 118–189 ms: ~16 ms from WGC, 2–3 ms to encode 1080p in camera
/// mode, ~70 ms of relayed path (single digits direct), 30–100 ms of browser jitter buffer and
/// decode. Adding 75 puts the p95 loop near 265 ms, over the ~150 ms at which a cursor stops
/// feeling attached to the hand, which is why this is a guard and not a target.
///
/// In camera mode the encoder holds its target (a panning 1080p scene at 4000 kbps produces
/// 3200–4000), so what fills this queue is a keyframe (50–85 kB) or the lag between the estimate
/// falling and the budget following: transients of a few hundred milliseconds that the five-second
/// [`LATE_ALPHA`] filter keeps from reading as a backlog. 75 is twice a 30 fps frame interval, so
/// a single late frame cannot reach it.
pub const QUEUE_GUARD_MS: u32 = 75;

/// What str0m's pacer drains at, relative to the estimate.
///
/// `PACING_FACTOR` in `str0m/src/bwe/delay/control.rs`: the divisor that turns bytes into
/// milliseconds. It is low (libwebrtc's `kDefaultPaceMultiplier` is 2.5), and str0m's force-drain
/// arms only near its two-second `DEFAULT_QUEUE_LIMIT`, so nothing downstream rescues a queue at
/// the scale that matters here.
const PACING_FACTOR: u32 = 11; // tenths

/// Weight on the newest sample when smoothing the ladder's inputs: an eighth, a time constant of
/// about 1.6 s at a 200 ms tick, inside [`DOWN_AFTER`] and a fifth of [`UP_AFTER`], so no single
/// frame decides anything. See [`QualityController::qp_smoothed`].
const SIGNAL_ALPHA: f32 = 0.125;

/// Weight on the newest sample when smoothing the queue's age.
///
/// Slower than [`SIGNAL_ALPHA`] because of keyframes. A 1080p IDR is 40 to 67 kB: on a relay
/// carrying ~900 kbps, 350 to 600 ms of real queue that clears in half a second. Through a fast
/// filter it reads as congestion, and since every rung change emits a keyframe of its own, the
/// ladder descends, emits an IDR, sees the spike and descends again (replayed on a recorded
/// session: eleven rung changes in 115 s, to the bottom, on a link that was never the limit).
///
/// At 0.04 and a 200 ms tick the time constant is about five seconds: a 600 ms spike lasting half
/// a second adds under 60 ms to the mean, while a backlog that is not draining crosses the guard in
/// a little over a second and then serves the dwell.
const LATE_ALPHA: f32 = 0.04;

/// How many ticks of egress the exploration bound is computed over: one second, as a maximum.
///
/// The bound is `demonstrated * 1.5 + margin`. The pacer drains on its own clock, so its output is
/// bursty and lags production by a frame or two, and a single quiet 200 ms window says nothing
/// about the link. Measured at 1080p with a healthy estimate and an empty queue:
///
/// ```text
/// 21:35:16  est 3152  bud 2836      21:35:32  est 3600  bud  901
/// 21:35:17  est 3045  bud  295      21:35:54  est 4146  bud 1336
/// 21:35:19  est 3045  bud 1370      21:36:48  est 3636  bud 2704
/// 21:35:20  est 3045  bud  399
/// ```
///
/// Each collapse pins the quantiser at 46, fires the frame dropper and banks `coarse` and
/// `throttled` dwell. The maximum, not the mean: the bound is a ceiling on growth, and one window
/// that carried this many bits proves the link can; a mean lets one gap halve the answer. Five
/// ticks span the pacer's bursts and two frames at the top half's lowest cadence while still being
/// about now (a remembered peak is its own failure: see [`QualityController::unpushed_kbps`]).
const EGRESS_WINDOW: usize = 5;

/// How recently a fresh receiver report must have arrived for the path to be judged clean at all.
///
/// Three seconds, one interval past [`BRAKE_STALE_REPORTS`]: Chrome reports about once a second,
/// randomised between half and one and a half times that, and recorded logs show a stale interval
/// (`loss_pct="-"`) every four to six seconds. While we are sending, the silence brake refuses the
/// path an interval before this does (`brake_refuses`); this is what applies when we are not.
const REPORT_FRESH_WITHIN: Duration = Duration::from_secs(3);

/// The estimate's fall within one stats interval, as a share of the interval's highest, under which
/// the control task logs it alongside the receiver's account of the same interval: 70%. str0m's
/// delay controller cuts to `0.85 x acked`, so a deeper fall is either a cut against an acked rate
/// well under the estimate (our own quiet) or a queue the receiver should be reporting, which is
/// the question behind every re-anchor.
const ESTIMATE_DROP_LOG_PCT: u64 = 70;

/// How many fresh round trips the baseline is the minimum of: thirty seconds at str0m's one-second
/// stats interval, long enough that a few seconds of queue cannot raise it, short enough to follow
/// a moving phone. The minimum, because a queue only adds delay.
pub(crate) const RTT_BASE_REPORTS: usize = 30;

/// How many consecutive fresh reports, all past the clean margin of the baseline, must lie flat for
/// the new level to be read as a longer path rather than a queue. See
/// [`QualityController::watch_path_step`].
///
/// The baseline is the least of [`RTT_BASE_REPORTS`] round trips, right for a queue (which only
/// adds delay) and wrong for a path that got longer: a Wi-Fi (127 ms) to LTE (flat 245 ms) handover
/// held the brake at 524 kbps for thirty seconds on a link that then carried 10-11 Mbps. The shape
/// of the following reports separates the two (recordings A-C and bench runs):
///
/// ```text
///                                 reports (ms)                         spread  first->last
/// path   A: LTE (WiFi 127)       247 253 249 | 249 246 243 244 ...        6        +2
///        B: LTE                  250 250 248 250 250 249 247 251 ...     <=7       <=+4
///        C: LTE                  378 379 377 377 374 377 376 ...         <=14      <=+13
///        C: 3G, drained          555 552 556 | 554 554 576 ...           <=31      <=+22
///        bench rtt-step (+200)   337 341 354 338 337 337 351 ...         <=17      <=+17
///        bench rtt-step, again   329 327 366 340 327 327 329 ...    39 (one spike)  +11
/// queue  A: a 6 s ramp           213 225 235 243 254 259 (a ramp)        16-19     +16..+19
///        A: a 2 s drain          225 208 208 (draining after a cut)      17        -17
///        C: 3G, 2 s              3857 3852 3867, then 6020 (a stall)     15        +10
///        B: 3G, 4 s              452 444 527 414 415                     83-113
/// either A: 4 s                  203 225 208 208, then 154                5 (+spike)  +5
/// ```
///
/// A path step jumps and lies flat whatever is sent; a queue ramps while the sender overshoots and
/// drains after a cut. Three reports within [`PATH_STEP_FLAT_MS`] of the least (or
/// [`PATH_STEP_FLAT_PCT`], whichever is wider), drifting first to last by no more than half that or
/// an eighth of the step ([`PATH_STEP_DRIFT_DIV`]), separate the rows: the ramp and drain by drift,
/// the 3G bursts by spread. The flat 3.9 s stall is refused by [`PATH_STEP_MAX_MS`]: no terrestrial
/// path is that long. Also required, as the brake requires: no report of [`REAL_LOSS`] in the
/// window and no standing queue of our own (`late_smoothed` within [`QUEUE_GUARD_MS`]).
///
/// Three because the round-trip arm cuts on the second inflated report and the ladder sheds a rung
/// [`DOWN_AFTER`] later: recognised on the third report, `braking` lifts a second into the episode,
/// on the fourth still before the rung goes. The three may be any of the last
/// [`PATH_STEP_WINDOW`], so one spike above the level (jitter is one-sided) costs a report, not the
/// rung.
///
/// A flat queue mistaken for a path raises the baseline by the queue's depth, bounded and
/// self-correcting: the baseline is a minimum, so the first report under the new level (the queue
/// draining) lowers it again. The "either" row is that case: read as a path, undone by the 154 ms
/// report a second later, at no cost.
const PATH_STEP_REPORTS: usize = 3;

/// How many of the latest elevated reports the [`PATH_STEP_REPORTS`] may be found among: one more,
/// so that one spike above the level does not reset the run. See [`PATH_STEP_REPORTS`].
const PATH_STEP_WINDOW: usize = PATH_STEP_REPORTS + 1;

/// How many of the viewer's reports the on-time reference is the least-delayed of: half a minute.
/// A reverse path that lengthens for good reads as late that long, which only mutes the viewer.
const DELIVERY_LATE_REPORTS: usize = 30;

/// Ticks of what we sent kept for the viewer's count: 64 s, past [`DRAIN_MAX_PROVEN`] (45 s). A
/// counted frame older than that cannot be priced, and the report says nothing.
pub(crate) const DELIVERY_HISTORY_TICKS: usize = 320;

/// At most this many of our frames in flight is none: one frame is the counts' own jitter (the
/// viewer counts at its `getStats` call, we at our tick).
const DELIVERY_NONE_IN_FLIGHT: f64 = 1.0;

/// The local send queue, in milliseconds, at which the startup window reads our own queue as the
/// link refusing the rung: the transport breaker's limit, where the encode loop's hard hold stops
/// encoding altogether. See [`QualityController::startup_queue_jump`].
///
/// The receiver rule waits for a doubled round trip or loss, because a low estimate alone is also a
/// slow start on a still screen. On a bufferbloated 3G path the receiver never says so: the first
/// report already carries the opening keyframes' queue (1726 ms) and the least round trip only
/// falls from there. Without this the ladder walked 1080p30 to 360p one dwell at a time, 26 s with
/// our queue at 630-1194 ms and two hard holds.
///
/// Our queue at the breaker's limit is the link refusing what we send: production is capped at the
/// budget, the budget at the estimate, and still a second of it waits. A still screen produces
/// nothing and cannot put a queue there. No good-network bench run comes near it in its first ten
/// seconds (all peak at 264 ms).
const STARTUP_QUEUE_LIMIT_MS: u32 = afklink_transport::QUEUE_HARD_LIMIT_MS;

/// How many ticks of egress the startup queue jump prices the link from: two seconds, as
/// [`DOWN_AFTER`]. A mean, because this measures a rate, not a ceiling on growth (compare
/// [`EGRESS_WINDOW`]).
const STARTUP_DRAIN_TICKS: usize = 10;

/// One point of the calibration sweep: a resolution, a cadence, and a bitrate to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalibrationPoint {
    pub max_h: u32,
    pub fps: u32,
    pub kbps: u32,
}

/// How long each point is held. Long enough for rate control to settle and for a few dozen frames
/// to be recorded; short enough that the whole sweep fits in one sitting.
pub const CALIBRATION_DWELL: Duration = Duration::from_secs(8);

/// The sweep, and why it is a cross rather than a walk.
///
/// A rate surface (frame cost by resolution, cadence and quantiser) fitted from ordinary sessions
/// cannot be identified: `R² = 0.17`, no coefficient significant, a negative pixel exponent. The
/// controller chose every operating point and always lowered resolution and raised the quantiser
/// together (`corr(log(pixels), qp) = +0.78`), so the data never varies one without the other. A
/// synthetic bench measured exponents from 1.41 to 2.18 per doubling of pixels depending on
/// content, so the constants belong to the user's screen, not a test pattern.
///
/// Holding a resolution and sweeping the bitrate makes resolution and quantiser vary independently.
/// Cadence, where the observational fit failed worst (`interval^0.013 ± 0.34` once the confounder
/// was removed), is swept over a subset; a full cross would triple the sitting.
pub const CALIBRATION: &[CalibrationPoint] = &{
    const HEIGHTS: [u32; 5] = [1080, 900, 720, 540, 360];
    const RATES: [u32; 4] = [300, 600, 1_200, 2_400];
    const SLOW_HEIGHTS: [u32; 2] = [1080, 540];
    const SLOW_RATES: [u32; 2] = [600, 1_200];

    let mut out = [CalibrationPoint {
        max_h: 0,
        fps: 0,
        kbps: 0,
    }; HEIGHTS.len() * RATES.len() + SLOW_HEIGHTS.len() * SLOW_RATES.len()];
    let mut n = 0;
    let mut h = 0;
    while h < HEIGHTS.len() {
        let mut r = 0;
        while r < RATES.len() {
            out[n] = CalibrationPoint {
                max_h: HEIGHTS[h],
                fps: 30,
                kbps: RATES[r],
            };
            n += 1;
            r += 1;
        }
        h += 1;
    }
    let mut h = 0;
    while h < SLOW_HEIGHTS.len() {
        let mut r = 0;
        while r < SLOW_RATES.len() {
            out[n] = CalibrationPoint {
                max_h: SLOW_HEIGHTS[h],
                fps: 10,
                kbps: SLOW_RATES[r],
            };
            n += 1;
            r += 1;
        }
        h += 1;
    }
    out
};

/// How long a full sweep takes, for telling the person holding the phone.
#[must_use]
pub fn calibration_duration() -> Duration {
    CALIBRATION_DWELL * u32::try_from(CALIBRATION.len()).unwrap_or(u32::MAX)
}

/// The current rung, shared between the threads that have to act on it.
///
/// Capture scales to `max_h` and the encode loop paces to `fps`; the session task that owns the
/// [`QualityController`] is the one writer. Atomics rather than a lock because readers touch this
/// once per frame on the hot path, and a torn read costs at most one frame at the old size or
/// pacing.
#[derive(Debug)]
pub struct QualityTarget {
    max_h: AtomicU32,
    fps: AtomicU32,
    source_w: AtomicU32,
    source_h: AtomicU32,
    /// What the current rung is worth in kbps, for the encoder to target. Published by the
    /// controller, the only holder of both the source size and the quality preference.
    target_kbps: AtomicU32,
    /// Bytes handed to the transport that have not yet left the socket.
    ///
    /// Written by the WebRTC peer loop, read by the capturer. Shared as an `Arc` because a signal
    /// passed through a channel and a task wake-up describes a queue that has grown since.
    ///
    /// Bytes, not milliseconds: str0m's delay snapshot refreshes only when the pacer releases a
    /// packet, so below ~120 kbps it is always older than any staleness cutoff and reads as zero on
    /// exactly the links that need it. Bytes need no rate to divide by.
    outstanding_bytes: Arc<AtomicU32>,
    /// How long the oldest packet still waiting has been waiting, in milliseconds.
    ///
    /// [`Feedback::queue_age_ms`], str0m's own measurement, republished by the control task on its
    /// 200 ms tick for the encode thread. The pre-encode latency guard reads this rather than
    /// [`Self::outstanding_bytes`] because bytes need a drain rate before they mean anything.
    /// Published on the controller's clock so latency decisions share one reader of the transport.
    /// Up to 200 ms stale, so the guard is bounded by a consecutive-skip count (`skip_for_queue` in
    /// `crate::agent`).
    queue_age_ms: AtomicU32,
    /// What the send queue drains at, kbps: [`drain_kbps`] of the transport's measured egress and
    /// str0m's estimate, as of the controller's last tick (`0` before the first). Read by the
    /// encode thread to price a keyframe's time to leave, the window in which the viewer's repeated
    /// keyframe requests are answered by it (`crate::keyframe_window`).
    drain_kbps: AtomicU32,
    /// What the OS handed the capturer, and what the capturer held back for its slot. Two counters
    /// because `captured_fps` alone cannot tell a still screen from ordinary pacing.
    offered: AtomicU32,
    early: AtomicU32,
    /// What [`crate::frame_dropper::FrameDropper`] reads, published by the encode thread, which
    /// sees both every offered frame and every encoded size. Hundredths, so the fractions fit an
    /// integer: `drop_ratio` is 0..0.96 and `fullness` is 0..6.
    ///
    /// `tick` reads `fd_ratio` as [`Feedback::drop_ratio`] and sheds the rung above [`DROP_SHARE`]:
    /// a rung held by discarding a third of the frames is not held. `fd_fullness` is for the log.
    /// See `crate::frame_dropper`.
    fd_ratio_pct: AtomicU32,
    fd_fullness_pct: AtomicU32,
    /// Drain mode, as the control task last published it: while set the encode loop encodes
    /// nothing and the heartbeat says `net_stall`. See [`QualityController::draining`].
    draining: AtomicBool,
    /// The background hold, as the session's hold cell last published it (`crate::bg_hold`): while
    /// set the viewer's page is hidden past its grace, the pipeline supervisor keeps capture
    /// stopped, the encode loop takes no frame, and the heartbeat says `bg_hold`. A flag here, like
    /// drain mode, because the hot paths read nothing else.
    bg_hold: AtomicBool,
}

/// How long the bytes already committed will take to leave, in milliseconds: bytes over the rate
/// they drain at. `drain_kbps` should be the pacer's rate (the estimate times [`PACING_FACTOR`]),
/// never the encoder's budget, which is a production rate and wrong exactly while the queue grows.
///
/// Floored rather than guarded: before an estimate exists `drain_kbps` is zero, and dividing would
/// give an infinity ("stop everything") or a `NaN` ("carry on").
#[must_use]
pub fn queue_ms(outstanding_bytes: u32, drain_kbps: u32) -> u32 {
    let drain = u64::from(drain_kbps.max(ABSOLUTE_FLOOR_KBPS));
    u32::try_from(u64::from(outstanding_bytes) * 8 / drain).unwrap_or(u32::MAX)
}

/// The rate the queue drains at, in kbps: the larger of measured egress and the estimate, floored.
/// Egress under-reads while there is nothing to send; the estimate, bounded by what was
/// acknowledged, under-reads harder (a still desktop sending 12 kbps drove it to 139, turning 17 kB
/// into a 922 ms "queue" on a healthy link).
#[must_use]
pub fn drain_kbps(measured_egress_kbps: u32, estimate_kbps: u32) -> u32 {
    let paced = estimate_kbps.saturating_mul(PACING_FACTOR) / 10;
    measured_egress_kbps.max(paced).max(ABSOLUTE_FLOOR_KBPS)
}

impl QualityTarget {
    #[must_use]
    pub fn new(rung: Rung) -> Self {
        Self::with_outstanding(rung, Arc::new(AtomicU32::new(0)))
    }

    /// As [`Self::new`], sharing the peer's outstanding-bytes gauge so the capturer can see it.
    #[must_use]
    pub fn with_outstanding(rung: Rung, outstanding_bytes: Arc<AtomicU32>) -> Self {
        Self {
            max_h: AtomicU32::new(rung.max_h),
            fps: AtomicU32::new(rung.fps),
            source_w: AtomicU32::new(0),
            source_h: AtomicU32::new(0),
            target_kbps: AtomicU32::new(0),
            outstanding_bytes,
            queue_age_ms: AtomicU32::new(0),
            drain_kbps: AtomicU32::new(0),
            offered: AtomicU32::new(0),
            early: AtomicU32::new(0),
            fd_ratio_pct: AtomicU32::new(0),
            fd_fullness_pct: AtomicU32::new(0),
            draining: AtomicBool::new(false),
            bg_hold: AtomicBool::new(false),
        }
    }

    /// Publish drain mode for the encode loop and the heartbeat. Returns whether it changed.
    pub fn set_draining(&self, draining: bool) -> bool {
        self.draining.swap(draining, Ordering::Relaxed) != draining
    }

    /// Publish the background hold for the supervisor, the encode loop and the heartbeat. Returns
    /// whether it changed. Written only by the session's hold cell (`crate::bg_hold::BgHold`).
    pub fn set_bg_hold(&self, held: bool) -> bool {
        self.bg_hold.swap(held, Ordering::SeqCst) != held
    }

    /// Whether the background hold is in force, as last published. See `crate::bg_hold`.
    #[must_use]
    pub fn bg_hold(&self) -> bool {
        self.bg_hold.load(Ordering::SeqCst)
    }

    /// Whether drain mode is in force, as last published. See [`QualityController::draining`].
    #[must_use]
    pub fn draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Bytes handed to the transport and not yet on the wire.
    #[must_use]
    pub fn outstanding_bytes(&self) -> u32 {
        self.outstanding_bytes.load(Ordering::Relaxed)
    }

    /// Republish the measured age of the send queue, for the encode thread. See the field.
    pub fn set_queue_age_ms(&self, ms: u32) {
        self.queue_age_ms.store(ms, Ordering::Relaxed);
    }

    /// The measured age of the send queue as of the control task's last tick, in milliseconds.
    #[must_use]
    pub fn queue_age_ms(&self) -> u32 {
        self.queue_age_ms.load(Ordering::Relaxed)
    }

    /// Republish what the send queue drains at, for the encode thread. See the field.
    pub fn set_drain_kbps(&self, kbps: u32) {
        self.drain_kbps.store(kbps, Ordering::Relaxed);
    }

    /// What the send queue drains at as of the control task's last tick, kbps; `0` before it.
    #[must_use]
    pub fn drain_kbps(&self) -> u32 {
        self.drain_kbps.load(Ordering::Relaxed)
    }

    /// The capturer was handed a frame by the OS.
    pub fn note_offered(&self) {
        self.offered.fetch_add(1, Ordering::Relaxed);
    }

    /// The deadline scheduler held it back: it arrived before its slot.
    pub fn note_early(&self) {
        self.early.fetch_add(1, Ordering::Relaxed);
    }

    /// Publish the frame dropper's two readings. See the field documentation.
    ///
    /// Clamped rather than wrapped: they come from float arithmetic on measured sizes.
    pub fn set_frame_dropper(&self, drop_ratio: f32, fullness: f32) {
        let pct = |v: f32| {
            if v.is_finite() {
                (v * 100.0).clamp(0.0, 10_000.0) as u32
            } else {
                0
            }
        };
        self.fd_ratio_pct.store(pct(drop_ratio), Ordering::Relaxed);
        self.fd_fullness_pct.store(pct(fullness), Ordering::Relaxed);
    }

    /// The frame dropper's readings: the smoothed duty cycle, and bucket fullness. Both as
    /// fractions. See [`crate::frame_dropper::FrameDropper`] for what each one can and cannot say.
    #[must_use]
    pub fn frame_dropper(&self) -> (f32, f32) {
        (
            self.fd_ratio_pct.load(Ordering::Relaxed) as f32 / 100.0,
            self.fd_fullness_pct.load(Ordering::Relaxed) as f32 / 100.0,
        )
    }

    /// Take and clear the two capture counters: offered by the OS, held back for its slot.
    pub fn take_capture_counts(&self) -> (u32, u32) {
        (
            self.offered.swap(0, Ordering::Relaxed),
            self.early.swap(0, Ordering::Relaxed),
        )
    }

    /// Record the screen's real size, as observed by whoever is capturing it.
    ///
    /// What a rung costs depends on the source's shape, so the controller cannot price one until it
    /// knows. Published by the capturer, which holds the pixels, rather than queried from the OS:
    /// no platform display query here, and correct for any capture source.
    pub fn set_source(&self, w: u32, h: u32) {
        // A degenerate frame must not erase a known size: against 0x0 every rung is free and the
        // ladder pins silently at the top.
        if w == 0 || h == 0 {
            return;
        }
        self.source_w.store(w, Ordering::Relaxed);
        self.source_h.store(h, Ordering::Relaxed);
    }

    /// The observed source size, or `None` before the first frame.
    #[must_use]
    pub fn source(&self) -> Option<(u32, u32)> {
        let w = self.source_w.load(Ordering::Relaxed);
        let h = self.source_h.load(Ordering::Relaxed);
        (w > 0 && h > 0).then_some((w, h))
    }

    pub fn set(&self, rung: Rung) {
        self.max_h.store(rung.max_h, Ordering::Relaxed);
        self.fps.store(rung.fps, Ordering::Relaxed);
    }

    /// Publish what the current rung is worth, in kbps.
    pub fn set_target_kbps(&self, kbps: u32) {
        self.target_kbps.store(kbps, Ordering::Relaxed);
    }

    /// The encoder's bitrate target, or `None` before the controller has priced a rung.
    #[must_use]
    pub fn target_kbps(&self) -> Option<u32> {
        let v = self.target_kbps.load(Ordering::Relaxed);
        (v > 0).then_some(v)
    }

    #[must_use]
    pub fn max_h(&self) -> u32 {
        self.max_h.load(Ordering::Relaxed).max(2)
    }

    #[must_use]
    pub fn fps(&self) -> u32 {
        self.fps.load(Ordering::Relaxed).max(1)
    }

    /// Shortest gap between frames, as the capturer should schedule them.
    ///
    /// The whole frame-rate lever: fewer frames to the encoder, no reconfiguration, no keyframe.
    /// Applied by the capturer before scaling, so skipped frames cost nothing.
    #[must_use]
    pub fn min_frame_interval(&self) -> Duration {
        Duration::from_micros(1_000_000 / u64::from(self.fps()))
    }
}

/// At the reference's opening rung, for the tests: production opens a target at its session
/// policy's [`QualityPolicy::start_rung`].
#[cfg(any(test, doc))]
impl Default for QualityTarget {
    fn default() -> Self {
        Self::new(start_rung())
    }
}

/// What the pipeline reports about itself, once per [`TICK`].
///
/// On a fixed clock of its own, not driven by the estimate handler: a link that stops producing
/// estimates must not freeze the ladder and the budget.
#[derive(Debug, Clone, Copy)]
pub struct Feedback {
    /// The link estimate, instantaneous. Not smoothed: retargeting is free, so smoothing is lag
    /// that buys nothing.
    pub estimate_kbps: u32,
    /// How long the oldest packet still waiting has been waiting, in milliseconds.
    ///
    /// Measured, not inferred: str0m's `first_unsent()` is when the oldest queued packet was
    /// enqueued, so its age is the queueing delay with no rate to be wrong about. Dividing bytes by
    /// the estimate misreads on an idle screen: measured, 40 817 bytes read as 1010 ms against an
    /// estimate of 294 kbps and tripped the breaker, while they drained in 367 ms.
    pub queue_age_ms: u32,
    /// What the encoder put on the wire in the window, in kbps, keyframes excluded.
    ///
    /// Against [`Self::egress_kbps`] this is the ladder's fast network signal: production above
    /// egress means the backlog grew, from two measurements with no estimate between them. A 28 to
    /// 55 kB IDR in one window would read as several times the link's capacity, hence the
    /// exclusion.
    pub produced_kbps: u32,
    /// What actually left the socket in the window, in kbps, unsmoothed.
    pub egress_kbps: u32,
    /// How many frames contributed to [`Self::avg_qp`] in this window. At the bottom rung a 200 ms
    /// tick holds 1.6 frames, so without a floor one frame decides the rung (libwebrtc's
    /// `QualityScaler` likewise needs `kMinFramesNeededToScale = 60`).
    pub qp_samples: u32,
    /// The rate the queue actually drains at, in kbps: measured egress, not an estimate. On a still
    /// screen sending 12 kbps the estimate collapses, and an ordinary 17 kB burst reads as a 922 ms
    /// queue; the same bytes at the link's demonstrated rate are under 140 ms.
    pub drain_kbps: u32,
    /// The mean quantiser of the frames encoded in this window, if the encoder can say.
    ///
    /// The ladder's primary signal, as in libwebrtc: the one number that says this picture does not
    /// fit in these bits, and a property of the encoder that no controller decision can suppress.
    /// `None` when the backend cannot report one; the ladder then steers on queue and encode time.
    pub avg_qp: Option<f32>,
    /// Mean milliseconds spent encoding one frame, in the window.
    pub encode_ms: f32,
    /// Bits the encoder produced over bits it was allowed, in the window.
    ///
    /// Only a precondition for climbing, never a reason to descend: the budget is already reduced
    /// by pushback, so an encoder on target reads `1 - 0.5 x pressure`, 0.70 just as the queue hits
    /// its limit.
    pub spend_ratio: f32,
    /// What the current rung promises, as the pipeline understands it.
    pub rung_fps_hint: f32,
    /// The coarsest quantiser the encoder is allowed to use, if it has one. Read by `starved` in
    /// [`QualityController::tick`]: an encoder clamped to 46 has spent everything it has at 46. See
    /// [`crate::traits::Encoder::max_qp`].
    pub qp_ceiling: Option<f32>,
    /// What fraction of offered frames the bit bucket withheld to hold the bitrate, 0.0 to 0.96:
    /// the frame rate the viewer is not getting. See
    /// [`crate::frame_dropper::FrameDropper::drop_ratio`].
    pub drop_ratio: f32,
    /// The receiver's account of the last stats interval: `Some` on exactly one tick per str0m
    /// `MediaEgressStats` event, `None` otherwise, because the brake counts reports.
    pub report: Option<ReceiverReport>,
}

/// What the far end said about one stats interval, from str0m's `MediaEgressStats`.
///
/// str0m emits that event once per `set_stats_interval` (one second here) for every stream that has
/// sent a byte, whether or not an RTCP receiver report arrived (`streams/send_stats.rs:101-104`).
/// So the event is a clock and the report may or may not be inside it:
///
/// - `loss` is `None` exactly when no report arrived, or none whose highest sequence number moved.
///   str0m averages fraction-lost over consecutive report pairs weighted by packets
///   (`send_stats.rs:106-120`) and keeps only the last report between events (`:122`), so no new
///   report means `NaN`, returned as `None`. **This is the freshness signal.**
/// - `rtt_ms` is the round trip of the last report (`send_stats.rs:89-90`), repeated on an interval
///   without one; read only when `loss` says the report is fresh.
/// - `nacks` counts retransmission requests since the previous event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReceiverReport {
    pub rtt_ms: Option<u32>,
    /// Fraction lost, 0.0 to 1.0.
    pub loss: Option<f32>,
    pub nacks: u32,
}

impl ReceiverReport {
    /// Whether a new receiver report arrived in this interval. See the struct.
    #[must_use]
    pub fn fresh(&self) -> bool {
        self.loss.is_some()
    }
}

/// Why the brake moved. Log-only: nothing reads it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrakeCause {
    /// A report at or above [`BRAKE_LOSS`].
    Loss,
    /// [`BRAKE_RTT_REPORTS`] fresh reports with the round trip past [`RTT_INFLATION`].
    Rtt,
    /// [`BRAKE_STALE_REPORTS`] intervals without a report while sending.
    Silence,
    /// A clean report: loss under [`BRAKE_CLEAR_LOSS`] and the round trip back near its baseline.
    Clear,
    /// Drain mode ended and the budget resumes at [`DRAIN_RESUME_SHARE_PCT`] of what the receiver
    /// last confirmed. See [`QualityController::draining`].
    Drain,
    /// A silence-only brake, dropped when the receiver came back clean for [`OUTAGE_CONFIRM`] and
    /// congestion control was re-anchored. See [`ReanchorTrigger::OutageResume`].
    Resumed,
}

impl BrakeCause {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            BrakeCause::Loss => "loss",
            BrakeCause::Rtt => "rtt",
            BrakeCause::Silence => "no-feedback",
            BrakeCause::Clear => "clear",
            BrakeCause::Drain => "drain",
            BrakeCause::Resumed => "resumed",
        }
    }
}

/// What the brake did on a tick, for the control task to log. See
/// [`QualityController::take_brake_event`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BrakeEvent {
    /// A new episode: the budget was cut from `before_kbps` to `after_kbps`.
    Engaged(BrakeDetail),
    /// A further cut inside an episode that was already engaged.
    Tightened(BrakeDetail),
    /// The ceiling has grown back to the budget the link alone allows, and is gone.
    Released(BrakeDetail),
}

/// The numbers behind a [`BrakeEvent`], all of them from the report that caused it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BrakeDetail {
    pub cause: BrakeCause,
    /// Percent, for the log.
    pub loss_pct: Option<f32>,
    pub rtt_ms: Option<u32>,
    pub rtt_base_ms: Option<u32>,
    pub before_kbps: u32,
    pub after_kbps: u32,
}

/// Where the brake is in an episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrakePhase {
    /// The last fresh report met a brake condition. Descent evidence for the ladder.
    Engaged,
    /// The last fresh report was neither bad enough to cut nor clean enough to release.
    Holding,
    /// A clean report arrived; the ceiling grows at [`BRAKE_RELEASE_PER_SEC`].
    Releasing,
}

/// A ceiling on the budget set from what the receiver reported, independent of the estimate.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Brake {
    cap_kbps: u32,
    phase: BrakePhase,
    /// The round trip of the report that made the last cut. The round-trip arm cuts again only
    /// above it. See [`BRAKE_BACKOFF`].
    rtt_at_cut: Option<u32>,
    /// Nothing the receiver has said about the current path is behind this cap: every cut of the
    /// episode was [`BrakeCause::Silence`], or the path has changed since the cuts the receiver did
    /// make (an outage, a recognised path step, a new candidate pair: see
    /// [`QualityController::note_path_change`]).
    ///
    /// Such an episode caps the budget and does nothing else. It is not descent evidence (`braking`
    /// in [`QualityController::tick`]): on a bench blackout silence alone walked 1080p60 to
    /// 1080p30, and ICE may wait twenty seconds for a restart. It does not lower the capacity
    /// evidence: silence is not a measurement, and lowering it (8464 to 1355 on the blackout) left
    /// nothing to re-anchor the estimate on when the link returned. Once the receiver calls the
    /// path clean it does not refuse it (`brake_refuses`), so a re-anchor does not wait for the
    /// release.
    ///
    /// The path-change case is a Wi-Fi to LTE handover: the round-trip arm cut on the dying Wi-Fi
    /// (685, then 1758 ms against 127), the phone was silent for 9.2 s and came back on LTE at a
    /// flat 245, and a brake still holding the Wi-Fi's word would shed rungs through the silence
    /// and refuse the outage's re-anchor.
    silence_only: bool,
    /// A cut of this episode was [`BrakeCause::Loss`]. A recognised path step voids an episode's
    /// round-trip evidence, never its loss evidence. See `QualityController::watch_path_step`.
    by_loss: bool,
}

/// An outage the silence brake answered, and how long the receiver has been back since. See
/// [`ReanchorTrigger::OutageResume`].
#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct Outage {
    /// Since the first fresh receiver report after the silence, or `None` while it lasts.
    resumed_for: Option<Duration>,
}

/// The last [`PATH_STEP_WINDOW`] consecutive fresh round trips past the baseline's clean margin,
/// oldest first. See [`QualityController::watch_path_step`].
#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct StepWatch {
    rtts: [u32; PATH_STEP_WINDOW],
    len: usize,
    /// Whether this run's refusal has been logged at debug; later ones go to trace.
    refusal_logged: bool,
    /// Whether this run's holding back of the round-trip brake's descent evidence has been logged.
    /// See `QualityController::path_step_pending`.
    pending_logged: bool,
}

impl StepWatch {
    fn push(&mut self, rtt: u32) {
        if self.len == PATH_STEP_WINDOW {
            self.rtts.rotate_left(1);
            self.rtts[PATH_STEP_WINDOW - 1] = rtt;
        } else {
            self.rtts[self.len] = rtt;
            self.len += 1;
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    /// The run so far, once it holds at least [`PATH_STEP_REPORTS`].
    fn window(&self) -> Option<&[u32]> {
        (self.len >= PATH_STEP_REPORTS).then_some(&self.rtts[..self.len])
    }
}

/// Whether a run of elevated round trips too short to judge could still become a path step: under
/// [`PATH_STEP_WINDOW`] reports, at most [`PATH_STEP_MAX_MS`], and at most one off the flat band of
/// the least. See `QualityController::path_step_pending`.
fn path_step_pending(policy: &QualityPolicy, window: &[u32]) -> bool {
    if window.is_empty() || window.len() >= PATH_STEP_WINDOW {
        return false;
    }
    let lo = window.iter().copied().min().unwrap_or(0);
    let band = policy
        .path_step_flat_ms
        .max(lo.saturating_mul(policy.path_step_flat_pct) / 100);
    let flat = window.iter().filter(|&&r| r - lo <= band).count();
    lo <= policy.path_step_max_ms && flat + 1 >= window.len()
}

/// Why a window of elevated round trips is not a path step, or `None` when it is one. `base` is
/// the baseline the window is elevated above. Pure, so the table in [`PATH_STEP_REPORTS`] is a
/// test.
///
/// The level is the window's least round trip; reports within its flat band
/// ([`PATH_STEP_FLAT_MS`], [`PATH_STEP_FLAT_PCT`]) are the level's, the rest are spikes. At least
/// [`PATH_STEP_REPORTS`] must be the level's (`spread`), drifting within [`PATH_STEP_DRIFT_DIV`]
/// (`trend`), and the level must not exceed [`PATH_STEP_MAX_MS`] (`too-long`).
fn path_step_refusal(policy: &QualityPolicy, window: &[u32], base: u32) -> Option<&'static str> {
    let lo = window.iter().copied().min().unwrap_or(0);
    let band = policy
        .path_step_flat_ms
        .max(lo.saturating_mul(policy.path_step_flat_pct) / 100);
    let mut flat = window.iter().copied().filter(|&r| r - lo <= band);
    let first = flat.next().unwrap_or(lo);
    let (count, last) = flat.fold((1usize, first), |(n, _), r| (n + 1, r));
    let drift_allowed = (band / 2).max(lo.saturating_sub(base) / policy.path_step_drift_div);
    if count < PATH_STEP_REPORTS {
        Some("spread")
    } else if first.abs_diff(last) > drift_allowed {
        Some("trend")
    } else if lo > policy.path_step_max_ms {
        Some("too-long")
    } else {
        None
    }
}

/// What one receiver report says the brake should do.
enum Verdict {
    Cut(BrakeCause, u32),
    Clear,
    Hold,
    /// A stale report short of [`BRAKE_STALE_REPORTS`]: no information, change nothing.
    NoInfo,
}

/// Why a re-anchor was requested: for the log, and for when the transport applies it
/// ([`Self::at_next_frame`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorTrigger {
    /// Motion resumed after an application-limited pause of ours, against an estimate our silence
    /// had collapsed. See [`REANCHOR_AFTER_PAUSE`].
    PauseResume,
    /// The estimate fell to under half the capacity evidence in the middle of motion while the
    /// receiver reported the path clean. See [`CLEAN_RTT_MARGIN_MS`].
    CleanCollapse,
    /// The receiver went silent while we sent, came back clean for [`OUTAGE_CONFIRM`], and the
    /// estimate is under two thirds of the capacity evidence. See [`OUTAGE_DIVERGENCE_PCT`].
    OutageResume,
    /// Drain mode ended with the estimate under the resume budget: str0m measured our silence
    /// through the drain and its pacer would hold the resume keyframe behind that. Restarted at the
    /// resume budget. See [`QualityController::draining`].
    DrainResume,
    /// The ladder climbed on an idle screen on the capacity evidence rather than the estimate (see
    /// `QualityController::idle_evidence`), and the estimate is under half of it. Restarted at the
    /// evidence, clamped to what the new rung can absorb, so the climb's keyframe drains at the
    /// rate the path demonstrated rather than behind a falling estimate (recorded: a 63 kB keyframe
    /// behind an estimate falling 1110 -> 412 hit the breaker's limit a second later and forced a
    /// second keyframe). Once per climb, never on a schedule; [`REANCHOR_DIVERGENCE_PCT`],
    /// [`REANCHOR_MIN_KBPS`] and [`REANCHOR_EVERY`] apply as to the others. No hold follows: on an
    /// idle screen only this keyframe queues behind the estimate.
    IdleClimb,
    /// A background hold ended (`crate::bg_hold`): congestion control is restarted, right before
    /// the resumed video's first frame, at the larger of the capacity evidence from before the hold
    /// (kept, not decayed; clamped to what the rung can absorb) and the current estimate, never
    /// down. Always, because the restart is for str0m's acknowledged-rate history, which the hold
    /// left at the padding rate whatever the estimate shows. See
    /// [`QualityController::reanchor_after_hold`].
    HoldResume,
    /// The media moved to a more direct candidate pair (host replacing reflexive or relayed,
    /// reflexive replacing relayed), or to one whose round trip is at most half the old path's.
    /// str0m's opening probes measured the first pair and nothing probes again by itself (measured:
    /// 1337 kbps on a srflx pair through a VPN, then the media moved to the LAN 0.7 s later and ran
    /// 40 s on the old number). Restarted at the live estimate with str0m's opening probes (3x and
    /// 6x of it) and the capacity evidence forgotten: the new path is as unmeasured as a new
    /// session's, so the probe target is the ladder's ceiling for its opening ([`PROBE_OPENING`],
    /// counted from the re-probe), then twice the best estimate seen. The opening ends before
    /// str0m's first periodic probe can fire, so no 23 Mbps burst goes into an unmeasured path (see
    /// [`desired_bitrate_kbps`]). A move the other way, or sideways, changes nothing. See
    /// [`QualityController::note_path_move`].
    PathChange,
}

impl ReanchorTrigger {
    /// Whether the transport applies this re-anchor right before the next video frame it hands to
    /// str0m (`PeerControl::ResetBweAtNextFrame`) rather than on arrival (`ResetBwe`). Only a
    /// hold's: it is decided before the resumed video exists and must measure that video, not the
    /// padding before it. See [`QualityController::reanchor_after_hold`].
    #[must_use]
    pub fn at_next_frame(self) -> bool {
        matches!(self, ReanchorTrigger::HoldResume)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ReanchorTrigger::PauseResume => "pause-resume",
            ReanchorTrigger::CleanCollapse => "clean-collapse",
            ReanchorTrigger::OutageResume => "outage-resume",
            ReanchorTrigger::DrainResume => "drain-resume",
            ReanchorTrigger::IdleClimb => "idle-climb",
            ReanchorTrigger::HoldResume => "hold-resume",
            ReanchorTrigger::PathChange => "path-change",
        }
    }
}

/// How direct the candidate pair carrying the media is (`afklink_transport::Peer::path_kind`):
/// relayed, reflexive, or host to host, ordered so a later one is more direct. See
/// [`QualityController::note_path_move`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathKind {
    Relay,
    Reflexive,
    Host,
}

impl PathKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Relay => "relay",
            PathKind::Reflexive => "reflexive",
            PathKind::Host => "host",
        }
    }
}

/// What [`QualityController::resume_after_hold`] did, for the hold's log line.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HoldResumed {
    /// The re-anchor decided here, if any: a drain's that the hold ended. The hold's own is decided
    /// next, by [`QualityController::reanchor_after_hold`].
    pub reanchor: Option<Reanchor>,
    /// Drain mode was in force when the hold began, and ended now through its own resume — which
    /// stands for the hold's re-anchor, so none is due.
    pub drain_ended: bool,
    /// Whether the hold's own re-anchor is to be decided ([`QualityController::reanchor_after_hold`]).
    pub reanchor_due: bool,
    /// The capacity evidence as the hold kept it, before the rung's clamp.
    pub capacity_kbps: u32,
}

/// What [`QualityController::reanchor_after_hold`] decided.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HoldReanchor {
    /// The re-anchor, when one was decided: taken with [`QualityController::take_bwe_reanchor`].
    pub reanchor: Option<Reanchor>,
    /// Why not: `cold`, `no-evidence`, `spacing`, `drain`, or the receiver's word (`brake`, `loss`,
    /// `rtt`). `None` when it was decided.
    pub refused: Option<&'static str>,
    /// The re-anchor raises the estimate (the hold's silence left it under the evidence), rather than
    /// restarting it at the value it has.
    pub raises: bool,
}

/// A re-anchor as decided, with the numbers it was decided on. See
/// [`QualityController::last_reanchor`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reanchor {
    /// What str0m is restarted at.
    pub kbps: u32,
    pub trigger: ReanchorTrigger,
    /// The estimate it replaced.
    pub estimate_kbps: u32,
    /// The capacity evidence before the clamp to the rung's absorbable price.
    pub capacity_kbps: u32,
    /// The last fresh receiver report's round trip and loss (percent), and the baseline.
    pub rtt_ms: Option<u32>,
    pub rtt_base_ms: Option<u32>,
    pub loss_pct: Option<f32>,
    /// How far str0m's opening probes may reach after the restart, in kbps. `None` holds them to
    /// [`Self::kbps`] (only [`ReanchorTrigger::PathChange`] reaches further); the transport bounds
    /// it by twice its ceiling either way (`afklink_transport::webrtc::reanchor_bwe_probing`).
    pub probe_cap_kbps: Option<u32>,
}

/// A collapse the receiver called clean, re-anchored, and being held while the reset lands.
///
/// While held, the descent arms that read our own queue and budget (`growing`, `queue_late`,
/// `coarse`, `throttled`) bank nothing, since what they would read is the collapse itself, and the
/// budget and climb gate read the capacity evidence instead of the collapsed estimate. The brake
/// and `cpu_bound` still act: a clean collapse says nothing about the receiver or the processor.
///
/// Ends on the first of: the estimate comes back to within half of the restart value; the receiver
/// stops calling the path clean; [`CLEAN_COLLAPSE_HOLD`] passes.
#[derive(Debug, Clone, Copy, PartialEq)]
struct CleanCollapse {
    anchor_kbps: u32,
    held: Duration,
    /// The divergence the re-anchor was decided on, as a percentage; the hold counts as recovered
    /// once the estimate is back inside it. [`REANCHOR_DIVERGENCE_PCT`], or
    /// [`OUTAGE_DIVERGENCE_PCT`] for an outage's end, which would otherwise "recover" on the next
    /// tick with the smoother still showing the outage.
    recovered_pct: u64,
}

/// A media path change awaiting a re-probe verdict ([`ReanchorTrigger::PathChange`]): the pair
/// before and after, and the round trips. See [`QualityController::note_path_move`].
#[derive(Debug, Clone, Copy, PartialEq)]
struct PathMove {
    from: Option<PathKind>,
    to: Option<PathKind>,
    /// The old path's round trip: its baseline, or its last fresh report when it had none yet.
    old_rtt_ms: Option<u32>,
    /// The least fresh round trip reported since the change, and how many such reports.
    new_rtt_min_ms: Option<u32>,
    new_reports: u32,
    /// Since the change. Judged for [`PATH_JUDGE_WINDOW`].
    age: Duration,
}

impl PathMove {
    /// Whether the move qualifies for a re-probe, and on what: `kind` (a more direct pair) or `rtt`
    /// (a round trip at most half the old path's: [`QualityPolicy::path_reprobe_rtt_factor`]).
    fn qualifies(&self, rtt_factor: u32) -> Option<&'static str> {
        if let (Some(from), Some(to)) = (self.from, self.to) {
            if to > from {
                return Some("kind");
            }
        }
        match (self.old_rtt_ms, self.new_rtt_min_ms) {
            (Some(old), Some(new)) if new.saturating_mul(rtt_factor) <= old => Some("rtt"),
            _ => None,
        }
    }
}

/// Drain mode in force: the path is holding a backlog of ours, and nothing more is encoded until it
/// has drained. See [`QualityController::draining`].
#[derive(Debug, Clone, Copy, PartialEq)]
struct Drain {
    /// Since it began.
    held: Duration,
    /// The baseline the exit band is measured against, as it was before the stall; `None` when none
    /// existed or the path changed during the drain. See [`QualityController::drain_exit_below`].
    ref_ms: Option<u32>,
    /// The round trip of the report that began it, and the worst reported during it.
    entered_rtt_ms: u32,
    peak_rtt_ms: u32,
    /// What the resume budget is a share of: the capacity evidence at entry, or what we were sending
    /// when there was none. See [`DRAIN_RESUME_SHARE_PCT`].
    resume_basis_kbps: u32,
    /// Fresh reports read during it, for the exit line.
    reports: u32,
    /// The last fresh report's round trip, and the intervals since without one: a receiver with
    /// nothing new of ours is how a drained backlog looks. See [`DRAIN_DRAINED_STALE`].
    last_rtt_ms: u32,
    stale: u32,
    /// Since the last fresh report that proved a backlog (the round trip past
    /// [`DRAIN_ENTER_RTT_MS`]). See [`DRAIN_MAX`].
    since_proof: Duration,
    /// When it began on the viewer-delivery clock (only a viewer report that reached us after this
    /// is about the drain), and the frames a second we handed the transport over the two seconds
    /// before: the rate the viewer must receive at for its count to end the drain. See
    /// [`DRAIN_LEAVE_WITHIN_MS`].
    began_at: Duration,
    sent_before_fps: f64,
}

impl Drain {
    /// What the budget resumes at when it ends. See [`DRAIN_RESUME_SHARE_PCT`].
    fn resume_kbps(&self, policy: &QualityPolicy) -> u32 {
        u32::try_from(u64::from(self.resume_basis_kbps) * policy.drain_resume_share_pct / 100)
            .unwrap_or(u32::MAX)
            .max(ABSOLUTE_FLOOR_KBPS)
    }
}

/// What one of the viewer's `vv` reports says about the frames it received, for
/// [`QualityController::note_viewer_frames`]. Untrusted numbers: a viewer can only affect its own
/// session, and at worst prevents or shortens a drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewerFrames {
    /// Frames the viewer has received this session (inbound-rtp `framesReceived`), cumulative.
    pub received: u64,
    /// The viewer's own clock as it made the report (`video.currentTime`, ms). `None` when the
    /// report carries none: such a report is never current evidence.
    pub viewer_ms: Option<u64>,
    /// How long before the tick it is handed over on the report reached the agent.
    pub age: Duration,
}

/// One tick of what we handed the transport, cumulative, on the delivery clock.
#[derive(Debug, Clone, Copy, PartialEq)]
struct SentMark {
    at: Duration,
    frames: u64,
    bytes: u64,
}

/// The viewer's previous report, for its interval and what it received over it.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PrevReport {
    at: Duration,
    received: u64,
    viewer_ms: Option<u64>,
}

/// One viewer report read against what we sent. See [`Delivery::read`].
#[derive(Debug, Clone, Copy, PartialEq)]
struct DeliveryReading {
    /// When it reached us, on the delivery clock.
    at: Duration,
    /// How much later it came than the least-delayed of the viewer's recent reports, by the
    /// viewer's own clock; `None` when it carries no clock.
    late_ms: Option<u32>,
    /// Frames the viewer received over its interval, and the interval: its own clock's when that is
    /// sane, else the time between the two reports' arrivals and at least a second.
    frames: u64,
    interval_ms: u32,
    /// Ours still in flight as of the report (frames handed over a base round trip before it
    /// reached us that the viewer had not received, beyond the clean-path reference), and their
    /// bytes. `None` without a reference or baseline, or past the history kept.
    in_flight_frames: Option<f64>,
    in_flight_bytes: Option<f64>,
    /// Our bytes the viewer received over its interval, and as kbps. `None` as above, or for a
    /// first report. A frame counts in the second it completes, so decisions read it over two
    /// reports or a whole drain.
    delivered_bytes: Option<f64>,
    goodput_kbps: Option<u32>,
}

impl DeliveryReading {
    /// Came on time by the viewer's clock: about the path as it is, not about a data channel held up
    /// behind our own queue. See [`DELIVERY_FRESH_LATE_MS`].
    fn on_time(&self, policy: &QualityPolicy) -> bool {
        self.late_ms
            .is_some_and(|l| l <= policy.delivery_fresh_late_ms)
    }

    /// Frames of ours the viewer received a second, over its interval.
    fn fps(&self) -> f64 {
        self.frames as f64 * 1000.0 / f64::from(self.interval_ms.max(1))
    }

    /// How long what is in flight takes to reach the viewer at the rate this report says ours
    /// reached it, ms: the longer of frames at its frame rate and bytes at its byte rate (a
    /// keyframe in flight is one frame and many bytes). 0 when nothing is in flight
    /// ([`DELIVERY_NONE_IN_FLIGHT`]), `None` when nothing of ours reached it or it cannot be
    /// priced.
    fn in_flight_ms(&self) -> Option<u32> {
        let frames = self.in_flight_frames?;
        if frames <= DELIVERY_NONE_IN_FLIGHT {
            return Some(0);
        }
        let fps = self.fps();
        if fps <= 0.0 {
            return None;
        }
        let by_frames = frames * 1000.0 / fps;
        // Bytes times eight over kilobits a second is milliseconds.
        let by_bytes = match (self.in_flight_bytes, self.goodput_kbps.filter(|&k| k > 0)) {
            (Some(b), Some(k)) => b * 8.0 / f64::from(k),
            _ => 0.0,
        };
        Some(by_frames.max(by_bytes).min(f64::from(u32::MAX)) as u32)
    }
}

/// What the viewer's count says about drain mode, as of a decision. See
/// [`QualityController::delivery_verdict`].
#[derive(Debug, Clone, Copy, PartialEq)]
enum DeliveryVerdict {
    /// No current word from the viewer: the round trip decides alone.
    Unknown(&'static str),
    /// On time, and our data is reaching it: little or nothing in flight, at least as fast as we
    /// send.
    Delivering(DeliveryReading),
    /// On time, and our data is not reaching it that fast: a backlog by its own count.
    Queued(DeliveryReading),
}

/// The viewer's delivery of our frames: what we handed the transport, per tick, against the
/// viewer's reports. See [`DELIVERY_FRESH_LATE_MS`], [`QualityController::note_viewer_frames`].
#[derive(Debug, Clone, Default)]
struct Delivery {
    /// Its own clock: the controller's ticks, summed.
    clock: Duration,
    /// What we had handed the transport at each tick, the last [`DELIVERY_HISTORY_TICKS`].
    sent: std::collections::VecDeque<SentMark>,
    /// Handed over by the control task before the tick that takes them.
    sent_pending: Option<(u64, u64)>,
    report_pending: Option<ViewerFrames>,
    /// Arrival less the viewer's clock, ms, of its recent reports: the least is "on time".
    offsets: std::collections::VecDeque<i64>,
    prev: Option<PrevReport>,
    /// Our frames in flight on a clean path by the two counts — the reference everything in flight
    /// is measured from — and the clean readings it is the least of. See [`DELIVERY_FLOOR_WINDOW`].
    floor: Option<f64>,
    floor_samples: std::collections::VecDeque<(Duration, f64)>,
    /// The last report read, and whether on the tick in progress.
    reading: Option<DeliveryReading>,
    read_this_tick: bool,
    /// What the last two reports said reached the viewer: our frames and bytes, and the interval by
    /// its clock.
    recent: std::collections::VecDeque<(u64, f64, u32)>,
}

impl Delivery {
    /// One tick: the clock moves, and what we had handed the transport by now is kept.
    fn advance(&mut self, dt: Duration) {
        self.clock = self.clock.saturating_add(dt);
        self.read_this_tick = false;
        if let Some((frames, bytes)) = self.sent_pending.take() {
            self.sent.push_back(SentMark {
                at: self.clock,
                frames,
                bytes,
            });
            while self.sent.len() > DELIVERY_HISTORY_TICKS {
                self.sent.pop_front();
            }
        }
    }

    /// Our frames handed to the transport by `t`, between ticks by straight line; `None` before the
    /// history kept.
    fn frames_sent_at(&self, t: Duration) -> Option<f64> {
        let first = self.sent.front()?;
        if t < first.at {
            return None;
        }
        let i = self.sent.partition_point(|m| m.at <= t);
        let a = self.sent[i - 1];
        let Some(b) = self.sent.get(i).copied() else {
            return Some(a.frames as f64);
        };
        let span = (b.at - a.at).as_secs_f64();
        let k = if span > 0.0 {
            (t - a.at).as_secs_f64() / span
        } else {
            1.0
        };
        Some(a.frames as f64 + (b.frames as f64 - a.frames as f64) * k)
    }

    /// Our bytes handed to the transport up to frame `n` of our count, between ticks by straight
    /// line; `None` for a frame older than the history kept.
    fn bytes_at_frame(&self, n: f64) -> Option<f64> {
        let first = self.sent.front()?;
        if n < first.frames as f64 {
            return None;
        }
        let i = self.sent.partition_point(|m| (m.frames as f64) < n);
        let Some(b) = self.sent.get(i).copied() else {
            return self.sent.back().map(|m| m.bytes as f64);
        };
        if i == 0 {
            return Some(b.bytes as f64);
        }
        let a = self.sent[i - 1];
        let span = b.frames as f64 - a.frames as f64;
        let k = if span > 0.0 {
            (n - a.frames as f64) / span
        } else {
            1.0
        };
        Some(a.bytes as f64 + (b.bytes as f64 - a.bytes as f64) * k)
    }

    /// What we handed the transport over the last `over`, kbps (0 without the history).
    fn sent_kbps(&self, over: Duration) -> u32 {
        let (Some(last), Some(first)) = (self.sent.back(), self.sent.front()) else {
            return 0;
        };
        let from = last.at.saturating_sub(over);
        let i = self.sent.partition_point(|m| m.at < from);
        let a = self.sent.get(i).copied().unwrap_or(*first);
        let ms = (last.at - a.at).as_millis();
        if ms == 0 {
            return 0;
        }
        u32::try_from(u128::from(last.bytes.saturating_sub(a.bytes)) * 8 / ms).unwrap_or(u32::MAX)
    }

    /// Frames we handed the transport a second over the last `over` (0 without the history).
    fn sent_fps(&self, over: Duration) -> f64 {
        let (Some(last), Some(first)) = (self.sent.back(), self.sent.front()) else {
            return 0.0;
        };
        let from = last.at.saturating_sub(over);
        let i = self.sent.partition_point(|m| m.at < from);
        let a = self.sent.get(i).copied().unwrap_or(*first);
        let s = (last.at - a.at).as_secs_f64();
        if s <= 0.0 {
            return 0.0;
        }
        last.frames.saturating_sub(a.frames) as f64 / s
    }

    /// Forget the viewer's side — its clock, its last report, the clean-path reference: they
    /// described a path, or a receiver, that is gone. What we sent stays.
    fn reset(&mut self, why: &'static str) {
        if self.prev.is_some() || self.floor.is_some() {
            tracing::debug!(
                why,
                floor_frames = ?self.floor.map(|f| f.round() as i64),
                reports = self.offsets.len(),
                "viewer delivery: its reports start over (no current word from the viewer until the \
                 next on-time report on a clean path sets the reference again)"
            );
        }
        self.offsets.clear();
        self.prev = None;
        self.floor = None;
        self.floor_samples.clear();
        self.reading = None;
        self.report_pending = None;
        self.recent.clear();
    }

    /// Frames a second and kbps of ours reaching the viewer over its last two reports, so one frame
    /// completing in a second is not read as the path's rate. `None` without two.
    fn recent_rates(&self) -> Option<(f64, u32)> {
        if self.recent.len() < 2 {
            return None;
        }
        let (frames, bytes, ms) = self
            .recent
            .iter()
            .fold((0u64, 0.0, 0u64), |(f, b, m), (ff, bb, mm)| {
                (f + ff, b + bb, m + u64::from(*mm))
            });
        (ms > 0).then(|| {
            (
                frames as f64 * 1000.0 / ms as f64,
                (bytes * 8.0 / ms as f64).min(f64::from(u32::MAX)) as u32,
            )
        })
    }

    /// Read a viewer report against what we sent. `base_ms` is the round-trip baseline (frames
    /// handed over that long before it reached us should have arrived); `clean_path` lets an
    /// on-time reading join the reference ([`DELIVERY_FLOOR_WINDOW`]).
    fn read(
        &mut self,
        policy: &QualityPolicy,
        r: ViewerFrames,
        base_ms: Option<u32>,
        clean_path: bool,
    ) -> DeliveryReading {
        let at = self.clock.saturating_sub(r.age);
        if let Some(p) = self.prev {
            let clock_back = matches!((r.viewer_ms, p.viewer_ms), (Some(n), Some(o)) if n < o);
            if r.received < p.received || clock_back {
                tracing::debug!(
                    received = r.received,
                    was_received = p.received,
                    viewer_ms = ?r.viewer_ms,
                    was_viewer_ms = ?p.viewer_ms,
                    "viewer delivery: the viewer's count or clock went back (a new receiver or video \
                     element)"
                );
                self.reset("viewer-counters-back");
            }
        }
        let late_ms = r.viewer_ms.map(|v| {
            let off = i64::try_from(at.as_millis())
                .unwrap_or(i64::MAX)
                .saturating_sub(i64::try_from(v).unwrap_or(i64::MAX));
            self.offsets.push_back(off);
            while self.offsets.len() > DELIVERY_LATE_REPORTS {
                self.offsets.pop_front();
            }
            let least = self.offsets.iter().copied().min().unwrap_or(off);
            u32::try_from(off.saturating_sub(least)).unwrap_or(u32::MAX)
        });
        let on_time = late_ms.is_some_and(|l| l <= policy.delivery_fresh_late_ms);
        let prev = self.prev;
        let frames = prev.map_or(0, |p| r.received.saturating_sub(p.received));
        let interval_ms = prev.map_or(1_000, |p| {
            let by_viewer = match (r.viewer_ms, p.viewer_ms) {
                (Some(n), Some(o)) => Some(n.saturating_sub(o)),
                _ => None,
            };
            let by_arrival = u64::try_from(at.saturating_sub(p.at).as_millis()).unwrap_or(u64::MAX);
            let ms = by_viewer
                .filter(|ms| (250..=5_000).contains(ms))
                .unwrap_or_else(|| by_arrival.max(1_000));
            u32::try_from(ms).unwrap_or(u32::MAX)
        });
        let expected = base_ms.and_then(|b| {
            self.frames_sent_at(at.saturating_sub(Duration::from_millis(u64::from(b))))
        });
        let shortfall = expected.map(|e| e - r.received as f64);
        if let (true, true, Some(s)) = (clean_path, on_time, shortfall) {
            self.floor_samples.push_back((at, s));
        }
        while self
            .floor_samples
            .front()
            .is_some_and(|(t, _)| at.saturating_sub(*t) > policy.delivery_floor_window())
            && self.floor_samples.len() > 1
        {
            self.floor_samples.pop_front();
        }
        if !self.floor_samples.is_empty() {
            let least = self
                .floor_samples
                .iter()
                .map(|(_, s)| *s)
                .fold(f64::INFINITY, f64::min);
            if self.floor.is_none() {
                tracing::debug!(
                    floor_frames = least.round() as i64,
                    late_ms = ?late_ms,
                    base_ms = ?base_ms,
                    "viewer delivery: the reference for our frames in flight on a clean path is set \
                     — the viewer's count is evidence for drain mode from here"
                );
            }
            self.floor = Some(least);
        }
        let in_flight_frames = match (shortfall, self.floor) {
            (Some(s), Some(f)) => Some((s - f).max(0.0)),
            _ => None,
        };
        let in_flight_bytes = match (expected, in_flight_frames) {
            (Some(e), Some(n)) => self
                .bytes_at_frame(e)
                .zip(self.bytes_at_frame(e - n))
                .map(|(hi, lo)| (hi - lo).max(0.0)),
            _ => None,
        };
        let delivered_bytes = match (prev, self.floor) {
            (Some(p), Some(f)) => self
                .bytes_at_frame(r.received as f64 + f)
                .zip(self.bytes_at_frame(p.received as f64 + f))
                .map(|(hi, lo)| (hi - lo).max(0.0)),
            _ => None,
        };
        let goodput_kbps = delivered_bytes
            .map(|b| (b * 8.0 / f64::from(interval_ms.max(1))).min(f64::from(u32::MAX)) as u32);
        match delivered_bytes {
            Some(b) => {
                self.recent.push_back((frames, b, interval_ms));
                while self.recent.len() > 2 {
                    self.recent.pop_front();
                }
            }
            None => self.recent.clear(),
        }
        self.prev = Some(PrevReport {
            at,
            received: r.received,
            viewer_ms: r.viewer_ms,
        });
        let reading = DeliveryReading {
            at,
            late_ms,
            frames,
            interval_ms,
            in_flight_frames,
            in_flight_bytes,
            delivered_bytes,
            goodput_kbps,
        };
        self.reading = Some(reading);
        self.read_this_tick = true;
        reading
    }
}

/// What drain mode did on a tick, for the control task to log and act on. See
/// [`QualityController::take_drain_event`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DrainEvent {
    /// The path is holding a backlog: stop encoding.
    Entered {
        /// The report round trip that completed the evidence.
        rtt_ms: u32,
        /// The pre-stall baseline, and the line the report crossed.
        ref_ms: Option<u32>,
        enter_at_ms: u32,
        /// Whether a silence was one of the two pieces of evidence.
        by_silence: bool,
        /// What we were sending over the interval before, and the budget.
        sent_kbps: u32,
        budget_kbps: u32,
    },
    /// The backlog drained (`report`: a report inside the band; `drained`: [`DRAIN_DRAINED_STALE`];
    /// `delivered`: [`DRAIN_LEAVE_WITHIN_MS`]) or [`DRAIN_MAX`] passed (`timeout`): resume with a
    /// keyframe at `resume_kbps`.
    Left {
        why: &'static str,
        /// The report that ended it, and the band it was under; `None` on a timeout.
        rtt_ms: Option<u32>,
        exit_below_ms: u32,
        held_ms: u64,
        peak_rtt_ms: u32,
        reports: u32,
        resume_kbps: u32,
    },
}

/// How often the controller runs, regardless of what arrives from the network.
pub const TICK: Duration = Duration::from_millis(200);

/// Accumulate a dwell time, decaying at half rate when the condition lapses.
///
/// Never a reset: a signal briefly missing or disagreeing should cost a little evidence, not all
/// of it, and the decision should not depend on the caller's sampling rate.
fn accumulate(held: Duration, condition: bool, dt: Duration) -> Duration {
    if condition {
        held.saturating_add(dt)
    } else {
        held.saturating_sub(dt / 2)
    }
}

/// Picks a rung from a bandwidth estimate, with hysteresis.
pub struct QualityController {
    src_w: u32,
    src_h: u32,
    quality: Quality,
    index: usize,
    /// When the estimate first justified a move in the direction it is still justifying.
    down_dwell: Duration,
    up_dwell: Duration,
    /// The median of `recent` as of the last observation, or 0 before the first. Kept because the
    /// encoder's budget reads it every frame and the ladder must decide on the same number.
    smoothed: u32,
    /// The local send queue as a fraction of [`QUEUE_GUARD_MS`], at the last observation.
    ///
    /// Zero is an empty pipe and one is the whole latency budget. The numerator is milliseconds of
    /// real queue at the pacer's real rate; the denominator is a constant. A credit that grows with
    /// the frames it meters makes the ratio blind to frame size.
    pressure: f32,
    /// The ladder's inputs, smoothed over roughly its own reaction time.
    ///
    /// The controller ticks every 200 ms and the ladder decides over 2 to 8 seconds; at 8 fps a
    /// tick holds 1.6 frames, and one frame's quantiser is not the session's. Read raw, the four
    /// climb conditions held together in only 14% of seconds at 360p@8 on a link with three times
    /// the bandwidth in use, while [`accumulate`] needs over a third to progress: the ladder could
    /// descend and never climb back (42 s parked at the bottom rung).
    ///
    /// An exponential mean at [`SIGNAL_ALPHA`] gives a time constant near 1.6 s: long enough that
    /// one frame cannot decide, short enough to react inside the descent dwell.
    qp_smoothed: Option<f32>,
    /// The queue's measured age, smoothed, with the settle after a move left out: the move's own
    /// keyframe is not evidence against the rung it bought. The ladder's network signal while the
    /// receiver reports no trouble. See [`Self::late_for_ladder`].
    late_smoothed: f32,
    /// The same filter fed through the settle too: what the ladder reads once the receiver reports
    /// loss, a queue at the brake's line, or a brake of its own, because then the settle's queue is
    /// the link failing and not only our pacer. See [`Self::late_for_ladder`].
    late_with_settle: f32,
    /// Which of the two the ladder read on the last tick (true: `late_with_settle`), and how long
    /// since that choice was last logged at debug.
    late_source_logged: bool,
    since_late_source_log: Duration,
    /// Time left before this rung may be judged. See `SETTLE_AFTER_MOVE`.
    settling: Duration,
    /// Produced bits over bits that actually left the socket, smoothed. See `growing` in tick.
    growth_smoothed: f32,
    /// How much of its allowance the encoder is using, smoothed. Gates the quantiser.
    spend_smoothed: f32,
    /// What fraction of offered frames the brake is withholding, smoothed. See [`DROP_SHARE`].
    drop_smoothed: f32,
    /// Quantiser samples gathered since the last rung change. See `QP_MIN_SAMPLES`.
    qp_seen: u32,
    /// What left the socket in each of the last [`EGRESS_WINDOW`] ticks, in kbps. Its maximum
    /// bounds the budget (see [`Self::unpushed_kbps`]). Zeros before the first second, which only
    /// tightens the bound.
    egress_recent: [u32; EGRESS_WINDOW],
    egress_at: usize,
    /// The last estimate taken while the link was actually in use, in kbps, decaying.
    ///
    /// str0m's delay estimate is bounded by acked traffic (`observed * 1.5 + 10 kbps`), so on a
    /// still screen it decays to the padding rate within seconds: a measurement of our silence, not
    /// the link. Measured, a seven-second pause on a link that carried 15 Mbps:
    ///
    /// ```text
    /// 21:36:07  900p   est 5298                       video, healthy
    /// 21:36:09  still screen, 1 fps offered
    /// 21:36:16  est  661                              the estimate has collapsed
    /// 21:36:17  motion resumes, bud 328-725 on 1080p@60: qp 46, dropper 0.96, queue 100-330 ms
    /// 21:36:23  -> 1080p@30      21:36:28  -> 900p      21:36:34  -> 720p
    /// ```
    ///
    /// A remembered capacity risks over-committing a link that narrowed while we were quiet (a
    /// remembered peak once put 367 kB in the send queue; see [`Self::unpushed_kbps`]). This one is
    /// safe because over-commitment is caught within a second (pushback halves the budget at 75 ms
    /// of queue age, `crate::frame_dropper` withholds frames, `queue_late`/`growing` shed the rung
    /// after two seconds) and because it corrects itself by sending:
    ///
    /// - The link is fine and the screen paused: the first motion is served at about the last
    ///   loaded estimate, and the estimate re-rises under real traffic within a second.
    /// - The link narrowed while idle: the first motion over-commits briefly, egress reaches the
    ///   reduced capacity, str0m decreases to 0.85x acked, the two fall inside the band `loaded`
    ///   tests for, and this follows the estimate down within a tick or two.
    ///
    /// The band's upper edge ([`LEADING_SHARE_PCT`], applied to the maximum of [`EGRESS_WINDOW`])
    /// keeps the first case from erasing itself: egress above a collapsed estimate is the estimate
    /// lagging. The pacer drains at `estimate * 1.1`, so a budget above the estimate queues inside
    /// str0m; [`Self::take_bwe_reanchor`] corrects that from this value or the capacity evidence.
    ///
    /// Set, not maximised: under load it follows the estimate down as readily as up. Set downward
    /// only once agreement has held for [`LOADED_CONFIRM`], because a collapsing estimate passes
    /// through the band on its way down. Not cleared by [`Self::moved`]: it describes the link.
    informative_kbps: u32,
    /// How long since the link last agreed with the estimate. See `measured` in [`Self::tick`].
    /// Starts at [`Duration::MAX`]: a fresh session has measured nothing.
    since_loaded: Duration,
    /// How long the link has been agreeing with the estimate without interruption: the question
    /// [`LOADED_CONFIRM`] asks, which a single coincident window ([`Self::since_loaded`]) does not
    /// answer. Reset by any tick that is not loaded.
    loaded_streak: Duration,
    /// What the encoder is producing, smoothed: prices a candidate rung from the content (see
    /// `best_affordable` in [`Self::tick`]). Cleared on a move.
    produced_smoothed: f32,
    /// Whether media has ever left the socket on this session.
    ///
    /// Read by [`Self::encoder_target_kbps`] (an unknown link and an idle one look identical in the
    /// estimate and want opposite budgets) and by `queue_late`, `growing` and the re-anchor
    /// decision in [`Self::tick`], none of which may act on a path that has carried nothing.
    ///
    /// Not an estimate: str0m publishes its configured `INITIAL_BITRATE_KBPS` (600) before any
    /// feedback. Not any egress: the transport counts ICE checks, TURN allocations and consent
    /// refreshes. Either way `growing` (`produced / max(egress, 120)`) shed rungs before the first
    /// frame was delivered, and a startup decision could be made on a session that never connected.
    ///
    /// So warm needs media: str0m emits `MediaEgressStats` ([`Feedback::report`]) only for a stream
    /// that has sent RTP (`streams/send_stats.rs`, `fill` returns early while `bytes == 0`), and a
    /// tick of [`MEDIA_EGRESS_KBPS`] is a rate connection setup never reaches, which lets the
    /// opening keyframe's tick count without waiting for str0m's stats clock.
    warm: bool,
    /// The first estimate this session saw, and whether any later one differed from it.
    ///
    /// An estimate that never moved from str0m's configured 600 is our configuration, not a
    /// measurement; the startup peak and the capacity evidence skip it. On a recorded 3G path that
    /// read 600 for four seconds and 161-204 after, a "peak" of 600 would have priced the startup
    /// jump at 540p on a link carrying a third of that.
    first_estimate: Option<u32>,
    estimate_moved: bool,
    /// The best recent evidence of what the path carries, in kbps, decaying on
    /// [`INFORMATIVE_HALF_LIFE`]. Read through [`Self::capacity_kbps`], which takes the larger of
    /// this and [`Self::informative_kbps`].
    ///
    /// The informative rate is set only while the link is loaded (egress within `[65%, 110%]` of
    /// the estimate), and scrolling text is loaded only in the wrong places: after each collapse
    /// the pacer limits egress to 1.1x the collapsed estimate, inside the band by construction. On
    /// a recorded Wi-Fi session it sat at 430-870 for most of the first eighty seconds while
    /// str0m's ALR probes lifted the estimate to 3000-4300; a probe is the network carrying a burst
    /// at that rate and the feedback confirming it.
    ///
    /// So this holds the largest of the estimate and the egress the path carried, taken only on
    /// ticks the receiver calls the path clean ([`QualityController::path_clean`]). Egress into a
    /// queue is what we pushed into a buffer, not what the path carried (a 3G path "sent" 1100 kbps
    /// with a one-second round trip). Egress is admitted a report late: a burst counts only when
    /// both receiver reports bracketing it are clean (no real loss, round trip inside the clean
    /// margin), and an interval without a report voids the bracket. Admitting it on the tick it
    /// left recorded 200 ms bursts into a simulated 700 kbps link's buffer as 778 and 1176 kbps of
    /// capacity, and a re-anchor at those values was followed by 96% loss. The estimate needs no
    /// bracket: it is already the receiver's account.
    ///
    /// Lowered by the half-life and the brake, not by agreement under load: after a collapse the
    /// estimate and egress agree at the collapsed value for seconds. A real narrowing queues, the
    /// receiver says so, and the brake cuts this and the informative rate to what it got.
    capacity_kbps: u32,
    /// A clean collapse being held: see [`CleanCollapse`].
    collapse: Option<CleanCollapse>,
    /// How many clean-collapse holds in a row have ended without the estimate recovering. See
    /// [`REANCHOR_BACKOFF_MAX`].
    reanchor_backoff: u32,
    /// What the pipeline line says about the estimate against the capacity evidence: `-`, `clean`,
    /// or the reason a collapse is not being treated as clean. See [`Self::collapse_state`].
    collapse_view: &'static str,
    /// The details of the last re-anchor decided, for the control task's log line.
    last_reanchor: Option<Reanchor>,
    /// The least round trip reported in the startup window, and whether the receiver has reported
    /// the link as congested inside it. See [`Self::startup_jump`].
    startup_rtt_min: Option<u32>,
    startup_evidence: Option<&'static str>,
    /// A re-anchor waiting to be handed to congestion control, in kbps. See
    /// [`Self::take_bwe_reanchor`] and the decision in [`Self::tick`].
    reanchor_kbps: Option<u32>,
    /// How long since the last re-anchor was decided. See [`REANCHOR_EVERY`]. Starts at
    /// [`Duration::MAX`] so that the first one is never rate-limited.
    since_reanchor: Duration,
    /// How long the sender has been application-limited without interruption. See
    /// [`APP_LIMITED_PCT`] and [`REANCHOR_AFTER_PAUSE`].
    app_limited_for: Duration,
    /// Time left in which a re-anchor may still fire after a qualifying pause ended. See
    /// [`REANCHOR_RESUME_WINDOW`].
    resume_window: Duration,
    /// Since the receiver last reported real loss, [`REAL_LOSS`] or more. [`Duration::MAX`] until
    /// it first does.
    since_real_loss: Duration,
    /// Since the last fresh receiver report, and since the last one whose round trip was past the
    /// clean margin ([`CLEAN_RTT_MARGIN_MS`]). [`Duration::MAX`] until each first happens.
    since_fresh: Duration,
    since_rtt_unclean: Duration,
    /// The last fresh report's round trip and loss, for the re-anchor's log line.
    last_fresh_rtt: Option<u32>,
    last_fresh_loss: Option<f32>,
    /// The loss/round-trip brake, when one is in force. See [`Self::take_brake_event`].
    brake: Option<Brake>,
    /// The brake's last move, waiting for the control task to log it.
    brake_event: Option<BrakeEvent>,
    /// The last [`RTT_BASE_REPORTS`] fresh round trips, in milliseconds; `rtt_seen` of them valid.
    rtt_recent: [u32; RTT_BASE_REPORTS],
    rtt_seen: usize,
    rtt_at: usize,
    /// Consecutive fresh reports whose round trip was past the inflation threshold.
    rtt_high_run: u32,
    /// The run of fresh round trips past the baseline's clean margin, watched for a path step.
    /// See [`Self::watch_path_step`].
    step: StepWatch,
    /// Consecutive stats intervals without a fresh receiver report while we were sending. Reset
    /// only by a fresh report or our going quiet, not by the cut it causes (which repeats every
    /// [`BRAKE_STALE_REPORTS`]). Non-zero means stale feedback ([`Self::feedback_live`]).
    stale_run: u32,
    /// The viewer's page is hidden (`crate::bg_hold`), so a silent receiver is the page asleep; and
    /// whether the current silence run was logged as such. See [`Self::set_page_hidden`].
    page_hidden: bool,
    hidden_silence_logged: bool,
    /// What remains of the post-hold window in which a very late or lossy report is the woken page
    /// describing its sleep, not the path. See [`HOLD_WAKE_WINDOW`].
    wake_window: Duration,
    /// Whether any fresh receiver report has arrived this session. Silence before the first one is
    /// the path not having reported yet, not the path having stopped.
    fresh_seen: bool,
    /// Egress summed over the ticks since the last report, and how many: what we sent over the
    /// interval the next report describes.
    report_egress_sum: u64,
    report_egress_ticks: u32,
    /// The mean egress of the previous report's interval. See [`BRAKE_BACKOFF`].
    prev_report_sent: u32,
    /// How long bytes have been leaving. The startup window's clock. See [`STARTUP_DECIDE_AFTER`].
    warm_for: Duration,
    /// The highest estimate seen since the first byte left, until the startup decision is made.
    startup_peak_kbps: u32,
    /// Time in the startup window with the encoder trying to fill its budget.
    startup_trying: Duration,
    /// Whether the startup decision has been made. It is made once.
    startup_done: bool,
    /// Why the ladder last moved, for the log line that reports the move.
    last_move_reason: &'static str,
    /// The resolution the viewer pinned, as an encoded height, or `None` for automatic. When set,
    /// the ladder is that height at [`PINNED_FPS`] instead of [`LADDER`].
    pinned: Option<u32>,
    /// The rungs for the current pin, rebuilt when it changes.
    pinned_rungs: Vec<Rung>,
    /// Which of the ladder's arms were last reported as active (see [`Arms`]), and how long since
    /// that line. Arms can flap on noisy signals, so a change is reported at most once per
    /// [`ARMS_LOG_EVERY`].
    arms_logged: Arms,
    /// Arms that would be active but are masked (by a held clean collapse or the startup slow
    /// start), as of the same line: each is a logged decision not to descend.
    masked_logged: Arms,
    since_arms_log: Duration,
    /// Whether the current run of loaded ticks has already been reported as confirming a lower
    /// informative floor. See the `loaded` block in [`Self::tick`].
    confirm_logged: bool,
    /// An outage the silence brake answered, waiting to see whether the receiver comes back clean.
    /// See [`ReanchorTrigger::OutageResume`].
    outage: Option<Outage>,
    /// Whether a climb held by stale feedback, and the startup slow-start mask, have been logged:
    /// one debug line per transition.
    climb_held_logged: bool,
    slow_start_logged: bool,
    /// Whether the path has produced capacity evidence since its last re-probe: before, the probe
    /// target is a multiple of [`Self::probe_best_kbps`]; after, of the evidence.
    evidence_seen: bool,
    /// Whether the probe opening is in force (the target at the ceiling while str0m runs its
    /// opening), from the session's start or a re-probe until [`PROBE_OPENING`] of
    /// `probe_path_for`.
    probe_opening: bool,
    /// Media time on the current path, every tick once warm (drain included), restarted at a
    /// re-probe: the clock of [`PROBE_OPENING`] and [`PROBE_RAMP`].
    probe_path_for: Duration,
    /// The session's time, every tick: what [`PROBE_OPENING_LATEST`] is measured on.
    probe_session_for: Duration,
    /// Whether this tick's estimate is the highest seen and was taken as a measurement (live, no
    /// receiver brake): the "still rising" of [`PROBE_RAMP`].
    estimate_at_best: bool,
    /// The highest estimate seen, in kbps: what the probe target is twice before the path has
    /// produced any capacity evidence. 0 while the estimate is str0m's configured opening value
    /// ([`STR0M_OPENING_KBPS`]); then taken on every tick whose feedback is live
    /// ([`Self::feedback_live`]) with no receiver brake in force. Not decayed: it bounds how far
    /// str0m may reach with nothing measured, and the evidence takes over at its first sample.
    /// Restarted at a path re-probe ([`ReanchorTrigger::PathChange`]).
    probe_best_kbps: u32,
    /// What str0m was last told to probe towards, as confirmed by the caller
    /// ([`Self::probe_target_sent`]); 0 before anything was. And how long ago.
    probe_sent_kbps: u32,
    since_probe_sent: Duration,
    /// A probe target waiting to be sent. See [`Self::take_probe_target`].
    probe_pending: Option<u32>,
    /// The last probe target the decision was logged for.
    probe_announced_kbps: u32,
    /// The most that left the socket in one tick since the last fresh report, the same for the
    /// interval before it (awaiting its bracket), and a peak both bracketing reports called clean,
    /// to be taken in this tick. See the `capacity_kbps` field.
    egress_open_kbps: u32,
    egress_pending_kbps: u32,
    egress_confirmed_kbps: u32,
    /// Drain mode, while in force. See [`Self::draining`].
    drain: Option<Drain>,
    /// Evidence toward drain mode since the last report under the line ([`DRAIN_EVIDENCE`]): count,
    /// kinds, and whether the current silence run was counted (once per run).
    drain_evidence: u32,
    drain_evidence_report: bool,
    drain_evidence_silence: bool,
    drain_silence_counted: bool,
    /// The round-trip baseline as it last stood with no evidence of a stall: what the entry line
    /// and exit band are measured against, kept through an outage's baseline reset (the first
    /// report after a silence would otherwise become the baseline, 6408 ms on one recorded 3G
    /// path).
    drain_ref_ms: Option<u32>,
    drain_event: Option<DrainEvent>,
    /// The viewer's own count of our frames, read against what we sent: the evidence that lets a
    /// drain not begin, or end, on the path as it is now. See [`Self::note_viewer_frames`].
    delivery: Delivery,
    /// Media produced and budget summed since the last report (over `report_egress_ticks`), for the
    /// silence rule. See [`SILENCE_MEDIA_SHARE_PCT`].
    report_produced_sum: u64,
    report_budget_sum: u64,
    /// The startup queue jump ([`Self::startup_queue_jump`]): egress and queue age over the last
    /// [`STARTUP_DRAIN_TICKS`], the decided rung, and whether a refusal was logged.
    startup_egress: [u32; STARTUP_DRAIN_TICKS],
    startup_queue_ages: [u32; STARTUP_DRAIN_TICKS],
    startup_egress_at: usize,
    startup_egress_seen: usize,
    startup_queue_target: Option<usize>,
    startup_queue_refusal_logged: bool,
    /// Whether the startup queue jump has been made (once per session), and how long media has been
    /// leaving outside drain mode — its window's clock. See [`STARTUP_QUEUE_WINDOW`].
    startup_queue_used: bool,
    media_for: Duration,
    /// Since the last fresh report at or past [`Self::rtt_queued_at`], or [`Duration::MAX`]. See
    /// [`Self::receiver_sees_no_queue`].
    since_rtt_queued: Duration,
    /// Whether the pacer-only mask is holding back `queue_late` or `growing`, so its start and end
    /// are one line each, and how long since one went out at debug (at most one per
    /// [`ARMS_LOG_EVERY`]; the rest at trace). See [`Self::pacer_only`].
    pacer_mask_logged: bool,
    since_pacer_mask_log: Duration,
    /// The oldest our own queue was during the settle in progress, for the line that ends it. See
    /// [`SETTLE_AFTER_MOVE`].
    settle_queue_peak_ms: u32,
    /// The rung the climb dwell has earned: the lowest the evidence pointed at on any tick that
    /// added to it, so a climb goes only as far as all of it reached. `None` without a dwell.
    up_target: Option<usize>,
    /// The encoder's per-frame time at this rung, in ms, smoothed at [`SIGNAL_ALPHA`]: what the
    /// climb gate prices a candidate rung against ([`ENCODE_CLIMB_SHARE`]); `cpu_bound` reads the
    /// tick's own mean. Fed only by ticks that encoded something and cleared by [`Self::moved`].
    /// `None` until a frame is encoded at this rung, which does not block a climb.
    encode_smoothed: Option<f32>,
    /// `cpu_bound` descents since the processor last held the shed rung for [`CPU_STREAK_FORGET`],
    /// that rung's index, and time spent at it or better. See [`Self::climb_dwell`].
    cpu_streak: u32,
    cpu_shed: Option<usize>,
    cpu_held: Duration,
    /// Whether an encoder-held climb was logged (rate-limited like `pacer_mask_logged`), and
    /// whether a climb waiting out the longer `cpu_bound` dwell was logged for this dwell.
    encode_hold_logged: bool,
    since_encode_hold_log: Duration,
    cpu_wait_logged: bool,
    /// Whether capacity evidence stands in for the estimate in the climb gate on an idle screen,
    /// for one line at start and end. See [`Self::idle_evidence`].
    idle_evidence_logged: bool,
    since_idle_evidence_log: Duration,
    /// Whether the informative floor was set while the estimate was still str0m's opening value
    /// (our configuration echoed back), forgotten when the estimate moves.
    informative_from_opening: bool,
    /// A media path change waiting to be judged for a re-probe, and how long since the last one went
    /// out. See [`Self::note_path_move`] and [`ReanchorTrigger::PathChange`].
    path_move: Option<PathMove>,
    since_path_reprobe: Duration,
    /// Send the probe target on the next decision regardless of [`PROBE_TARGET_EVERY`]: a
    /// re-probe's probes are held to twice the peer's target, which must be the new one first.
    probe_urgent: bool,
    /// Why str0m was last told to probe nothing ([`Self::probe_quiet`]), or `None`. A change goes
    /// out at once as one log line. See [`PROBE_QUIET_KBPS`].
    probe_quiet_was: Option<&'static str>,
    /// The most the path has been measured carrying since its evidence began (reset at a re-probe),
    /// for [`Self::probe_path_thin`], since the evidence decays through a still stretch.
    capacity_peak_kbps: u32,
    /// The highest estimate since the last stats interval closed. See [`ESTIMATE_DROP_LOG_PCT`].
    interval_estimate_peak: u32,
    /// Whether [`Self::set_source`] has had a real size, so the first is checked against the probe
    /// ceiling even when it equals the 1920x1080 guess. See [`Self::note_probe_ceiling_reach`].
    source_known: bool,
    /// The tuning, fixed for the session: every judgement the fields above are read against.
    policy: QualityPolicy,
}

/// Which of the ladder's arms are active on a tick, as bits. For the log only: the decision reads
/// the booleans themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Arms(u16);

impl Arms {
    const GROWING: u16 = 1 << 0;
    const COARSE: u16 = 1 << 1;
    const QUEUE_LATE: u16 = 1 << 2;
    const CPU_BOUND: u16 = 1 << 3;
    const THROTTLED: u16 = 1 << 4;
    const BRAKING: u16 = 1 << 5;
    const AFFORDABLE: u16 = 1 << 6;
    const STARVED: u16 = 1 << 7;

    const NAMES: [(u16, &'static str); 8] = [
        (Self::GROWING, "growing"),
        (Self::COARSE, "coarse"),
        (Self::QUEUE_LATE, "queue_late"),
        (Self::CPU_BOUND, "cpu_bound"),
        (Self::THROTTLED, "throttled"),
        (Self::BRAKING, "braking"),
        (Self::AFFORDABLE, "affordable"),
        (Self::STARVED, "starved"),
    ];

    fn set(&mut self, bit: u16, on: bool) {
        if on {
            self.0 |= bit;
        }
    }

    /// `growing+coarse`, or `-` for none: the arms by name, for a log field.
    fn names(self) -> String {
        let on: Vec<&str> = Self::NAMES
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| *name)
            .collect();
        if on.is_empty() {
            "-".to_string()
        } else {
            on.join("+")
        }
    }
}

impl QualityController {
    /// A controller on the reference policy ([`QualityPolicy::reference`]), for the tests:
    /// production names its policy ([`Self::with_policy`]).
    #[cfg(any(test, doc))]
    #[must_use]
    pub fn new(src_w: u32, src_h: u32, quality: Quality) -> Self {
        Self::with_policy(src_w, src_h, quality, QualityPolicy::reference())
    }

    /// A controller tuned by `policy`, which it keeps for the session and reads on every tick.
    #[must_use]
    pub fn with_policy(src_w: u32, src_h: u32, quality: Quality, policy: QualityPolicy) -> Self {
        Self {
            src_w,
            src_h,
            quality,
            index: policy.start_rung_index,
            down_dwell: Duration::ZERO,
            up_dwell: Duration::ZERO,
            smoothed: 0,
            pressure: 0.0,
            qp_smoothed: None,
            late_smoothed: 0.0,
            late_with_settle: 0.0,
            late_source_logged: false,
            since_late_source_log: Duration::MAX,
            settling: Duration::ZERO,
            // One, not zero: the neutral value of a ratio. Starting at zero delayed the ladder's
            // response to a growing backlog from 2 s to 3.6 s while the mean climbed to neutral.
            growth_smoothed: 1.0,
            spend_smoothed: 0.0,
            drop_smoothed: 0.0,
            qp_seen: 0,
            egress_recent: [0; EGRESS_WINDOW],
            egress_at: 0,
            informative_kbps: 0,
            since_loaded: Duration::MAX,
            loaded_streak: Duration::ZERO,
            produced_smoothed: 0.0,
            warm: false,
            first_estimate: None,
            estimate_moved: false,
            capacity_kbps: 0,
            collapse: None,
            reanchor_backoff: 0,
            collapse_view: "-",
            last_reanchor: None,
            startup_rtt_min: None,
            startup_evidence: None,
            reanchor_kbps: None,
            since_reanchor: Duration::MAX,
            app_limited_for: Duration::ZERO,
            resume_window: Duration::ZERO,
            since_real_loss: Duration::MAX,
            since_fresh: Duration::MAX,
            since_rtt_unclean: Duration::MAX,
            last_fresh_rtt: None,
            last_fresh_loss: None,
            brake: None,
            brake_event: None,
            rtt_recent: [0; RTT_BASE_REPORTS],
            rtt_seen: 0,
            rtt_at: 0,
            rtt_high_run: 0,
            step: StepWatch::default(),
            stale_run: 0,
            page_hidden: false,
            hidden_silence_logged: false,
            wake_window: Duration::ZERO,
            fresh_seen: false,
            report_egress_sum: 0,
            report_egress_ticks: 0,
            prev_report_sent: 0,
            warm_for: Duration::ZERO,
            startup_peak_kbps: 0,
            startup_trying: Duration::ZERO,
            startup_done: false,
            last_move_reason: "",
            pinned: None,
            pinned_rungs: Vec::new(),
            arms_logged: Arms::default(),
            masked_logged: Arms::default(),
            since_arms_log: Duration::MAX,
            confirm_logged: false,
            outage: None,
            climb_held_logged: false,
            slow_start_logged: false,
            evidence_seen: false,
            probe_opening: true,
            probe_path_for: Duration::ZERO,
            probe_session_for: Duration::ZERO,
            estimate_at_best: false,
            probe_best_kbps: 0,
            probe_sent_kbps: 0,
            since_probe_sent: Duration::MAX,
            probe_pending: None,
            probe_announced_kbps: 0,
            egress_open_kbps: 0,
            egress_pending_kbps: 0,
            egress_confirmed_kbps: 0,
            drain: None,
            drain_evidence: 0,
            drain_evidence_report: false,
            drain_evidence_silence: false,
            drain_silence_counted: false,
            drain_ref_ms: None,
            drain_event: None,
            delivery: Delivery::default(),
            report_produced_sum: 0,
            report_budget_sum: 0,
            startup_egress: [0; STARTUP_DRAIN_TICKS],
            startup_queue_ages: [0; STARTUP_DRAIN_TICKS],
            startup_egress_at: 0,
            startup_egress_seen: 0,
            startup_queue_target: None,
            startup_queue_refusal_logged: false,
            startup_queue_used: false,
            media_for: Duration::ZERO,
            since_rtt_queued: Duration::MAX,
            pacer_mask_logged: false,
            since_pacer_mask_log: Duration::MAX,
            settle_queue_peak_ms: 0,
            up_target: None,
            encode_smoothed: None,
            cpu_streak: 0,
            cpu_shed: None,
            cpu_held: Duration::ZERO,
            encode_hold_logged: false,
            since_encode_hold_log: Duration::MAX,
            cpu_wait_logged: false,
            idle_evidence_logged: false,
            since_idle_evidence_log: Duration::MAX,
            informative_from_opening: false,
            path_move: None,
            since_path_reprobe: Duration::MAX,
            probe_urgent: false,
            probe_quiet_was: None,
            capacity_peak_kbps: 0,
            interval_estimate_peak: 0,
            source_known: false,
            policy,
        }
    }

    /// The tuning this controller runs on.
    #[must_use]
    pub fn policy(&self) -> &QualityPolicy {
        &self.policy
    }

    /// The least time between two `ladder arms` lines: the descent dwell. A flapping arm (`growing`
    /// at a ratio of 0.9 to 1.02 is an ordinary healthy session) costs at most one line per dwell;
    /// a move is logged regardless.
    fn arms_log_every(&self) -> Duration {
        self.policy.down_after()
    }

    /// The rungs currently in play: the curated ladder, or one resolution at falling frame rates
    /// when the viewer has pinned it.
    fn rungs(&self) -> &[Rung] {
        if self.pinned.is_some() {
            &self.pinned_rungs
        } else {
            &self.policy.ladder
        }
    }

    #[must_use]
    pub fn current(&self) -> Rung {
        let rungs = self.rungs();
        rungs[self.index.min(rungs.len() - 1)]
    }

    /// Pin a resolution, or pass `None` to hand the choice back to the controller.
    ///
    /// Returns the rung to switch to when the setting changed. Resets to the opening rung of the
    /// new ladder rather than mapping the old position: the two ladders measure different things,
    /// and a viewer who asks for 1080p should get 1080p, not a degraded position they just
    /// overrode.
    pub fn set_pinned_height(&mut self, height: Option<u32>) -> Option<Rung> {
        if self.pinned == height {
            return None;
        }
        self.pinned = height;
        self.pinned_rungs = height
            .map(|h| {
                self.policy
                    .pinned_fps
                    .iter()
                    .map(|&fps| Rung { max_h: h, fps })
                    .collect()
            })
            .unwrap_or_default();
        // A pin opens at the top of its own ladder; unpinned, the ladder opens where a session does
        // (`start_rung_index`, a rung of the policy's ladder, checked on receipt).
        self.index = if height.is_some() {
            0
        } else {
            self.policy.start_rung_index
        };
        tracing::debug!(
            pinned = ?height,
            index = self.index,
            "ladder changed by the viewer's pin; opening at this rung of it"
        );
        // A pin is the viewer's explicit choice and is honoured above the profile's own top (a 1080
        // pin on the compiled 720p30 profile runs 1080p at `pinned_fps`); logged once per pin.
        let top_h = self.policy.ladder.first().map_or(0, |r| r.max_h);
        if let Some(h) = height.filter(|&h| h > top_h) {
            tracing::debug!(
                pinned_h = h,
                ladder_top_h = top_h,
                pinned_fps = ?self.policy.pinned_fps,
                "viewer's pin is above the profile ladder's top: honoured, at the profile's pinned \
                 frame rates"
            );
        }
        // The evidence was gathered on a different ladder.
        self.down_dwell = Duration::ZERO;
        self.up_dwell = Duration::ZERO;
        self.up_target = None;
        // So was the processor's: the rung it shed is an index into the ladder just replaced.
        if self.cpu_streak > 0 {
            tracing::debug!(
                streak = self.cpu_streak,
                pinned = ?height,
                "cpu_bound streak forgotten: the viewer changed the ladder, and the rung the \
                 processor shed was a rung of the old one"
            );
        }
        self.forget_cpu_streak();
        Some(self.current())
    }

    /// The pinned height, or `None` when the controller is choosing.
    #[must_use]
    pub fn pinned_height(&self) -> Option<u32> {
        self.pinned
    }

    /// What the current rung needs, for logging and for the viewer's quality indicator.
    #[must_use]
    pub fn current_required_kbps(&self) -> u32 {
        self.current()
            .required_kbps_with(&self.policy, self.src_w, self.src_h, self.quality)
    }

    /// The smoothed bandwidth estimate the controller is deciding on, in kbps. 0 before the first.
    #[must_use]
    pub fn smoothed_estimate_kbps(&self) -> u32 {
        self.smoothed
    }

    /// What to tell the encoder to spend, in kbps.
    ///
    /// The measured link, less a margin, less a pushback for what is in flight, capped by what the
    /// pixels can absorb. Deliberately not floored at the current rung's price: the ladder settles
    /// where the price meets the estimate, so such a floor would erase the [`SPEND_PCT`] margin
    /// that keeps the operating point off the cliff, leaving a zero-drift queue that crosses any
    /// nearby threshold again and again. A still screen below its budget leaves the pipe empty, so
    /// the first moving frame goes at once and QP recovers within 30 to 100 ms.
    ///
    /// The pushback has libwebrtc's `CongestionWindowPushbackController` shape: continuous in its
    /// input (a step would strobe), bounded, and never zero (a zero budget is a freeze).
    #[must_use]
    pub fn encoder_target_kbps(&self) -> u32 {
        ((f64::from(self.unpushed_kbps()) * self.pushback()) as u32).max(ABSOLUTE_FLOOR_KBPS)
    }

    /// A bitrate congestion control should be restarted from, in kbps, or `None`.
    ///
    /// Yielded at most once per decision: taking it clears it. The caller passes it to str0m's
    /// `Rtc::bwe().reset()` (`afklink_transport::PeerControl::ResetBwe`).
    ///
    /// str0m's pacer drains at `estimate * PACING_FACTOR` (1.1, `pacer/control.rs:49`) with no
    /// application lever, so a budget above the estimate queues inside str0m, whose delay
    /// controller reads that as overuse and decreases to `0.85 x acked`
    /// (`bwe/delay/rate_control.rs:248-270`), and acked after an idle stretch is ~50 kbps. Recorded
    /// two seconds after motion resumed against a budget of 5430: an estimate of 59 kbps, 146 to
    /// 325 ms of queue, three descents and 42 s back to 1080p@60. [`Self::informative_kbps`] cannot
    /// be spent unless the estimate moves.
    ///
    /// This is a starting point, not a remembered peak: `reset` rebuilds
    /// `SendSideBandwidthEstimator::new(init)` whole (`bwe/mod.rs:404`), and if the link narrowed
    /// the first feedback under load shows delay building and the estimate decreases from there.
    /// Applied at the resume rather than during the pause, because the rebuilt probe controller
    /// fires 3x and 6x of the init bitrate, which during a pause is tens of megabits of padding
    /// (cellular data on a phone) for nothing.
    ///
    /// Never where congestion control was right: a reset throws away str0m's measurement and probes
    /// on top. On a recorded 3G session, re-anchors at 1.25-1.96x a correct estimate were followed
    /// within six seconds by 1.75-25.6% loss, five times in eight. The receiver tells the cases
    /// apart: those went out with the round trip 35-65% over its baseline or near double-digit
    /// loss, while the collapses that should be served (str0m cutting to `0.85 x acked` on our own
    /// quiet between scroll bursts, `bwe/delay/rate_control.rs:250`) came with the round trip
    /// within 13 ms of baseline and no loss; refusing those walked a Wi-Fi session from 1080p60 to
    /// 360p in seventy seconds on a link carrying 3.5 Mbps. The clean-collapse trigger in
    /// [`Self::tick`] serves them; [`CLEAN_RTT_MARGIN_MS`], [`REAL_LOSS_MEMORY`] and the brake
    /// refuse the rest.
    ///
    /// See [`Self::last_reanchor`] for the numbers each one was decided on.
    #[must_use]
    pub fn take_bwe_reanchor(&mut self) -> Option<u32> {
        self.reanchor_kbps.take()
    }

    /// The last re-anchor decided, with its trigger and evidence, for the log line. Not cleared by
    /// [`Self::take_bwe_reanchor`].
    #[must_use]
    pub fn last_reanchor(&self) -> Option<Reanchor> {
        self.last_reanchor
    }

    /// The best recent evidence of what the path carries, in kbps: the larger of the loaded
    /// informative rate and the receiver-confirmed capacity. See the `capacity_kbps` field.
    #[must_use]
    pub fn capacity_kbps(&self) -> u32 {
        self.capacity_kbps.max(self.informative_kbps)
    }

    /// Whether the receiver's feedback is current: false from the first stats interval without a
    /// fresh receiver report while we are sending, until one arrives. Before the first report ever,
    /// and while we are not sending, silence is not staleness (as for the silence brake).
    ///
    /// When feedback stops the estimate does not: str0m's smoother emits the mean of the last three
    /// seconds of distinct values (`bwe/smoother.rs`), walking up as older, lower ones age out. On
    /// a bench blackout it read 8464 to 10476 with nothing arriving, and the ladder climbed to
    /// 1080p60, sending a keyframe and 9.5 Mbps into a dead link. So while feedback is stale
    /// nothing is learned from the estimate or egress: no climb, no loaded confirmation, no
    /// capacity sample, no startup peak. The budget still follows the estimate: its risk is the
    /// second before the silence brake, and one empty interval in five seconds is Chrome's normal
    /// cadence.
    ///
    /// One interval rather than [`BRAKE_STALE_REPORTS`], because the first empty interval is the
    /// first sign. On a healthy link this holds a climb (which pauses rather than decays) for at
    /// most one second in six.
    #[must_use]
    pub fn feedback_live(&self) -> bool {
        !(self.fresh_seen && self.stale_run > 0)
    }

    /// What [`Self::feedback_live`] will say once `report` has been read by [`Self::on_report`]: the
    /// same test the silence count makes there, on the same interval's egress.
    fn feedback_live_with(&self, report: Option<ReceiverReport>) -> bool {
        match report {
            None => self.feedback_live(),
            Some(r) if r.fresh() => true,
            Some(_) => !self.silence_counts(self.interval_means()),
        }
    }

    /// Means over the interval the next report closes, in kbps: egress, media produced (keyframes
    /// excluded, as [`Feedback::produced_kbps`]), and the encoder's budget.
    fn interval_means(&self) -> (u32, u32, u32) {
        let ticks = u64::from(self.report_egress_ticks);
        if ticks == 0 {
            return (0, 0, 0);
        }
        let mean = |sum: u64| u32::try_from(sum / ticks).unwrap_or(u32::MAX);
        (
            mean(self.report_egress_sum),
            mean(self.report_produced_sum),
            mean(self.report_budget_sum),
        )
    }

    /// Whether an interval without a fresh receiver report, having carried `(egress, produced,
    /// budget)`, counts as the receiver's silence: after the first report ever, never while
    /// draining, and only while we were asking the link for something: [`LOADED_FLOOR_KBPS`] of
    /// egress, or on a thinner link [`SILENCE_MEDIA_SHARE_PCT`] of the budget in media and at least
    /// [`SILENCE_MEDIA_FLOOR_KBPS`]. One definition for [`Self::on_report`] and
    /// [`Self::feedback_live`].
    fn silence_counts(&self, (sent, produced, budget): (u32, u32, u32)) -> bool {
        if !self.fresh_seen || self.drain.is_some() {
            return false;
        }
        if sent >= self.policy.loaded_floor_kbps {
            return true;
        }
        let media = sent.min(produced);
        media >= self.policy.silence_media_floor_kbps
            && u64::from(media) * 100 >= u64::from(budget) * self.policy.silence_media_share_pct
    }

    /// The bookkeeping every fresh report does, whatever else it decides: when the receiver last
    /// spoke, what it said, and the memory of real loss.
    fn record_fresh(&mut self, r: &ReceiverReport) {
        let loss = r.loss.unwrap_or(0.0).clamp(0.0, 1.0);
        self.since_fresh = Duration::ZERO;
        self.last_fresh_rtt = r.rtt_ms;
        self.last_fresh_loss = Some(loss);
        // Real loss, not the NACK-recovered tenths of a percent a relay always has. See
        // [`REAL_LOSS_MEMORY`].
        if loss >= self.policy.real_loss() {
            if self.since_real_loss >= self.policy.real_loss_memory() {
                tracing::debug!(
                    loss_pct = format!("{:.2}", loss * 100.0),
                    rtt_ms = ?r.rtt_ms,
                    "receiver reports real loss: re-anchors refused for the next {} s",
                    self.policy.real_loss_memory().as_secs()
                );
            }
            self.since_real_loss = Duration::ZERO;
        }
    }

    /// How long since the last fresh receiver report, or `None` before the first one. For the
    /// pipeline line: a round trip that is ten seconds old is not the path's round trip.
    #[must_use]
    pub fn report_age(&self) -> Option<Duration> {
        self.fresh_seen.then_some(self.since_fresh)
    }

    /// What congestion control should probe towards, in kbps.
    ///
    /// Twice the capacity evidence ([`Self::capacity_kbps`], [`PROBE_CAPACITY_MULTIPLE`]), never
    /// under [`probe_floor_kbps`] and never over the ladder's ceiling, [`desired_bitrate_kbps`].
    ///
    /// During the opening ([`PROBE_OPENING`], from the session's start or a path re-probe) it is
    /// the ceiling: str0m holds its opening and exponential probes to twice the target as they are
    /// queued, and a target that follows the estimate holds them back exactly while the link is
    /// answering.
    ///
    /// Before the path has produced evidence it is twice the best estimate seen
    /// ([`Self::probe_best_kbps`]; the floor while nothing is measured). libwebrtc probes an
    /// application-limited path at twice its estimate; str0m at twice desired, so this holds that
    /// probe to four times the best estimate, which the shallowest buffer on record holds. Best
    /// rather than current, so an early collapse does not also narrow exploration. A rise goes out
    /// on the tick it is decided ([`PROBE_TARGET_EVERY`]). The evidence takes over at its first
    /// sample ([`Self::update_probe_target`]).
    ///
    /// Sent through [`Self::take_probe_target`].
    #[must_use]
    pub fn probe_target_kbps(&self) -> u32 {
        let ceiling = desired_bitrate_kbps_with(&self.policy, self.src_w, self.src_h, self.quality);
        if self.probe_opening {
            return ceiling;
        }
        let floor = probe_floor_kbps_with(&self.policy, self.src_w, self.src_h).min(ceiling);
        let base = if self.evidence_seen {
            self.capacity_kbps()
        } else {
            self.probe_best_kbps
        };
        base.saturating_mul(self.policy.probe_capacity_multiple)
            .clamp(floor, ceiling)
    }

    /// Whether the probe opening is in force: the probe target at the ceiling while str0m runs its
    /// opening on this path. See [`PROBE_OPENING`].
    #[must_use]
    pub fn probe_opening(&self) -> bool {
        self.probe_opening
    }

    /// Why str0m should probe nothing right now, or `None`: then it is told [`PROBE_QUIET_KBPS`]
    /// instead of [`Self::probe_target_kbps`]. See [`PROBE_QUIET_KBPS`] for why at all.
    ///
    /// - `drain`: drain mode, on any path. The path holds a backlog of ours, and a probe's bytes
    ///   only join it.
    /// - `brake-loss`, `brake-rtt`: on a thin path ([`Self::probe_path_thin`]), a brake set by the
    ///   receiver's reports, until it has fully let go. Not a brake of silence alone, nor drain
    ///   mode's resume ceiling: neither is the receiver's word about the path.
    ///
    /// Through the release too: the brake holds media under 65% of the estimate, which is ALR by
    /// str0m's rule, and str0m answers a desired that rises in ALR with an allocation probe at once
    /// (`maybe_increase_alr`, `bwe/probe/control.rs:331-372`). In the simulator's `3g` analogue
    /// (700 kbps, 60 ms buffer, 1% loss, continuous scroll, ten seeds, medians), quiet only while
    /// engaged fired 11 such probes a run; quiet until released, 2, with keyframes 49 against 62,
    /// queue drops 412 against 576 and latency p95 504 against 802 ms. On the browser bench the
    /// keyframe difference was not visible, with frame age p95 748 against 1231 ms (p 0.18) and
    /// fewer brakes (8 against 14, p 0.024).
    ///
    /// Thin paths only for the brake: on a wide path a brake is a dip, and str0m's probes are how
    /// the estimate finds the room again. Never during the opening ([`PROBE_OPENING`]), where the
    /// probes are the point, nor during a background hold, which sets the same value itself
    /// (`crate::bg_hold`).
    #[must_use]
    pub fn probe_quiet(&self) -> Option<&'static str> {
        if self.probe_opening {
            return None;
        }
        if self.drain.is_some() {
            return Some("drain");
        }
        match self.brake {
            Some(b) if !b.silence_only && self.probe_path_thin() => {
                Some(if b.by_loss { "brake-loss" } else { "brake-rtt" })
            }
            _ => None,
        }
    }

    /// Whether the path has been measured thinner than the floor ([`probe_floor_kbps`]): by the
    /// most it has been measured carrying (`capacity_peak_kbps`, before decay, so a wide path that
    /// has been still is not taken for thin) or, before any evidence, the best estimate seen.
    /// Nothing measured yet counts as thin. See [`Self::probe_quiet`].
    ///
    /// Known limit: behind a deep queue the bracketed evidence can read far over the link (up to
    /// 2077 kbps on a bench path of 300 kbps behind a 30 s queue), and the peak keeps that sample,
    /// so the brake's quiet never ran in 4 of 15 such runs; drain mode's still did. A peak that
    /// forgets, or evidence a standing queue cannot inflate, would close it.
    fn probe_path_thin(&self) -> bool {
        let ceiling = desired_bitrate_kbps_with(&self.policy, self.src_w, self.src_h, self.quality);
        let floor = probe_floor_kbps_with(&self.policy, self.src_w, self.src_h).min(ceiling);
        let base = if self.evidence_seen {
            self.capacity_peak_kbps
        } else {
            self.probe_best_kbps
        };
        base < floor
    }

    /// Whether a rise of the probe target goes out at once despite capacity evidence
    /// ([`PROBE_RAMP`]), or why not: `over`, `cold`, `not-rising`, `brake`, `loss`.
    fn probe_ramp(&self) -> Result<(), &'static str> {
        if !self.warm {
            return Err("cold");
        }
        if self.probe_path_for >= self.policy.probe_ramp() {
            return Err("over");
        }
        if self.brake.is_some() {
            return Err("brake");
        }
        if self.since_real_loss < self.policy.real_loss_memory() {
            return Err("loss");
        }
        if !self.estimate_at_best {
            return Err("not-rising");
        }
        Ok(())
    }

    /// The best estimate seen, which the probe target is twice of before any capacity evidence.
    /// See [`Self::probe_target_kbps`].
    #[must_use]
    pub fn probe_best_kbps(&self) -> u32 {
        self.probe_best_kbps
    }

    /// Whether the path has produced capacity evidence (since the last path re-probe): whether the
    /// probe target follows [`Self::capacity_kbps`] or [`Self::probe_best_kbps`].
    #[must_use]
    pub fn probe_evidence_seen(&self) -> bool {
        self.evidence_seen
    }

    /// A probe target to hand congestion control, when it has moved far enough from the last one
    /// sent ([`PROBE_TARGET_CHANGE_PCT`], at most once per [`PROBE_TARGET_EVERY`]) or nothing has
    /// been confirmed sent yet. Taking it clears it; it counts as sent only once the caller calls
    /// [`Self::probe_target_sent`], so a refused send is offered again next tick.
    /// `afklink_transport::PeerControl::SetDesiredBitrate`.
    pub fn take_probe_target(&mut self) -> Option<u32> {
        self.probe_pending.take()
    }

    /// The caller delivered this probe target to congestion control.
    pub fn probe_target_sent(&mut self, kbps: u32) {
        self.probe_sent_kbps = kbps;
        self.since_probe_sent = Duration::ZERO;
    }

    /// Decide whether the probe target should be sent again. Once per tick, after the evidence has
    /// been updated. See [`Self::take_probe_target`].
    fn update_probe_target(&mut self, dt: Duration) {
        self.since_probe_sent = self.since_probe_sent.saturating_add(dt);
        // The opening's clock runs on media: str0m's opening probes are themselves the first media
        // tick. A session's opening ends at PROBE_OPENING_LATEST regardless.
        self.probe_session_for = self.probe_session_for.saturating_add(dt);
        if self.warm {
            self.probe_path_for = self.probe_path_for.saturating_add(dt);
        }
        let opening_why = if !self.probe_opening {
            None
        } else if self.probe_path_for >= self.policy.probe_opening() {
            Some("media")
        } else if !self.warm && self.probe_session_for >= self.policy.probe_opening_latest() {
            Some("no-media")
        } else {
            None
        };
        let opening_over = opening_why.is_some();
        if opening_over {
            self.probe_opening = false;
        }
        // Evidence only once str0m's estimate has left its configured opening value: before that
        // the informative floor can have "confirmed" 600, our own configuration echoed back (see
        // `first_estimate`), and twice that would cap the exponential probing a fat link needs in
        // its first seconds. That floor is forgotten when the estimate moves (see
        // `informative_from_opening`), so the first evidence is a measurement.
        if !self.evidence_seen && self.estimate_moved && self.capacity_kbps() > 0 {
            self.evidence_seen = true;
            tracing::debug!(
                capacity_kbps = self.capacity_kbps(),
                best_estimate_kbps = self.probe_best_kbps,
                cap_was_kbps = self
                    .probe_best_kbps
                    .saturating_mul(self.policy.probe_capacity_multiple),
                opening = self.probe_opening,
                path_ms = self.probe_path_for.as_millis() as u64,
                "first capacity evidence: the probe target follows it from here (after the \
                 opening, if it is still in force), not the best estimate seen"
            );
        }
        // The receiver's word that the path is full holds str0m's probing whatever the target is,
        // and a change either way goes out on this tick. See [`PROBE_QUIET_KBPS`].
        if self.evidence_seen {
            self.capacity_peak_kbps = self.capacity_peak_kbps.max(self.capacity_kbps());
        }
        let quiet = self.probe_quiet();
        let quiet_changed = quiet != self.probe_quiet_was;
        if quiet_changed {
            tracing::debug!(
                quiet = quiet.unwrap_or("-"),
                was = self.probe_quiet_was.unwrap_or("-"),
                target_kbps = self.probe_target_kbps(),
                quiet_kbps = PROBE_QUIET_KBPS,
                sent_kbps = self.probe_sent_kbps,
                brake = self.brake_state(),
                brake_kbps = ?self.brake.map(|b| b.cap_kbps),
                brake_silence_only = ?self.brake.map(|b| b.silence_only),
                drain = self.drain.is_some(),
                thin = self.probe_path_thin(),
                capacity_kbps = self.capacity_kbps(),
                capacity_peak_kbps = self.capacity_peak_kbps,
                best_estimate_kbps = self.probe_best_kbps,
                evidence = self.evidence_seen,
                since_real_loss_ms = self.since_real_loss.as_millis().min(u128::from(u64::MAX))
                    as u64,
                "{}",
                if quiet.is_some() {
                    "probe quiet: the receiver says the path is full (quiet: drain mode, or on a \
                     thin path a brake its reports set), so str0m is told a desired bitrate under \
                     its probing minimum and probes nothing until that is over"
                } else {
                    "probe quiet over: the probe target is its own again (target_kbps), sent on \
                     this tick"
                }
            );
            self.probe_quiet_was = quiet;
        }
        let want = if quiet.is_some() {
            PROBE_QUIET_KBPS
        } else {
            self.probe_target_kbps()
        };
        let ceiling = desired_bitrate_kbps_with(&self.policy, self.src_w, self.src_h, self.quality);
        let floor = probe_floor_kbps_with(&self.policy, self.src_w, self.src_h).min(ceiling);
        let sent = self.probe_sent_kbps;
        let moved = sent == 0
            || u64::from(want.abs_diff(sent)) * 100
                >= u64::from(sent) * self.policy.probe_target_change_pct;
        if let Some(why) = opening_why {
            tracing::debug!(
                why,
                path_ms = self.probe_path_for.as_millis() as u64,
                session_ms = self.probe_session_for.as_millis() as u64,
                opening_ms = self.policy.probe_opening().as_millis() as u64,
                sent_kbps = sent,
                to_kbps = want,
                // Under a fifth from what the peer has, the move is not worth a message (the
                // periodic probe at twice either is the same probe), and it is not sent.
                sends = moved,
                evidence = self.evidence_seen,
                capacity_kbps = self.capacity_kbps(),
                best_estimate_kbps = self.probe_best_kbps,
                floor_kbps = floor,
                ceiling_kbps = ceiling,
                brake = self.brake_state(),
                "probe opening over: str0m's opening probes and the exponential probing behind \
                 them had the ladder's ceiling; from here the target is twice the capacity \
                 evidence, or before there is any, twice the best estimate seen, and the move \
                 (sends) goes out on this tick, ahead of str0m's first periodic probe (five \
                 seconds after its opening probes)"
            );
        }
        if sent == 0 {
            // Nothing confirmed yet: offer it on every tick until the caller says it went out.
            self.probe_pending = Some(want);
            return;
        }
        // A path re-probe needs its target at the peer before its probes are queued, on this very
        // tick: the control task sends the target before the re-anchor. See [`Self::probe_urgent`].
        let urgent = std::mem::take(&mut self.probe_urgent);
        // A rise is str0m's exponential probing asking for room (before evidence, or in the ramp);
        // a second's wait would stop it. See [`PROBE_TARGET_EVERY`], [`PROBE_RAMP`].
        let rising = want > sent;
        let ramp = self.probe_ramp();
        let before_evidence = rising && !self.evidence_seen;
        let ramping = rising && self.evidence_seen && ramp.is_ok();
        let every = self.since_probe_sent >= self.policy.probe_target_every();
        if moved && (urgent || opening_over || before_evidence || ramping || every || quiet_changed)
        {
            // Once per decided value: a send the peer refuses is offered again every tick, and the
            // decision behind it has not changed.
            if self.probe_announced_kbps != want {
                self.probe_announced_kbps = want;
                tracing::debug!(
                    from_kbps = sent,
                    to_kbps = want,
                    rule = if quiet.is_some() {
                        "quiet"
                    } else if self.probe_opening {
                        "opening"
                    } else if self.evidence_seen {
                        "evidence"
                    } else {
                        "best-estimate"
                    },
                    capacity_kbps = self.capacity_kbps(),
                    best_estimate_kbps = self.probe_best_kbps,
                    floor_kbps = floor,
                    ceiling_kbps = ceiling,
                    sent_because = if urgent {
                        "path-reprobe"
                    } else if opening_over {
                        "opening-over"
                    } else if quiet_changed {
                        if quiet.is_some() {
                            "quiet"
                        } else {
                            "quiet-over"
                        }
                    } else if every {
                        "interval"
                    } else if before_evidence {
                        "climb-before-evidence"
                    } else {
                        "ramp"
                    },
                    ramp = ramp.err().unwrap_or("clean"),
                    path_ms = self.probe_path_for.as_millis() as u64,
                    brake = self.brake_state(),
                    since_last_ms = self.since_probe_sent.as_millis() as u64,
                    "probe target moved: congestion control is told to probe towards the ladder's \
                     ceiling in the opening, then twice the capacity evidence, or before there is \
                     any, twice the best estimate seen"
                );
            }
            self.probe_pending = Some(want);
        } else {
            if moved {
                // Decided but held by the interval, at trace: the same decision repeats every tick
                // until the interval passes, and the line that sends it reports `since_last_ms`.
                tracing::trace!(
                    from_kbps = sent,
                    to_kbps = want,
                    evidence = self.evidence_seen,
                    ramp = ramp.err().unwrap_or("clean"),
                    since_last_ms = self.since_probe_sent.as_millis() as u64,
                    "probe target move held until a second has passed since the last one"
                );
            }
            self.probe_pending = None;
        }
    }

    /// The estimate against the capacity evidence, as a word for the pipeline line.
    ///
    /// `-` when the estimate is not under half of [`Self::capacity_kbps`] (or nothing is known);
    /// `clean` while a clean collapse is held; otherwise why a collapse is not treated as clean:
    /// `rtt`, `loss`, `brake`, `no-report`, `no-baseline` (the receiver's evidence says no, or is
    /// missing), `spacing` (a re-anchor went out under [`REANCHOR_EVERY`] ago), `no-demand` (the
    /// encoder asks no more than the collapsed pacer drains).
    #[must_use]
    pub fn collapse_state(&self) -> &'static str {
        self.collapse_view
    }

    /// Whether the receiver's reports say the path is clean right now, or why not.
    ///
    /// Clean means: no brake in force; no report of [`REAL_LOSS`] in [`REAL_LOSS_MEMORY`]; a
    /// round-trip baseline exists; a fresh report arrived within [`REPORT_FRESH_WITHIN`]; and no
    /// fresh report in the last [`CLEAN_RTT_FOR`] was past the clean margin. Only the far end's
    /// word, nothing of this machine's own queue or estimate.
    fn path_clean(&self) -> Result<(), &'static str> {
        if let Some(reason) = self.brake_refuses() {
            return Err(reason);
        }
        if self.since_real_loss < self.policy.real_loss_memory() {
            return Err("loss");
        }
        if self.rtt_base_ms().is_none() {
            return Err("no-baseline");
        }
        if self.since_fresh > REPORT_FRESH_WITHIN {
            return Err("no-report");
        }
        if self.since_rtt_unclean < self.policy.clean_rtt_for() {
            return Err("rtt");
        }
        Ok(())
    }

    /// The part of [`Self::path_clean`] a pause-resume re-anchor is held to: no brake, no recent
    /// real loss, no recently inflated round trip, but no demand for a fresh report, since a
    /// receiver shown a still screen has nothing new to report.
    fn nothing_unclean_reported(&self) -> Result<(), &'static str> {
        if let Some(reason) = self.brake_refuses() {
            return Err(reason);
        }
        if self.since_real_loss < self.policy.real_loss_memory() {
            return Err("loss");
        }
        if self.since_rtt_unclean < self.policy.clean_rtt_for() {
            return Err("rtt");
        }
        Ok(())
    }

    /// Whether the brake in force says the path is not clean, and in what word.
    ///
    /// A brake set by loss or a standing round trip is the receiver's word: `brake`, until
    /// released. A brake set by silence alone is `no-report` while the silence lasts, and nothing
    /// once the receiver has come back clean and the brake is releasing. Otherwise the release and
    /// the re-anchor wait on each other: the release grows towards the budget the collapsed
    /// estimate allows, and the re-anchor that would lift the estimate cannot fire.
    fn brake_refuses(&self) -> Option<&'static str> {
        match self.brake {
            None => None,
            Some(b) if b.silence_only && b.phase == BrakePhase::Releasing => None,
            Some(b) if b.silence_only && b.phase == BrakePhase::Engaged => Some("no-report"),
            Some(_) => Some("brake"),
        }
    }

    /// The round trip at or past which a fresh report says the path is holding a queue, for
    /// [`Self::receiver_sees_no_queue`]: the brake's inflation line ([`Self::rtt_inflated_at`]),
    /// never above [`PATH_STEP_MAX_MS`]: a baseline learned on a bloated path is itself the queue
    /// (a bench 3G stall learned 1318 ms).
    fn rtt_queued_at(&self, base: u32) -> u32 {
        self.rtt_inflated_at(base).min(self.policy.path_step_max_ms)
    }

    /// Whether the receiver's reports say the path is holding no queue, or why not.
    ///
    /// Not [`Self::path_clean`], which answers whether congestion control may be overridden and so
    /// wants every report of the last two seconds within 40-75 ms of the least round trip. That bar
    /// is wrong for anything else on a jittery path: on a relay reached over TCP/TLS with a VPN at
    /// both ends, idle reports ran 180-450 ms against a least of 175-220, so the path was "unclean"
    /// nearly all the time with nothing queued. Jitter only adds delay, so an ordinary report sits
    /// well above the least.
    ///
    /// This asks the brake's own question: no report at or past [`Self::rtt_queued_at`] (twice the
    /// baseline, or the baseline plus [`RTT_MARGIN_MS`]) in [`CLEAN_RTT_FOR`]. Every cut the brake
    /// made on that path was past it (427 and 527 on 193, 506 on 175, 959 on 333). Also required: a
    /// fresh report within [`REPORT_FRESH_WITHIN`], a baseline, no real loss in
    /// [`REAL_LOSS_MEMORY`], and no brake of any kind in force.
    fn receiver_sees_no_queue(&self) -> Result<(), &'static str> {
        if self.brake.is_some() {
            return Err("brake");
        }
        if self.since_real_loss < self.policy.real_loss_memory() {
            return Err("loss");
        }
        if self.rtt_base_ms().is_none() {
            return Err("no-baseline");
        }
        if self.since_fresh > REPORT_FRESH_WITHIN {
            return Err("no-report");
        }
        if self.since_rtt_queued < self.policy.clean_rtt_for() {
            return Err("rtt");
        }
        Ok(())
    }

    /// Whether a queue in our own pacer is only that (the pacer draining at an estimate nothing has
    /// measured) and not the network refusing the rung, or why it may be the network.
    ///
    /// On a nearly still screen str0m's estimate sinks to the padding rate (78-121 kbps here) and
    /// the pacer drains at 1.1x that. Recorded on such an opening:
    ///
    /// ```text
    /// 16:16:35  a burst of 19 kB -> 760 ms of queue      rtt 313 on 313    -> 1080p30 (16:16:37)
    /// 16:16:53  a burst of 29 kB -> 1073 ms, a hard hold rtt 190 on 190    -> 900p   (16:16:55)
    /// 16:16:56  900p's own keyframe, 63 kB -> 1258 ms    rtt 244 on 180    -> 720p   (16:17:00, 4 frames in)
    /// 16:17:01  720p's own keyframe, 48 kB               rtt 214 on 175    -> 540p   (16:17:08)
    /// ```
    ///
    /// Every step was `queue_late` with the receiver at its baseline and no loss, and a tick later
    /// the path was found clean. The capacity evidence (196 kbps) was under [`REANCHOR_MIN_KBPS`],
    /// so no re-anchor could correct the estimate, and each rung bought a keyframe the size of the
    /// burst it answered.
    ///
    /// Two things must both hold: the estimate has not been measured under load in the dwell's
    /// window (`measured` in [`Self::tick`], as for `coarse` and `throttled`), and the receiver
    /// reports no queue ([`Self::receiver_sees_no_queue`]); a rung above what the path carries
    /// would put the excess where the far end sees it. Then `queue_late` and `growing` bank
    /// nothing. Latency is still guarded where it is made (pushback at [`QUEUE_GUARD_MS`], the
    /// pre-encode guards, the hard hold at the breaker's limit), and the brake still answers a
    /// queue the receiver sees. The startup queue jump follows the same rule
    /// ([`Self::watch_startup_queue`]). An estimate the link has agreed with under load
    /// ([`LOADED_SHARE_PCT`], [`LOADED_CONFIRM`]) is a measurement, and a queue behind it is the
    /// link.
    fn pacer_only(&self) -> Result<(), &'static str> {
        if !self.warm {
            return Err("cold");
        }
        if self.since_loaded <= self.policy.measured_within() {
            return Err("measured");
        }
        self.receiver_sees_no_queue()
    }

    /// What the receiver has positively reported against the path, if anything: a brake it set,
    /// real loss in [`REAL_LOSS_MEMORY`], or a report at [`Self::rtt_queued_at`] in
    /// [`CLEAN_RTT_FOR`]. Unlike [`Self::receiver_sees_no_queue`], a missing report or baseline is
    /// not trouble.
    fn receiver_reports_trouble(&self) -> Option<&'static str> {
        if self.brake.is_some_and(|b| !b.silence_only) {
            return Some("brake");
        }
        if self.since_real_loss < self.policy.real_loss_memory() {
            return Some("loss");
        }
        if self.since_rtt_queued < self.policy.clean_rtt_for() {
            return Some("rtt");
        }
        None
    }

    /// The queue filter the ladder reads: [`Self::late_smoothed`], which leaves the settle after a
    /// move out, unless the receiver reports trouble ([`Self::receiver_reports_trouble`]); then
    /// `late_with_settle`, which does not.
    ///
    /// The settle is left out because a move's own keyframe queued behind a pacer a still screen
    /// set is only the move's price. Once the far end reports missing packets it is a queue the
    /// link failed to carry: on a simulated 3G path (700 kbps behind a 60 ms buffer) a climb's
    /// keyframe and a scroll queued 985 ms behind a 71 kbps estimate, str0m force-drained it into
    /// the buffer, the receiver reported 8.2% loss, and ignoring that kept the session a rung or
    /// two too high until a 720p keyframe was lost at 18-76% loss and the picture froze for ten
    /// seconds (latency p95 1069 -> 1681 ms). The same line [`Self::pacer_only`] draws.
    fn late_for_ladder(&self) -> f32 {
        if self.receiver_reports_trouble().is_some() {
            self.late_with_settle
        } else {
            self.late_smoothed
        }
    }

    /// The capacity evidence, when it may stand in for the estimate in the climb gate: the screen
    /// is idle, the evidence is above the estimate, and the receiver sees no queue. `None`
    /// otherwise.
    ///
    /// On an idle screen str0m cuts to `0.85 x acked` when it reads the path's jitter as overuse,
    /// and what is acknowledged is our padding. Probes lift the estimate (recorded: to 1082 and
    /// 1909 on a game screen held at 360p for 115 s), the climb gate opens for a tick, and the
    /// estimate falls back to 55-95 kbps. The climb needs [`UP_AFTER`] of the estimate above the
    /// next rung's price, which a still screen cannot sustain, and a still screen is deliberately
    /// not re-anchored on a schedule (`no-demand`).
    ///
    /// The capacity evidence is receiver-confirmed, decays on [`INFORMATIVE_HALF_LIFE`] and is cut
    /// by the brake, and on an idle screen it is the only measurement there can be. It stands in
    /// when:
    ///
    /// - idle: production is under [`APP_LIMITED_PCT`] of the evidence, so the estimate describes
    ///   our silence;
    /// - above: the evidence exceeds the live estimate and is at least [`REANCHOR_MIN_KBPS`];
    /// - no queue: the receiver sees none ([`Self::receiver_sees_no_queue`]);
    /// - live: the receiver's feedback is current ([`Self::feedback_live`]).
    ///
    /// Under load the estimate is a measurement and the gate reads it (see `seen` in
    /// [`Self::tick`]). A climb this enables re-anchors on the same tick
    /// ([`ReanchorTrigger::IdleClimb`]) so its keyframe is not paced at the collapsed estimate.
    fn idle_evidence(&self, estimate_kbps: u32, live: bool) -> Option<u32> {
        let capacity = self.capacity_kbps();
        if !live || capacity < self.policy.reanchor_min_kbps() || capacity <= estimate_kbps {
            return None;
        }
        let idle = f64::from(self.produced_smoothed) * 100.0
            < f64::from(capacity) * self.policy.app_limited_pct as f64;
        if !idle {
            return None;
        }
        self.receiver_sees_no_queue().ok()?;
        Some(capacity)
    }

    /// The round trip above which a fresh report is not clean, for a given baseline:
    /// `clamp(30% of base, 40, 75)` over it. See [`CLEAN_RTT_MARGIN_MS`].
    fn rtt_clean_up_to(&self, base: u32) -> u32 {
        let margin = (base.saturating_mul(self.policy.clean_rtt_margin_pct) / 100)
            .clamp(self.policy.clean_rtt_margin_ms, QUEUE_GUARD_MS);
        base.saturating_add(margin)
    }

    /// What the loss/round-trip brake did since the last call, if anything. Taking it clears it.
    ///
    /// When transport-wide feedback stops, the estimate freezes while RTCP receiver reports keep
    /// arriving. Recorded at the end of an LTE session, 1080p60 at a budget of 10306:
    ///
    /// ```text
    /// 08:10:15  egress 11453  est 12482  rtt 253  loss  0.00%
    /// 08:10:16  egress 12611  est 12482  rtt 292  loss 24.69%  nacks 11
    /// 08:10:17  egress 11530  est 13480  rtt 801  loss 94.15%  nacks 69
    /// 08:10:18  egress 11312  est 13480  rtt 764  loss 93.92%  nacks 107
    /// ...       every report to 08:10:23 at 92.6-94.2%, egress 10300-12100, est 13480
    /// ```
    ///
    /// The local queue was empty: the pacer drained at 1.1x a frozen number into a link dropping
    /// 94%.
    ///
    /// On a fresh report with loss at or above [`BRAKE_LOSS`], [`BRAKE_RTT_REPORTS`] fresh reports
    /// with the round trip past [`RTT_INFLATION`] of its baseline, or [`BRAKE_STALE_REPORTS`]
    /// intervals with no report while sending, the budget is capped at [`BRAKE_BACKOFF`] of what
    /// the receiver got (egress times `1 - loss`) and lowered again by any report showing less
    /// getting through. The cap holds between the thresholds and grows back at
    /// [`BRAKE_RELEASE_PER_SEC`] once a report is clean, never snapping back to the estimate. While
    /// engaged it is descent evidence for the ladder and lowers [`Self::informative_kbps`], so
    /// neither the floor nor a re-anchor hands back what the link refused.
    ///
    /// A brake set by silence alone only cuts the budget: the receiver has said nothing about the
    /// link. When it comes back clean the brake is dropped by the re-anchor
    /// ([`ReanchorTrigger::OutageResume`]) or grows back. See `Brake::silence_only`.
    ///
    /// `the_lte_ending_engages_the_brake_on_the_first_bad_report` replays the recording above.
    pub fn take_brake_event(&mut self) -> Option<BrakeEvent> {
        self.brake_event.take()
    }

    /// The brake's ceiling on the budget, in kbps, while one is in force.
    #[must_use]
    pub fn brake_kbps(&self) -> Option<u32> {
        self.brake.map(|b| b.cap_kbps)
    }

    /// The brake's phase as a word for the log: `engaged`, `holding`, `releasing`, or `-`.
    #[must_use]
    pub fn brake_state(&self) -> &'static str {
        match self.brake.map(|b| b.phase) {
            None => "-",
            Some(BrakePhase::Engaged) => "engaged",
            Some(BrakePhase::Holding) => "holding",
            Some(BrakePhase::Releasing) => "releasing",
        }
    }

    /// The round trip the brake measures inflation against: the least of the recent fresh ones.
    #[must_use]
    pub fn rtt_base_ms(&self) -> Option<u32> {
        (self.rtt_seen >= self.policy.rtt_base_min_reports)
            .then(|| self.rtt_recent[..self.rtt_seen].iter().copied().min())
            .flatten()
    }

    /// The transport says the media path changed: ICE moved the media to another candidate pair,
    /// or brought a lost path back (`afklink_transport::Peer::path_changes`).
    ///
    /// Against the old path's baseline a longer new path reads as a standing queue for up to
    /// [`RTT_BASE_REPORTS`] seconds. So the baseline starts over, and whatever the brake holds is
    /// held as ignorance (`Brake::silence_only`): the budget stays where the cuts left it and grows
    /// back as the new path reports clean, but sheds no rungs and refuses no re-anchor.
    pub fn note_path_change(&mut self, why: &'static str) {
        self.reset_rtt_baseline(why);
        self.void_brake_evidence(why);
        // The drain line and exit band come from the old baseline too. A drain in progress goes on
        // (our backlog may still be in the old path) but leaves on the fallback band, and evidence
        // gathered on the old path is dropped.
        if self.drain_ref_ms.is_some() || self.drain_evidence > 0 {
            tracing::debug!(
                why,
                ref_ms = ?self.drain_ref_ms,
                evidence = self.drain_evidence,
                draining = self.drain.is_some(),
                "path change: the drain reference and any drain evidence are forgotten"
            );
        }
        self.drain_ref_ms = None;
        self.clear_drain_evidence();
        if let Some(d) = self.drain.as_mut() {
            d.ref_ms = None;
        }
    }

    /// [`Self::note_path_change`] for a change the transport can name (`Peer::path_kind`, `None` if
    /// unknown). Judged for a re-probe ([`ReanchorTrigger::PathChange`]): at once when more direct,
    /// else on the new round trip for [`PATH_JUDGE_WINDOW`]; never for a less direct pair.
    pub fn note_path_move(
        &mut self,
        why: &'static str,
        from: Option<PathKind>,
        to: Option<PathKind>,
    ) {
        // The old path's round trip, before the change forgets it.
        let old_rtt_ms = self.rtt_base_ms().or(self.last_fresh_rtt);
        self.note_path_change(why);
        let mv = PathMove {
            from,
            to,
            old_rtt_ms,
            new_rtt_min_ms: None,
            new_reports: 0,
            age: Duration::ZERO,
        };
        let less_direct = matches!((from, to), (Some(f), Some(t)) if t < f);
        let kind = |k: Option<PathKind>| k.map_or("unknown", PathKind::as_str);
        tracing::debug!(
            why,
            from = kind(from),
            to = kind(to),
            old_rtt_ms = ?old_rtt_ms,
            judge_ms = self.policy.path_judge_window().as_millis() as u64,
            "{}",
            if mv
                .qualifies(self.policy.path_reprobe_rtt_factor)
                .is_some()
            {
                "media path change to a more direct pair: str0m's opening probes are run again on it \
                 on the next tick"
            } else if less_direct {
                "media path change to a less direct pair: no re-probe, the estimate carries over as \
                 before"
            } else {
                "media path change: re-probed if the new path's round trip comes in at most half the \
                 old one's"
            }
        );
        self.path_move = (!less_direct).then_some(mv);
    }

    /// Start the round-trip baseline over. Until [`RTT_BASE_MIN_REPORTS`] fresh reports exist the
    /// round-trip arm cannot fire and the path is not clean (`no-baseline`); loss is unaffected.
    fn reset_rtt_baseline(&mut self, why: &'static str) {
        tracing::debug!(
            why,
            was_ms = ?self.rtt_base_ms(),
            samples = self.rtt_seen,
            inflated_run = self.rtt_high_run,
            last_rtt_ms = ?self.last_fresh_rtt,
            "round-trip baseline reset: the path changed, so the least round trip seen on the old one \
             is not this path's; the next reports set it again"
        );
        self.rtt_recent = [0; RTT_BASE_REPORTS];
        self.rtt_seen = 0;
        self.rtt_at = 0;
        self.rtt_high_run = 0;
        self.step.clear();
        // The viewer's reports came over the old path too, and the reference for what is in flight
        // was taken against the old baseline.
        self.delivery.reset(why);
        // A report past the clean margin of the old baseline said nothing about this path.
        self.since_rtt_unclean = Duration::MAX;
        self.since_rtt_queued = Duration::MAX;
        if let Some(b) = self.brake.as_mut() {
            // Neither did the round trip the last cut was made at: the arm's "has it risen since"
            // compares against this path's reports from here.
            b.rtt_at_cut = None;
        }
    }

    /// Whether the brake in force was set by the round trip alone and the reports behind it could
    /// still turn out to be a longer path: too few for [`Self::watch_path_step`] to judge, and flat
    /// so far. While true the cut stands but is not descent evidence (`braking` in [`Self::tick`]).
    ///
    /// The round-trip arm cuts on the second inflated report and the ladder sheds a rung
    /// [`DOWN_AFTER`] later; the verdict needs a third report, and Chrome's reports are 1 to 1.5 s
    /// apart, so one long gap puts the verdict after the rung (a bench RTT step lost 1080p@60 200
    /// ms before the third flat report). Holding back costs a real queue at most
    /// [`PATH_STEP_WINDOW`] reports of rung, and a ramp is refused once two reports are off one
    /// level.
    fn path_step_pending(&self) -> bool {
        self.brake.is_some_and(|b| !b.by_loss)
            && path_step_pending(&self.policy, &self.step.rtts[..self.step.len])
    }

    /// Hold the brake in force, if any, as ignorance rather than as the receiver's word about the
    /// path. See `Brake::silence_only` and [`Self::note_path_change`].
    fn void_brake_evidence(&mut self, why: &'static str) {
        if let Some(b) = self.brake.as_mut() {
            if !b.silence_only {
                tracing::debug!(
                    why,
                    cap_kbps = b.cap_kbps,
                    phase = ?b.phase,
                    by_loss = b.by_loss,
                    "brake held as silence from here: what the receiver said about the old path is \
                     not evidence about this one — the budget stays cut, but the brake no longer \
                     sheds rungs or refuses a re-anchor"
                );
                b.silence_only = true;
            }
            b.rtt_at_cut = None;
        }
    }

    /// Watch the run of elevated round trips for a longer path, and re-base on one. See
    /// [`PATH_STEP_REPORTS`] for the rule and the recordings behind it.
    ///
    /// Called for every fresh report with a round trip, after its sample has joined the baseline. A
    /// report inside the clean margin, or with [`REAL_LOSS`], ends the run. A run that
    /// [`path_step_refusal`] accepts, over no standing queue of our own, makes its least round trip
    /// the baseline; a brake whose cuts were only round-trip cuts is lifted to what the live
    /// estimate allows and held as ignorance ([`Self::void_brake_evidence`]). Returns whether it
    /// re-based.
    fn watch_path_step(&mut self, rtt: u32, loss: f32) -> bool {
        let Some(base) = self.rtt_base_ms() else {
            self.step.clear();
            return false;
        };
        let elevated = rtt > self.rtt_clean_up_to(base) && loss < self.policy.real_loss();
        if !elevated {
            if self.step.len > 0 {
                tracing::trace!(
                    rtt_ms = rtt,
                    base_ms = base,
                    loss_pct = format!("{:.2}", loss * 100.0),
                    run = self.step.len,
                    "path-step watch: run ended (back inside the clean margin, or lossy)"
                );
            }
            self.step.clear();
            return false;
        }
        self.step.push(rtt);
        if self.step.window().is_none() {
            return false;
        }
        // A copy, so the run can be cleared or the baseline reseeded from it below.
        let (buf, n) = (self.step.rtts, self.step.len);
        let window = &buf[..n];
        let queued = self.late_smoothed > QUEUE_GUARD_MS as f32;
        let refusal =
            path_step_refusal(&self.policy, window, base).or(queued.then_some("local-queue"));
        if let Some(why) = refusal {
            // Once per run at debug: a flat-but-refused level is a decision with a cost (the
            // brake stays the queue's), and its reason is what a later reader needs.
            if self.step.refusal_logged {
                tracing::trace!(refused = why, window_ms = ?window, base_ms = base, "path-step watch");
            } else {
                self.step.refusal_logged = true;
                tracing::debug!(
                    refused = why,
                    window_ms = ?window,
                    base_ms = base,
                    late_ms = format!("{:.0}", self.late_smoothed),
                    "round trip past the baseline for {n} reports, not read as a longer path: \
                     spread/trend means a queue building or draining, too-long a stalled \
                     bottleneck, local-queue our own backlog"
                );
            }
            return false;
        }
        let new_base = window.iter().copied().min().unwrap_or(rtt);
        tracing::debug!(
            from_ms = base,
            to_ms = new_base,
            window_ms = ?window,
            late_ms = format!("{:.0}", self.late_smoothed),
            brake = self.brake_state(),
            "path step: the round trip stepped up and lies flat with no loss and no queue of ours, \
             which is a longer path, not a queue — the baseline moves to it"
        );
        self.rtt_recent = [0; RTT_BASE_REPORTS];
        self.rtt_recent[..n].copy_from_slice(window);
        self.rtt_seen = n;
        self.rtt_at = n % RTT_BASE_REPORTS;
        self.rtt_high_run = 0;
        self.step.clear();
        // Measured against the new baseline these reports were clean.
        self.since_rtt_unclean = Duration::MAX;
        self.since_rtt_queued = Duration::MAX;
        if let Some(b) = self.brake {
            if b.by_loss {
                tracing::debug!(
                    cap_kbps = b.cap_kbps,
                    "path step: the brake also cut on loss, which a longer path does not explain; \
                     it stays the receiver's word and releases by the ordinary rules"
                );
                if let Some(b) = self.brake.as_mut() {
                    b.rtt_at_cut = None;
                }
            } else {
                // Every cut was the round trip (or silence) against the old baseline. Releasing
                // from the cut at a quarter a second would take ten seconds to reach the budget
                // congestion control gives this path, for no reason the receiver has given.
                let floor = u32::try_from(u64::from(self.smoothed) * self.policy.spend_pct / 100)
                    .unwrap_or(u32::MAX);
                self.void_brake_evidence("path_step");
                if let Some(b) = self.brake.as_mut() {
                    if b.cap_kbps < floor {
                        tracing::debug!(
                            from_kbps = b.cap_kbps,
                            to_kbps = floor,
                            estimate_kbps = self.smoothed,
                            "path step: the round-trip brake was cutting against the path; lifted \
                             to the budget the live estimate allows, and it releases from there"
                        );
                        b.cap_kbps = floor;
                    }
                }
            }
        }
        true
    }

    /// Why the ladder last moved: `startup-thin`, `startup-queue`, `brake`, `down`, `climb`; empty
    /// before any move.
    #[must_use]
    pub fn last_move_reason(&self) -> &'static str {
        self.last_move_reason
    }

    /// The budget before pushback, in kbps: what the link alone says is available.
    ///
    /// The ladder reads this, not the pushed-back figure: overshoot measured against a budget that
    /// pushback just halved doubles mechanically, and the ladder would descend because the pushback
    /// acted (one controller reading another's output).
    ///
    /// Capped by the loss/round-trip brake while one is in force. That is not another controller's
    /// output: it is the receiver's measurement of what the link delivered, capping the budget
    /// where the estimate would have if its feedback had not stopped. See
    /// [`Self::take_brake_event`].
    #[must_use]
    pub fn unpushed_kbps(&self) -> u32 {
        let unbraked = self.unbraked_kbps();
        match self.brake {
            Some(b) => unbraked.min(b.cap_kbps).max(ABSOLUTE_FLOOR_KBPS),
            None => unbraked,
        }
    }

    /// [`Self::unpushed_kbps`] without the brake: what the estimate, the informative floor and the
    /// exploration bound allow. The brake releases once its ceiling reaches this.
    fn unbraked_kbps(&self) -> u32 {
        let rung = self.current();
        let ceiling = rung
            .absorbable_kbps_with(&self.policy, self.src_w, self.src_h)
            .max(ABSOLUTE_FLOOR_KBPS);

        // Before media has flowed, price the rung rather than fall to the floor: with
        // `smoothed == 0` the budget would be 120 kbps, about 500 bytes a 1080p frame, pinning the
        // quantiser and banking descent evidence before any network measurement exists. The rung's
        // price is what `desired_bitrate_kbps` already probes towards; being briefly high is fixed
        // in a tick. `warm` means media has left (see [`Self::warm`]), not that str0m published its
        // configured 600.
        if !self.warm || self.smoothed == 0 {
            return self
                .current_required_kbps()
                .clamp(ABSOLUTE_FLOOR_KBPS, ceiling);
        }

        // No reach above the estimate: str0m's delay estimate is bounded by `acked x 1.5 + 10
        // kbps`, so filling the budget already lets it grow a third per step. Asking for 1.2x
        // whenever the pipe looked empty strobed a 20% step through the budget, since pressure sits
        // near any threshold at the operating point.
        //
        // Never more than the link has just demonstrated plus a bounded exploration margin:
        // `demonstrated * 1.5 + margin` is GCC's increase rule, which str0m applies to the estimate
        // (`bwe/delay/rate_control.rs`), so the budget is at most one exploration step ahead of
        // evidence. A remembered egress peak instead put 367 kB (three seconds) in the queue when
        // motion resumed after a pause on a link that had narrowed:
        //
        //     prod=5271  est=8036  egress=5272  age=0    flight=0        motion, healthy
        //     prod= 182  bud=4268  egress= 273  age=0    flight=0        the screen goes still
        //     prod=3460  bud=3841  egress= 946  age=226  flight=367446   motion resumes
        //
        // The bound applies only while the encoder is trying to fill its allowance. A still desktop
        // produces 5 to 15 kbps, so the bound alone pins the budget near 290 kbps whatever the link
        // carries, and with QP already at `QP_MAX` moving content cannot fit that:
        //
        //     qp=46.0  prod= 875  bud=120  est=137  age=372  flight= 95230   spend=20.5
        //     qp=46.0  prod=2584  bud=141  est=315  age=817  flight=275591   spend=20.7
        //
        // That is libwebrtc's application-limited reasoning (str0m ships the same detector,
        // `bwe/alr_detector/`): low throughput is the application's, not the link's. The threshold
        // is [`SPENDING_SHARE`] halved, the same question the quantiser gate asks. On the still
        // line above this gives `estimate * 0.90` = 1550 kbps, against the peak's 4268 and the
        // bound's 290.
        //
        // The estimate itself is also only the link's word when the link was asked: a still screen
        // talks it down to the padding rate, so it is held at [`Self::informative_kbps`] (see the
        // failure modes there), taken as a maximum with the live estimate so a rise is believed at
        // once.
        //
        // While a clean collapse is held, the capacity evidence too: the re-anchor moves str0m's
        // pacer at once, but the estimate read here comes through a three-second smoother
        // ([`CLEAN_COLLAPSE_HOLD`]) and describes neither link nor pacer for those ticks. Bounded
        // by the hold, the brake and the receiver ending it.
        let held = if self.collapse.is_some() {
            self.capacity_kbps()
        } else {
            0
        };
        let believed_base = u64::from(self.smoothed.max(self.informative_kbps).max(held));
        let trying = self.spend_smoothed >= self.policy.trying_share;
        let believed = if trying {
            // The maximum over the last second, not the last 200 ms window: a gap in the pacer's
            // output is an artefact of pacing ([`EGRESS_WINDOW`]).
            //
            // A second covers a pacing gap but not a pause: scroll, stop, read, scroll empties the
            // ring in five ticks while `trying` is still true (`spend_smoothed` has a 1.6 s time
            // constant). Measured on 900p video with an estimate of 5893: the screen stopped, the
            // budget read 1912 a second later, and a sharp scroll served at that put 293 kB in
            // flight and the queue at the transport's hard limit, a PLI and two descents. The
            // re-anchor needs a longer pause (`spend_smoothed < 0.4`). So the bound is floored at
            // [`Self::informative_kbps`], the estimate as it stood with at least
            // [`LOADED_SHARE_PCT`] of it on the wire, decaying on the same 20 s half-life. Unlike a
            // throughput peak it follows a link down and is corrected by sending.
            let demonstrated = u64::from(self.egress_recent.iter().copied().max().unwrap_or(0))
                .max(
                    u64::from(self.informative_kbps.max(held)) * self.policy.loaded_share_pct / 100,
                );
            let explore = demonstrated * self.policy.explore_growth_pct / 100
                + u64::from(self.policy.explore_margin_kbps);
            believed_base.min(explore)
        } else {
            believed_base
        };
        // Why not a high-water mark of demonstrated egress, released by the queue: the estimate
        // falls when content gets cheap, not only when the link narrows, and a video session showed
        // `coarse` shedding 1080p on a link that had carried 3789 kbps four seconds earlier:
        //
        //     1080p qp=20.2 prod=3652 egr=3789 bud=3654 est=5191   climbed, picture excellent
        //     1080p qp=18.8 prod=2877 egr=2926 bud=4671 est=5191   the video wants less
        //     1080p qp=22.8 prod=2728 egr=2746 bud=1582 est=2680   estimate halves
        //     1080p qp=22.5 prod=1768                   est=2173   1768 * 1.5 + 10 = 2662
        //     1080p qp=46.0 prod=1294 egr=2507 bud=2390 est=2929   quantiser hits its ceiling
        //     900p  <- `coarse` sheds the rung
        //
        // Each such descent costs a ~65 kB IDR (160 to 290 ms of queue), which talks the estimate
        // down again. But not sending is not evidence: an idle sender cannot tell "the link is
        // fine" from "the link narrowed", and a mark released by the queue releases after the
        // damage (`the_budget_cannot_over_commit_after_a_still_moment`). str0m's continuous padding
        // is `PADDING_TARGET = 50 kbps`, far too little to keep a multi-megabit estimate alive.
        //
        // `informative_kbps` differs: it is congestion control's estimate, not our throughput; it
        // is set under load rather than maximised, so it follows a narrowing link down; it decays;
        // and sending, not a formed queue, corrects it. Under-commitment measured at three rungs
        // and twenty seconds per pause, while three mechanisms catch over-commitment within a
        // second. See `motion_after_a_pause_is_served_at_the_estimate_measured_under_load`.
        let spend = believed * self.policy.spend_pct / 100;
        // The lower clamp is the global floor, not a learned per-rung floor: an encoder whose
        // quantiser is pinned produces what it produces whatever it is handed, but `spend_ratio >
        // 1.0` is ordinary rate-control jitter, not proof the target is unreachable, and a floor
        // learned from it pinned the budget up while capacity fell.
        u32::try_from(spend)
            .unwrap_or(u32::MAX)
            .clamp(ABSOLUTE_FLOOR_KBPS, ceiling)
    }

    /// Settle after a rung change: forget the measurements that described the old one.
    ///
    /// The quantiser, encode time and spend ratio describe the old resolution until frames are
    /// encoded at the new one. Reading them steers on the past: replayed on recorded sessions, the
    /// ladder fell from 1080p to the bottom in twelve seconds, one step every two, on what was a
    /// single observation. Cleared, the next descent needs evidence from the rung it condemns.
    fn moved(&mut self) -> Rung {
        self.down_dwell = Duration::ZERO;
        self.up_dwell = Duration::ZERO;
        self.qp_smoothed = None;
        self.late_smoothed = 0.0;
        self.late_with_settle = 0.0;
        self.growth_smoothed = 1.0;
        self.spend_smoothed = 0.0;
        self.drop_smoothed = 0.0;
        // Production depends on the rung as much as the content. The egress ring and
        // `informative_kbps` describe the link and are kept.
        self.produced_smoothed = 0.0;
        self.qp_seen = 0;
        // The encode time describes the old rung's pixels; after a cadence step too, the settle and
        // climb dwell refill it before a climb reads it.
        self.encode_smoothed = None;
        self.cpu_wait_logged = false;
        self.settling = self.policy.settle_after_move();
        self.settle_queue_peak_ms = 0;
        self.up_target = None;
        self.current()
    }

    /// The pushback multiplier for the queue that has already formed. Continuous, bounded, never
    /// zero.
    ///
    /// The bitrate gives way, not the frame rate: fewer bits per frame is monotone, while fewer
    /// frames makes each one describe a longer interval (exponent 1.248), so the byte rate rises.
    fn pushback(&self) -> f64 {
        1.0 - self.policy.pushback_depth * f64::from(self.pressure.clamp(0.0, 1.0))
    }

    /// The round trip past which a fresh report counts as inflated, for a given baseline.
    fn rtt_inflated_at(&self, base: u32) -> u32 {
        base.saturating_mul(self.policy.rtt_inflation)
            .max(base.saturating_add(self.policy.rtt_margin_ms))
    }

    /// The round trip under which the brake may release: halfway from the inflation threshold to
    /// the baseline. Between the two a report holds, so a hovering round trip cannot flap the
    /// brake.
    fn rtt_clear_below(&self, base: u32) -> u32 {
        base + (self.rtt_inflated_at(base) - base) / 2
    }

    /// Read one receiver report: update the round-trip baseline and the loss clock, and decide
    /// what the brake does. See [`Self::take_brake_event`].
    fn on_report(&mut self, r: ReceiverReport) {
        // What we sent over the interval this report closes: the mean of the ticks since the
        // previous one. Egress is a socket count including retransmissions and padding, which the
        // link was asked to carry too. With it, the media produced and the budget, for the silence
        // rule.
        let means = self.interval_means();
        let (sent_now, _, budget_now) = means;
        self.report_egress_sum = 0;
        self.report_produced_sum = 0;
        self.report_budget_sum = 0;
        self.report_egress_ticks = 0;
        // And the rate the report's loss is applied to: the larger of this interval and the one
        // before, because the report is partly about the one before. See [`BRAKE_BACKOFF`].
        let sent = sent_now.max(self.prev_report_sent);
        self.prev_report_sent = sent_now;

        // While the path drains, a report is read for one thing only: whether the backlog is gone.
        // See [`Self::draining`].
        if self.drain.is_some() {
            self.on_report_draining(r);
            return;
        }

        let verdict = if r.fresh() {
            self.fresh_seen = true;
            if self.stale_run > 0 {
                tracing::debug!(
                    empty_intervals = self.stale_run,
                    silent_ms = self.since_fresh.as_millis() as u64,
                    rtt_ms = ?r.rtt_ms,
                    loss_pct = ?r.loss.map(|l| l * 100.0),
                    "receiver report after a silence: feedback is live again"
                );
            }
            self.stale_run = 0;
            self.climb_held_logged = false;
            self.drain_silence_counted = false;
            self.hidden_silence_logged = false;
            // Right after a hold, a round trip past the drain line or most of the interval lost is
            // the woken page describing its sleep: it says only that the receiver is back.
            if !self.wake_window.is_zero() {
                let line = self.drain_enter_at();
                let loss = r.loss.unwrap_or(0.0);
                let rtt_slept = r.rtt_ms.is_some_and(|rtt| rtt >= line);
                let loss_slept = loss >= self.policy.hold_wake_loss;
                if rtt_slept || loss_slept {
                    self.since_fresh = Duration::ZERO;
                    tracing::debug!(
                        rtt_ms = ?r.rtt_ms,
                        line_ms = line,
                        loss_pct = format!("{:.2}", loss * 100.0),
                        loss_line_pct = format!("{:.0}", self.policy.hold_wake_loss * 100.0),
                        window_left_ms = self.wake_window.as_millis() as u64,
                        rtt_base_ms = ?self.rtt_base_ms(),
                        brake = self.brake_state(),
                        "receiver report right after a background hold with a round trip past the \
                         drain line or most of the interval lost: the woken page's word about the \
                         time it slept, not the path — read as the receiver being back and nothing \
                         else (no drain evidence, no loss or round-trip sample, no brake verdict)"
                    );
                    return;
                }
                tracing::debug!(
                    rtt_ms = ?r.rtt_ms,
                    line_ms = line,
                    loss_pct = format!("{:.2}", loss * 100.0),
                    window_left_ms = self.wake_window.as_millis() as u64,
                    "receiver report after a background hold under the drain line and the loss \
                     line: its reports are about the path again"
                );
                self.wake_window = Duration::ZERO;
            }
            // The baseline the drain line is drawn from, taken while nothing yet says the path is
            // holding a backlog — and before an outage below can reset it to this report's value.
            if self.drain_evidence == 0 {
                if let Some(base) = self.rtt_base_ms() {
                    if self.drain_ref_ms != Some(base) {
                        tracing::trace!(
                            from_ms = ?self.drain_ref_ms,
                            to_ms = base,
                            "drain reference follows the round-trip baseline"
                        );
                    }
                    self.drain_ref_ms = Some(base);
                }
            }
            // A report past the drain line describes a backlog: once it completes the evidence,
            // nothing below (baseline, brake, outage) may read it. See [`DRAIN_EVIDENCE`].
            if self.note_drain_report(r.rtt_ms, sent_now, budget_now) {
                self.record_fresh(&r);
                return;
            }
            // The first word from the receiver after an outage the silence brake answered: from
            // here the path has [`OUTAGE_CONFIRM`] to show it is clean before it is re-anchored.
            let mut back_after_outage = false;
            if let Some(o) = self.outage.as_mut() {
                if o.resumed_for.is_none() {
                    o.resumed_for = Some(Duration::ZERO);
                    back_after_outage = true;
                    tracing::debug!(
                        silent_ms = self.since_fresh.as_millis() as u64,
                        rtt_ms = ?r.rtt_ms,
                        loss_pct = ?r.loss.map(|l| l * 100.0),
                        confirm_ms = self.policy.outage_confirm().as_millis() as u64,
                        "the receiver reports again after an outage: a re-anchor is considered once \
                         the path has been clean this long"
                    );
                }
            }
            // Very possibly on another path: an outage long enough to answer is what a phone
            // changing networks looks like from here (Wi-Fi at 127 ms, 9.2 s of silence, LTE at a
            // flat 245). The old path's least round trip is not this one's.
            if back_after_outage {
                self.reset_rtt_baseline("outage");
            }
            let loss = r.loss.unwrap_or(0.0).clamp(0.0, 1.0);
            self.record_fresh(&r);
            // Startup evidence, against the least round trip so far: the baseline needs three
            // reports, and a thin link's first three can already be inflated.
            if self.warm && !self.startup_done {
                let inflated = match (r.rtt_ms, self.startup_rtt_min) {
                    (Some(rtt), Some(min)) => rtt >= self.rtt_inflated_at(min),
                    _ => false,
                };
                let evidence = if loss >= self.policy.real_loss() {
                    Some("loss")
                } else if inflated {
                    Some("rtt")
                } else {
                    None
                };
                if let (Some(what), None) = (evidence, self.startup_evidence) {
                    tracing::debug!(
                        evidence = what,
                        rtt_ms = ?r.rtt_ms,
                        rtt_min_ms = ?self.startup_rtt_min,
                        loss_pct = format!("{:.2}", loss * 100.0),
                        "startup window: the receiver reports the link congested"
                    );
                    self.startup_evidence = Some(what);
                }
                if let Some(rtt) = r.rtt_ms {
                    self.startup_rtt_min = Some(self.startup_rtt_min.map_or(rtt, |m| m.min(rtt)));
                }
            }
            // Only a fresh report's round trip is a sample: str0m repeats the last one without a
            // report (`streams/send_stats.rs:89-90,134`), which would double a spike.
            if let Some(rtt) = r.rtt_ms {
                self.rtt_recent[self.rtt_at] = rtt;
                self.rtt_at = (self.rtt_at + 1) % RTT_BASE_REPORTS;
                self.rtt_seen = (self.rtt_seen + 1).min(RTT_BASE_REPORTS);
                // A step to a longer path re-bases before this report is judged, so it is judged
                // against the path it was measured on.
                self.watch_path_step(rtt, loss);
            }
            let base = self.rtt_base_ms();
            // Past the clean margin: a queue, however small. Not a brake condition
            // ([`CLEAN_RTT_MARGIN_MS`]), but no override of congestion control for
            // [`CLEAN_RTT_FOR`].
            if let (Some(rtt), Some(base)) = (r.rtt_ms, base) {
                if rtt > self.rtt_clean_up_to(base) {
                    self.since_rtt_unclean = Duration::ZERO;
                }
                // Past the brake's own line: keeps our pacer's queue counting as the network's for
                // [`CLEAN_RTT_FOR`]. See [`Self::receiver_sees_no_queue`].
                if rtt >= self.rtt_queued_at(base) {
                    if self.since_rtt_queued >= self.policy.clean_rtt_for() {
                        tracing::debug!(
                            rtt_ms = rtt,
                            base_ms = base,
                            line_ms = self.rtt_queued_at(base),
                            "receiver reports a queue on the path (the brake's inflation line): our \
                             own queue counts as the network's again"
                        );
                    }
                    self.since_rtt_queued = Duration::ZERO;
                }
            }
            // The egress this report and the one before bracket: a burst between two reports is
            // confirmed carried, and may be capacity evidence, only when both are clean.
            let report_clean = loss < self.policy.real_loss()
                && matches!((r.rtt_ms, base), (Some(rtt), Some(b)) if rtt <= self.rtt_clean_up_to(b));
            self.egress_confirmed_kbps = if report_clean {
                self.egress_pending_kbps
            } else {
                0
            };
            if !report_clean && self.egress_pending_kbps.max(self.egress_open_kbps) > 0 {
                tracing::trace!(
                    pending_kbps = self.egress_pending_kbps,
                    open_kbps = self.egress_open_kbps,
                    rtt_ms = ?r.rtt_ms,
                    rtt_base_ms = ?base,
                    loss_pct = format!("{:.2}", loss * 100.0),
                    "egress bursts not confirmed as carried: the report is not clean"
                );
            }
            self.egress_pending_kbps = if report_clean {
                self.egress_open_kbps
            } else {
                0
            };
            self.egress_open_kbps = 0;
            let (inflated, rtt_clear) = match (r.rtt_ms, base) {
                (Some(rtt), Some(base)) => (
                    rtt >= self.rtt_inflated_at(base),
                    rtt < self.rtt_clear_below(base),
                ),
                // No baseline yet, or no round trip in this report: nothing to say about delay.
                _ => (false, true),
            };
            self.rtt_high_run = if inflated { self.rtt_high_run + 1 } else { 0 };
            let delivered = f64::from(sent) * f64::from(1.0 - loss) * self.policy.brake_backoff;
            if loss >= self.policy.brake_loss {
                Verdict::Cut(BrakeCause::Loss, delivered as u32)
            } else if self.rtt_high_run >= self.policy.brake_rtt_reports {
                Verdict::Cut(BrakeCause::Rtt, delivered as u32)
            } else if loss < self.policy.brake_clear_loss && rtt_clear {
                Verdict::Clear
            } else {
                Verdict::Hold
            }
        } else {
            // Silence counts only while we are asking the link for something (300 kbps of egress,
            // or on a thinner link half the budget in media: [`SILENCE_MEDIA_SHARE_PCT`]) and only
            // once the path has reported at all.
            if self.silence_counts(means) {
                self.stale_run += 1;
                // Egress the receiver has not reported on in its turn cannot be confirmed by later
                // reports: a bench blackout's 9.5 Mbps into a dead link would otherwise count as
                // capacity. An ordinary empty interval delays a confirmation by one report.
                self.egress_open_kbps = 0;
                self.egress_pending_kbps = 0;
                // One line per empty interval: the count toward a silence brake must be visible
                // while it builds. From the first one the feedback is stale
                // ([`Self::feedback_live`]).
                tracing::debug!(
                    run = self.stale_run,
                    cut_every = self.policy.brake_stale_reports,
                    sent_kbps = sent_now,
                    produced_kbps = means.1,
                    budget_kbps = budget_now,
                    by = if sent_now >= self.policy.loaded_floor_kbps {
                        "egress"
                    } else {
                        "media-share"
                    },
                    silent_ms = self.since_fresh.as_millis() as u64,
                    "no receiver report for an interval while sending: feedback is stale — no \
                     climb, no loaded confirmation, no capacity sample until one arrives"
                );
            } else {
                if self.stale_run > 0 {
                    tracing::debug!(
                        run = self.stale_run,
                        sent_kbps = sent_now,
                        produced_kbps = means.1,
                        budget_kbps = budget_now,
                        media_floor_kbps = self.policy.silence_media_floor_kbps,
                        media_share_pct = self.policy.silence_media_share_pct,
                        "silence count reset: we are no longer sending enough for silence to mean \
                         anything"
                    );
                } else if self.fresh_seen && sent_now > 0 {
                    // Once a second at most, and the whole reason an empty interval decided
                    // nothing: a still screen's padding, or a stream too light for its budget.
                    tracing::trace!(
                        sent_kbps = sent_now,
                        produced_kbps = means.1,
                        budget_kbps = budget_now,
                        "an interval without a receiver report, not counted as silence"
                    );
                }
                self.stale_run = 0;
                self.drain_silence_counted = false;
            }
            // The viewer's page is hidden: its silence is the page asleep (an iPhone's WebView
            // stops everything when hidden), not the path. No cut, no outage, no drain evidence;
            // feedback is still stale. See [`Self::set_page_hidden`].
            if self.page_hidden && self.stale_run > 0 {
                if !self.hidden_silence_logged {
                    self.hidden_silence_logged = true;
                    tracing::debug!(
                        run = self.stale_run,
                        silent_ms = self.since_fresh.as_millis() as u64,
                        sent_kbps = sent_now,
                        budget_kbps = budget_now,
                        capacity_kbps = self.capacity_kbps(),
                        brake = self.brake_state(),
                        "receiver silent while the viewer's page is hidden: read as the page \
                         asleep, not the network — no silence brake, no outage, no drain evidence, \
                         and the capacity evidence does not decay while it lasts"
                    );
                }
                Verdict::NoInfo
            } else {
                // A silence long enough to cut on is one piece of drain evidence (once per run);
                // with a report past the drain line it is a stall.
                if self.stale_run >= self.policy.brake_stale_reports && !self.drain_silence_counted
                {
                    self.drain_silence_counted = true;
                    if self.note_drain_silence(sent_now, budget_now) {
                        return;
                    }
                }
                if self.stale_run > 0
                    && self
                        .stale_run
                        .is_multiple_of(self.policy.brake_stale_reports)
                {
                    // One cut per [`BRAKE_STALE_REPORTS`] of silence, from what leaves now, so a
                    // silence that goes on halves the rate each time.
                    Verdict::Cut(
                        BrakeCause::Silence,
                        (f64::from(sent_now) * self.policy.brake_stale_backoff) as u32,
                    )
                } else {
                    Verdict::NoInfo
                }
            }
        };

        let detail = |cause, before_kbps, after_kbps, this: &Self| BrakeDetail {
            cause,
            loss_pct: r.loss.map(|l| l * 100.0),
            rtt_ms: r.rtt_ms,
            rtt_base_ms: this.rtt_base_ms(),
            before_kbps,
            after_kbps,
        };
        match verdict {
            Verdict::Cut(cause, target) => {
                let target = target.max(ABSOLUTE_FLOOR_KBPS);
                let before = self.unpushed_kbps();
                let silence = cause == BrakeCause::Silence;
                // Silence only if every cut of the episode was; a report of loss or of a queue
                // makes the whole episode the receiver's word.
                let silence_only = silence && self.brake.is_none_or(|b| b.silence_only);
                match self.brake {
                    Some(b) if b.phase == BrakePhase::Engaged => {
                        // Already engaged. A loss report cuts again only if it shows less getting
                        // through than the last cut assumed; the round trip only if it has risen
                        // since the last cut (see [`BRAKE_BACKOFF`]). `None`: the cuts predate a
                        // path change, so any cut is new.
                        let again = match cause {
                            BrakeCause::Rtt => {
                                b.rtt_at_cut.is_none_or(|at| r.rtt_ms.unwrap_or(0) > at)
                            }
                            _ => true,
                        };
                        let by_loss = b.by_loss || cause == BrakeCause::Loss;
                        let cap = target.min(before);
                        if again && cap < b.cap_kbps {
                            self.brake = Some(Brake {
                                cap_kbps: cap,
                                phase: BrakePhase::Engaged,
                                rtt_at_cut: r.rtt_ms,
                                silence_only,
                                by_loss,
                            });
                            self.brake_event =
                                Some(BrakeEvent::Tightened(detail(cause, before, cap, self)));
                        } else {
                            tracing::debug!(
                                cause = cause.as_str(),
                                cap_kbps = b.cap_kbps,
                                target_kbps = cap,
                                rtt_ms = ?r.rtt_ms,
                                rtt_at_cut_ms = ?b.rtt_at_cut,
                                "brake not tightened: the report shows no less getting through, or \
                                 no higher round trip, than the last cut"
                            );
                            if (!silence && b.silence_only) || by_loss != b.by_loss {
                                // The receiver has spoken, and said no: the episode is its word now
                                // — and if it said so with loss, that is on the record too.
                                self.brake = Some(Brake {
                                    silence_only: b.silence_only && silence,
                                    by_loss,
                                    ..b
                                });
                            }
                        }
                    }
                    _ => {
                        // A new episode, or a holding or releasing one just refuted: cut now, never
                        // above the current budget.
                        let cap = target.min(before);
                        self.brake = Some(Brake {
                            cap_kbps: cap,
                            phase: BrakePhase::Engaged,
                            rtt_at_cut: r.rtt_ms,
                            silence_only,
                            by_loss: cause == BrakeCause::Loss,
                        });
                        self.brake_event =
                            Some(BrakeEvent::Engaged(detail(cause, before, cap, self)));
                    }
                }
                if silence {
                    // Silence lowers the budget only (not the evidence: `Brake::silence_only`), and
                    // opens an outage whose end may be re-anchored.
                    if self.outage.is_none_or(|o| o.resumed_for.is_some()) {
                        tracing::debug!(
                            capacity_kbps = self.capacity_kbps(),
                            informative_kbps = self.informative_kbps,
                            sent_kbps = sent_now,
                            "outage: the receiver is silent while we send; the budget is cut, the \
                             capacity evidence is kept, and the rung is held"
                        );
                        // A brake the receiver's reports set before the silence was about a path
                        // that may now be gone (a dying Wi-Fi's round-trip cuts would shed rungs
                        // through the handover's silence). When the receiver is back its reports
                        // decide again.
                        self.void_brake_evidence("outage");
                    }
                    self.outage = Some(Outage::default());
                } else {
                    // The informative floor and the capacity evidence are what the link last agreed
                    // to, and it has just disagreed; left standing, the floor or a re-anchor would
                    // hand back the rate the receiver reported it could not take.
                    if let Some(b) = self.brake {
                        self.informative_kbps = self.informative_kbps.min(b.cap_kbps);
                        self.capacity_kbps = self.capacity_kbps.min(b.cap_kbps);
                    }
                    // An outage whose end the receiver answers with loss or a queue is not one to
                    // re-anchor: the link came back narrower, and congestion control is right.
                    if self.outage.take().is_some() {
                        tracing::debug!(
                            cause = cause.as_str(),
                            loss_pct = ?r.loss.map(|l| l * 100.0),
                            rtt_ms = ?r.rtt_ms,
                            "outage over without a re-anchor: the receiver reports the link \
                             congested since it came back"
                        );
                    }
                }
            }
            // Phase changes that are not events (the control task prints those): at most one a
            // second, so debug and on change only.
            Verdict::Clear => {
                if let Some(b) = self.brake.as_mut() {
                    if b.phase != BrakePhase::Releasing {
                        tracing::debug!(
                            cap_kbps = b.cap_kbps,
                            loss_pct = ?r.loss.map(|l| l * 100.0),
                            rtt_ms = ?r.rtt_ms,
                            "brake releasing: the report is clean; the ceiling grows back"
                        );
                    }
                    b.phase = BrakePhase::Releasing;
                }
            }
            // Neither cut nor release: hold, which also stops a release, since 2-10% loss does not
            // confirm the step just given.
            Verdict::Hold => {
                if let Some(b) = self.brake.as_mut() {
                    if b.phase != BrakePhase::Holding {
                        tracing::debug!(
                            cap_kbps = b.cap_kbps,
                            loss_pct = ?r.loss.map(|l| l * 100.0),
                            rtt_ms = ?r.rtt_ms,
                            "brake holding: the report is neither clean nor bad enough to cut again"
                        );
                    }
                    b.phase = BrakePhase::Holding;
                }
            }
            Verdict::NoInfo => {}
        }
    }

    /// Grow a releasing brake's ceiling by one tick, and drop the brake once it stops binding.
    fn release_brake(&mut self, dt: Duration) {
        let Some(mut b) = self.brake else {
            return;
        };
        if b.phase == BrakePhase::Releasing {
            let held = b.cap_kbps;
            let grown = f64::from(held) * self.policy.brake_release_per_sec.powf(dt.as_secs_f64());
            // At least a kilobit a tick, so a ceiling near the floor cannot round to a standstill.
            b.cap_kbps = (grown as u32).max(held + 1);
            let unbraked = self.unbraked_kbps();
            if b.cap_kbps >= unbraked {
                self.brake = None;
                self.brake_event = Some(BrakeEvent::Released(BrakeDetail {
                    cause: BrakeCause::Clear,
                    loss_pct: None,
                    rtt_ms: None,
                    rtt_base_ms: self.rtt_base_ms(),
                    before_kbps: held.min(unbraked),
                    after_kbps: unbraked,
                }));
                return;
            }
        }
        self.brake = Some(b);
    }

    /// Whether drain mode is in force: the path is holding a backlog of ours, so nothing more is
    /// encoded until it has drained. The encode loop reads it (through
    /// [`QualityTarget::set_draining`]) and withholds every frame; RTCP, the data channels and the
    /// heartbeat (`net_stall`) go on.
    ///
    /// On a bufferbloated 3G path the receiver's round trip grew from 4.8 s to 39.4 s over a minute
    /// with 0% loss while the viewer showed frames 20-40 s old. The loss arm never fires there, the
    /// round-trip arm makes small cuts into a queue that keeps growing, and every frame sent joins
    /// the back of it. The only rate that shortens a backlog the path holds is zero.
    ///
    /// Entered on [`DRAIN_EVIDENCE`]: two pieces with no report under the line between them, either
    /// two reports with the round trip past [`DRAIN_ENTER_RTT_MS`], or one such report and a
    /// silence of [`BRAKE_STALE_REPORTS`] while sending, in either order. No Wi-Fi or LTE recording
    /// (130-800 ms) can enter it, nor can a single report or silence alone (a blackout drops what
    /// it cannot carry). Vetoed when the viewer's own on-time count says our data is reaching it
    /// ([`DRAIN_VETO_WITHIN_MS`]): the round trip describes an earlier queue, the count the path
    /// now.
    ///
    /// Left on the first of: a fresh report under [`Self::drain_exit_below`]; the receiver with
    /// nothing new of ours to report for longer than its last backlog ([`DRAIN_DRAINED_STALE`]);
    /// the viewer's count saying the rest arrives within [`DRAIN_LEAVE_WITHIN_MS`] at our rate
    /// (`delivered`); [`DRAIN_MAX`] without a report proving the backlog; [`DRAIN_MAX_PROVEN`]
    /// regardless. The budget then resumes at [`DRAIN_RESUME_SHARE_PCT`] of what the receiver last
    /// confirmed, held as a brake that releases on clean reports; congestion control is restarted
    /// there if below ([`ReanchorTrigger::DrainResume`]); a keyframe is requested.
    ///
    /// It cannot recall what is already in the path, only stop it growing (a 4 s queue drained in
    /// about as long). Nor does it stop str0m's 50 kbps padding (`pacer/control.rs:35-44`,
    /// `session.rs:1358-1379`), which on a 100 kbit/s bench stall left 2-3 s of padding ahead of
    /// the resume keyframe. Receiver reports stop with our video ([`DRAIN_DRAINED_STALE`]).
    ///
    /// While it lasts a report describes the backlog, not the path: it reaches neither the
    /// baseline, the brake, the capacity evidence nor the outage and re-anchor logic; silence does
    /// not count; the ladder and the startup window are frozen. Entry drops the brake, an outage
    /// and a held collapse; a path change during it forgets the pre-stall baseline.
    #[must_use]
    pub fn draining(&self) -> bool {
        self.drain.is_some()
    }

    /// How long drain mode has been in force, for the pipeline line; `None` outside it.
    #[must_use]
    pub fn drain_held(&self) -> Option<Duration> {
        self.drain.map(|d| d.held)
    }

    /// What drain mode did since the last call, if anything. Taking it clears it. On
    /// [`DrainEvent::Left`] the caller asks the encoder for a keyframe.
    pub fn take_drain_event(&mut self) -> Option<DrainEvent> {
        self.drain_event.take()
    }

    /// Frames and bytes handed to the transport this session, cumulative, as counted before each
    /// tick: what the viewer's count is read against. See [`Self::note_viewer_frames`].
    pub fn note_frames_sent(&mut self, frames: u64, bytes: u64) {
        self.delivery.sent_pending = Some((frames, bytes));
    }

    /// A report from the viewer of the frames it received, handed over before the tick that reads
    /// it; when several arrived between two ticks, the last.
    ///
    /// Read against [`Self::note_frames_sent`] it says how much of ours is in flight and at what
    /// rate the viewer receives it, a reverse one-way trip ago rather than a round trip. On time,
    /// it vetoes a drain ([`DRAIN_VETO_WITHIN_MS`]) or ends one ([`DRAIN_LEAVE_WITHIN_MS`]). Late,
    /// missing or before its reference is set, it says nothing ([`DELIVERY_FRESH_LATE_MS`]).
    pub fn note_viewer_frames(&mut self, r: ViewerFrames) {
        self.delivery.report_pending = Some(r);
    }

    /// Read this tick's viewer report, if any, before the receiver report so a drain can be judged
    /// against it. `queue_age_ms` must be zero for a reading to join the reference.
    fn read_viewer_frames(&mut self, queue_age_ms: u32) {
        let Some(r) = self.delivery.report_pending.take() else {
            return;
        };
        let base = self.rtt_base_ms();
        let fallback = self.policy.drain_exit_fallback_ms();
        let band = base.map_or(fallback, |b| self.rtt_inflated_at(b).min(fallback));
        let rtt_clean = self.last_fresh_rtt.is_some_and(|rtt| rtt < band)
            && self.since_fresh <= REPORT_FRESH_WITHIN;
        let clean_path = rtt_clean
            && self.drain.is_none()
            && self.drain_evidence == 0
            && queue_age_ms <= QUEUE_GUARD_MS;
        let reading = self.delivery.read(&self.policy, r, base, clean_path);
        let recent = self.delivery.recent_rates();
        // Once a second at most, while the round trip is building a drain's evidence: each is the
        // viewer's word on it (in a drain, `drain_delivery_check` says what it made of it).
        debug_or_trace!(
            self.drain.is_none() && self.drain_evidence > 0,
            received = r.received,
            frames = reading.frames,
            interval_ms = reading.interval_ms,
            late_ms = ?reading.late_ms,
            on_time = reading.on_time(&self.policy),
            in_flight_frames = ?reading.in_flight_frames.map(|f| f.round() as i64),
            in_flight_kb = ?reading.in_flight_bytes.map(|b| (b / 1000.0).round() as i64),
            in_flight_ms = ?reading.in_flight_ms(),
            goodput_kbps = ?reading.goodput_kbps,
            two_reports_fps = ?recent.map(|(f, _)| f.round() as u32),
            two_reports_kbps = ?recent.map(|(_, k)| k),
            sent_fps = self.delivery.sent_fps(self.policy.delivery_rate_window()).round() as u32,
            sent_kbps = self.delivery.sent_kbps(self.policy.delivery_rate_window()),
            base_ms = ?base,
            clean_path,
            draining = self.drain.is_some(),
            drain_evidence = self.drain_evidence,
            "viewer delivery: the viewer's count of our frames, against what we sent"
        );
    }

    /// The viewer's word on drain mode as of now: [`DeliveryVerdict::Delivering`] when its recent,
    /// on-time report says our data is reaching it (at most [`DRAIN_VETO_WITHIN_MS`] in flight at
    /// its rate, and its frame rate at least ours).
    fn delivery_verdict(&self) -> DeliveryVerdict {
        let Some(r) = self.delivery.reading else {
            return DeliveryVerdict::Unknown("no-report");
        };
        if self.delivery.clock.saturating_sub(r.at) > self.policy.delivery_report_age() {
            return DeliveryVerdict::Unknown("report-old");
        }
        if !r.on_time(&self.policy) {
            return DeliveryVerdict::Unknown(if r.late_ms.is_none() {
                "no-viewer-clock"
            } else {
                "late"
            });
        }
        let Some(frames) = r.in_flight_frames else {
            return DeliveryVerdict::Unknown("no-reference");
        };
        if frames <= DELIVERY_NONE_IN_FLIGHT {
            return DeliveryVerdict::Delivering(r);
        }
        // This report's own rate: the one before can span seconds of a data channel held up behind
        // our queue (measured: 5 frames over 4 s, then 20 in the next one), and the bytes are
        // already weighed in what is in flight.
        let keeps_up = r.fps() >= self.delivery.sent_fps(self.policy.delivery_rate_window());
        match r.in_flight_ms() {
            Some(ms) if ms <= self.policy.drain_veto_within_ms && keeps_up => {
                DeliveryVerdict::Delivering(r)
            }
            // Ours in flight and, by this report, none of it reaching the viewer: a backlog by its
            // count, as much as one of seconds.
            _ => DeliveryVerdict::Queued(r),
        }
    }

    /// Whether the viewer's count vetoes a drain the round trip would begin now. Logged either way:
    /// a drain begun is the picture stopped, and one not begun is a queue the brake is left with.
    fn delivery_vetoes_drain(&self, rtt: u32, by: &'static str) -> bool {
        let sent_fps = self
            .delivery
            .sent_fps(self.policy.delivery_rate_window())
            .round() as u32;
        let sent_kbps = self.delivery.sent_kbps(self.policy.delivery_rate_window());
        let recent = self.delivery.recent_rates();
        let age_ms =
            |r: &DeliveryReading| self.delivery.clock.saturating_sub(r.at).as_millis() as u64;
        match self.delivery_verdict() {
            DeliveryVerdict::Delivering(r) => {
                tracing::debug!(
                    rtt_ms = rtt,
                    by,
                    in_flight_frames = ?r.in_flight_frames.map(|f| f.round() as i64),
                    in_flight_ms = ?r.in_flight_ms(),
                    within_ms = self.policy.drain_veto_within_ms,
                    viewer_fps = r.fps().round() as u32,
                    two_reports_fps = ?recent.map(|(f, _)| f.round() as u32),
                    two_reports_kbps = ?recent.map(|(_, k)| k),
                    sent_fps,
                    sent_kbps,
                    viewer_frames = r.frames,
                    late_ms = ?r.late_ms,
                    report_age_ms = age_ms(&r),
                    evidence = self.drain_evidence,
                    "drain mode not entered: the viewer's own count, on time, says our frames are \
                     reaching it — the round trip describes a queue an earlier sender report met, not \
                     the path now"
                );
                true
            }
            DeliveryVerdict::Queued(r) => {
                tracing::debug!(
                    rtt_ms = rtt,
                    by,
                    in_flight_frames = ?r.in_flight_frames.map(|f| f.round() as i64),
                    in_flight_ms = ?r.in_flight_ms(),
                    within_ms = self.policy.drain_veto_within_ms,
                    viewer_fps = r.fps().round() as u32,
                    two_reports_fps = ?recent.map(|(f, _)| f.round() as u32),
                    two_reports_kbps = ?recent.map(|(_, k)| k),
                    sent_fps,
                    sent_kbps,
                    viewer_frames = r.frames,
                    late_ms = ?r.late_ms,
                    report_age_ms = age_ms(&r),
                    "drain mode: the viewer's own count agrees — a backlog of ours in flight"
                );
                false
            }
            DeliveryVerdict::Unknown(why) => {
                tracing::debug!(
                    rtt_ms = rtt,
                    by,
                    why,
                    late_ms = ?self.delivery.reading.and_then(|r| r.late_ms),
                    report_age_ms = ?self.delivery.reading.map(|r| age_ms(&r)),
                    "drain mode: no current word from the viewer's count; the round trip decides alone"
                );
                false
            }
        }
    }

    /// The viewer's word on a drain in force, on a tick that read one of its reports made during
    /// it: end it when the report, on time, says the rest of the backlog reaches the viewer within
    /// [`DRAIN_LEAVE_WITHIN_MS`] (or nothing is left) and the path has room for the resume: our
    /// frames arrive at least as fast as we sent before the drain (over its last two reports, or
    /// half again that on this one), and our bytes at least as fast as the resume will send them.
    /// Returns whether it ended it.
    fn drain_delivery_check(&mut self) -> bool {
        if !self.delivery.read_this_tick {
            return false;
        }
        let (Some(r), Some(d)) = (self.delivery.reading, self.drain) else {
            return false;
        };
        if r.at <= d.began_at {
            tracing::trace!(
                late_ms = ?r.late_ms,
                "drain mode: the viewer's report is from before the drain; not about it"
            );
            return false;
        }
        if !r.on_time(&self.policy) {
            tracing::debug!(
                late_ms = ?r.late_ms,
                fresh_late_ms = self.policy.delivery_fresh_late_ms,
                held_ms = d.held.as_millis() as u64,
                "drain mode: the viewer's report came late (its data channel held up behind our \
                 queue); not current evidence"
            );
            return false;
        }
        let Some(frames) = r.in_flight_frames else {
            tracing::debug!(
                held_ms = d.held.as_millis() as u64,
                "drain mode: no reference for the viewer's count yet; the round trip decides alone"
            );
            return false;
        };
        let resume = d.resume_kbps(&self.policy);
        let fps = r.fps();
        let recent = self.delivery.recent_rates();
        let frames_ok = fps >= d.sent_before_fps * self.policy.drain_leave_one_report
            || recent.is_some_and(|(f, _)| f >= d.sent_before_fps);
        let bytes_ok = recent.is_some_and(|(_, k)| k >= resume);
        let in_flight_ms = r.in_flight_ms();
        let left_ok = frames <= DELIVERY_NONE_IN_FLIGHT
            || in_flight_ms.is_some_and(|ms| ms <= self.policy.drain_leave_within_ms);
        let band = self.drain_exit_below();
        let in_flight_frames = frames.round() as i64;
        let in_flight_kb = r.in_flight_bytes.map(|b| (b / 1000.0).round() as i64);
        if frames_ok && bytes_ok && left_ok {
            tracing::debug!(
                in_flight_frames,
                in_flight_kb = ?in_flight_kb,
                in_flight_ms = ?in_flight_ms,
                within_ms = self.policy.drain_leave_within_ms,
                viewer_fps = fps.round() as u32,
                two_reports_fps = ?recent.map(|(f, _)| f.round() as u32),
                sent_before_fps = d.sent_before_fps.round() as u32,
                two_reports_kbps = ?recent.map(|(_, k)| k),
                resume_kbps = resume,
                late_ms = ?r.late_ms,
                held_ms = d.held.as_millis() as u64,
                last_rtt_ms = d.last_rtt_ms,
                exit_below_ms = band,
                "drain mode: the viewer's own count, on time, says our backlog is reaching it, at a \
                 rate the resume fits in — the resume will follow it in"
            );
            self.leave_drain("delivered", None, band);
            return true;
        }
        // Once a second at most: the viewer's word on the drain, and why it is not over by it.
        let why = if !frames_ok {
            "frames-rate"
        } else if !bytes_ok {
            "bytes-rate"
        } else {
            "left"
        };
        tracing::debug!(
            in_flight_frames,
            in_flight_kb = ?in_flight_kb,
            in_flight_ms = ?in_flight_ms,
            within_ms = self.policy.drain_leave_within_ms,
            viewer_fps = fps.round() as u32,
            two_reports_fps = ?recent.map(|(f, _)| f.round() as u32),
            sent_before_fps = d.sent_before_fps.round() as u32,
            two_reports_kbps = ?recent.map(|(_, k)| k),
            resume_kbps = resume,
            late_ms = ?r.late_ms,
            held_ms = d.held.as_millis() as u64,
            why,
            "drain mode: the viewer's own count does not end the drain (frames-rate: our frames \
             reach it fewer a second than we were sending; bytes-rate: our bytes slower than the \
             resume would send — either way a resume would build the backlog again; left: more is \
             in flight than the bar)"
        );
        false
    }

    /// The round trip at or above which a fresh report is drain evidence. Absolute: see
    /// [`DRAIN_ENTER_RTT_MS`] for why not a multiple of the baseline.
    fn drain_enter_at(&self) -> u32 {
        self.policy.drain_enter_rtt_ms
    }

    /// The round trip a fresh report must be under to end drain mode: the brake's inflation line
    /// over the pre-stall baseline (twice it, or it plus [`RTT_MARGIN_MS`]), never above
    /// [`DRAIN_EXIT_FALLBACK_MS`], which also applies with no baseline. At most half the entry
    /// line, so the two cannot chatter.
    fn drain_exit_below(&self) -> u32 {
        let fallback = self.policy.drain_exit_fallback_ms();
        self.drain
            .and_then(|d| d.ref_ms)
            .map_or(fallback, |b| self.rtt_inflated_at(b))
            .min(fallback)
    }

    /// Clear the drain evidence: a report under the line, or a drain that just began or ended.
    fn clear_drain_evidence(&mut self) {
        self.drain_evidence = 0;
        self.drain_evidence_report = false;
        self.drain_evidence_silence = false;
    }

    /// A fresh report's round trip as drain evidence. Returns whether it began drain mode.
    fn note_drain_report(&mut self, rtt: Option<u32>, sent_kbps: u32, budget_kbps: u32) -> bool {
        // No round trip in the report (no sender report reached the receiver yet): nothing either
        // way.
        let Some(rtt) = rtt else {
            return false;
        };
        let line = self.drain_enter_at();
        if rtt < line {
            if self.drain_evidence > 0 {
                tracing::debug!(
                    rtt_ms = rtt,
                    line_ms = line,
                    ref_ms = ?self.drain_ref_ms,
                    evidence = self.drain_evidence,
                    "drain evidence cleared: a report under the line says the path is carrying what \
                     we send"
                );
            }
            self.clear_drain_evidence();
            return false;
        }
        self.drain_evidence += 1;
        self.drain_evidence_report = true;
        tracing::debug!(
            rtt_ms = rtt,
            line_ms = line,
            ref_ms = ?self.drain_ref_ms,
            evidence = self.drain_evidence,
            needed = self.policy.drain_evidence,
            silence = self.drain_evidence_silence,
            sent_kbps,
            "drain evidence: a report with the round trip past the line — the path is holding \
             what we send"
        );
        if self.drain_evidence >= self.policy.drain_evidence {
            // The evidence stands, so the next piece of it is judged again against the viewer's
            // count as it is then; the report itself goes on to the brake as any other.
            if self.delivery_vetoes_drain(rtt, "report") {
                return false;
            }
            let by_silence = self.drain_evidence_silence;
            self.enter_drain(rtt, line, by_silence, sent_kbps, budget_kbps);
            return true;
        }
        false
    }

    /// A silence of [`BRAKE_STALE_REPORTS`] intervals while sending, as drain evidence (once per
    /// run). Returns whether it began drain mode — only after a report past the line.
    fn note_drain_silence(&mut self, sent_kbps: u32, budget_kbps: u32) -> bool {
        self.drain_evidence += 1;
        self.drain_evidence_silence = true;
        let line = self.drain_enter_at();
        tracing::debug!(
            evidence = self.drain_evidence,
            needed = self.policy.drain_evidence,
            with_report = self.drain_evidence_report,
            last_rtt_ms = ?self.last_fresh_rtt,
            line_ms = line,
            sent_kbps,
            "drain evidence: the receiver is silent while we send (on its own this is an outage's, \
             not a stall's)"
        );
        if self.drain_evidence >= self.policy.drain_evidence && self.drain_evidence_report {
            let rtt = self.last_fresh_rtt.unwrap_or(line);
            if self.delivery_vetoes_drain(rtt, "silence") {
                return false;
            }
            self.enter_drain(rtt, line, true, sent_kbps, budget_kbps);
            return true;
        }
        false
    }

    /// Begin drain mode. See [`Self::draining`].
    fn enter_drain(
        &mut self,
        rtt: u32,
        line: u32,
        by_silence: bool,
        sent_kbps: u32,
        budget_kbps: u32,
    ) {
        // The resume is priced from what the receiver last confirmed, capped at what we were
        // sending when the stall began (the path did not carry even that). The evidence can hold a
        // burst the path merely queued: a 300 kbps bench path read 1063 at its drain.
        let capacity = self.capacity_kbps();
        let sent = sent_kbps.max(self.prev_report_sent);
        let basis = if capacity > 0 {
            capacity.min(sent.max(ABSOLUTE_FLOOR_KBPS))
        } else {
            sent
        };
        tracing::debug!(
            rtt_ms = rtt,
            line_ms = line,
            ref_ms = ?self.drain_ref_ms,
            by_silence,
            sent_kbps,
            budget_kbps,
            capacity_kbps = capacity,
            resume_basis_kbps = basis,
            media_sent_kbps = self.delivery.sent_kbps(Duration::from_secs(1)),
            rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
            "drain mode: the path is holding a backlog of ours; nothing more is encoded until it \
             drains"
        );
        // Each of these was answering the same stall with less than it needs.
        if let Some(b) = self.brake.take() {
            tracing::debug!(
                cap_kbps = b.cap_kbps,
                phase = ?b.phase,
                silence_only = b.silence_only,
                by_loss = b.by_loss,
                "drain mode: the brake in force is dropped; the resume sets its own"
            );
        }
        if let Some(o) = self.outage.take() {
            tracing::debug!(
                resumed_for_ms = ?o.resumed_for.map(|d| d.as_millis() as u64),
                "drain mode: the outage in progress is a stall, not an outage; no outage re-anchor"
            );
        }
        if let Some(h) = self.collapse.take() {
            tracing::debug!(
                anchor_kbps = h.anchor_kbps,
                held_ms = h.held.as_millis() as u64,
                "drain mode: the clean-collapse hold ends"
            );
        }
        // After a drain what leaves is the resume's conservative budget, not the link, so no new
        // startup queue jump; one already decided stands and takes the resume's keyframe.
        if !self.startup_queue_used {
            tracing::debug!(
                pending = ?self.startup_queue_target,
                "startup queue window closed by drain mode (a jump already decided is kept for the \
                 resume)"
            );
            if self.startup_queue_target.is_none() {
                self.startup_queue_used = true;
            }
        }
        self.rtt_high_run = 0;
        self.step.clear();
        self.stale_run = 0;
        self.app_limited_for = Duration::ZERO;
        self.resume_window = Duration::ZERO;
        self.egress_open_kbps = 0;
        self.egress_pending_kbps = 0;
        self.egress_confirmed_kbps = 0;
        self.clear_drain_evidence();
        self.drain = Some(Drain {
            held: Duration::ZERO,
            ref_ms: self.drain_ref_ms,
            entered_rtt_ms: rtt,
            peak_rtt_ms: rtt,
            resume_basis_kbps: basis,
            reports: 0,
            last_rtt_ms: rtt,
            stale: 0,
            since_proof: Duration::ZERO,
            began_at: self.delivery.clock,
            sent_before_fps: self.delivery.sent_fps(self.policy.delivery_rate_window()),
        });
        self.drain_event = Some(DrainEvent::Entered {
            rtt_ms: rtt,
            ref_ms: self.drain_ref_ms,
            enter_at_ms: line,
            by_silence,
            sent_kbps,
            budget_kbps,
        });
    }

    /// A receiver report during drain mode: read only for whether the backlog is gone.
    fn on_report_draining(&mut self, r: ReceiverReport) {
        // Nothing is confirmed as carried while we are not sending.
        self.egress_open_kbps = 0;
        self.egress_pending_kbps = 0;
        self.egress_confirmed_kbps = 0;
        let band = self.drain_exit_below();
        if !r.fresh() {
            // Silence does not count while draining (`silence_counts`): with nothing new arriving
            // the receiver has nothing to report, which, sustained, is the backlog gone.
            let silent = self.since_fresh;
            let Some(d) = self.drain.as_mut() else {
                return;
            };
            d.stale += 1;
            let proven = Duration::from_millis(u64::from(d.last_rtt_ms.saturating_sub(band)));
            let (stale, last_rtt) = (d.stale, d.last_rtt_ms);
            if stale >= self.policy.drain_drained_stale && silent >= proven {
                tracing::debug!(
                    stale_intervals = stale,
                    silent_ms = silent.as_millis() as u64,
                    last_rtt_ms = last_rtt,
                    exit_below_ms = band,
                    "drain mode: the receiver has had nothing new of ours to report for longer than \
                     the backlog its last report showed — the backlog is delivered"
                );
                self.leave_drain("drained", None, band);
            } else {
                tracing::trace!(
                    stale_intervals = stale,
                    silent_ms = silent.as_millis() as u64,
                    proven_ms = proven.as_millis() as u64,
                    "drain mode: no fresh report this interval"
                );
            }
            return;
        }
        self.fresh_seen = true;
        self.stale_run = 0;
        self.climb_held_logged = false;
        self.drain_silence_counted = false;
        self.record_fresh(&r);
        let Some(d) = self.drain.as_mut() else {
            return;
        };
        d.reports += 1;
        d.stale = 0;
        if let Some(rtt) = r.rtt_ms {
            d.peak_rtt_ms = d.peak_rtt_ms.max(rtt);
            d.last_rtt_ms = rtt;
            if rtt >= self.policy.drain_enter_rtt_ms {
                d.since_proof = Duration::ZERO;
            }
        }
        let (ref_ms, held, peak) = (d.ref_ms, d.held, d.peak_rtt_ms);
        let Some(rtt) = r.rtt_ms else {
            tracing::debug!("drain mode: a fresh report without a round trip; still draining");
            return;
        };
        if rtt < band {
            self.leave_drain("report", Some(rtt), band);
        } else {
            // One a second at most: each is the receiver's word on how much is left.
            tracing::debug!(
                rtt_ms = rtt,
                exit_below_ms = band,
                ref_ms = ?ref_ms,
                held_ms = held.as_millis() as u64,
                peak_rtt_ms = peak,
                "drain mode: the path still holds our backlog"
            );
        }
    }

    /// End drain mode: the budget resumes at [`DRAIN_RESUME_SHARE_PCT`] of the entry basis, held as
    /// a brake clean reports release; congestion control restarts there if below
    /// ([`ReanchorTrigger::DrainResume`]); the signals restart with a settle; the caller asks for a
    /// keyframe.
    fn leave_drain(&mut self, why: &'static str, rtt: Option<u32>, band: u32) {
        let Some(d) = self.drain.take() else {
            return;
        };
        let resume = d.resume_kbps(&self.policy);
        let unbraked = self.unbraked_kbps();
        self.brake = Some(Brake {
            cap_kbps: resume,
            phase: BrakePhase::Holding,
            rtt_at_cut: None,
            // Not the receiver's word about the path: a ceiling of caution. It neither sheds the
            // rung nor lowers the evidence, and a clean report starts its release.
            silence_only: true,
            by_loss: false,
        });
        self.brake_event = Some(BrakeEvent::Engaged(BrakeDetail {
            cause: BrakeCause::Drain,
            loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
            rtt_ms: rtt,
            rtt_base_ms: d.ref_ms,
            before_kbps: unbraked,
            after_kbps: resume.min(unbraked),
        }));
        // str0m measured our silence through the drain (299 -> 52 kbps on a bench path) and its
        // pacer would hold the resume keyframe behind that (926 ms of our own queue). Restarted at
        // the resume budget with the opening probes held to it (`afklink_transport::reanchor_bwe`).
        if self.smoothed < resume {
            let r = Reanchor {
                kbps: resume,
                trigger: ReanchorTrigger::DrainResume,
                estimate_kbps: self.smoothed,
                capacity_kbps: self.capacity_kbps(),
                rtt_ms: rtt.or(self.last_fresh_rtt),
                rtt_base_ms: d.ref_ms,
                loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
                probe_cap_kbps: None,
            };
            tracing::debug!(
                kbps = resume,
                estimate_kbps = self.smoothed,
                since_last_reanchor_ms = self.since_reanchor.as_millis() as u64,
                "re-anchor decided: the drain left the estimate under the resume budget"
            );
            self.reanchor_kbps = Some(resume);
            self.last_reanchor = Some(r);
            self.since_reanchor = Duration::ZERO;
        } else {
            tracing::debug!(
                estimate_kbps = self.smoothed,
                resume_kbps = resume,
                "no re-anchor at the drain's end: the estimate already covers the resume budget"
            );
        }
        // A startup queue jump decided before the drain moves the rung on this very tick, and its
        // keyframe is the resume's: no settle in front of it, or the resume would pay two.
        let startup_move = self.startup_queue_target.is_some() && !self.startup_queue_used;
        self.moved();
        if startup_move {
            self.settling = Duration::ZERO;
        }
        self.app_limited_for = Duration::ZERO;
        self.resume_window = Duration::ZERO;
        self.stale_run = 0;
        self.rtt_high_run = 0;
        self.step.clear();
        // The reports of the stall were a queue by any measure: nothing overrides congestion
        // control on the path's word until two clean seconds have followed it.
        self.since_rtt_unclean = Duration::ZERO;
        self.since_rtt_queued = Duration::ZERO;
        self.clear_drain_evidence();
        tracing::debug!(
            why,
            rtt_ms = ?rtt,
            exit_below_ms = band,
            ref_ms = ?d.ref_ms,
            held_ms = d.held.as_millis() as u64,
            entered_rtt_ms = d.entered_rtt_ms,
            peak_rtt_ms = d.peak_rtt_ms,
            reports = d.reports,
            resume_basis_kbps = d.resume_basis_kbps,
            resume_kbps = resume,
            unbraked_kbps = unbraked,
            startup_move,
            "drain mode over: resuming with a keyframe at a conservative budget, held as a brake \
             that the receiver's clean reports release"
        );
        self.drain_event = Some(DrainEvent::Left {
            why,
            rtt_ms: rtt,
            exit_below_ms: band,
            held_ms: d.held.as_millis() as u64,
            peak_rtt_ms: d.peak_rtt_ms,
            reports: d.reports,
            resume_kbps: resume,
        });
    }

    /// One tick of drain mode, when it did not end: the bookkeeping that runs whatever the link is
    /// doing, and nothing that judges the link or the rung.
    fn drain_tick(&mut self, dt: Duration) {
        let decay =
            0.5f64.powf(dt.as_secs_f64() / self.policy.informative_half_life().as_secs_f64());
        self.capacity_kbps = (f64::from(self.capacity_kbps) * decay) as u32;
        // Not a pause of ours: its end is not a resume.
        self.app_limited_for = Duration::ZERO;
        self.resume_window = self.resume_window.saturating_sub(dt);
        self.update_probe_target(dt);
    }

    /// The best rung at or below the current one that `kbps` pays for at its desktop price with
    /// [`UP_HEADROOM`] — the climb gate's floor pricing, and the startup jump's — or the last rung.
    fn best_rung_for(&self, kbps: u32) -> usize {
        let rungs = self.rungs();
        (self.index..rungs.len())
            .find(|&i| {
                let price = f64::from(rungs[i].required_kbps_with(
                    &self.policy,
                    self.src_w,
                    self.src_h,
                    self.quality,
                ));
                f64::from(kbps) >= price * self.policy.up_headroom
            })
            .unwrap_or(rungs.len() - 1)
    }

    /// What this rung's content costs at a comfortable quantiser, in kbps, from what the encoder
    /// has been producing here: production (keyframes excluded) moved from its quantiser to
    /// [`QP_UP`] at the rate-halves-per-six rule [`QP_DOWN`] cites. `None` when the encoder reports
    /// no quantiser, or before the source is known.
    ///
    /// Not grossed up for frames the bit bucket withheld: its duty cycle fills with keyframes as
    /// readily as content (in the simulator, after a flood of keyframe requests, it read 0.96 and a
    /// grossed-up landing went to 360p@8 where the walk settled at 540p@30). Content that does not
    /// fit shows in the quantiser, which is read here.
    fn content_kbps_at_comfort(&self, quantiser_known: bool) -> Option<f64> {
        if !quantiser_known {
            return None;
        }
        let (w, h) = self.current().size_for(self.src_w, self.src_h);
        if w == 0 || h == 0 {
            return None;
        }
        let at_comfort = self.qp_smoothed.map_or(1.0, |qp| {
            f64::from(2.0f32.powf((qp - self.policy.qp_up) / 6.0))
        });
        Some(f64::from(self.produced_smoothed) * at_comfort)
    }

    /// The best rung at or below the current one whose content a braked budget pays for — `content`
    /// scaled by pixels and [`fps_factor`], with [`UP_HEADROOM`] — or the last rung.
    fn braked_landing(&self, cap_kbps: u32, content: f64) -> usize {
        let rungs = self.rungs();
        let cur = self.current();
        let (cw, ch) = cur.size_for(self.src_w, self.src_h);
        let cur_px = (f64::from(cw) * f64::from(ch)).max(1.0);
        (self.index..rungs.len())
            .find(|&i| {
                let r = rungs[i];
                let (w, h) = r.size_for(self.src_w, self.src_h);
                let need = content
                    * (f64::from(w) * f64::from(h) / cur_px)
                    * (fps_factor_with(&self.policy, r.fps)
                        / fps_factor_with(&self.policy, cur.fps));
                need * self.policy.up_headroom <= f64::from(cap_kbps)
            })
            .unwrap_or(rungs.len() - 1)
    }

    /// What the encoder would need a frame at rung `i`, and the climb line it is held to there, in
    /// ms: [`Self::encode_smoothed`] scaled by pixels (not cadence, see [`ENCODE_CLIMB_SHARE`])
    /// against that share of `i`'s frame interval. `None` while nothing has been encoded at this
    /// rung, or before the source is known.
    ///
    /// Linear in pixels. Measured against 1080p on one machine: 900p 0.6-0.83 of the time at 0.69
    /// the pixels, 720p 0.41-0.72 at 0.44, 540p 0.18-0.48 at 0.25, 360p 0.12-0.24 at 0.11. A frame
    /// has a fixed part, so from small rungs the line errs high (a climb may take two steps), and
    /// from 720p and 900p it is about right.
    fn encode_projection(&self, i: usize) -> Option<(f32, f32)> {
        let measured = self.encode_smoothed?;
        let rung = *self.rungs().get(i)?;
        let (cw, ch) = self.current().size_for(self.src_w, self.src_h);
        let (w, h) = rung.size_for(self.src_w, self.src_h);
        let cur_px = f64::from(cw) * f64::from(ch);
        if cur_px <= 0.0 || rung.fps == 0 {
            return None;
        }
        let projected = f64::from(measured) * (f64::from(w) * f64::from(h) / cur_px);
        let line = self.policy.encode_climb_share * 1000.0 / rung.fps as f32;
        Some((projected as f32, line))
    }

    /// Whether the encoder has room at rung `i`: its projected per-frame time inside the climb line.
    /// See [`Self::encode_projection`].
    fn encode_room(&self, i: usize) -> bool {
        self.encode_projection(i)
            .is_none_or(|(projected, line)| projected <= line)
    }

    /// The climb dwell a climb to rung `to` needs: [`UP_AFTER`], doubled for each `cpu_bound`
    /// descent after the first since the processor last held the rung it shed, up to
    /// [`CPU_CLIMB_DWELL_MAX`], for a climb to that rung or better. A climb to a worse rung waits
    /// the ordinary dwell.
    fn climb_dwell(&self, to: usize) -> Duration {
        match self.cpu_shed {
            Some(shed) if self.cpu_streak > 1 && to <= shed => {
                let doublings = (self.cpu_streak - 1).min(8);
                self.policy
                    .up_after()
                    .saturating_mul(1 << doublings)
                    .min(self.policy.cpu_climb_dwell_max())
            }
            _ => self.policy.up_after(),
        }
    }

    /// A descent `cpu_bound` asked for, from rung `from` (an index, before the move): count it, and
    /// say what the next climb back will need.
    fn note_cpu_descent(&mut self, from: usize, to: usize, encode_ms: f32) {
        let held_ms = self.cpu_held.as_millis().min(u128::from(u64::MAX)) as u64;
        let was_shed = self.cpu_shed;
        self.cpu_streak = self.cpu_streak.saturating_add(1);
        self.cpu_shed = Some(from);
        self.cpu_held = Duration::ZERO;
        let rungs = self.rungs();
        let rung = |i: usize| {
            rungs
                .get(i)
                .map_or_else(|| "-".to_string(), |r| format!("{}p@{}", r.max_h, r.fps))
        };
        let from_rung = rungs.get(from).copied();
        tracing::debug!(
            streak = self.cpu_streak,
            from = %rung(from),
            to = %rung(to),
            encode_ms = format!("{encode_ms:.1}"),
            encode_avg_ms = self
                .encode_smoothed
                .map_or_else(|| "-".to_string(), |e| format!("{e:.1}")),
            line_ms = format!(
                "{:.1}",
                from_rung.map_or(0.0, |r| self.policy.encode_budget_share * 1000.0 / r.fps.max(1) as f32)
            ),
            climb_line_ms = format!(
                "{:.1}",
                from_rung.map_or(0.0, |r| self.policy.encode_climb_share * 1000.0 / r.fps.max(1) as f32)
            ),
            climb_dwell_ms = self.climb_dwell(from).as_millis() as u64,
            previous_shed = %was_shed.map_or_else(|| "-".to_string(), rung),
            previous_held_ms = held_ms,
            "cpu_bound descent: the processor could not hold the rung; a climb back to it needs the \
             encoder inside the climb line there, for climb_dwell_ms"
        );
    }

    /// The processor at the rung it last shed, or a better one, for this tick: once that has lasted
    /// [`CPU_STREAK_FORGET`], the run of `cpu_bound` descents is forgotten.
    fn watch_cpu_hold(&mut self, dt: Duration) {
        let Some(shed) = self.cpu_shed else {
            return;
        };
        if self.index > shed {
            return;
        }
        self.cpu_held = self.cpu_held.saturating_add(dt);
        if self.cpu_held >= self.policy.cpu_streak_forget() {
            tracing::debug!(
                streak = self.cpu_streak,
                rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
                held_ms = self.cpu_held.as_millis() as u64,
                encode_avg_ms = self
                    .encode_smoothed
                    .map_or_else(|| "-".to_string(), |e| format!("{e:.1}")),
                "cpu_bound streak forgotten: the processor has held the rung it last shed; climbs \
                 need the ordinary dwell again"
            );
            self.forget_cpu_streak();
        }
    }

    /// No `cpu_bound` descents on record. See [`Self::climb_dwell`].
    fn forget_cpu_streak(&mut self) {
        self.cpu_streak = 0;
        self.cpu_shed = None;
        self.cpu_held = Duration::ZERO;
    }

    /// Where a matured descent goes: one rung, except a pixel step while a receiver-set brake is in
    /// force, which goes straight to the rung the braked budget pays for, or nowhere (`None`) when
    /// the content already fits it here.
    ///
    /// Walking one rung per dwell under a brake (cut to 130 kbps at 900p, content costing 106):
    ///
    /// ```text
    /// 16:19:44.8  900p -> 720p   a 57 kB keyframe: 3.8 s of a 120 kbps budget; the bit bucket
    ///                            withheld 96% of frames and the phone showed 1-4 fps for five seconds
    /// 16:19:50.4  720p -> 540p   a 37 kB keyframe: a hard hold at 1050 ms (16:19:51.6)
    /// 16:19:55.4  540p -> 360p   a 21 kB keyframe — and 200 ms later the brake's reports were
    ///                            recognised as a longer path and it released
    /// ```
    ///
    /// A rung does not answer a brake: the brake cuts the budget and the encoder holds the cut at
    /// any rung by coarsening. A pixel step costs a keyframe, `K x 8 / cap` seconds of the braked
    /// budget; a cadence step costs nothing. So under a brake:
    ///
    /// - cadence step: taken as ever; from 1080p60 that still gives up the bonus rung at once.
    /// - pixel step: only when the content does not fit the braked budget here
    ///   ([`Self::content_kbps_at_comfort`] with [`UP_HEADROOM`] above the ceiling), and then
    ///   straight to where it fits ([`Self::braked_landing`]): one keyframe, not one per dwell.
    /// - under loss (a brake cut on loss, or real loss in [`REAL_LOSS_MEMORY`]): one rung as ever,
    ///   since the viewer's keyframe requests make the content unpriceable.
    ///
    /// Chosen in the simulator against the walk and cadence alone
    /// (`crates/sim/scenarios/brake-120k*.toml`). The brake
    /// itself is unchanged, and `cpu_bound` is the processor, not the budget, so it always steps.
    fn descent_target(&self, cpu_bound: bool, quantiser_known: bool) -> Option<usize> {
        let next = self.index + 1;
        let rungs = self.rungs();
        let cur = self.current();
        let pixel_step = rungs.get(next).is_some_and(|r| r.max_h != cur.max_h);
        let braked = self.brake.filter(|b| !b.silence_only);
        let (Some(b), true, false) = (braked, pixel_step, cpu_bound) else {
            return Some(next);
        };
        // Loss: the viewer is recovering, and its keyframe requests fill production and the bit
        // bucket, so the content cannot be priced. One step.
        if b.by_loss || self.since_real_loss < self.policy.real_loss_memory() {
            tracing::debug!(
                cap_kbps = b.cap_kbps,
                by_loss = b.by_loss,
                last_loss_pct = ?self.last_fresh_loss.map(|l| l * 100.0),
                since_real_loss_ms = self.since_real_loss.as_millis().min(u128::from(u64::MAX)) as u64,
                "braked descent under loss: the content cannot be priced while the viewer recovers; \
                 one rung, as always"
            );
            return Some(next);
        }
        let Some(content) = self.content_kbps_at_comfort(quantiser_known) else {
            tracing::debug!(
                cap_kbps = b.cap_kbps,
                "braked descent: the encoder reports no quantiser, so the content cannot be priced; \
                 one rung, as always"
            );
            return Some(next);
        };
        let landing = self.braked_landing(b.cap_kbps, content);
        let rung = |i: usize| format!("{}p@{}", rungs[i].max_h, rungs[i].fps);
        if landing <= self.index {
            tracing::debug!(
                cap_kbps = b.cap_kbps,
                content_kbps = format!("{content:.0}"),
                produced_kbps = format!("{:.0}", self.produced_smoothed),
                qp = self.qp_smoothed.map_or_else(|| "-".to_string(), |q| format!("{q:.1}")),
                drop = format!("{:.2}", self.drop_smoothed),
                rtt_ms = ?self.last_fresh_rtt,
                rtt_base_ms = ?self.rtt_base_ms(),
                rung = %rung(self.index),
                refused = %rung(next),
                "braked descent refused: this rung's content fits the brake's budget at a \
                 comfortable quantiser, so the cut answers the brake and a keyframe would only \
                 spend it"
            );
            return None;
        }
        let to = landing.max(next);
        tracing::debug!(
            cap_kbps = b.cap_kbps,
            content_kbps = format!("{content:.0}"),
            produced_kbps = format!("{:.0}", self.produced_smoothed),
            qp = self.qp_smoothed.map_or_else(|| "-".to_string(), |q| format!("{q:.1}")),
            drop = format!("{:.2}", self.drop_smoothed),
            from = %rung(self.index),
            to = %rung(to),
            skipped = to - next,
            "braked descent: the content does not fit the brake's budget here; straight to the rung \
             it fits, one keyframe"
        );
        Some(to)
    }

    /// Watch our own send queue in the startup window and decide the startup queue jump when it
    /// says the link refuses the rung. Each tick while the window is open.
    fn watch_startup_queue(&mut self, queue_age_ms: u32) {
        if self.startup_queue_target.is_some() || self.startup_queue_used || self.pinned.is_some() {
            return;
        }
        let mean = |ring: &[u32; STARTUP_DRAIN_TICKS]| {
            let sum: u64 = ring.iter().map(|&k| u64::from(k)).sum();
            u32::try_from(sum / STARTUP_DRAIN_TICKS as u64).unwrap_or(u32::MAX)
        };
        let full = self.startup_egress_seen >= STARTUP_DRAIN_TICKS;
        let at_limit = queue_age_ms >= STARTUP_QUEUE_LIMIT_MS;
        let standing_ms = mean(&self.startup_queue_ages);
        let standing = full && standing_ms >= self.policy.startup_queue_standing_ms;
        if !(at_limit || standing) {
            // An episode over: the next one's refusal is said again.
            self.startup_queue_refusal_logged = false;
            return;
        }
        // A copy: the refusals below write to `self` with it in hand. Eight rungs at most, and only
        // on the ticks our queue is at the limit.
        let rungs = self.rungs().to_vec();
        let rung = |i: usize| format!("{}p@{}", rungs[i].max_h, rungs[i].fps);
        if !full {
            // At most the first two seconds of media, and decided again on the next tick.
            tracing::trace!(
                queue_age_ms,
                ticks = self.startup_egress_seen,
                needed = STARTUP_DRAIN_TICKS,
                "startup queue: our queue is at the limit, but there is not yet two seconds of \
                 egress to price the link from"
            );
            return;
        }
        // Nothing measured yet: the estimate is still str0m's opening 600, so the queue is our
        // opening keyframes waiting for feedback, not the link. See the `first_estimate` field.
        if !self.estimate_moved {
            tracing::trace!(
                queue_age_ms,
                standing_ms,
                "startup queue: the estimate has not left str0m's opening value; nothing measured"
            );
            return;
        }
        // A clean collapse held: the queue is str0m's pacer draining at a number the receiver says
        // is not the link, which the hold exists to keep from shedding rungs. See [`CleanCollapse`].
        if self.collapse.is_some() {
            tracing::trace!(
                queue_age_ms,
                standing_ms,
                "startup queue: a clean collapse is held, so the queue is the collapse's"
            );
            return;
        }
        // Behind an estimate nothing has measured, with the receiver seeing no queue: the queue is
        // a keyframe or burst behind a pacer our own quiet set, not production the link refuses (in
        // the simulator a still screen's keyframe waited 1010 ms behind a 67 kbps estimate, and
        // this jumped 1080p60 to 360p@15 on a screen producing 2 kbps:
        // `crates/sim/scenarios/still-keyframe.toml`). A link that refuses the rung holds what we
        // send, past the line in [`Self::rtt_queued_at`]. Not gated on production: on a 120 kbps
        // budget one 24 kB refinement frame is most of two seconds' budget. See
        // [`Self::pacer_only`].
        if let Ok(()) = self.pacer_only() {
            if !self.startup_queue_refusal_logged {
                self.startup_queue_refusal_logged = true;
                tracing::debug!(
                    queue_age_ms,
                    standing_ms,
                    at_limit,
                    produced_kbps = format!("{:.0}", self.produced_smoothed),
                    estimate_kbps = self.smoothed,
                    capacity_kbps = self.capacity_kbps(),
                    rtt_ms = ?self.last_fresh_rtt,
                    rtt_base_ms = ?self.rtt_base_ms(),
                    "startup queue: not the link refusing the rung — the queue waits behind an \
                     estimate nothing has measured, and the receiver sees no queue on the path"
                );
            }
            return;
        }
        let drain = mean(&self.startup_egress);
        let target = self.best_rung_for(drain);
        // What the link is believed to carry besides: the estimate, or the capacity the receiver
        // confirmed when that is larger — a link measured fat is not made thin by our own queue.
        let believed = self.smoothed.max(self.capacity_kbps());
        let by_estimate = self.best_rung_for(believed);
        // Two rungs or more: one is the ordinary ladder's step, and a jump that saves no keyframe
        // over walking is not worth making on our own queue's word.
        let thin =
            target >= self.index + 2 && rungs[target].max_h < self.policy.startup_thin_below_h;
        // The estimate must agree the link is thin: our queue at the limit with the estimate above
        // the line is str0m's slow start behind a fat link, which it outgrows in a second.
        let estimate_thin = rungs[by_estimate].max_h < self.policy.startup_thin_below_h;
        if thin && estimate_thin {
            tracing::debug!(
                queue_age_ms,
                standing_ms,
                at_limit,
                drain_kbps = drain,
                estimate_kbps = self.smoothed,
                capacity_kbps = self.capacity_kbps(),
                from = %rung(self.index),
                to = %rung(target),
                "startup queue: our queue is at the breaker's limit (or standing past the guard) \
                 while what leaves pays for no rung above the thin line — the link is refusing this \
                 rung; jumping to what the drain rate carries"
            );
            self.startup_queue_target = Some(target);
        } else if !self.startup_queue_refusal_logged {
            // Once per episode of our queue at the limit: a decision not to jump, on numbers a
            // later reader needs.
            self.startup_queue_refusal_logged = true;
            tracing::debug!(
                queue_age_ms,
                standing_ms,
                at_limit,
                drain_kbps = drain,
                estimate_kbps = self.smoothed,
                capacity_kbps = self.capacity_kbps(),
                by_drain = %rung(target),
                by_estimate = %rung(by_estimate),
                refused = if !thin { "drain" } else { "estimate" },
                "startup queue: our queue is at the limit, but the link is not measured thin (drain: \
                 what left pays for a rung at or above the thin line, or one within a step of this \
                 one; estimate: the estimate pays for a rung at or above the thin line)"
            );
        }
    }

    /// The startup decision our own queue makes: the first tick after the settle once
    /// [`Self::watch_startup_queue`] has decided it, straight to the best rung the measured drain
    /// rate (egress, not the estimate) pays for. Once per session, inside [`STARTUP_QUEUE_WINDOW`].
    /// Inside the receiver rule's eight seconds it is the startup decision; after, the only other
    /// jump a session gets. Two rungs or more, never on a pinned ladder.
    ///
    /// While a second of our frames waits, what leaves the socket is what the path takes from us.
    /// On a recorded 3G path it read 237 kbps over the three seconds before a hard hold, enough for
    /// 360p@30; without this the ladder walked there over thirteen seconds.
    fn startup_queue_jump(&mut self) -> Option<usize> {
        let target = self.startup_queue_target.take()?;
        if self.startup_queue_used {
            return None;
        }
        self.startup_queue_used = true;
        if !self.startup_done {
            tracing::debug!(
                warm_ms = self.warm_for.as_millis() as u64,
                "startup decision made by our own queue: the receiver rule's window closes with it"
            );
            self.startup_done = true;
        }
        let rungs = self.rungs();
        if target <= self.index {
            tracing::debug!(
                target = %format!("{}p@{}", rungs[target].max_h, rungs[target].fps),
                rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
                "startup decision: queue — the ladder already reached the rung it chose; no jump"
            );
            return None;
        }
        tracing::debug!(
            from = %format!("{}p@{}", self.current().max_h, self.current().fps),
            to = %format!("{}p@{}", rungs[target].max_h, rungs[target].fps),
            warm_ms = self.warm_for.as_millis() as u64,
            "startup decision: queue — our own queue at the limit says the link is thin; jumping"
        );
        Some(target)
    }

    /// The startup decision: once, [`STARTUP_DECIDE_AFTER`] into the session, jump straight to the
    /// rung a thin link can carry. Returns the rung index to move to.
    ///
    /// A low estimate is not a thin link: early on it is str0m's slow start on whatever traffic we
    /// make (an LTE opening on a still screen sat at 244-532 with a flat round trip and no loss,
    /// and later carried 5-8 Mbps at 1080p60). A thin link says so at the far end once the opening
    /// traffic hits it: a round trip past [`RTT_INFLATION`] of the least seen, or loss (recorded 3G
    /// openings: 431 ms on 211 with 25.6% loss; 2020 on 1001, then a brake). So a jump needs that
    /// evidence inside the window ([`Self::on_report`], the brake in [`Self::tick`]) as well as a
    /// thin estimate.
    fn startup_jump(&mut self) -> Option<usize> {
        if self.startup_done || !self.warm || self.warm_for < self.policy.startup_decide_after() {
            return None;
        }
        self.startup_done = true;
        // A pinned ladder only sheds cadence, and a cadence step costs no keyframe — the walk this
        // exists to shorten is a walk through IDRs, and a pinned ladder does not take one.
        if self.pinned.is_some() {
            tracing::debug!("startup decision: none, the resolution is pinned");
            return None;
        }
        if self.startup_trying < self.policy.startup_trying() {
            tracing::debug!(
                trying_ms = self.startup_trying.as_millis() as u64,
                "startup decision: none, the encoder was not trying to fill its budget"
            );
            return None;
        }
        // Nothing to price a jump from: str0m's estimate never left its configured opening value,
        // so no feedback ever reached it.
        if self.startup_peak_kbps == 0 {
            tracing::debug!(
                "startup decision: none, the estimate never moved off its initial value"
            );
            return None;
        }
        let measured = self.brake.map_or(self.startup_peak_kbps, |b| {
            self.startup_peak_kbps.min(b.cap_kbps)
        });
        let rungs = self.rungs();
        // The same pricing the climb gate uses as its floor: the table, with headroom. The best
        // rung at or below the current one that the most the link was measured at can pay for.
        let target = (self.index..rungs.len())
            .find(|&i| {
                let price = f64::from(rungs[i].required_kbps_with(
                    &self.policy,
                    self.src_w,
                    self.src_h,
                    self.quality,
                ));
                f64::from(measured) >= price * self.policy.up_headroom
            })
            .unwrap_or(rungs.len() - 1);
        let thin = target > self.index && rungs[target].max_h < self.policy.startup_thin_below_h;
        match (thin, self.startup_evidence) {
            (true, Some(evidence)) => {
                tracing::debug!(
                    peak_kbps = self.startup_peak_kbps,
                    measured_kbps = measured,
                    evidence,
                    rung = %format!("{}p@{}", rungs[target].max_h, rungs[target].fps),
                    "startup decision: thin, and the receiver says so; jumping"
                );
                Some(target)
            }
            (true, None) => {
                tracing::debug!(
                    peak_kbps = self.startup_peak_kbps,
                    rtt_min_ms = ?self.startup_rtt_min,
                    "startup decision: none, the estimate is low but the receiver reports no queue \
                     and no loss — a slow start is not a thin link"
                );
                None
            }
            (false, _) => {
                tracing::debug!(
                    peak_kbps = self.startup_peak_kbps,
                    measured_kbps = measured,
                    evidence = ?self.startup_evidence,
                    "startup decision: none, the link was measured above the thin line"
                );
                None
            }
        }
    }

    /// Point the ladder at the real screen size once it is known. Called each tick; a no-op unless
    /// it changed.
    pub fn set_source(&mut self, w: u32, h: u32) {
        if w == 0 || h == 0 {
            return;
        }
        let changed = (w, h) != (self.src_w, self.src_h);
        if changed {
            // Every rung's price and the probe ceiling are priced against this.
            tracing::debug!(
                from = %format!("{}x{}", self.src_w, self.src_h),
                to = %format!("{w}x{h}"),
                "ladder priced against a new source size"
            );
            self.src_w = w;
            self.src_h = h;
        }
        // The first real size too when it is the guess: the reach is the real source's.
        if changed || !self.source_known {
            self.source_known = true;
            self.note_probe_ceiling_reach();
        }
    }

    /// Whether the probe ceiling on this source reaches the price at which the climb gate opens the
    /// top rung (its desktop price times `up_headroom`), as the reference ladder always does
    /// (`the_probe_ceiling_can_actually_reach_the_top_rung`). The server does not know the source
    /// when it picks a profile, so a profile is not refused for it: such a session climbs to the
    /// top only on the estimate, never by padding. One line per source size.
    fn note_probe_ceiling_reach(&self) {
        let ceiling = desired_bitrate_kbps_with(&self.policy, self.src_w, self.src_h, self.quality);
        let top = self.policy.ladder[0].required_kbps_with(
            &self.policy,
            self.src_w,
            self.src_h,
            self.quality,
        );
        if f64::from(ceiling) < f64::from(top) * self.policy.up_headroom {
            tracing::debug!(
                rule = "probe_ceiling_reaches_top_rung",
                source = %format!("{}x{}", self.src_w, self.src_h),
                "quality profile: the probe ceiling on this source is under the top rung's climb \
                 price; padding alone cannot lift the estimate that far"
            );
        }
    }

    /// Change the manual quality setting. Returns the rung if it moved.
    pub fn set_quality(&mut self, quality: Quality) -> Option<Rung> {
        if self.quality == quality {
            return None;
        }
        tracing::debug!(from = ?self.quality, to = ?quality, "quality preference changed");
        self.quality = quality;
        self.down_dwell = Duration::ZERO;
        Some(self.current())
    }

    /// One tick of the ladder. Returns a new rung when it moved.
    ///
    /// Three descent signals, each a direct measurement of a different limit and none derived from
    /// this controller's own output:
    ///
    /// - `avg_qp`, the encoder's quantiser: this picture does not fit in these bits (libwebrtc's
    ///   `QualityScaler` steers on the same).
    /// - `encode_ms`, the processor: the only limit visible before any network signal, and the one
    ///   that matters on a two-core machine.
    /// - `queue_ms`, the wire: bytes committed over the rate they actually drain at.
    ///
    /// A capture-versus-delivery ratio is not one of them: counted after an admission gate it can
    /// never fall (measured 0.9992 over a session the viewer saw at 2.4 fps).
    ///
    /// Climbing needs the quantiser low, the encoder spending its allowance, the estimate covering
    /// the next rung and a quiet queue: a low quantiser alone means cheap content, not a wide link.
    /// Plus the processor: the encode time scaled to the rung's pixels inside
    /// [`ENCODE_CLIMB_SHARE`] of its interval, waited out longer after repeated `cpu_bound`
    /// descents ([`CPU_CLIMB_DWELL_MAX`]).
    ///
    /// It terminates: each descent strictly decreases a bounded index, and descending lowers every
    /// bar it is measured against.
    pub fn tick(&mut self, fb: Feedback, dt: Duration) -> Option<Rung> {
        self.smoothed = fb.estimate_kbps;
        // What we had handed the transport by this tick, for the viewer's count to be read against.
        // See [`Self::note_viewer_frames`].
        self.delivery.advance(dt);
        // Warm means media has left, and nothing else may set it. Before congestion control has
        // said anything the floor in [`queue_ms`] assumes 120 kbps, so one ordinary 4 kB frame
        // reads as 242 ms; and str0m reports its configured 600 kbps before any feedback. Until
        // media has left, neither the queue nor the conservation check says anything. See
        // [`Self::warm`].
        let media = fb.egress_kbps > 0
            && (fb.report.is_some() || fb.egress_kbps >= self.policy.media_egress_kbps);
        if media && !self.warm {
            tracing::debug!(
                egress_kbps = fb.egress_kbps,
                by_stats = fb.report.is_some(),
                "media is flowing: the ladder's network arms and the startup window are live"
            );
        }
        self.warm |= media;
        // str0m's configured opening estimate is not a measurement; the first one that differs
        // from it is. See the `first_estimate` field.
        if fb.estimate_kbps > 0 {
            match self.first_estimate {
                None => self.first_estimate = Some(fb.estimate_kbps),
                Some(first) if first != fb.estimate_kbps => {
                    if !self.estimate_moved {
                        tracing::debug!(
                            opening_kbps = first,
                            estimate_kbps = fb.estimate_kbps,
                            "the estimate left str0m's opening value: it is a measurement from here"
                        );
                        // An informative floor that only ever confirmed the opening value is that
                        // value echoed back, and once the first measurement is above it, not a
                        // floor: kept, it became the first capacity evidence and set the probe
                        // target to twice our own configuration one second in. A first measurement
                        // below it is left to the loaded band.
                        if self.informative_from_opening
                            && self.informative_kbps > 0
                            && fb.estimate_kbps > first
                        {
                            tracing::debug!(
                                forgotten_kbps = self.informative_kbps,
                                opening_kbps = first,
                                estimate_kbps = fb.estimate_kbps,
                                "informative floor forgotten: it had only confirmed str0m's opening \
                                 value, our own configuration, and the first measurement is above \
                                 it — it is not capacity evidence"
                            );
                            self.informative_kbps = 0;
                            self.informative_from_opening = false;
                            self.loaded_streak = Duration::ZERO;
                            self.since_loaded = Duration::MAX;
                        }
                    }
                    self.estimate_moved = true;
                }
                Some(_) => {}
            }
        }
        self.egress_recent[self.egress_at] = fb.egress_kbps;
        self.egress_at = (self.egress_at + 1) % EGRESS_WINDOW;
        // Into the interval the next fresh receiver report closes. See `egress_open_kbps`.
        self.egress_open_kbps = self.egress_open_kbps.max(fb.egress_kbps);
        // What the next receiver report will be describing. See `on_report`. The budget is the
        // encoder's, priced before anything below moves it: the one it has been spending against.
        self.report_egress_sum = self
            .report_egress_sum
            .saturating_add(u64::from(fb.egress_kbps));
        self.report_produced_sum = self
            .report_produced_sum
            .saturating_add(u64::from(fb.produced_kbps));
        self.report_budget_sum = self
            .report_budget_sum
            .saturating_add(u64::from(self.encoder_target_kbps()));
        self.report_egress_ticks = self.report_egress_ticks.saturating_add(1);
        self.since_real_loss = self.since_real_loss.saturating_add(dt);
        self.since_fresh = self.since_fresh.saturating_add(dt);
        self.since_rtt_unclean = self.since_rtt_unclean.saturating_add(dt);
        self.since_rtt_queued = self.since_rtt_queued.saturating_add(dt);
        if let Some(resumed) = self.outage.as_mut().and_then(|o| o.resumed_for.as_mut()) {
            *resumed = resumed.saturating_add(dt);
        }
        // Feedback liveness after this tick's report, computed first because the evidence below is
        // taken before the report is read. See [`Self::feedback_live`].
        let live = self.feedback_live_with(fb.report);
        // Page hidden and receiver silent: the page asleep. Nothing is learned and the evidence
        // does not decay. See [`Self::set_page_hidden`].
        let asleep = self.page_hidden && !live;
        self.wake_window = self.wake_window.saturating_sub(dt);
        // The best estimate seen, which the probe target is twice of until the path has produced
        // capacity evidence (see `probe_best_kbps`): only a measurement (the estimate has left
        // str0m's opening value, or was never that value) on live feedback, with no receiver brake.
        // Trace: it can rise every tick of a climb, and the probe target line says it at debug.
        //
        // "Or was never that value": str0m 0.24 emits its first estimate through its three-second
        // smoother, so when the opening probes return before our first tick the first value seen is
        // already their mean with the 600 (1521 in the simulator's `smoke`), and waiting for
        // `estimate_moved` would hold str0m's exponential probing at the floor for three seconds.
        let refused_by_receiver = self.brake.is_some_and(|b| !b.silence_only);
        let measured = self.estimate_moved || fb.estimate_kbps != STR0M_OPENING_KBPS;
        let taken = measured && live && !refused_by_receiver;
        if measured && fb.estimate_kbps > self.probe_best_kbps {
            if taken {
                tracing::trace!(
                    from_kbps = self.probe_best_kbps,
                    to_kbps = fb.estimate_kbps,
                    evidence = self.evidence_seen,
                    "best estimate seen rose"
                );
                self.probe_best_kbps = fb.estimate_kbps;
            } else {
                tracing::trace!(
                    estimate_kbps = fb.estimate_kbps,
                    best_kbps = self.probe_best_kbps,
                    live,
                    refused_by_receiver,
                    "estimate above the best seen not taken: the receiver is silent or braking"
                );
            }
        }
        // The ramp's "still rising": the best estimate, taken as such. Equal to an older best (the
        // smoother holds between emissions) counts; the ramp ends when it falls.
        self.estimate_at_best =
            taken && self.probe_best_kbps > 0 && fb.estimate_kbps >= self.probe_best_kbps;

        // Did the link answer the question the estimate is asking, in this window? A band, and
        // every edge matters:
        //
        // - at least 65%: str0m's own ALR test (`bwe/alr_detector/`). Below it the sender is
        //   application-limited and throughput describes the application.
        // - at most 110% ([`LEADING_SHARE_PCT`]): above it the estimate is behind the traffic, the
        //   normal state just after a pause when the budget comes from the informative floor.
        //   Without this edge the floor recorded the collapsed estimate and erased itself.
        // - at least 300 kbps: a ratio of two small numbers is noise, and a still desktop's padding
        //   can satisfy both edges of an estimate the padding itself dragged down.
        //
        // The upper edge is tested against the maximum of [`EGRESS_WINDOW`], not this tick: a
        // quantity sweeping through a band satisfies it for one window on the way past (recorded
        // twice: egress falling from 10 Mbps landed inside the band of a collapsed 3072; resume
        // packets at 1224 looked like agreement with an estimate of 1186). The lower edge and the
        // floor stay per tick: "application-limited right now" is about now.
        //
        // Lowering the floor needs [`LOADED_CONFIRM`] of uninterrupted agreement, since a
        // transition can also land in the band for a window or two (see that constant). Raising it
        // applies at once: that direction cannot over-commit. Set rather than maximised, so it
        // follows a link down; otherwise decaying on [`INFORMATIVE_HALF_LIFE`] against `dt`.
        //
        // Only on live feedback ([`Self::feedback_live`]): on a bench blackout the smoother's
        // estimate and egress into the dead link sat in the band for two seconds. And not under a
        // brake the receiver set: it just said the link is not carrying what the estimate allows.
        let egress_peak = u64::from(self.egress_recent.iter().copied().max().unwrap_or(0));
        let loaded = live
            && !refused_by_receiver
            && fb.egress_kbps >= self.policy.loaded_floor_kbps
            && u64::from(fb.egress_kbps) * 100
                >= u64::from(fb.estimate_kbps) * self.policy.loaded_share_pct
            && egress_peak * 100 <= u64::from(fb.estimate_kbps) * self.policy.leading_share_pct;
        if loaded {
            self.loaded_streak = self.loaded_streak.saturating_add(dt);
            self.since_loaded = Duration::ZERO;
            if fb.estimate_kbps >= self.informative_kbps
                || self.loaded_streak >= self.policy.loaded_confirm()
            {
                // Lowering the floor is the decision with a cost — it is what a paused screen's
                // budget stands on — so the first tick of a run that does it is on record.
                if fb.estimate_kbps < self.informative_kbps && !self.confirm_logged {
                    self.confirm_logged = true;
                    tracing::debug!(
                        from_kbps = self.informative_kbps,
                        to_kbps = fb.estimate_kbps,
                        egress_kbps = fb.egress_kbps,
                        streak_ms = self.loaded_streak.as_millis() as u64,
                        "informative floor follows the estimate down: the link agreed under load"
                    );
                }
                self.informative_kbps = fb.estimate_kbps;
                // Set against an estimate str0m has not moved yet: see the block above that
                // forgets it when the first measurement lands above it.
                self.informative_from_opening = !self.estimate_moved;
            }
        } else {
            self.confirm_logged = false;
            self.loaded_streak = Duration::ZERO;
            if !asleep {
                let decay = 0.5f64
                    .powf(dt.as_secs_f64() / self.policy.informative_half_life().as_secs_f64());
                self.informative_kbps = (f64::from(self.informative_kbps) * decay) as u32;
            }
            self.since_loaded = self.since_loaded.saturating_add(dt);
        }
        self.pressure = fb.queue_age_ms as f32 / QUEUE_GUARD_MS as f32;

        // While a clean collapse is held, the queue and the production-over-egress ratio describe
        // the collapsed pacer, not the network, and are kept out of the ladder's filters until the
        // hold ends; otherwise the five-second queue filter would carry the collapse's backlog past
        // the hold. Pushback still reads the live queue. See [`CleanCollapse`]. Nor while the last
        // move's own keyframe is on the wire: a 63 kB keyframe behind a ~110 kbps pacer drained in
        // 1.6 s, yet the filter still read 83 ms when the settle ended and `queue_late` shed the
        // rung four frames in. See [`SETTLE_AFTER_MOVE`]; the filter that keeps the settle is for
        // when the receiver says the link is failing ([`Self::late_for_ladder`]).
        if !self.settling.is_zero() {
            self.settle_queue_peak_ms = self.settle_queue_peak_ms.max(fb.queue_age_ms);
        }
        if self.collapse.is_none() {
            // The queue's own measured age, smoothed. The only network signal the ladder gets.
            if self.settling.is_zero() {
                self.late_smoothed += (fb.queue_age_ms as f32 - self.late_smoothed) * LATE_ALPHA;
            }
            self.late_with_settle += (fb.queue_age_ms as f32 - self.late_with_settle) * LATE_ALPHA;

            // Production over egress, both measured. SIGNAL_ALPHA rather than LATE_ALPHA: keyframe
            // bytes are already excluded from production.
            let egress = f32::max(fb.egress_kbps as f32, ABSOLUTE_FLOOR_KBPS as f32);
            let growth = fb.produced_kbps as f32 / egress;
            self.growth_smoothed += (growth - self.growth_smoothed) * SIGNAL_ALPHA;
        }
        // What this content costs at this rung, smoothed: the climb gate prices a candidate rung
        // from the content rather than a table.
        self.produced_smoothed += (fb.produced_kbps as f32 - self.produced_smoothed) * SIGNAL_ALPHA;
        // The re-anchor decision below reads measured egress and production, not this mean, so
        // updating it first is harmless.
        self.spend_smoothed += (fb.spend_ratio - self.spend_smoothed) * SIGNAL_ALPHA;
        self.drop_smoothed += (fb.drop_ratio - self.drop_smoothed) * SIGNAL_ALPHA;
        // The encoder's per-frame time at this rung, for the climb gate. `0.0` is a tick with no
        // frame in it, which says nothing about the encoder. See the `encode_smoothed` field.
        if fb.encode_ms > 0.0 {
            self.encode_smoothed = Some(match self.encode_smoothed {
                None => fb.encode_ms,
                Some(prev) => prev + (fb.encode_ms - prev) * SIGNAL_ALPHA,
            });
        }
        self.watch_cpu_hold(dt);
        // `fb.qp_ceiling` has one reader, `starved` below.
        self.qp_seen = self.qp_seen.saturating_add(fb.qp_samples);
        // Kept for the log and for nothing else. See below.
        if let Some(qp) = fb.avg_qp {
            self.qp_smoothed = Some(match self.qp_smoothed {
                None => qp,
                Some(prev) => prev + (qp - prev) * SIGNAL_ALPHA,
            });
        }

        // ── what the receiver says ─────────────────────────────────────────────────────────────
        //
        // Before the re-anchor, so a report of loss on this tick can refuse it. The viewer's own
        // count first: a drain this tick's report would begin is judged against it.
        self.read_viewer_frames(fb.queue_age_ms);
        if let Some(report) = fb.report {
            self.on_report(report);
        }
        self.release_brake(dt);
        // The new path's round trip, for the path-change test "at most half the old one": the
        // least fresh report since the change. See [`PathMove`].
        if let Some(mv) = self.path_move.as_mut() {
            mv.age = mv.age.saturating_add(dt);
            if let Some(rtt) = fb
                .report
                .filter(ReceiverReport::fresh)
                .and_then(|r| r.rtt_ms)
            {
                mv.new_rtt_min_ms = Some(mv.new_rtt_min_ms.map_or(rtt, |m| m.min(rtt)));
                mv.new_reports += 1;
            }
        }
        // A fall of the estimate by more than [`ESTIMATE_DROP_LOG_PCT`] within one stats interval,
        // logged with the receiver's account of the same interval: whether a collapse was a queue
        // the far end saw or our own quiet decides every re-anchor. At most one a second.
        self.interval_estimate_peak = self.interval_estimate_peak.max(fb.estimate_kbps);
        if let Some(r) = fb.report {
            let peak = self.interval_estimate_peak;
            if peak > 0
                && u64::from(fb.estimate_kbps) * 100 < u64::from(peak) * ESTIMATE_DROP_LOG_PCT
            {
                tracing::debug!(
                    from_kbps = peak,
                    to_kbps = fb.estimate_kbps,
                    fresh = r.fresh(),
                    rtt_ms = ?r.rtt_ms,
                    rtt_base_ms = ?self.rtt_base_ms(),
                    loss_pct = r.loss.map_or_else(|| "-".to_string(), |l| format!("{:.2}", l * 100.0)),
                    nacks = r.nacks,
                    egress_kbps = fb.egress_kbps,
                    produced_kbps = fb.produced_kbps,
                    queue_age_ms = fb.queue_age_ms,
                    brake = self.brake_state(),
                    "estimate dropped by more than 30% in one stats interval"
                );
            }
            self.interval_estimate_peak = fb.estimate_kbps;
        }

        // ── drain mode ─────────────────────────────────────────────────────────────────────────
        //
        // While the path drains a backlog of ours nothing below may judge the link or the rung:
        // what it would read is our own silence. A report back inside the band (`on_report`) or the
        // viewer's count here ends it, and the rest of this tick runs on the resumed state. See
        // [`Self::draining`].
        if self.drain.is_some() {
            self.drain_delivery_check();
        }
        if let Some(mut d) = self.drain {
            d.held = d.held.saturating_add(dt);
            d.since_proof = d.since_proof.saturating_add(dt);
            self.drain = Some(d);
            if d.since_proof >= self.policy.drain_max() || d.held >= self.policy.drain_max_proven()
            {
                let band = self.drain_exit_below();
                tracing::debug!(
                    held_ms = d.held.as_millis() as u64,
                    since_proof_ms = d.since_proof.as_millis() as u64,
                    max_ms = self.policy.drain_max().as_millis() as u64,
                    max_proven_ms = self.policy.drain_max_proven().as_millis() as u64,
                    exit_below_ms = band,
                    peak_rtt_ms = d.peak_rtt_ms,
                    last_rtt_ms = ?self.last_fresh_rtt,
                    reports = d.reports,
                    "drain mode timed out (no report has proved the backlog for its bound, or its \
                     absolute bound passed): resuming anyway; a path still holding a backlog will \
                     show it again in two reports"
                );
                self.leave_drain("timeout", None, band);
            } else {
                self.drain_tick(dt);
                return None;
            }
        }

        // ── re-anchoring congestion control ────────────────────────────────────────────────────
        //
        // The mechanism is in [`Self::take_bwe_reanchor`]. A `reset` discards str0m's measurements
        // and fires probes at 3x and 6x, so it is kept to cases where the estimate is demonstrably
        // not a measurement of the link, with the receiver as judge:
        //
        // - pause-resume: we were silent (egress and production under [`APP_LIMITED_PCT`] of the
        //   informative rate for [`REANCHOR_AFTER_PAUSE`]), that ended under
        //   [`REANCHOR_RESUME_WINDOW`] ago, and the encoder is past [`REANCHOR_RESUME_SPEND`] now.
        //   Nothing unclean reported (`nothing_unclean_reported`); a fresh report is not required.
        // - clean-collapse: the estimate fell under half the capacity evidence during motion, the
        //   encoder wants more than the collapsed pacer drains (or packets wait past
        //   [`QUEUE_GUARD_MS`]), and the receiver calls the path clean (`path_clean`).
        //
        // Both require warm ([`Self::warm`]); the clamped value at least
        // [`REANCHOR_DIVERGENCE_PCT`] of the live estimate and at least [`REANCHOR_MIN_KBPS`] (so
        // it never lowers the estimate or chases its ordinary breathing); and [`REANCHOR_EVERY`].
        // The value is [`Self::capacity_kbps`] clamped to what this rung can absorb. Outage-resume
        // and path-change ([`ReanchorTrigger::PathChange`]) are decided below.
        //
        // Every harmful override on record followed a queue or loss at the far end (a 3G link:
        // round trips of 283-347 on a 210 baseline, or 16.6% loss three seconds before), and every
        // collapse that should have been served had neither (see [`CLEAN_RTT_MARGIN_MS`]):
        //
        // ```text
        // 07:14:41  4752 -> 735    rtt 146 (base ~136), loss 0.10%      clean: re-anchored, a probe
        //                                                               measured 14519 four
        //                                                               seconds later
        // 07:15:47  3778, 270 kB   NACKs and 0.54% two seconds before   clean; the estimate was back
        //           in flight                                           at 5772 on its own
        // ```
        //
        // A real narrowing needs no re-anchor on the budget side: the floor follows the link down
        // after [`LOADED_CONFIRM`], pushback and the guards hold latency meanwhile, and the brake
        // cuts below the floor on loss or a standing queue.
        self.since_reanchor = self.since_reanchor.saturating_add(dt);
        self.since_path_reprobe = self.since_path_reprobe.saturating_add(dt);
        let app_limited = self.informative_kbps > 0
            && u64::from(fb.egress_kbps.max(fb.produced_kbps)) * 100
                < u64::from(self.informative_kbps) * self.policy.app_limited_pct;
        // A pause ends when demand comes back past [`APP_LIMITED_PCT`], or comes back lighter but
        // already above what the collapsed pacer drains: the moment the collapse starts to cost
        // (recorded: a 650-1100 kbps resume against an estimate fallen to 59).
        let binds = u64::from(fb.produced_kbps) * 10
            > u64::from(fb.estimate_kbps) * u64::from(PACING_FACTOR);
        if self.brake.is_some() {
            // A brake holds egress down for the receiver's reason, not ours: not a pause, and its
            // end is not a resume. Through an outage the silence brake drives egress under a
            // quarter of the informative rate, and pause-resume would fire as the link returned
            // without dropping the brake; the outage-resume trigger judges that end.
            if self.app_limited_for > Duration::ZERO {
                tracing::trace!(
                    app_limited_ms = self.app_limited_for.as_millis() as u64,
                    brake = self.brake_state(),
                    "application-limited count cleared: a brake is holding egress down"
                );
            }
            self.app_limited_for = Duration::ZERO;
        } else if !app_limited || binds {
            if self.app_limited_for >= self.policy.reanchor_after_pause() {
                self.resume_window = self.policy.reanchor_resume_window();
            }
            self.app_limited_for = Duration::ZERO;
        } else {
            self.app_limited_for = self.app_limited_for.saturating_add(dt);
        }
        // The capacity evidence decays on the informative half-life and takes in the estimate and
        // the last second's egress only on ticks the receiver calls the path clean (see
        // `capacity_kbps`). Not while the hidden page sleeps.
        if !asleep {
            let decay =
                0.5f64.powf(dt.as_secs_f64() / self.policy.informative_half_life().as_secs_f64());
            self.capacity_kbps = (f64::from(self.capacity_kbps) * decay) as u32;
        }
        let clean = self.path_clean();
        // Not while feedback is stale: the estimate is the smoother walking up and egress goes into
        // the silence ([`Self::feedback_live`]). Egress only once the reports either side call it
        // carried.
        let confirmed = std::mem::take(&mut self.egress_confirmed_kbps);
        if self.warm && clean.is_ok() && live {
            let mut sample = confirmed;
            if self.estimate_moved {
                sample = sample.max(fb.estimate_kbps);
            }
            if sample > self.capacity_kbps && confirmed > fb.estimate_kbps {
                tracing::debug!(
                    from_kbps = self.capacity_kbps,
                    egress_kbps = confirmed,
                    estimate_kbps = fb.estimate_kbps,
                    "capacity evidence raised by egress the receiver has since reported carried"
                );
            }
            self.capacity_kbps = self.capacity_kbps.max(sample);
        }
        let capacity = self.capacity_kbps();
        let anchor = capacity.min(
            self.current()
                .absorbable_kbps_with(&self.policy, self.src_w, self.src_h)
                .max(ABSOLUTE_FLOOR_KBPS),
        );
        let diverged = self.warm
            && anchor >= self.policy.reanchor_min_kbps()
            && u64::from(anchor) * 100
                >= u64::from(fb.estimate_kbps) * self.policy.reanchor_divergence_pct;
        let spaced = self.since_reanchor >= self.policy.reanchor_every();
        // The clean-collapse trigger's spacing, doubled for each hold in a row that did not recover
        // ([`REANCHOR_BACKOFF_MAX`]). Pause-resume keeps the plain spacing: a different history.
        let spaced_collapse =
            self.since_reanchor >= self.policy.reanchor_every() * (1 << self.reanchor_backoff);
        // The collapse is costing something now: the encoder wants more than the collapsed pacer
        // drains, or packets are waiting. Otherwise a still screen would be re-anchored every
        // [`REANCHOR_EVERY`], padding at 3x and 6x down a link nobody is using.
        let demand = binds || fb.queue_age_ms >= QUEUE_GUARD_MS;
        let pause_resume = diverged
            && self.resume_window > Duration::ZERO
            && self.nothing_unclean_reported().is_ok()
            && fb.spend_ratio >= self.policy.reanchor_resume_spend
            && spaced;
        // The end of an outage: the receiver went silent while we were sending, came back, and has
        // called the path clean for [`OUTAGE_CONFIRM`]. Its own divergence
        // ([`OUTAGE_DIVERGENCE_PCT`]), since the estimate is recovering rather than breathing;
        // demand is the encoder claiming what it is given, since the silence brake holds it down.
        // Window: [`REANCHOR_RESUME_WINDOW`] past the confirmation.
        let outage_resumed = self.outage.and_then(|o| o.resumed_for);
        let outage_ready = outage_resumed.is_some_and(|r| r >= self.policy.outage_confirm());
        let outage_diverged = self.warm
            && anchor >= self.policy.reanchor_min_kbps()
            && u64::from(anchor) * 100
                >= u64::from(fb.estimate_kbps) * self.policy.outage_divergence_pct;
        let outage_resume = outage_ready
            && !pause_resume
            && outage_diverged
            && clean.is_ok()
            && fb.spend_ratio >= self.policy.reanchor_resume_spend
            && spaced;
        let clean_collapse = diverged
            && !pause_resume
            && !outage_resume
            && clean.is_ok()
            && demand
            && spaced_collapse;

        // A media path that became more direct comes first: what the old one measured is moot.
        let path_reprobe = self.judge_path_move();

        if outage_ready && !outage_resume && !outage_diverged && clean.is_ok() {
            // The receiver is back and clean and the estimate recovered on its own: nothing to
            // re-anchor. The silence brake may have halved the budget four or five times into the
            // dead link, and growing back at a quarter a second would take fourteen seconds from
            // 225 kbps to 5 Mbps. Lift it to what the live estimate allows (congestion control's
            // number, with fresh feedback behind it) and release from there.
            let floor = u32::try_from(u64::from(fb.estimate_kbps) * self.policy.spend_pct / 100)
                .unwrap_or(u32::MAX);
            if let Some(b) = self.brake.as_mut().filter(|b| b.silence_only) {
                if b.cap_kbps < floor {
                    tracing::debug!(
                        from_kbps = b.cap_kbps,
                        to_kbps = floor,
                        estimate_kbps = fb.estimate_kbps,
                        anchor_kbps = anchor,
                        "outage over, the estimate is back by itself: the silence brake is lifted \
                         to the budget the live estimate allows and releases from there"
                    );
                    b.cap_kbps = floor;
                }
            }
            tracing::debug!(
                estimate_kbps = fb.estimate_kbps,
                anchor_kbps = anchor,
                "outage over without a re-anchor: the estimate is within reach of the evidence"
            );
            self.outage = None;
        } else if outage_ready && !outage_resume {
            // Considered on every tick of its window and refused on this one; said once, when the
            // window closes, with the reason as of then.
            if outage_resumed.is_some_and(|r| {
                r >= self.policy.outage_confirm() + self.policy.reanchor_resume_window()
            }) {
                let why = if pause_resume {
                    "pause-resume took it"
                } else if let Err(reason) = clean {
                    reason
                } else if !outage_diverged {
                    "the estimate is back within reach of the evidence"
                } else if fb.spend_ratio < self.policy.reanchor_resume_spend {
                    "the encoder is not claiming its budget"
                } else {
                    "spacing"
                };
                tracing::debug!(
                    refused = why,
                    estimate_kbps = fb.estimate_kbps,
                    anchor_kbps = anchor,
                    capacity_kbps = capacity,
                    spend_ratio = format!("{:.2}", fb.spend_ratio),
                    brake = self.brake_state(),
                    "outage over without a re-anchor"
                );
                self.outage = None;
            }
        }
        if let Some((on, mv)) = path_reprobe {
            self.reprobe_path(fb.estimate_kbps, on, mv);
        } else if pause_resume || outage_resume || clean_collapse {
            let trigger = if pause_resume {
                ReanchorTrigger::PauseResume
            } else if outage_resume {
                ReanchorTrigger::OutageResume
            } else {
                ReanchorTrigger::CleanCollapse
            };
            let r = Reanchor {
                kbps: anchor,
                trigger,
                estimate_kbps: fb.estimate_kbps,
                capacity_kbps: capacity,
                rtt_ms: self.last_fresh_rtt,
                rtt_base_ms: self.rtt_base_ms(),
                loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
                probe_cap_kbps: None,
            };
            tracing::debug!(
                trigger = trigger.as_str(),
                kbps = anchor,
                estimate_kbps = fb.estimate_kbps,
                capacity_kbps = capacity,
                rtt_ms = ?r.rtt_ms,
                rtt_base_ms = ?r.rtt_base_ms,
                loss_pct = ?r.loss_pct,
                produced_kbps = fb.produced_kbps,
                queue_age_ms = fb.queue_age_ms,
                "re-anchor decided"
            );
            self.reanchor_kbps = Some(anchor);
            self.last_reanchor = Some(r);
            self.since_reanchor = Duration::ZERO;
            self.resume_window = Duration::ZERO;
            // Hold it while the reset lands — only when the receiver has actually called the path
            // clean, which a pause-resume on a still screen may not have had the reports to do.
            if clean.is_ok() {
                self.collapse = Some(CleanCollapse {
                    anchor_kbps: anchor,
                    held: Duration::ZERO,
                    recovered_pct: if outage_resume {
                        self.policy.outage_divergence_pct
                    } else {
                        self.policy.reanchor_divergence_pct
                    },
                });
                // The queue and the growth ratio the filters hold are the collapse's own; the
                // ladder must not carry them past the hold. See [`CleanCollapse`].
                self.late_smoothed = 0.0;
                self.late_with_settle = 0.0;
                self.growth_smoothed = 1.0;
                tracing::debug!(
                    anchor_kbps = anchor,
                    estimate_kbps = fb.estimate_kbps,
                    down_dwell_ms = self.down_dwell.as_millis() as u64,
                    "clean collapse held: the network's descent arms are masked and the budget \
                     comes from the capacity evidence until the estimate returns"
                );
            }
            if outage_resume {
                self.outage = None;
                // The silence cut had no measurement behind it, the receiver has called the path
                // clean for two seconds, and congestion control restarts at the evidence this tick.
                // A cut the receiver made (loss, a queue) is not dropped here.
                if let Some(b) = self.brake.filter(|b| b.silence_only) {
                    self.brake = None;
                    let after = self.unbraked_kbps();
                    tracing::debug!(
                        cap_kbps = b.cap_kbps,
                        budget_kbps = after,
                        "silence brake dropped: the receiver is back and clean, and congestion \
                         control is re-anchored at the capacity evidence"
                    );
                    self.brake_event = Some(BrakeEvent::Released(BrakeDetail {
                        cause: BrakeCause::Resumed,
                        loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
                        rtt_ms: self.last_fresh_rtt,
                        rtt_base_ms: self.rtt_base_ms(),
                        before_kbps: b.cap_kbps,
                        after_kbps: after,
                    }));
                }
            }
        } else if let Some(mut hold) = self.collapse {
            hold.held = hold.held.saturating_add(dt);
            // Recovered: the estimate is back within the re-anchor's own two-to-one, and the
            // backlog the collapsed pacer built has drained at the restored rate. Releasing on the
            // estimate alone would hand the ladder's filters the collapse's own queue next tick
            // (over a second of it, recorded). If it does not drain inside the hold, the hold
            // expires and the queue is the ladder's to judge.
            let ended = if u64::from(fb.estimate_kbps) * hold.recovered_pct
                >= u64::from(hold.anchor_kbps) * 100
                && fb.queue_age_ms < QUEUE_GUARD_MS
            {
                Some("recovered")
            } else if let Err(reason) = clean {
                Some(reason)
            } else if hold.held >= self.policy.clean_collapse_hold() {
                Some("expired")
            } else {
                None
            };
            if let Some(why) = ended {
                // Backed off only when the reset demonstrably did not take: the estimate never came
                // back, or the receiver answered with real loss or a brake. A round-trip spike or a
                // missing report ends the hold but says nothing about the reset.
                self.reanchor_backoff = match why {
                    "recovered" => 0,
                    "expired" | "loss" | "brake" => {
                        (self.reanchor_backoff + 1).min(self.policy.reanchor_backoff_max)
                    }
                    _ => self.reanchor_backoff,
                };
                tracing::debug!(
                    ended = why,
                    held_ms = hold.held.as_millis() as u64,
                    estimate_kbps = fb.estimate_kbps,
                    anchor_kbps = hold.anchor_kbps,
                    queue_age_ms = fb.queue_age_ms,
                    rtt_ms = ?self.last_fresh_rtt,
                    rtt_base_ms = ?self.rtt_base_ms(),
                    next_spacing_s =
                        (self.policy.reanchor_every() * (1 << self.reanchor_backoff)).as_secs(),
                    "clean collapse released: the ordinary rules are back"
                );
                self.collapse = None;
            } else {
                self.collapse = Some(hold);
            }
        }
        self.resume_window = self.resume_window.saturating_sub(dt);
        // The pipeline line's word, and a debug line when it changes for a receiver reason (or the
        // spacing): each is a decision not to override congestion control. `-` and `no-demand`
        // flap with the estimate and the encoder's bursts, so they go to trace.
        let view = if self.collapse.is_some() {
            "clean"
        } else if !diverged {
            "-"
        } else if let Err(reason) = clean {
            reason
        } else if !spaced_collapse {
            "spacing"
        } else if !demand {
            "no-demand"
        } else {
            "-"
        };
        if view != self.collapse_view {
            if matches!(view, "-" | "no-demand" | "clean") {
                tracing::trace!(
                    from = self.collapse_view,
                    to = view,
                    estimate_kbps = fb.estimate_kbps,
                    capacity_kbps = capacity,
                    "collapse view"
                );
            } else {
                tracing::debug!(
                    refused = view,
                    estimate_kbps = fb.estimate_kbps,
                    anchor_kbps = anchor,
                    rtt_ms = ?self.last_fresh_rtt,
                    rtt_base_ms = ?self.rtt_base_ms(),
                    loss_pct = ?self.last_fresh_loss.map(|l| l * 100.0),
                    brake = self.brake_state(),
                    "estimate under half the capacity evidence, not treated as a clean collapse"
                );
            }
            self.collapse_view = view;
        }

        // ── the startup window ─────────────────────────────────────────────────────────────────
        //
        // What the link was measured at while the encoder tried to use it, from the first media
        // until [`Self::startup_jump`] decides, and whether the receiver called it congested. The
        // estimate counts only once it has left str0m's configured opening value.
        if self.warm && !self.startup_done {
            self.warm_for = self.warm_for.saturating_add(dt);
            // Not while the receiver is silent: the estimate then is the smoother, not a peak.
            if self.estimate_moved && live {
                self.startup_peak_kbps = self.startup_peak_kbps.max(fb.estimate_kbps);
            }
            if self.spend_smoothed >= self.policy.trying_share {
                self.startup_trying = self.startup_trying.saturating_add(dt);
            }
            // A brake the receiver's reports set, not silence: a receiver that has not answered
            // yet has said nothing about thinness.
            if self.startup_evidence.is_none()
                && self
                    .brake
                    .is_some_and(|b| b.phase == BrakePhase::Engaged && !b.silence_only)
            {
                tracing::debug!(
                    "startup window: the brake is engaged, which is the receiver's evidence"
                );
                self.startup_evidence = Some("brake");
            }
        }
        // And our own queue, which the receiver may never mention, over a window of its own: see
        // [`Self::startup_queue_jump`] and [`STARTUP_QUEUE_WINDOW`].
        if self.warm
            && !self.startup_queue_used
            && self.media_for < self.policy.startup_queue_window()
        {
            self.media_for = self.media_for.saturating_add(dt);
            self.startup_egress[self.startup_egress_at] = fb.egress_kbps;
            self.startup_queue_ages[self.startup_egress_at] = fb.queue_age_ms;
            self.startup_egress_at = (self.startup_egress_at + 1) % STARTUP_DRAIN_TICKS;
            self.startup_egress_seen = (self.startup_egress_seen + 1).min(STARTUP_DRAIN_TICKS);
            self.watch_startup_queue(fb.queue_age_ms);
            if self.media_for >= self.policy.startup_queue_window()
                && self.startup_queue_target.is_none()
            {
                tracing::debug!(
                    window_s = self.policy.startup_queue_window().as_secs(),
                    "startup queue window closed without a jump"
                );
            }
        }

        // What congestion control should probe towards, now that this tick's evidence is in. Every
        // tick, the settle included: the evidence is the link's, not the rung's.
        self.update_probe_target(dt);

        let last = self.index + 1 >= self.rungs().len();
        let top = self.index == 0;

        // Nothing is decided while the last move's own keyframe is still on the wire.
        //
        // A resolution change re-initialises the encoder and the first frame is an IDR (28 to 55 kB
        // at 1080p, most of a second of queue on a 500 kbps relay), so a descent creates the very
        // signal it reads (replayed: eleven rung changes in 115 s, to the bottom, on a link that
        // was never the limit). Not hysteresis: this waits for a known transient before any
        // threshold is consulted.
        if self.settling > Duration::ZERO {
            self.settling = self.settling.saturating_sub(dt);
            if self.settling.is_zero() {
                // Once per move: what the move's own keyframe cost in queue, which the ladder has
                // just been kept from reading. See `late_smoothed` above.
                tracing::debug!(
                    rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
                    queue_peak_ms = self.settle_queue_peak_ms,
                    queue_age_ms = fb.queue_age_ms,
                    estimate_kbps = fb.estimate_kbps,
                    "settle over: the move's own keyframe is behind it, and the queue filter starts \
                     judging this rung from here"
                );
                self.settle_queue_peak_ms = 0;
            }
            return None;
        }

        // The startup decision, after the settle: a jump is a keyframe of its own, and right after
        // an ordinary step it would put two IDRs on a thin link within 300 ms. Waiting costs at
        // most [`SETTLE_AFTER_MOVE`].
        if let Some(target) = self.startup_queue_jump() {
            self.index = target;
            self.last_move_reason = "startup-queue";
            return Some(self.moved());
        }
        if let Some(target) = self.startup_jump() {
            self.index = target;
            self.last_move_reason = "startup-thin";
            return Some(self.moved());
        }

        // ── the only two reasons to give up quality ────────────────────────────────────────────
        //
        // The network cannot carry it, or the processor cannot encode it. Anything else that lowers
        // the picture is a bug. Not reasons, because each was computed from our own estimate: the
        // quantiser against a budget we set (descents with the encoder at 3 to 16% of budget and an
        // empty queue), production against an estimate-derived drain, a queue depth over a guessed
        // rate. If the network cannot carry the rung, packets wait, and `queue_age_ms` measures
        // that directly.
        //
        // Except when the wait is str0m's pacer at a collapsed estimate on a path the receiver
        // calls clean (946 ms of queue behind an estimate of 192, round trip 142 on 136): while a
        // clean collapse is held, this arm and the three that read the same pacer bank nothing
        // (`unmasked`, [`CleanCollapse`]). `cpu_bound` and `braking` are the processor and the
        // receiver and are never masked.
        //
        // Or str0m's slow start: the session opens at 600 kbps with the opening keyframes behind a
        // pacer at 1.1x an unmeasured estimate. On a clean relayed bench link `growing` shed
        // 1080p60 two seconds in, and the climb back took 36 s. So inside [`STARTUP_DECIDE_AFTER`],
        // while the receiver has reported and called the path clean (no [`REAL_LOSS`], no round
        // trip at twice the least, no receiver brake), `growing`, `coarse` and `throttled` bank
        // nothing. `queue_late`, `cpu_bound` and `braking` still act, and a thin link says so at
        // the far end within the window, where the startup decision jumps it in one move.
        let unmasked = self.collapse.is_none();
        let slow_start =
            self.warm && !self.startup_done && self.fresh_seen && self.startup_evidence.is_none();
        if slow_start != self.slow_start_logged {
            self.slow_start_logged = slow_start;
            tracing::debug!(
                masked = slow_start,
                warm_ms = self.warm_for.as_millis() as u64,
                evidence = ?self.startup_evidence,
                startup_done = self.startup_done,
                estimate_kbps = fb.estimate_kbps,
                growth = format!("{:.2}", self.growth_smoothed),
                "{}",
                if slow_start {
                    "startup window: the receiver calls the path clean, so production over egress \
                     and the quantiser read str0m's slow start — those arms are masked"
                } else {
                    "startup window's slow-start mask lifted"
                }
            );
        }
        // And while our queue is only our pacer's: the estimate has not been measured under load and
        // the receiver sees no queue on the path. See [`Self::pacer_only`].
        let pacer = self.pacer_only();
        // The filter with the last settle left out, unless the receiver reports trouble. See
        // [`Self::late_for_ladder`]; one line when the choice changes, with both values.
        let late = self.late_for_ladder();
        let with_settle = self.receiver_reports_trouble();
        self.since_late_source_log = self.since_late_source_log.saturating_add(dt);
        if with_settle.is_some() != self.late_source_logged {
            self.late_source_logged = with_settle.is_some();
            let debug = self.since_late_source_log >= self.arms_log_every();
            if debug {
                self.since_late_source_log = Duration::ZERO;
            }
            debug_or_trace!(
                debug,
                trouble = with_settle.unwrap_or("-"),
                late_ms = format!("{:.0}", self.late_smoothed),
                late_with_settle_ms = format!("{:.0}", self.late_with_settle),
                settling_ms = self.settling.as_millis() as u64,
                rtt_ms = ?self.last_fresh_rtt,
                rtt_base_ms = ?self.rtt_base_ms(),
                loss_pct = ?self.last_fresh_loss.map(|l| l * 100.0),
                "{}",
                if with_settle.is_some() {
                    "the receiver reports trouble: the queue filter reads the last settle's queue \
                     too, as evidence against the rung"
                } else {
                    "the receiver reports no trouble: the queue filter leaves the last settle out"
                }
            );
        }
        let queue_late_raw = self.warm && late > QUEUE_GUARD_MS as f32;
        let queue_late = unmasked && pacer.is_err() && queue_late_raw;

        // The backlog is growing right now: the fast half of "the network cannot carry it".
        //
        // Conservation between two measurements in the same window, bits produced (keyframes
        // excluded) against bits that left the socket, with no estimate in either term. It responds
        // within one window, where the queue's age needs seconds to tell a backlog from a keyframe:
        // at a sustained 300 ms the age route alone takes 5.4 s to shed a rung.
        let growing_raw = self.warm && self.growth_smoothed > 1.0;
        let growing = unmasked && !slow_start && pacer.is_err() && growing_raw;
        // One line when the pacer-only mask starts holding an arm back and one when it stops, with
        // the numbers either way: each is a decision about whether our own queue is the network's.
        let pacer_masking =
            unmasked && pacer.is_ok() && (queue_late_raw || (growing_raw && !slow_start));
        self.since_pacer_mask_log = self.since_pacer_mask_log.saturating_add(dt);
        if pacer_masking != self.pacer_mask_logged {
            self.pacer_mask_logged = pacer_masking;
            let ended_by = match pacer {
                _ if pacer_masking => "-",
                Err(why) => why,
                Ok(()) => "queue",
            };
            let debug = self.since_pacer_mask_log >= self.arms_log_every();
            if debug {
                self.since_pacer_mask_log = Duration::ZERO;
            }
            debug_or_trace!(
                debug,
                masking = pacer_masking,
                ended_by,
                queue_age_ms = fb.queue_age_ms,
                late_ms = format!("{late:.0}"),
                growth = format!("{:.2}", self.growth_smoothed),
                estimate_kbps = fb.estimate_kbps,
                capacity_kbps = self.capacity_kbps(),
                since_loaded_ms = self.since_loaded.as_millis().min(u128::from(u64::MAX)) as u64,
                rtt_ms = ?self.last_fresh_rtt,
                rtt_base_ms = ?self.rtt_base_ms(),
                queue_line_ms = ?self.rtt_base_ms().map(|b| self.rtt_queued_at(b)),
                "{}",
                if pacer_masking {
                    "our queue is our pacer's: the estimate has not been measured under load and the \
                     receiver sees no queue on the path — queue_late and growing bank nothing"
                } else {
                    "pacer-only mask lifted: our queue counts as the network's again, or there is \
                     none"
                }
            );
        }

        // Rate control has run out of room, and enough frames agree to believe it.
        //
        // The quantiser is a fast measurement of the network limit, valid only against a budget the
        // link has confirmed. Three gates:
        //
        // - spending: on a still desktop frames are tiny whatever the quantiser says, so it
        //   describes content, not pixels.
        // - enough samples: at the bottom rung a 200 ms tick holds 1.6 frames and the mean is
        //   cleared on every move (libwebrtc's `QualityScaler` waits for 60).
        // - measured: below.
        let spending = self.spend_smoothed >= self.policy.trying_share;

        // Has the link confirmed the budget recently enough for the quantiser to be about the link?
        //
        // `queue_late`, `growing` and `cpu_bound` measure the network or the processor directly and
        // are not gated. `coarse` and `throttled` say the encoder could not fit the picture into a
        // budget we set, which is evidence about the network only when that budget is a measurement
        // of the link. Against a collapsed idle estimate, or the informative floor while the
        // estimate climbs back, a quantiser at 46 means we have not asked yet; the answer is a tick
        // or two of patience, not a rung (an IDR and a freeze). Recorded without this gate: after a
        // seven-second pause, motion against a budget of 328 shed three rungs in twenty seconds on
        // a link carrying 15 Mbps.
        //
        // [`MEASURED_WITHIN`] is [`DOWN_AFTER`]: the link must have agreed with the estimate within
        // the window the dwell judges. A window, because ordinary traffic steps in and out of the
        // `loaded` band.
        let measured = self.since_loaded <= self.policy.measured_within();

        // Masked while a clean collapse is held, like `queue_late` (the budget is the collapsed
        // estimate's), and in the startup window's slow start, like `growing`.
        let coarse_raw = spending
            && self.qp_seen >= self.policy.qp_min_samples
            && self.qp_smoothed.is_some_and(|qp| qp > self.policy.qp_down)
            && measured;
        let coarse = unmasked && !slow_start && coarse_raw;

        // The processor is the limit, not the link. The arm that serves a weak machine, and the
        // only one that can act before any network signal exists at all.
        let cpu_bound = fb.rung_fps_hint > 0.0
            && fb.encode_ms > self.policy.encode_budget_share * 1000.0 / fb.rung_fps_hint;

        // The bit bucket is holding this rung by throwing frames away, which is not holding it.
        //
        // `crate::frame_dropper` withholds frames to keep production inside the budget, because
        // OpenH264 cannot control its bitrate without frame skip and its own skip is broken:
        //
        // ```text
        // Warning: bEnableFrameSkip = 0, bitrate can't be controlled for RC_QUALITY_MODE,
        //          RC_BITRATE_MODE and RC_TIMESTAMP_MODE without enabling skip frame.
        // ```
        //
        // A rung held that way looks healthy to the other arms (empty queue, comfortable
        // quantiser); measured, a session sat at 1080p and five frames a second with every signal
        // green. A rung down is a 1.5 to 1.8x pixel reduction, about what a third of the frames
        // cost, so at that share the same bits buy full frame rate instead: the crossover sets the
        // threshold. Gated on `spending` (a still screen is not throttled) and `measured` (a
        // dropper at 0.96 against an unconfirmed budget measures the budget).
        let throttled_raw = spending && self.drop_smoothed > self.policy.drop_share && measured;
        let throttled = unmasked && !slow_start && throttled_raw;

        // Climbing is the same two questions asked in reverse, plus the price of the next rung.
        //
        // No spend term: a still screen spends nothing, and requiring it made the bottom rung a
        // one-way door. The link's capacity is the larger of the estimate and what has drained,
        // since on a quiet screen the estimate measures our own silence.
        //
        // Never while the receiver reports the link is not carrying what it is sent: an engaged
        // brake is the network saying no, and the estimate may be frozen (`braking` below). A brake
        // set by silence alone is not `braking` (`Brake::silence_only`); `live` holds the climb
        // through a silence instead.
        let braking_raw = self
            .brake
            .is_some_and(|b| b.phase == BrakePhase::Engaged && !b.silence_only);
        // Not while the round trip behind a brake could still be a longer path
        // ([`Self::path_step_pending`]). The climb is held all the same (`quiet` reads the raw
        // one).
        let step_pending = braking_raw && self.path_step_pending();
        if step_pending && !self.step.pending_logged {
            self.step.pending_logged = true;
            tracing::debug!(
                run_ms = ?&self.step.rtts[..self.step.len],
                base_ms = ?self.rtt_base_ms(),
                cap_kbps = self.brake_kbps(),
                down_dwell_ms = self.down_dwell.as_millis() as u64,
                "brake engaged on the round trip alone, and its reports could still be a longer \
                 path: the budget stays cut, but the rung waits for the path-step verdict"
            );
        }
        let braking = braking_raw && !step_pending;
        let quiet = !top
            && late * self.policy.roomy_late_factor < QUEUE_GUARD_MS as f32
            && !cpu_bound
            && !braking_raw;

        // A quantiser term, which stops the ladder oscillating on a game. The table's price knows
        // nothing about content and under-prices expensive content threefold, so `affordable` opens
        // 1080p at 1.5 Mbps where the content needs four, `coarse` sheds it two seconds later, and
        // the cycle repeats every ten seconds with an IDR each turn. See [`QP_UP`].
        //
        // `None` must not block: no frame was encoded, which is a still screen, and silence is not
        // an objection.
        let has_headroom = self.qp_smoothed.is_none_or(|qp| qp < self.policy.qp_up);
        // The highest rung the evidence supports, not merely the next one up: walking costs
        // `UP_AFTER + SETTLE_AFTER_MOVE` and a keyframe per step even when every rung's price and
        // the capacity are known. Only `affordable` may skip, as far as `believed` reaches;
        // `starved` is a blind experiment and moves one rung.
        //
        // Capped by the brake's ceiling while one is holding or releasing: that is what the
        // receiver confirmed, and the estimate may be frozen (13480 at the recorded LTE ending, 94%
        // lost).
        //
        // While a clean collapse is held the capacity evidence stands in for the collapsed
        // estimate, as in the budget (no brake can be in force then: one ends the hold). Outside a
        // hold the climb waits for the estimate, which str0m's probes lift during quiet stretches
        // anyway; except on an idle screen, where they lift it for one tick only
        // ([`Self::idle_evidence`], and `IdleClimb` for the re-anchor that goes with the climb).
        let idle_evidence = if self.collapse.is_none() {
            self.idle_evidence(fb.estimate_kbps, live)
        } else {
            None
        };
        self.since_idle_evidence_log = self.since_idle_evidence_log.saturating_add(dt);
        if idle_evidence.is_some() != self.idle_evidence_logged {
            self.idle_evidence_logged = idle_evidence.is_some();
            let debug = self.since_idle_evidence_log >= self.arms_log_every();
            if debug {
                self.since_idle_evidence_log = Duration::ZERO;
            }
            debug_or_trace!(
                debug,
                standing_in = idle_evidence.is_some(),
                capacity_kbps = self.capacity_kbps(),
                estimate_kbps = fb.estimate_kbps,
                produced_kbps = format!("{:.0}", self.produced_smoothed),
                receiver = self.receiver_sees_no_queue().err().unwrap_or("no-queue"),
                live,
                brake = self.brake_state(),
                "{}",
                if idle_evidence.is_some() {
                    "idle screen: the capacity evidence stands in for the estimate in the climb gate"
                } else {
                    "idle-screen evidence no longer stands in for the estimate in the climb gate"
                }
            );
        }
        let seen = if self.collapse.is_some() {
            fb.estimate_kbps.max(self.capacity_kbps())
        } else {
            fb.estimate_kbps.max(idle_evidence.unwrap_or(0))
        };
        let believed = self.brake.map_or(seen.max(fb.drain_kbps), |b| {
            seen.max(fb.drain_kbps).min(b.cap_kbps)
        });
        // Gated on the whole climb, not per rung: if this rung is already at QP 38, nothing above
        // fits.
        //
        // When the encoder is spending, a candidate rung is priced at the larger of the table and
        // the content: current production scaled by the pixel ratio and [`fps_factor`]. Measured
        // without it: 720p producing 3100 kbps at QP 26-30 with an estimate of 4083, the table
        // priced 1080p@60 at 1727, and the ladder jumped to the top, where the content costs about
        // 9.9 Mbps; QP 41-44, a 77 kB IDR, 154 kB in flight, the estimate knocked to 1956 by our
        // own queue, and two more keyframes walking back down.
        //
        // - The rung above only has to be comfortable ([`QP_UP`]), not hold today's quantiser: rate
        //   halves per six steps ([`QP_DOWN`]), so the content price is scaled by
        //   `2^((qp - QP_UP)/6)`, never above one since `has_headroom` requires `qp < QP_UP`.
        // - The table stays a floor via `max`, so cheap content behaves as before.
        //
        // Not applied when the encoder is not spending: a still screen would price every rung at
        // nothing.
        let cur = self.current();
        let (cur_w, cur_h) = cur.size_for(self.src_w, self.src_h);
        let cur_pixels = f64::from(cur_w) * f64::from(cur_h);
        let qp_room = self
            .qp_smoothed
            .map_or(1.0, |qp| {
                f64::from(2.0f32.powf((qp - self.policy.qp_up) / 6.0))
            })
            .min(1.0);
        let priced_from_content = spending && cur_pixels > 0.0 && self.produced_smoothed > 0.0;
        let priced = |i: usize| {
            let rung = self.rungs()[i];
            let table = f64::from(rung.required_kbps_with(
                &self.policy,
                self.src_w,
                self.src_h,
                self.quality,
            ));
            let need = if priced_from_content {
                let (w, h) = rung.size_for(self.src_w, self.src_h);
                let content = f64::from(self.produced_smoothed)
                    * (f64::from(w) * f64::from(h) / cur_pixels)
                    * (fps_factor_with(&self.policy, rung.fps)
                        / fps_factor_with(&self.policy, cur.fps))
                    * qp_room;
                table.max(content)
            } else {
                table
            };
            f64::from(believed) >= need * self.policy.up_headroom
        };
        // And the processor prices it: the best rung the link affords that the encoder has room at.
        // `quiet` only asks whether this rung is `cpu_bound`, which after a 60 -> 30 step it cannot
        // be (the line is 25 ms), so a rung shed for 12-13 ms a frame would be climbed straight
        // back into. See [`ENCODE_CLIMB_SHARE`]. Both prices fall down the ladder, so the first
        // rung both pass is the best.
        let link_best = if quiet && has_headroom {
            (0..self.index).find(|&i| priced(i))
        } else {
            None
        };
        let best_affordable = link_best
            .and_then(|best| (best..self.index).find(|&i| priced(i) && self.encode_room(i)));
        let affordable = best_affordable.is_some();

        // The rung is the only reason the picture is bad, and nothing says the link is the limit.
        //
        // A closed loop, recorded for eight minutes on a pinned 1080p:
        //
        // ```text
        // 1080p@8  off=60  cap=8  enc=8  qp=46  prod=170-220  egr=180-210
        //                  bud=170-250  est=190-300  q=0  loss=0  discarded=0
        // ```
        //
        // The rung caps capture at 8 fps, so the encoder produces 180 kbps (QP 46 at 1620x1080), so
        // the estimate, bounded by acknowledged traffic, sits near 280, so `affordable` never sees
        // the 1500 the next rung needs. Both its terms measure our own suppressed output.
        //
        // The quantiser at its ceiling, an empty queue, no loss and the whole allowance spent say
        // the budget, not the content or the network, is holding production down. So ask: a climb
        // is a bounded, reversible experiment, and if the link cannot carry it `queue_late` returns
        // the ladder within seconds, at the cost of one keyframe spaced by `UP_AFTER`.
        //
        // Narrower than `affordable`: the quantiser must be saturated, not merely coarse. And a
        // cadence climb only (same height, more frames): more frames is the only thing that
        // produces new evidence, while a pixel climb at the same bits is a worse picture through an
        // IDR. That is the pinned ladder ([`PINNED_FPS`]) and the bottom two rungs of the main one.
        let cadence_climb = self
            .index
            .checked_sub(1)
            .and_then(|above| self.rungs().get(above).copied())
            .is_some_and(|above| {
                above.max_h == self.current().max_h && above.fps > self.current().fps
            });
        let starved_raw = quiet
            && spending
            && cadence_climb
            && fb.queue_age_ms == 0
            && match (fb.avg_qp, fb.qp_ceiling) {
                (Some(qp), Some(ceiling)) => qp >= ceiling - 1.0,
                _ => false,
            };
        // More frames ask more of the processor whatever the link says, so the blind experiment is
        // priced against it like `affordable`.
        let starved = starved_raw && self.encode_room(self.index.saturating_sub(1));

        // The processor holding back a climb the link affords: one line when that starts and one
        // when it stops. A game's encode time hovers at the climb line, so at most one per
        // [`ARMS_LOG_EVERY`] goes out at debug and the rest at trace.
        let encode_hold =
            (link_best.is_some() && best_affordable != link_best) || (starved_raw && !starved);
        self.since_encode_hold_log = self.since_encode_hold_log.saturating_add(dt);
        if encode_hold != self.encode_hold_logged {
            self.encode_hold_logged = encode_hold;
            let debug = self.since_encode_hold_log >= self.arms_log_every();
            if debug {
                self.since_encode_hold_log = Duration::ZERO;
            }
            let asked = link_best.or_else(|| starved_raw.then(|| self.index.saturating_sub(1)));
            let projection = asked.and_then(|i| self.encode_projection(i));
            let rung = |i: Option<usize>| {
                i.and_then(|i| self.rungs().get(i).copied())
                    .map_or_else(|| "-".to_string(), |r| format!("{}p@{}", r.max_h, r.fps))
            };
            debug_or_trace!(
                debug,
                holding = encode_hold,
                rung = %rung(Some(self.index)),
                link_to = %rung(asked),
                encoder_to = %rung(best_affordable),
                encode_avg_ms = self
                    .encode_smoothed
                    .map_or_else(|| "-".to_string(), |e| format!("{e:.1}")),
                projected_ms = projection.map_or_else(|| "-".to_string(), |(p, _)| format!("{p:.1}")),
                climb_line_ms = projection.map_or_else(|| "-".to_string(), |(_, l)| format!("{l:.1}")),
                cpu_streak = self.cpu_streak,
                "{}",
                if encode_hold {
                    "climb held: the encoder has no room at the rung the link affords — its time a \
                     frame, scaled to that rung's pixels, is over the climb line there (encoder_to \
                     is the best rung it has room at)"
                } else {
                    "climb no longer held by the encoder: it has room at the rung the link affords, \
                     or the link affords no climb"
                }
            );
        }

        let roomy = affordable || starved;

        // Dwell, not unanimity: requiring every sample in a window to agree makes the decision
        // depend on the sampling rate, and one briefly missing signal can hold the ladder forever.
        // Accumulating and decaying makes a disagreeing sample cost half a tick.
        //
        // `braking` reads the far end: a tenth of the traffic lost, or a round trip twice its
        // baseline for two reports running. That is the network's own output, so it is not gated on
        // `measured` or `spending`. One bad report engages it for about a second, half the dwell,
        // so a single spike moves the budget and not the rung; two running take the rung as well.
        // Silence is not in it (`Brake::silence_only`).
        let down = (growing || coarse || queue_late || cpu_bound || throttled || braking) && !last;
        self.down_dwell = accumulate(self.down_dwell, down, dt);
        // Never climb on stale feedback. The climb dwell pauses while the receiver is silent, so
        // one of Chrome's ordinary empty intervals delays a pending climb by at most that interval;
        // a descent arm still spends it. See [`Self::feedback_live`].
        if live || down {
            let earning = roomy && !down && live;
            self.up_dwell = accumulate(self.up_dwell, earning, dt);
            // What the dwell is being earned for: a climb goes only as far as the evidence reached
            // on every tick that earned it. Otherwise a probe lifting the estimate for the last 1.6
            // s of a four-second dwell spent it all on 900p, whose 63 kB keyframe overran the
            // breaker as the estimate fell back and forced a second keyframe.
            if earning {
                let reached = best_affordable.unwrap_or(self.index.saturating_sub(1));
                self.up_target = Some(self.up_target.map_or(reached, |t| t.max(reached)));
            } else if self.up_dwell.is_zero() && self.up_target.is_some() {
                tracing::trace!(
                    target = ?self.up_target,
                    "climb dwell spent without a climb: its target is forgotten"
                );
                self.up_target = None;
            }
        }
        if !live && roomy && !self.climb_held_logged {
            self.climb_held_logged = true;
            tracing::debug!(
                up_dwell_ms = self.up_dwell.as_millis() as u64,
                estimate_kbps = fb.estimate_kbps,
                believed_kbps = believed,
                silent_ms = self.since_fresh.as_millis() as u64,
                empty_intervals = self.stale_run,
                "climb held: the receiver has not reported for an interval while we send, and the \
                 estimate is not evidence without it"
            );
        }

        // Which arms are asking, whenever that set changes (at most once per `ARMS_LOG_EVERY`), and
        // on every move: which of the six descent or two climb reasons built the dwell, on what
        // numbers. `masked` names arms held back by a clean collapse or the startup slow start, and
        // the climb arms when the encoder has no room at the rung the link affords.
        let mut arms = Arms::default();
        arms.set(Arms::GROWING, growing);
        arms.set(Arms::COARSE, coarse);
        arms.set(Arms::QUEUE_LATE, queue_late);
        arms.set(Arms::CPU_BOUND, cpu_bound);
        arms.set(Arms::THROTTLED, throttled);
        arms.set(Arms::BRAKING, braking);
        arms.set(Arms::AFFORDABLE, affordable);
        arms.set(Arms::STARVED, starved);
        let mut masked = Arms::default();
        masked.set(Arms::GROWING, growing_raw && !growing);
        masked.set(Arms::COARSE, coarse_raw && !coarse);
        masked.set(Arms::QUEUE_LATE, queue_late_raw && !queue_late);
        masked.set(Arms::THROTTLED, throttled_raw && !throttled);
        masked.set(Arms::BRAKING, braking_raw && !braking);
        masked.set(Arms::AFFORDABLE, link_best.is_some() && !affordable);
        masked.set(Arms::STARVED, starved_raw && !starved);
        self.since_arms_log = self.since_arms_log.saturating_add(dt);
        // Where each move would go, decided before the line below reports it (`moved()` clears the
        // signals the line shows). A descent per [`Self::descent_target`]; a climb to the rung its
        // whole dwell earned.
        let quantiser_known = self.qp_smoothed.is_some() || fb.qp_ceiling.is_some();
        let descent = (!last && self.down_dwell >= self.policy.down_after())
            .then(|| self.descent_target(cpu_bound, quantiser_known));
        let climb_target = {
            let now = best_affordable.unwrap_or(self.index.saturating_sub(1));
            self.up_target.map_or(now, |t| t.max(now))
        };
        // The dwell the climb needs ([`Self::climb_dwell`]), judged for the rung the dwell was
        // earned for: a tick that earns nothing must not turn evidence gathered under the longer
        // dwell into a climb to a lower rung needing the ordinary one.
        let up_needed = self.climb_dwell(self.up_target.unwrap_or(climb_target));
        let climb_to = (descent.is_none() && !top && live && self.up_dwell >= up_needed)
            .then_some(climb_target);
        if descent.is_none()
            && climb_to.is_none()
            && !top
            && live
            && self.up_dwell >= self.policy.up_after()
            && !self.cpu_wait_logged
        {
            self.cpu_wait_logged = true;
            let target = self.up_target.unwrap_or(climb_target);
            let projection = self.encode_projection(target);
            let rung = |i: Option<usize>| {
                i.and_then(|i| self.rungs().get(i).copied())
                    .map_or_else(|| "-".to_string(), |r| format!("{}p@{}", r.max_h, r.fps))
            };
            tracing::debug!(
                streak = self.cpu_streak,
                rung = %rung(Some(self.index)),
                to = %rung(Some(target)),
                shed = %rung(self.cpu_shed),
                up_dwell_ms = self.up_dwell.as_millis() as u64,
                up_needed_ms = up_needed.as_millis() as u64,
                held_ms = self.cpu_held.as_millis() as u64,
                forget_ms = self.policy.cpu_streak_forget().as_millis() as u64,
                encode_avg_ms = self
                    .encode_smoothed
                    .map_or_else(|| "-".to_string(), |e| format!("{e:.1}")),
                projected_ms = projection.map_or_else(|| "-".to_string(), |(p, _)| format!("{p:.1}")),
                climb_line_ms = projection.map_or_else(|| "-".to_string(), |(_, l)| format!("{l:.1}")),
                "climb waiting out a longer dwell: the processor has shed the rung climbed to more \
                 than once without holding it for forget_ms since, so the encoder has to show room \
                 for up_needed_ms"
            );
        }
        let moving = descent.is_some() || climb_to.is_some();
        let changed = arms != self.arms_logged || masked != self.masked_logged;
        if moving || (changed && self.since_arms_log >= self.arms_log_every()) {
            let to = descent
                .flatten()
                .or(climb_to)
                .and_then(|i| self.rungs().get(i).copied());
            let rung = |r: Rung| format!("{}p@{}", r.max_h, r.fps);
            tracing::debug!(
                arms = %arms.names(),
                was = %self.arms_logged.names(),
                masked = %masked.names(),
                rung = %rung(cur),
                to = %to.map_or_else(|| "-".to_string(), rung),
                down_dwell_ms = self.down_dwell.as_millis() as u64,
                up_dwell_ms = self.up_dwell.as_millis() as u64,
                up_needed_ms = up_needed.as_millis() as u64,
                late_ms = format!("{late:.0}"),
                late_settle_left_out_ms = format!("{:.0}", self.late_smoothed),
                growth = format!("{:.2}", self.growth_smoothed),
                qp = self.qp_smoothed.map_or_else(|| "-".to_string(), |q| format!("{q:.1}")),
                qp_samples = self.qp_seen,
                drop = format!("{:.2}", self.drop_smoothed),
                spend = format!("{:.2}", self.spend_smoothed),
                measured,
                live,
                slow_start,
                encode_ms = format!("{:.1}", fb.encode_ms),
                encode_avg_ms = self
                    .encode_smoothed
                    .map_or_else(|| "-".to_string(), |e| format!("{e:.1}")),
                cpu_streak = self.cpu_streak,
                believed_kbps = believed,
                pacer = pacer.err().unwrap_or("ours"),
                idle_evidence_kbps = idle_evidence.unwrap_or(0),
                brake_kbps = self.brake_kbps().unwrap_or(0),
                "{}",
                if to.is_some() {
                    "ladder moving"
                } else {
                    "ladder arms"
                }
            );
            self.arms_logged = arms;
            self.masked_logged = masked;
            self.since_arms_log = Duration::ZERO;
        }

        match descent {
            Some(Some(to)) => {
                // A `cpu_bound` descent lengthens the next climb back's dwell if it is not the
                // first since the processor last held the rung ([`Self::climb_dwell`]).
                if cpu_bound {
                    self.note_cpu_descent(self.index, to, fb.encode_ms);
                }
                self.index = to;
                self.last_move_reason = if braking { "brake" } else { "down" };
                return Some(self.moved());
            }
            // Refused (and said so in `descent_target`): the dwell was spent on a question the
            // content answered, and the next descent needs dwell of its own.
            Some(None) => self.down_dwell = Duration::ZERO,
            None => {}
        }
        if let Some(to) = climb_to {
            // Straight to the highest rung the evidence supports (one step for `starved`), no
            // higher than the dwell earned. A lower index is a better rung.
            if best_affordable.is_some_and(|best| best < to) {
                tracing::debug!(
                    to = %format!("{}p@{}", self.rungs()[to].max_h, self.rungs()[to].fps),
                    affordable_now = ?best_affordable.and_then(|i| self.rungs().get(i).copied()),
                    believed_kbps = believed,
                    "climb held to the rung the whole dwell earned: the higher one became affordable \
                     only during it, and earns a dwell of its own"
                );
            }
            if let Some(evidence) = idle_evidence {
                self.idle_climb_reanchor(evidence, to, fb.estimate_kbps);
            }
            self.index = to;
            self.last_move_reason = "climb";
            return Some(self.moved());
        }
        None
    }

    /// The path change waiting to be judged, if it qualifies for a re-probe now (and on what);
    /// forgotten, with a line, once it is decided either way. See [`Self::note_path_move`].
    fn judge_path_move(&mut self) -> Option<(&'static str, PathMove)> {
        let mv = self.path_move?;
        let kind = |k: Option<PathKind>| k.map_or("unknown", PathKind::as_str);
        if let Some(on) = mv.qualifies(self.policy.path_reprobe_rtt_factor) {
            self.path_move = None;
            if self.since_path_reprobe < self.policy.path_reprobe_every() {
                tracing::debug!(
                    on,
                    from = kind(mv.from),
                    to = kind(mv.to),
                    since_ms = self.since_path_reprobe.as_millis() as u64,
                    every_ms = self.policy.path_reprobe_every().as_millis() as u64,
                    "media path change not re-probed: the last path re-probe went out too recently \
                     (a pair flapping between two paths is probed once)"
                );
                return None;
            }
            return Some((on, mv));
        }
        if mv.age >= self.policy.path_judge_window() {
            tracing::debug!(
                from = kind(mv.from),
                to = kind(mv.to),
                old_rtt_ms = ?mv.old_rtt_ms,
                new_rtt_min_ms = ?mv.new_rtt_min_ms,
                new_reports = mv.new_reports,
                "media path change not re-probed: the new pair is not more direct and its round trip \
                 is not at most half the old one's; the estimate carries over as before"
            );
            self.path_move = None;
        }
        None
    }

    /// The media moved to a more direct path: restart str0m at the live estimate with its opening
    /// probes and forget the old path's capacity evidence, so the probe target is a new session's
    /// (the ceiling for the new path's opening, [`PROBE_OPENING`], then twice the best estimate
    /// seen), sent this tick ahead of the re-anchor. See [`ReanchorTrigger::PathChange`].
    fn reprobe_path(&mut self, estimate_kbps: u32, on: &'static str, mv: PathMove) {
        let kbps = estimate_kbps.max(self.policy.reanchor_min_kbps());
        let capacity_before = self.capacity_kbps();
        let capacity_forgotten = self.capacity_kbps;
        let informative_forgotten = self.informative_kbps;
        let best_forgotten = self.probe_best_kbps;
        let target_before = self.probe_target_kbps();
        // The old path's evidence, and everything that would feed it on the next tick.
        self.capacity_kbps = 0;
        self.informative_kbps = 0;
        self.informative_from_opening = false;
        self.loaded_streak = Duration::ZERO;
        self.since_loaded = Duration::MAX;
        self.egress_open_kbps = 0;
        self.egress_pending_kbps = 0;
        self.egress_confirmed_kbps = 0;
        self.evidence_seen = false;
        self.capacity_peak_kbps = 0;
        // The new path's opening: the ceiling, so str0m's opening probes (3x and 6x the restart,
        // held to twice the target by `queue_probe`) and its exponential probing run as on a new
        // session. str0m's periodic probe waits five seconds after them, so it meets the target
        // that follows the opening.
        let opening_was = self.probe_opening;
        let path_ms_was = self.probe_path_for.as_millis() as u64;
        self.probe_opening = true;
        self.probe_path_for = Duration::ZERO;
        // And what bounds the probes after the opening, until the new path has produced evidence of
        // its own: the value str0m restarts at, the one estimate it will hold of this path.
        self.probe_best_kbps = kbps;
        let target = self.probe_target_kbps();
        let reach = target.saturating_mul(2);
        let r = Reanchor {
            kbps,
            trigger: ReanchorTrigger::PathChange,
            estimate_kbps,
            capacity_kbps: capacity_before,
            rtt_ms: self.last_fresh_rtt,
            rtt_base_ms: self.rtt_base_ms(),
            loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
            probe_cap_kbps: Some(reach),
        };
        let kind = |k: Option<PathKind>| k.map_or("unknown", PathKind::as_str);
        tracing::debug!(
            on,
            from = kind(mv.from),
            to = kind(mv.to),
            old_rtt_ms = ?mv.old_rtt_ms,
            new_rtt_min_ms = ?mv.new_rtt_min_ms,
            since_change_ms = mv.age.as_millis() as u64,
            kbps,
            probe_cap_kbps = reach,
            probe_target_kbps = target,
            probe_target_was_kbps = target_before,
            opening_ms = self.policy.probe_opening().as_millis() as u64,
            opening_was,
            path_ms_was,
            best_estimate_forgotten_kbps = best_forgotten,
            capacity_forgotten_kbps = capacity_forgotten,
            informative_forgotten_kbps = informative_forgotten,
            collapse_held = self.collapse.is_some(),
            "re-anchor decided: the media moved to a more direct path; str0m's opening probes run \
             again on it from the live estimate, and the old path's capacity evidence is forgotten: \
             the probe target is the ladder's ceiling for the new path's opening (opening_ms), then \
             twice the restart value until the new path is measured"
        );
        self.reanchor_kbps = Some(kbps);
        self.last_reanchor = Some(r);
        self.since_reanchor = Duration::ZERO;
        self.since_path_reprobe = Duration::ZERO;
        self.resume_window = Duration::ZERO;
        self.probe_urgent = true;
        // A hold of the old path's collapse is over, and so is what its failed resets taught.
        self.collapse = None;
        self.reanchor_backoff = 0;
    }

    /// The re-anchor an idle climb takes with it: congestion control restarted at the evidence the
    /// climb was decided on, so its keyframe drains at the demonstrated rate. See
    /// [`ReanchorTrigger::IdleClimb`].
    fn idle_climb_reanchor(&mut self, evidence_kbps: u32, to: usize, estimate_kbps: u32) {
        let rung = self.rungs()[to];
        let anchor = evidence_kbps.min(
            rung.absorbable_kbps_with(&self.policy, self.src_w, self.src_h)
                .max(ABSOLUTE_FLOOR_KBPS),
        );
        let diverged = anchor >= self.policy.reanchor_min_kbps()
            && u64::from(anchor) * 100
                >= u64::from(estimate_kbps) * self.policy.reanchor_divergence_pct;
        let spaced = self.since_reanchor >= self.policy.reanchor_every();
        if !(diverged && spaced) {
            tracing::debug!(
                anchor_kbps = anchor,
                estimate_kbps,
                diverged,
                spaced,
                since_last_reanchor_ms =
                    self.since_reanchor.as_millis().min(u128::from(u64::MAX)) as u64,
                "idle climb without a re-anchor: the estimate is within reach of the evidence, or a \
                 re-anchor went out under REANCHOR_EVERY ago"
            );
            return;
        }
        let r = Reanchor {
            kbps: anchor,
            trigger: ReanchorTrigger::IdleClimb,
            estimate_kbps,
            capacity_kbps: self.capacity_kbps(),
            rtt_ms: self.last_fresh_rtt,
            rtt_base_ms: self.rtt_base_ms(),
            loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
            probe_cap_kbps: None,
        };
        tracing::debug!(
            trigger = r.trigger.as_str(),
            kbps = anchor,
            estimate_kbps,
            capacity_kbps = r.capacity_kbps,
            rtt_ms = ?r.rtt_ms,
            rtt_base_ms = ?r.rtt_base_ms,
            to = %format!("{}p@{}", rung.max_h, rung.fps),
            "re-anchor decided"
        );
        self.reanchor_kbps = Some(anchor);
        self.last_reanchor = Some(r);
        self.since_reanchor = Duration::ZERO;
    }

    /// Whether the viewer's page is hidden (its background-hold grace or hold, `crate::bg_hold`):
    /// set on every control tick, logged on a change.
    ///
    /// A hidden page may sleep: Telegram's WebView on iOS stops every receiver report within two
    /// seconds of being hidden. Read as the path dying, the silence brake cut 5851 -> 247 kbps
    /// through the grace and the capacity evidence decayed, then the hold froze that state, the
    /// resume came back braked, and the brake refused the hold's restart of str0m. Pages that stay
    /// awake (Chromium, Safari, Telegram on macOS) report through their grace.
    ///
    /// So while hidden, a silent receiver is the page asleep: no silence cut, outage or drain
    /// evidence ([`Self::on_report`]), and the evidence and informative floor do not decay
    /// ([`Self::tick`]). A receiver that does report is read as always, and stale feedback still
    /// teaches nothing. Video goes on into a sleeping page only until its silence reaches
    /// `bg_hold::BG_HOLD_ASLEEP_AFTER` ([`Self::receiver_silence`]); the hold begins then.
    pub fn set_page_hidden(&mut self, hidden: bool) {
        if hidden == self.page_hidden {
            return;
        }
        self.page_hidden = hidden;
        self.hidden_silence_logged = false;
        tracing::debug!(
            hidden,
            stale_run = self.stale_run,
            silent_ms = self.since_fresh.as_millis() as u64,
            brake = self.brake_state(),
            capacity_kbps = self.capacity_kbps(),
            "{}",
            if hidden {
                "viewer page hidden: a silent receiver is read as the page asleep from here — no \
                 silence brake, no outage, no drain evidence, no evidence decay; what it does \
                 report is read as always"
            } else {
                "viewer page visible again: the receiver's silence is the path's again"
            }
        );
    }

    /// Whether the viewer's page is hidden, as [`Self::set_page_hidden`] was last told.
    #[must_use]
    pub fn page_hidden(&self) -> bool {
        self.page_hidden
    }

    /// How long the receiver has been silent (since its last fresh report), once
    /// [`BRAKE_STALE_REPORTS`] intervals in a row have passed without one while we sent enough for
    /// one to be due (the silence brake's count). `None` while it reports, before its first report,
    /// and while we send too little for silence to mean anything. For the background hold, which
    /// reads a hidden page's silence past `bg_hold::BG_HOLD_ASLEEP_AFTER` as the page asleep.
    #[must_use]
    pub fn receiver_silence(&self) -> Option<Duration> {
        (self.fresh_seen && self.stale_run >= self.policy.brake_stale_reports)
            .then_some(self.since_fresh)
    }

    /// A background hold is over (`crate::bg_hold`): the controller was frozen for `held` (not
    /// ticked, so nothing decayed and no dwell grew) and is put back to work at the same rung, with
    /// str0m's estimate restored to what the path carried before.
    ///
    /// Frozen rather than ticked through the silence: minutes of padding would decay the evidence
    /// below [`REANCHOR_MIN_KBPS`] (after 100 s it is a thirty-second of itself) and collapse the
    /// estimate, so the resume keyframe would crawl through the pacer and the queue would step the
    /// session down for having looked away. After a hold the estimate returns to where it was and
    /// the rung stays.
    ///
    /// - Clocks that measure how long ago move on by `held`: last fresh report, real loss, unclean
    ///   or queued round trip, re-anchor, loaded tick, probe target.
    /// - What was gathered toward a decision starts over: application-limited count and resume
    ///   window, silence run, interval sums, egress brackets and ring, drain evidence, a watched
    ///   outage, a held collapse.
    /// - The evidence ([`Self::capacity_kbps`], the informative floor) is kept.
    /// - A silence-only brake is dropped; one the receiver's reports set stays until they release
    ///   it.
    /// - For [`HOLD_WAKE_WINDOW`], until a report under the drain line and [`HOLD_WAKE_LOSS`], a
    ///   report past either is the woken page describing its sleep and only says the receiver is
    ///   back.
    /// - A settle, as after a move ([`Self::moved`]); no brake is set.
    /// - str0m's restart is decided next by [`Self::reanchor_after_hold`] when `reanchor_due`, and
    ///   applied right before the resumed video's first frame.
    /// - Drain mode in force when the hold began ends here through its own resume
    ///   ([`Self::leave_drain`]).
    ///
    /// `estimate_kbps` is str0m's estimate now. A drain's re-anchor, if any, is taken with
    /// [`Self::take_bwe_reanchor`].
    pub fn resume_after_hold(&mut self, held: Duration, estimate_kbps: u32) -> HoldResumed {
        let before = (
            self.since_fresh,
            self.since_real_loss,
            self.since_reanchor,
            self.since_loaded,
        );
        for clock in [
            &mut self.since_fresh,
            &mut self.since_real_loss,
            &mut self.since_rtt_unclean,
            &mut self.since_rtt_queued,
            &mut self.since_reanchor,
            &mut self.since_loaded,
            &mut self.since_probe_sent,
        ] {
            *clock = clock.saturating_add(held);
        }
        let ms = |d: Duration| d.as_millis().min(u128::from(u64::MAX)) as u64;
        // "never" for the clocks still at their `Duration::MAX` sentinel (nothing of the kind yet).
        let moved = |from: Duration, to: Duration| {
            let one = |d: Duration| {
                if d == Duration::MAX {
                    "never".to_string()
                } else {
                    ms(d).to_string()
                }
            };
            format!("{} -> {}", one(from), one(to))
        };
        tracing::debug!(
            held_ms = ms(held),
            since_fresh_ms = %moved(before.0, self.since_fresh),
            since_real_loss_ms = %moved(before.1, self.since_real_loss),
            since_reanchor_ms = %moved(before.2, self.since_reanchor),
            since_loaded_ms = %moved(before.3, self.since_loaded),
            app_limited_ms = ms(self.app_limited_for),
            stale_run = self.stale_run,
            "background hold over: the controller's clocks move on by the hold, what it was gathering \
             across the silence starts over, and its evidence is kept"
        );
        self.loaded_streak = Duration::ZERO;
        self.confirm_logged = false;
        self.app_limited_for = Duration::ZERO;
        self.resume_window = Duration::ZERO;
        self.stale_run = 0;
        self.drain_silence_counted = false;
        self.climb_held_logged = false;
        self.report_egress_sum = 0;
        self.report_egress_ticks = 0;
        self.report_produced_sum = 0;
        self.report_budget_sum = 0;
        self.egress_open_kbps = 0;
        self.egress_pending_kbps = 0;
        self.egress_confirmed_kbps = 0;
        self.egress_recent = [0; EGRESS_WINDOW];
        self.clear_drain_evidence();
        // The viewer's clock ran through the hold and this controller's did not: its reports are
        // read afresh against what we send from here.
        self.delivery.reset("hold");
        if let Some(o) = self.outage.take() {
            tracing::debug!(
                resumed_for_ms = ?o.resumed_for.map(ms),
                "background hold over: the outage being watched before it is forgotten — the \
                 receiver's word after the hold is about the path now"
            );
        }
        if let Some(h) = self.collapse.take() {
            tracing::debug!(
                anchor_kbps = h.anchor_kbps,
                held_ms = ms(h.held),
                "background hold over: the clean-collapse hold from before it is released; the \
                 hold outlasted it"
            );
        }
        // A silence-only brake is ignorance, and the receiver is back to end it, whether the
        // silence was the page asleep or the path. One the receiver's reports set stays until they
        // release it.
        let phase = self.brake_state();
        match self.brake {
            Some(b) if b.silence_only => {
                self.brake = None;
                tracing::debug!(
                    cap_kbps = b.cap_kbps,
                    phase,
                    "background hold over: the silence brake from before it is dropped — silence is \
                     no word about the path, and the receiver's reports decide from here"
                );
            }
            Some(b) => tracing::debug!(
                cap_kbps = b.cap_kbps,
                phase,
                by_loss = b.by_loss,
                "background hold over: the brake the receiver's reports set before it stays until \
                 they release it"
            ),
            None => {}
        }
        // The first reports of a page that slept read its sleep as round trip. See
        // [`HOLD_WAKE_WINDOW`].
        self.wake_window = self.policy.hold_wake_window();
        self.hidden_silence_logged = false;
        tracing::debug!(
            window_ms = self.policy.hold_wake_window().as_millis() as u64,
            line_ms = self.drain_enter_at(),
            loss_line_pct = format!("{:.0}", self.policy.hold_wake_loss * 100.0),
            "background hold over: until a report under the drain line and the loss line, or for \
             the window, a report past either is read as the woken page's and not as the path's"
        );
        self.smoothed = estimate_kbps;
        let capacity = self.capacity_kbps();
        if self.drain.is_some() {
            let band = self.drain_exit_below();
            let had = self.last_reanchor;
            tracing::debug!(
                held_drain_ms = ?self.drain.map(|d| ms(d.held)),
                exit_below_ms = band,
                estimate_kbps,
                capacity_kbps = capacity,
                "background hold over with drain mode in force: the drain was the path's own \
                 evidence of a backlog, so it ends now through its own conservative resume, not \
                 the hold's re-anchor"
            );
            self.leave_drain("bg_hold", None, band);
            let reanchor = (self.reanchor_kbps.is_some() && self.last_reanchor != had)
                .then_some(self.last_reanchor)
                .flatten();
            return HoldResumed {
                reanchor,
                drain_ended: true,
                reanchor_due: false,
                capacity_kbps: capacity,
            };
        }
        // The same rung, settled: the resume keyframe is this rung's price, not its evidence.
        self.moved();
        tracing::debug!(
            estimate_kbps,
            capacity_kbps = capacity,
            rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
            "background hold over: the same rung, settled; str0m's restart is decided next and \
             applied right before the resumed video's first frame"
        );
        HoldResumed {
            reanchor: None,
            drain_ended: false,
            reanchor_due: true,
            capacity_kbps: capacity,
        }
    }

    /// The re-anchor that ends a background hold, decided on the tick that resumes the controller:
    /// str0m restarted at the larger of the pre-hold capacity evidence (clamped to what the rung
    /// can absorb) and `estimate_kbps`, never below it. [`ReanchorTrigger::HoldResume`] is applied
    /// right before the next video frame ([`ReanchorTrigger::at_next_frame`]).
    ///
    /// Always, because a hold leaves str0m's acknowledged rate at the padding rate even when the
    /// estimate is intact. `AckedBitrateEstimator` (`str0m-0.23.1/src/bwe/
    /// acked_bitrate_estimator.rs`) weighs a sample by its distance relative to the estimate, so a
    /// 10 Mbps sample against a 42-78 kbps history barely moves it (6 to 13 s of video to reach
    /// half the video's rate). The first overuse after the resume then cuts the estimate to `BETA`
    /// (0.85) times that (`delay/rate_control.rs`, `decrease`): 13305 -> 66 kbps on the bench, 3224
    /// -> 40 in the simulator. libwebrtc answers ALR's end with `ExpectFastRateChange`; str0m's
    /// public `Bwe` has only `set_desired_bitrate` and `reset`.
    ///
    /// `Rtc::bwe().reset` rebuilds the estimator whole (`bwe/mod.rs`), which has no acknowledged
    /// rate until its first 500 ms window (`INITIAL_BITRATE_WINDOW`) closes and changes nothing
    /// before that (`delay/control.rs`, `update_estimate`). Restarted just before the resumed
    /// keyframe, it measures the resumed video, and the first overuse costs 15%, not 99%. Earlier
    /// measures padding again (capture's first frame comes 83-430 ms after it starts); later races
    /// the stale estimator, which reads the keyframe's queue as overuse within a few hundred
    /// milliseconds (in the simulator a restart on the next tick often came after the estimate had
    /// already fallen to about 1500). The transport applies it as it hands the frame to str0m
    /// (`PeerControl::ResetBweAtNextFrame`) via `afklink_transport::reanchor_bwe`, opening probes
    /// held to the value.
    ///
    /// Refused while draining (the drain's own resume stands), cold, with no evidence, within
    /// [`REANCHOR_EVERY`] of the last re-anchor, and on anything unclean the receiver reported
    /// since the resume ([`Self::nothing_unclean_reported`]). Taken with
    /// [`Self::take_bwe_reanchor`].
    pub fn reanchor_after_hold(&mut self, estimate_kbps: u32) -> HoldReanchor {
        let capacity = self.capacity_kbps();
        let anchor = capacity.min(
            self.current()
                .absorbable_kbps_with(&self.policy, self.src_w, self.src_h)
                .max(ABSOLUTE_FLOOR_KBPS),
        );
        let value = anchor.max(estimate_kbps);
        let raises = anchor > estimate_kbps;
        let refused = if self.drain.is_some() {
            Some("drain")
        } else if !self.warm {
            Some("cold")
        } else if value < self.policy.reanchor_min_kbps() {
            Some("no-evidence")
        } else if self.since_reanchor < self.policy.reanchor_every() {
            Some("spacing")
        } else {
            self.nothing_unclean_reported().err()
        };
        if let Some(why) = refused {
            tracing::debug!(
                refused = why,
                estimate_kbps,
                anchor_kbps = anchor,
                capacity_kbps = capacity,
                brake = self.brake_state(),
                rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
                "background hold over without a re-anchor"
            );
            return HoldReanchor {
                reanchor: None,
                refused: Some(why),
                raises,
            };
        }
        let r = Reanchor {
            kbps: value,
            trigger: ReanchorTrigger::HoldResume,
            estimate_kbps,
            capacity_kbps: capacity,
            rtt_ms: self.last_fresh_rtt,
            rtt_base_ms: self.rtt_base_ms(),
            loss_pct: self.last_fresh_loss.map(|l| l * 100.0),
            probe_cap_kbps: None,
        };
        tracing::debug!(
            trigger = r.trigger.as_str(),
            kbps = value,
            estimate_kbps,
            anchor_kbps = anchor,
            capacity_kbps = capacity,
            raises,
            rtt_ms = ?r.rtt_ms,
            rtt_base_ms = ?r.rtt_base_ms,
            rung = %format!("{}p@{}", self.current().max_h, self.current().fps),
            "re-anchor decided, to go right before the resumed video's first frame: {}",
            if raises {
                "the hold's silence left the estimate under the evidence from before it, and str0m's \
                 acknowledged-rate history at the padding rate; restarted at the evidence"
            } else {
                "the estimate held through the hold but str0m's acknowledged-rate history is the \
                 padding's; restarted at the estimate itself, so the resumed video is what it measures"
            }
        );
        self.reanchor_kbps = Some(value);
        self.last_reanchor = Some(r);
        self.since_reanchor = Duration::ZERO;
        // Held while the reset lands only when it raises a collapsed estimate and the receiver has
        // called the path clean, as for pause-resume; rare after a hold.
        if raises
            && u64::from(anchor) * 100
                >= u64::from(estimate_kbps) * self.policy.reanchor_divergence_pct
            && self.path_clean().is_ok()
        {
            self.collapse = Some(CleanCollapse {
                anchor_kbps: value,
                held: Duration::ZERO,
                recovered_pct: self.policy.reanchor_divergence_pct,
            });
            tracing::debug!(
                anchor_kbps = value,
                estimate_kbps,
                "clean collapse held after the background hold: the receiver reported the path clean \
                 since the resume"
            );
        }
        HoldReanchor {
            reanchor: Some(r),
            refused: None,
            raises,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Arc;

    // ── the reference policy under short names ───────────────────────────────────────────────
    //
    // Fields of `QualityPolicy::reference()`, which every test here runs on, restated under their
    // constant names; `the_test_names_are_the_reference_policy` holds them to the reference.

    const PINNED_FPS: &[u32] = &[60, 30, 15, 8];
    const PROBE_OPENING_LATEST: Duration = Duration::from_secs(10);
    const SPEND_PCT: u64 = 90;
    const SETTLE_AFTER_MOVE: Duration = Duration::from_secs(3);
    const EXPLORE_MARGIN_KBPS: u32 = 300;
    const LOADED_CONFIRM: Duration = Duration::from_secs(2);
    const CLEAN_COLLAPSE_HOLD: Duration = Duration::from_secs(4);
    const REANCHOR_MIN_KBPS: u32 = 300;
    const OUTAGE_DIVERGENCE_PCT: u64 = 150;
    const BRAKE_RELEASE_PER_SEC: f64 = 1.25;
    const DRAIN_MAX: Duration = Duration::from_secs(15);
    const DRAIN_MAX_PROVEN: Duration = Duration::from_secs(45);
    const STARTUP_DECIDE_AFTER: Duration = Duration::from_secs(8);
    const CPU_CLIMB_DWELL_MAX: Duration = Duration::from_secs(32);
    const CPU_STREAK_FORGET: Duration = Duration::from_secs(60);
    const UP_HEADROOM: f64 = 1.25;
    const DOWN_AFTER: Duration = Duration::from_secs(2);
    const UP_AFTER: Duration = Duration::from_secs(4);

    #[test]
    fn the_test_names_are_the_reference_policy() {
        let p = QualityPolicy::reference();
        assert_eq!(PINNED_FPS, p.pinned_fps.as_slice());
        assert_eq!(PROBE_OPENING_LATEST, p.probe_opening_latest());
        assert_eq!(SPEND_PCT, p.spend_pct);
        assert_eq!(SETTLE_AFTER_MOVE, p.settle_after_move());
        assert_eq!(EXPLORE_MARGIN_KBPS, p.explore_margin_kbps);
        assert_eq!(LOADED_CONFIRM, p.loaded_confirm());
        assert_eq!(CLEAN_COLLAPSE_HOLD, p.clean_collapse_hold());
        assert_eq!(REANCHOR_MIN_KBPS, p.reanchor_min_kbps());
        assert_eq!(OUTAGE_DIVERGENCE_PCT, p.outage_divergence_pct);
        assert_eq!(
            BRAKE_RELEASE_PER_SEC.to_bits(),
            p.brake_release_per_sec.to_bits()
        );
        assert_eq!(DRAIN_MAX, p.drain_max());
        assert_eq!(DRAIN_MAX_PROVEN, p.drain_max_proven());
        assert_eq!(STARTUP_DECIDE_AFTER, p.startup_decide_after());
        assert_eq!(CPU_CLIMB_DWELL_MAX, p.cpu_climb_dwell_max());
        assert_eq!(CPU_STREAK_FORGET, p.cpu_streak_forget());
        assert_eq!(UP_HEADROOM.to_bits(), p.up_headroom.to_bits());
        assert_eq!(DOWN_AFTER, p.down_after());
        assert_eq!(UP_AFTER, p.up_after());
        assert_eq!(p.ladder.as_slice(), LADDER);
    }

    /// `new` is `with_policy` on the reference: the same inputs give the same decisions, tick by
    /// tick, through a healthy opening, a thin stretch and a recovery.
    #[test]
    fn with_the_reference_policy_is_new() {
        let mut a = QualityController::new(1620, 1080, Quality::Balanced);
        let mut b = QualityController::with_policy(
            1620,
            1080,
            Quality::Balanced,
            QualityPolicy::reference(),
        );
        assert_eq!(a.policy(), b.policy());
        let feed = |i: u32, fps: f32| {
            if (40..90).contains(&i) {
                Feedback {
                    estimate_kbps: 700,
                    drain_kbps: 770,
                    produced_kbps: 900,
                    egress_kbps: 650,
                    queue_age_ms: 180,
                    avg_qp: Some(45.0),
                    spend_ratio: 1.0,
                    ..healthy(fps)
                }
            } else {
                healthy(fps)
            }
        };
        for i in 0..200 {
            let fa = feed(i, a.current().fps as f32);
            let fb = feed(i, b.current().fps as f32);
            assert_eq!(a.tick(fa, TICK), b.tick(fb, TICK), "tick {i}");
            assert_eq!(a.current(), b.current(), "tick {i}");
            assert_eq!(a.encoder_target_kbps(), b.encoder_target_kbps(), "tick {i}");
            assert_eq!(a.probe_target_kbps(), b.probe_target_kbps(), "tick {i}");
        }
    }

    /// The controller reads its own policy's ladder, not the reference's.
    #[test]
    fn a_policy_ladder_is_the_ladder_the_controller_walks() {
        let ladder = vec![
            Rung {
                max_h: 720,
                fps: 30,
            },
            Rung {
                max_h: 360,
                fps: 30,
            },
        ];
        let policy = QualityPolicy {
            ladder: ladder.clone(),
            ..QualityPolicy::reference()
        };
        let c = QualityController::with_policy(1920, 1080, Quality::Balanced, policy);
        assert_eq!(c.current(), ladder[0]);
        assert_eq!(c.policy().start_rung(), ladder[0]);
    }

    // ── pricing ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn matches_rustdesk_presets() {
        assert_eq!(base_bitrate_kbps(1280, 720), 1000);
        assert_eq!(base_bitrate_kbps(1920, 1080), 2073);
        assert_eq!(base_bitrate_kbps(3840, 2160), 5000);
    }

    #[test]
    fn scales_between_presets() {
        // 1620x1080 — a 3:2 panel fitted to the 1080p cap — lands proportionally between table
        // rows rather than being rounded onto one.
        let b = base_bitrate_kbps(1620, 1080);
        assert!(b > base_bitrate_kbps(1280, 720));
        assert!(b < base_bitrate_kbps(1920, 1080));
    }

    #[test]
    fn ladder_descends() {
        // Every rung must need strictly less than the one above it, or a step "down" lands
        // somewhere no more affordable and the ladder oscillates.
        for &(w, h) in &[(1920, 1080), (1620, 1080), (3840, 1080)] {
            let mut prev = u32::MAX;
            for r in LADDER {
                let need = r.required_kbps(w, h, Quality::Balanced);
                assert!(
                    need < prev,
                    "{r:?} at {w}x{h} needs {need}, not below {prev}"
                );
                prev = need;
            }
        }
    }

    #[test]
    fn the_ladder_gives_way_on_pixels_before_cadence() {
        // Two rules, divided at 1080p30, the product's standard. Above it one bonus rung, 1080p60,
        // whose first step down is cadence (pixels would trade the standard away for a bonus).
        // From 1080p30 down, pixels before cadence: at a fixed budget a pixel step costs no
        // serialization time and buys quantiser, while a cadence step makes every frame 41% longer
        // on the wire ([`fps_factor`]). See [`LADDER`].
        let top = LADDER[0];
        assert_eq!(
            (top.max_h, top.fps),
            (1080, 60),
            "the bonus rung is the top of the ladder"
        );
        let standard = LADDER[1];
        assert_eq!(
            (standard.max_h, standard.fps),
            (1080, 30),
            "and the first step down from it is cadence, not pixels"
        );

        // Below the standard, pixels before cadence.
        let below = &LADDER[1..];
        let first_fps_drop = below
            .iter()
            .position(|r| r.fps < standard.fps)
            .expect("the ladder must eventually shed frames");
        let first_pixel_drop = below
            .iter()
            .position(|r| r.max_h < standard.max_h)
            .expect("the ladder must shed pixels");
        assert!(
            first_pixel_drop < first_fps_drop,
            "below 1080p30, pixels must give way before cadence"
        );
    }

    #[test]
    fn the_bottom_rung_is_below_the_worst_link_supported() {
        let bottom = LADDER[LADDER.len() - 1].required_kbps(1620, 1080, Quality::Balanced);
        assert!(
            bottom <= ABSOLUTE_FLOOR_KBPS,
            "bottom rung {bottom} kbps is above the {ABSOLUTE_FLOOR_KBPS} floor"
        );
    }

    #[test]
    fn quality_scales_the_whole_ladder() {
        // 1080p30, not 1080p60: the figure below is RustDesk's 1080p preset times `Balanced`, which
        // only means something at the frame rate their table assumes.
        let rung = LADDER[1];
        let best = rung.required_kbps(1920, 1080, Quality::Best);
        let balanced = rung.required_kbps(1920, 1080, Quality::Balanced);
        let low = rung.required_kbps(1920, 1080, Quality::Low);
        assert!(best > balanced && balanced > low);
        assert!((1300..=1450).contains(&balanced), "balanced = {balanced}");
    }

    #[test]
    fn a_taller_source_does_not_cost_more() {
        let mut c = QualityController::new(1920, 1080, Quality::Balanced);
        let at_1080p = c.current_required_kbps();
        c.set_source(3840, 2160);
        assert_eq!(c.current_required_kbps(), at_1080p);
    }

    #[test]
    fn a_wider_source_costs_more() {
        let mut c = QualityController::new(1920, 1080, Quality::Balanced);
        let at_16_9 = c.current_required_kbps();
        c.set_source(5120, 1440);
        assert!(c.current_required_kbps() > at_16_9);
    }

    #[test]
    fn rungs_preserve_aspect_ratio() {
        assert_eq!(LADDER[0].size_for(3600, 2400), (1620, 1080));
        assert_eq!(
            Rung {
                max_h: 720,
                fps: 30
            }
            .size_for(5120, 1440),
            (2560, 720)
        );
    }

    #[test]
    fn the_probe_ceiling_can_actually_reach_the_top_rung() {
        // The ladder climbs into a rung only when the estimate clears its price by `UP_HEADROOM`,
        // so a ceiling below `top x UP_HEADROOM` makes the top rung unreachable, and the symptom is
        // an estimate plateauing at a plausible number. The ceiling must also be what the budget
        // can reach (`absorbable_kbps`), not what a text desktop is worth.
        for (w, h) in [(1920, 1080), (1620, 1080), (3840, 1080), (3840, 2160)] {
            for q in [Quality::Low, Quality::Balanced, Quality::Best] {
                let ceiling = desired_bitrate_kbps(w, h, q);
                let top = LADDER[0].required_kbps(w, h, q);
                assert!(
                    f64::from(ceiling) >= f64::from(top) * UP_HEADROOM,
                    "{w}x{h} {q:?}: ceiling {ceiling} cannot reach a top rung priced at {top}"
                );
                assert_eq!(
                    ceiling,
                    LADDER[0]
                        .absorbable_kbps(w, h)
                        .clamp(MIN_DESIRED_KBPS, MAX_DESIRED_KBPS),
                    "{w}x{h} {q:?}: the ceiling is the top rung's absorbable price"
                );
            }
        }
    }

    #[test]
    fn the_probe_ceiling_survives_a_degenerate_source() {
        assert!(desired_bitrate_kbps(0, 0, Quality::Balanced) >= 600);
        assert!(desired_bitrate_kbps(7680, 2160, Quality::Best) <= 12_000);
    }

    #[test]
    fn every_rung_can_absorb_at_least_what_it_is_worth() {
        // `spend.clamp(floor, ceiling)` panics if the ceiling lands below the floor.
        for r in LADDER {
            for q in [Quality::Low, Quality::Balanced, Quality::Best] {
                for (w, h) in [(1920, 1080), (1620, 1080), (3840, 1080)] {
                    assert!(
                        r.absorbable_kbps(w, h) >= r.required_kbps(w, h, q),
                        "{r:?} {q:?}"
                    );
                }
            }
        }
    }

    // ── the latency measurement ───────────────────────────────────────────────────────────────

    #[test]
    fn the_queue_is_measured_in_milliseconds_at_the_rate_it_drains() {
        // 12 500 bytes is 100 000 bits; at a 1000 kbps drain that is 100 ms.
        assert_eq!(queue_ms(12_500, 1_000), 100);
        // And it scales the way a queue does.
        assert_eq!(
            queue_ms(25_000, 1_000),
            200,
            "twice the bytes, twice the wait"
        );
        assert_eq!(queue_ms(12_500, 500), 200, "half the link, twice the wait");
    }

    #[test]
    fn an_idle_link_is_not_a_slow_link() {
        // On a static desktop sending ~12 kbps the estimate, bounded by what was acknowledged,
        // collapsed to 139 kbps, and an ordinary 17 524-byte burst divided by it read as a 922 ms
        // queue and cost a rung. The same link later carried 1138 kbps: those bytes are 123 ms.
        let bytes = 17_524;
        let by_estimate_alone = queue_ms(bytes, 139);
        assert!(
            by_estimate_alone > 900,
            "the failure reproduces: {by_estimate_alone} ms from an idle estimate"
        );

        // Measured egress is a demonstration: these bytes left. The drain rate is the larger of
        // what the link has been seen to carry and what congestion control permits.
        let honest = drain_kbps(1_138, 139);
        assert_eq!(
            honest, 1_138,
            "a demonstrated rate outranks an idle estimate"
        );
        let ms = queue_ms(bytes, honest);
        assert!(
            ms < by_estimate_alone / 7,
            "and then it is not a crisis: {ms} ms against {by_estimate_alone}"
        );
        // 123 ms is above [`QUEUE_GUARD_MS`], but the guard compares `late_smoothed`, not a sample:
        // one such burst moves the five-second mean by five milliseconds.
        assert!(
            ms as f32 * LATE_ALPHA < QUEUE_GUARD_MS as f32,
            "a single burst must not be able to cross the guard on its own"
        );

        // The other direction still works: when congestion control has seen real traffic and says
        // the link is wide, that counts even if the screen has gone quiet since.
        assert_eq!(
            drain_kbps(0, 2_000),
            2_200,
            "the estimate is paced up by 1.1"
        );
        // And neither of them can produce a zero divisor.
        assert_eq!(drain_kbps(0, 0), ABSOLUTE_FLOOR_KBPS);
    }

    #[test]
    fn the_two_degenerate_openings_agree() {
        // Before any estimate the drain rate is zero: unguarded, `0/0` is NaN ("do nothing") and
        // one byte is infinity ("stop everything"). The floor makes both finite.
        assert_eq!(queue_ms(0, 0), 0);
        assert!(
            queue_ms(4_000, 0) > 0,
            "and a real queue is still a real number"
        );
    }

    #[test]
    fn nothing_is_decided_from_a_queue_before_the_link_has_spoken() {
        // The floor in `queue_ms` is arithmetic safety, not a measurement: at 120 kbps a 4 kB frame
        // reads as 242 ms, past the guard. Without `warm`, a session that has measured nothing
        // would bank descent evidence and halve its budget on its first frame.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        let opening = c.encoder_target_kbps();
        run(
            &mut c,
            |c| Feedback {
                estimate_kbps: 0, // congestion control has not reported yet
                drain_kbps: 0,
                produced_kbps: 100,
                egress_kbps: 0,
                qp_samples: 30,
                queue_age_ms: 0,
                avg_qp: None,
                encode_ms: 8.0,
                spend_ratio: 0.5,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: None,
                drop_ratio: 0.0,
                report: None,
            },
            DOWN_AFTER.as_secs_f32() * 3.0,
        );
        assert_eq!(
            c.current(),
            start,
            "an unmeasured link must not move the ladder"
        );
        assert_eq!(c.encoder_target_kbps(), opening, "nor push the budget back");
    }

    /// str0m's configured initial estimate is not the link speaking.
    ///
    /// Recorded before the media path carried a byte:
    ///
    /// ```text
    /// est 600   egress 0   for 20 s
    /// 22:33:22  -> 1080p@30
    /// 22:33:27  -> 900p
    /// ```
    ///
    /// 600 is `INITIAL_BITRATE_KBPS` in `transport/src/webrtc.rs`, echoed back before any feedback.
    /// If `warm` accepted an estimate, `growing` (production over `max(egress, 120)`) would be live
    /// with egress at zero and read whatever the encoder made.
    #[test]
    fn an_unconnected_media_path_is_not_a_slow_link() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        let rung_price = c.current_required_kbps();
        for _ in 0..20 {
            let fb = Feedback {
                // str0m's initial value, with nothing behind it.
                estimate_kbps: 600,
                drain_kbps: 660,
                // The encoder is working. Nothing is reaching the wire.
                produced_kbps: 300,
                egress_kbps: 0,
                qp_samples: 30,
                queue_age_ms: 0,
                // And the picture is as bad as it gets: `growing` and `coarse` would both read a
                // failing link if the flag were wrong.
                avg_qp: Some(46.0),
                encode_ms: 4.0,
                spend_ratio: 0.9,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        assert_eq!(
            c.current(),
            start,
            "shed a rung on a media path that had never carried a byte"
        );
        assert_eq!(
            c.encoder_target_kbps(),
            rung_price,
            "and the opening budget is what the rung is worth, not 0.9 x an estimate nothing has \
             confirmed"
        );
    }

    // ── the ladder ────────────────────────────────────────────────────────────────────────────

    /// A pipeline delivering the rung, inside budget, on an idle pipe, spending what it is given.
    fn healthy(rung_fps: f32) -> Feedback {
        Feedback {
            estimate_kbps: 50_000,
            drain_kbps: 55_000,
            // Consistent: a link estimated at 50 Mbps has also been seen to carry megabits, or the
            // exploration bound would rightly refuse to spend against it.
            produced_kbps: 5_000,
            egress_kbps: 6_000,
            qp_samples: 30,
            queue_age_ms: 0,
            avg_qp: Some(20.0),
            encode_ms: 4.0,
            spend_ratio: 1.0,
            // Comfortably under the drain: 50 Mbps estimated, half a megabit produced.
            rung_fps_hint: rung_fps,
            qp_ceiling: None,
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// A healthy link must survive the ratio measured on a healthy link.
    ///
    /// Transcribed from a recorded 1080p30 stretch: queue at zero, quantiser 33-36 against a guard
    /// of 37, encode 5 ms against a budget of 23, the link carrying 4 Mbps. Production over
    /// same-window egress was 0.89 to 1.02.
    ///
    /// The two must be measured over one window: a fresh 200 ms numerator over a once-a-second
    /// egress gauge reads 3691 over a stale 2809 as 1.31 during a climb, so every climb produced
    /// the evidence for its own undoing. The control task differences a monotonic byte counter;
    /// this test guards the controller's half, holding the rung on the ratios a healthy link
    /// produces.
    #[test]
    fn the_ratio_a_healthy_link_really_produces_does_not_shed_a_rung() {
        // 0.89 to 1.02, the measured envelope, walked repeatedly so the mean has time to settle.
        let pairs = [
            (2207u32, 2331u32),
            (1981, 2220),
            (2003, 1962),
            (2344, 2515),
            (2458, 2431),
            (2399, 2632),
            (2487, 2555),
            (2696, 2809),
            (3691, 3706),
            (2730, 3022),
        ];
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        // Long enough that a 2 s dwell plus a 3 s settle could have fired several times over.
        for round in 0..6 {
            for (produced, egress) in pairs {
                let fb = Feedback {
                    produced_kbps: produced,
                    egress_kbps: egress,
                    estimate_kbps: 4131,
                    drain_kbps: 4131,
                    queue_age_ms: 0,
                    avg_qp: Some(34.5),
                    encode_ms: 5.4,
                    spend_ratio: 1.0,
                    qp_samples: 6,
                    rung_fps_hint: 30.0,
                    qp_ceiling: None,
                    drop_ratio: 0.0,
                    report: None,
                };
                if let Some(moved) = c.tick(fb, TICK) {
                    assert!(
                        moved.max_h >= start.max_h,
                        "round {round}: shed to {}p on produced={produced} egress={egress}, \
                         a ratio of {:.2}",
                        moved.max_h,
                        produced as f32 / egress as f32
                    );
                }
            }
        }
    }

    /// A still screen must not pin the budget below what the next motion will cost.
    ///
    /// Recorded: at 1080p30 on a link that later carried 4.1 Mbps, `egress * 1.5 + 300` held the
    /// budget at 249 kbps on a still desktop, and the first sharp scroll produced 2584 kbps, 817 ms
    /// of queue and a cascade to 360p. Both directions are asserted: suspending the bound
    /// unconditionally would restore the fault it exists for.
    #[test]
    fn a_still_screen_does_not_pin_the_budget_and_a_busy_one_still_bounds_it() {
        let idle = |c: &mut QualityController| {
            for _ in 0..60 {
                c.tick(
                    Feedback {
                        // A still desktop: a few hundred bytes a frame at 5 fps.
                        produced_kbps: 12,
                        egress_kbps: 12,
                        estimate_kbps: 4000,
                        drain_kbps: 4000,
                        queue_age_ms: 0,
                        avg_qp: Some(20.0),
                        encode_ms: 1.0,
                        // The encoder is using 1% of what it was given. This is the whole signal.
                        spend_ratio: 0.01,
                        qp_samples: 1,
                        rung_fps_hint: 30.0,
                        qp_ceiling: None,
                        drop_ratio: 0.0,
                        report: None,
                    },
                    TICK,
                );
            }
        };

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        idle(&mut c);
        let budget = c.encoder_target_kbps();
        assert!(
            budget > 1_000,
            "a still screen pinned the budget at {budget} kbps against a 4 Mbps estimate; the \
             next motion would be handed that and overshoot it twentyfold"
        );

        // And the other way: an encoder that *is* spending its allowance, on a link that has only
        // demonstrated 600 kbps, must still be bounded by what the link showed.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..60 {
            c.tick(
                Feedback {
                    produced_kbps: 600,
                    egress_kbps: 600,
                    estimate_kbps: 50_000,
                    drain_kbps: 50_000,
                    queue_age_ms: 0,
                    avg_qp: Some(30.0),
                    encode_ms: 4.0,
                    spend_ratio: 1.0,
                    qp_samples: 6,
                    rung_fps_hint: 30.0,
                    qp_ceiling: None,
                    drop_ratio: 0.0,
                    report: None,
                },
                TICK,
            );
        }
        let bounded = c.encoder_target_kbps();
        assert!(
            bounded <= 600 * 3 / 2 + EXPLORE_MARGIN_KBPS,
            "a link that demonstrated 600 kbps while the encoder was spending its whole allowance \
             must still bound the budget; got {bounded}"
        );
    }

    /// The measured deadlock must be escapable, and a genuinely narrow link must not be escaped.
    ///
    /// Recorded for eight minutes on a pinned 1080p: `qp=46 q=0 est~250 prod~190` at 1080p@8, on a
    /// link that had carried 3789 kbps, with the encoder at 7 ms against a 125 ms budget.
    #[test]
    fn a_rung_that_suppresses_its_own_evidence_can_still_be_escaped() {
        let stuck = |c: &QualityController| Feedback {
            produced_kbps: 190,
            egress_kbps: 200,
            // What `acked * 1.5 + 10` gives for 190 kbps of traffic, which is the whole trap.
            estimate_kbps: 295,
            drain_kbps: 295,
            queue_age_ms: 0,
            // At its ceiling: the picture is as bad as this encoder can make it.
            avg_qp: Some(46.0),
            encode_ms: 7.0,
            spend_ratio: 1.0,
            qp_samples: 8,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        // Pinned: a pinned ladder only sheds frame rate, so its bottom is 1080p@8, whose next step
        // costs more than the suppressed estimate can justify. Unpinned, `affordable` alone would
        // escape and the test would prove nothing.
        c.set_pinned_height(Some(1080));
        for _ in 0..(PINNED_FPS.len() as u32 * 60) {
            let fb = congested(c.current().fps as f32);
            c.tick(fb, TICK);
        }
        let bottom = c.current();
        assert_eq!(
            bottom.fps,
            *PINNED_FPS.last().expect("pinned ladder is not empty"),
            "the setup did not reach the bottom of the pinned ladder"
        );
        assert_eq!(bottom.max_h, 1080);
        let mut climbed = None;
        for tick in 1..=200 {
            let fb = stuck(&c);
            if let Some(moved) = c.tick(fb, TICK) {
                climbed = Some((tick, moved));
                break;
            }
        }
        let (tick, moved) = climbed.expect(
            "the ladder never left a rung whose quantiser was pinned on a link showing no strain; \
             that is eight minutes at 8 fps on a link carrying four megabits",
        );
        assert!(
            moved.max_h > bottom.max_h || moved.fps > bottom.fps,
            "moved to {moved:?}, which is not upward from {bottom:?}"
        );
        // Spaced by the climb dwell, not instant: this is an experiment, not a belief.
        assert!(
            u32::try_from(tick).unwrap_or(u32::MAX) * TICK.as_millis() as u32
                >= UP_AFTER.as_millis() as u32,
            "climbed after {tick} ticks, faster than the dwell that spaces the attempts"
        );
    }

    /// Recovery from the bottom of the full ladder, on a link that is plainly carrying it.
    ///
    /// One rung at a time, `UP_AFTER + SETTLE_AFTER_MOVE` each, is a minute for six rungs. The
    /// bound is loose on purpose: it pins seconds rather than a minute, not the dwell constants.
    ///
    /// Production is what one piece of content costs at whichever rung is live, scaled as the
    /// ladder scales prices (162 kbps at the bottom rung), and the encode time is 4 ms at the top
    /// rung scaled by pixels. Constants across rungs would describe content and a processor that
    /// cannot exist, and the content and encode terms of the climb gate would rightly refuse them.
    #[test]
    fn a_link_that_is_obviously_carrying_it_gets_the_picture_back_in_seconds() {
        // Content that costs 4000 kbps and 4 ms a frame at the top rung, priced at whichever rung
        // is live.
        let pixels = |rung: Rung| {
            let (w, h) = rung.size_for(1620, 1080);
            f64::from(w) * f64::from(h)
        };
        let content_at = |rung: Rung| {
            (4_000.0 * pixels(rung) / pixels(LADDER[0])
                * (fps_factor(rung.fps) / fps_factor(LADDER[0].fps))) as u32
        };
        let encode_at = |rung: Rung| (4.0 * pixels(rung) / pixels(LADDER[0])) as f32;

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..(LADDER.len() as u32 * 60) {
            let fb = congested(c.current().fps as f32);
            c.tick(fb, TICK);
        }
        assert_eq!(
            c.current(),
            *LADDER.last().expect("ladder is not empty"),
            "the setup did not reach the bottom rung"
        );

        // A link with room to spare and nothing wrong: empty queue, quantiser well inside its
        // range, encode time a fraction of its budget.
        let mut ticks = 0u32;
        while c.current() != LADDER[0] {
            ticks += 1;
            assert!(
                ticks < 600,
                "still at {:?} after {} seconds",
                c.current(),
                ticks / 5
            );
            let produced = content_at(c.current());
            let fb = Feedback {
                produced_kbps: produced,
                egress_kbps: produced + 200,
                estimate_kbps: 12_000,
                drain_kbps: 12_000,
                queue_age_ms: 0,
                avg_qp: Some(24.0),
                encode_ms: encode_at(c.current()),
                spend_ratio: 0.95,
                qp_samples: 6,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        let seconds =
            f32::from(u16::try_from(ticks).unwrap_or(u16::MAX)) * TICK.as_millis() as f32 / 1000.0;
        assert!(
            seconds < 20.0,
            "took {seconds:.0} s to cross the ladder on a link estimated at 12 Mbps; the reported \
             fault was about a minute"
        );
    }

    /// The same signal must not lift a ladder off a link that cannot carry more: with a queue past
    /// its guard, the escape hatch would be a ratchet, not an experiment.
    #[test]
    fn a_saturated_quantiser_with_a_queue_does_not_climb() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        for _ in 0..200 {
            let fb = Feedback {
                produced_kbps: 900,
                egress_kbps: 300,
                estimate_kbps: 300,
                drain_kbps: 300,
                // The link is full and saying so.
                queue_age_ms: QUEUE_GUARD_MS * 3,
                avg_qp: Some(46.0),
                encode_ms: 7.0,
                spend_ratio: 1.0,
                qp_samples: 8,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            if let Some(moved) = c.tick(fb, TICK) {
                assert!(
                    moved.max_h <= start.max_h,
                    "climbed to {moved:?} on a link with a queue three times its guard"
                );
            }
        }
    }

    /// A quantiser measured against a budget the link has never confirmed is not a network signal.
    ///
    /// Quality is given up only when the network cannot carry it or the processor cannot encode it.
    /// `coarse` and `throttled` say the encoder could not fit the picture into bits this controller
    /// chose, which is network evidence only while the budget is a measurement of the link.
    /// Recorded: after a seven-second pause the estimate fell to 661, motion resumed against a
    /// budget of 328, and those two arms shed three rungs in twenty seconds on a 15 Mbps link. Both
    /// halves are asserted, because an arm that never fires is not a fix.
    #[test]
    fn a_high_quantiser_against_an_unmeasured_budget_does_not_shed_a_rung() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();

        // Four seconds of the post-pause state: 4000 kbps going out against an estimate of 700,
        // which lags the traffic. Everything `coarse` and `throttled` need is past its threshold,
        // while the queue is empty and production is under egress.
        for _ in 0..20 {
            let fb = Feedback {
                estimate_kbps: 700,
                drain_kbps: 770,
                produced_kbps: 3_500,
                egress_kbps: 4_000,
                qp_samples: 12,
                queue_age_ms: 0,
                avg_qp: Some(46.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.5,
                report: None,
            };
            c.tick(fb, TICK);
        }
        assert_eq!(
            c.current(),
            start,
            "shed a rung on a saturated quantiser and a brake at 0.5 against a budget of 630 that \
             the link had never confirmed — the queue was empty and 4000 kbps was going out"
        );

        // The link saying no, measured: 1350 kbps leaving against an estimate of 1500, inside the
        // band, so the budget the quantiser saturated against is the link's own.
        let mut shed = None;
        for tick in 1..=20 {
            let fb = Feedback {
                estimate_kbps: 1_500,
                drain_kbps: 1_650,
                produced_kbps: 1_200,
                egress_kbps: 1_350,
                qp_samples: 12,
                queue_age_ms: 0,
                avg_qp: Some(46.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            if c.tick(fb, TICK).is_some() {
                shed = Some(tick);
                break;
            }
        }
        assert!(
            shed.is_some(),
            "a saturated quantiser against a budget the link confirmed is the network saying no, \
             and the rung must give way — otherwise the assertion above is satisfied by a ladder \
             with no quantiser arm at all"
        );
    }

    /// A rung held by throwing frames away is not being held, and the ladder must notice.
    ///
    /// With the bit bucket holding production inside the budget, the queue is empty and surviving
    /// frames are coded comfortably, so every other descent arm reads green (measured: 1080p at
    /// five frames a second with nothing complaining).
    #[test]
    fn a_rung_held_only_by_dropping_frames_is_shed() {
        let throttled_feedback = |c: &QualityController| Feedback {
            // Production is inside the budget — because two frames in three never reach the
            // encoder. That is exactly what makes this invisible to everything else.
            produced_kbps: 1_900,
            egress_kbps: 2_000,
            estimate_kbps: 2_200,
            drain_kbps: 2_200,
            queue_age_ms: 0,
            avg_qp: Some(30.0),
            encode_ms: 5.0,
            spend_ratio: 0.95,
            qp_samples: 6,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.66,
            report: None,
        };

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        let mut shed = None;
        for tick in 1..=100 {
            let fb = throttled_feedback(&c);
            if let Some(moved) = c.tick(fb, TICK) {
                if moved.max_h < start.max_h || moved.fps < start.fps {
                    shed = Some(tick);
                    break;
                }
            }
        }
        assert!(
            shed.is_some(),
            "the ladder held {start:?} while two frames in three were being thrown away to \
             afford it; every other arm reads healthy in exactly that situation"
        );

        // And the converse: a brake that is barely engaging must not cost a rung. Dropping the
        // occasional frame is the mechanism working, not a reason to shed pixels.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        for _ in 0..100 {
            let mut fb = throttled_feedback(&c);
            fb.drop_ratio = 0.1;
            if let Some(moved) = c.tick(fb, TICK) {
                assert!(
                    moved.max_h >= start.max_h,
                    "shed a rung over a tenth of frames dropped, which is the brake working"
                );
            }
        }
    }

    /// The other half of the test above, which keeps it from being vacuous: fed the ratio that a
    /// mismatched-window assembly produces (this window's production over the previous window's
    /// egress), the ladder does shed. Otherwise the test above would pass on a controller with no
    /// network signal at all.
    #[test]
    fn the_ratio_the_stale_denominator_produced_does_shed_a_rung() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        // 3691 produced over the previous window's 2809 of egress: 1.31, on an otherwise healthy
        // pipeline. Only the denominator is wrong.
        let mut moved_down = false;
        for _ in 0..60 {
            let fb = Feedback {
                produced_kbps: 3691,
                egress_kbps: 2809,
                estimate_kbps: 4131,
                drain_kbps: 4131,
                queue_age_ms: 0,
                avg_qp: Some(34.5),
                encode_ms: 5.4,
                spend_ratio: 1.0,
                qp_samples: 6,
                rung_fps_hint: 30.0,
                qp_ceiling: None,
                drop_ratio: 0.0,
                report: None,
            };
            if let Some(moved) = c.tick(fb, TICK) {
                if moved.max_h < start.max_h {
                    moved_down = true;
                    break;
                }
            }
        }
        assert!(
            moved_down,
            "a ratio of 1.31 must still shed a rung — otherwise the test above proves nothing"
        );
    }

    /// A pipeline whose packets wait far longer than the latency budget allows: the network signal,
    /// stated as a measured age.
    fn congested(rung_fps: f32) -> Feedback {
        Feedback {
            queue_age_ms: QUEUE_GUARD_MS * 4,
            produced_kbps: 2_000,
            egress_kbps: 800,
            ..healthy(rung_fps)
        }
    }

    /// Run `secs` worth of ticks.
    fn run(c: &mut QualityController, fb: impl Fn(&QualityController) -> Feedback, secs: f32) {
        let ticks = (secs / TICK.as_secs_f32()).ceil() as u32;
        for _ in 0..ticks {
            let f = fb(c);
            c.tick(f, TICK);
        }
    }

    #[test]
    fn a_rung_the_network_cannot_carry_falls() {
        // One of the two reasons quality may drop. If the pixels do not fit down the link, packets
        // wait, and that is read off str0m as the measured age of the oldest queued packet, with no
        // denominator to get wrong.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        run(
            &mut c,
            |c| congested(c.current().fps as f32),
            // Two steps: from the 1080p60 bonus rung the first is cadence (see [`LADDER`]), and
            // each is followed by `SETTLE_AFTER_MOVE`.
            (DOWN_AFTER + SETTLE_AFTER_MOVE).as_secs_f32() * 3.0,
        );
        assert!(
            c.current().max_h < start.max_h,
            "packets waiting past the budget must move pixels"
        );
    }

    #[test]
    #[ignore = "supplanted: replays a state the deleted admission gate produced and which the \
                architecture can no longer reach. Kept as a record of the failure it described."]
    fn the_session_that_shipped_would_now_descend() {
        // 1080p30, the capturer offering 60 frames a second, the pipeline delivering 2.4, and 730
        // ms of local queue for thirty seconds. A captured-versus-delivered ratio could not see it
        // (1229 captured, 1228 delivered); the queue's age is a descent condition of its own.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        run(
            &mut c,
            |c| Feedback {
                estimate_kbps: 1_283,
                drain_kbps: 1_411,
                produced_kbps: 852,
                egress_kbps: 900,
                qp_samples: 30,
                queue_age_ms: 730,
                avg_qp: Some(30.0), // not saturated: the old ladder saw nothing wrong here either
                encode_ms: 23.0,
                spend_ratio: 0.84,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: None,
                drop_ratio: 0.0,
                report: None,
            },
            DOWN_AFTER.as_secs_f32() * 1.5,
        );
        assert!(
            c.current().max_h < start.max_h,
            "a queue five times its budget must move pixels"
        );
    }

    #[test]
    fn the_ladder_reacts_inside_the_latency_budget_it_is_defending() {
        // A response time is part of the contract. With only the queue's age, filtered over five
        // seconds to ride out a keyframe, `q(1 - 0.96^n)` against the guard and a two-second dwell
        // gives:
        //
        //     600 ms of queue -> 3.4 s to shed a rung
        //     300 ms          -> 5.4 s
        //     200 ms          -> 8.8 s
        //
        // and meanwhile only the transport's breaker holds latency, by discarding frames and asking
        // for keyframes into the queue it is draining. Production against egress, two independent
        // measurements, sees a growing backlog within one window.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        let mut elapsed = Duration::ZERO;
        while c.current() == start && elapsed < Duration::from_secs(30) {
            // Twice the guard, and production half again what is leaving.
            c.tick(
                Feedback {
                    queue_age_ms: QUEUE_GUARD_MS * 2,
                    produced_kbps: 1_500,
                    egress_kbps: 1_000,
                    ..healthy(c.current().fps as f32)
                },
                TICK,
            );
            elapsed += TICK;
        }
        assert!(
            elapsed <= Duration::from_secs(3),
            "a growing backlog must move the ladder within three seconds, took {elapsed:?}"
        );
    }

    #[test]
    fn a_saturated_quantiser_alone_does_not_give_up_pixels() {
        // Quality is given up for two reasons only: the network cannot carry it, or the processor
        // cannot encode it. A high quantiser is neither: it says the content did not fit a budget
        // this controller set from an estimate, which is low on every idle screen. Recorded, six
        // descents from 1080p to 360p@8, each like:
        //
        //     900p: est=832  qp=46  queue=4    spend=0.03
        //     720p: est=128  qp=46  queue=676  spend=0.13
        //     540p: est=167  qp=46  queue=113  spend=0.16
        //     360p: est=83   qp=43  queue=9    spend=0.12
        //
        // The encoder used 3 to 16% of its budget. If the pixels do not fit, `queue_age_ms` says
        // so.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        run(
            &mut c,
            |c| Feedback {
                avg_qp: Some(51.0),
                spend_ratio: 0.05,
                ..healthy(c.current().fps as f32)
            },
            DOWN_AFTER.as_secs_f32() * 4.0,
        );
        assert_eq!(
            c.current(),
            start,
            "a quiet queue and an idle processor must hold the rung, whatever the quantiser says"
        );
    }

    #[test]
    fn a_slow_processor_gives_up_pixels_before_any_network_signal() {
        // The arm for a weak machine must work with a perfect link and an empty queue: no network
        // measurement will say a dual-core laptop is the limit.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        run(
            &mut c,
            |c| Feedback {
                // 25 ms is the line at 30 fps, 12.5 at 60; 28 ms fails both, so a machine this slow
                // must not stop at the cadence step.
                encode_ms: 28.0,
                ..healthy(c.current().fps as f32)
            },
            // Two steps now, and each is followed by `SETTLE_AFTER_MOVE`: the first sheds the
            // bonus rung's cadence, the second the pixels.
            (DOWN_AFTER + SETTLE_AFTER_MOVE).as_secs_f32() * 3.0,
        );
        assert!(
            c.current().max_h < start.max_h,
            "a processor that cannot keep up must shed pixels, not stop at 1080p30"
        );
    }

    /// Recorded seconds of encode time, each fed for the ticks a second holds — the resolution the
    /// session's `pipeline` lines have — on an otherwise healthy link. The moves, in order.
    fn feed_encode_seconds(c: &mut QualityController, seconds: &[f32]) -> Vec<Rung> {
        let ticks = (Duration::from_secs(1).as_millis() / TICK.as_millis()) as usize;
        let mut moves = Vec::new();
        for &encode_ms in seconds {
            for _ in 0..ticks {
                let fb = Feedback {
                    encode_ms,
                    ..healthy(c.current().fps as f32)
                };
                moves.extend(c.tick(fb, TICK));
            }
        }
        moves
    }

    /// Ticks of `encode_ms` on a healthy link until the ladder moves, at most `secs`: the move and
    /// how long it took, or `None`.
    fn until_move(
        c: &mut QualityController,
        encode_ms: f32,
        secs: f32,
    ) -> Option<(Rung, Duration)> {
        let ticks = (secs / TICK.as_secs_f32()).ceil() as u32;
        for n in 1..=ticks {
            let fb = Feedback {
                encode_ms,
                ..healthy(c.current().fps as f32)
            };
            if let Some(r) = c.tick(fb, TICK) {
                return Some((r, TICK * n));
            }
        }
        None
    }

    const SIXTY: Rung = Rung {
        max_h: 1080,
        fps: 60,
    };
    const THIRTY: Rung = Rung {
        max_h: 1080,
        fps: 30,
    };

    /// The rung the processor gave up is not climbed back into until the encoder has room there.
    ///
    /// Recorded on a handheld (Ryzen Z1 Extreme) at 1080p: `cpu_bound` shed 1080p@60 at 12-13 ms a
    /// frame, and the climb back was the network's alone, since at 30 fps the `cpu_bound` line is
    /// 25 ms. The encode times here are that recording's at 1080p@30 in order (11.0-15.6 ms, then
    /// 9.7-14.3), on which the controller without this gate climbed and was down again 37 s later.
    /// Both halves are asserted: the same link climbs as soon as the encoder shows room.
    #[test]
    fn a_rung_the_processor_shed_is_climbed_back_only_when_the_encoder_has_room() {
        let mut c = QualityController::new(1920, 1080, Quality::Balanced);
        assert_eq!(c.current(), SIXTY);
        let shed = until_move(&mut c, 13.3, DOWN_AFTER.as_secs_f32() * 3.0);
        assert_eq!(
            shed.map(|(r, _)| r),
            Some(THIRTY),
            "13.3 ms a frame at 60 fps is cpu_bound"
        );

        // 18:46:42-18:47:02, at 30.
        let first_stay = [
            11.0, 13.5, 13.3, 13.5, 13.3, 13.5, 13.7, 14.5, 14.8, 14.2, 13.2, 15.6, 14.4, 12.8,
            12.6, 14.2, 12.6, 13.5, 15.4, 14.1, 13.6,
        ];
        // 18:47:16-18:47:35, at 30 again after the next descent: the stay the live controller ended
        // with a climb.
        let second_stay = [
            10.7, 13.1, 12.0, 10.8, 12.4, 11.8, 11.5, 14.3, 12.1, 11.1, 9.7, 11.3, 11.7, 12.0,
            10.3, 12.9, 13.0, 10.7, 14.1, 10.9,
        ];
        let moves = feed_encode_seconds(&mut c, &first_stay);
        assert!(
            moves.is_empty(),
            "climbed back into 1080p@60 on 11-16 ms a frame, which 1080p@60 had just been shed \
             for: {moves:?}"
        );
        let moves = feed_encode_seconds(&mut c, &second_stay);
        assert!(moves.is_empty(), "and again on 10-14 ms: {moves:?}");

        // 18:48:13-18:48:29: the lull, 6.6-9.3 ms, and the seconds at 60 that followed it live.
        let lull = [
            9.3, 8.0, 6.6, 7.7, 8.9, 8.3, 8.4, 8.7, 7.3, 8.9, 8.9, 8.7, 9.1, 8.8, 8.5, 8.9, 8.4,
        ];
        let moves = feed_encode_seconds(&mut c, &lull);
        assert_eq!(
            moves.first().copied(),
            Some(SIXTY),
            "the same link with the encoder at 8 ms a frame must climb back — otherwise the holds \
             above are satisfied by a ladder that has stopped climbing"
        );
    }

    /// Each `cpu_bound` descent after the first since the processor last held the rung doubles the
    /// dwell the climb back needs, up to [`CPU_CLIMB_DWELL_MAX`]; a minute held at the rung
    /// ([`CPU_STREAK_FORGET`]) forgets them.
    ///
    /// For a load alternating faster than the climb gate can see: a lull passes it, the climb
    /// lands, the next scene takes the rung back. 8 ms a frame at 30, 13.3 ms at 60, as recorded.
    #[test]
    fn repeated_cpu_bound_descents_ask_the_encoder_for_longer_lulls() {
        let mut c = QualityController::new(1920, 1080, Quality::Balanced);
        let window = (SETTLE_AFTER_MOVE + CPU_CLIMB_DWELL_MAX).as_secs_f32() * 2.0;
        for (n, dwell) in [4u64, 8, 16, 32, 32].into_iter().enumerate() {
            let shed = until_move(&mut c, 13.3, window);
            assert_eq!(shed.map(|(r, _)| r), Some(THIRTY), "descent {}", n + 1);
            let (to, took) = until_move(&mut c, 8.0, window)
                .unwrap_or_else(|| panic!("descent {}: never climbed back", n + 1));
            assert_eq!(to, SIXTY, "descent {}", n + 1);
            let needed = SETTLE_AFTER_MOVE + Duration::from_secs(dwell);
            assert!(
                took >= needed && took <= needed + Duration::from_secs(1),
                "descent {}: climbed back after {took:?}, not the settle and {dwell} s",
                n + 1
            );
        }

        // A minute at 1080p@60 with the encoder at 8 ms: the processor held the rung.
        assert_eq!(
            until_move(&mut c, 8.0, CPU_STREAK_FORGET.as_secs_f32() + 1.0),
            None
        );
        let shed = until_move(&mut c, 13.3, window);
        assert_eq!(shed.map(|(r, _)| r), Some(THIRTY));
        let (to, took) = until_move(&mut c, 8.0, window).expect("never climbed back");
        assert_eq!(to, SIXTY);
        assert!(
            took <= SETTLE_AFTER_MOVE + UP_AFTER + Duration::from_secs(1),
            "after the processor held the rung for a minute a descent is a first again: {took:?}"
        );
    }

    /// The climb gate scales the encoder's time by pixels, not cadence: at 900p@30 a 9 ms frame is
    /// 13 ms at 1080p, over 1080p@60's 10.8 ms line and inside 1080p@30's 21.7, so the climb lands
    /// at 1080p@30; at 4 ms (5.8 at 1080p) it goes to the top in one move.
    #[test]
    fn a_climb_is_priced_against_the_encoder_by_the_rungs_pixels() {
        let first_climb = |encode_ms: f32| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            descend_to(&mut c, 900);
            until_move(
                &mut c,
                encode_ms,
                (SETTLE_AFTER_MOVE + UP_AFTER).as_secs_f32() * 3.0,
            )
            .map(|(r, _)| r)
        };
        assert_eq!(
            first_climb(9.0),
            Some(THIRTY),
            "13 ms a frame at 1080p is no room for 60 fps, and room for 30"
        );
        assert_eq!(first_climb(4.0), Some(SIXTY), "and 5.8 ms is room for 60");
    }

    /// `starved`, the blind cadence climb, asks the encoder too. The pinned ladder's 1080p@30 after
    /// `cpu_bound` shed 60, on the fixture of `a_saturated_quantiser_does_not_buy_a_pixel_climb`.
    #[test]
    fn a_starved_cadence_climb_waits_for_the_encoder_too() {
        let first_climb = |encode_ms: f32| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            c.set_pinned_height(Some(1080));
            let shed = until_move(&mut c, 13.3, DOWN_AFTER.as_secs_f32() * 3.0);
            assert_eq!(shed.map(|(r, _)| r), Some(THIRTY));
            let ticks = ((SETTLE_AFTER_MOVE + UP_AFTER).as_secs_f32() * 1.4 / TICK.as_secs_f32())
                .ceil() as u32;
            for _ in 0..ticks {
                let fb = Feedback {
                    estimate_kbps: 898,
                    drain_kbps: 898,
                    produced_kbps: 880,
                    egress_kbps: 880,
                    qp_samples: 1,
                    queue_age_ms: 0,
                    avg_qp: Some(46.0),
                    encode_ms,
                    spend_ratio: 1.0,
                    rung_fps_hint: c.current().fps as f32,
                    qp_ceiling: Some(46.0),
                    drop_ratio: 0.0,
                    report: None,
                };
                if let Some(r) = c.tick(fb, TICK) {
                    return Some(r);
                }
            }
            None
        };
        assert_eq!(
            first_climb(11.5),
            None,
            "11.5 ms a frame is no room for 60 fps, starved or not"
        );
        assert_eq!(
            first_climb(8.0),
            Some(SIXTY),
            "and at 8 ms the starved climb is the one it always was"
        );
    }

    #[test]
    fn a_cheap_picture_on_a_thin_link_does_not_climb() {
        // A still desktop needs almost no bits, so the quantiser sits at its floor on any link. A
        // ladder that read low QP as room would climb on a link that cannot carry the bottom rung.
        // Two guards say no: the encoder is not spending, and the estimate does not cover the
        // price.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        // Start from the bottom, where there is somewhere to climb to.
        run(
            &mut c,
            |c| Feedback {
                ..congested(c.current().fps as f32)
            },
            600.0,
        );
        let bottom = c.current();
        assert_eq!(bottom, LADDER[LADDER.len() - 1]);

        run(
            &mut c,
            |c| Feedback {
                // Genuinely too thin for the next rung up, which at 360p@15 on this source prices
                // at about 120 kbps and needs 150 with headroom.
                estimate_kbps: 90,
                drain_kbps: 99,
                produced_kbps: 10,
                egress_kbps: 90,
                qp_samples: 30,
                queue_age_ms: 0,
                avg_qp: Some(18.0), // nothing on screen: the quantiser bottoms out
                encode_ms: 3.0,
                spend_ratio: 0.05, // and the encoder is nowhere near its allowance
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: None,
                drop_ratio: 0.0,
                report: None,
            },
            UP_AFTER.as_secs_f32() * 4.0,
        );
        assert_eq!(
            c.current(),
            bottom,
            "a cheap picture is not evidence of a wide link"
        );
    }

    #[test]
    fn a_full_queue_cannot_be_read_as_room_to_climb() {
        // Overshoot is produced over allowed bits, and the encoder is handed a budget pushback has
        // already reduced, so an encoder on target reports `1 - 0.5 x pressure`, which falls as the
        // queue grows. As a climb signal it would bank evidence to climb into a filling pipe.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        run(
            &mut c,
            |c| Feedback {
                ..congested(c.current().fps as f32)
            },
            600.0,
        );
        let bottom = c.current();

        run(
            &mut c,
            |c| Feedback {
                queue_age_ms: QUEUE_GUARD_MS,
                ..healthy(c.current().fps as f32)
            },
            UP_AFTER.as_secs_f32() * 4.0,
        );
        assert_eq!(c.current(), bottom, "a full pipe is not an invitation");
    }

    #[test]
    fn a_still_screen_does_not_move_the_ladder() {
        // Only the content limits the picture: no queue, comfortable quantiser, fast encode. The
        // estimate collapsed because nothing is sent, which is not a failing link.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        run(
            &mut c,
            |_| Feedback {
                estimate_kbps: 90,
                drain_kbps: 120,
                produced_kbps: 2,
                egress_kbps: 100,
                qp_samples: 30,
                queue_age_ms: 0,
                avg_qp: Some(18.0),
                encode_ms: 2.0,
                spend_ratio: 0.02,
                rung_fps_hint: 30.0,
                qp_ceiling: None,
                drop_ratio: 0.0,
                report: None,
            },
            60.0,
        );
        assert_eq!(
            c.current(),
            start,
            "nothing is limiting the picture but the content"
        );
    }

    #[test]
    fn a_recovered_link_climbs_all_the_way_back() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        run(
            &mut c,
            |c| Feedback {
                ..congested(c.current().fps as f32)
            },
            120.0,
        );
        assert_eq!(
            c.current(),
            LADDER[LADDER.len() - 1],
            "starved to the floor"
        );

        run(&mut c, |c| healthy(c.current().fps as f32), 240.0);
        assert_eq!(
            c.current(),
            LADDER[0],
            "a recovered link must reach the top"
        );
    }

    // ── the compiled safe profile ─────────────────────────────────────────────────────────────
    //
    // `QualityPolicy::safe`: careful, not broken. It reaches its top on a good link, brakes where
    // the reference rides loss out, recovers, leaves drain mode, and descends no slower.

    fn on_safe() -> QualityController {
        QualityController::with_policy(1620, 1080, Quality::Balanced, QualityPolicy::safe())
    }

    /// A clean link carrying whatever the budget asks of it.
    fn carrying(c: &QualityController) -> Feedback {
        let budget = c.encoder_target_kbps().max(EXPLORE_MARGIN_KBPS);
        Feedback {
            produced_kbps: budget * 9 / 10,
            egress_kbps: budget,
            ..healthy(c.current().fps as f32)
        }
    }

    #[test]
    fn safe_climbs_to_its_top_on_a_clean_link_and_never_above() {
        let mut c = on_safe();
        let top = c.policy().start_rung();
        assert_eq!((top.max_h, top.fps), (720, 30));
        assert_eq!(c.current(), top, "it opens at its top");
        let floor = *c.policy().ladder.last().expect("a ladder");
        let ticks = |secs: f32| (secs / TICK.as_secs_f32()).ceil() as u32;
        let mut seen = vec![c.current()];

        for _ in 0..ticks(60.0) {
            let fb = carrying(&c);
            if let Some(r) = c.tick(fb, TICK) {
                seen.push(r);
            }
        }
        assert_eq!(c.current(), top, "a clean link keeps the top: {seen:?}");

        for _ in 0..ticks(120.0) {
            let fb = congested(c.current().fps as f32);
            if let Some(r) = c.tick(fb, TICK) {
                seen.push(r);
            }
        }
        assert_eq!(c.current(), floor, "starved to the floor: {seen:?}");

        let mut back_after = None;
        for i in 0..ticks(240.0) {
            let fb = carrying(&c);
            if let Some(r) = c.tick(fb, TICK) {
                seen.push(r);
            }
            if back_after.is_none() && c.current() == top {
                back_after = Some(i);
            }
        }
        assert_eq!(
            c.current(),
            top,
            "a recovered link reaches the top: {seen:?}"
        );
        assert!(back_after.is_some());
        assert!(
            seen.iter()
                .all(|r| c.policy().ladder.contains(r) && r.max_h <= 720 && r.fps <= 30),
            "never above 720p30, never off its ladder: {seen:?}"
        );
    }

    /// A congested link takes the safe profile's top no later than it takes the reference's.
    #[test]
    fn safe_descends_no_slower_than_the_reference() {
        let first_move = |mut c: QualityController| {
            (1..=1_000u32)
                .find(|_| {
                    let fb = congested(c.current().fps as f32);
                    c.tick(fb, TICK).is_some()
                })
                .expect("a congested link moves the rung")
        };
        let safe = first_move(on_safe());
        let reference = first_move(QualityController::new(1620, 1080, Quality::Balanced));
        assert!(
            safe <= reference,
            "safe moved after {safe} ticks, the reference after {reference}"
        );
    }

    /// 9% loss in one report: past the safe line (8%), under the reference's (10%), so the safe
    /// profile brakes (to 0.7 of what got through) where the reference rides it out; clean reports
    /// then give the budget back and the picture stays at or returns to the top.
    #[test]
    fn safe_brakes_on_loss_the_reference_rides_out_and_recovers() {
        let link = |c: &QualityController| {
            let budget = c.encoder_target_kbps().max(1_000);
            Feedback {
                produced_kbps: budget * 95 / 100,
                ..lte(c, 12_482, budget)
            }
        };
        let mut safe = on_safe();
        let mut reference = QualityController::new(1620, 1080, Quality::Balanced);
        for c in [&mut safe, &mut reference] {
            for rtt in [251, 258, 253, 250, 252, 251, 257, 251, 251, 258, 253, 250] {
                one_second(c, link, fresh(rtt, 0.0, 0));
            }
            assert_eq!(c.brake_kbps(), None);
            let _ = c.take_brake_event();
        }
        let top = safe.policy().start_rung();
        assert_eq!(safe.current(), top);
        let before = safe.encoder_target_kbps();

        one_second(&mut safe, link, fresh(255, 9.0, 6));
        one_second(&mut reference, link, fresh(255, 9.0, 6));
        assert_eq!(
            reference.take_brake_event(),
            None,
            "9% is under the reference's line"
        );
        match safe.take_brake_event() {
            Some(BrakeEvent::Engaged(d)) => assert_eq!(d.cause, BrakeCause::Loss),
            other => panic!("9% loss must engage the safe brake: {other:?}"),
        }
        let cut = safe.brake_kbps().expect("engaged");
        assert!(
            f64::from(cut) <= f64::from(before) * 0.91 * 0.7 * 1.05,
            "cut to {cut} from {before}: 0.7 of the 91% that got through"
        );

        let mut released_after = None;
        for second in 1..=60u32 {
            one_second(&mut safe, link, fresh(252, 0.0, 0));
            if let Some(BrakeEvent::Released(_)) = safe.take_brake_event() {
                released_after = Some(second);
                break;
            }
        }
        let after = released_after.expect("a clean link must get its budget back");
        assert!(
            after >= 3,
            "released after {after} s: gradually, not at once"
        );
        assert_eq!(safe.brake_kbps(), None);
        for _ in 0..60 {
            one_second(&mut safe, link, fresh(252, 0.0, 0));
        }
        assert_eq!(safe.current(), top, "and the picture is at its top");
        assert!(
            safe.encoder_target_kbps() >= before * 9 / 10,
            "the budget back: {} against {before}",
            safe.encoder_target_kbps()
        );
    }

    /// Drain mode on the safe profile: entered on a recorded 3G stall's first two reports (past
    /// its 1500 ms line), and left at its own, shorter bound when the receiver stops proving the
    /// backlog, and at once on a report under the exit band.
    #[test]
    fn safe_leaves_drain_mode() {
        let mut c = on_3g_before_the_stall_on(on_safe());
        let drain_max_s = c.policy().drain_max().as_secs();
        assert!(drain_max_s < DRAIN_MAX.as_secs());
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(4_752, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(6_607, 0.0, 0));
        assert!(c.draining());
        let _ = c.take_drain_event();
        let mut held_s: u64 = 1;
        while c.draining() {
            // Between the exit band (750 on this baseline) and the entry line: no proof either way.
            one_second(&mut c, draining_tick, fresh(1_200, 0.0, 0));
            held_s += 1;
            assert!(held_s <= drain_max_s + 1, "the drain is bounded");
        }
        assert!(held_s >= drain_max_s, "not before its bound: {held_s} s");
        assert!(matches!(
            c.take_drain_event(),
            Some(DrainEvent::Left { why: "timeout", .. })
        ));

        one_second(&mut c, |c| three_g(c, 293, 250), fresh(4_000, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(4_100, 0.0, 0));
        assert!(c.draining(), "two reports past the line are a stall again");
        let _ = c.take_drain_event();
        one_second(&mut c, draining_tick, fresh(600, 0.0, 0));
        assert!(
            !c.draining(),
            "600 ms is under the band: the backlog is gone"
        );
        assert!(matches!(
            c.take_drain_event(),
            Some(DrainEvent::Left { why: "report", .. })
        ));
    }

    /// A 1080 pin on the safe profile: honoured above its 720p30 top on the safe pinned cadences
    /// (30, 15, 8), holding the height under congestion down to the pinned floor.
    #[test]
    fn safe_honours_a_1080_pin_at_its_cadences_and_sheds_frame_rate() {
        let mut c = on_safe();
        let pinned = c.set_pinned_height(Some(1080)).expect("a change");
        assert_eq!((pinned.max_h, pinned.fps), (1080, 30), "opens at 1080p30");
        let ticks = |secs: f32| (secs / TICK.as_secs_f32()).ceil() as u32;
        let mut seen = vec![c.current()];
        for _ in 0..ticks(120.0) {
            let fb = congested(c.current().fps as f32);
            if let Some(r) = c.tick(fb, TICK) {
                seen.push(r);
            }
        }
        assert!(
            seen.iter().all(|r| r.max_h == 1080),
            "the pin holds the height: {seen:?}"
        );
        let cadences: Vec<u32> = seen.iter().map(|r| r.fps).collect();
        assert_eq!(cadences, vec![30, 15, 8], "frame rate is what gives way");
    }

    /// Walk the ladder down to a given height with a link that cannot carry it. Bounded, so a
    /// controller that stops descending fails rather than hangs.
    fn descend_to(c: &mut QualityController, max_h: u32) {
        for _ in 0..10_000 {
            if c.current().max_h <= max_h {
                return;
            }
            let fb = congested(c.current().fps as f32);
            c.tick(fb, TICK);
        }
        panic!("the ladder never reached {max_h}p");
    }

    /// The oscillation a content-blind climb gate produces on a game, and the term that closes it.
    ///
    /// 1080p30 `Balanced` on this source prices at 1220 kbps, about a third of what a game needs,
    /// so a 1.9 Mbps estimate opens a rung the content cannot live at: climb, `coarse` sheds it two
    /// seconds later, re-open four seconds after that, an IDR each turn. The quantiser is the only
    /// content measurement here. Both halves are asserted: a gate that never climbs would pass the
    /// first alone.
    #[test]
    fn a_rung_with_no_quality_headroom_does_not_climb_on_price_alone() {
        // Same link, same queue, same spend. The *only* difference between the two runs is what
        // the encoder says it is costing to code this content at the rung it is on.
        let game = |c: &QualityController, qp: f32| Feedback {
            // 1.6x the 1080p30 price, which clears `UP_HEADROOM` comfortably.
            estimate_kbps: 1_953,
            drain_kbps: 1_953,
            produced_kbps: 1_900,
            egress_kbps: 1_900,
            qp_samples: 30,
            queue_age_ms: 0,
            avg_qp: Some(qp),
            encode_ms: 4.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        descend_to(&mut c, 900);
        let at = c.current();
        run(&mut c, |c| game(c, 38.0), UP_AFTER.as_secs_f32() * 3.0);
        assert_eq!(
            c.current(),
            at,
            "a rung already needing QP 38 has no room to give the rung above, and climbing into it \
             costs a keyframe each way for a result that is already known"
        );

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        descend_to(&mut c, 900);
        let at = c.current();
        run(&mut c, |c| game(c, 26.0), UP_AFTER.as_secs_f32() * 3.0);
        assert!(
            c.current().max_h > at.max_h,
            "the same link with quality to spare must still climb — otherwise the assertion above \
             is satisfied by a ladder that never moves"
        );
    }

    /// A climb must be priced from what the content costs, not only from the table.
    ///
    /// Recorded: 720p producing 3100 kbps at QP 26-30, estimate 4083, queue empty. The table priced
    /// 1080p@60 at about 1727 and the ladder jumped there, where the content costs roughly
    /// `3100 x 2.25 pixels x 1.41 cadence` ≈ 9.9 Mbps; it then walked back down through two more
    /// keyframes. `has_headroom` only says the current rung is comfortable.
    ///
    /// Asserted on the first move only, since the fixture holds production constant across rungs.
    /// The still screen is covered by `a_still_screen_does_not_move_the_ladder`, healthy climbing
    /// by `a_recovered_link_climbs_all_the_way_back`.
    #[test]
    fn a_climb_is_priced_from_what_the_content_costs_when_the_encoder_is_spending() {
        let video = |c: &QualityController, estimate_kbps: u32, drain_kbps: u32| Feedback {
            estimate_kbps,
            drain_kbps,
            produced_kbps: 3_100,
            egress_kbps: 3_200,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(27.0),
            encode_ms: 3.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };

        // The first rung the ladder moves to from 720p on this evidence, or `None` if it never
        // moves. Bounded well past `UP_AFTER + SETTLE_AFTER_MOVE`.
        let first_move = |estimate_kbps, drain_kbps| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            descend_to(&mut c, 720);
            for _ in 0..300 {
                let fb = video(&c, estimate_kbps, drain_kbps);
                if let Some(moved) = c.tick(fb, TICK) {
                    return Some(moved);
                }
            }
            None
        };

        let thin = first_move(4_083, 4_491).expect("the ladder never moved at all");
        assert_ne!(
            thin, LADDER[0],
            "climbed straight from 720p to 1080p@60 on an estimate of 4083 for content measured \
             at 3100 kbps two and a quarter times smaller — the jump that cost 77 kB of IDR, \
             QP 44, and two rungs back down"
        );

        // The identical fixture on a link that genuinely covers the content at the top rung.
        assert_eq!(
            first_move(12_000, 13_000),
            Some(LADDER[0]),
            "the same content on a 12 Mbps link must still reach the top — otherwise the \
             assertion above is satisfied by a ladder that has stopped climbing"
        );
    }

    /// `starved` is a cadence escape hatch, and applying it to pixels is a step down in disguise.
    ///
    /// The deadlock it breaks is a capped frame rate capping production and so the estimate; only
    /// more frames produce new evidence. At 900p30 with the quantiser pinned and the budget spent,
    /// a pixel climb produces no new evidence and spreads the same bits over 1.4x the pixels.
    ///
    /// A saturated quantiser is above [`QP_DOWN`], so normally `coarse` descends first; `starved`
    /// decides only while `coarse` is short of [`QP_MIN_SAMPLES`] or at the last rung. This fixture
    /// is the first case (one quantiser sample per tick). Without the cadence restriction the
    /// ladder climbs to 1080p on a link that covers 898 kbps for a rung needing 1525.
    #[test]
    fn a_saturated_quantiser_does_not_buy_a_pixel_climb() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        descend_to(&mut c, 900);
        let at = c.current();
        run(
            &mut c,
            |c| Feedback {
                // Just over what this rung itself is worth (816 kbps), and far under the 1525 the
                // rung above needs — so `affordable` cannot fire and only `starved` is in play.
                estimate_kbps: 898,
                drain_kbps: 898,
                produced_kbps: 880,
                egress_kbps: 880,
                qp_samples: 1,
                queue_age_ms: 0,
                avg_qp: Some(46.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            },
            UP_AFTER.as_secs_f32() * 2.0,
        );
        assert_eq!(
            c.current(),
            at,
            "a saturated quantiser at a full frame rate is not a reason to add pixels"
        );
    }

    #[test]
    fn one_disagreeing_sample_does_not_reset_the_evidence() {
        // Requiring every sample in a window to agree is unsound: as the sampling rate rises,
        // unanimity becomes improbable.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        // Long enough for the smoothed queue to rise from cold: the exponential mean has a 1.6 s
        // time constant and the dwell then needs two more seconds on top.
        let ticks = (DOWN_AFTER.as_secs_f32() * 5.0 / TICK.as_secs_f32()).ceil() as u32;
        for n in 1..=ticks {
            let fps = c.current().fps as f32;
            let fb = if n % 4 == 0 {
                healthy(fps)
            } else {
                congested(fps)
            };
            c.tick(fb, TICK);
        }
        assert_ne!(
            c.current(),
            start,
            "three quarters agreement must still decide"
        );
    }

    #[test]
    fn the_ladder_never_walks_off_either_end() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        run(&mut c, |c| congested(c.current().fps as f32), 600.0);
        assert_eq!(c.current(), LADDER[LADDER.len() - 1]);
        run(&mut c, |c| healthy(c.current().fps as f32), 600.0);
        assert_eq!(c.current(), LADDER[0]);
    }

    #[test]
    fn a_backend_with_no_quantiser_still_adapts() {
        // A hardware encoder may not report QP. The ladder must not go blind — the queue and the
        // encode time are still measured, and they are enough.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let start = c.current();
        run(
            &mut c,
            |c| Feedback {
                avg_qp: None,
                ..congested(c.current().fps as f32)
            },
            // The queue's mean has a five-second time constant, so the evidence takes that long to
            // build before the dwell counts.
            DOWN_AFTER.as_secs_f32() * 5.0,
        );
        assert!(
            c.current().max_h < start.max_h,
            "queue alone must be able to move the ladder"
        );
    }

    // ── the budget ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_session_opens_at_the_rungs_price_and_not_at_the_floor() {
        // With no estimate yet the budget would be the absolute floor, 120 kbps, about 500 bytes a
        // 1080p frame: the quantiser pinned and descent evidence banked before any measurement.
        let c = QualityController::new(1620, 1080, Quality::Balanced);
        let opening = c.encoder_target_kbps();
        assert!(
            opening > ABSOLUTE_FLOOR_KBPS * 4,
            "an unmeasured link must not open at the floor: {opening} kbps"
        );
        assert_eq!(
            opening,
            c.current_required_kbps(),
            "it opens at what the rung is worth"
        );
    }

    #[test]
    fn the_budget_follows_the_estimate_and_is_never_floored_at_the_rung() {
        // A budget floored at the rung's price puts production within the SPEND_PCT margin of the
        // drain rate at equilibrium, erasing the margin that keeps the operating point off the
        // cliff.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let rung_price = c.current_required_kbps();
        let thin = rung_price / 4;
        run(
            &mut c,
            |c| Feedback {
                estimate_kbps: thin,
                drain_kbps: thin,
                ..healthy(c.current().fps as f32)
            },
            1.0,
        );
        let budget = c.encoder_target_kbps();
        assert!(
            budget < rung_price,
            "budget {budget} must be allowed below the rung's {rung_price}"
        );
        assert!(budget <= thin, "and must never exceed the measured {thin}");
        assert!(budget >= ABSOLUTE_FLOOR_KBPS);
    }

    #[test]
    fn the_budget_cannot_over_commit_after_a_still_moment() {
        // Replayed: the screen went still for a second, then motion resumed:
        //
        //     prod=5271  est=8036  egress=5272  age=0    flight=0
        //     prod= 182  bud=4268  egress= 273  age=0    flight=0
        //     prod=3460  bud=3841  egress= 946  age=226  flight=367446
        //
        // A budget floored at a decaying egress peak read 3841 while the estimate had fallen to
        // 1722; the link took 946 kbps and 367 kB (three seconds of latency) queued within a
        // second.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);

        // A fat link, filled.
        run(
            &mut c,
            |c| Feedback {
                estimate_kbps: 8_000,
                egress_kbps: 5_300,
                produced_kbps: 5_200,
                ..healthy(c.current().fps as f32)
            },
            4.0,
        );
        assert!(
            c.encoder_target_kbps() > 4_000,
            "a demonstrated 5.3 Mbps must be spent: {}",
            c.encoder_target_kbps()
        );

        // One still second: almost nothing produced, so almost nothing leaves. The estimate falls
        // because it is bounded by what was acknowledged.
        run(
            &mut c,
            |c| Feedback {
                estimate_kbps: 2_137,
                egress_kbps: 273,
                produced_kbps: 182,
                ..healthy(c.current().fps as f32)
            },
            1.0,
        );
        let after_idle = c.encoder_target_kbps();

        // A still second empties the egress ring in five ticks while `spend_smoothed` (1.6 s) still
        // says we are trying, so the exploration bound alone would describe a screen at rest:
        // recorded at 900p, the budget read 1912 with the estimate at 5893, and the next scroll put
        // 293 kB in flight and cost two rungs. The floor of the bound is what the link was last
        // seen to carry. See [`Self::unpushed_kbps`].
        assert!(
            after_idle > 4_000,
            "one still second is not a measurement of the link, and the 5.3 Mbps it carried a \
             second earlier is: {after_idle}"
        );

        // Bounded by the estimate recorded while the link agreed with it, less [`SPEND_PCT`],
        // decaying on [`INFORMATIVE_HALF_LIFE`], not by a peak of egress.
        let ceiling =
            u32::try_from(u64::from(c.informative_kbps) * SPEND_PCT / 100).unwrap_or(u32::MAX);
        assert!(
            after_idle <= ceiling,
            "the budget {after_idle} is above the {ceiling} the last loaded measurement supports \
             — that is a peak again, with a slower name"
        );
        assert!(
            after_idle > ABSOLUTE_FLOOR_KBPS,
            "and it must not collapse to the floor either: {after_idle}"
        );

        // The correction a peak never has: the link really narrowed, egress reaches the reduced
        // capacity, and after [`LOADED_CONFIRM`] in the band the floor follows it down (see
        // [`Self::informative_kbps`]).
        run(
            &mut c,
            |c| Feedback {
                estimate_kbps: 2_137,
                egress_kbps: 2_000,
                produced_kbps: 1_950,
                ..healthy(c.current().fps as f32)
            },
            3.0,
        );
        let corrected = c.encoder_target_kbps();
        assert!(
            corrected <= 2_137,
            "sending is what corrects this, and after three seconds of it the budget still reads \
             {corrected} on a link measured at 2137"
        );
    }

    /// A pause must not cost the link, and the link narrowing during one must still be believed.
    ///
    /// str0m's delay estimate is bounded by acked traffic, so a still screen talks it down to the
    /// padding rate within seconds. Recorded on a link that carried 15 Mbps throughout:
    ///
    /// ```text
    /// 21:36:07  900p, estimate 5298, video playing
    /// 21:36:09  the screen goes still, 1 fps offered
    /// 21:36:16  estimate 661
    /// 21:36:17  motion resumes: budget 328-725 on 1080p@60, QP 46, dropper 0.96, queue 100-330 ms
    /// 21:36:23  -> 1080p@30     21:36:28  -> 900p     21:36:34  -> 720p
    /// ```
    ///
    /// Both halves are asserted: believing a stale measurement unconditionally is the 367 kB
    /// failure in `the_budget_cannot_over_commit_after_a_still_moment`.
    #[test]
    fn motion_after_a_pause_is_served_at_the_estimate_measured_under_load() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);

        // Six seconds of real load: 4500 of 5000 kbps, 90%, above str0m's 65% ALR line.
        for _ in 0..30 {
            let fb = Feedback {
                estimate_kbps: 5_000,
                drain_kbps: 5_500,
                produced_kbps: 4_400,
                egress_kbps: 4_500,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(28.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        let loaded = c.encoder_target_kbps();
        assert!(
            loaded >= 4_000,
            "a link carrying 4.5 Mbps must be spent: {loaded}"
        );

        // Eight seconds of still screen. Nothing is produced, so nothing leaves, so the estimate
        // decays — 5000 to 700, which is what the session recorded over a comparable pause.
        for i in 0..40u32 {
            let fb = Feedback {
                estimate_kbps: 5_000 - (5_000 - 700) * i / 39,
                drain_kbps: 770,
                produced_kbps: 10,
                egress_kbps: 50,
                qp_samples: 1,
                queue_age_ms: 0,
                avg_qp: Some(18.0),
                encode_ms: 1.0,
                spend_ratio: 0.01,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }

        // The first frame of motion, served before any of it has been acknowledged.
        c.tick(
            Feedback {
                estimate_kbps: 700,
                drain_kbps: 770,
                produced_kbps: 3_000,
                egress_kbps: 60,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(30.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            },
            TICK,
        );
        let resumed = c.encoder_target_kbps();
        // 5000 measured under load, decayed over 8.2 s at a 20 s half-life (0.752), less 10%: 3383
        // kbps. The collapsed estimate alone would give 630, the budget that cost three rungs.
        assert!(
            resumed >= 3_300,
            "motion after a pause was served at {resumed} kbps on a link last measured at 5000 \
             while it was actually carrying traffic"
        );

        // 4000 kbps leaving against an estimate climbing from 700 at about 10% a second (str0m's
        // AIMD recovery rate as logged). Egress above 1.1x the estimate means the estimate is
        // behind the traffic: none of these ticks is a measurement, and QP 44 is not read as one
        // either.
        let mut rising = 700_u32;
        let mut floor_held = u32::MAX;
        let start = c.current();
        for _ in 0..8 {
            rising = rising * 11 / 10;
            let fb = Feedback {
                estimate_kbps: rising,
                drain_kbps: rising * 11 / 10,
                produced_kbps: 3_500,
                egress_kbps: 4_000,
                qp_samples: 12,
                queue_age_ms: 0,
                avg_qp: Some(44.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
            floor_held = floor_held.min(c.encoder_target_kbps());
        }
        // Decay from the resume tick's 3746 reaches 3186 at worst over these ticks; what must not
        // happen is a fall to the estimate's 0.9x (630 rising to 1347).
        assert!(
            floor_held >= 3_100,
            "the floor fell to {floor_held} while the estimate was still catching up; egress of \
             4000 against an estimate of 700 is the estimate lagging, not a measurement"
        );
        assert_eq!(
            c.current(),
            start,
            "shed a rung on QP 44 against a budget the link had not confirmed — that is the \
             quantiser measuring my own arithmetic, not the network"
        );

        // The converse, and why this is not a remembered peak: the link really did narrow, egress
        // now reaches the reduced capacity, and the belief follows it down.
        //
        // Sixteen ticks: four flush the 4000 kbps out of the egress ring (`loaded`'s upper edge
        // reads the whole second), ten are [`LOADED_CONFIRM`]. Pushback, the frame dropper and the
        // queue guard cover over-commitment meanwhile.
        for _ in 0..16 {
            let fb = Feedback {
                estimate_kbps: 1_200,
                drain_kbps: 1_320,
                produced_kbps: 1_150,
                egress_kbps: 1_100,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(34.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        let narrowed = c.encoder_target_kbps();
        let allowed = (f64::from(1_200_u32) * 0.9 * 1.05) as u32;
        assert!(
            narrowed <= allowed,
            "the link narrowed to 1200 kbps while we were idle and the budget still reads \
             {narrowed}, against the {allowed} the new estimate allows"
        );
    }

    /// A band is something a falling quantity passes through, and one window inside it is a
    /// coincidence rather than a measurement.
    ///
    /// Both halves were recorded, each erasing the informative floor when it was needed:
    ///
    /// ```text
    /// 22:34:10  the previous second carried ~10 Mbps, the estimate had collapsed to 3072, and one
    ///           200 ms tick of egress landed inside [65%, 110%] of 3072 on its way down.
    ///           `informative_kbps := 3072`, and the floor was gone.
    /// 22:35:04  estimate 1186, and the first resume packets measured 1224 — 103% of it. Nothing
    ///           had been re-measured; the estimate was simply small enough that one burst of
    ///           catch-up traffic looked like agreement.
    /// ```
    #[test]
    fn a_sweep_through_the_band_does_not_count_as_the_link_agreeing() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);

        // Six seconds of genuine load: 11500 against 17000 is 68%, past str0m's 65% ALR line.
        for _ in 0..30 {
            let fb = Feedback {
                estimate_kbps: 17_000,
                drain_kbps: 18_700,
                produced_kbps: 11_000,
                egress_kbps: 11_500,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(26.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        assert_eq!(
            c.informative_kbps, 17_000,
            "a link carrying 11.5 Mbps against a 17 Mbps estimate is the estimate being confirmed"
        );

        // The screen goes still while the estimate collapses. The third tick, 2500 against 3072, is
        // 81%: inside both edges of a per-tick band.
        for egress_kbps in [8_000, 4_000, 2_500, 800, 50] {
            let fb = Feedback {
                estimate_kbps: 3_072,
                drain_kbps: 3_379,
                produced_kbps: egress_kbps,
                egress_kbps,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(30.0),
                encode_ms: 4.0,
                spend_ratio: 0.5,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        assert!(
            c.informative_kbps > 12_000,
            "the floor fell to {} on a screen going still; one second of the traffic behind that \
             tick was eight to eleven megabits, which is the estimate lagging and not the link \
             answering. Only the half-life may lower this.",
            c.informative_kbps
        );

        // 22:35:04: motion resumes and the first packets run above the collapsed estimate. Sending
        // three times the estimate and getting it through is not the estimate being confirmed.
        for egress_kbps in [1_224, 3_000, 4_000] {
            let fb = Feedback {
                estimate_kbps: 1_186,
                drain_kbps: 1_305,
                produced_kbps: 3_500,
                egress_kbps,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(44.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        assert!(
            c.informative_kbps > 12_000,
            "the floor fell to {} on the first resume tick, where 1224 kbps against an estimate \
             of 1186 is 103% — arithmetic agreement between two numbers that have not met",
            c.informative_kbps
        );
    }

    /// And a band is also something a transition lands in, which the window alone cannot see.
    ///
    /// Once the estimate has collapsed and the ring has flushed, the two rates can sit in the band
    /// for a window or two on the way elsewhere. Recorded: the link had carried 12712 kbps ten
    /// seconds earlier, the estimate was 4752, and three windows of 4544, 4144 and 4435 set the
    /// floor to 4752; the re-anchor two seconds later went out at its decayed 4367. See
    /// [`LOADED_CONFIRM`].
    #[test]
    fn a_transition_that_lands_in_the_band_is_not_the_link_agreeing_either() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);

        // Six seconds of the real thing: 11000 against 12712 is 86.5%, inside both edges and
        // sustained, which is what the link agreeing with the estimate looks like.
        for _ in 0..30 {
            let fb = Feedback {
                estimate_kbps: 12_712,
                drain_kbps: 13_983,
                produced_kbps: 10_800,
                egress_kbps: 11_000,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(26.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
        }
        assert_eq!(
            c.informative_kbps, 12_712,
            "measured, and set on the first tick"
        );

        // Three seconds of the transition: the first four ticks are outside the band (the ring
        // still holds the previous second's 11 Mbps), the next ten inside.
        let mut seen: Vec<(Duration, u32)> = Vec::new();
        for i in 0..15 {
            let egress_kbps = [4_544, 4_144, 4_435][i % 3];
            let fb = Feedback {
                estimate_kbps: 4_752,
                drain_kbps: 5_227,
                produced_kbps: egress_kbps,
                egress_kbps,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(32.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
            c.tick(fb, TICK);
            seen.push((c.loaded_streak, c.informative_kbps));
        }

        let (_, after_nine) = seen
            .iter()
            .find(|(streak, _)| *streak == LOADED_CONFIRM - TICK)
            .copied()
            .expect("nine consecutive in-band ticks must occur inside three seconds");
        assert!(
            after_nine > 9_000,
            "nine in-band windows lowered the floor to {after_nine}; the link carried 12.7 Mbps \
             ten seconds ago and 1.8 s inside the band of a collapsing estimate is a transition"
        );

        let (_, after_ten) = seen
            .iter()
            .find(|(streak, _)| *streak == LOADED_CONFIRM)
            .copied()
            .expect("and the tenth must too");
        assert_eq!(
            after_ten, 4_752,
            "two seconds of uninterrupted agreement is a measurement, and the floor must follow \
             the link down as readily as up"
        );
    }

    /// One second of a still screen is not the link narrowing, and the budget must survive it.
    ///
    /// Scroll, stop, read, scroll: the egress ring is one second long and `spend_smoothed` has a
    /// 1.6 s time constant, so in between `trying` is still true while the ring describes a screen
    /// at rest. Recorded:
    ///
    /// ```text
    /// 07:17:09  900p video, est 5893, spend 1.0
    /// 07:17:10  the screen stops (produced 82); the budget reads 1912, est still 5893
    /// 07:17:11  a sharp scroll is served at 1912: 293 kB in flight, queue 315 ms -> 1031 ms,
    ///           the transport's hard limit, a discard, a PLI, and 900p -> 720p -> 540p
    /// ```
    ///
    /// The re-anchor does not and must not cover this: it wants [`REANCHOR_AFTER_PAUSE`] of
    /// application-limited sending.
    #[test]
    fn a_one_second_pause_does_not_collapse_the_budget() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let loaded = |c: &QualityController| Feedback {
            estimate_kbps: 5_893,
            drain_kbps: 6_482,
            produced_kbps: 5_200,
            egress_kbps: 5_300,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(28.0),
            encode_ms: 4.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };

        // Six seconds of 900p video on a link that is carrying it: 5300 against 5893 is 90%.
        for _ in 0..30 {
            let fb = loaded(&c);
            c.tick(fb, TICK);
        }
        assert_eq!(c.informative_kbps, 5_893);

        // The screen stops. Five ticks empty the ring; the estimate has not moved, because nothing
        // has happened to the link.
        for tick in 1..=5 {
            let fb = Feedback {
                produced_kbps: 82,
                egress_kbps: 60,
                spend_ratio: 0.02,
                qp_samples: 1,
                avg_qp: Some(18.0),
                encode_ms: 1.0,
                ..loaded(&c)
            };
            c.tick(fb, TICK);
            let budget = c.encoder_target_kbps();
            assert!(
                budget >= 4_000,
                "tick {tick} of a one-second pause took the budget to {budget} on an estimate of \
                 5893 that never moved; the session recorded 1912 and the scroll that followed \
                 cost two rungs"
            );
        }

        // And the scroll itself, served on the tick it arrives rather than a second later.
        let fb = Feedback {
            produced_kbps: 4_000,
            egress_kbps: 3_000,
            spend_ratio: 1.0,
            ..loaded(&c)
        };
        c.tick(fb, TICK);
        let budget = c.encoder_target_kbps();
        assert!(
            budget >= 4_000,
            "the scroll after the pause was handed {budget} on a link measured at 5893 one second \
             earlier"
        );
    }

    // ── re-anchoring the estimate ─────────────────────────────────────────────────────────────

    /// A link being used: 4500 kbps leaving against a 5000 estimate, which `loaded` records.
    fn under_load(c: &QualityController) -> Feedback {
        Feedback {
            estimate_kbps: 5_000,
            drain_kbps: 5_500,
            produced_kbps: 4_400,
            egress_kbps: 4_500,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(28.0),
            encode_ms: 4.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// A still screen: the encoder spends a hundredth of its allowance and the estimate decays
    /// towards the padding rate, which is what str0m does when nothing is being acknowledged.
    fn gone_still(c: &QualityController, estimate_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: 10,
            egress_kbps: 50,
            qp_samples: 1,
            queue_age_ms: 0,
            avg_qp: Some(18.0),
            encode_ms: 1.0,
            spend_ratio: 0.01,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// The first tick of motion after a pause: the encoder spends against the informative floor,
    /// and the collapsed estimate has not moved yet.
    fn motion_resumes(c: &QualityController) -> Feedback {
        Feedback {
            estimate_kbps: 700,
            drain_kbps: 770,
            produced_kbps: 4_000,
            egress_kbps: 800,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(40.0),
            encode_ms: 4.0,
            spend_ratio: 0.9,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// Six seconds of load, then eight of a still screen with the estimate decaying 5000 -> 700.
    fn load_then_pause(c: &mut QualityController) {
        for _ in 0..30 {
            let fb = under_load(c);
            c.tick(fb, TICK);
        }
        for i in 0..40u32 {
            let fb = gone_still(c, 5_000 - (5_000 - 700) * i / 39);
            c.tick(fb, TICK);
        }
    }

    /// The floor is unspendable until the estimate is moved, so the resume has to move it.
    ///
    /// The pacer drains at `estimate * 1.1` (see [`QualityController::take_bwe_reanchor`]), so a
    /// budget above the estimate queues inside str0m and reads as overuse. Recorded: budget 5430
    /// from the floor, 46 kB in flight, and two seconds later an estimate of 59 kbps.
    #[test]
    fn motion_after_a_pause_re_anchors_the_estimate_once() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        load_then_pause(&mut c);
        assert_eq!(
            c.take_bwe_reanchor(),
            None,
            "a pause on its own is not a reason to disturb congestion control"
        );

        let fb = motion_resumes(&c);
        c.tick(fb, TICK);
        let anchor = c
            .take_bwe_reanchor()
            .expect("the first motion after a pause must re-anchor the estimate it is served on");
        assert!(
            (3_500..=5_000).contains(&anchor),
            "re-anchored at {anchor} kbps; the link measured 5000 under load and the half-life has \
             had 8.2 s to work on it"
        );

        let fb = motion_resumes(&c);
        c.tick(fb, TICK);
        assert_eq!(
            c.take_bwe_reanchor(),
            None,
            "a reset discards every measurement str0m holds; one per resume, not one per tick"
        );
    }

    /// A link that is being used continuously has nothing stale to replace.
    #[test]
    fn a_healthy_link_is_never_re_anchored() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for tick in 1..=100 {
            let fb = under_load(&c);
            c.tick(fb, TICK);
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "tick {tick}: the estimate is being confirmed under load every 200 ms, and a \
                 reset would throw that measurement away to start guessing again"
            );
        }
    }

    /// And a pause that nobody has come back from is not a resume: re-anchoring during the quiet
    /// period would fire str0m's 3x and 6x probes of a multi-megabit init, repeatedly, down a link
    /// nobody is using (cellular data, on a phone).
    #[test]
    fn an_idle_link_is_not_re_anchored_until_motion_returns() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..30 {
            let fb = under_load(&c);
            c.tick(fb, TICK);
            assert_eq!(c.take_bwe_reanchor(), None);
        }
        for i in 0..40u32 {
            let fb = gone_still(&c, 5_000 - (5_000 - 700) * i / 39);
            c.tick(fb, TICK);
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "padding a link the user is not using is the cost this timing exists to avoid"
            );
        }
    }

    /// Two resumes inside [`REANCHOR_EVERY`] buy one reset. The second pause is 2.2 s because a
    /// shorter stop is not a pause at all ([`REANCHOR_AFTER_PAUSE`]), and the middle assertion
    /// would then pass without the spacing being consulted.
    #[test]
    fn re_anchoring_is_rate_limited_and_then_available_again() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        load_then_pause(&mut c);
        let fb = motion_resumes(&c);
        c.tick(fb, TICK);
        assert!(c.take_bwe_reanchor().is_some(), "the first resume");

        // Eleven still ticks — a genuine pause of 2.2 s — and motion: the second resume is 2.4 s
        // after the first, and its whole resume window closes (at 4.4 s) inside the spacing.
        for _ in 0..11 {
            let fb = gone_still(&c, 700);
            c.tick(fb, TICK);
        }
        for tick in 1..=11 {
            let fb = motion_resumes(&c);
            c.tick(fb, TICK);
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "tick {tick} of the second resume; a reset costs a probe cluster at 3x and 6x of \
                 the init and must not be fired twice inside the ramp that follows the first"
            );
        }

        // And past five seconds from the one that fired, it is available again — this is a
        // spacing, not a one-shot.
        for _ in 0..15 {
            let fb = gone_still(&c, 700);
            c.tick(fb, TICK);
        }
        let fb = motion_resumes(&c);
        c.tick(fb, TICK);
        assert!(
            c.take_bwe_reanchor().is_some(),
            "a third genuine pause, well past the spacing, must still be served"
        );
    }

    /// A collapse under load that the receiver calls clean is str0m's artifact, and is re-anchored.
    ///
    /// From the sender this looks like a 3G failure; the receiver tells them apart in the same
    /// second. Recorded on relayed Wi-Fi, baseline ~136:
    ///
    /// ```text
    /// 07:14:38  est 4752  egress 4544  rtt 140  loss 0
    /// 07:14:40  est 4752  egress 4435  rtt 143  loss 0.17%  2 NACKs
    /// 07:14:41  est  735  egress 2468  rtt 146  loss 0.10%  2 NACKs   queue 669 ms
    /// 07:14:42  re-anchored (old rule); 07:14:46 a probe measured 14519
    /// ```
    ///
    /// The 3G link's harmful re-anchors all came with the round trip 35-65% over its baseline or
    /// double-digit loss; see `a_collapse_the_receiver_calls_congested_is_never_re_anchored`.
    #[test]
    fn a_collapse_under_load_the_receiver_calls_clean_is_re_anchored() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let at =
            |c: &QualityController, estimate_kbps: u32, egress_kbps: u32, queue: u32| Feedback {
                estimate_kbps,
                drain_kbps: estimate_kbps * 11 / 10,
                produced_kbps: egress_kbps,
                egress_kbps,
                qp_samples: 6,
                queue_age_ms: queue,
                avg_qp: Some(30.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
        // 07:14:36-40: 1080p60 video on a relay, the receiver reporting the path at its baseline
        // with the relay's ordinary tenths of a percent.
        for (rtt, loss, nacks) in [(137, 0.0, 0), (139, 0.0, 0), (140, 0.0, 0), (141, 0.0, 0)] {
            one_second(&mut c, |c| at(c, 4_752, 4_400, 0), fresh(rtt, loss, nacks));
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "a healthy estimate is left alone"
            );
        }
        one_second(&mut c, |c| at(c, 4_752, 4_435, 0), fresh(143, 0.17, 2));
        assert_eq!(c.take_bwe_reanchor(), None);
        assert_eq!(c.collapse_state(), "-");

        // 07:14:41: the collapse, with the report that describes it.
        let mut fired = None;
        for tick in 0..5 {
            let fb = Feedback {
                produced_kbps: 2_962,
                report: if tick == 0 { fresh(146, 0.10, 2) } else { None },
                ..at(&c, 735, 2_468, 669)
            };
            c.tick(fb, TICK);
            if let Some(kbps) = c.take_bwe_reanchor() {
                fired = Some((tick, kbps));
                break;
            }
        }
        let (tick, kbps) = fired.expect(
            "a collapse to 735 with the round trip at its baseline and 0.10% NACK-recovered loss \
             is the estimator, not the path",
        );
        assert_eq!(tick, 0, "promptly: on the tick the collapse is seen");
        assert!(
            (4_500..=4_752).contains(&kbps),
            "re-anchored at {kbps}; the path carried 4752 a second ago"
        );
        let r = c.last_reanchor().expect("the details are kept for the log");
        assert_eq!(r.trigger, ReanchorTrigger::CleanCollapse);
        assert_eq!(
            (r.estimate_kbps, r.rtt_ms, r.rtt_base_ms),
            (735, Some(146), Some(137))
        );
        assert_eq!(c.collapse_state(), "clean");
    }

    /// The clean margin, on every baseline the recordings contain. See [`CLEAN_RTT_MARGIN_MS`].
    #[test]
    fn the_clean_margin_passes_each_paths_jitter_and_no_queue() {
        let cases = [
            // (baseline, ordinary worst, the queue that must not pass)
            (136, 165, 187), // Wi-Fi relay: 187 on a 1080p60 keyframe
            (128, 141, 192), // Wi-Fi relay: its isolated spikes, 192-303
            (210, 271, 283), // 3G: just before 16.6% loss
            (373, 397, 471), // LTE: 471 and 474, then 1.35% loss
            (551, 614, 639), // 3G after its bloat cleared
        ];
        let c = QualityController::new(1920, 1080, Quality::Balanced);
        for (base, ordinary, queue) in cases {
            let line = c.rtt_clean_up_to(base);
            assert!(
                ordinary <= line && queue > line,
                "base {base}: the line at {line} must pass {ordinary} and refuse {queue}"
            );
        }
        assert_eq!(c.rtt_clean_up_to(2), 42, "a LAN still gets 40 ms");
    }

    /// The same collapse with a queue at the far end is congestion control answering, and is not
    /// overridden while the receiver says so.
    ///
    /// Recorded on LTE, baseline 373: estimate 4790 at 1080p60, then 1024 with the round trip at
    /// 534 (+43%) once, and 394 the second after. Refused for [`CLEAN_RTT_FOR`] after the inflated
    /// report; if the estimate is still collapsed once two seconds of reports come back clean, the
    /// queue has gone and the collapse is served (1771 -> 4464 in the replay).
    #[test]
    fn a_collapse_with_a_queue_at_the_far_end_waits_for_the_receiver() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let lte = |c: &QualityController, estimate_kbps: u32, egress_kbps: u32| Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: 4_200,
            egress_kbps,
            qp_samples: 12,
            queue_age_ms: 0,
            avg_qp: Some(30.0),
            encode_ms: 4.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };
        for rtt in [374, 377, 379, 374, 376] {
            one_second(&mut c, |c| lte(c, 4_790, 4_345), fresh(rtt, 0.0, 0));
        }
        assert_eq!(c.rtt_base_ms(), Some(374));

        // 19:02:23 and the second after: refused, on the receiver's word.
        one_second(&mut c, |c| lte(c, 1_024, 2_946), fresh(534, 0.0, 0));
        assert_eq!(c.take_bwe_reanchor(), None, "534 against 373 is a queue");
        assert_eq!(c.collapse_state(), "rtt");
        one_second(&mut c, |c| lte(c, 1_456, 1_195), fresh(394, 0.0, 0));
        assert_eq!(
            c.take_bwe_reanchor(),
            None,
            "one clean report after a queue is the collapsed pacer draining it, not proof it was \
             never there"
        );

        // 19:02:25: two seconds of clean reports, and the estimate still under half.
        one_second(&mut c, |c| lte(c, 1_771, 1_987), fresh(394, 0.0, 0));
        assert!(
            c.take_bwe_reanchor().is_some(),
            "two clean seconds after the spike, with the estimate still at 1771 against a path \
             that carried 4345: served"
        );
        assert_eq!(
            c.last_reanchor().map(|r| r.trigger),
            Some(ReanchorTrigger::CleanCollapse)
        );
    }

    /// A 3G link that never paused, whose re-anchors should not have happened.
    ///
    /// Two recorded shapes: estimate 736 against an informative 941 with 808 kbps leaving (ratio
    /// 1.28, the estimate breathing); and estimate 426 at ratio 1.96 after one second at 17% of the
    /// informative rate. Both were served into a ~700 kbps link; the first was followed by 16.6%
    /// loss two seconds later.
    #[test]
    fn a_thin_link_that_never_paused_is_never_re_anchored() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let thin =
            |c: &QualityController, estimate_kbps: u32, egress_kbps: u32, spend: f32| Feedback {
                estimate_kbps,
                drain_kbps: estimate_kbps * 11 / 10,
                produced_kbps: egress_kbps * 9 / 10,
                egress_kbps,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(36.0),
                encode_ms: 1.5,
                spend_ratio: spend,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            };
        // Loaded at 941: 800 kbps leaving is 85% of it.
        for _ in 0..25 {
            let fb = thin(&c, 941, 800, 1.0);
            c.tick(fb, TICK);
        }
        let mut phases: Vec<(u32, u32, f32, u32)> = vec![
            (736, 808, 1.27, 15), // 08:11:54-56
            (680, 160, 0.20, 5),  // one stalled second, as at 08:10:59
            (681, 473, 0.98, 5),  // 08:11:57
            (426, 514, 0.66, 10), // 08:11:59: ratio 1.96, and 2.1 against the undecayed floor
        ];
        for (estimate, egress, spend, ticks) in phases.drain(..) {
            for tick in 1..=ticks {
                let fb = thin(&c, estimate, egress, spend);
                c.tick(fb, TICK);
                assert_eq!(
                    c.take_bwe_reanchor(),
                    None,
                    "re-anchored a busy thin link at estimate {estimate}, egress {egress}, tick \
                     {tick} — this is the 3G session's failure"
                );
            }
        }
    }

    /// The clamp to the rung's absorbable price must never make a "re-anchor" lower the estimate,
    /// and after it the divergence must still be two to one.
    ///
    /// A Wi-Fi link measured 13000-17000 while the rung could absorb 10306, so re-anchors went out
    /// at 10306, one at 1.19x an estimate of 8690, several just after the estimate read above it.
    #[test]
    fn a_re_anchor_never_lowers_the_estimate_and_the_clamp_does_not_excuse_the_divergence() {
        let first_resume = |estimate_at_resume: u32| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            // 11000 leaving against 16000 is 69%, so 16000 is recorded — above 10306.
            for _ in 0..30 {
                let fb = Feedback {
                    estimate_kbps: 16_000,
                    drain_kbps: 17_600,
                    produced_kbps: 10_500,
                    egress_kbps: 11_000,
                    ..under_load(&c)
                };
                c.tick(fb, TICK);
            }
            for _ in 0..30 {
                let fb = gone_still(&c, estimate_at_resume);
                c.tick(fb, TICK);
            }
            let mut out = None;
            for _ in 0..5 {
                let fb = Feedback {
                    estimate_kbps: estimate_at_resume,
                    drain_kbps: estimate_at_resume * 11 / 10,
                    produced_kbps: 4_916,
                    egress_kbps: 859,
                    ..motion_resumes(&c)
                };
                c.tick(fb, TICK);
                out = out.or(c.take_bwe_reanchor());
            }
            out
        };
        assert_eq!(
            first_resume(15_864),
            None,
            "a reset to 10306 against a live 15864 would lower the estimate"
        );
        assert_eq!(
            first_resume(8_690),
            None,
            "10306 against 8690 is 1.19x after the clamp, inside the estimate's own breathing"
        );
        assert_eq!(
            first_resume(5_000),
            Some(10_306),
            "and 10306 against a collapsed 5000 is the case this exists for"
        );
    }

    /// A pause-resume the recordings show was right must still be served: the link measured ~7200
    /// under load, the screen went still for eight seconds, the estimate fell to 1039, and the
    /// reset restarted it at 5386 (12997 a second later, no rung change). The numbers below are
    /// that stretch's per-second values.
    #[test]
    fn the_pause_resume_the_recordings_show_is_still_re_anchored() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..20 {
            let fb = Feedback {
                estimate_kbps: 7_242,
                drain_kbps: 7_966,
                produced_kbps: 6_300,
                egress_kbps: 6_500,
                ..under_load(&c)
            };
            c.tick(fb, TICK);
        }
        let pause: [(u32, u32, u32); 8] = [
            // (egress, produced, estimate), 07:12:35-42
            (787, 530, 6_694),
            (743, 912, 3_461),
            (762, 520, 2_439),
            (533, 147, 2_455),
            (41, 24, 1_039),
            (143, 24, 1_039),
            (70, 24, 1_039),
            (48, 47, 1_039),
        ];
        for (egress_kbps, produced_kbps, estimate_kbps) in pause {
            for _ in 0..5 {
                let fb = Feedback {
                    estimate_kbps,
                    drain_kbps: estimate_kbps * 11 / 10,
                    produced_kbps,
                    egress_kbps,
                    spend_ratio: 0.08,
                    ..gone_still(&c, estimate_kbps)
                };
                c.tick(fb, TICK);
                assert_eq!(c.take_bwe_reanchor(), None, "not during the pause");
            }
        }
        // 07:12:43: motion, against the collapsed 1039.
        let fb = Feedback {
            estimate_kbps: 1_039,
            drain_kbps: 1_143,
            produced_kbps: 1_794,
            egress_kbps: 61,
            spend_ratio: 1.29,
            ..motion_resumes(&c)
        };
        c.tick(fb, TICK);
        let anchor = c
            .take_bwe_reanchor()
            .expect("07:12:43 was the re-anchor that worked, and it must still fire");
        assert!(
            (4_500..=7_242).contains(&anchor),
            "re-anchored at {anchor}; the recording went out at 5386"
        );
    }

    /// A resume lighter than the pause threshold is still a resume once the collapsed pacer cannot
    /// carry it.
    ///
    /// Recorded: eleven still seconds after ~9 Mbps, then 650-1100 kbps of motion (under
    /// [`APP_LIMITED_PCT`]) against an estimate of 1186, then of 59. Unserved, that was 146-325 ms
    /// of queue, three descents and 42 seconds back to 1080p@60.
    #[test]
    fn a_light_resume_against_a_collapsed_pacer_is_still_a_resume() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..20 {
            let fb = Feedback {
                estimate_kbps: 10_878,
                drain_kbps: 11_966,
                produced_kbps: 7_593,
                egress_kbps: 8_802,
                ..under_load(&c)
            };
            c.tick(fb, TICK);
        }
        for estimate in [
            3_323, 3_323, 3_323, 1_739, 1_739, 1_739, 1_739, 1_186, 1_186, 1_186, 1_186,
        ] {
            for _ in 0..5 {
                let fb = gone_still(&c, estimate);
                c.tick(fb, TICK);
            }
        }
        // 22:35:03-04: light motion the collapsed estimate can still carry. Nothing to fix yet.
        for (produced_kbps, egress_kbps) in [(769, 64), (646, 1_224)] {
            for _ in 0..5 {
                let fb = Feedback {
                    estimate_kbps: 1_186,
                    drain_kbps: 1_305,
                    produced_kbps,
                    egress_kbps,
                    spend_ratio: 0.9,
                    ..motion_resumes(&c)
                };
                c.tick(fb, TICK);
                assert_eq!(
                    c.take_bwe_reanchor(),
                    None,
                    "{produced_kbps} kbps against a pacer draining 1305 is not held back by it"
                );
            }
        }
        // 22:35:05: the estimate is 59 and the same light motion now queues behind it.
        let fb = Feedback {
            estimate_kbps: 59,
            drain_kbps: 120,
            produced_kbps: 1_085,
            egress_kbps: 1_119,
            spend_ratio: 1.08,
            ..motion_resumes(&c)
        };
        c.tick(fb, TICK);
        assert!(
            c.take_bwe_reanchor().is_some(),
            "1085 kbps of motion against a pacer draining 65 is the unspendable budget, after an \
             eleven-second pause"
        );
    }

    /// The collapsed estimate can surface a second after motion resumes, and the resume must
    /// still be recognised: recorded, the pipeline line read the pre-pause 15864 after a second of
    /// 4916 kbps produced, and the collapsed 110 appeared 0.2 s later. See
    /// [`REANCHOR_RESUME_WINDOW`].
    #[test]
    fn a_late_estimate_after_a_resume_still_re_anchors() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        load_then_pause(&mut c);
        // The first second of motion reads a stale, high estimate: nothing to re-anchor against.
        for _ in 0..5 {
            let fb = Feedback {
                estimate_kbps: 15_864,
                drain_kbps: 17_450,
                produced_kbps: 4_916,
                egress_kbps: 859,
                spend_ratio: 0.73,
                ..motion_resumes(&c)
            };
            c.tick(fb, TICK);
            assert_eq!(c.take_bwe_reanchor(), None, "15864 is not collapsed");
        }
        let fb = Feedback {
            estimate_kbps: 110,
            drain_kbps: 121,
            spend_ratio: 0.99,
            ..motion_resumes(&c)
        };
        c.tick(fb, TICK);
        assert!(
            c.take_bwe_reanchor().is_some(),
            "the collapsed estimate arrived a second into motion, inside the resume window"
        );
    }

    /// A one-second stop is not a pause, whatever the estimate does after it: recorded, one still
    /// second, a burst putting 177 kB in flight and 662 ms in the queue, the estimate at 4613 (our
    /// own queue, measured), and an unjustified reset to 10306 at 2.23x.
    #[test]
    fn a_one_second_stop_is_not_a_pause() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..30 {
            let fb = under_load(&c);
            c.tick(fb, TICK);
        }
        for _ in 0..5 {
            let fb = gone_still(&c, 5_000);
            c.tick(fb, TICK);
        }
        for _ in 0..10 {
            let fb = Feedback {
                estimate_kbps: 1_900,
                drain_kbps: 2_090,
                ..motion_resumes(&c)
            };
            c.tick(fb, TICK);
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "a one-second stop is not a pause"
            );
        }
    }

    /// Real loss in the last ten seconds refuses a re-anchor; a relay's NACK-recovered tenths of a
    /// percent do not.
    ///
    /// A recorded relay reported 0.15-1.26% with two or three NACKs every ten to twenty seconds;
    /// the brake rightly ignored them, and a gate on any loss would read each as ten seconds of
    /// "lossy link". The memory is of loss at [`REAL_LOSS`] (a 3G link's 25.6%, 7.0%, 16.6%).
    #[test]
    fn real_loss_refuses_a_re_anchor_and_relay_nacks_do_not() {
        let report_before_resume = |seconds_before: u32, loss_pct: f32, nacks: u32| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            for _ in 0..30 {
                let fb = under_load(&c);
                c.tick(fb, TICK);
            }
            // Twelve still seconds, the estimate collapsing, with one lossy report in them.
            for second in 0..12u32 {
                let hit = 12 - second == seconds_before;
                let report = if hit {
                    fresh(140, loss_pct, nacks)
                } else {
                    fresh(140, 0.0, 0)
                };
                one_second(&mut c, |c| gone_still(c, 5_000 - 360 * second), report);
            }
            let fb = motion_resumes(&c);
            c.tick(fb, TICK);
            c.take_bwe_reanchor()
        };
        assert_eq!(
            report_before_resume(5, 3.0, 6),
            None,
            "3% loss five seconds before the resume: the link is losing packets, and a probe \
             burst is fuel"
        );
        assert!(
            report_before_resume(5, 0.3, 3).is_some(),
            "0.3% with three NACKs is a relay retransmitting, not a link refusing — the brake \
             ignores it and so must this"
        );
        assert!(
            report_before_resume(11, 3.0, 6).is_some(),
            "eleven seconds is outside the transport's own ten-second memory of loss"
        );
    }

    // ── clean collapses ───────────────────────────────────────────────────────────────────────

    /// One second of a recorded Wi-Fi stretch: scrolling text on a TURN relay, baseline 136-140.
    fn wifi(
        c: &QualityController,
        estimate_kbps: u32,
        egress_kbps: u32,
        produced_kbps: u32,
        queue_age_ms: u32,
    ) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps,
            egress_kbps,
            qp_samples: 12,
            queue_age_ms,
            avg_qp: Some(30.0),
            encode_ms: 3.0,
            spend_ratio: 0.9,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// A recorded Wi-Fi stretch: text scrolling in bursts, ALR probes lifting the estimate 1126 ->
    /// 4308 while egress is 80-900, round trip 140-165 on a 140 baseline, one 0.15% loss report.
    /// Then the tick where the estimate is 46 with 340 ms of queue behind it and the receiver at
    /// 136. Returns the value re-anchored on that tick, if any.
    fn wifi_to_the_collapse(c: &mut QualityController) -> Option<u32> {
        let seconds: [(u32, u32, u32, Option<ReceiverReport>); 10] = [
            (1_126, 760, 921, fresh(140, 0.0, 0)),
            (1_185, 895, 544, silent(140)),
            (1_391, 395, 26, fresh(140, 0.0, 0)),
            (2_840, 82, 19, fresh(142, 0.0, 0)),
            (2_840, 94, 14, fresh(165, 0.0, 0)),
            (2_840, 89, 20, silent(165)),
            (2_840, 79, 29, fresh(145, 0.0, 0)),
            (4_308, 918, 432, fresh(146, 0.0, 0)),
            (4_308, 2_352, 2_100, silent(146)),
            (4_308, 2_561, 2_173, fresh(149, 0.15, 2)),
        ];
        for (estimate, egress, produced, report) in seconds {
            one_second(c, |c| wifi(c, estimate, egress, produced, 0), report);
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "nothing to re-anchor at {estimate}"
            );
        }
        let fb = Feedback {
            report: fresh(136, 0.0, 0),
            ..wifi(c, 46, 3_260, 2_696, 340)
        };
        c.tick(fb, TICK);
        c.take_bwe_reanchor()
    }

    /// The collapse a recorded Wi-Fi stretch could not escape, re-anchored on the tick it is seen,
    /// at the capacity the network had just demonstrated.
    ///
    /// 4308 -> 46 with the round trip at its baseline of 136 and no loss: str0m's `0.85 x acked` on
    /// an acked rate that was our own quiet between bursts. Unserved, frames were discarded at the
    /// hard limit and 1080p60 shed two seconds later. The value is the probe's 4308, not the
    /// informative rate, which scrolling text never lifted above 1299.
    #[test]
    fn a_clean_collapse_is_re_anchored_promptly_at_the_capacity_evidence() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let kbps = wifi_to_the_collapse(&mut c)
            .expect("4308 -> 46 on a path the receiver calls clean must be re-anchored at once");
        assert!(
            (4_200..=4_308).contains(&kbps),
            "re-anchored at {kbps}; the probes measured 4308 a second ago"
        );
        assert!(
            c.informative_kbps < kbps / 2,
            "and this is not the informative rate ({}), which never saw the probes",
            c.informative_kbps
        );
        let r = c.last_reanchor().expect("details");
        assert_eq!(r.trigger, ReanchorTrigger::CleanCollapse);
        assert_eq!(r.estimate_kbps, 46);
        assert_eq!((r.rtt_ms, r.rtt_base_ms), (Some(136), Some(136)));
        assert_eq!(c.collapse_state(), "clean");
        assert!(c.capacity_kbps() >= kbps);
        // The collapse's queue (340 ms on this tick) is not left in the ladder's filters, or a hold
        // that recovers would hand it to `queue_late`.
        assert!(c.late_smoothed.abs() < f32::EPSILON, "{}", c.late_smoothed);
        assert!(
            (c.growth_smoothed - 1.0).abs() < f32::EPSILON,
            "{}",
            c.growth_smoothed
        );
    }

    /// While the collapse is held, nothing the collapsed pacer produces sheds the rung, and the
    /// budget is the capacity evidence rather than the collapse; if the estimate never comes back,
    /// the ordinary rules take over when the hold runs out. Recorded without the hold: queue 340
    /// ms, the hard limit, a PLI and a step to 1080p30, every signal of it the pacer at 1.1 x 46.
    #[test]
    fn a_clean_collapse_is_held_without_descent_and_then_released() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        wifi_to_the_collapse(&mut c).expect("re-anchored");
        let start = c.current();
        // Every local arm past its threshold: a second of queue, production seven times egress, the
        // quantiser pinned, the dropper holding most frames, and egress at 1.07x the collapsed
        // estimate, which `loaded` reads as agreement, so `coarse` and `throttled` have a
        // "measured" budget to fire against.
        let collapsed = |c: &QualityController| Feedback {
            avg_qp: Some(46.0),
            drop_ratio: 0.9,
            spend_ratio: 1.0,
            ..wifi(c, 400, 430, 3_200, 1_000)
        };
        let hold_ticks = (CLEAN_COLLAPSE_HOLD.as_millis() / TICK.as_millis()) as u32;
        let mut banked = c.down_dwell;
        for tick in 1..hold_ticks {
            let fb = Feedback {
                report: if tick % 5 == 0 {
                    fresh(140, 0.0, 0)
                } else {
                    None
                },
                ..collapsed(&c)
            };
            assert_eq!(
                c.tick(fb, TICK),
                None,
                "tick {tick} of the hold: shed a rung on the collapsed pacer's own queue"
            );
            assert_eq!(c.collapse_state(), "clean", "tick {tick}");
            assert!(
                c.down_dwell <= banked,
                "tick {tick}: descent evidence banked in a hold, {:?} after {banked:?}",
                c.down_dwell
            );
            banked = c.down_dwell;
            assert!(
                c.encoder_target_kbps() >= 1_500,
                "tick {tick}: the budget is {} — priced from the collapse, not from the 4278 the \
                 reset restored (halved by pushback for the queue, which is still the latency \
                 guard)",
                c.encoder_target_kbps()
            );
        }

        // The estimate never came back: the hold expires and the queue is the ladder's to judge.
        let mut shed = None;
        for tick in 1..=(3 * 5) {
            if let Some(r) = c.tick(collapsed(&c), TICK) {
                shed = Some((tick, r));
                break;
            }
        }
        let (tick, rung) = shed.expect("a collapse the reset did not fix is the link, eventually");
        assert!(rung.fps < start.fps || rung.max_h < start.max_h);
        assert!(
            tick * 200 >= 2_000,
            "after the hold, the ordinary dwell: shed on tick {tick}"
        );
        assert_ne!(c.collapse_state(), "clean");
    }

    /// The hold masks what reads the collapsed pacer and nothing else: the processor and the
    /// receiver still act inside it.
    #[test]
    fn a_held_collapse_still_yields_to_the_processor_and_to_the_receiver() {
        // An encoder too slow for 60 fps: `cpu_bound`, which no collapse can have caused.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        wifi_to_the_collapse(&mut c).expect("re-anchored");
        let mut moved = None;
        for tick in 1..=(DOWN_AFTER.as_millis() / TICK.as_millis()) as u32 + 1 {
            let fb = Feedback {
                encode_ms: 20.0,
                ..wifi(&c, 83, 390, 2_000, 0)
            };
            if let Some(r) = c.tick(fb, TICK) {
                moved = Some((tick, r));
                break;
            }
        }
        let (_, rung) =
            moved.expect("a processor that cannot hold 60 fps sheds the rung in a hold");
        assert_eq!((rung.max_h, rung.fps), (1080, 30));

        // 12% loss reported inside the hold: the receiver has spoken, the hold ends, the brake
        // engages and the rung goes with it.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        wifi_to_the_collapse(&mut c).expect("re-anchored");
        let first = Feedback {
            report: fresh(150, 12.0, 20),
            ..wifi(&c, 83, 2_000, 2_000, 0)
        };
        c.tick(first, TICK);
        assert_eq!(
            c.collapse_state(),
            "brake",
            "the hold ends on the receiver's word"
        );
        assert!(matches!(c.take_brake_event(), Some(BrakeEvent::Engaged(_))));
        let mut shed = None;
        for _ in 0..(DOWN_AFTER.as_millis() / TICK.as_millis()) as u32 + 1 {
            if let Some(r) = c.tick(wifi(&c, 83, 2_000, 2_000, 0), TICK) {
                shed = Some(r);
                break;
            }
        }
        assert!(shed.is_some(), "the brake still takes the rung");
        assert_eq!(c.last_move_reason(), "brake");
    }

    /// A reset that holds clears the way for the next one; resets that do not hold back off.
    #[test]
    fn resets_that_hold_are_repeatable_and_resets_that_do_not_back_off() {
        let clean = |c: &QualityController, estimate: u32, queue: u32| Feedback {
            report: None,
            ..wifi(c, estimate, 2_500, 2_400, queue)
        };
        let reported = |c: &mut QualityController, estimate: u32, queue: u32, secs: u32| {
            let mut moved = None;
            for _ in 0..secs {
                moved = one_second(c, |c| clean(c, estimate, queue), fresh(140, 0.0, 0)).or(moved);
            }
            moved
        };

        // The reset works: the estimate is back over half of what it was restarted at — but the
        // collapse's backlog is still draining, so the hold stays until it has...
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let first = wifi_to_the_collapse(&mut c).expect("re-anchored");
        reported(&mut c, first * 3 / 4, 1_000, 1);
        assert_eq!(
            c.collapse_state(),
            "clean",
            "the estimate is back but a second of the collapse's own queue is not yet"
        );
        // ...and ends as "recovered" once it has, without handing that queue to the ladder: the
        // five-second filter would otherwise carry it past the hold and shed the rung on it.
        reported(&mut c, first * 3 / 4, 0, 1);
        assert_eq!(c.collapse_state(), "-", "recovered");
        // Five seconds on, the same collapse again: served, with no backoff.
        assert_eq!(
            reported(&mut c, 3_000, 0, 5),
            None,
            "shed a rung after a hold that recovered, on the backlog the collapse built"
        );
        let _ = c.take_bwe_reanchor();
        one_second(&mut c, |c| clean(c, 90, 400), fresh(140, 0.0, 0));
        assert!(
            c.take_bwe_reanchor().is_some(),
            "a second collapse after a reset that held is served at the ordinary spacing"
        );

        // The reset does not take: the estimate stays collapsed for the whole hold. The next
        // collapse inside twice the spacing is refused and served after it.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        wifi_to_the_collapse(&mut c).expect("re-anchored");
        reported(&mut c, 90, 400, 5);
        assert_ne!(c.collapse_state(), "clean", "expired");
        reported(&mut c, 3_000, 0, 3);
        let mut served_at = None;
        for second in 9..=13 {
            one_second(&mut c, |c| clean(c, 90, 400), fresh(140, 0.0, 0));
            if c.take_bwe_reanchor().is_some() {
                assert!(
                    second >= 10,
                    "a reset that did not hold is repeated {second} s later, inside the backoff"
                );
                served_at = Some(second);
                break;
            }
            assert_eq!(c.collapse_state(), "spacing", "second {second}");
        }
        assert!(
            served_at.is_some(),
            "and after twice the spacing it is served again: a backoff, not a ban"
        );
    }

    /// The 3G collapses stay refused when the capacity evidence does diverge: the receiver's word
    /// decides, not the arithmetic.
    ///
    /// Recorded on 3G, baseline ~210: round trips of 283, 283, 347 (past the clean margin of 273),
    /// then 524 with 16.6% loss, 277 with 6.5%, then 212 and 214 with the loss three seconds old.
    /// Here a probe has lifted the evidence to 2000 beforehand, so every second is diverged two to
    /// one and the receiver alone refuses.
    #[test]
    fn a_collapse_the_receiver_calls_congested_is_never_re_anchored() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let thin = |c: &QualityController, estimate_kbps: u32, egress_kbps: u32| Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: 850,
            egress_kbps,
            qp_samples: 6,
            queue_age_ms: 120,
            avg_qp: Some(36.0),
            encode_ms: 1.5,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };
        for rtt in [212, 214, 211, 215, 210, 213] {
            one_second(&mut c, |c| thin(c, 700, 700), fresh(rtt, 0.0, 0));
        }
        one_second(&mut c, |c| thin(c, 2_000, 600), fresh(215, 0.0, 0));
        assert!(c.capacity_kbps() >= 1_900, "{}", c.capacity_kbps());
        let _ = c.take_bwe_reanchor();

        let episode = [
            (736, 785, fresh(283, 0.0, 0)),
            (736, 705, fresh(283, 0.0, 0)),
            (736, 808, fresh(347, 0.0, 0)),
            (736, 960, fresh(373, 0.0, 0)),
            (736, 627, fresh(524, 16.61, 40)),
            (681, 473, fresh(277, 6.54, 24)),
            (584, 516, fresh(212, 0.0, 5)),
            (426, 514, fresh(214, 0.0, 0)),
            (426, 514, fresh(212, 0.0, 0)),
            (426, 514, fresh(213, 0.0, 0)),
        ];
        for (i, (estimate, egress, report)) in episode.into_iter().enumerate() {
            one_second(&mut c, |c| thin(c, estimate, egress), report);
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "second {i}: re-anchored {estimate} with the receiver reporting {report:?} — the \
                 3G failure"
            );
            assert!(
                ["rtt", "loss", "brake", "-"].contains(&c.collapse_state()),
                "second {i}: {}",
                c.collapse_state()
            );
        }
    }

    // ── the receiver's reports, and the brake ─────────────────────────────────────────────────

    fn fresh(rtt_ms: u32, loss_pct: f32, nacks: u32) -> Option<ReceiverReport> {
        Some(ReceiverReport {
            rtt_ms: Some(rtt_ms),
            loss: Some(loss_pct / 100.0),
            nacks,
        })
    }

    /// An interval in which no receiver report arrived: str0m repeats the last round trip and
    /// reports no loss at all.
    fn silent(rtt_ms: u32) -> Option<ReceiverReport> {
        Some(ReceiverReport {
            rtt_ms: Some(rtt_ms),
            loss: None,
            nacks: 0,
        })
    }

    /// One second of `fb`: five ticks, with `report` on the first. Returns any rung it moved to.
    fn one_second(
        c: &mut QualityController,
        fb: impl Fn(&QualityController) -> Feedback,
        report: Option<ReceiverReport>,
    ) -> Option<Rung> {
        let mut moved = None;
        for tick in 0..5 {
            let f = Feedback {
                report: if tick == 0 { report } else { None },
                ..fb(c)
            };
            moved = c.tick(f, TICK).or(moved);
        }
        moved
    }

    /// 1080p@60 on the LTE link before it failed: 11.5 Mbps leaving against an estimate of 12482,
    /// the budget at the rung's absorbable 10306.
    fn lte(c: &QualityController, estimate_kbps: u32, egress_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: 10_400,
            egress_kbps,
            qp_samples: 12,
            queue_age_ms: 0,
            avg_qp: Some(28.0),
            encode_ms: 4.5,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// The recorded end of an LTE session, report by report.
    ///
    /// ```text
    /// 08:10:15  egress 11453  est 12482  rtt 253  loss  0.00%
    /// 08:10:16  egress 12611  est 12482  rtt 292  loss 24.69%  nacks 11
    /// 08:10:17  egress 11530  est 13480  rtt 801  loss 94.15%  nacks 69
    /// 08:10:18  egress 11312  est 13480  rtt 764  loss 93.92%  nacks 107
    /// ```
    ///
    /// The estimate froze and the sender went on at ~11 Mbps into a link delivering a sixteenth of
    /// it. The brake must engage on the first report, cut below what the receiver got, and take the
    /// rung down within the descent dwell.
    #[test]
    fn the_lte_ending_engages_the_brake_on_the_first_bad_report() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [251, 258, 253, 250, 252, 251, 257, 251, 251, 258, 253, 250] {
            one_second(&mut c, |c| lte(c, 12_482, 11_453), fresh(rtt, 0.0, 0));
        }
        assert_eq!(
            c.current(),
            LADDER[0],
            "the setup is 1080p@60 on a healthy link"
        );
        assert_eq!(c.brake_kbps(), None);
        let before = c.encoder_target_kbps();
        assert_eq!(before, 10_306, "at the rung's absorbable price");

        // 08:10:16.
        let moved = one_second(&mut c, |c| lte(c, 12_482, 12_611), fresh(292, 24.69, 11));
        assert!(moved.is_none(), "one bad second is half the descent dwell");
        let Some(BrakeEvent::Engaged(d)) = c.take_brake_event() else {
            panic!("24.69% loss in one report must engage the brake");
        };
        assert_eq!(d.cause, BrakeCause::Loss);
        assert_eq!(d.rtt_base_ms, Some(250));
        let first_cut = c.encoder_target_kbps();
        // 0.85 x (1 - 0.2469) x the larger interval's egress, ~12000: about 7700.
        assert!(
            (7_000..=8_100).contains(&first_cut),
            "cut to {first_cut}; the receiver got about three quarters of ~12 Mbps"
        );

        // 08:10:17: the estimate has frozen at 13480 and the receiver gets 6%.
        let moved = one_second(&mut c, |c| lte(c, 13_480, 11_530), fresh(801, 94.15, 69));
        assert!(
            matches!(c.take_brake_event(), Some(BrakeEvent::Tightened(_))),
            "a report showing a sixteenth getting through must cut again"
        );
        let second_cut = c.encoder_target_kbps();
        assert!(
            second_cut <= 700,
            "the budget is {second_cut} while the receiver gets ~700 kbps of what we send and the \
             estimate reads 13480"
        );
        // Two seconds of the brake engaged is the descent dwell, and the brake is "the network
        // cannot carry it": the rung gives way at the end of 08:10:17.
        let rung = moved.expect("two seconds of the brake engaged must take the rung");
        assert!(rung.fps < 60 || rung.max_h < 1080, "moved to {rung:?}");
        assert_eq!(c.last_move_reason(), "brake");

        // 08:10:18: still 94%. The budget stays cut and nothing climbs back on the frozen 13480.
        let moved = one_second(&mut c, |c| lte(c, 13_480, 11_312), fresh(764, 93.92, 107));
        assert!(
            moved.is_none(),
            "settling after the move, and braking: {moved:?}"
        );
        assert!(
            c.encoder_target_kbps() <= 700,
            "and the budget stays cut: {}",
            c.encoder_target_kbps()
        );
    }

    /// NACK-recovered loss on a relay is not congestion, and single round-trip spikes are not a
    /// queue. Neither may move the brake.
    ///
    /// The reports below are recorded relayed Wi-Fi shapes: loss of 0.04-1.18% with a few NACKs in
    /// two seconds of five, two single reports past 5% (5.09%, 5.88%), and round-trip spikes of
    /// 263, 280 and 303 alone and 244-245 twice in a row against a baseline of ~128. A twin
    /// controller never shown a report must make every decision the same.
    #[test]
    fn relay_loss_and_single_spikes_never_engage_the_brake() {
        let rtts = [
            131, 128, 263, 131, 130, 134, 280, 134, 131, 129, 303, 131, 244, 245, 182, 180, 144,
            131, 129, 133,
        ];
        let losses = [
            0.0, 0.17, 0.0, 0.10, 0.0, 0.04, 0.0, 1.18, 0.0, 0.14, 5.09, 0.0, 0.33, 0.0, 0.08, 0.0,
            5.88, 0.0, 0.22, 0.0,
        ];
        let mut with = QualityController::new(1620, 1080, Quality::Balanced);
        let mut without = QualityController::new(1620, 1080, Quality::Balanced);
        for second in 0..200usize {
            let rtt = rtts[second % rtts.len()];
            let loss = losses[second % losses.len()];
            let nacks = if loss > 0.0 { 4 } else { 0 };
            let a = one_second(
                &mut with,
                |c| lte(c, 12_482, 11_453),
                fresh(rtt, loss, nacks),
            );
            let b = one_second(&mut without, |c| lte(c, 12_482, 11_453), None);
            assert_eq!(
                with.take_brake_event(),
                None,
                "second {second}: rtt {rtt}, loss {loss}% moved the brake"
            );
            assert_eq!(a, b, "second {second}: the reports changed a rung decision");
            assert_eq!(
                with.encoder_target_kbps(),
                without.encoder_target_kbps(),
                "second {second}: the reports changed the budget"
            );
        }
    }

    /// Two fresh reports in a row with the round trip past twice its baseline are a queue; one is
    /// jitter. Recorded on 3G, baseline ~210: 431 alone, then 226; later 452 and 444, which the
    /// ladder answered a second later by shedding 720p on its quantiser.
    #[test]
    fn a_standing_round_trip_engages_the_brake_and_a_spike_does_not() {
        let three_g = |c: &QualityController| Feedback {
            estimate_kbps: 720,
            drain_kbps: 792,
            produced_kbps: 640,
            egress_kbps: 700,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(33.0),
            encode_ms: 2.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [212, 211, 214, 243, 223, 223, 353, 302, 271, 261] {
            one_second(&mut c, three_g, fresh(rtt, 0.0, 0));
        }
        assert_eq!(c.rtt_base_ms(), Some(211));

        // A spike, alone.
        one_second(&mut c, three_g, fresh(431, 0.0, 1));
        one_second(&mut c, three_g, fresh(226, 0.0, 0));
        // And a spike followed by an interval with no report, which repeats it: still one.
        one_second(&mut c, three_g, fresh(539, 0.0, 2));
        one_second(&mut c, three_g, silent(539));
        one_second(&mut c, three_g, fresh(215, 0.0, 0));
        assert_eq!(
            c.take_brake_event(),
            None,
            "single reports are jitter on this link"
        );
        assert_eq!(c.brake_kbps(), None);

        // 08:11:16-17.
        one_second(&mut c, three_g, fresh(452, 0.0, 0));
        assert_eq!(c.take_brake_event(), None, "the first of two");
        one_second(&mut c, three_g, fresh(444, 0.0, 0));
        let Some(BrakeEvent::Engaged(d)) = c.take_brake_event() else {
            panic!("two reports past 420 against a 211 baseline must engage");
        };
        assert_eq!(d.cause, BrakeCause::Rtt);
        assert!(
            c.encoder_target_kbps() <= 700 * 85 / 100 + 1,
            "cut to {}, above 0.85 of what was leaving",
            c.encoder_target_kbps()
        );
    }

    /// The brake holds between its thresholds, releases gradually once a report is clean, and
    /// never snaps back to the estimate it was set against.
    #[test]
    fn the_brake_holds_then_releases_gradually_and_never_snaps_back() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..12 {
            one_second(&mut c, |c| lte(c, 12_482, 11_453), fresh(252, 0.0, 0));
        }
        one_second(&mut c, |c| lte(c, 12_482, 11_453), fresh(292, 24.69, 11));
        one_second(&mut c, |c| lte(c, 13_480, 11_530), fresh(801, 94.15, 69));
        let cut = c.brake_kbps().expect("engaged");
        let _ = c.take_brake_event();

        // From here the link carries whatever the budget asks of it, and the estimate is still
        // the frozen 13480 — the number the brake exists to disbelieve.
        let following = |c: &QualityController| {
            let budget = c.encoder_target_kbps();
            Feedback {
                produced_kbps: budget * 95 / 100,
                ..lte(c, 13_480, budget)
            }
        };

        // A report between the thresholds — 5% loss — holds: no cut, no release.
        one_second(&mut c, following, fresh(300, 5.0, 3));
        assert_eq!(c.brake_kbps(), Some(cut), "5% neither cuts nor releases");
        assert_eq!(c.brake_state(), "holding");

        // Clean from here on. The ceiling may grow by at most a quarter a second.
        let mut prev = c.encoder_target_kbps();
        let mut released_after = None;
        for second in 1..=40u32 {
            one_second(&mut c, following, fresh(255, 0.0, 0));
            let now = c.encoder_target_kbps();
            assert!(
                f64::from(now) <= f64::from(prev) * BRAKE_RELEASE_PER_SEC * 1.01 + 5.0,
                "second {second}: the budget jumped {prev} -> {now}, a snap back towards the \
                 frozen estimate"
            );
            prev = now;
            if let Some(BrakeEvent::Released(_)) = c.take_brake_event() {
                released_after = Some(second);
                break;
            }
        }
        let after = released_after.expect("a clean link must get its budget back");
        assert!(
            (5..=20).contains(&after),
            "released after {after} s: from {cut} to the rung's ceiling at 1.25x a second is \
             about twelve"
        );
        assert_eq!(c.brake_kbps(), None);
    }

    /// Silence from the receiver while we are sending is a brake condition; silence while we are
    /// not, or before the receiver has ever reported, is not.
    ///
    /// One empty interval is Chrome's cadence (a report every second, randomised between half and
    /// one and a half times that); two in a row is more than that cadence produces. See
    /// [`BRAKE_STALE_REPORTS`]. Silence only cuts the budget: not a rung, not the capacity
    /// evidence (`Brake::silence_only`).
    #[test]
    fn a_receiver_gone_silent_while_we_send_engages_the_brake() {
        let busy = |c: &QualityController| Feedback {
            produced_kbps: 2_800,
            ..lte(c, 4_000, 3_000)
        };
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        // Before any fresh report: silence is a path that has not spoken, not one that stopped.
        for _ in 0..5 {
            one_second(&mut c, busy, silent(250));
        }
        assert_eq!(c.take_brake_event(), None, "nothing had ever been reported");
        assert!(
            c.feedback_live(),
            "nor is feedback stale before it ever arrived"
        );

        for _ in 0..5 {
            one_second(&mut c, busy, fresh(250, 0.0, 0));
        }
        let evidence = c.capacity_kbps();
        let rung = c.current();
        one_second(&mut c, busy, silent(250));
        assert_eq!(
            c.take_brake_event(),
            None,
            "one empty interval is Chrome's jitter"
        );
        assert!(!c.feedback_live(), "but the feedback is stale from it");
        one_second(&mut c, busy, silent(250));
        let Some(BrakeEvent::Engaged(d)) = c.take_brake_event() else {
            panic!("two seconds without a report while sending 3 Mbps must engage");
        };
        assert_eq!(d.cause, BrakeCause::Silence);
        assert!(
            c.encoder_target_kbps() <= 1_500,
            "{}",
            c.encoder_target_kbps()
        );
        // A silence that goes on: the budget halves every second interval, and neither the rung nor
        // the capacity evidence (beyond its half-life) moves.
        for _ in 0..8 {
            assert_eq!(
                one_second(&mut c, busy, silent(250)),
                None,
                "the rung moved on silence"
            );
        }
        assert_eq!(c.current(), rung);
        let decayed = f64::from(evidence) * 0.5f64.powf(10.0 / 20.0);
        assert!(
            f64::from(c.capacity_kbps()) >= decayed * 0.95,
            "silence lowered the capacity evidence: {evidence} -> {} (half-life alone: {decayed:.0})",
            c.capacity_kbps()
        );
        assert_eq!(c.brake_state(), "engaged");

        // And a still screen goes quiet without it meaning anything.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..5 {
            one_second(&mut c, busy, fresh(250, 0.0, 0));
        }
        for _ in 0..10 {
            one_second(&mut c, |c| gone_still(c, 1_000), silent(250));
        }
        assert_eq!(
            c.take_brake_event(),
            None,
            "a still screen gives the receiver nothing to report"
        );
    }

    // ── an outage: stale feedback, the silence brake, and the way back ────────────────────────

    /// One second at 1080p30 of a bench blackout run: scrolling code over a clean TURN relay,
    /// round trip 133-146.
    fn bench(
        c: &QualityController,
        estimate_kbps: u32,
        egress_kbps: u32,
        produced_kbps: u32,
        qp: f32,
    ) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps,
            egress_kbps,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(qp),
            encode_ms: 4.1,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// The bench run just before the blackout: 1080p30, estimate 8464, 7324 leaving, 6928 produced
    /// at QP 26.6, the receiver reporting 144 on a baseline of ~134, with a climb to 1080p60 banked
    /// two seconds of its four, so one more second does not climb and a second after that does.
    /// (Down to 1080p30 first by an encoder too slow for 60 fps, plus the move's settle.)
    fn bench_about_to_climb() -> QualityController {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut moved = None;
        for rtt in [135, 134, 137, 136] {
            let slow = |c: &QualityController| Feedback {
                encode_ms: 20.0,
                ..bench(c, 3_000, 2_700, 2_600, 30.0)
            };
            moved = one_second(&mut c, slow, fresh(rtt, 0.0, 0)).or(moved);
        }
        assert_eq!(moved.map(|r| (r.max_h, r.fps)), Some((1080, 30)));
        let at_1080p30 = |c: &QualityController| bench(c, 8_464, 7_324, 6_928, 26.6);
        for _ in 0..30 {
            if c.settling == Duration::ZERO && c.up_dwell >= UP_AFTER - Duration::from_secs(2) {
                return c;
            }
            assert_eq!(one_second(&mut c, at_1080p30, fresh(144, 0.0, 0)), None);
        }
        panic!("the climb never banked: up dwell {:?}", c.up_dwell);
    }

    /// A bench blackout (both directions dead for ten seconds). The estimate went on rising (8906,
    /// 9374, 10403, 10476) with nothing arriving, str0m's smoother walking up to its last value.
    /// Without the live-feedback rule the controller climbed to 1080p60 on it 1.4 s after the last
    /// report and then walked back down on the silence.
    ///
    /// Expected: no climb from the first empty interval, the brake on the second, the rung held,
    /// and the capacity evidence neither raised nor cut. A twin that keeps hearing from the
    /// receiver climbs on the same numbers, so the hold is the silence's doing.
    #[test]
    fn a_blackout_is_not_climbed_into_and_its_silence_brakes_on_the_second_interval() {
        // 12:59:01 (the last report) and 12:59:02-03, as recorded.
        let last = |c: &QualityController| bench(c, 8_906, 7_610, 7_495, 26.8);
        let after = [(9_374, 7_639, 7_177, 25.8), (10_403, 7_600, 7_200, 26.0)];

        let mut heard = bench_about_to_climb();
        one_second(&mut heard, last, fresh(135, 0.0, 0));
        let mut climbed = None;
        for (e, g, p, q) in after {
            climbed =
                one_second(&mut heard, |c| bench(c, e, g, p, q), fresh(140, 0.0, 0)).or(climbed);
        }
        assert_eq!(
            climbed.map(|r| (r.max_h, r.fps)),
            Some((1080, 60)),
            "the twin that hears from the receiver climbs on these numbers"
        );

        let mut dark = bench_about_to_climb();
        one_second(&mut dark, last, fresh(135, 0.0, 0));
        let before = dark.capacity_kbps();
        let rung = dark.current();
        assert!(before >= 8_000, "the evidence before the cut: {before}");
        let (e, g, p, q) = after[0];
        assert_eq!(
            one_second(&mut dark, |c| bench(c, e, g, p, q), silent(135)),
            None
        );
        assert!(!dark.feedback_live(), "one empty interval: stale");
        assert_eq!(dark.take_brake_event(), None, "and not yet a brake");
        let (e, g, p, q) = after[1];
        assert_eq!(
            one_second(&mut dark, |c| bench(c, e, g, p, q), silent(135)),
            None,
            "climbed into a dead link"
        );
        let Some(BrakeEvent::Engaged(d)) = dark.take_brake_event() else {
            panic!("the second empty interval while sending 7.6 Mbps must engage the brake");
        };
        assert_eq!(d.cause, BrakeCause::Silence);
        assert!(
            dark.encoder_target_kbps() <= 3_900,
            "{}",
            dark.encoder_target_kbps()
        );
        // 12:59:04-10: the smoother's 10476, and nothing from the receiver.
        for second in 4..=10 {
            assert_eq!(
                one_second(
                    &mut dark,
                    |c| bench(c, 10_476, 7_600, 7_200, 26.0),
                    silent(135)
                ),
                None,
                "12:59:{second:02}: the rung moved on silence"
            );
        }
        assert_eq!(dark.current(), rung, "held through the outage");
        assert!(
            dark.capacity_kbps() <= before,
            "the smoother's rise was taken as evidence: {before} -> {}",
            dark.capacity_kbps()
        );
        assert!(
            f64::from(dark.capacity_kbps()) >= f64::from(before) * 0.5f64.powf(10.0 / 20.0) * 0.95,
            "the silence cut the evidence: {before} -> {}",
            dark.capacity_kbps()
        );
        assert_eq!(
            dark.last_move_reason(),
            "down",
            "no move since the opening one"
        );
    }

    /// One of Chrome's ordinary empty intervals costs a climb that is about to happen exactly that
    /// interval: the climb dwell pauses through it rather than decaying.
    #[test]
    fn an_ordinary_empty_interval_holds_a_climb_for_that_interval_and_no_longer() {
        let at = |c: &QualityController| bench(c, 8_464, 7_324, 6_928, 26.6);
        let climb_tick = |silent_first: bool| {
            let mut c = bench_about_to_climb();
            for tick in 1..=40u32 {
                let report = match tick % 5 {
                    1 if silent_first && tick == 1 => silent(144),
                    1 => fresh(144, 0.0, 0),
                    _ => None,
                };
                let fb = Feedback { report, ..at(&c) };
                if c.tick(fb, TICK).is_some() {
                    return tick;
                }
            }
            panic!("never climbed");
        };
        let heard = climb_tick(false);
        let held = climb_tick(true);
        assert_eq!(
            held - heard,
            5,
            "an empty interval held the climb {} ticks, not the one interval (5)",
            held - heard
        );
    }

    /// The link comes back: the first second still empty, a clean report (143 on ~134), and the
    /// estimate the outage left falling 5672 -> 3117 while the brake released towards it; recorded,
    /// 1080p60 came back 27 seconds later. Expected: once the receiver has called the path clean
    /// for two seconds, str0m is re-anchored at the intact capacity evidence and the silence brake
    /// goes.
    #[test]
    fn an_outage_is_re_anchored_once_the_receiver_is_back_and_clean() {
        let mut c = outage_of_ten_seconds();
        let cut = c.brake_kbps().expect("the silence brake is in force");
        let evidence = c.capacity_kbps();
        // What leaves is what the brake lets out; the recorded estimates after the link returned.
        let following = |estimate: u32| {
            move |c: &QualityController| {
                let budget = c.encoder_target_kbps();
                bench(c, estimate, budget, budget * 95 / 100, 30.0)
            }
        };
        let after = [
            (5_672, silent(135)),
            (4_929, fresh(143, 0.0, 0)),
            (4_929, silent(143)),
            (3_682, fresh(136, 0.0, 0)),
            (3_117, silent(136)),
            (3_273, fresh(136, 0.0, 0)),
        ];
        let mut served = None;
        for (i, (estimate, report)) in after.into_iter().enumerate() {
            one_second(&mut c, following(estimate), report);
            assert_eq!(c.current().fps, 30, "second {i}: the rung moved");
            if let Some(kbps) = c.take_bwe_reanchor() {
                served = Some((i, kbps, estimate));
                break;
            }
        }
        let (i, kbps, estimate) = served.expect("the outage's end must be re-anchored");
        assert!(
            (3..=5).contains(&i),
            "re-anchored at second {i}: not before two seconds of clean reports (12:59:14)"
        );
        assert!(
            u64::from(kbps) * 100 >= u64::from(estimate) * OUTAGE_DIVERGENCE_PCT,
            "{kbps} against {estimate}"
        );
        assert!(
            kbps >= evidence / 2,
            "at the evidence the silence left: {kbps} of {evidence}"
        );
        let r = c.last_reanchor().expect("details");
        assert_eq!(r.trigger, ReanchorTrigger::OutageResume);
        let Some(BrakeEvent::Released(d)) = c.take_brake_event() else {
            panic!("the silence brake goes with the re-anchor");
        };
        assert_eq!(d.cause, BrakeCause::Resumed);
        // Two seconds of growth at a quarter a second from the cut, and not the jump to the budget
        // that the release by growth would have waited another ten seconds for.
        assert!(
            d.before_kbps < cut * 2 && d.after_kbps > d.before_kbps * 4,
            "{cut} -> {} -> {}",
            d.before_kbps,
            d.after_kbps
        );
        assert_eq!(c.brake_kbps(), None);
        assert_eq!(c.collapse_state(), "clean", "held while the reset lands");
        assert!(
            c.encoder_target_kbps() >= kbps * 3 / 4,
            "the budget is {} after a re-anchor at {kbps}",
            c.encoder_target_kbps()
        );
    }

    /// The same outage, and a link that came back narrower — a report of 12% loss the moment it
    /// returns — or an estimate that came back by itself. Neither is re-anchored.
    #[test]
    fn an_outage_the_receiver_answers_with_loss_or_that_heals_itself_is_not_re_anchored() {
        let following = |estimate: u32| {
            move |c: &QualityController| {
                let budget = c.encoder_target_kbps();
                bench(c, estimate, budget, budget * 95 / 100, 30.0)
            }
        };

        let mut c = outage_of_ten_seconds();
        one_second(&mut c, following(5_672), silent(135));
        let _ = c.take_brake_event();
        one_second(&mut c, following(4_929), fresh(150, 12.0, 20));
        // No new cut (the silence brake is already lower), but the episode is now the receiver's
        // word: descent evidence, and the capacity evidence drops to what got through.
        assert!(
            c.brake
                .is_some_and(|b| !b.silence_only && b.phase == BrakePhase::Engaged),
            "{:?}",
            c.brake
        );
        assert!(c.capacity_kbps() <= c.brake_kbps().unwrap_or(u32::MAX));
        assert_eq!(
            c.outage, None,
            "the outage is over, and not one to re-anchor"
        );
        for rtt in [140, 138, 137, 139, 136] {
            one_second(&mut c, following(3_500), fresh(rtt, 0.0, 0));
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "re-anchored into a link that came back lossy"
            );
        }

        // The estimate back at 8000 against ~5700 of evidence: under one and a half, nothing to
        // correct; the brake grows back instead.
        let mut c = outage_of_ten_seconds();
        one_second(&mut c, following(8_000), silent(135));
        let mut released = false;
        for rtt in [
            143, 136, 137, 136, 138, 136, 135, 137, 136, 136, 138, 136, 137, 135,
        ] {
            one_second(&mut c, following(8_000), fresh(rtt, 0.0, 0));
            assert_eq!(
                c.take_bwe_reanchor(),
                None,
                "re-anchored an estimate that had recovered"
            );
            if let Some(BrakeEvent::Released(d)) = c.take_brake_event() {
                assert_eq!(d.cause, BrakeCause::Clear);
                released = true;
            }
        }
        assert!(released, "the silence brake grows back and releases");
    }

    /// The blackout without a returning receiver, with egress following the budget as the silence
    /// brake halves it: 7288 -> 3644 -> 1822 -> 911 -> 455.
    fn outage_of_ten_seconds() -> QualityController {
        let mut c = bench_about_to_climb();
        one_second(
            &mut c,
            |c| bench(c, 8_906, 7_610, 7_495, 26.8),
            fresh(135, 0.0, 0),
        );
        for estimate in [
            9_374, 10_403, 10_476, 10_476, 10_476, 10_476, 10_476, 10_476, 10_476,
        ] {
            let into_the_dark = |c: &QualityController| {
                let budget = c.encoder_target_kbps();
                bench(c, estimate, budget, budget * 95 / 100, 26.0)
            };
            one_second(&mut c, into_the_dark, silent(135));
        }
        assert!(
            c.brake_kbps().is_some_and(|k| k < 1_000),
            "four halvings into a dead link: {:?}",
            c.brake_kbps()
        );
        let _ = c.take_brake_event();
        let _ = c.take_bwe_reanchor();
        c
    }

    // ── a longer path is not a queue ──────────────────────────────────────────────────────────

    /// 1080p@60 on a recorded relayed link: what leaves is what is produced, nothing queued
    /// locally, QP 23.
    fn handover(c: &QualityController, estimate_kbps: u32, egress_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: egress_kbps,
            egress_kbps,
            qp_samples: 12,
            queue_age_ms: 0,
            avg_qp: Some(23.0),
            encode_ms: 4.6,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// The Wi-Fi half of a recorded handover: 1080p@60, 10.4 Mbps leaving against an estimate of
    /// ~15 Mbps, round trips as recorded (127-140).
    fn on_wifi_at_1080p60() -> QualityController {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [
            128, 136, 139, 135, 135, 130, 131, 140, 127, 130, 127, 129, 129, 129, 128, 132, 130,
            132, 127, 132, 129, 128, 128, 127, 127, 135, 131, 132, 130, 128,
        ] {
            one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(rtt, 0.0, 0));
        }
        assert_eq!(c.current(), LADDER[0], "the setup is 1080p@60");
        assert_eq!(c.rtt_base_ms(), Some(127));
        assert_eq!(c.brake_kbps(), None);
        let _ = c.take_brake_event();
        let _ = c.take_bwe_reanchor();
        c
    }

    /// A recorded Wi-Fi to LTE handover (Telegram iOS, relayed, a VPN on the phone): the Wi-Fi link
    /// dies under 9.4 Mbps (round trips of 1480, 685 and 1758 against 127), the phone is silent for
    /// 9.2 s, and comes back on LTE at a flat 245 with no loss and no ICE restart.
    ///
    /// Recorded, the round-trip brake rightly engaged on the dying link and shed 1080p@60, then
    /// shed 1080p@30 during the silence, held 524 kbps for thirty seconds because 245 was "not yet
    /// clear" of the Wi-Fi baseline, refused the outage's re-anchor, and the top rung returned 72 s
    /// later on a link carrying 10-11 Mbps.
    ///
    /// Expected: the first descent stands, the silence holds the rung, and the first LTE report
    /// starts the baseline over, so the brake releases and the budget is what the live estimate
    /// allows once the path has been clean for two seconds.
    #[test]
    fn a_handover_through_an_outage_starts_the_round_trip_baseline_over() {
        let mut c = on_wifi_at_1080p60();
        let mut moves = Vec::new();
        // 19:52:56-58: the dying WiFi, as recorded.
        for (rtt, estimate, egress) in [
            (1_480, 7_423, 9_194),
            (685, 8_030, 9_455),
            (1_758, 8_030, 9_404),
        ] {
            moves.extend(one_second(
                &mut c,
                |c| handover(c, estimate, egress),
                fresh(rtt, 0.0, 0),
            ));
        }
        assert!(
            c.brake
                .is_some_and(|b| !b.silence_only && b.phase == BrakePhase::Engaged),
            "a round trip ramping to 1758 on 127 is a queue: {:?}",
            c.brake
        );
        // 19:52:59-19:53:07: silence, with what leaves following what the brake allows.
        for _ in 0..8 {
            let braked = |c: &QualityController| {
                let budget = c.encoder_target_kbps();
                handover(c, 8_030, budget)
            };
            moves.extend(one_second(&mut c, braked, silent(1_758)));
        }
        assert!(
            moves.iter().all(|r| r.max_h == 1080),
            "the silence held the rung (recorded: 900p@30 at 19:53:04): {moves:?}"
        );
        assert!(
            c.brake.is_some_and(|b| b.silence_only),
            "the WiFi's word is not evidence about whatever path comes back: {:?}",
            c.brake
        );

        // 19:53:08: the first LTE report.
        let lte_back = |estimate: u32| {
            move |c: &QualityController| {
                let budget = c.encoder_target_kbps();
                handover(c, estimate, budget)
            }
        };
        moves.extend(one_second(&mut c, lte_back(8_673), fresh(247, 0.0, 0)));
        assert_eq!(
            c.rtt_base_ms(),
            None,
            "the outage started the baseline over: 127 was the WiFi's"
        );
        assert_eq!(
            c.brake_state(),
            "releasing",
            "recorded: holding, against 127, for thirty seconds"
        );
        // 19:53:09-13.
        for (rtt, estimate) in [
            (253, 8_673),
            (249, 10_382),
            (351, 9_707),
            (249, 9_707),
            (246, 10_202),
        ] {
            moves.extend(one_second(&mut c, lte_back(estimate), fresh(rtt, 0.0, 0)));
        }
        assert_eq!(
            c.rtt_base_ms(),
            Some(246),
            "the LTE path's own least round trip"
        );
        assert!(
            c.brake_kbps().is_none_or(|k| k >= 8_000),
            "the outage's end lifts the silence brake to the live estimate: {:?}",
            c.brake
        );
        assert!(
            c.encoder_target_kbps() >= 8_000,
            "recorded: 524 kbps until 19:53:38; now {}",
            c.encoder_target_kbps()
        );
        assert_eq!(c.outage, None, "the outage is over");
        assert_eq!(
            moves.first().map(|r| (r.max_h, r.fps)),
            Some((1080, 30)),
            "the one descent is the dying WiFi's: {moves:?}"
        );
        assert!(
            moves.iter().skip(1).all(|r| r.max_h == 1080 && r.fps == 60),
            "and nothing after it but the climb back (recorded: 19:54:24): {moves:?}"
        );
    }

    /// The same handover with no outage: the round trip steps from 127 to 245 and stays, nothing
    /// lost or queued. Under the inflation threshold (277), so no brake, but past the clean margin
    /// for the thirty seconds the baseline takes to forget 127. Three flat reports re-base it.
    #[test]
    fn a_longer_path_without_an_outage_is_recognised_in_three_reports() {
        let mut c = on_wifi_at_1080p60();
        for (i, rtt) in [247, 253, 249].into_iter().enumerate() {
            one_second(&mut c, |c| handover(c, 13_376, 10_400), fresh(rtt, 0.0, 0));
            if i < 2 {
                assert_eq!(c.rtt_base_ms(), Some(127), "report {i}: not yet");
            }
        }
        assert_eq!(c.rtt_base_ms(), Some(247), "a flat step is the path");
        assert_eq!(c.brake_kbps(), None);
        // The recorded spike at 19:53:11 is past the new clean margin, and is an ordinary unclean
        // report — not a step, not a brake.
        for rtt in [351, 249, 246, 243] {
            one_second(&mut c, |c| handover(c, 13_376, 10_400), fresh(rtt, 0.0, 0));
        }
        assert_eq!(c.rtt_base_ms(), Some(243));
        assert_eq!(c.brake_kbps(), None);
        assert_eq!(
            c.path_clean(),
            Ok(()),
            "clean again two seconds after the spike"
        );
        assert_eq!(c.current(), LADDER[0]);
    }

    /// A step past the inflation threshold (a 30 ms Wi-Fi path to LTE at 250): the round-trip arm
    /// cuts on the second report, the flat third re-bases, voids the cut and lifts the budget, one
    /// second of braking, so the rung stays.
    #[test]
    fn a_step_past_the_inflation_threshold_brakes_for_one_report_and_keeps_the_rung() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [31, 30, 32, 30, 31, 33, 30, 31, 30, 32, 31, 30] {
            one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(rtt, 0.0, 0));
        }
        assert_eq!(c.rtt_base_ms(), Some(30));
        let mut moves = Vec::new();
        let mut engaged = false;
        for rtt in [250, 250, 251, 249, 250, 252, 250, 251, 250, 249] {
            moves.extend(one_second(
                &mut c,
                |c| handover(c, 12_000, 10_400),
                fresh(rtt, 0.0, 0),
            ));
            engaged |= matches!(c.take_brake_event(), Some(BrakeEvent::Engaged(_)));
        }
        assert!(
            engaged,
            "two reports past twice the baseline are a queue until shown otherwise"
        );
        assert!(moves.is_empty(), "the rung went: {moves:?}");
        assert_eq!(c.rtt_base_ms(), Some(249));
        assert_eq!(c.brake_kbps(), None, "released: {:?}", c.brake);
        assert!(
            c.encoder_target_kbps() >= 9_000,
            "{}",
            c.encoder_target_kbps()
        );
    }

    /// A bench RTT step: the step's second report cut, Chrome's next report came two seconds later
    /// instead of one, and the third flat report (the verdict) landed after the descent dwell, so
    /// 1080p@60 went 200 ms before the baseline moved. While the reports could still be a path, the
    /// cut stands but the rung waits. A ramp does not wait: it is off one level by its third
    /// report.
    #[test]
    fn the_rung_waits_for_a_path_step_verdict_and_a_ramp_does_not() {
        let settled = || {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            for rtt in [126, 125, 127, 126, 125, 128, 126, 125, 127, 126, 125, 126] {
                one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(rtt, 0.0, 0));
            }
            assert_eq!(c.rtt_base_ms(), Some(125));
            c
        };

        let mut c = settled();
        let mut moves = Vec::new();
        for report in [
            fresh(327, 0.0, 0),
            fresh(328, 0.0, 0),
            silent(328),
            fresh(330, 0.0, 0),
            fresh(329, 0.0, 0),
            fresh(327, 0.0, 0),
        ] {
            moves.extend(one_second(&mut c, |c| handover(c, 11_455, 10_400), report));
        }
        assert!(
            moves.is_empty(),
            "the rung went before the verdict: {moves:?}"
        );
        assert_eq!(c.rtt_base_ms(), Some(327));
        assert_eq!(c.brake_kbps(), None);

        // A queue building: 300, 400, 500 ... over the same 125 ms path.
        let mut c = settled();
        let mut moves = Vec::new();
        for rtt in [300, 400, 500, 600, 700, 800] {
            moves.extend(one_second(
                &mut c,
                |c| handover(c, 11_455, 10_400),
                fresh(rtt, 0.0, 0),
            ));
        }
        assert!(
            moves.iter().any(|r| r.max_h < 1080 || r.fps < 60),
            "a ramp must still shed the rung: {moves:?}"
        );
        assert_eq!(c.rtt_base_ms(), Some(125), "and is never a path");
    }

    /// What the rule must not call a path, from the recordings — and what it must. See
    /// [`PATH_STEP_REPORTS`] for where each window comes from.
    #[test]
    fn queues_in_the_recordings_are_not_path_steps() {
        // (window, the baseline it is elevated above)
        let paths: [(&[u32], u32); 7] = [
            (&[247, 253, 249], 127),
            (&[250, 250, 248], 128),
            (&[378, 379, 377], 135),
            (&[555, 552, 556], 373),
            (&[337, 341, 354], 135),
            // One spike above the level among four: still the level.
            (&[329, 327, 366, 340], 126),
            (&[327, 366, 340, 327], 126),
        ];
        for (w, base) in paths {
            assert_eq!(
                path_step_refusal(&QualityPolicy::reference(), w, base),
                None,
                "{w:?} over {base} is a path"
            );
        }
        let queues: [(&[u32], u32, &str); 11] = [
            (&[213, 225, 235], 150, "spread"),
            (&[225, 235, 243], 150, "trend"),
            (&[235, 243, 254], 150, "trend"),
            (&[243, 254, 259], 150, "trend"),
            (&[213, 225, 235, 243], 150, "spread"),
            (&[225, 235, 243, 254], 150, "trend"),
            (&[225, 208, 208], 150, "trend"),
            (&[3_857, 3_852, 3_867, 6_020], 1_001, "too-long"),
            (&[452, 444, 527], 211, "spread"),
            (&[452, 444, 527, 414], 211, "trend"),
            // Three reports, one of them a spike: not yet — the level needs three of its own.
            (&[329, 327, 366], 126, "spread"),
        ];
        for (w, base, why) in queues {
            assert_eq!(
                path_step_refusal(&QualityPolicy::reference(), w, base),
                Some(why),
                "{w:?} over {base}"
            );
        }

        // A recorded queue building on a ~150 ms path, under the inflation threshold: never
        // re-based.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [153, 150, 152, 151, 153, 150] {
            one_second(&mut c, |c| handover(c, 1_239, 1_000), fresh(rtt, 0.0, 0));
        }
        for rtt in [213, 225, 235, 243, 254, 259] {
            one_second(&mut c, |c| handover(c, 1_239, 1_000), fresh(rtt, 0.0, 0));
            assert_eq!(c.rtt_base_ms(), Some(150), "re-based on a ramp at {rtt}");
        }

        // A recorded 3G opening queue, flat at 3.9 s for three reports: a stalled bottleneck, not a
        // path. The baseline stays the least seen.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [1_001, 1_004, 2_020, 2_022, 3_857, 3_852, 3_867, 6_020] {
            one_second(&mut c, |c| handover(c, 178, 100), fresh(rtt, 0.0, 0));
            assert!(
                c.rtt_base_ms().is_none_or(|b| b == 1_001),
                "re-based on the 3G stall at {rtt}: {:?}",
                c.rtt_base_ms()
            );
        }
    }

    /// ICE moves the media while a round-trip brake holds: the baseline starts over, the brake
    /// stops being descent evidence, and the new path's clean reports release it.
    #[test]
    fn a_new_candidate_pair_starts_the_baseline_over_and_voids_the_brakes_evidence() {
        let mut c = on_wifi_at_1080p60();
        for rtt in [420, 690] {
            one_second(&mut c, |c| handover(c, 9_000, 9_400), fresh(rtt, 0.0, 0));
        }
        assert!(
            c.brake
                .is_some_and(|b| !b.silence_only && b.phase == BrakePhase::Engaged),
            "{:?}",
            c.brake
        );
        c.note_path_change("selected_pair");
        assert_eq!(c.rtt_base_ms(), None);
        assert!(c.brake.is_some_and(|b| b.silence_only), "{:?}", c.brake);
        let mut moves = Vec::new();
        for rtt in [245, 247, 244, 246, 245, 244, 246, 245, 247, 244, 245, 246] {
            moves.extend(one_second(
                &mut c,
                |c| {
                    let budget = c.encoder_target_kbps();
                    handover(c, 12_000, budget)
                },
                fresh(rtt, 0.0, 0),
            ));
        }
        assert_eq!(c.rtt_base_ms(), Some(244));
        assert!(
            moves.iter().all(|r| r.max_h == 1080),
            "the brake stopped shedding rungs at the path change: {moves:?}"
        );
        assert_eq!(
            c.brake_kbps(),
            None,
            "released on the new path: {:?}",
            c.brake
        );
    }

    // ── the slow start ────────────────────────────────────────────────────────────────────────

    /// A bench opening over a clean TURN relay: str0m ramping 1171 -> 1861 -> 2313 from its opening
    /// 600, the opening keyframes queued behind it (241 ms), production over egress 1.27-1.38 in
    /// its mean, and `growing` shed 1080p60 two seconds in with the receiver reporting 148 ms and
    /// no loss; the climb back took 34 s.
    ///
    /// Held, because the receiver called the path clean. The same opening with a queue reported at
    /// the far end, or with no receiver report, still descends.
    #[test]
    fn a_slow_start_the_receiver_calls_clean_is_not_descended() {
        // (estimate, egress, produced, queue, qp) per second from 12:56:55.
        let seconds: [(u32, u32, u32, u32, f32); 8] = [
            (1_171, 663, 2_000, 241, 45.2),
            (1_861, 1_533, 1_900, 0, 46.0),
            (1_861, 1_550, 1_800, 0, 46.0),
            (1_861, 1_600, 1_700, 0, 44.0),
            (2_092, 1_800, 1_850, 0, 40.0),
            (2_202, 1_950, 1_990, 0, 38.0),
            (2_313, 2_100, 2_150, 0, 37.0),
            (2_313, 2_150, 2_180, 0, 36.0),
        ];
        let run = |reports: [Option<ReceiverReport>; 8]| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            let mut moves = Vec::new();
            for (i, ((estimate, egress, produced, queue, qp), report)) in
                seconds.into_iter().zip(reports).enumerate()
            {
                let fb = |c: &QualityController| Feedback {
                    estimate_kbps: estimate,
                    drain_kbps: estimate * 11 / 10,
                    produced_kbps: produced,
                    egress_kbps: egress,
                    qp_samples: 12,
                    queue_age_ms: queue,
                    avg_qp: Some(qp),
                    encode_ms: 3.1,
                    spend_ratio: 0.9,
                    rung_fps_hint: c.current().fps as f32,
                    qp_ceiling: Some(46.0),
                    drop_ratio: 0.0,
                    report: None,
                };
                if let Some(r) = one_second(&mut c, fb, report) {
                    moves.push((i, r, c.last_move_reason()));
                }
            }
            moves
        };

        let clean = [
            fresh_no_rtt(0.0),
            fresh(148, 0.0, 0),
            fresh(148, 0.0, 0),
            fresh(149, 0.0, 0),
            fresh(148, 0.0, 0),
            fresh(148, 0.0, 0),
            fresh(149, 0.0, 0),
            fresh(147, 0.0, 0),
        ];
        let moves = run(clean);
        assert!(
            moves.is_empty(),
            "descended on str0m's slow start: {moves:?}"
        );

        let mut queued = clean;
        queued[2] = fresh(400, 0.0, 0);
        let moves = run(queued);
        assert!(
            moves.iter().any(|m| m.2 == "down"),
            "a round trip at 2.7x the least seen is the far end reporting a queue: {moves:?}"
        );

        let moves = run([None; 8]);
        assert!(
            moves.iter().any(|m| m.2 == "down"),
            "with no report the receiver has said nothing, and the arms read as before: {moves:?}"
        );
    }

    // ── the probe target ──────────────────────────────────────────────────────────────────────

    /// One second, taking and confirming every probe target the way the control task does.
    fn probing_second(
        c: &mut QualityController,
        fb: impl Fn(&QualityController) -> Feedback,
        report: Option<ReceiverReport>,
    ) -> Vec<u32> {
        let mut sent = Vec::new();
        for tick in 0..5 {
            let f = Feedback {
                report: if tick == 0 { report } else { None },
                ..fb(c)
            };
            c.tick(f, TICK);
            if let Some(kbps) = c.take_probe_target() {
                c.probe_target_sent(kbps);
                sent.push(kbps);
            }
        }
        sent
    }

    /// What str0m is told to probe towards: the ceiling for the opening, then twice the best
    /// estimate seen until the path has been measured (the floor while nothing is), then twice the
    /// capacity evidence, never under the floor or over the ceiling, re-sent when it moves by a
    /// fifth and, once there is evidence and the first seconds are over, at most once a second.
    ///
    /// A recorded 3G link carried about 700 kbps behind a buffer the simulator models at 60 ms;
    /// str0m's periodic ALR probe goes to twice the target whatever the estimate, 20.6 Mbps at the
    /// ceiling, every five seconds after its opening probes, which is why the opening's ceiling
    /// ends at three.
    #[test]
    fn the_probe_target_follows_the_capacity_evidence_within_the_ladders_bounds() {
        assert_eq!(probe_floor_kbps(1620, 1080), 1_078);
        assert_eq!(probe_floor_kbps(1920, 1080), 1_227);
        assert_eq!(
            probe_floor_kbps(0, 0),
            MIN_DESIRED_KBPS,
            "a degenerate source still probes"
        );
        let ceiling = desired_bitrate_kbps(1620, 1080, Quality::Balanced);
        assert_eq!(ceiling, 10_306);

        let thin = |estimate: u32| {
            move |c: &QualityController| Feedback {
                estimate_kbps: estimate,
                drain_kbps: estimate * 11 / 10,
                produced_kbps: estimate * 85 / 100,
                egress_kbps: estimate * 9 / 10,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(33.0),
                encode_ms: 2.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            }
        };
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        // What the agent sends as the peer is created, priced on a guessed 1920x1080: the ceiling
        // there, for the opening.
        let opening = opening_probe_target_kbps(1920, 1080, Quality::Balanced);
        assert_eq!(opening, desired_bitrate_kbps(1920, 1080, Quality::Balanced));
        c.probe_target_sent(opening);
        assert_eq!(c.probe_target_kbps(), ceiling, "the opening");

        // str0m's opening 600 "confirmed" by egress in its band: our configuration, not a
        // measurement. Through the opening the target is the ceiling; on the tick it ends (three
        // seconds of media) the floor goes out at once.
        let mut sent = Vec::new();
        for _ in 0..3 {
            sent.extend(probing_second(&mut c, thin(600), None));
        }
        assert!(!c.probe_opening());
        assert_eq!(sent, vec![1_078], "the floor, when the opening ends");
        assert_eq!(c.probe_target_kbps(), 1_078);

        // The 3G link measured (~700, receiver clean): twice the best estimate goes out at once;
        // twice the evidence after it is within a fifth, so nothing more is sent.
        let mut sent = Vec::new();
        for (estimate, rtt) in [(690, 212), (700, 211), (710, 214), (700, 213), (705, 212)] {
            sent.extend(probing_second(&mut c, thin(estimate), fresh(rtt, 0.0, 0)));
        }
        let target = c.probe_target_kbps();
        assert!((1_380..=1_430).contains(&target), "{target}");
        assert!(
            c.probe_evidence_seen(),
            "the clean reports are the evidence"
        );
        assert_eq!(sent, vec![2 * 690], "one rise, then quiet");
        // A 15 ms probe at P into a bottleneck of C holds (P - C) x 15 ms, which a 60 ms buffer
        // takes up to P = 5C; the periodic probe is twice the target, four times the evidence.
        assert!(
            2 * target <= c.capacity_kbps() * (1 + 60 / 15) * 8 / 10,
            "a periodic probe at {} kbps against {} measured",
            2 * target,
            c.capacity_kbps()
        );

        // A fat link: the evidence climbs past the ceiling, and the target stops there.
        let mut sent = Vec::new();
        for estimate in [1_400, 2_800, 5_600, 9_000, 14_000, 20_000] {
            sent.extend(probing_second(&mut c, thin(estimate), fresh(212, 0.0, 0)));
        }
        assert_eq!(c.probe_target_kbps(), ceiling);
        assert!(sent.iter().all(|&k| k <= ceiling), "{sent:?}");
        assert!(sent.windows(2).all(|w| w[1] > w[0]), "{sent:?}");
        assert_eq!(sent.last(), Some(&ceiling));

        // 25% then 94% loss: the brake cuts the evidence to what got through and the target follows
        // within a second, while egress and the frozen estimate stay put.
        let mut lowered = probing_second(&mut c, thin(20_000), fresh(292, 24.7, 11));
        lowered.extend(probing_second(&mut c, thin(20_000), fresh(801, 94.2, 69)));
        lowered.extend(probing_second(&mut c, thin(20_000), fresh(764, 93.9, 107)));
        assert!(
            lowered.last().is_some_and(|&k| k < ceiling / 2),
            "the target stayed up after a loss brake: {lowered:?}, evidence {}",
            c.capacity_kbps()
        );

        // A refused send is offered again on the next tick, not lost.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        for (estimate, rtt) in [(690, 212), (700, 211), (710, 214), (700, 213)] {
            one_second(&mut c, thin(estimate), fresh(rtt, 0.0, 0));
        }
        let offered = c
            .take_probe_target()
            .expect("the evidence moved the target");
        c.tick(thin(700)(&c), TICK);
        assert_eq!(
            c.take_probe_target(),
            Some(offered),
            "not confirmed sent, so offered again"
        );
    }

    /// While the receiver says a thin path is full (drain mode, or a brake its reports set, until
    /// it has let go) str0m is told [`PROBE_QUIET_KBPS`] on the tick that is decided and nothing
    /// more while it lasts; the probe target returns on the tick it ends (drain mode's end, or the
    /// tick the brake lets go). See [`PROBE_QUIET_KBPS`] and [`QualityController::probe_quiet`].
    #[test]
    fn a_path_the_receiver_calls_full_is_not_probed() {
        let mut c = on_3g_before_the_stall();
        let target = c.probe_target_kbps();
        assert!(target > PROBE_QUIET_KBPS);
        c.probe_target_sent(target);
        assert_eq!(c.probe_quiet(), None);

        // A recorded 3G stall's first reports: drain mode, and the probing stops at once.
        let mut sent = probing_second(&mut c, |c| three_g(c, 293, 250), fresh(4_752, 0.0, 0));
        sent.extend(probing_second(
            &mut c,
            |c| three_g(c, 293, 250),
            fresh(6_607, 0.0, 0),
        ));
        assert!(c.draining());
        assert_eq!(c.probe_quiet(), Some("drain"));
        assert_eq!(sent.last(), Some(&PROBE_QUIET_KBPS), "{sent:?}");
        let more = probing_second(&mut c, draining_tick, fresh(3_100, 0.0, 0));
        assert!(more.is_empty(), "nothing more while it lasts: {more:?}");

        // Drained: the resume's ceiling is not the receiver's word, so the target is back.
        let back = probing_second(&mut c, draining_tick, fresh(700, 0.0, 0));
        assert!(!c.draining());
        assert_eq!(c.brake_state(), "holding");
        assert_eq!(c.probe_quiet(), None);
        assert_eq!(back, vec![c.probe_target_kbps()]);

        // Clean reports release the drain's ceiling: that brake gone, a report of real loss engages
        // the receiver's own brake, and str0m probes nothing ...
        let mut seconds = 0;
        while c.brake_state() != "-" {
            assert!(seconds < 60, "the drain's resume ceiling never let go");
            probing_second(&mut c, |c| three_g(c, 290, 200), fresh(600, 0.0, 0));
            seconds += 1;
        }
        assert!(c.probe_path_thin(), "a 3G path is under the floor");
        let quiet = probing_second(&mut c, |c| three_g(c, 290, 280), fresh(620, 15.0, 9));
        assert_eq!(c.brake_state(), "engaged");
        assert_eq!(c.probe_quiet(), Some("brake-loss"));
        assert_eq!(quiet, vec![PROBE_QUIET_KBPS]);
        // ... through its release, the clean reports included ...
        let mut sent = probing_second(&mut c, |c| three_g(c, 290, 200), fresh(600, 0.0, 0));
        assert_eq!(c.brake_state(), "releasing");
        assert_eq!(c.probe_quiet(), Some("brake-loss"));
        // ... until it has let go, and then the target goes back on that tick.
        let mut seconds = 0;
        while c.brake_state() != "-" {
            assert!(seconds < 60, "the brake never let go");
            sent.extend(probing_second(
                &mut c,
                |c| three_g(c, 290, 200),
                fresh(600, 0.0, 0),
            ));
            seconds += 1;
        }
        assert_eq!(c.probe_quiet(), None);
        assert_eq!(
            sent,
            vec![c.probe_target_kbps()],
            "one send, when it let go"
        );
    }

    /// A brake on a wide path holds nothing: str0m's probes are how the estimate finds its room
    /// again after a dip. A recorded Wi-Fi link at 10.4 Mbps, then a report of 25% loss.
    #[test]
    fn a_brake_on_a_wide_path_does_not_stop_the_probing() {
        let mut c = on_wifi_at_1080p60();
        assert!(!c.probe_path_thin());
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(292, 24.7, 11),
        );
        assert_eq!(c.brake_state(), "engaged");
        assert_eq!(c.probe_quiet(), None);
        assert_ne!(c.take_probe_target(), Some(PROBE_QUIET_KBPS));
    }

    /// The opening is never quiet: str0m's opening probes and a path re-probe need the ceiling,
    /// whatever the receiver says in those seconds (see [`PROBE_OPENING`]).
    #[test]
    fn the_opening_is_never_quiet() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let ceiling = desired_bitrate_kbps(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        // Media flowing and a report of heavy loss inside the opening's three seconds.
        let sent = probing_second(&mut c, |c| opening_keyframe(c, 600), fresh(300, 30.0, 20));
        assert!(c.probe_opening());
        assert_eq!(c.brake_state(), "engaged");
        assert_eq!(c.probe_quiet(), None);
        assert!(sent.is_empty(), "the ceiling stands: {sent:?}");
    }

    /// One tick of `fb`, taking and confirming the probe target as the control task does: what
    /// went out on it, if anything.
    fn probing_tick(c: &mut QualityController, fb: Feedback) -> Option<u32> {
        c.tick(fb, TICK);
        let sent = c.take_probe_target();
        if let Some(kbps) = sent {
            c.probe_target_sent(kbps);
        }
        sent
    }

    /// A still screen's opening, as str0m 0.24 sees it: the estimate as given, the encoder sending
    /// little — under the loaded band, so nothing here is capacity evidence until a test says so.
    fn opening_still(c: &QualityController, estimate_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: 150,
            egress_kbps: 200,
            qp_samples: 3,
            queue_age_ms: 0,
            avg_qp: Some(24.0),
            encode_ms: 2.0,
            spend_ratio: 0.2,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// The opening keyframe's tick: [`opening_still`] with the frame leaving, which is media (over
    /// [`MEDIA_EGRESS_KBPS`]) and so starts the probe opening's clock.
    fn opening_keyframe(c: &QualityController, estimate_kbps: u32) -> Feedback {
        Feedback {
            egress_kbps: 2_000,
            ..opening_still(c, estimate_kbps)
        }
    }

    /// Runs `fb` tick by tick until the probe opening is over, taking and confirming every probe
    /// target as the control task does. Returns the ticks it took and what was sent.
    fn through_the_probe_opening(
        c: &mut QualityController,
        fb: impl Fn(&QualityController) -> Feedback,
    ) -> (u32, Vec<u32>) {
        let mut ticks = 0;
        let mut sent = Vec::new();
        while c.probe_opening() {
            assert!(ticks < 100, "the opening never ended");
            let f = fb(c);
            sent.extend(probing_tick(c, f));
            ticks += 1;
        }
        (ticks, sent)
    }

    /// Through a session's opening the probe target is the ladder's ceiling, for every source the
    /// ladder prices: str0m's two opening probes (3x and 6x of 600) and the exponential probing
    /// after them are held to twice it ([`PROBE_OPENING`]). The opening's clock runs on media and
    /// ends three seconds in, with the following target sent on that tick. At the floor instead
    /// (1227 on 16:9), str0m's second opening probe would go out at 2454 instead of 3600.
    #[test]
    fn the_probe_target_is_the_ceiling_through_the_opening() {
        for (w, h) in [
            (1620, 1080),
            (1920, 1080),
            (2880, 1780),
            (3840, 2160),
            (5120, 1440),
        ] {
            for q in [Quality::Best, Quality::Balanced, Quality::Low] {
                let c = QualityController::new(w, h, q);
                let opening = opening_probe_target_kbps(w, h, q);
                assert!(c.probe_opening(), "{w}x{h} {q:?}");
                assert_eq!(c.probe_target_kbps(), opening, "{w}x{h} {q:?}");
                assert_eq!(opening, desired_bitrate_kbps(w, h, q), "{w}x{h} {q:?}");
                assert!(
                    2 * opening >= 6 * STR0M_OPENING_KBPS,
                    "{w}x{h} {q:?}: str0m's second opening probe (3600) goes out as it is"
                );
            }
        }
        assert!(
            QualityController::new(0, 0, Quality::Balanced).probe_target_kbps() >= MIN_DESIRED_KBPS,
            "a degenerate source still probes"
        );

        let ceiling = desired_bitrate_kbps(1620, 1080, Quality::Balanced);
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));

        // Connection setup: ICE and DTLS traffic, no media. The clock does not run, however long it
        // takes — str0m's opening probes go out when DTLS is up.
        for _ in 0..25 {
            let fb = opening_still(&c, 600);
            assert_eq!(probing_tick(&mut c, fb), None);
        }
        assert!(
            c.probe_opening(),
            "five seconds of setup: still the opening"
        );

        // The opening keyframe leaves and str0m's probes return one round per tick with no receiver
        // report yet; the target is the ceiling throughout, so nothing is sent.
        let fb = opening_keyframe(&c, 600);
        assert_eq!(probing_tick(&mut c, fb), None);
        for estimate in [1_800, 3_600, 7_200, 14_400] {
            let fb = opening_still(&c, estimate);
            assert_eq!(probing_tick(&mut c, fb), None);
            assert_eq!(c.probe_target_kbps(), ceiling);
        }
        // The estimate collapses (0.85 x acked on our quiet). The opening ends fifteen ticks in,
        // and twice the best estimate (not decayed) is past the ceiling: nothing to send.
        let (ticks, sent) = through_the_probe_opening(&mut c, |c| opening_still(c, 900));
        assert_eq!(5 + ticks, 15, "three seconds of media");
        assert_eq!(sent, Vec::<u32>::new());
        assert_eq!(c.probe_best_kbps(), 14_400);
        assert_eq!(c.probe_target_kbps(), ceiling);
        assert!(!c.probe_evidence_seen());
        assert_eq!(c.capacity_kbps(), 0);

        // A link that showed little: twice the best estimate goes out on the opening's last tick,
        // before str0m's first periodic probe can fire.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        let fb = opening_keyframe(&c, 600);
        assert_eq!(probing_tick(&mut c, fb), None);
        let (ticks, sent) = through_the_probe_opening(&mut c, |c| opening_still(c, 1_500));
        assert_eq!(1 + ticks, 15);
        assert_eq!(sent, vec![2 * 1_500], "the opening's end, on its tick");

        // Media that never flows: the opening ends ten seconds into the session regardless.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        let (ticks, sent) = through_the_probe_opening(&mut c, |c| opening_still(c, 600));
        assert_eq!(ticks, 50, "PROBE_OPENING_LATEST");
        assert_eq!(sent, vec![1_078], "the floor: nothing measured");
    }

    /// After the opening, before the path has produced any capacity evidence, the probe target is
    /// twice the best estimate seen, within the floor and the ceiling: str0m's opening 600 not
    /// counted; each rise sent on the tick it is decided while str0m's own probes climb; not
    /// lowered by a collapse; not raised by an estimate the receiver's silence or brake disowns.
    /// The evidence takes over at its first sample. At the ceiling instead, str0m 0.24's periodic
    /// probe would send 23.4 Mbps into a simulated 3G link every five seconds.
    #[test]
    fn before_any_capacity_evidence_the_probe_target_is_twice_the_best_estimate_seen() {
        let ceiling = desired_bitrate_kbps(1620, 1080, Quality::Balanced);
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));

        // str0m's opening 600 is our own configuration: twice it (1200) would be above this
        // panel's floor (1078), and the target leaves the opening for the floor.
        let fb = opening_keyframe(&c, 600);
        probing_tick(&mut c, fb);
        let (_, sent) = through_the_probe_opening(&mut c, |c| opening_still(c, 600));
        assert_eq!(sent, vec![1_078]);
        assert_eq!(c.probe_best_kbps(), 0, "the opening value is not counted");
        assert_eq!(c.probe_target_kbps(), 1_078);

        // A fat link: str0m's probes come back one exponential round per tick, no receiver report
        // yet. Each rise goes out on the tick it is decided, not a second later — 200 ms apart.
        let mut sent = Vec::new();
        for estimate in [1_800, 3_600, 7_200] {
            let fb = opening_still(&c, estimate);
            sent.push(probing_tick(&mut c, fb));
        }
        assert_eq!(
            sent,
            vec![Some(3_600), Some(7_200), Some(ceiling)],
            "twice the best estimate, at once, up to the ceiling"
        );
        assert!(!c.probe_evidence_seen());
        assert_eq!(c.capacity_kbps(), 0);

        // The estimate collapses (str0m's 0.85 x acked on our quiet): the best is not decayed, so
        // how far the path may be explored stays where the probes showed it.
        for _ in 0..10 {
            let fb = opening_still(&c, 900);
            assert_eq!(probing_tick(&mut c, fb), None);
        }
        assert_eq!(c.probe_target_kbps(), ceiling);

        // The first capacity evidence — the encoder fills the estimate and the link carries it —
        // takes over, as it always did: twice it, and down from the ceiling a second later.
        let loaded = |c: &QualityController| Feedback {
            egress_kbps: 2_700,
            produced_kbps: 2_600,
            spend_ratio: 0.95,
            ..opening_still(c, 3_000)
        };
        let mut sent = Vec::new();
        for _ in 0..10 {
            let fb = loaded(&c);
            sent.extend(probing_tick(&mut c, fb));
        }
        assert!(c.probe_evidence_seen());
        assert_eq!(c.probe_target_kbps(), 2 * c.capacity_kbps());
        assert_eq!(sent, vec![6_000], "{sent:?}");

        // The receiver's brake: an estimate that rises while a brake its reports set is in force is
        // not the link's word, and does not raise the bound — at the opening's end or after it.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        let fb = Feedback {
            egress_kbps: 400,
            report: fresh(212, 30.0, 40),
            ..opening_still(&c, 600)
        };
        c.tick(fb, TICK);
        assert!(c.brake_kbps().is_some(), "the fixture engages the brake");
        let (_, sent) = through_the_probe_opening(&mut c, |c| opening_still(c, 3_000));
        // At the opening's end the quiet value goes out: the brake still holds on a path shown no
        // wider (see [`PROBE_QUIET_KBPS`]). Behind it the target is the floor.
        assert_eq!(sent, vec![PROBE_QUIET_KBPS], "quiet under the brake");
        assert_eq!(c.probe_quiet(), Some("brake-loss"));
        assert_eq!(c.probe_best_kbps(), 0, "taken while braked");
        assert_eq!(c.probe_target_kbps(), 1_078);

        // The receiver's silence: the smoother walks the estimate up with nothing behind it, and
        // none of it is a measurement.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        let sending = |c: &QualityController, estimate: u32| Feedback {
            egress_kbps: 400,
            ..opening_still(c, estimate)
        };
        one_second(&mut c, |c| sending(c, 600), fresh(150, 0.0, 0));
        one_second(&mut c, |c| sending(c, 600), silent(150));
        assert!(!c.feedback_live(), "the fixture makes the feedback stale");
        let (_, sent) = through_the_probe_opening(&mut c, |c| sending(c, 600));
        assert_eq!(sent, vec![1_078]);
        for estimate in [3_000, 3_500, 4_000, 4_500] {
            let fb = sending(&c, estimate);
            assert_eq!(probing_tick(&mut c, fb), None);
        }
        assert_eq!(c.probe_best_kbps(), 0, "taken on stale feedback");
        assert_eq!(c.probe_target_kbps(), 1_078);

        // str0m 0.24's first estimate can already be a measurement: the opening probes came back
        // before the first tick and the smoother emitted their mean with the 600 (1521 in the
        // simulator's `smoke`, then nothing for three seconds). It is not the opening value, so it
        // counts at once.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        let fb = opening_keyframe(&c, 1_521);
        assert_eq!(probing_tick(&mut c, fb), None, "the opening");
        let (_, sent) = through_the_probe_opening(&mut c, |c| opening_still(c, 1_521));
        assert_eq!(sent, vec![2 * 1_521], "twice it when the opening ends");
        assert_eq!(c.probe_best_kbps(), 1_521);
    }

    /// In the first seconds of media on a path ([`PROBE_RAMP`]) a rise of the probe target goes out
    /// at once even with capacity evidence, while the estimate is at its highest with no brake or
    /// real loss; afterwards a rise waits out the second since the last send.
    #[test]
    fn in_the_first_seconds_a_clean_rise_goes_out_at_once_after_the_evidence() {
        let carried = |estimate: u32| {
            move |c: &QualityController| Feedback {
                estimate_kbps: estimate,
                drain_kbps: estimate * 11 / 10,
                produced_kbps: estimate * 85 / 100,
                egress_kbps: estimate * 9 / 10,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(33.0),
                encode_ms: 2.0,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            }
        };
        let ceiling = desired_bitrate_kbps(1620, 1080, Quality::Balanced);
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        // Connection setup at str0m's opening 600; then the opening, the link carrying 1200 and the
        // receiver clean: the evidence, and twice it when the opening ends.
        one_second(&mut c, |c| opening_still(c, 600), None);
        let mut sent = Vec::new();
        for _ in 0..3 {
            sent.extend(probing_second(&mut c, carried(1_200), fresh(60, 0.0, 0)));
        }
        assert!(c.probe_evidence_seen());
        assert!(!c.probe_opening());
        assert_eq!(sent, vec![2 * 1_200]);

        // str0m's probing finds more, a step a tick, the receiver clean: each rise goes out on its
        // tick, not a second after the last.
        let mut sent = Vec::new();
        for (i, estimate) in [1_600, 2_100, 2_800, 3_700].into_iter().enumerate() {
            let fb = Feedback {
                report: if i == 0 { fresh(60, 0.0, 0) } else { None },
                ..carried(estimate)(&c)
            };
            sent.push(probing_tick(&mut c, fb));
            assert_eq!(c.probe_ramp(), Ok(()), "{estimate}");
        }
        assert_eq!(
            sent,
            vec![Some(3_200), Some(4_200), Some(5_600), Some(7_400)],
            "twice the evidence, on every tick it rose a fifth"
        );

        // Not while the estimate is off its best, nor after real loss: those wait a second.
        let fb = carried(3_000)(&c);
        probing_tick(&mut c, fb);
        assert_eq!(c.probe_ramp(), Err("not-rising"));
        let fb = Feedback {
            report: fresh(60, 5.0, 4),
            ..carried(3_700)(&c)
        };
        probing_tick(&mut c, fb);
        assert_eq!(c.probe_ramp(), Err("loss"));

        // After the ramp's seconds on this path, a rise waits for the second, as before.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        one_second(&mut c, |c| opening_still(c, 600), None);
        for _ in 0..8 {
            probing_second(&mut c, carried(1_200), fresh(60, 0.0, 0));
        }
        assert!(c.probe_evidence_seen());
        assert_eq!(c.probe_ramp(), Err("over"));
        let mut sent = Vec::new();
        for (i, estimate) in [1_600, 2_100, 2_800, 3_700, 3_700].into_iter().enumerate() {
            let fb = Feedback {
                report: if i == 0 { fresh(60, 0.0, 0) } else { None },
                ..carried(estimate)(&c)
            };
            sent.push(probing_tick(&mut c, fb));
        }
        assert_eq!(
            sent.iter().flatten().count(),
            1,
            "at most once a second past the ramp: {sent:?}"
        );
    }

    /// The simulated 3G link with str0m 0.24 (`3g-0919`, seed 2): the estimate at 130-700 from the
    /// first second, real loss reported, and no capacity evidence for twenty-five seconds. A
    /// ceiling held until evidence would put str0m's periodic probe at 23.4 Mbps into a 700 kbps
    /// link behind 60 ms of buffer every five seconds. The ceiling is the opening's alone (three
    /// seconds, over before the first periodic probe), and after it the probe stays inside what
    /// that buffer holds (`PROBE_CAPACITY_MULTIPLE`).
    #[test]
    fn a_thin_link_with_no_capacity_evidence_is_not_probed_at_twice_the_ceiling() {
        let estimates = [
            632, 697, 697, 453, 219, 196, 156, 190, 232, 257, 284, 128, 128, 128, 128, 128, 213,
            237, 261, 289, 289, 305, 94, 94, 94,
        ];
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        one_second(&mut c, |c| opening_still(c, 600), None);
        assert!(c.probe_opening(), "no media yet");
        let mut sent = Vec::new();
        for (second, estimate) in estimates.into_iter().enumerate() {
            for kbps in probing_second(
                &mut c,
                |c| opening_still(c, estimate),
                // Real loss (over 2%), not enough for the brake (10%): never clean.
                fresh(260, 5.0, 4),
            ) {
                sent.push((second, kbps));
            }
        }
        assert!(
            !c.probe_evidence_seen(),
            "the fixture reproduces the session"
        );
        assert_eq!(c.probe_best_kbps(), 697);
        let target = c.probe_target_kbps();
        assert_eq!(target, 2 * 697);
        // The media starts with the first report; the ceiling is gone at the end of its third
        // second, and nothing above twice the best estimate went out after.
        assert_eq!(
            sent,
            vec![(2, 2 * 697)],
            "the opening's end, and nothing else"
        );
        // A 15 ms probe at P into a bottleneck of C holds (P - C) x 15 ms, which a 60 ms buffer
        // takes up to P = 5C; the periodic probe is twice the target.
        assert!(
            2 * target <= 700 * (1 + 60 / 15),
            "a periodic probe at {} kbps into a 700 kbps link",
            2 * target
        );
    }

    /// A burst that left the socket is capacity evidence once the receiver has reported on it and
    /// called it delivered, not on the tick it left. On a simulated 700 kbps 3G link a 1176 kbps
    /// window became evidence at once, a re-anchor followed, and the receiver answered with 96%
    /// loss.
    #[test]
    fn a_burst_is_capacity_evidence_only_once_the_receiver_has_reported_it_carried() {
        let three_g = |egress: u32| {
            move |c: &QualityController| Feedback {
                estimate_kbps: 340,
                drain_kbps: 374,
                produced_kbps: 280,
                egress_kbps: egress,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(36.0),
                encode_ms: 1.5,
                spend_ratio: 1.0,
                rung_fps_hint: c.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: None,
            }
        };
        let setup = || {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            for (i, rtt) in [212, 213, 211, 212, 214, 212].into_iter().enumerate() {
                let estimate = 320 + 5 * i as u32;
                let fb = move |c: &QualityController| Feedback {
                    estimate_kbps: estimate,
                    ..three_g(300)(c)
                };
                one_second(&mut c, fb, fresh(rtt, 0.0, 0));
            }
            // The burst, in the middle of a second.
            c.tick(
                Feedback {
                    report: fresh(212, 0.0, 0),
                    ..three_g(300)(&c)
                },
                TICK,
            );
            c.tick(three_g(1_176)(&c), TICK);
            assert!(
                c.capacity_kbps() < 500,
                "a burst taken as capacity on the tick it left: {}",
                c.capacity_kbps()
            );
            for _ in 0..3 {
                c.tick(three_g(300)(&c), TICK);
            }
            c
        };

        // Both reports after it clean: carried.
        let mut c = setup();
        one_second(&mut c, three_g(300), fresh(213, 0.0, 0));
        assert!(
            c.capacity_kbps() < 500,
            "one report is half the bracket: {}",
            c.capacity_kbps()
        );
        one_second(&mut c, three_g(300), fresh(212, 0.0, 0));
        assert!(
            c.capacity_kbps() >= 1_100,
            "two clean reports bracket the burst: {}",
            c.capacity_kbps()
        );

        // The next report lossy: never evidence.
        let mut c = setup();
        one_second(&mut c, three_g(300), fresh(230, 4.0, 6));
        for rtt in [212, 213, 212, 211] {
            one_second(&mut c, three_g(300), fresh(rtt, 0.0, 0));
        }
        assert!(
            c.capacity_kbps() < 500,
            "a burst the receiver lost: {}",
            c.capacity_kbps()
        );

        // An interval with no report after it: nobody described those packets, and later reports do
        // not vouch for them.
        let mut c = setup();
        one_second(&mut c, three_g(300), silent(212));
        for rtt in [212, 213, 212] {
            one_second(&mut c, three_g(300), fresh(rtt, 0.0, 0));
        }
        assert!(
            c.capacity_kbps() < 500,
            "a burst confirmed across a silence: {}",
            c.capacity_kbps()
        );
    }

    // ── the thin-link start ───────────────────────────────────────────────────────────────────

    /// One second of a session's opening, from the recorded estimate and egress.
    fn opening(
        c: &QualityController,
        estimate_kbps: u32,
        egress_kbps: u32,
        spend: f32,
    ) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            // Under egress, so the conservation check stays quiet: these tests are about the
            // startup decision and nothing else.
            produced_kbps: egress_kbps * 9 / 10,
            egress_kbps,
            qp_samples: 30,
            queue_age_ms: 0,
            avg_qp: Some(40.0),
            encode_ms: 3.0,
            spend_ratio: spend,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// Replay a session's opening seconds with each second's receiver report (by index, `None` if
    /// missing); return every move, its tick and why. `then_secs` repeats the last second.
    fn open_session(
        seconds: &[(u32, u32, f32)],
        reports: &[Option<ReceiverReport>],
        then_secs: usize,
    ) -> (QualityController, Vec<(u32, Rung, &'static str)>) {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut moves = Vec::new();
        let last = *seconds.last().expect("at least one second");
        let last_report = reports.last().copied().flatten();
        let mut tick = 0u32;
        for (i, &(estimate, egress, spend)) in seconds
            .iter()
            .chain(std::iter::repeat_n(&last, then_secs))
            .enumerate()
        {
            let report = if i < seconds.len() {
                reports.get(i).copied().flatten()
            } else {
                last_report
            };
            for t in 0..5 {
                tick += 1;
                let fb = Feedback {
                    report: if t == 0 { report } else { None },
                    ..opening(&c, estimate, egress, spend)
                };
                if let Some(r) = c.tick(fb, TICK) {
                    moves.push((tick, r, c.last_move_reason()));
                }
            }
        }
        (c, moves)
    }

    /// A fresh report with no round trip in it: str0m had a receiver report but no RTT yet.
    fn fresh_no_rtt(loss_pct: f32) -> Option<ReceiverReport> {
        Some(ReceiverReport {
            rtt_ms: None,
            loss: Some(loss_pct / 100.0),
            nacks: 0,
        })
    }

    /// A stats interval with no round trip and no report: str0m's stream has sent RTP, nothing
    /// has come back yet. Media evidence, nothing else.
    fn stats_only() -> Option<ReceiverReport> {
        Some(ReceiverReport {
            rtt_ms: None,
            loss: None,
            nacks: 0,
        })
    }

    /// A recorded 3G link: never above 726 in its first eight seconds, 929 overall. The ladder took
    /// thirteen seconds to walk from 1080p@60 to 720p through three keyframes at 1-3 fps with the
    /// viewer's jitter buffer at 1137 ms. Measured and reported thin, it is now jumped once.
    ///
    /// The receiver's reports, per second: 351 (0.59%, 5 NACKs), 212, 212, 211, 214, 243, then 431
    /// (past twice the least seen) and then 25.6% loss.
    #[test]
    fn a_link_measured_thin_is_jumped_to_its_rung_in_one_move() {
        let three_g = [
            (600, 25, 1.14),
            (517, 522, 0.9),
            (640, 529, 0.71),
            (640, 330, 0.8),
            (640, 324, 0.91),
            (360, 471, 0.83),
            (657, 583, 0.77),
            (726, 844, 0.9),
            (726, 601, 0.9),
            (726, 817, 0.9),
            (603, 760, 0.9),
        ];
        let reports = [
            None,
            None,
            fresh(351, 0.59, 5),
            fresh(212, 0.0, 0),
            fresh(212, 0.0, 0),
            fresh(211, 0.0, 0),
            fresh(214, 0.0, 0),
            fresh(243, 0.0, 0),
            fresh(431, 0.0, 1),
            fresh(226, 25.62, 10),
            fresh(225, 0.0, 3),
        ];
        let (c, moves) = open_session(&three_g, &reports, 5);
        let &(tick, rung, _) = moves.first().expect("a thin link must be moved");
        // Media from the second second (522 kbps; the first second's 25 kbps is connection setup),
        // and the window is eight seconds of media.
        assert_eq!(
            tick,
            5 + (STARTUP_DECIDE_AFTER.as_millis() / TICK.as_millis()) as u32,
            "at the end of the startup window and not before: before it, LTE looks the same"
        );
        assert_eq!(
            rung,
            Rung {
                max_h: 720,
                fps: 30
            },
            "726 kbps pays for 720p at its desktop price with headroom (662), not 900p (1020)"
        );
        assert_eq!(moves.len(), 1, "one move, one keyframe: {moves:?}");
        assert_eq!(c.last_move_reason(), "startup-thin");
    }

    /// The jump waits for the last move's keyframe, as every other decision does. On the 3G
    /// recording the ordinary ladder stepped to 900p a quarter of a second before the startup
    /// window closed; here that step is forced at 7.0 s by an encoder too slow for 60 fps, and the
    /// jump must come when its settle ends, not on top of its IDR.
    #[test]
    fn the_startup_jump_waits_out_the_last_moves_settle() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut moves = Vec::new();
        for tick in 1..=80u32 {
            let second = (tick - 1) / 5;
            let (estimate, egress) = if second == 0 { (600, 25) } else { (700, 600) };
            // The receiver's evidence that the link is thin: a round trip past twice the least
            // seen, once, at 6 s — a queue, which is what makes the low estimate a thin link.
            let report = match ((tick - 1) % 5, second) {
                (0, 0) => None,
                (0, 6) => fresh(560, 0.0, 0),
                (0, _) => fresh(250, 0.0, 0),
                _ => None,
            };
            let fb = Feedback {
                // Past the 12.5 ms a 60 fps rung allows from 5 s on, inside the 25 ms of 30 fps.
                encode_ms: if second >= 5 { 20.0 } else { 3.0 },
                report,
                ..opening(&c, estimate, egress, 0.9)
            };
            if let Some(r) = c.tick(fb, TICK) {
                moves.push((tick, r, c.last_move_reason()));
            }
        }
        let settle_ticks = (SETTLE_AFTER_MOVE.as_millis() / TICK.as_millis()) as u32;
        assert_eq!(moves.len(), 2, "{moves:?}");
        let (first, rung, why) = moves[0];
        assert_eq!((rung.max_h, rung.fps, why), (1080, 30, "down"), "{moves:?}");
        let (second, rung, why) = moves[1];
        assert_eq!(
            (rung.max_h, rung.fps, why),
            (720, 30, "startup-thin"),
            "{moves:?}"
        );
        assert!(
            second > first + settle_ticks,
            "jumped at tick {second}, inside the settle of the move at tick {first}"
        );
    }

    /// The LTE and Wi-Fi openings of the same recording must not be moved. LTE read 441-671 for six
    /// seconds, then 1355 and 3245; Wi-Fi 1122 in its first second. Asserted twice for LTE: as
    /// recorded, and without the probe that found 3245, since 1355 alone must suffice.
    #[test]
    fn the_lte_and_wifi_openings_stay_at_the_top() {
        let lte_open = [
            (600, 62, 0.0),
            (441, 325, 0.02),
            (512, 635, 2.93),
            (538, 169, 0.01),
            (565, 230, 0.38),
            (671, 594, 0.44),
            (1_355, 1_012, 1.14),
            (3_245, 1_247, 0.49),
            (3_245, 1_145, 0.46),
            (3_245, 1_140, 0.59),
        ];
        // Its round trip, 08:09:24 on: 250, 250, 248, 250, 250, 249, 247 — flat.
        let lte_reports = [
            None,
            fresh(250, 0.0, 0),
            fresh(250, 0.0, 0),
            fresh(248, 0.0, 0),
            fresh(250, 0.0, 0),
            fresh(250, 0.0, 0),
            fresh(249, 0.0, 0),
            fresh(247, 0.0, 0),
            fresh(251, 0.0, 0),
            fresh(250, 0.0, 0),
        ];
        let (c, moves) = open_session(&lte_open, &lte_reports, 20);
        assert!(moves.is_empty(), "LTE was moved: {moves:?}");
        assert_eq!(c.current(), LADDER[0]);

        let mut no_probe = lte_open;
        for s in &mut no_probe[7..] {
            s.0 = 1_355;
        }
        let (_, moves) = open_session(&no_probe, &lte_reports, 20);
        assert!(
            moves.is_empty(),
            "1355 affords 900p, which is not thin — and LTE was moved: {moves:?}"
        );

        let wifi_open = [
            (1_122, 647, 8.18),
            (1_845, 2_180, 1.14),
            (1_938, 1_263, 0.75),
            (1_938, 1_150, 0.64),
            (2_036, 1_222, 0.69),
            (2_190, 1_420, 0.58),
            (4_902, 1_167, 0.34),
            (4_902, 2_426, 0.89),
        ];
        let (_, moves) = open_session(&wifi_open, &[], 20);
        assert!(moves.is_empty(), "WiFi was moved: {moves:?}");
    }

    /// A low estimate on a quiet receiver is a slow start, not a thin link.
    ///
    /// A recorded LTE opening on a still screen: the estimate at 244-532 for twenty seconds while
    /// every report said clean (round trip 373-382, loss 0 bar one NACK-recovered 1.26%); a probe
    /// later measured 3270 and the session ran 1080p60 on 5-8 Mbps. The encoder is shown spending,
    /// so the decision rests on the receiver's evidence; the second half shows the same opening
    /// with one queue reported is jumped.
    #[test]
    fn a_slow_start_on_a_quiet_receiver_is_not_a_thin_link() {
        let lte = [
            (600, 16, 0.9),
            (600, 355, 0.9),
            (358, 434, 0.9),
            (416, 465, 0.9),
            (459, 112, 0.9),
            (507, 78, 0.9),
            (532, 647, 0.9),
            (244, 330, 0.9),
            (270, 396, 0.9),
            (313, 133, 0.9),
            (396, 210, 0.9),
            (445, 292, 0.9),
            (352, 379, 0.9),
            (257, 322, 0.9),
            (271, 238, 0.9),
        ];
        let quiet = [
            None,
            stats_only(),
            fresh(378, 0.0, 0),
            fresh(379, 0.0, 0),
            fresh(377, 0.0, 0),
            fresh(377, 0.0, 0),
            fresh(377, 0.0, 0),
            fresh(374, 0.0, 0),
            fresh(377, 0.0, 0),
            fresh(376, 0.0, 0),
            silent(376),
            fresh(373, 0.0, 0),
            fresh(382, 0.0, 0),
            fresh(379, 0.0, 0),
            fresh(378, 0.0, 0),
        ];
        let (c, moves) = open_session(&lte, &quiet, 10);
        assert!(
            moves.iter().all(|m| m.2 != "startup-thin"),
            "jumped on a slow start the receiver called clean: {moves:?}"
        );
        assert_eq!(c.current(), LADDER[0], "{moves:?}");

        // The same, with one report of a queue past twice the least seen: now the receiver says
        // the link is thin, and the estimate agrees.
        let mut queued = quiet;
        queued[7] = fresh(760, 0.0, 0);
        let (_, moves) = open_session(&lte, &queued, 10);
        assert!(
            moves
                .iter()
                .any(|m| m.2 == "startup-thin" && m.1.max_h < 900),
            "a thin estimate with a queue at the far end must still be jumped: {moves:?}"
        );
    }

    /// Connection-setup traffic is not media, and nothing may be decided on it.
    ///
    /// A recorded LTE session that never connected: str0m's opening 600 kbps and 0-22 kbps of ICE
    /// and TURN traffic for twenty seconds, no receiver stats (no RTP was ever sent), the encoder
    /// producing 13-951 kbps into nothing. Read as "bytes have left", that shed two rungs on
    /// `growing` and then jumped to 540p on `startup-thin`.
    #[test]
    fn connection_setup_traffic_is_not_media() {
        let egress = [
            20, 22, 14, 0, 14, 0, 0, 14, 0, 0, 14, 0, 0, 14, 0, 0, 14, 0, 0,
        ];
        let produced = [
            951, 216, 13, 229, 303, 64, 156, 551, 165, 348, 355, 119, 24, 36, 25, 27, 31, 27, 37,
        ];
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let price = c.current_required_kbps();
        for (&egress_kbps, &produced_kbps) in egress.iter().zip(&produced) {
            let moved = one_second(
                &mut c,
                |c| Feedback {
                    produced_kbps,
                    spend_ratio: produced_kbps as f32 / 540.0,
                    avg_qp: Some(44.0),
                    ..opening(c, 600, egress_kbps, 0.9)
                },
                None,
            );
            assert_eq!(moved, None, "moved on {egress_kbps} kbps of ICE traffic");
        }
        assert_eq!(c.current(), LADDER[0]);
        assert_eq!(
            c.encoder_target_kbps(),
            price,
            "and the budget is still the opening bid: nothing has been measured"
        );
    }

    /// A recorded 3G opening is still jumped, on the receiver's word.
    ///
    /// str0m's opening 600 with 0-41 kbps of setup traffic, media four seconds in, then an estimate
    /// of 161-204 and round trips of 1001, 1004, 2020 (twice the least) and 3857, where the brake
    /// engaged. 360p was right on that link.
    ///
    /// The path was holding a backlog (3857, 3852, 3867, then 6020), and 3857 is the second report
    /// past the drain line, so drain mode begins there. A drained path reports its backlog
    /// shrinking, which is what is replayed (2600, 1500, then 900 under the exit band). The startup
    /// clock stands still through the drain, and the jump still comes after the resume's settle.
    #[test]
    fn a_3g_opening_is_still_jumped() {
        let three_g = [
            (600, 0, 0.9),
            (600, 4, 0.9),
            (600, 20, 0.9),
            (600, 41, 0.9),
            (600, 243, 0.9),
            (161, 481, 0.9),
            (170, 1_084, 0.9),
            (170, 1_165, 0.9),
            (202, 357, 0.9),
            (204, 96, 0.9),
            (178, 283, 0.9),
            (178, 109, 0.9),
            (178, 98, 0.9),
            (178, 94, 0.9),
            (178, 31, 0.9),
            (198, 470, 0.9),
            (198, 71, 0.9),
        ];
        let reports = [
            None,
            None,
            None,
            None,
            stats_only(),
            fresh_no_rtt(0.0),
            fresh(1_001, 0.0, 0),
            fresh(1_004, 0.0, 0),
            fresh(2_020, 0.0, 0),
            silent(2_022),
            fresh(3_857, 0.0, 0),
            // From here the path is drained rather than fed: see the doc comment.
            fresh(2_600, 0.0, 0),
            fresh(1_500, 0.0, 0),
            fresh(900, 0.0, 0),
            silent(900),
            fresh(880, 0.0, 0),
            fresh(870, 0.0, 0),
        ];
        let (c, moves) = open_session(&three_g, &reports, 5);
        assert!(!c.draining(), "the drain must have ended on 900 ms");
        let jump = moves
            .iter()
            .find(|m| m.2 == "startup-thin")
            .unwrap_or_else(|| panic!("the 3G opening must still be jumped: {moves:?}"));
        assert_eq!(jump.1.max_h, 360, "{moves:?}");
    }

    /// str0m's configured opening estimate is not a measurement, and must not price the jump.
    ///
    /// A recorded 3G session read 600 for four seconds (`INITIAL_BITRATE_KBPS`, echoed before any
    /// feedback) and 161-204 after. Here the receiver reports one queue and no brake, so the peak
    /// alone decides: 204 affords 360p@15, and a "peak" of 600 would buy 540p on a link carrying a
    /// third of that.
    #[test]
    fn the_opening_estimate_does_not_price_the_startup_jump() {
        let mut seconds = vec![(600, 0, 0.9), (600, 12, 0.9), (600, 400, 0.9)];
        seconds.extend([
            (190, 250, 0.9),
            (204, 250, 0.9),
            (198, 250, 0.9),
            (180, 250, 0.9),
        ]);
        seconds.extend([(190, 250, 0.9), (195, 250, 0.9)]);
        let reports = [
            None,
            None,
            stats_only(),
            fresh(1_000, 0.0, 0),
            fresh(1_002, 0.0, 0),
            fresh(1_001, 0.0, 0),
            fresh(2_100, 0.0, 0),
            fresh(1_003, 0.0, 0),
            fresh(1_002, 0.0, 0),
        ];
        let (c, moves) = open_session(&seconds, &reports, 8);
        let jump = moves
            .iter()
            .find(|m| m.2 == "startup-thin")
            .unwrap_or_else(|| panic!("a thin link the receiver called congested: {moves:?}"));
        assert_eq!(
            (jump.1.max_h, jump.1.fps),
            (360, 15),
            "priced from 204, the most the link was measured at: {moves:?}"
        );
        assert_eq!(
            c.brake_kbps(),
            None,
            "no brake capped it: the peak alone decided"
        );
    }

    /// A still screen at the start of a session is not a thin link, and the decision is taken once.
    ///
    /// A recorded still-desktop opening: egress 50-650 kbps, the encoder spending nothing, the
    /// estimate at 541-641 for five seconds, describing our silence. Once the window has closed
    /// without a verdict, a thin estimate later is the ordinary ladder's to judge. The receiver
    /// reports a queue once (second 6), so the refusal is the still screen's.
    #[test]
    fn a_still_opening_is_not_thin_and_the_window_closes() {
        let reports = [
            None,
            fresh(300, 0.0, 0),
            fresh(300, 0.0, 0),
            fresh(301, 0.0, 0),
            fresh(300, 0.0, 0),
            fresh(302, 0.0, 0),
            fresh(700, 0.0, 0),
            fresh(300, 0.0, 0),
            fresh(300, 0.0, 0),
            fresh(300, 0.0, 0),
        ];
        let still = [
            (541, 139, 0.0),
            (541, 54, 0.0),
            (541, 652, 0.0),
            (641, 637, 0.02),
            (641, 48, 0.0),
            (641, 380, 0.0),
            (600, 51, 0.0),
            (600, 63, 0.0),
            (600, 47, 0.0),
            (600, 47, 0.0),
        ];
        let (mut c, moves) = open_session(&still, &reports, 5);
        assert!(
            moves.is_empty(),
            "a still opening was judged thin: {moves:?}"
        );

        // The screen comes alive on a thin link after the window: not the startup rule's call.
        for _ in 0..(20 * 5) {
            let fb = opening(&c, 700, 650, 0.9);
            assert_eq!(c.tick(fb, TICK), None, "the startup decision is made once");
        }
    }

    /// One quiet window of the pacer is not a narrow link, and it must not collapse the budget.
    ///
    /// The exploration bound is `demonstrated x 1.5 + margin`. The pacer drains on its own clock,
    /// so a single 200 ms window of egress can have a gap that would halve or quarter the budget
    /// while the estimate is fine; recorded four times in one session, each pinning QP at 46 on
    /// 1080p video (see [`EGRESS_WINDOW`]):
    ///
    /// ```text
    /// 21:35:16 est 3152 bud 2836   ->   21:35:17 est 3045 bud 295
    /// ```
    #[test]
    fn a_single_quiet_pacer_window_does_not_collapse_the_budget() {
        let busy = |c: &QualityController, egress_kbps: u32| Feedback {
            estimate_kbps: 3_000,
            drain_kbps: 3_300,
            produced_kbps: 2_000,
            egress_kbps,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(30.0),
            encode_ms: 4.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        };

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..20 {
            let fb = busy(&c, 2_000);
            c.tick(fb, TICK);
        }
        // `min(estimate, 2000 x 1.5 + 300) x 0.9`, which is the estimate's own 90% here.
        let floor = (2_000 * 3 / 2 + EXPLORE_MARGIN_KBPS).min(3_000) * SPEND_PCT as u32 / 100;
        let settled = c.encoder_target_kbps();
        assert!(settled >= floor, "settled at {settled}, under {floor}");

        let fb = busy(&c, 49);
        c.tick(fb, TICK);
        let during = c.encoder_target_kbps();
        assert!(
            during >= floor,
            "one 200 ms window with 49 kbps of egress took the budget to {during}; the \
             instantaneous rule gives (49 x 1.5 + 300) x 0.9 = 336 on a 3 Mbps estimate"
        );

        let fb = busy(&c, 2_000);
        c.tick(fb, TICK);
        let after = c.encoder_target_kbps();
        assert!(after >= floor, "and the tick after reads {after}");
    }

    #[test]
    fn the_budget_spends_what_a_fat_link_offers() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let rung_price = c.current_required_kbps();
        run(&mut c, |c| healthy(c.current().fps as f32), 1.0);
        assert!(
            c.encoder_target_kbps() > rung_price,
            "a link with room must be spent"
        );
        assert!(c.encoder_target_kbps() <= LADDER[0].absorbable_kbps(1620, 1080));
    }

    #[test]
    fn the_queue_pushes_the_budget_back_continuously_and_never_to_zero() {
        // libwebrtc's CongestionWindowPushback shape: a multiplier, bounded, never zero (a zero
        // budget is a freeze), and continuous (a step would strobe). The denominator is a constant:
        // a credit that grows with the frames it meters makes the ratio blind to frame size.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut prev = u32::MAX;
        for ms in [0u32, 75, 150, 300, 600, 5_000] {
            run(
                &mut c,
                |c| Feedback {
                    queue_age_ms: ms,
                    ..healthy(c.current().fps as f32)
                },
                0.4,
            );
            let b = c.encoder_target_kbps();
            assert!(b <= prev, "a longer queue must not raise the budget");
            assert!(b >= ABSOLUTE_FLOOR_KBPS, "and must never reach zero");
            prev = b;
        }
    }

    // ── pinning ───────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_pin_holds_the_resolution_and_gives_up_frames_instead() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let pinned = c.set_pinned_height(Some(1080)).expect("a change");
        assert_eq!(pinned.max_h, 1080);
        run(
            &mut c,
            |c| Feedback {
                ..congested(c.current().fps as f32)
            },
            120.0,
        );
        assert_eq!(c.current().max_h, 1080, "the pin must hold");
        assert!(c.current().fps < 30, "frames are what give way");
    }

    #[test]
    fn every_offered_resolution_has_room_to_adapt() {
        for &h in PINNABLE_HEIGHTS {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            c.set_pinned_height(Some(h));
            run(&mut c, |c| congested(c.current().fps as f32), 120.0);
            assert_eq!(c.current().max_h, h);
            assert!(c.current().fps < 30, "{h}p must be able to shed frames");
        }
    }

    /// The `ladder arms` line names the arms, in a fixed order, and says `-` for none.
    #[test]
    fn the_arms_line_names_the_arms() {
        let mut a = Arms::default();
        assert_eq!(a.names(), "-");
        a.set(Arms::BRAKING, true);
        a.set(Arms::GROWING, true);
        a.set(Arms::STARVED, false);
        assert_eq!(a.names(), "growing+braking");
    }

    #[test]
    fn setting_the_same_pin_twice_changes_nothing() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        assert!(c.set_pinned_height(Some(720)).is_some());
        assert!(c.set_pinned_height(Some(720)).is_none());
        assert!(c.set_pinned_height(None).is_some());
        assert!(c.set_pinned_height(None).is_none());
    }

    /// Pin and unpin on a profile's own ladders: a pin opens at the top of its pinned ladder, and
    /// unpinning opens the curated ladder at `start_rung_index`, not at the top.
    #[test]
    fn pin_and_unpin_open_where_the_profile_says() {
        let ladder = vec![
            Rung {
                max_h: 1080,
                fps: 30,
            },
            Rung {
                max_h: 720,
                fps: 30,
            },
            Rung {
                max_h: 360,
                fps: 15,
            },
        ];
        let policy = QualityPolicy {
            ladder: ladder.clone(),
            start_rung_index: 1,
            pinned_fps: vec![24, 12],
            ..QualityPolicy::reference()
        };
        assert_eq!(policy.validate(), Ok(()));
        let mut c = QualityController::with_policy(1920, 1080, Quality::Balanced, policy);
        assert_eq!(
            c.current(),
            ladder[1],
            "a session opens at start_rung_index"
        );
        assert_eq!(
            c.set_pinned_height(Some(540)),
            Some(Rung {
                max_h: 540,
                fps: 24
            }),
            "a pin opens at its best frame rate"
        );
        // Shed the pinned ladder's frames, then hand the choice back.
        run(&mut c, |c| congested(c.current().fps as f32), 30.0);
        assert_eq!(
            c.current(),
            Rung {
                max_h: 540,
                fps: 12
            },
            "the pinned ladder is the profile's"
        );
        assert_eq!(
            c.set_pinned_height(None),
            Some(ladder[1]),
            "unpinned, the ladder opens at start_rung_index again"
        );
    }

    /// A value of the profile is a value the controller decides by: a longer descent dwell holds the
    /// rung longer on the same congested link.
    #[test]
    fn a_profile_value_changes_a_decision() {
        let first_move = |policy: QualityPolicy| {
            let mut c = QualityController::with_policy(1620, 1080, Quality::Balanced, policy);
            let start = c.current();
            (1..=300u32)
                .find(|_| {
                    let f = congested(c.current().fps as f32);
                    c.tick(f, TICK);
                    c.current() != start
                })
                .expect("a congested link moves the rung within a minute")
        };
        let reference = first_move(QualityPolicy::reference());
        let patient = first_move(QualityPolicy {
            down_after_ms: 6_000,
            ..QualityPolicy::reference()
        });
        assert!(
            patient > reference,
            "a 6 s dwell moves later than a 2 s one: tick {patient} against {reference}"
        );
    }

    /// A profile whose probe ceiling is under its top rung's climb price says so once per real
    /// source size (the first too, even when it equals the guess); the reference says nothing.
    #[test]
    fn a_ceiling_under_the_top_rungs_climb_price_is_said_once_per_source() {
        let rule = "rule=\"probe_ceiling_reaches_top_rung\"";
        let reference = QualityPolicy::reference();
        // At the least absorb and the most headroom the rules allow, the climb price is past the
        // ceiling.
        let short = QualityPolicy {
            up_headroom: 4.0,
            absorb_ratio: f64::from(reference.quality_ratio_best),
            ..reference.clone()
        };
        assert_eq!(short.validate(), Ok(()));

        let log = crate::quality_policy::log_capture::start();
        let mut c = QualityController::with_policy(1920, 1080, Quality::Balanced, short);
        c.set_source(1920, 1080);
        c.set_source(1920, 1080);
        c.set_source(2560, 1440);
        let text = log.text();
        assert_eq!(text.matches(rule).count(), 2, "{text}");
        assert!(text.contains("source=1920x1080"), "{text}");
        assert!(text.contains("source=2560x1440"), "{text}");

        let log = crate::quality_policy::log_capture::start();
        let mut c = QualityController::with_policy(1920, 1080, Quality::Balanced, reference);
        for (w, h) in [(1920, 1080), (2560, 1440), (1280, 720), (3840, 2160)] {
            c.set_source(w, h);
        }
        let text = log.text();
        assert_eq!(text.matches(rule).count(), 0, "{text}");
    }

    /// A profile at either corner of the contract runs the controller for minutes of congested,
    /// still, lossy and clean feedback, pins, source changes and a hold, without a panic (a debug
    /// build checks every overflow).
    #[test]
    fn a_profile_at_a_corner_of_the_contract_runs_without_a_panic() {
        for at_max in [false, true] {
            let policy = crate::quality_policy::corner_profile(at_max);
            for (w, h) in [(1920, 1080), (640, 360), (3840, 2160)] {
                let mut c = QualityController::with_policy(w, h, Quality::Balanced, policy.clone());
                c.probe_target_sent(opening_probe_target_kbps_with(
                    &policy,
                    w,
                    h,
                    Quality::Balanced,
                ));
                // Four minutes, a phase a minute, 5 ticks a second.
                for t in 0..(4 * 60 * 5u32) {
                    let fps = c.current().fps as f32;
                    let fb = match t / 300 {
                        0 => congested(fps),
                        1 => gone_still(&c, 300),
                        // A report a second: lossy and late, then clean.
                        2 => Feedback {
                            report: if t % 5 == 0 {
                                fresh(250, 35.0, 80)
                            } else {
                                None
                            },
                            ..healthy(fps)
                        },
                        _ => Feedback {
                            report: if t % 5 == 0 { fresh(30, 0.0, 0) } else { None },
                            ..healthy(fps)
                        },
                    };
                    let _ = c.tick(fb, TICK);
                    match t {
                        100 => {
                            let _ = c.set_pinned_height(Some(540));
                        }
                        400 => {
                            let _ = c.set_pinned_height(None);
                        }
                        500 => c.set_source(w / 2, h / 2),
                        700 => c.set_page_hidden(true),
                        760 => {
                            c.set_page_hidden(false);
                            c.resume_after_hold(Duration::from_secs(12), 200);
                        }
                        _ => {}
                    }
                    let _ = (
                        c.encoder_target_kbps(),
                        c.current_required_kbps(),
                        c.take_probe_target(),
                        c.take_bwe_reanchor(),
                        c.take_brake_event(),
                        c.take_drain_event(),
                    );
                }
                assert!(
                    policy.ladder.contains(&c.current())
                        || policy.pinned_fps.contains(&c.current().fps),
                    "{at_max} {w}x{h}: {:?}",
                    c.current()
                );
            }
        }
    }

    // ── the target ────────────────────────────────────────────────────────────────────────────

    #[test]
    fn target_paces_to_the_rung() {
        let t = QualityTarget::new(LADDER[0]);
        assert_eq!(
            t.fps(),
            60,
            "the top of the ladder is the 1080p60 bonus rung"
        );
        // 16 666, not 16 667: truncation is the safe direction. An interval slightly shorter than a
        // 60 Hz refresh admits every frame; slightly longer rejects every other one. See
        // `capture/src/wgc.rs`.
        assert_eq!(t.min_frame_interval(), Duration::from_micros(16_666));
        t.set(Rung {
            max_h: 1080,
            fps: 30,
        });
        assert_eq!(t.min_frame_interval(), Duration::from_micros(33_333));
        t.set(Rung { max_h: 360, fps: 8 });
        assert_eq!(t.max_h(), 360);
        assert_eq!(t.min_frame_interval(), Duration::from_micros(125_000));
    }

    #[test]
    fn target_reports_no_source_until_a_frame_arrives() {
        let t = QualityTarget::new(LADDER[0]);
        assert_eq!(t.source(), None);
        t.set_source(3600, 2400);
        assert_eq!(t.source(), Some((3600, 2400)));
        // A zero from a degenerate frame must not be mistaken for a real size — pricing against
        // 0x0 makes every rung free and pins the ladder at the top, silently.
        t.set_source(0, 0);
        assert_eq!(t.source(), Some((3600, 2400)));
    }

    #[test]
    fn the_capture_counters_are_taken_and_cleared() {
        let t = QualityTarget::with_outstanding(LADDER[0], Arc::new(AtomicU32::new(0)));
        t.note_offered();
        t.note_offered();
        t.note_early();
        assert_eq!(t.take_capture_counts(), (2, 1));
        assert_eq!(t.take_capture_counts(), (0, 0), "taking must clear");
    }

    // ── drain mode, silence on a thin link, and the startup queue ─────────────────────────────

    /// One tick on a recorded bufferbloated 3G path: `egress_kbps` leaving against an estimate of
    /// `estimate_kbps`, the encoder producing nine tenths of it and spending what it is given,
    /// nothing queued locally.
    fn three_g(c: &QualityController, estimate_kbps: u32, egress_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: egress_kbps * 9 / 10,
            egress_kbps,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(36.0),
            encode_ms: 1.0,
            spend_ratio: 1.0,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// A tick of drain mode: nothing encoded, str0m's padding and RTCP leaving.
    fn draining_tick(c: &QualityController) -> Feedback {
        Feedback {
            produced_kbps: 0,
            qp_samples: 0,
            avg_qp: None,
            spend_ratio: 0.0,
            ..three_g(c, 290, 50)
        }
    }

    /// A recorded 3G path before its stall: forty seconds of its recorded round trips
    /// (09:12:40-09:13:21: 560-911 ms, loss 0) at 160-240 kbps against estimates of 190-280.
    fn on_3g_before_the_stall() -> QualityController {
        on_3g_before_the_stall_on(QualityController::new(1620, 1080, Quality::Balanced))
    }

    /// [`on_3g_before_the_stall`] with the controller given (on a policy of its own).
    fn on_3g_before_the_stall_on(mut c: QualityController) -> QualityController {
        let rtts = [564, 911, 571, 565, 712, 606, 560, 573, 595, 635];
        for i in 0..40 {
            one_second(
                &mut c,
                |c| three_g(c, 260, 220),
                fresh(rtts[i % rtts.len()], 0.0, 0),
            );
        }
        assert!(!c.draining(), "nothing on this path is a stall");
        assert_eq!(c.rtt_base_ms(), Some(560));
        let _ = c.take_brake_event();
        let _ = c.take_drain_event();
        c
    }

    /// The failure drain mode exists for, replayed from its first sign to the backlog drained.
    ///
    /// Recorded: 870 and 599 ms (the path's ordinary jitter); four intervals with no report while
    /// 233-297 kbps went out; then 4752 ms, the stall's first report, followed by 6607 ... 39351 as
    /// the path was fed for another minute. Replayed drained instead: 6607 (still the earlier
    /// backlog), 3100, 1600, then 700 under the band.
    #[test]
    fn a_3g_stall_is_drained_from_its_first_report() {
        let mut c = on_3g_before_the_stall();
        let mut moves = Vec::new();
        let mut second = |c: &mut QualityController,
                          fb: &dyn Fn(&QualityController) -> Feedback,
                          report: Option<ReceiverReport>| {
            if let Some(r) = one_second(c, fb, report) {
                moves.push(r);
            }
        };
        second(&mut c, &|c| three_g(c, 290, 243), fresh(870, 0.0, 0));
        second(&mut c, &|c| three_g(c, 226, 225), fresh(599, 0.0, 0));
        for egress in [233, 263, 280, 297] {
            second(&mut c, &move |c| three_g(c, 280, egress), silent(599));
            assert!(!c.draining(), "silence alone is never a stall");
        }
        assert_eq!(
            c.brake_state(),
            "engaged",
            "four silent intervals at 233-297 kbps of a ~260 budget count as silence now"
        );
        // What the resume is priced from: the evidence as the stall finds it.
        let capacity = c.capacity_kbps();
        second(&mut c, &|c| three_g(c, 293, 315), fresh(4_752, 0.0, 0));
        assert!(c.draining(), "4752 ms after a silence is a stall");
        match c.take_drain_event() {
            Some(DrainEvent::Entered {
                rtt_ms: 4_752,
                by_silence: true,
                ref_ms: Some(560),
                ..
            }) => {}
            other => panic!("expected the stall to enter drain mode: {other:?}"),
        }
        assert_eq!(
            c.brake_state(),
            "-",
            "the silence brake is superseded by the drain"
        );
        // The backlog of before still arriving, then draining.
        for rtt in [None, Some(6_607), Some(3_100), Some(1_600)] {
            let report = rtt.map_or(silent(4_752), |r| fresh(r, 0.0, 0));
            second(&mut c, &draining_tick, report);
            assert!(c.draining(), "still draining at {rtt:?}");
            assert_eq!(c.brake_state(), "-", "no brake reads a backlog's reports");
            assert_eq!(c.take_drain_event(), None);
        }
        second(&mut c, &draining_tick, fresh(700, 0.0, 0));
        assert!(
            !c.draining(),
            "700 ms is under the band (1000 on a 560 baseline)"
        );
        let resume = match c.take_drain_event() {
            Some(DrainEvent::Left {
                why: "report",
                rtt_ms: Some(700),
                exit_below_ms: 1_000,
                resume_kbps,
                ..
            }) => resume_kbps,
            other => panic!("expected the drain to end on 700 ms: {other:?}"),
        };
        // Half of what the path was last confirmed carrying: the ~290 estimate the link agreed with
        // under load, or the capacity evidence if larger.
        assert!(
            (ABSOLUTE_FLOOR_KBPS..=150).contains(&resume) && resume >= capacity / 2,
            "resumed at {resume}, against evidence of {capacity} and an estimate of 293"
        );
        assert_eq!(c.brake_state(), "holding");
        assert_eq!(c.brake_kbps(), Some(resume));
        assert!(
            moves.is_empty(),
            "nothing moves the rung through a stall and its drain: {moves:?}"
        );
        // A clean report releases the resume's ceiling as any brake is released.
        one_second(&mut c, |c| three_g(c, 290, 150), fresh(610, 0.0, 0));
        assert_eq!(c.brake_state(), "releasing");
    }

    /// One report past the line is not a stall, however far past it. The same recording printed
    /// 52495 between 701 and 1052, and 50619 before 724: sender reports from the path ICE had just
    /// left, reaching the receiver out of turn.
    #[test]
    fn a_single_report_past_the_line_is_not_a_stall() {
        let mut c = on_3g_before_the_stall();
        for rtt in [701, 52_495, 1_052, 700, 50_619, 724, 980, 701] {
            one_second(&mut c, |c| three_g(c, 243, 200), fresh(rtt, 0.0, 0));
            assert!(
                !c.draining(),
                "entered drain mode on a single report of {rtt}"
            );
        }
        assert_eq!(c.take_drain_event(), None);
    }

    /// A blackout drops what it cannot carry: silence, and then the path's own round trip. It is an
    /// outage — the silence brake's, and the outage re-anchor's — never a stall.
    #[test]
    fn a_blackout_is_an_outage_not_a_stall() {
        let mut c = outage_of_ten_seconds();
        assert!(!c.draining(), "ten silent seconds are not a stall");
        one_second(
            &mut c,
            |c| bench(c, 5_672, 700, 650, 30.0),
            fresh(126, 0.0, 0),
        );
        one_second(
            &mut c,
            |c| bench(c, 5_672, 900, 850, 30.0),
            fresh(125, 0.0, 0),
        );
        assert!(!c.draining());
        assert_eq!(c.take_drain_event(), None);
    }

    /// Round trips a Wi-Fi or LTE path produces never enter drain mode: the bench's relayed paths
    /// (130-380 ms, and the worst single report on record, 1510 at an RTT step), a dying Wi-Fi in a
    /// handover (1480, 685, 1758 against 127), and an LTE ending's queue (292, 801, 764 with 25-94%
    /// loss).
    #[test]
    fn good_network_round_trips_never_drain() {
        let mut c = on_wifi_at_1080p60();
        for rtt in [
            135, 138, 145, 380, 150, 137, 1_510, 337, 341, 354, 338, 337, 1_480, 685, 1_758, 245,
            247, 253, 249, 292, 801, 764, 250,
        ] {
            one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(rtt, 0.0, 0));
            assert!(!c.draining(), "drained on {rtt} ms");
        }
        assert_eq!(c.take_drain_event(), None);
    }

    /// A drain the receiver has stopped proving (reports between the exit band and the entry line)
    /// ends at [`DRAIN_MAX`] after the last proof: the viewer's picture is frozen and its heartbeat
    /// keeps its own deadlines away, so this bound is the only one. A path still holding a backlog
    /// re-enters drain mode on two more reports.
    #[test]
    fn a_drain_that_never_sees_the_path_drain_resumes_after_its_bound() {
        let mut c = on_3g_before_the_stall();
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(4_752, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(6_607, 0.0, 0));
        assert!(c.draining());
        let _ = c.take_drain_event();
        let max_s = DRAIN_MAX.as_secs();
        // The second that entered it spent most of itself draining already.
        let mut held_s: u32 = 1;
        while c.draining() {
            one_second(&mut c, draining_tick, fresh(1_500, 0.0, 0));
            held_s += 1;
            assert!(u64::from(held_s) <= max_s + 1, "the drain is bounded");
        }
        assert!(
            u64::from(held_s) >= max_s,
            "not before its bound: {held_s} s"
        );
        assert!(matches!(
            c.take_drain_event(),
            Some(DrainEvent::Left {
                why: "timeout",
                rtt_ms: None,
                ..
            })
        ));
        one_second(&mut c, |c| three_g(c, 293, 150), fresh(8_000, 0.0, 0));
        assert!(
            !c.draining(),
            "one report is not a stall, after a drain as before one"
        );
        one_second(&mut c, |c| three_g(c, 293, 150), fresh(8_400, 0.0, 0));
        assert!(c.draining(), "two are");
    }

    /// While the receiver keeps proving a backlog, a resume would only feed it: the drain goes on
    /// past [`DRAIN_MAX`], to [`DRAIN_MAX_PROVEN`].
    #[test]
    fn a_drain_the_receiver_keeps_proving_lasts_to_its_absolute_bound() {
        let mut c = on_3g_before_the_stall();
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(4_752, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(6_607, 0.0, 0));
        assert!(c.draining());
        let _ = c.take_drain_event();
        let mut held_s: u32 = 1;
        while c.draining() {
            // The 30 kbps stall's reports: a sender report stuck behind the backlog, its round
            // trip repeated, then the next, later one.
            one_second(&mut c, draining_tick, fresh(6_104 + 400 * held_s, 0.0, 0));
            held_s += 1;
            assert!(
                u64::from(held_s) <= DRAIN_MAX_PROVEN.as_secs() + 1,
                "the drain is bounded"
            );
        }
        assert!(
            u64::from(held_s) >= DRAIN_MAX_PROVEN.as_secs(),
            "resumed after {held_s} s into a path the receiver said was holding a backlog"
        );
    }

    /// A bench `3g-bloat` drain. Entered on 2116 and 2062 ms with no baseline yet (the opening's
    /// reports were all queue); 1773 and 1375 as the backlog drained; then nothing fresh at all
    /// (the viewer's own pair round trip was back at 436 ms, and later reports were about a
    /// sequence number that had stopped moving). Without the drained rule it sat frozen until
    /// [`DRAIN_MAX`]. The second empty interval, past the 375 ms of backlog the 1375 proved, ends
    /// it; with the estimate walked down to 52 by our silence, congestion control restarts at the
    /// resume budget.
    #[test]
    fn a_drained_backlog_is_seen_in_the_receivers_silence() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for rtt in [1_471, 1_472] {
            one_second(&mut c, |c| three_g(c, 221, 230), fresh(rtt, 0.0, 0));
        }
        one_second(&mut c, |c| three_g(c, 198, 231), fresh(2_116, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 198, 244), fresh(2_062, 0.0, 0));
        assert!(c.draining());
        let _ = c.take_drain_event();
        for rtt in [1_773, 1_375] {
            one_second(&mut c, draining_tick, fresh(rtt, 0.0, 0));
            assert!(c.draining(), "{rtt} ms is past the 1000 ms fallback band");
        }
        let collapsed = |c: &QualityController| Feedback {
            estimate_kbps: 52,
            ..draining_tick(c)
        };
        one_second(&mut c, collapsed, silent(1_375));
        assert!(c.draining(), "one empty interval is Chrome's cadence");
        one_second(&mut c, collapsed, silent(1_375));
        assert!(
            !c.draining(),
            "two, past the backlog the last report proved, are drained"
        );
        match c.take_drain_event() {
            Some(DrainEvent::Left {
                why: "drained",
                rtt_ms: None,
                resume_kbps,
                ..
            }) => {
                assert_eq!(c.take_bwe_reanchor(), Some(resume_kbps));
                let r = c.last_reanchor().expect("the re-anchor's details");
                assert_eq!(r.trigger, ReanchorTrigger::DrainResume);
                assert_eq!(r.estimate_kbps, 52);
            }
            other => panic!("expected the drain to end as drained: {other:?}"),
        }
    }

    /// A silence shorter than the backlog the last report proved does not end a drain: after 6607
    /// ms, two empty intervals are not the backlog gone; six are.
    #[test]
    fn a_silence_shorter_than_the_proven_backlog_does_not_end_a_drain() {
        let mut c = on_3g_before_the_stall();
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(4_752, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 293, 250), fresh(6_607, 0.0, 0));
        assert!(c.draining());
        let mut silent_s = 0;
        while c.draining() {
            one_second(&mut c, draining_tick, silent(6_607));
            silent_s += 1;
            assert!(
                silent_s <= 7,
                "the drain must end once the silence outlasts 5.6 s"
            );
        }
        assert!(
            silent_s >= 5,
            "ended after {silent_s} s of silence, inside the 5.6 s the last report proved"
        );
    }

    /// A path change during a drain forgets the old path's baseline: the drain leaves on the
    /// fallback band. On a relayed Wi-Fi baseline (127 ms) the brake's line is 277 ms, and the new
    /// path's 600 would never meet it.
    #[test]
    fn a_path_change_during_a_drain_leaves_on_the_fallback_band() {
        let mut c = on_wifi_at_1080p60();
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(2_500, 0.0, 0),
        );
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(3_900, 0.0, 0),
        );
        assert!(c.draining());
        one_second(&mut c, draining_tick, fresh(600, 0.0, 0));
        assert!(
            c.draining(),
            "600 is past 277, the band over the WiFi baseline"
        );
        c.note_path_change("transport");
        one_second(&mut c, draining_tick, fresh(600, 0.0, 0));
        assert!(
            !c.draining(),
            "on another path the band is the fallback's 1000"
        );
    }

    // ── drain mode and the viewer's own count of our frames ──────────────────────────────────

    /// A session driven as the control task drives it: our frames to the transport every tick (none
    /// while draining) and the viewer's `vv` reports as they arrive, on the 200 ms clock.
    struct Counted {
        c: QualityController,
        ticks: u64,
        sent_frames: u64,
        sent_bytes: u64,
        /// What we had sent by each tick: (ms, frames), to say what the viewer has had.
        history: Vec<(u64, u64)>,
        /// Our frames per second and their size while not draining.
        fps: u64,
        frame_bytes: u64,
        /// What the viewer has received so far.
        received: u64,
    }

    impl Counted {
        fn new(c: QualityController, fps: u64, frame_bytes: u64) -> Self {
            Self {
                c,
                ticks: 0,
                sent_frames: 0,
                sent_bytes: 0,
                history: vec![(0, 0)],
                fps,
                frame_bytes,
                received: 0,
            }
        }

        /// The controller's clock as of the tick about to run, ms.
        fn next_ms(&self) -> u64 {
            (self.ticks + 1) * 200
        }

        /// Our frames sent by `ms`.
        fn sent_by(&self, ms: u64) -> u64 {
            self.history
                .iter()
                .take_while(|(t, _)| *t <= ms)
                .last()
                .map_or(0, |(_, f)| *f)
        }

        /// One tick: `vv` a report arriving now — the viewer's total received, and its clock when
        /// it made it (`made_ms`, on the controller's clock: equal to now for one on time).
        fn tick(&mut self, fb: Feedback, vv: Option<(u64, u64)>) -> Option<Rung> {
            if !self.c.draining() {
                // `fps` over five ticks, the remainder on the first ones.
                let k = self.ticks % 5;
                let n = self.fps / 5 + u64::from(k < self.fps % 5);
                self.sent_frames += n;
                self.sent_bytes += n * self.frame_bytes;
            }
            let now = self.next_ms();
            self.history.push((now, self.sent_frames));
            self.c.note_frames_sent(self.sent_frames, self.sent_bytes);
            if let Some((received, made_ms)) = vv {
                self.received = received;
                self.c.note_viewer_frames(ViewerFrames {
                    received,
                    viewer_ms: Some(made_ms),
                    age: Duration::ZERO,
                });
            }
            self.ticks += 1;
            self.c.tick(fb, TICK)
        }

        /// One second of `fb`: the receiver report on its first tick, and on its third (xx.4) an
        /// on-time viewer report of `got` more frames, or with `None` of all sent `fwd_ms` before.
        fn second(
            &mut self,
            fb: impl Fn(&QualityController) -> Feedback,
            report: Option<ReceiverReport>,
            got: Option<Option<u64>>,
            fwd_ms: u64,
        ) {
            for k in 0..5 {
                let f = Feedback {
                    report: if k == 0 { report } else { None },
                    ..fb(&self.c)
                };
                let vv = (k == 2).then_some(got).flatten().map(|g| {
                    let now = self.next_ms();
                    let total = g.map_or_else(
                        || self.sent_by(now.saturating_sub(fwd_ms)),
                        |n| self.received + n,
                    );
                    (total, now)
                });
                self.tick(f, vv);
            }
        }
    }

    /// A recorded 1080p@60 stretch before a stall: 10.4 Mbit/s against an estimate of 15.7, round
    /// trips of 290-300, and an on-time viewer report each second of everything sent half a round
    /// trip before, so the in-flight reference is set.
    fn at_1080p60_before_the_stall() -> Counted {
        let mut s = Counted::new(
            QualityController::new(1920, 1080, Quality::Balanced),
            60,
            21_000,
        );
        let rtts = [292, 293, 296, 290, 294, 298, 291, 300, 292, 294];
        for i in 0..30 {
            s.second(
                |c| handover(c, 15_744, 10_400),
                fresh(rtts[i % rtts.len()], 0.0, 0),
                Some(None),
                145,
            );
        }
        assert!(!s.c.draining());
        assert_eq!(s.c.rtt_base_ms(), Some(290));
        let _ = s.c.take_brake_event();
        let _ = s.c.take_drain_event();
        s
    }

    /// A recorded stall, second by second from xx.0 (receiver reports landing at xx.02, the
    /// viewer's at xx.42): the receiver silent, 300, 2564, silent, 2661, 872, 294; the viewer's
    /// reports of 28 frames (made at 50.4, in at 51.4), 0 (51.4, 51.6), 8 (52.4, 53.4), 61 (53.4,
    /// 54.0), 74 (on time at 54.4), 116 (55.4), 68 (56.4), 5 (57.4), late as they came. We send 60
    /// frames a second of 21 kB until a drain stops us. Returns when the drain began and ended, in
    /// ms of this sequence (from 50.0).
    fn a_two_second_stall(s: &mut Counted, with_viewer: bool) -> (Option<u64>, Option<u64>) {
        let t0 = s.next_ms();
        let at = |s: &Counted| s.next_ms() - 200 - t0;
        let mut entered = None;
        let mut left = None;
        // (receiver report, viewer reports by tick: (tick, frames, made at ms into the sequence))
        type Second<'a> = (Option<ReceiverReport>, &'a [(u64, u64, u64)]);
        let seconds: [Second; 8] = [
            (fresh(296, 0.0, 0), &[]),
            (silent(296), &[(2, 28, 400), (3, 0, 1_400)]),
            (fresh(300, 0.0, 0), &[]),
            (fresh(2_564, 0.0, 0), &[(2, 8, 2_400)]),
            (silent(2_564), &[(0, 61, 3_400), (2, 74, 4_400)]),
            (fresh(2_661, 0.0, 0), &[(2, 116, 5_400)]),
            (fresh(872, 0.0, 0), &[(2, 68, 6_400)]),
            (fresh(294, 0.0, 0), &[(2, 5, 7_400)]),
        ];
        for (report, vv) in seconds {
            for k in 0..5u64 {
                let fb = if s.c.draining() {
                    Feedback {
                        produced_kbps: 0,
                        qp_samples: 0,
                        avg_qp: None,
                        spend_ratio: 0.0,
                        ..handover(&s.c, 15_744, 120)
                    }
                } else {
                    handover(&s.c, 15_744, 10_400)
                };
                let f = Feedback {
                    report: if k == 0 { report } else { None },
                    ..fb
                };
                let v = vv
                    .iter()
                    .find(|(tick, _, _)| *tick == k)
                    .filter(|_| with_viewer)
                    .map(|&(_, n, made)| (s.received + n, t0 + made));
                let was = s.c.draining();
                s.tick(f, v);
                if !was && s.c.draining() && entered.is_none() {
                    entered = Some(at(s));
                }
                if was && !s.c.draining() && left.is_none() {
                    left = Some(at(s));
                }
            }
        }
        (entered, left)
    }

    /// The recorded stall on the receiver's round trips alone: drain mode from the 2661 ms report
    /// at 55.0 until the 294 at 57.0, two seconds encoding nothing on a backlog the viewer said was
    /// flushing. With the viewer's count: the same entry (its on-time report at 54.4 still had 130
    /// of our frames in flight, 1.9 s at their rate), and the end at 55.4, when 116 frames came in
    /// a second with about 60 left, half a second at that rate.
    #[test]
    fn a_two_second_stall_ends_on_the_viewers_count() {
        let mut s = at_1080p60_before_the_stall();
        let (entered, left) = a_two_second_stall(&mut s, false);
        assert_eq!(entered, Some(5_000), "the round trip's drain: in at 55.0");
        assert_eq!(left, Some(7_000), "and out on the 294 ms report at 57.0");

        let mut s = at_1080p60_before_the_stall();
        let (entered, left) = a_two_second_stall(&mut s, true);
        assert_eq!(
            entered,
            Some(5_000),
            "the report on time at 54.4 said a backlog was in flight"
        );
        assert_eq!(left, Some(5_400), "out on the viewer's report at 55.4");
        match s.c.take_drain_event() {
            Some(DrainEvent::Left {
                why: "delivered",
                rtt_ms: None,
                held_ms,
                resume_kbps,
                ..
            }) => {
                assert!(held_ms <= 600, "held {held_ms} ms");
                assert!(
                    (4_000..=6_000).contains(&resume_kbps),
                    "half of the ~10 Mbit/s sent: {resume_kbps}"
                );
            }
            other => panic!("expected the drain to end on the viewer's count: {other:?}"),
        }
        assert!(
            !s.c.draining(),
            "the 872 and 294 ms reports after it begin nothing"
        );
    }

    /// A drain on the round trip alone is begun as before when the viewer says nothing current: no
    /// reports, or reports held up behind our queue (the bench's bursts of four, 1-8 s late).
    #[test]
    fn a_drain_is_begun_without_the_viewer_when_its_reports_are_missing_or_late() {
        for late in [None, Some(1_400)] {
            let mut s = at_1080p60_before_the_stall();
            s.second(
                |c| handover(c, 15_744, 10_400),
                fresh(2_564, 0.0, 0),
                late.map(|_| Some(60)),
                145,
            );
            // The report of this second, made at its start and in only now (or never).
            let made = s.next_ms() - 200;
            let vv = late.map(|l| (s.received + 120, made.saturating_sub(l)));
            for k in 0..5 {
                let f = Feedback {
                    report: if k == 0 { fresh(2_661, 0.0, 0) } else { None },
                    ..handover(&s.c, 15_744, 10_400)
                };
                s.tick(f, if k == 0 { vv } else { None });
            }
            assert!(
                s.c.draining(),
                "two reports past the line with the viewer's {late:?}-late count: a drain"
            );
        }
    }

    /// A thin path's viewer, on time, after a drain's end on a bench `3g-stall-100` run: the
    /// receiver reports 3403 and then 2161 ms, while the viewer's reports say our frames arrive at
    /// 20 a second against our 10 (catching up) with five left in flight. The round trips describe
    /// padding and the resume keyframe the drain left in the path; drain mode does not begin.
    /// Without the viewer's word it does (2 s, ended on a 930 ms report).
    #[test]
    fn a_thin_path_catching_up_by_the_viewers_count_is_not_drained() {
        let thin = |c: &QualityController| Feedback {
            queue_age_ms: 0,
            ..three_g(c, 300, 90)
        };
        for with_viewer in [true, false] {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            c.set_source(1620, 1080);
            let mut s = Counted::new(c, 10, 1_000);
            let rtts = [452, 460, 449, 455, 470, 450, 458, 448, 451, 465];
            for i in 0..30 {
                s.second(thin, fresh(rtts[i % rtts.len()], 0.0, 0), Some(None), 225);
            }
            assert_eq!(s.c.rtt_base_ms(), Some(448));
            let vv = |n: u64| with_viewer.then_some(Some(n));
            // Three seconds stuck behind what the drain left in the path; then catching up.
            s.second(thin, fresh(1_200, 0.0, 0), vv(0), 225);
            s.second(thin, silent(1_200), vv(0), 225);
            s.second(thin, fresh(3_403, 0.0, 0), vv(0), 225);
            s.second(thin, silent(3_403), vv(34), 225);
            s.second(thin, fresh(2_161, 0.0, 0), vv(15), 225);
            assert_eq!(
                s.c.draining(),
                !with_viewer,
                "with the viewer's count: catching up, no drain; without it: a drain"
            );
        }
    }

    /// The bench's other re-entry shape: drain mode begun on 3184 and 3667 ms while the viewer's
    /// on-time reports had nothing of ours arriving (our frames sat behind the previous drain's
    /// padding), then 25 of 30 in a second and the rest in the next. The drain ends on the first
    /// report when what reached the viewer is twice what the resume will send (one frame completing
    /// in a second can read as more than the path carried), else on the second when the two
    /// together reach the resume's 120 kbit/s. Recorded, it lasted 4 s and ended on silence.
    #[test]
    fn a_drain_begun_behind_a_remnant_ends_when_the_viewer_has_our_frames() {
        let thin = |c: &QualityController| Feedback {
            queue_age_ms: 0,
            ..three_g(c, 300, 90)
        };
        // (frame size, the report the drain ends on: 0 = the first after it began with frames)
        for (frame_bytes, ends_on) in [(2_500, 0), (1_100, 1)] {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            c.set_source(1620, 1080);
            let mut s = Counted::new(c, 10, frame_bytes);
            let rtts = [492, 500, 495, 510, 498, 493, 505, 499, 496, 502];
            for i in 0..30 {
                s.second(thin, fresh(rtts[i % rtts.len()], 0.0, 0), Some(None), 250);
            }
            s.second(thin, fresh(1_100, 0.0, 0), Some(Some(0)), 250);
            s.second(thin, fresh(3_184, 0.0, 0), Some(Some(0)), 250);
            s.second(thin, fresh(3_667, 0.0, 0), Some(Some(0)), 250);
            assert!(
                s.c.draining(),
                "nothing of ours arriving: the viewer agrees there is a backlog"
            );
            let _ = s.c.take_drain_event();
            for (i, got) in [25, 5].into_iter().enumerate() {
                s.second(draining_tick, fresh(2_576, 0.0, 0), Some(Some(got)), 250);
                assert_eq!(
                    s.c.draining(),
                    i < ends_on,
                    "{frame_bytes}-byte frames, report {i} after the drain began"
                );
                if !s.c.draining() {
                    assert!(matches!(
                        s.c.take_drain_event(),
                        Some(DrainEvent::Left {
                            why: "delivered",
                            ..
                        })
                    ));
                    break;
                }
            }
        }
    }

    /// A thin path's stall (100 kbit/s for 20 s): the viewer gets our backlog at 72 kbit/s until
    /// none is left. The resume would send 120 and rebuild it, so the viewer's count does not end
    /// this drain; the receiver's reports do.
    #[test]
    fn a_thin_stall_is_not_left_on_the_viewers_count_while_the_resume_would_not_fit() {
        let thin = |c: &QualityController| Feedback {
            queue_age_ms: 0,
            ..three_g(c, 250, 230)
        };
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.set_source(1620, 1080);
        let mut s = Counted::new(c, 25, 1_100);
        let rtts = [603, 610, 605, 620, 608, 604, 615, 606, 611, 609];
        for i in 0..30 {
            s.second(thin, fresh(rtts[i % rtts.len()], 0.0, 0), Some(None), 300);
        }
        s.second(thin, fresh(1_500, 0.0, 0), Some(Some(9)), 300);
        s.second(thin, fresh(2_500, 0.0, 0), Some(Some(9)), 300);
        s.second(thin, fresh(3_100, 0.0, 0), Some(Some(9)), 300);
        assert!(s.c.draining());
        let _ = s.c.take_drain_event();
        for _ in 0..12 {
            s.second(draining_tick, fresh(3_500, 0.0, 0), Some(Some(9)), 300);
            assert!(
                s.c.draining(),
                "72 kbit/s reaching the viewer is not room for a 120 kbit/s resume"
            );
        }
    }

    /// A session opening into a bloated path has no clean round trip for the in-flight reference
    /// (first reports at 1505 and 1497 ms, already 118 frames short): the viewer's count says
    /// nothing and the drain begins as before.
    #[test]
    fn a_session_opening_into_a_queue_has_no_viewer_reference_to_veto_with() {
        let thin = |c: &QualityController| Feedback {
            queue_age_ms: 0,
            ..three_g(c, 300, 240)
        };
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.set_source(1620, 1080);
        let mut s = Counted::new(c, 10, 3_000);
        for rtt in [1_505, 1_497, 1_498, 1_500] {
            // Reports on time, of everything sent: by the counts nothing is in flight.
            s.second(thin, fresh(rtt, 0.0, 0), Some(None), 750);
        }
        s.second(thin, fresh(2_203, 0.0, 0), Some(None), 750);
        s.second(thin, fresh(2_188, 0.0, 0), Some(None), 750);
        assert!(s.c.draining(), "no reference, no veto");
    }

    /// Silence counts on a link too thin for 300 kbps while sending: two empty intervals at 205-252
    /// kbps of egress, 162-167 of it media, against a budget of ~165.
    #[test]
    fn silence_counts_on_a_thin_link_that_is_sending() {
        let mut c = on_3g_before_the_stall();
        one_second(&mut c, |c| three_g(c, 180, 190), fresh(580, 0.0, 0));
        assert!(c.feedback_live());
        one_second(&mut c, |c| three_g(c, 180, 205), silent(580));
        assert!(
            !c.feedback_live(),
            "the first empty interval makes the feedback stale"
        );
        one_second(&mut c, |c| three_g(c, 180, 252), silent(580));
        assert_eq!(
            c.brake_state(),
            "engaged",
            "the second is a silence brake, as it is above 300 kbps"
        );
        assert!(!c.draining(), "and silence alone is not a stall");
    }

    /// A still screen is never silence, however thin its budget: the encoder produces a few kbps,
    /// and what leaves is str0m's padding (recorded on 3G: 52-72 kbps against a 120 budget, the
    /// encoder at 4-8).
    #[test]
    fn a_still_screen_is_never_silence_however_thin_the_budget() {
        let mut c = on_3g_before_the_stall();
        let still = |egress: u32| {
            move |c: &QualityController| Feedback {
                produced_kbps: 6,
                spend_ratio: 0.05,
                ..three_g(c, 110, egress)
            }
        };
        one_second(&mut c, still(64), fresh(580, 0.0, 0));
        for egress in [52, 72, 64, 71, 60, 66] {
            one_second(&mut c, still(egress), silent(580));
            assert!(
                c.feedback_live(),
                "padding at {egress} kbps is not us asking for anything"
            );
        }
        assert_eq!(c.brake_state(), "-");
    }

    /// A recorded bufferbloated 3G opening, per second from its first media. The receiver never
    /// called it congested (its first round trip, 1726, was already the opening's queue), and the
    /// ladder walked 1080p30 to 360p over 26 s with our queue at 630-1194 ms. Our queue says it.
    #[test]
    fn a_bufferbloated_opening_jumps_on_its_own_queue() {
        let seconds: [(u32, u32, u32, Option<ReceiverReport>); 14] = [
            (422, 609, 15, stats_only()),
            (330, 408, 51, None),
            (330, 343, 22, fresh_no_rtt(0.0)),
            (330, 125, 0, fresh(1_726, 0.0, 0)),
            (259, 260, 133, fresh(2_008, 0.0, 0)),
            (231, 204, 0, fresh(1_399, 0.0, 0)),
            (231, 178, 0, fresh(791, 0.0, 0)),
            (229, 147, 0, fresh(754, 0.0, 0)),
            (229, 138, 0, fresh(623, 0.0, 0)),
            (314, 318, 235, fresh(559, 0.0, 0)),
            (199, 185, 630, silent(559)),
            (111, 183, 430, fresh(956, 0.0, 0)),
            (93, 471, 1_194, fresh(692, 0.0, 0)),
            (103, 58, 330, fresh(557, 0.0, 0)),
        ];
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut moves = Vec::new();
        for (i, &(estimate, egress, queue, report)) in seconds.iter().enumerate() {
            let fb = move |c: &QualityController| Feedback {
                queue_age_ms: queue,
                produced_kbps: egress,
                avg_qp: Some(46.0),
                ..three_g(c, estimate, egress)
            };
            if let Some(r) = one_second(&mut c, fb, report) {
                moves.push((i, r, c.last_move_reason()));
            }
        }
        let jump = moves
            .iter()
            .find(|m| m.2 == "startup-queue")
            .unwrap_or_else(|| panic!("our own queue must jump the opening: {moves:?}"));
        assert_eq!(
            (jump.1.max_h, jump.1.fps),
            (360, 30),
            "~250 kbps leaving pays for 360p@30 (212) and not 540p (381): {moves:?}"
        );
        assert!(
            jump.0 <= 12,
            "by 09:11:55, where the queue reached the breaker, not 09:12:08: {moves:?}"
        );
        assert_eq!(
            moves.iter().filter(|m| m.2 == "startup-queue").count(),
            1,
            "once: {moves:?}"
        );
    }

    /// A startup queue jump decided during a move's settle, with a drain beginning before the
    /// settle ends: taken on the drain's last tick, so the resume's keyframe is the jump's.
    #[test]
    fn a_startup_jump_decided_before_a_drain_is_taken_with_its_resume() {
        // (estimate, egress, our queue, encode ms, report)
        let seconds: [(u32, u32, u32, f32, Option<ReceiverReport>); 9] = [
            (600, 609, 15, 3.0, stats_only()),
            (330, 408, 51, 20.0, fresh(450, 0.0, 0)),
            (330, 343, 22, 20.0, fresh(460, 0.0, 0)),
            (300, 300, 600, 3.0, fresh(470, 0.0, 0)),
            (300, 300, 700, 3.0, fresh(2_100, 0.0, 0)),
            (300, 300, 700, 3.0, fresh(2_600, 0.0, 0)),
            (300, 50, 0, 3.0, fresh(1_500, 0.0, 0)),
            (300, 50, 0, 3.0, fresh(1_200, 0.0, 0)),
            (300, 50, 0, 3.0, fresh(800, 0.0, 0)),
        ];
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut moves = Vec::new();
        let mut left_at = None;
        for (i, &(estimate, egress, queue, encode_ms, report)) in seconds.iter().enumerate() {
            let fb = move |c: &QualityController| Feedback {
                queue_age_ms: queue,
                encode_ms,
                ..three_g(c, estimate, egress)
            };
            if let Some(r) = one_second(&mut c, fb, report) {
                moves.push((i, r, c.last_move_reason()));
            }
            if let Some(DrainEvent::Left { .. }) = c.take_drain_event() {
                left_at = Some(i);
            }
        }
        let left_at = left_at.unwrap_or_else(|| panic!("the drain must end on 800 ms: {moves:?}"));
        let jump = moves
            .iter()
            .find(|m| m.2 == "startup-queue")
            .unwrap_or_else(|| panic!("the decided jump was lost: {moves:?}"));
        assert_eq!((jump.1.max_h, jump.1.fps), (360, 30), "{moves:?}");
        assert_eq!(
            jump.0, left_at,
            "taken with the resume, not a settle later: {moves:?}"
        );
    }

    /// Our queue past the limit behind a fat estimate is str0m's slow start, not the link (bench:
    /// 405 ms once with the estimate 1008 -> 2876 within two seconds).
    #[test]
    fn a_queue_behind_a_fat_link_does_not_jump_the_opening() {
        let seconds: [(u32, u32, u32); 10] = [
            (600, 1_104, 0),
            (1_008, 1_500, 405),
            (2_876, 2_600, 1_050),
            (2_876, 2_700, 240),
            (3_298, 3_000, 0),
            (3_298, 3_100, 0),
            (3_600, 3_200, 60),
            (3_600, 3_300, 0),
            (4_000, 3_400, 0),
            (4_000, 3_500, 0),
        ];
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for (estimate, egress, queue) in seconds {
            let fb = move |c: &QualityController| Feedback {
                queue_age_ms: queue,
                ..three_g(c, estimate, egress)
            };
            let moved = one_second(&mut c, fb, fresh(135, 0.0, 0));
            assert!(
                c.last_move_reason() != "startup-queue",
                "jumped on a queue behind {estimate} kbps: {moved:?}"
            );
        }
        // A thin link whose queue never stands (a recorded LTE still screen) is left to the
        // receiver's rule.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        for _ in 0..20 {
            one_second(&mut c, |c| three_g(c, 300, 250), fresh(376, 0.0, 0));
            assert_ne!(c.last_move_reason(), "startup-queue");
        }
    }

    // ── a still game over a jittering relay ──────────────────────────────────────────────────

    /// A nearly still game screen as a recorded relay opening showed it: 2-10 kbps produced, the
    /// estimate at the padding rate the stillness set, egress its padding and RTCP.
    fn still_game(c: &QualityController, estimate_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: (estimate_kbps * 11 / 10).max(ABSOLUTE_FLOOR_KBPS),
            produced_kbps: 5,
            egress_kbps: 95,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(46.0),
            encode_ms: 2.6,
            spend_ratio: 0.04,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// A recorded opening, one second per step: the estimate and the receiver's round trips as
    /// recorded (`None` where an interval had no report), then a 19 kB burst queued behind a pacer
    /// at 1.1 x 78 kbps, its age tick by tick as it drains. `burst_rtt` replaces the round trip
    /// reported while the burst is on the path; `loaded` replaces the still screen's feedback with
    /// a link measured under load. Returns every move.
    fn still_relay_opening(burst_rtt: Option<u32>, loaded: bool) -> Vec<Rung> {
        let seconds: [(u32, Option<u32>); 18] = [
            (354, Some(329)),
            (372, None),
            (393, Some(513)),
            (393, Some(458)),
            (312, Some(635)),
            (166, Some(564)),
            (184, Some(388)),
            (195, Some(522)),
            (205, None),
            (161, Some(338)),
            (121, None),
            (121, Some(343)),
            (115, Some(379)),
            (108, Some(454)),
            (116, Some(346)),
            (104, Some(335)),
            (83, Some(442)),
            (78, Some(378)),
        ];
        let feedback = move |c: &QualityController, estimate: u32| {
            if loaded {
                Feedback {
                    produced_kbps: 700,
                    egress_kbps: 750,
                    spend_ratio: 0.9,
                    avg_qp: Some(28.0),
                    ..still_game(c, 800)
                }
            } else {
                still_game(c, estimate)
            }
        };
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let mut moves = Vec::new();
        for (estimate, rtt) in seconds {
            moves.extend(one_second(
                &mut c,
                |c| feedback(c, estimate),
                rtt.and_then(|r| fresh(r, 0.0, 0)),
            ));
        }
        assert_eq!(
            c.current(),
            LADDER[0],
            "the setup holds the top rung: {moves:?} ({})",
            c.last_move_reason()
        );
        // 16:16:35-36: the burst's queue, then its round trips.
        let ages = [200, 400, 600, 760, 900, 1_000, 0, 0, 0, 0];
        for (i, age) in ages.into_iter().enumerate() {
            let report = match i {
                0 => fresh(burst_rtt.unwrap_or(313), 0.0, 0),
                5 => fresh(burst_rtt.unwrap_or(435), 0.0, 0),
                _ => None,
            };
            let fb = Feedback {
                queue_age_ms: age,
                produced_kbps: if i < 2 { 700 } else { 5 },
                report,
                ..feedback(&c, 78)
            };
            moves.extend(c.tick(fb, TICK));
        }
        // 16:16:37-45: still again.
        for rtt in [280, 226, 396, 223, 280, 350, 361, 259] {
            moves.extend(one_second(&mut c, |c| feedback(c, 60), fresh(rtt, 0.0, 0)));
        }
        moves
    }

    /// A still screen's burst behind an estimate the stillness set, with the receiver at its
    /// baseline, shed 1080p60 on `queue_late`, then 900p, 720p and 540p the same way. The queue was
    /// our pacer's. Not a blanket: with a queue reported on the path, or on a link measured under
    /// load, the burst still descends.
    #[test]
    fn a_still_opening_is_not_shed_on_its_own_pacers_queue() {
        let moves = still_relay_opening(None, false);
        assert!(
            moves.is_empty(),
            "the burst behind our own pacer shed the rung: {moves:?}"
        );

        let moves = still_relay_opening(Some(700), false);
        assert!(
            !moves.is_empty(),
            "the receiver reported a queue (700 on 313) and nothing gave way"
        );
        let moves = still_relay_opening(None, true);
        assert!(
            !moves.is_empty(),
            "a queue behind an estimate the link agreed with under load is the link"
        );
    }

    /// A move's own 63 kB keyframe queued 1258 ms behind a ~110 kbps pacer and cleared in 1.6 s,
    /// inside the settle, yet the five-second filter's memory shed the rung four frames later. No
    /// receiver report here, so the settle, not the pacer-only mask, is what holds the rung.
    #[test]
    fn a_moves_own_keyframe_is_not_the_next_moves_evidence() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        // Past the startup windows, whose own queue rule is not what this is about.
        run(&mut c, |c| healthy(c.current().fps as f32), 25.0);
        descend_to(&mut c, 900);
        assert_eq!(c.current().max_h, 900);
        let thin = |c: &QualityController| Feedback {
            produced_kbps: 20,
            egress_kbps: 110,
            ..still_game(c, 110)
        };
        // The settle: the move's keyframe draining, then nothing.
        let ages = [281, 700, 1_100, 1_258, 1_258, 900, 500, 100];
        let mut moves = Vec::new();
        for age in ages {
            let fb = Feedback {
                queue_age_ms: age,
                ..thin(&c)
            };
            moves.extend(c.tick(fb, TICK));
        }
        run(&mut c, thin, 8.0);
        moves.extend((c.current().max_h != 900).then(|| c.current()));
        assert!(
            moves.is_empty(),
            "the keyframe that arrived at 900p shed it: {moves:?}"
        );
    }

    /// The other side of the settle rule, from the simulated 3G path (`3g-0919`, seed 1): the same
    /// queue through the settle, then 8% loss (under the brake's 10%), so the link failed to carry
    /// what the pacer pushed. The settle's queue counts again and the rung gives way; without the
    /// loss it holds. Ignoring it regardless kept that run a rung or two too high until a keyframe
    /// into the same buffer froze the picture for ten seconds. See `late_for_ladder`.
    #[test]
    fn the_settles_queue_counts_once_the_receiver_reports_loss() {
        let settle_then = |loss_pct: f32| {
            let mut c = QualityController::new(1620, 1080, Quality::Balanced);
            run(&mut c, |c| healthy(c.current().fps as f32), 25.0);
            descend_to(&mut c, 900);
            let thin = |c: &QualityController| Feedback {
                produced_kbps: 20,
                egress_kbps: 110,
                ..still_game(c, 110)
            };
            let mut moves = Vec::new();
            for age in [281, 700, 1_100, 1_258, 1_258, 900, 500, 100] {
                let fb = Feedback {
                    queue_age_ms: age,
                    ..thin(&c)
                };
                moves.extend(c.tick(fb, TICK));
            }
            // Out of the settle, the report on what the drain did to the path.
            run(&mut c, thin, 1.4);
            moves.extend(one_second(&mut c, thin, fresh(212, loss_pct, 3)));
            run(&mut c, thin, 6.0);
            moves.extend((c.current().max_h != 900).then(|| c.current()));
            (moves, c)
        };
        let (moves, c) = settle_then(8.2);
        assert!(
            moves.iter().any(|r| r.max_h < 900),
            "the receiver reported the loss the settle's drain caused, and 900p held: {moves:?} \
             (late {} / with the settle {})",
            c.late_smoothed,
            c.late_with_settle
        );
        let (moves, _) = settle_then(0.0);
        assert!(
            moves.is_empty(),
            "a clean report after the settle is no reason to read its queue: {moves:?}"
        );
    }

    /// 900p in the same recording, before its first step down: a nearly still game, 106 kbps at QP 16, on a relay with a
    /// ~193 ms baseline, the estimate at ~150.
    fn game_at_900p(c: &QualityController, produced: u32, qp: f32) -> Feedback {
        Feedback {
            estimate_kbps: 152,
            drain_kbps: 167,
            produced_kbps: produced,
            egress_kbps: 160,
            qp_samples: 6,
            queue_age_ms: 0,
            avg_qp: Some(qp),
            encode_ms: 1.8,
            spend_ratio: 0.8,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// A recorded round-trip jump to 327-643 on a 193 baseline (a path changing under a VPN, too
    /// jittery to recognise), with a burst and 0% loss; the brake cuts to ~130 kbps.
    /// `produced`/`qp` are the encoder's output at 900p, `loss_pct` the reports'. Returns the
    /// moves, whether the brake engaged, and the least budget allowed.
    fn brake_at_900p(produced: u32, qp: f32, loss_pct: f32) -> (Vec<Rung>, bool, u32) {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        descend_to(&mut c, 900);
        for rtt in [205, 193, 224, 206, 248, 245, 193, 201, 199, 215, 197, 223] {
            one_second(&mut c, |c| game_at_900p(c, 106, 16.0), fresh(rtt, 0.0, 0));
        }
        assert_eq!(c.current().max_h, 900, "the setup sits at 900p");
        assert_eq!(c.rtt_base_ms(), Some(193));
        let _ = c.take_brake_event();
        let mut moves = Vec::new();
        let mut engaged = false;
        let mut least_budget = u32::MAX;
        let reports = [
            Some(416),
            None,
            Some(327),
            Some(586),
            Some(427),
            Some(527),
            Some(345),
            Some(525),
            Some(433),
            Some(616),
            Some(473),
            Some(643),
            Some(469),
            None,
            Some(495),
        ];
        for (i, rtt) in reports.into_iter().enumerate() {
            let burst = i == 3;
            let fb = move |c: &QualityController| {
                let budget = c.encoder_target_kbps();
                Feedback {
                    produced_kbps: if burst {
                        331
                    } else {
                        produced.min(budget.max(106))
                    },
                    queue_age_ms: if burst { 901 } else { 0 },
                    ..game_at_900p(c, produced, qp)
                }
            };
            moves.extend(one_second(
                &mut c,
                fb,
                rtt.and_then(|r| fresh(r, loss_pct, 0)),
            ));
            engaged |= matches!(c.take_brake_event(), Some(BrakeEvent::Engaged(_)));
            least_budget = least_budget.min(c.encoder_target_kbps());
        }
        (moves, engaged, least_budget)
    }

    /// With the brake at ~130 kbps the ladder walked 900p to 360p, keyframes of 57, 37 and 21 kB,
    /// for a picture that already fit. The brake still cuts; the rung holds. Content that does not
    /// fit gives its pixels up in one move, and under loss the step is one rung.
    #[test]
    fn a_braked_budget_is_answered_once_and_only_when_the_picture_does_not_fit_it() {
        // Fits: 106 kbps at QP 16 against ~130.
        let (moves, engaged, least_budget) = brake_at_900p(106, 16.0, 0.0);
        assert!(
            engaged,
            "the brake must still engage on 427 after 586 over 193"
        );
        assert!(
            least_budget <= 160,
            "and cut the budget: at least {least_budget}"
        );
        assert!(
            moves.is_empty(),
            "recorded: 900p -> 720p -> 540p -> 360p; now: {moves:?}"
        );

        // Does not fit: the encoder at its ceiling on the braked budget. One pixel step, straight
        // past 720p; cadence steps after it are free and still the brake's to take.
        let (moves, engaged, _) = brake_at_900p(400, 46.0, 0.0);
        assert!(engaged);
        let heights: Vec<u32> = moves.iter().map(|r| r.max_h).collect();
        assert!(
            heights.first().is_some_and(|&h| h <= 540),
            "straight to the rung the content fits, past 720p: {moves:?}"
        );
        assert!(
            heights.iter().all(|&h| h == heights[0]),
            "one pixel step, not a walk: {moves:?}"
        );

        // Under loss: one rung, as it always was.
        let (moves, _, _) = brake_at_900p(400, 46.0, 12.0);
        assert_eq!(
            moves.first().map(|r| r.max_h),
            Some(720),
            "under loss the step is one rung: {moves:?}"
        );
    }

    /// A still game at 360p@30 on the same recording's relay, later on: 10 kbps produced, the estimate
    /// at ~60, the round trip jittering around a ~220 baseline.
    fn still_at_360(c: &QualityController, estimate_kbps: u32, produced: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: (estimate_kbps * 11 / 10).max(ABSOLUTE_FLOOR_KBPS),
            produced_kbps: produced,
            egress_kbps: 100,
            qp_samples: 8,
            queue_age_ms: 0,
            avg_qp: Some(16.0),
            encode_ms: 0.4,
            spend_ratio: 0.08,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// Fourteen seconds of the same recording: a still game at 360p@30 on the relay, then a probe —
    /// str0m's estimate reads 1082 for a second, the path clean around it.
    fn still_360_through_a_probe() -> QualityController {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        descend_to(&mut c, 360);
        assert_eq!(
            c.current(),
            Rung {
                max_h: 360,
                fps: 30
            }
        );
        for rtt in [
            262, 318, 281, 250, 262, 220, 238, 226, 231, 222, 245, 228, 220, 236,
        ] {
            one_second(&mut c, |c| still_at_360(c, 60, 10), fresh(rtt, 0.0, 0));
        }
        let _ = c.take_bwe_reanchor();
        one_second(&mut c, |c| still_at_360(c, 1_082, 10), fresh(242, 0.0, 0));
        c
    }

    /// After the probe, one second each: the estimate falling back and the round trips as recorded
    /// (`spike` replaces every other one, never two in a row). Returns the moves and the re-anchor.
    fn after_the_probe(spike: Option<u32>) -> (Vec<Rung>, Option<Reanchor>) {
        let mut c = still_360_through_a_probe();
        let produced = 10;
        let mut moves = Vec::new();
        let mut reanchor = None;
        let after: [(u32, Option<u32>); 15] = [
            (88, None),
            (63, Some(294)),
            (63, Some(265)),
            (55, Some(411)),
            (55, None),
            (52, Some(381)),
            (52, Some(297)),
            (55, None),
            (66, Some(208)),
            (105, None),
            (124, Some(189)),
            (219, Some(182)),
            (95, Some(276)),
            (90, Some(257)),
            (58, Some(230)),
        ];
        for (i, (estimate, rtt)) in after.into_iter().enumerate() {
            let rtt = if i % 2 == 1 { spike.or(rtt) } else { rtt };
            for t in 0..5 {
                let fb = Feedback {
                    report: if t == 0 {
                        rtt.and_then(|r| fresh(r, 0.0, 0))
                    } else {
                        None
                    },
                    ..still_at_360(&c, estimate, produced)
                };
                if let Some(r) = c.tick(fb, TICK) {
                    moves.push(r);
                    if c.take_bwe_reanchor().is_some() && reanchor.is_none() {
                        reanchor = c.last_reanchor();
                    }
                }
            }
        }
        (moves, reanchor)
    }

    /// 115 s at 360p on a still game while probes showed 1082 and 1909 kbps: each probe opened the
    /// climb gate for one tick, the estimate was back at 55-95 in two seconds, and the re-anchor
    /// was refused on the clean margin (294 on 220) and for want of demand. The probe's evidence
    /// now stands in for the estimate on an idle screen, and the climb re-anchors at it so its
    /// keyframe drains at the measured rate. Not on a busy screen, and not with a queue reported on
    /// the path.
    #[test]
    fn a_still_screen_climbs_on_the_capacity_a_probe_measured() {
        let (moves, reanchor) = after_the_probe(None);
        let first = moves.first().copied();
        assert!(
            first.is_some_and(|r| r.max_h >= 540),
            "recorded: 360p for the rest of the session; now: {moves:?}"
        );
        let r = reanchor.expect("the climb re-anchors at the evidence");
        assert_eq!(r.trigger.as_str(), "idle-climb");
        assert!(
            r.kbps >= 2 * r.estimate_kbps && r.kbps <= 1_082,
            "at the evidence, not above it: {r:?}"
        );

        // A busy screen is not idle: there the estimate is a measurement, and it is what the gate
        // reads (and a collapse of it the receiver calls clean is the clean-collapse re-anchor's).
        let mut c = still_360_through_a_probe();
        assert!(
            c.idle_evidence(88, true).is_some(),
            "idle after the probe: the evidence stands in"
        );
        run(&mut c, |c| still_at_360(c, 88, 600), 3.0);
        assert_eq!(
            c.idle_evidence(88, true),
            None,
            "600 kbps produced against ~1000 of evidence is not an idle screen"
        );
        let (moves, _) = after_the_probe(Some(460));
        assert!(
            moves.iter().all(|r| r.max_h == 360),
            "the receiver reporting a queue (460 on 220) holds the climb: {moves:?}"
        );
    }

    /// A climb dwell built for four seconds on an estimate (270) affording 360p@30, with a probe
    /// lifting it to 1110 for the last 1.6 s: the climb goes where the whole dwell reached, not
    /// 900p.
    #[test]
    fn a_climb_goes_only_as_far_as_its_whole_dwell_reached() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let at_360_15 = Rung {
            max_h: 360,
            fps: 15,
        };
        for _ in 0..20_000 {
            if c.current() == at_360_15 {
                break;
            }
            let fb = congested(c.current().fps as f32);
            c.tick(fb, TICK);
        }
        assert_eq!(c.current(), at_360_15);
        let busy = |c: &QualityController, estimate: u32| Feedback {
            produced_kbps: 200,
            egress_kbps: 230,
            spend_ratio: 0.9,
            ..still_at_360(c, estimate, 200)
        };
        // The settle and a baseline, on an estimate that affords nothing.
        for rtt in [180, 176, 175, 181, 179] {
            one_second(&mut c, |c| busy(c, 150), fresh(rtt, 0.0, 0));
        }
        let mut moves = Vec::new();
        for (estimate, rtt) in [
            (270, 184),
            (270, 174),
            (1_110, 179),
            (1_110, 183),
            (1_110, 180),
        ] {
            moves.extend(one_second(
                &mut c,
                |c| busy(c, estimate),
                fresh(rtt, 0.0, 0),
            ));
        }
        assert_eq!(
            moves.first().copied(),
            Some(Rung {
                max_h: 360,
                fps: 30
            }),
            "recorded: 360p@15 -> 900p@30 on a probe 1.6 s old; the dwell earned 360p@30: {moves:?}"
        );
    }

    /// A viewer's keyframe request on a still screen, in the startup window: the keyframe queues a
    /// second behind the estimate the stillness set, the receiver at its baseline. In the simulator
    /// (`still-keyframe`) the startup queue jump read that as the link refusing 1080p60 and jumped
    /// to 360p@15. The bufferbloated opening it exists for still jumps: see
    /// `a_bufferbloated_opening_jumps_on_its_own_queue`.
    #[test]
    fn a_keyframe_behind_a_still_screens_estimate_is_not_a_thin_link() {
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        let estimates = [
            600, 494, 400, 350, 300, 280, 250, 220, 180, 150, 120, 100, 90, 80, 70, 67,
        ];
        let rtts = [
            250, 262, 225, 247, 261, 260, 275, 294, 246, 250, 247, 280, 259, 292, 247, 260,
        ];
        let mut moves = Vec::new();
        for (estimate, rtt) in estimates.into_iter().zip(rtts) {
            let fb = move |c: &QualityController| Feedback {
                egress_kbps: 100,
                ..still_game(c, estimate)
            };
            // The first second carries the opening keyframe out, as media.
            let fb0 = move |c: &QualityController| Feedback {
                egress_kbps: 700,
                ..still_game(c, estimate)
            };
            if moves.is_empty() && c.current() == LADDER[0] && estimate == 600 {
                moves.extend(one_second(&mut c, fb0, fresh(rtt, 0.0, 0)));
            } else {
                moves.extend(one_second(&mut c, fb, fresh(rtt, 0.0, 0)));
            }
        }
        // 15.5 s: the requested keyframe, queued behind 1.1 x 67 kbps.
        for age in [126, 400, 700, 1_010, 1_129, 800, 400, 0, 0, 0] {
            let fb = Feedback {
                queue_age_ms: age,
                egress_kbps: 100,
                ..still_game(&c, 67)
            };
            moves.extend(c.tick(fb, TICK));
        }
        for _ in 0..4 {
            moves.extend(one_second(
                &mut c,
                |c| still_game(c, 67),
                fresh(255, 0.0, 0),
            ));
        }
        assert!(
            moves.is_empty(),
            "a keyframe behind a still screen's estimate moved the ladder: {moves:?} ({})",
            c.last_move_reason()
        );
    }

    // ── the background hold ───────────────────────────────────────────────────────────────────

    /// Ten minutes held, the controller not ticked: it returns at the same rung with undecayed
    /// evidence, and str0m's padding-level estimate is re-anchored up to it (clamped to the rung).
    /// Then thirty seconds of the same path: nothing moves.
    #[test]
    fn a_ten_minute_hold_resumes_at_the_same_rung_with_the_estimate_restored_up() {
        let mut c = on_wifi_at_1080p60();
        let rung = c.current();
        let capacity = c.capacity_kbps();
        let informative = c.informative_kbps;
        assert!(capacity >= 10_000, "{capacity}");

        let r = c.resume_after_hold(Duration::from_secs(600), 60);
        assert_eq!(
            c.capacity_kbps(),
            capacity,
            "the evidence is kept, not decayed"
        );
        assert_eq!(c.informative_kbps, informative);
        assert_eq!(c.current(), rung, "the same rung");
        assert!(r.reanchor_due && !r.drain_ended && r.reanchor.is_none());
        assert_eq!(
            c.take_bwe_reanchor(),
            None,
            "decided by its own call, not by the resume"
        );
        let want = capacity.min(rung.absorbable_kbps(1620, 1080));
        let h = c.reanchor_after_hold(60);
        assert_eq!(h.refused, None);
        assert!(h.raises);
        let decided = h.reanchor.expect("re-anchored");
        assert_eq!(decided.trigger, ReanchorTrigger::HoldResume);
        assert!(
            decided.trigger.at_next_frame(),
            "applied right before the resumed keyframe"
        );
        assert_eq!(decided.estimate_kbps, 60);
        let anchor = c.take_bwe_reanchor().expect("taken like any re-anchor");
        assert_eq!(anchor, want);
        assert!(anchor > 60, "only ever up");
        assert_eq!(c.brake_state(), "-", "no brake");
        assert!(!c.draining());
        assert_eq!(c.take_drain_event(), None);
        assert_eq!(c.take_brake_event(), None);

        // The resume keyframe's second, str0m's smoother still showing the collapse, then the path.
        let mut moves = Vec::new();
        for (est, egress) in [(60, 2_400), (3_000, 6_000), (anchor, 9_000)] {
            moves.extend(one_second(
                &mut c,
                |c| handover(c, est, egress),
                fresh(131, 0.0, 0),
            ));
        }
        for rtt in [128, 136, 139, 135, 135, 130, 131, 140, 127, 130].repeat(3) {
            moves.extend(one_second(
                &mut c,
                |c| handover(c, 15_338, 10_400),
                fresh(rtt, 0.0, 0),
            ));
        }
        assert!(moves.is_empty(), "the hold cost a rung: {moves:?}");
        assert_eq!(c.current(), rung);
    }

    /// What the freeze is for: the same ten minutes *ticked* through str0m's padding decays the
    /// evidence under anything a re-anchor would trust, and the resume could restore nothing.
    #[test]
    fn the_same_ten_minutes_ticked_through_would_have_lost_the_evidence() {
        let mut c = on_wifi_at_1080p60();
        for _ in 0..(600 * 5) {
            let fb = gone_still(&c, 60);
            c.tick(fb, TICK);
        }
        assert!(
            c.capacity_kbps() < REANCHOR_MIN_KBPS,
            "decayed to {}",
            c.capacity_kbps()
        );
        let _ = c.take_bwe_reanchor();
        c.resume_after_hold(Duration::ZERO, 60);
        let h = c.reanchor_after_hold(60);
        assert_eq!(h.refused, Some("no-evidence"));
        assert_eq!(c.take_bwe_reanchor(), None);
    }

    /// Never down, and always: whatever the estimate the hold left (under, at or above the
    /// evidence), it restarts at the larger of the two, so str0m's fresh acknowledged-rate history
    /// measures the resumed video (on the bench, an intact 13305 otherwise fell to 66 kbps 2.8 s
    /// after the resume).
    #[test]
    fn a_hold_reanchor_is_never_below_the_estimate() {
        for estimate in [9_000, 15_338, 40_000] {
            let mut c = on_wifi_at_1080p60();
            let rung = c.current();
            let anchor = c.capacity_kbps().min(rung.absorbable_kbps(1620, 1080));
            c.resume_after_hold(Duration::from_secs(30), estimate);
            let h = c.reanchor_after_hold(estimate);
            assert_eq!(h.refused, None, "{estimate}");
            assert_eq!(h.raises, anchor > estimate, "{estimate}");
            assert_eq!(
                c.take_bwe_reanchor(),
                Some(anchor.max(estimate)),
                "{estimate}"
            );
            assert_eq!(c.current(), rung);
            assert_eq!(c.brake_state(), "-");
        }
    }

    /// The "how long ago" clocks move on by the hold: a receiver silent for ten minutes is not
    /// known clean, and a loss ten minutes old refuses nothing.
    #[test]
    fn the_staleness_clocks_move_on_by_the_hold() {
        let mut c = on_wifi_at_1080p60();
        // Real loss just before the hold.
        one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(131, 3.0, 4));
        assert_eq!(c.nothing_unclean_reported(), Err("loss"));
        assert!(c.report_age().is_some_and(|a| a < Duration::from_secs(2)));
        let _ = c.take_brake_event();
        c.resume_after_hold(Duration::from_secs(600), 15_000);
        assert!(c
            .report_age()
            .is_some_and(|a| a >= Duration::from_secs(600)));
        assert_eq!(c.path_clean(), Err("no-report"));
        assert_eq!(
            c.nothing_unclean_reported(),
            Ok(()),
            "the loss is ten minutes old"
        );
    }

    /// Drain mode in force as the hold began ends through its own conservative resume, not the
    /// hold's. Same rung.
    #[test]
    fn a_drain_in_force_when_the_hold_began_ends_through_its_own_resume() {
        let mut c = on_3g_before_the_stall();
        one_second(&mut c, |c| three_g(c, 290, 243), fresh(870, 0.0, 0));
        one_second(&mut c, |c| three_g(c, 226, 225), fresh(599, 0.0, 0));
        for egress in [233, 263, 280, 297] {
            one_second(&mut c, move |c| three_g(c, 280, egress), silent(599));
        }
        one_second(&mut c, |c| three_g(c, 293, 315), fresh(4_752, 0.0, 0));
        assert!(c.draining());
        let _ = c.take_drain_event();
        let _ = c.take_brake_event();
        let rung = c.current();

        let r = c.resume_after_hold(Duration::from_secs(120), 52);
        assert!(r.drain_ended);
        assert!(!r.reanchor_due, "the drain's resume stands for the hold's");
        assert!(!c.draining());
        assert!(matches!(
            c.take_drain_event(),
            Some(DrainEvent::Left { why: "bg_hold", .. })
        ));
        assert_eq!(
            c.brake_state(),
            "holding",
            "the drain's own conservative resume"
        );
        assert_eq!(c.current(), rung);
        let decided = r
            .reanchor
            .expect("52 kbps is under the drain's resume budget");
        assert_eq!(decided.trigger, ReanchorTrigger::DrainResume);
        assert!(decided.kbps > 52);
        assert_eq!(c.take_bwe_reanchor(), Some(decided.kbps));
    }

    // ── a hidden page that sleeps ─────────────────────────────────────────────────────────────

    /// A recorded iPhone page hidden and silent from about a second later; the silence brake read
    /// it as the path dying through the grace (5851 -> 247 kbps, evidence 2945 -> 2230). With the
    /// page hidden the same ten silent seconds brake nothing, open no outage, gather no drain
    /// evidence and forget nothing, and learn nothing either (feedback is stale). With the page
    /// visible they brake.
    #[test]
    fn a_hidden_pages_silent_receiver_is_no_outage() {
        let ten_silent_seconds = |c: &mut QualityController| {
            for _ in 0..10 {
                one_second(c, |c| handover(c, 15_338, 10_400), silent(130));
            }
        };
        let mut hidden = on_wifi_at_1080p60();
        let capacity = hidden.capacity_kbps();
        hidden.set_page_hidden(true);
        assert!(hidden.page_hidden());
        ten_silent_seconds(&mut hidden);
        assert_eq!(hidden.brake_state(), "-", "{:?}", hidden.take_brake_event());
        assert_eq!(hidden.take_brake_event(), None);
        assert!(!hidden.draining());
        assert_eq!(
            hidden.capacity_kbps(),
            capacity,
            "nothing forgotten for a page asleep"
        );
        assert!(!hidden.feedback_live(), "and nothing learned from it");

        let mut visible = on_wifi_at_1080p60();
        ten_silent_seconds(&mut visible);
        assert_eq!(visible.brake_state(), "engaged", "the silence rule itself");
        assert!(visible.capacity_kbps() < capacity);
    }

    /// The silence the background hold reads a sleeping page by: two empty intervals while sending,
    /// and nothing while a still screen sends too little for a report to be due.
    #[test]
    fn receiver_silence_is_two_empty_intervals_while_sending() {
        let mut c = on_wifi_at_1080p60();
        assert_eq!(c.receiver_silence(), None);
        one_second(&mut c, |c| handover(c, 15_338, 10_400), silent(130));
        assert_eq!(
            c.receiver_silence(),
            None,
            "one empty interval is Chrome's cadence"
        );
        // The next report read a tick late: two seconds since the last, one empty interval.
        c.tick(handover(&c, 15_338, 10_400), TICK);
        assert!(c.report_age().is_some_and(|a| a >= Duration::from_secs(2)));
        assert_eq!(c.receiver_silence(), None, "still one empty interval");
        one_second(&mut c, |c| handover(c, 15_338, 10_400), silent(130));
        assert!(
            c.receiver_silence()
                .is_some_and(|s| s >= Duration::from_secs(2)),
            "{:?}",
            c.receiver_silence()
        );
        one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(130, 0.0, 0));
        assert_eq!(c.receiver_silence(), None, "reporting again");

        let mut still = on_wifi_at_1080p60();
        for _ in 0..3 {
            one_second(&mut still, |c| gone_still(c, 15_338), silent(130));
        }
        assert_eq!(still.receiver_silence(), None, "a still screen's quiet");
    }

    /// Only silence is the page's: a hidden page that is awake and reports loss is braked on its
    /// word, as any other.
    #[test]
    fn a_hidden_page_that_reports_loss_is_braked_as_always() {
        let mut c = on_wifi_at_1080p60();
        c.set_page_hidden(true);
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(131, 12.0, 30),
        );
        assert_eq!(c.brake_state(), "engaged");
        assert!(matches!(c.take_brake_event(), Some(BrakeEvent::Engaged(_))));
    }

    /// A silence-only brake from before the hold is dropped on the resume, as the outage is, so the
    /// hold's restart is not refused `no-report`. A brake the receiver's reports set stays and
    /// refuses it.
    #[test]
    fn a_silence_brake_is_dropped_on_the_resume_and_the_restart_goes() {
        let mut c = on_wifi_at_1080p60();
        for _ in 0..6 {
            one_second(&mut c, |c| handover(c, 15_338, 10_400), silent(130));
        }
        assert_eq!(c.brake_state(), "engaged");
        let _ = c.take_brake_event();
        let anchor = c
            .capacity_kbps()
            .min(c.current().absorbable_kbps(1620, 1080));
        let r = c.resume_after_hold(Duration::from_secs(22), 368);
        assert!(r.reanchor_due);
        assert_eq!(c.brake_state(), "-", "silence is no word about the path");
        let h = c.reanchor_after_hold(368);
        assert_eq!(h.refused, None);
        assert_eq!(c.take_bwe_reanchor(), Some(anchor.max(368)));

        let mut c = on_wifi_at_1080p60();
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(131, 12.0, 30),
        );
        assert_eq!(c.brake_state(), "engaged");
        let _ = c.take_brake_event();
        c.resume_after_hold(Duration::from_secs(22), 368);
        assert_ne!(c.brake_state(), "-", "the receiver's own word stays");
        assert_eq!(c.reanchor_after_hold(368).refused, Some("brake"));
    }

    /// The woken page's first reports read the time it slept: round trips of 10993 and 19668 ms
    /// (recorded on an iPhone), or the whole interval lost over a UDP path. Inside the window after
    /// a hold they say only that the receiver is back (no drain mode, no brake, no round-trip
    /// sample) until a report under both lines ends the window; past it, a stalled path is judged
    /// as ever.
    #[test]
    fn the_woken_pages_first_reports_are_not_the_path() {
        let mut c = on_wifi_at_1080p60();
        c.resume_after_hold(Duration::from_secs(30), 15_000);
        let _ = c.take_bwe_reanchor();
        for report in [
            fresh(10_993, 0.0, 0),
            fresh(19_668, 0.0, 0),
            fresh(131, 100.0, 0),
        ] {
            one_second(&mut c, |c| handover(c, 15_338, 10_400), report);
            assert!(!c.draining(), "{report:?}");
            assert_eq!(c.brake_state(), "-", "{report:?}");
            assert_eq!(c.take_brake_event(), None, "{report:?}");
        }
        assert_eq!(c.rtt_base_ms(), Some(127), "no sample from the sleep");
        assert!(c.report_age().is_some_and(|a| a < Duration::from_secs(2)));
        // A report under both lines: the path speaks again, and is heard as always.
        one_second(&mut c, |c| handover(c, 15_338, 10_400), fresh(130, 0.0, 0));
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(4_752, 0.0, 0),
        );
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(6_408, 0.0, 0),
        );
        assert!(c.draining(), "a stall after the window is a stall");

        // And the window ends by itself: four seconds on, a stall is a stall.
        let mut c = on_wifi_at_1080p60();
        c.resume_after_hold(Duration::from_secs(30), 15_000);
        for _ in 0..5 {
            one_second(&mut c, |c| handover(c, 15_338, 10_400), None);
        }
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(4_752, 0.0, 0),
        );
        one_second(
            &mut c,
            |c| handover(c, 15_338, 10_400),
            fresh(6_408, 0.0, 0),
        );
        assert!(c.draining());
    }

    // ── a recorded opening and path change ───────────────────────────────────────────────────

    /// A recorded opening as the control task saw it: 1080p@60 of a 2880x1780 game window, the
    /// encoder producing ~600 kbps against str0m's configured 600 before anything was measured.
    fn b57_opening(c: &QualityController, estimate_kbps: u32, egress_kbps: u32) -> Feedback {
        Feedback {
            estimate_kbps,
            drain_kbps: estimate_kbps * 11 / 10,
            produced_kbps: egress_kbps,
            egress_kbps,
            qp_samples: 0,
            queue_age_ms: 0,
            avg_qp: None,
            encode_ms: 3.2,
            spend_ratio: 0.5,
            rung_fps_hint: c.current().fps as f32,
            qp_ceiling: Some(46.0),
            drop_ratio: 0.0,
            report: None,
        }
    }

    /// The first second of a recorded session's media: egress 539 and 585 against str0m's opening
    /// 600 (inside the loaded band, so the informative floor "confirmed" 600), then the opening
    /// probes on a srflx pair through a VPN put the estimate at 1337. The echoed 600 must not
    /// become the first capacity evidence: once the opening is over the target is twice the 1337
    /// measured, not twice the echo.
    #[test]
    fn the_opening_estimate_echoed_back_is_not_the_first_capacity_evidence() {
        let ceiling = desired_bitrate_kbps(2880, 1780, Quality::Balanced);
        let mut c = QualityController::new(2880, 1780, Quality::Balanced);
        c.probe_target_sent(opening_probe_target_kbps(1920, 1080, Quality::Balanced));
        let mut taken = Vec::new();
        let fb = b57_opening(&c, 600, 0);
        taken.extend(probing_tick(&mut c, fb));
        let fb = b57_opening(&c, 600, 539);
        taken.extend(probing_tick(&mut c, fb));
        assert_eq!(
            c.informative_kbps, 600,
            "the opening value echoed back: the fixture reproduces the session"
        );
        // 18:29:43.44: the estimate leaves 600 for 1337, egress 585 — then a second of the same.
        for _ in 0..6 {
            let fb = b57_opening(&c, 1_337, 585);
            taken.extend(probing_tick(&mut c, fb));
        }
        assert_eq!(
            c.informative_kbps, 0,
            "the floor that only confirmed our own configuration is forgotten once a measurement \
             lands above it"
        );
        assert!(
            !c.probe_evidence_seen(),
            "the echo is not the first capacity evidence"
        );
        assert!(c.probe_opening());
        assert_eq!(c.probe_target_kbps(), ceiling, "the opening");
        assert!(taken.iter().all(|&k| k == ceiling), "{taken:?}");
        // The rest of the opening, the same: then twice the first measurement.
        let (ticks, sent) = through_the_probe_opening(&mut c, |c| b57_opening(c, 1_337, 585));
        taken.extend(sent);
        assert_eq!(
            7 + ticks,
            15,
            "three seconds of media, from the first egress"
        );
        assert!(!c.probe_evidence_seen());
        assert_eq!(
            c.probe_target_kbps(),
            2 * 1_337,
            "twice the first measurement, not twice our own configuration"
        );
        assert_eq!(
            taken
                .iter()
                .filter(|&&k| k != ceiling)
                .copied()
                .collect::<Vec<_>>(),
            vec![2 * 1_337],
            "sent on the tick the opening ended, and nothing else (the session sent 1180)"
        );
    }

    /// Runs `seconds` of `fb` with `report(second)` on each second's first tick, and returns every
    /// re-anchor taken as (tick index, value, its details).
    fn run_reanchors(
        c: &mut QualityController,
        seconds: u32,
        fb: impl Fn(&QualityController) -> Feedback,
        report: impl Fn(u32) -> Option<ReceiverReport>,
    ) -> Vec<(u32, u32, Reanchor)> {
        let mut out = Vec::new();
        for second in 0..seconds {
            for t in 0..5u32 {
                let f = Feedback {
                    report: if t == 0 { report(second) } else { None },
                    ..fb(c)
                };
                c.tick(f, TICK);
                if let Some(kbps) = c.take_probe_target() {
                    c.probe_target_sent(kbps);
                }
                if let Some(kbps) = c.take_bwe_reanchor() {
                    out.push((second * 5 + t, kbps, c.last_reanchor().expect("details")));
                }
            }
        }
        out
    }

    /// A controller past str0m's opening: one second at the configured 600.
    fn past_the_opening(c: &mut QualityController) {
        one_second(c, |c| b57_opening(c, 600, 540), None);
    }

    /// A healthy link to start from: the estimate at 1337 and carried, the receiver at `rtt`.
    fn settled_at(c: &mut QualityController, rtt: u32) {
        let carried = |c: &QualityController| Feedback {
            avg_qp: Some(30.0),
            qp_samples: 12,
            spend_ratio: 0.9,
            drop_ratio: 0.0,
            ..b57_opening(c, 1_337, 1_250)
        };
        past_the_opening(c);
        let _ = run_reanchors(c, 5, carried, |_| fresh(rtt, 0.0, 0));
    }

    /// The media moved from a srflx pair (through a VPN, 134-163 ms) to the viewer's host address
    /// on the LAN (8 ms). The opening probes had measured the old pair; the new one is probed again
    /// at once from the live estimate, and the old pair's evidence is forgotten. A move to a less
    /// direct pair, or a sideways one whose round trip does not halve, keeps the estimate; a
    /// sideways one whose round trip halves is probed too.
    ///
    /// The new path's probe target is a new session's: the ladder's ceiling for its opening
    /// ([`PROBE_OPENING`], counted from the re-probe), so str0m's opening probes reach 3x and 6x
    /// the restart (8022 here) and the exponential probing after them is not held to our tick; then
    /// twice the best estimate seen, restarting at the restart value.
    #[test]
    fn a_more_direct_path_is_probed_again_from_the_live_estimate() {
        let ceiling = desired_bitrate_kbps(1620, 1080, Quality::Balanced);
        let carried = |c: &QualityController| Feedback {
            avg_qp: Some(30.0),
            qp_samples: 12,
            spend_ratio: 0.9,
            drop_ratio: 0.0,
            ..b57_opening(c, 1_337, 1_250)
        };

        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        settled_at(&mut c, 134);
        assert!(!c.probe_opening(), "the session's opening is behind it");
        let before = c.probe_target_kbps();
        assert_eq!(before, 2 * 1_337, "the old path's evidence set the target");
        c.note_path_move(
            "selected_pair",
            Some(PathKind::Reflexive),
            Some(PathKind::Host),
        );
        c.tick(carried(&c), TICK);
        assert_eq!(
            c.take_probe_target(),
            Some(ceiling),
            "the new path's opening goes out on the same tick, ahead of the re-anchor"
        );
        c.probe_target_sent(ceiling);
        let kbps = c
            .take_bwe_reanchor()
            .expect("a more direct path is re-probed at once");
        assert_eq!(kbps, 1_337, "restarted at the live estimate");
        let r = c.last_reanchor().expect("details");
        assert_eq!(r.trigger, ReanchorTrigger::PathChange);
        assert_eq!(
            r.probe_cap_kbps,
            Some(2 * ceiling),
            "str0m's opening, held to twice the target: 3x and 6x the restart"
        );
        assert_eq!(c.capacity_kbps(), 0, "the old path's evidence is forgotten");
        assert!(!c.probe_evidence_seen());
        assert!(c.probe_opening());
        assert_eq!(c.probe_best_kbps(), 1_337);
        assert_eq!(c.probe_target_kbps(), ceiling);

        // The LAN answers the opening probes within a round trip, before its first receiver
        // report: the target stays at the ceiling, so nothing to send and nothing held back.
        let mut sent = Vec::new();
        for estimate in [4_011, 8_022, 16_000] {
            let fb = Feedback {
                estimate_kbps: estimate,
                drain_kbps: estimate * 11 / 10,
                ..carried(&c)
            };
            sent.push(probing_tick(&mut c, fb));
            assert_eq!(c.probe_target_kbps(), ceiling);
        }
        assert_eq!(sent, vec![None, None, None]);
        assert!(
            !c.probe_evidence_seen(),
            "no report on the new path yet: the bound, not evidence"
        );
        // Three seconds after the re-probe the opening is over; twice the best estimate seen is past
        // the ceiling, so the target stays there.
        let (ticks, sent) = through_the_probe_opening(&mut c, |c| Feedback {
            estimate_kbps: 16_000,
            drain_kbps: 17_600,
            ..carried(c)
        });
        assert_eq!(1 + 3 + ticks, 15, "three seconds from the re-probe's tick");
        assert_eq!(sent, Vec::<u32>::new());
        assert_eq!(c.probe_target_kbps(), ceiling);

        // A new path that answers with less: when its opening ends the target is twice the restart
        // value, before str0m's periodic probe can go out at twice the ceiling.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        settled_at(&mut c, 134);
        let dipped = |c: &QualityController| Feedback {
            estimate_kbps: 1_000,
            drain_kbps: 1_100,
            ..carried(c)
        };
        c.note_path_move(
            "selected_pair",
            Some(PathKind::Reflexive),
            Some(PathKind::Host),
        );
        let fb = dipped(&c);
        assert_eq!(probing_tick(&mut c, fb), Some(ceiling));
        assert_eq!(c.take_bwe_reanchor(), Some(1_000));
        assert_eq!(
            c.last_reanchor().and_then(|r| r.probe_cap_kbps),
            Some(2 * ceiling)
        );
        let (ticks, sent) = through_the_probe_opening(&mut c, dipped);
        assert_eq!(1 + ticks, 15);
        assert_eq!(
            sent,
            vec![2 * 1_000],
            "twice the restart value, on the opening's last tick"
        );

        // Less direct: nothing, for as long as the change is judged and after.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        settled_at(&mut c, 8);
        c.note_path_move("selected_pair", Some(PathKind::Host), Some(PathKind::Relay));
        let fired = run_reanchors(&mut c, 8, carried, |_| fresh(140, 0.0, 0));
        assert!(
            fired
                .iter()
                .all(|(_, _, r)| r.trigger != ReanchorTrigger::PathChange),
            "{fired:?}"
        );
        assert!(
            c.capacity_kbps() > 0,
            "and the evidence carries over, as it always did"
        );

        // Sideways, the round trip not halved: nothing.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        settled_at(&mut c, 140);
        c.note_path_move(
            "selected_pair",
            Some(PathKind::Relay),
            Some(PathKind::Relay),
        );
        let fired = run_reanchors(&mut c, 8, carried, |_| fresh(120, 0.0, 0));
        assert!(
            fired
                .iter()
                .all(|(_, _, r)| r.trigger != ReanchorTrigger::PathChange),
            "{fired:?}"
        );

        // Sideways, the round trip halved: probed once the new path has reported.
        let mut c = QualityController::new(1620, 1080, Quality::Balanced);
        c.probe_target_sent(ceiling);
        settled_at(&mut c, 140);
        c.note_path_move(
            "selected_pair",
            Some(PathKind::Relay),
            Some(PathKind::Relay),
        );
        let fired = run_reanchors(&mut c, 3, carried, |_| fresh(40, 0.0, 0));
        assert!(
            fired
                .iter()
                .any(|(_, _, r)| r.trigger == ReanchorTrigger::PathChange),
            "{fired:?}"
        );
    }
}
