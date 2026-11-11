//! Software H.264 encoding via OpenH264.
//!
//! Chosen encoder: the `openh264` crate (Cisco OpenH264, built from source).
//! It is pure-Rust-friendly (only a bundled C++ build, no external runtime),
//! browser-decodable, and str0m can packetize its Annex-B output. Hardware
//! encoders (Media Foundation / NVENC) are a future impl behind the same
//! [`Encoder`](afklink_core::traits::Encoder) trait.
//!
//! Config: Constrained Baseline, `CAMERA_VIDEO_REAL_TIME` with scene-change detection off (see
//! the note at the config: screen-content mode cannot hold a bitrate),
//! bitrate and frame rate from the quality ladder, on-demand IDR via `force_intra_frame` with a
//! long periodic one as a backstop (see `GOP_SECONDS`).

use anyhow::{Context, Result};
use openh264::encoder::{
    BitRate, Encoder as Oh264Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod,
    Profile, QpRange, RateControlMode, UsageType,
};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::{OpenH264API, Timestamp};
use openh264_sys2::{
    SBitrateInfo, SEncoderStatistics, ENCODER_OPTION_BITRATE, ENCODER_OPTION_FRAME_RATE,
    ENCODER_OPTION_GET_STATISTICS, ENCODER_OPTION_MAX_BITRATE, SPATIAL_LAYER_0, SPATIAL_LAYER_ALL,
};

use afklink_core::scale::Scaler;
use afklink_core::traits::Encoder;
use afklink_core::types::{EncodedFrame, Frame};

/// The bitrate an encoder is *constructed* with, in bits/sec.
///
/// Almost immediately overridden by [`Encoder::set_target`], so its only lasting effect is one
/// frame — and that frame is an IDR. The `openh264` crate re-initialises on every frame-size
/// change and re-pushes its own `EncoderConfig` (`encoder.rs:966`, `:1010-1011`), so the keyframe
/// that every ladder step produces is encoded against *this* number rather than the ladder's. At
/// 3 Mbps a 1080p step costs about 98 kB, roughly a second of the link, and that frame is also the
/// only `idr_bytes` sample the step produces.
///
/// 1.5 Mbps sits in the middle of the ladder, so that frame is priced like the stream around it.
pub const DEFAULT_BITRATE_BPS: u32 = 1_500_000;
/// Target frame rate.
pub const DEFAULT_FPS: f32 = 30.0;
/// GOP length in frames: [`GOP_SECONDS`] at [`DEFAULT_FPS`], so 3000.
///
/// Fixed in frames at construction, so the interval in *seconds* stretches as the ladder lowers
/// the frame rate: fifty seconds at 60 fps, two hundred at 15. That is acceptable only because a
/// periodic keyframe is not how a viewer recovers here: the browser sends a PLI and
/// [`Encoder::request_keyframe`] answers it. This is the backstop for a lost PLI, and it is the
/// same number libwebrtc's H.264 screen share uses (`key_frame_interval = 3000`).
///
/// OpenH264 only requires `uiIntraPeriod` to be a multiple of the GOP size, which is 1 here
/// (`encoder_ext.cpp`, `ParamValidationExt`). There is no upper bound to run into.
pub const DEFAULT_GOP_FRAMES: u32 = 30 * GOP_SECONDS;
/// Default max encoded resolution (also under OpenH264's 3840x2160 cap).
///
/// Re-exported from `afklink_core::scale`, where the capture side reads the same two numbers.
/// One definition, because capture scales to this bound and the encoder enforces it: two copies
/// would mean scaling twice, to two different sizes, for every frame.
pub use afklink_core::scale::{DEFAULT_MAX_H, DEFAULT_MAX_W};

/// The largest a single slice may be, in bytes.
///
/// Two jobs, and it is the same number for both.
///
/// **It is what makes threads mean anything.** OpenH264 divides work by slice, and on screen
/// content it emits one slice per frame unless told otherwise, so a thread count above one has
/// nothing to divide. Measured at 1620x1080: 11.32 ms on one thread, 11.29 on four, and 7.62 once
/// the frame is sliced. A third off the stage that limits the frame rate.
///
/// **And it bounds what one frame can put on the wire at once.** A hard 1080p frame measured 110
/// kB against a 1756 kbps budget, and one of those is several hundred milliseconds of send queue
/// on a relayed link, which is what trips the capturer's latency ramp and produces the drops
/// people report while watching video. Sliced, the same bits arrive as many bounded pieces.
///
/// Four kilobytes because the slice count then follows the difficulty of the frame: an ordinary 7
/// kB frame becomes two slices and pays almost nothing, while the 110 kB frame that actually hurts
/// becomes twenty-seven and is spread across every thread there is. A slice cannot predict across
/// its own boundary, so this is paid for in compression: the synthetic bench says between -8% and
/// +10%, which is too noisy to trust, and `encode_ms` and `kbps` on a real session are what settle
/// it.
const SLICE_BYTES: u32 = 4 * 1024;

/// The smallest bitrate change worth a call into OpenH264, as a percentage.
///
/// Unrelated to keyframes: retargeting is free (see [`Encoder::set_target`]). This exists only so
/// the encoder is not handed a new number several times a second for changes
/// no picture could show, and it is deliberately small.
const RETARGET_THRESHOLD_PCT: u64 = 5;

/// How long a GOP should last, in seconds: a backstop, not the recovery mechanism.
///
/// ## Why this is a hundred and not two
///
/// An IDR at 1080p costs 50 to 85 kB *whatever the budget is*, and that "whatever" is the whole
/// argument. `RcCalculateIdrQp` (`ratectl.cpp:403-474`) clips an IDR's quantiser into a hard-coded
/// table whose coarsest entry is 40, so a keyframe cannot be made to fit a small budget the way a
/// P-frame can: lowering the bitrate does not shrink it, it only makes it a larger share of the
/// second it lands in.
///
/// Priced as latency rather than as overhead: 85 kB is 170 ms of send queue at 4 Mbps and over
/// 500 ms at 1.2 Mbps. At a ten-second period that is half a second of queue on a schedule, in a
/// product whose entire end-to-end budget is a few hundred milliseconds, for keyframes no viewer
/// asked for.
///
/// A *short* period is ruled out outright. Measured at 1620x1080@30 with a video playing and a
/// 2 s GOP:
///
///   encode_fps=3.0  kbps=1902  budget=2446  skipped_by_encoder=27
///   encode_fps=3.9  kbps=2303  budget=2446  skipped_by_encoder=26
///   encode_fps=3.0  kbps=1745  budget=2570  skipped_by_encoder=28
///   encode_fps=4.0  kbps=2293  budget=2570  skipped_by_encoder=26
///
/// Four seconds of three frames a second while still pushing two megabits, almost all of it
/// keyframe. At two seconds the stream collapses, at ten the keyframe is a recurring latency
/// spike, and at a hundred the periodic IDR stops being a term in the latency sum at all (under
/// half a percent of a 1.2 Mbps stream).
///
/// ## Why a backstop is enough
///
/// In WebRTC the receiver asks. A browser that joins late, or loses the picture, sends a PLI, and
/// the agent answers it with `force_intra_frame`; that path is what keeps a viewer in sync.
/// libwebrtc's own H.264 screen share does not rely on a short period either: its
/// `key_frame_interval` is 3000 frames, which at 30 fps is exactly this number, the shipped
/// setting of the reference implementation.
const GOP_SECONDS: u32 = 100;

/// Bounds on what the ladder may ask for.
///
/// The floor is not politeness: OpenH264's rate control given a few kbps produces a picture that
/// is worse than useless, and the session would look broken rather than degraded.
///
/// The ceiling is a guard against a nonsense value reaching OpenH264, not a policy. Policy is the
/// ladder's job (`afklink_core::quality`), and the ladder goes to 1080p60, which on a 32:9
/// ultrawide at the `Best` quality setting prices at roughly 7.2 Mbps. A ceiling below that would
/// silently clip the top of the ladder and produce the one failure that is genuinely hard to see
/// from the outside: a rung the controller believes it is sending and the encoder is not.
///
/// 12 Mbps is RustDesk's own top table entry, which is where the rest of these numbers come from.
const MIN_BITRATE_KBPS: u32 = 120;
const MAX_BITRATE_KBPS: u32 = 12_000;

/// The quantiser range this encoder is allowed to use.
///
/// ## This is the single most consequential line in the file
///
/// The default is not what it looks like. `EncoderConfig::default()` uses
/// `QpRange::new(0, 51)` (`openh264-0.9.8/src/encoder.rs:678`) and pushes both halves into
/// `iMinQp`/`iMaxQp` (`:986-987`). OpenH264 then reads them:
///
/// ```text
/// // encoder_ext.cpp:375-380
/// if ((pCfg->iMaxQp <= 0) || (pCfg->iMinQp <= 0)) {
///   if (pCfg->iUsageType == SCREEN_CONTENT_REAL_TIME) {
///     pCfg->iMinQp = MIN_SCREEN_QP;   // 26
///     pCfg->iMaxQp = MAX_SCREEN_QP;   // 35
///   }
/// ```
///
/// The condition is an `||`, so a zero `iMinQp` overwrites **both** bounds. In screen-content
/// mode that is `[26, 35]`: nine steps. Bitrate roughly halves per +6 QP, so that is about 2.8x
/// of rate-control authority where `[12, 51]` offers around ninety. The `else` branch, which a
/// camera-content encoder hits, substitutes `[GOM_MIN_QP_MODE, MAX_LOW_BR_QP]` = `[12, 42]`:
/// wider, and still not the band the ladder steers on.
///
/// The narrow band shows both symptoms in one measured session. At 30 fps the encoder produced
/// 280-374 kbps against a 412-606 budget: QP pinned at its floor, *forbidden* to spend what it was
/// given. At 2.5 fps it produced 770-1210 against 345-780 with 40-46 kB frames: QP pinned at its
/// ceiling, forbidden to compress further. And because congestion control cannot estimate above
/// what is offered, the "1.4 Mbps link" in the logs was a measurement of `iMinQp`, not of the
/// network.
///
/// OpenH264 logs the substitution at `WELS_LOG_INFO`, which `.debug(false)` filters out. The
/// neighbouring warning at `encoder_ext.cpp:370-374`, "bitrate can't be controlled ... without
/// enabling skip frame", is at `WELS_LOG_WARNING` and does reach stderr.
///
/// ## Why 16 and 46
///
/// The band has to contain the thresholds the ladder steers on, with room on both sides, because a
/// threshold at the edge of the reachable range is a threshold that never fires. Those are
/// `afklink_core::quality`'s `QP_UP` (32) for climbing and `QP_DOWN` (42) for shedding pixels.
///
/// `QP_DOWN` sits above libwebrtc's `kHighH264QpThreshold` of 37 (their *camera video*
/// scale-down threshold) as a deliberate trade: every rung change forces an IDR of 50 to 85 kB
/// and makes the browser rebuild its hardware decoder on the new SPS, which the user sees as close
/// to a second of frozen picture. So a rung is ridden further on quantiser before pixels are shed:
/// a coarser picture under load, in exchange for fewer freezes. Camera mode is what makes that
/// affordable: it holds its bitrate, so a coarse quantiser means "this content is expensive"
/// rather than "the encoder has lost control".
///
/// 46 leaves four steps above `QP_DOWN`, which `starved` needs: it fires at `ceiling - 1`, so 45
/// must still be distinguishable from 42. 16 is sharp enough that a generous link is visibly
/// spent.
///
/// Not wider. `GOM_MIN_QP_MODE` is 12 and `QP_MAX_VALUE` 51, and both extremes are worse than the
/// ladder step they would postpone: QP 12 spends a fortune on detail nobody asked for, and QP 51
/// is a picture that looks broken rather than small.
///
/// Neither bound may ever be zero, or OpenH264 silently substitutes its own band again.
const QP_MIN: u8 = 16;
const QP_MAX: u8 = 46;

// Zero on *either* bound re-arms the substitution: OpenH264's test is an `||`, so a zero minimum
// silently replaces the maximum too. Checked at compile time because there is no runtime signal:
// the substitution is logged at `WELS_LOG_INFO`, which this encoder filters out.
const _: () = assert!(
    QP_MIN > 0 && QP_MAX > 0,
    "zero re-arms OpenH264's own quantiser clamp"
);
// And the band must contain the thresholds the ladder steers on, with room on both sides, or those
// thresholds can never be crossed and the ladder is blind. `afklink_core::quality` climbs below
// `QP_UP` = 32 and sheds pixels above `QP_DOWN` = 42; `starved` additionally needs daylight between
// `QP_DOWN` and `QP_MAX - 1`, which is where the four-step margin below comes from. (These cannot
// be imported, because `afklink-core` does not depend on this crate and must not, so they are
// restated here and the numbers are load-bearing in both files.)
const _: () = assert!(
    QP_MIN < 32 && QP_MAX >= 42 + 4,
    "the ladder's QP thresholds must be inside the range the encoder can reach, and QP_DOWN must \
     leave room below the ceiling for `starved` to mean something"
);

/// What to hand OpenH264 as the per-layer maximum bitrate, in bits/sec.
///
/// Not `UNSPECIFIED_BIT_RATE`, which cannot work: `codec_app_def.h:60` defines it as **0**, and
/// `welsEncoderExt.cpp:912-917` rejects `iBitrate <= 0` with `cmInitParaError` before reaching
/// the layer switch, so the call always fails with `rc=1`.
///
/// A large finite number does the same job. The crate pins `iMaxSpatialBitrate` to the
/// *construction* bitrate (`encoder.rs:1010-1011`) and re-pins it on every re-initialisation, and
/// `WelsBitRateVerification` refuses any layer whose target exceeds its maximum, so without this
/// every retarget above [`DEFAULT_BITRATE_BPS`] would fail, visible only as a `debug!` line.
/// `WelsBitRateVerification` clamps this down to the level's own ceiling, which is the real
/// "unpinned" state and exactly what libwebrtc arranges by setting `iMaxBitrate` before init.
const MAX_SPATIAL_BITRATE_BPS: i32 = 100_000_000;

pub struct OpenH264Encoder {
    enc: Oh264Encoder,
    pending_keyframe: bool,
    started: bool,
    /// Fits oversized frames to max_w/max_h. A no-op when capture already scaled.
    scaler: Scaler,
    /// Maximum encoded dimensions; larger frames are downscaled to fit.
    max_w: u32,
    max_h: u32,
    /// What this encoder was built with, so a retarget knows whether it is worth a rebuild.
    bitrate_bps: u32,
    fps: f32,
    gop_frames: u32,
    threads: u16,
    /// The last size actually handed to OpenH264, for spotting a re-initialisation.
    last_dims: Option<(u32, u32)>,
    /// Set when OpenH264 has just been (re-)initialised and has therefore reverted to the crate's
    /// own configuration. See the note in [`Encoder::encode`].
    needs_reassert: bool,
    /// Whether the last target asked for was outside [`MIN_BITRATE_KBPS`, `MAX_BITRATE_KBPS`], so
    /// the clamp is logged when it starts and stops binding rather than on every frame.
    clamped: bool,
    /// Whether reading the quantiser has already been reported failing. The ladder's primary
    /// signal going dark is worth one warning, not one per frame.
    qp_read_failed: bool,
}

impl OpenH264Encoder {
    pub fn new(bitrate_bps: u32, fps: f32, gop_frames: u32) -> Result<Self> {
        Self::new_tuned(
            bitrate_bps,
            fps,
            gop_frames,
            Self::auto_threads(),
            Some(SLICE_BYTES),
        )
    }

    /// Encoder threads: up to four, and only useful together with [`SLICE_BYTES`].
    ///
    /// ## Why threads need slices
    ///
    /// Threads alone change nothing: 11.32 ms on one against 11.29 on four at 1620x1080. OpenH264
    /// parallelises by handing each thread a *slice*, and left to itself on screen content it
    /// emits one slice per frame, so the extra threads have nothing to divide. Give them slices and
    /// the same bench reads 7.6 ms: a third off the stage that limits the frame rate.
    ///
    /// ## How many, and why not more
    ///
    /// Half the logical cores, capped at four.
    ///
    /// Not a flat four: four threads of H.264 on a two-core laptop is the whole processor, and the
    /// person whose laptop it is did not ask for a slideshow of their own desktop in exchange for a
    /// smoother picture somewhere else. Half scales in the right direction: one thread on a dual
    /// core, two on a quad, four on anything from eight up.
    ///
    /// The cap at four is not politeness, it is where the returns stop: OpenH264 hands each thread
    /// a slice, and at [`SLICE_BYTES`] an ordinary frame only produces two or three. Threads past
    /// the slice count wait.
    ///
    /// ## Why the threads are not the whole story
    ///
    /// These threads are not pinned and not prioritised, so what actually keeps the encoder from
    /// starving the foreground is that it only runs when there is a frame to encode, and the
    /// capturer decides how often that is. The frame rate is the throttle. That is why the ladder
    /// and the latency ramp both live upstream of here: an encoder given fewer frames uses less
    /// processor, exactly and immediately, with no scheduler tuning involved.
    fn auto_threads() -> u16 {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        u16::try_from(cores / 2).unwrap_or(1).clamp(1, 4)
    }

    /// As [`Self::new`], with an explicit thread count (1 = single-threaded).
    pub fn new_with_threads(
        bitrate_bps: u32,
        fps: f32,
        gop_frames: u32,
        threads: u16,
    ) -> Result<Self> {
        Self::new_tuned(bitrate_bps, fps, gop_frames, threads, None)
    }

    /// As [`Self::new_with_threads`], optionally capping the size of one slice in bytes.
    ///
    /// The cap is what makes the thread count mean anything. OpenH264 parallelises by handing each
    /// thread a slice, and left to itself on screen content it produces one slice per frame, so
    /// without a cap extra threads have nothing to do.
    ///
    /// A cap also bounds what a single frame can put on the wire in one go, which is the other
    /// half of the problem: a hard frame at 1080p measured 110 kB against a 1756 kbps budget, and
    /// one of those is several hundred milliseconds of send queue on a relayed link.
    pub fn new_tuned(
        bitrate_bps: u32,
        fps: f32,
        gop_frames: u32,
        threads: u16,
        max_slice_len: Option<u32>,
    ) -> Result<Self> {
        Self::from_config(
            Self::config(bitrate_bps, fps, gop_frames, threads, max_slice_len),
            bitrate_bps,
            fps,
            gop_frames,
            threads,
        )
    }

    /// The `EncoderConfig` this crate hands to OpenH264, split out of [`Self::new_tuned`] so a
    /// test can start from it and vary one field; see
    /// `the_quantiser_band_is_the_configured_one_and_both_ends_are_reachable` and
    /// `continuous_motion_is_not_coded_as_a_keyframe_every_frame`, both of which build a
    /// screen-content variant this way rather than duplicating the whole builder chain.
    fn config(
        bitrate_bps: u32,
        fps: f32,
        gop_frames: u32,
        threads: u16,
        max_slice_len: Option<u32>,
    ) -> EncoderConfig {
        let config = EncoderConfig::new()
            .profile(Profile::Baseline)
            .bitrate(BitRate::from_bps(bitrate_bps))
            .max_frame_rate(FrameRate::from_hz(fps))
            .rate_control_mode(RateControlMode::Bitrate)
            .usage_type(UsageType::CameraVideoRealTime)
            .intra_frame_period(IntraFramePeriod::from_num_frames(gop_frames))
            .num_threads(threads)
            // OpenH264 does NOT get to decide which frames to drop.
            //
            // Dropping frames beats accruing latency, and RC_BITRATE_MODE needs skipping to hold a
            // target. The question is *who* does the dropping.
            //
            // OpenH264's skip governor is a leaky bucket, `iBufferFullnessSkip`, sized at half a
            // second of bitrate. Three properties of it combine badly here. It is zeroed only by
            // `RcInitRefreshParameter`, which is guarded by `0 == iIdrNum`, so it is drained after
            // the *first* IDR and never again, while every later IDR dumps `IDR_BITRATE_RATIO = 4`
            // times a frame's budget into it. `RcUpdateBitrateFps` (which is what
            // `SetOption(ENCODER_OPTION_BITRATE)` calls) resizes the bucket while leaving its
            // contents, so a bitrate change against a full bucket instantly overfills it. And the
            // governor then permits *more* consecutive skips the more overfull it is, so the
            // failure is not "half the frames", it is "almost all of them".
            //
            // Measured with OpenH264 skipping, an empty send queue and an estimate above the
            // budget:
            //
            //   cap=35.3  enc=1.8  out=1090  bud=1726  est=1758  q=0  skip=38
            //   cap=38.4  enc=1.7  out=1163  bud=1726  est=1847  q=0  skip=44
            //   cap=42.4  enc=1.8  out=1161  bud=1726  est=2045  q=0  skip=46
            //
            // Forty-six frames captured, forty-six declined, while *under* budget on a link with
            // room to spare, and nothing outside the encoder can see why: no queue, no congestion,
            // no loss.
            //
            // ## Who drops instead
            //
            // Frames still have to be dropped occasionally, and the pipeline does it in the one
            // place that knows something OpenH264 does not: the encode loop's bit bucket
            // (`afklink_core::frame_dropper`), which sees the budget the ladder decided as well as
            // every frame's size, and spreads its drops as a duty cycle instead of a run.
            //
            // It is a safety net rather than the rate controller. Under `ScreenContentRealTime`
            // the encoder overshoots four to five times whatever it is told and the bucket would
            // carry the whole rate. In camera mode the encoder holds its target, so what is left
            // for the bucket is what no rate controller without a VBV can bound: one keyframe, or
            // one short burst, costing more than the budget for the window it lands in. The
            // control task warns if it starts
            // withholding more than a tenth of frames for more than three seconds, because that
            // means rate control has stopped working and this is hiding it.
            //
            // That cascade (degrade quality, then drop at the source, then step the ladder down)
            // is libwebrtc's, and it is why libwebrtc runs its own `FrameDropper` instead of
            // trusting the codec's.
            .skip_frames(false)
            // The quantiser range, explicitly, because the default is a trap. See [`QP_MIN`].
            //
            // With `skip_frames(false)` above, QP is the *only* rate-control lever this encoder
            // has, as OpenH264's own stderr warning says. So these two lines are the entire rate
            // controller, and the default would narrow the second to a ninth of its range.
            .qp(QpRange::new(QP_MIN, QP_MAX))
            // `CameraVideoRealTime` above, not `ScreenContentRealTime`, and scene-change
            // detection forced off: the two belong together, because the first is what makes the
            // second possible.
            //
            // ## Screen-content mode does not default to detecting scene changes; it forces it
            //
            // `encoder_ext.cpp:292-295` overwrites `bEnableSceneChangeDetect == false` back to
            // `true` whenever `iUsageType == SCREEN_CONTENT_REAL_TIME`, logging "screen change
            // detection should be turned on". In that mode `.scene_change_detect(false)` is a
            // no-op: the output is byte-identical to leaving it at its default.
            //
            // ## And the detector fires on exactly the content this product carries
            //
            // `CWelsPreProcessScreen::DetectSceneChange` (`wels_preprocess.cpp:1096-1260`, called
            // from `:409-413`) reports `LARGE_CHANGED_SCENE` when block matching fails against
            // every available reference, which under full-screen motion (a game or a pan) is
            // every single frame. `DecideFrameType` (`encoder.cpp:341-350`) codes a reported
            // scene change as an IDR without a long-term reference to fall back on, and
            // `RcCalculateIdrQp` (`ratectl.cpp:403-474`) clips that IDR's quantiser into a
            // hard-coded `iQpRangeArray = {{40,28},{37,25},{36,24},{35,23},{34,22}}`, never
            // coarser than QP 40 regardless of `QP_MAX` above, while `RcDecideTargetBits`
            // (`:576-581`) budgets it at `IDR_BITRATE_RATIO = 4` times an ordinary frame's bits.
            // `QP_MAX` is not the binding constraint there; the frame type chosen ahead of it is.
            //
            // ## Measured
            //
            // `examples/usage_mode.rs`, 1080p at a 4000 kbps budget: `churn` (a panning,
            // structured picture) under screen mode produced 34702 kbps with all 60/60 frames
            // coded IDR; the same content under camera mode with detection off produced 3162
            // kbps, 1/60 IDR. On `desktop` at the same budget, screen mode held quantiser at 40
            // where camera mode held 30. Encoding was faster too: 2.6 ms/frame under camera
            // against 6.5 under screen.
            //
            // Adaptive quantization and background detection were measured, not assumed: both on
            // cost more time (3.04 vs 2.32 ms/frame) for no bitrate improvement, so both stay off.
            .scene_change_detect(false)
            .adaptive_quantization(false)
            .background_detection(false)
            .debug(false);
        match max_slice_len {
            Some(len) => config.max_slice_len(len),
            None => config,
        }
    }

    /// Build an encoder from an already-constructed [`EncoderConfig`], doing exactly what
    /// [`Self::new_tuned`] does with one it built itself. Split out so a test can hand in a
    /// deliberately different config (see [`Self::config`]) without reconstructing this struct
    /// by hand.
    fn from_config(
        config: EncoderConfig,
        bitrate_bps: u32,
        fps: f32,
        gop_frames: u32,
        threads: u16,
    ) -> Result<Self> {
        let enc = Oh264Encoder::with_api_config(OpenH264API::from_source(), config)
            .context("init OpenH264 encoder")?;
        let me = Self {
            enc,
            pending_keyframe: false,
            started: false,
            scaler: Scaler::new(),
            max_w: DEFAULT_MAX_W,
            max_h: DEFAULT_MAX_H,
            bitrate_bps,
            fps,
            gop_frames,
            threads,
            last_dims: None,
            needs_reassert: false,
            clamped: false,
            qp_read_failed: false,
        };
        tracing::debug!(
            bitrate_kbps = bitrate_bps / 1000,
            fps,
            gop_frames = me.gop_frames,
            threads = me.threads,
            qp_min = QP_MIN,
            qp_max = QP_MAX,
            "openh264 encoder built"
        );
        Ok(me)
    }

    /// Push this encoder's real settings back onto a freshly (re-)initialised OpenH264 handle.
    ///
    /// Called after the first frame and after every resolution change, because both reset OpenH264
    /// to the `openh264` crate's own `EncoderConfig` — see the note in [`Encoder::encode`]. Best
    /// effort throughout: a refused option leaves the encoder mistargeted, which is a picture
    /// problem, and there is nothing better to do from here than say so.
    fn reassert(&mut self) {
        self.lift_max_bitrate();
        let kbps = self.bitrate_bps / 1000;
        if let Err(rc) = self.apply_bitrate(kbps) {
            tracing::warn!(kbps, rc, "could not restore bitrate after re-init");
        }
        let fps = self.fps;
        if let Err(rc) = self.apply_frame_rate(fps) {
            tracing::warn!(fps, rc, "could not restore frame rate after re-init");
        }
    }

    /// Hand OpenH264 a new bitrate without rebuilding it.
    ///
    /// `SPATIAL_LAYER_ALL` rather than layer 0: for a single-layer encoder OpenH264 redistributes
    /// it to the one layer, and it also updates the overall target, which layer 0 alone does not.
    ///
    /// Returns the raw return code on failure. `cmResultSuccess` is 0.
    fn apply_bitrate(&mut self, kbps: u32) -> Result<(), i32> {
        let mut info = SBitrateInfo {
            iLayer: SPATIAL_LAYER_ALL,
            iBitrate: (kbps as i32).saturating_mul(1000),
        };
        // SAFETY: `info` is a live, correctly-typed `SBitrateInfo` for the duration of the call,
        // which is what `ENCODER_OPTION_BITRATE` expects. OpenH264 copies out of it and does not
        // retain the pointer.
        let rc = unsafe {
            self.enc
                .raw_api()
                .set_option(ENCODER_OPTION_BITRATE, std::ptr::from_mut(&mut info).cast())
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// Hand OpenH264 a new frame rate without rebuilding it.
    ///
    /// Rate control divides the bitrate by this to get a per-frame allowance, so an encoder that
    /// believes in 60 while the ladder feeds it 15 gives every frame a quarter of its due. It is
    /// half of the budget.
    fn apply_frame_rate(&mut self, fps: f32) -> Result<(), i32> {
        let mut value = fps;
        // SAFETY: as above; `ENCODER_OPTION_FRAME_RATE` reads a single `f32` through the pointer.
        let rc = unsafe {
            self.enc.raw_api().set_option(
                ENCODER_OPTION_FRAME_RATE,
                std::ptr::from_mut(&mut value).cast(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// Lift the `openh264` crate's `iMaxSpatialBitrate == iSpatialBitrate` off the target.
    ///
    /// The crate pins both to the construction bitrate (`encoder.rs:1010-1011`) and re-pins them
    /// on every re-initialisation, and OpenH264 warns against exactly that: "Setting
    /// MaxSpatialBitrate the same at SpatialBitrate will make the actual bit rate lower than
    /// SpatialBitrate". `WelsBitRateVerification` also refuses any layer whose target exceeds its
    /// maximum, and that check runs inside every `SetOption(ENCODER_OPTION_BITRATE)`, so left
    /// pinned, every retarget above the construction bitrate fails silently.
    ///
    /// ## Why not libwebrtc's way
    ///
    /// libwebrtc sets `encoder_params.iMaxBitrate = UNSPECIFIED_BIT_RATE`
    /// (crbug.com/webrtc/11543). Passing that with `SPATIAL_LAYER_ALL` through the runtime API
    /// fails twice:
    ///
    ///   `UNSPECIFIED_BIT_RATE` is **0** (`codec_app_def.h:60`) and `welsEncoderExt.cpp:912-917`
    ///   rejects `iBitrate <= 0` with `cmInitParaError` before it looks at the layer, so the call
    ///   returns `rc=1`.
    ///
    ///   `SPATIAL_LAYER_ALL` is **4**, not -1, and for this option it writes `iMaxBitrate` on the
    ///   *parameter set* rather than `iMaxSpatialBitrate` on the layer: a different field from
    ///   the one that needs lifting.
    ///
    /// libwebrtc gets away with the zero because it sets the field in `SEncParamExt` *before*
    /// `InitializeExt`, where no range check runs. Through `SetOption` the equivalent is a large
    /// finite value on layer 0; `WelsBitRateVerification` clamps it to the level's own ceiling,
    /// which is the state libwebrtc is asking for.
    ///
    /// Best effort: an encoder that refuses this still works, it just cannot be retargeted upward.
    fn lift_max_bitrate(&mut self) {
        let mut info = SBitrateInfo {
            iLayer: SPATIAL_LAYER_0,
            iBitrate: MAX_SPATIAL_BITRATE_BPS,
        };
        // SAFETY: as `apply_bitrate`.
        let rc = unsafe {
            self.enc.raw_api().set_option(
                ENCODER_OPTION_MAX_BITRATE,
                std::ptr::from_mut(&mut info).cast(),
            )
        };
        if rc != 0 {
            tracing::warn!(rc, "could not lift OpenH264's max spatial bitrate");
        }
    }

    /// The quantiser OpenH264 used on the frame it just encoded, or `None` before the first.
    ///
    /// This is the ladder's primary signal, and it is the one libwebrtc's `QualityScaler` uses for
    /// the same decision. It says something no other measurement here can: *the picture is already
    /// as coarse as this many pixels gets and it still does not fit.* That is exactly the condition
    /// under which fewer pixels is the only remaining lever, and it is a property of the encoder,
    /// not of any controller's output, so reading it breaks no wiring rule.
    ///
    /// `uiAverageFrameQP` is documented as "the average QP of last encoded frame" and is written
    /// per frame, so this must be read per encoded frame rather than polled on a timer: on a slow
    /// tick the same frame is read many times and one frame can move the rung.
    fn read_frame_qp(&mut self) -> Option<u32> {
        if !self.started {
            return None;
        }
        let mut stats = SEncoderStatistics::default();
        // SAFETY: `stats` is a live, correctly-typed `SEncoderStatistics` for the duration of the
        // call, which is what `ENCODER_OPTION_GET_STATISTICS` writes through. OpenH264 fills it
        // and does not retain the pointer. The option is get-only; `SetOption` refuses it.
        let rc = unsafe {
            self.enc.raw_api().get_option(
                ENCODER_OPTION_GET_STATISTICS,
                std::ptr::from_mut(&mut stats).cast(),
            )
        };
        if rc != 0 && !self.qp_read_failed {
            // Without it the ladder sees `avg_qp=-` and its quantiser arms go quiet; once, because
            // this is called per frame.
            self.qp_read_failed = true;
            tracing::warn!(
                rc,
                "OpenH264 statistics unavailable: the quantiser cannot be read"
            );
        }
        (rc == 0 && stats.uiAverageFrameQP > 0).then_some(stats.uiAverageFrameQP)
    }

    /// Override the maximum encoded resolution (frames are downscaled to fit).
    pub fn set_max_resolution(&mut self, max_w: u32, max_h: u32) {
        self.max_w = max_w.max(2);
        self.max_h = max_h.max(2);
    }

    pub fn with_defaults() -> Result<Self> {
        Self::new(DEFAULT_BITRATE_BPS, DEFAULT_FPS, DEFAULT_GOP_FRAMES)
    }
}

impl Encoder for OpenH264Encoder {
    fn encode(&mut self, frame: &Frame) -> Result<Option<EncodedFrame>> {
        // OpenH264 (and I420 subsampling) require even dimensions.
        let full_w = frame.width as usize;
        let full_h = frame.height as usize;
        let w = full_w & !1;
        let h = full_h & !1;
        if w == 0 || h == 0 {
            // Counted as skipped by the caller; a degenerate frame is worth saying what it was.
            tracing::debug!(
                width = frame.width,
                height = frame.height,
                "frame too small to encode; skipped"
            );
            return Ok(None);
        }
        let _ = (w, h);
        let expected = full_w * full_h * 4;
        if frame.data.len() < expected {
            anyhow::bail!(
                "frame buffer too small: {} < {expected} ({full_w}x{full_h})",
                frame.data.len()
            );
        }

        // Fit within the max resolution (and OpenH264's 3840x2160 cap), preserving aspect ratio;
        // dimensions are made even for I420.
        //
        // On the WGC path this is a no-op: the capture thread already scaled, precisely so this
        // thread does not have to. It stays here because the `Encoder` trait promises to encode
        // whatever `Frame` it is handed, and a capturer that does not scale (a future DXGI
        // backend, a test) must not produce a frame OpenH264 rejects for being over its cap.
        let (bgra_data, dw, dh) = self.scaler.fit(
            &frame.data,
            frame.width,
            frame.height,
            self.max_w,
            self.max_h,
        )?;

        let bgra = BgraSliceU8::new(bgra_data, (dw as usize, dh as usize));
        let yuv = YUVBuffer::from_bgra8_source(bgra);

        if self.pending_keyframe {
            if self.started {
                self.enc.force_intra_frame();
            } else {
                // The first frame of an encoder is an IDR anyway.
                tracing::trace!("keyframe request before the first frame: nothing to force");
            }
            self.pending_keyframe = false;
        }

        // The `openh264` crate initialises lazily and re-initialises whenever the frame size
        // changes, and both paths push *its* `EncoderConfig` back into OpenH264: the bitrate this
        // encoder was constructed with, and `iMaxSpatialBitrate` pinned equal to it
        // (`encoder.rs:1010-1012`, `ENCODER_OPTION_SVC_ENCODE_PARAM_EXT`). So every ladder step
        // that changes resolution silently undoes both of the things `set_target` establishes.
        //
        // Noted before the encode and acted on after it, because `reinit` happens inside
        // `encode_at` and nothing can be set on an encoder that is not initialised yet.
        let dims = (dw, dh);
        if self.last_dims != Some(dims) {
            // The crate re-initialises OpenH264 at a new size: an IDR, and the rate settings put
            // back by `reassert` after it.
            tracing::debug!(
                from = ?self.last_dims,
                to = %format!("{dw}x{dh}"),
                bitrate_kbps = self.bitrate_bps / 1000,
                fps = self.fps,
                "openh264 (re)initialises at a new size"
            );
            self.last_dims = Some(dims);
            self.needs_reassert = true;
        }

        let bitstream = self
            .enc
            .encode_at(&yuv, Timestamp::from_millis(frame.timestamp_ms))
            .context("openh264 encode")?;
        self.started = true;

        let frame_type = bitstream.frame_type();
        if matches!(frame_type, FrameType::Invalid) {
            // Not a skip the encoder chose: it produced nothing usable. Counted as skipped by the
            // caller, so it is otherwise indistinguishable from rate control holding its target.
            tracing::debug!(
                size = %format!("{dw}x{dh}"),
                "openh264 returned an invalid frame type; nothing sent"
            );
        }
        let data = (!matches!(frame_type, FrameType::Skip | FrameType::Invalid))
            .then(|| bitstream.to_vec());

        if self.needs_reassert {
            self.needs_reassert = false;
            self.reassert();
        }

        let Some(data) = data else {
            return Ok(None);
        };
        if data.is_empty() {
            return Ok(None);
        }

        Ok(Some(EncodedFrame {
            data,
            is_keyframe: matches!(frame_type, FrameType::IDR | FrameType::I),
            timestamp_ms: frame.timestamp_ms,
        }))
    }

    fn request_keyframe(&mut self) {
        self.pending_keyframe = true;
    }

    fn last_frame_qp(&mut self) -> Option<u32> {
        self.read_frame_qp()
    }

    /// [`QP_MAX`], the ceiling this encoder is configured with rather than OpenH264's own 51.
    ///
    /// The ladder compares the observed quantiser against this to tell "comfortably on target"
    /// from "out of quality and still over budget". It must be the configured value: an encoder
    /// clamped to 46 has spent everything it has at 46, and comparing against 51 would mean the
    /// condition never held.
    fn max_qp(&self) -> Option<u32> {
        Some(u32::from(QP_MAX))
    }

    /// Retarget the encoder in place. No rebuild, no keyframe, no rate-control reset.
    ///
    /// The `openh264` crate does expose OpenH264's own API, so no fresh encoder (and no IDR of
    /// about 98 kB) is needed. `openh264-0.9.8/src/encoder.rs:1062`:
    ///
    /// ```text
    /// pub const unsafe fn raw_api(&mut self) -> &mut EncoderRawAPI
    /// ```
    ///
    /// `SetOption(ENCODER_OPTION_BITRATE)` mutates the encoder's parameters and returns; the rate
    /// controller picks the new number up on the next frame. It is exactly what libwebrtc's
    /// `H264EncoderImpl::SetRates` does, and it is what every adaptive sender relies on.
    ///
    /// So nothing here rations retargets: no large threshold, no cooldown, no "emergency" bypass.
    /// Rationing does real damage: with a 33% threshold, a ten-second cooldown and a bypass for
    /// drops steeper than half, a link that fell by 46% was neither urgent nor past the cooldown,
    /// so the encoder held a rate the link could not carry for ten seconds while the send queue
    /// absorbed the difference. Measured: 4139 kbps produced against a 2106 budget, then four
    /// seconds of over-rate while the estimate collapsed to 1033.
    ///
    /// The target follows in both directions as fast as it is given, because there is no cost
    /// left to amortise.
    fn set_target(&mut self, kbps: u32, fps: u32) {
        let requested = kbps.clamp(MIN_BITRATE_KBPS, MAX_BITRATE_KBPS);
        // A budget the encoder will not follow is exactly the "rung the controller believes it is
        // sending and the encoder is not" that the ceiling's comment warns about: logged when the
        // clamp starts binding and when it stops, never per frame.
        let clamped = requested != kbps;
        if clamped != self.clamped {
            self.clamped = clamped;
            tracing::debug!(
                asked_kbps = kbps,
                applied_kbps = requested,
                min_kbps = MIN_BITRATE_KBPS,
                max_kbps = MAX_BITRATE_KBPS,
                "{}",
                if clamped {
                    "encoder target clamped to its bounds"
                } else {
                    "encoder target back inside its bounds"
                }
            );
        }
        let fps = fps.clamp(1, 120);
        let current = self.bitrate_bps / 1000;

        // Small enough to be noise in the estimate, not small enough to be free to forward: every
        // call crosses into C. The threshold is a courtesy to the CPU, not a policy.
        let bitrate_moved = u64::from(requested.abs_diff(current)) * 100
            >= u64::from(current) * RETARGET_THRESHOLD_PCT;
        let fps_moved = (self.fps - fps as f32).abs() >= 0.5;
        if !bitrate_moved && !fps_moved {
            return;
        }
        // Trace: the budget moves on every 200 ms tick that changes it by 5%, and the pipeline line
        // carries it once a second; the frame rate is logged where it is decided, in the encode
        // loop.
        tracing::trace!(
            from_kbps = current,
            to_kbps = requested,
            from_fps = self.fps,
            to_fps = fps,
            "encoder retarget"
        );

        // Recorded first and pushed second, deliberately. What this encoder *intends* to send is
        // this object's own business; whether OpenH264 has been initialised far enough to be told
        // yet is not. A session can set a target before the first frame, when there is no
        // initialised encoder to tell; `reassert` then carries it across on the first encode.
        if bitrate_moved {
            self.bitrate_bps = requested * 1000;
        }
        if fps_moved {
            self.fps = fps as f32;
        }

        if bitrate_moved {
            if let Err(rc) = self.apply_bitrate(requested) {
                tracing::debug!(kbps = requested, rc, "bitrate deferred to the next frame");
                self.needs_reassert = true;
            }
        }
        if fps_moved {
            if let Err(rc) = self.apply_frame_rate(fps as f32) {
                tracing::debug!(fps, rc, "frame rate deferred to the next frame");
                self.needs_reassert = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OpenH264Encoder, UsageType, DEFAULT_GOP_FRAMES, GOP_SECONDS, MAX_BITRATE_KBPS,
        MIN_BITRATE_KBPS, QP_MIN, SLICE_BYTES,
    };
    use afklink_core::traits::Encoder;
    use afklink_core::types::Frame;

    /// The encoder's configured target, in kbps.
    fn target(e: &OpenH264Encoder) -> u32 {
        e.bitrate_bps / 1000
    }

    /// A frame with enough going on that the encoder has something to spend bits on.
    ///
    /// A flat field encodes to nothing and is declined as a skip, which would make the keyframe
    /// assertions below vacuous.
    fn frame(seed: u8) -> Frame {
        let (w, h) = (320usize, 240usize);
        let mut data = vec![0u8; w * h * 4];
        for (i, px) in data.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let x = (i % w) as u8;
            let y = (i / w) as u8;
            px[0] = x.wrapping_mul(3).wrapping_add(seed);
            px[1] = y.wrapping_mul(5).wrapping_add(seed);
            px[2] = x ^ y ^ seed;
            px[3] = 255;
        }
        Frame {
            data,
            width: w as u32,
            height: h as u32,
            timestamp_ms: u64::from(seed) * 33,
        }
    }

    #[test]
    fn retargeting_does_not_cost_a_keyframe() {
        // A rebuilt encoder has no history, so its next frame is an IDR: about 98 kB, roughly two
        // thirds of a second's budget at 1080p.
        //
        // `SetOption(ENCODER_OPTION_BITRATE)` changes the target and nothing else. If this test
        // fails, retargeting has started rebuilding the encoder.
        let mut e = OpenH264Encoder::new(1_000_000, 30.0, 60).expect("encoder");
        let first = e.encode(&frame(0)).expect("first").expect("output");
        assert!(first.is_keyframe, "a new stream opens with an IDR");

        e.set_target(400, 30);
        let after = e.encode(&frame(7)).expect("after").expect("output");
        assert!(
            !after.is_keyframe,
            "a bitrate change must not break the prediction chain"
        );
        assert_eq!(target(&e), 400, "and it must actually take effect");
    }

    #[test]
    fn noise_is_not_forwarded() {
        // Retargeting is free but not quite zero: each one crosses into C. A bandwidth estimate
        // wobbles by a few percent between every sample and none of it is visible.
        let mut e = OpenH264Encoder::new(1_000_000, 30.0, 60).expect("encoder");
        e.set_target(1_020, 30); // +2%
        assert_eq!(target(&e), 1_000);
        e.set_target(980, 30); // -2%
        assert_eq!(target(&e), 1_000);
    }

    #[test]
    fn the_target_follows_in_both_directions_with_no_waiting() {
        // A link that falls by 46% is followed at once. With a cooldown, or a bypass reserved for
        // drops of 50%, the encoder would hold a rate the link cannot carry while the send queue
        // swallowed the difference, and the picture would fall seconds behind the desktop.
        //
        // With no keyframe to amortise there is nothing left to ration, in either direction.
        let mut e = OpenH264Encoder::new(2_000_000, 30.0, 60).expect("encoder");
        e.set_target(1_080, 30); // -46%
        assert_eq!(target(&e), 1_080, "a falling link is followed at once");
        e.set_target(700, 30);
        assert_eq!(target(&e), 700, "and again, with no cooldown in between");
        e.set_target(2_400, 30);
        assert_eq!(target(&e), 2_400, "recovery is immediate too");
    }

    #[test]
    fn the_frame_rate_reaches_the_encoder() {
        // Rate control divides the bitrate by the frame rate to get a per-frame allowance, so an
        // encoder that believes in 60 while the ladder feeds it 15 hands every frame a quarter of
        // its due: a softer picture and more frames declined, for no reason anyone chose.
        let mut e = OpenH264Encoder::new(1_000_000, 30.0, 60).expect("encoder");
        assert!((e.fps - 30.0).abs() < f32::EPSILON);

        e.set_target(1_000, 15);
        assert!(
            (e.fps - 15.0).abs() < f32::EPSILON,
            "the frame rate must take effect on its own"
        );
        e.set_target(1_000, 60);
        assert!((e.fps - 60.0).abs() < f32::EPSILON);
    }

    #[test]
    fn keyframes_are_a_backstop_and_not_the_budget() {
        // A 1080p IDR measures 50 to 85 kB in camera mode, and it stays that size whatever the
        // budget: `RcCalculateIdrQp` clips its quantiser at 40. So the periodic keyframe is not a
        // bitrate cost that scales down on a thin link, it is a fixed lump of send queue: 567 ms
        // of it at 1.2 Mbps for the 85 kB end.
        //
        // Priced that way, the question is not "what fraction of the stream" but "how often does
        // the picture owe half a second of queue to a frame nobody asked for". Recovery is the
        // receiver's job in WebRTC (a browser sends a PLI and `request_keyframe` answers it), so
        // this period only has to cover a lost PLI, and libwebrtc's H.264 screen share ships the
        // same 3000 frames.
        let e = OpenH264Encoder::new(1_000_000, 30.0, DEFAULT_GOP_FRAMES).expect("encoder");
        let keyframe_kbits = 85.0 * 8.0;
        let overhead = keyframe_kbits / f64::from(GOP_SECONDS) / 1_200.0;
        assert!(
            overhead < 0.01,
            "keyframes are {:.1}% of a 1.2 Mbps stream",
            overhead * 100.0
        );
        // And the latency the same keyframe imposes: one 567 ms spike per GOP is tolerable at
        // this spacing and is not at ten seconds.
        let spike_ms = keyframe_kbits / 1_200.0 * 1_000.0;
        assert!(
            spike_ms / (f64::from(GOP_SECONDS) * 1_000.0) < 0.01,
            "the periodic IDR owns {:.1}% of the session's wall clock",
            spike_ms / (f64::from(GOP_SECONDS) * 1_000.0) * 100.0
        );
        assert_eq!(e.gop_frames, 3_000, "three thousand frames, as libwebrtc's");
        assert_eq!(e.gop_frames, 30 * GOP_SECONDS, "and the default agrees");
    }

    /// Something shaped like a remote desktop: flat ground, text-like rows, and a video pane.
    ///
    /// The shape matters. Pure noise is incompressible and gives a quantiser nothing to trade, and
    /// a purely flat desktop is so cheap that no budget ever binds. Either one measures something
    /// other than this product and hides the defect below.
    fn desktop(w: usize, h: usize, n: u32, buf: &mut Vec<u8>) {
        buf.resize(w * h * 4, 0);
        let scroll = (n as usize) * 3;
        for (i, px) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let (x, y) = (i % w, i / w);
            let mut v: u8 = if x < w / 6 { 0x2b } else { 0xf2 };
            if (40..64).contains(&y) && x >= w / 6 {
                v = 0xd8;
            }
            if y > 70 && x > w / 6 + 24 && (y + scroll) % 22 < 9 {
                let row = (y + scroll) / 22;
                if (row * 37 + x / 7) % 11 < 7 {
                    v = 0x33;
                }
            }
            let (vx0, vy0, vw, vh) = (w / 2, 100, w / 3, h / 3);
            if (vx0..vx0 + vw).contains(&x) && (vy0..vy0 + vh).contains(&y) {
                let u = x - vx0 + (n as usize) * 5;
                let t = y - vy0 + (n as usize) * 2;
                let wave = ((u * u / 64 + t * t / 48) % 256) as u8;
                let grain = (((u * 2_654_435_761) ^ (t * 40_503)) >> 7) as u8 & 0x1f;
                v = wave.wrapping_add(grain);
            }
            *px = [v, v, v, 255];
        }
    }

    /// A structured picture panning fast, which is what a game presents.
    ///
    /// **Not** per-pixel noise. Noise is incompressible by intra *and* inter prediction alike, so
    /// it produces enormous frames whichever path the encoder takes and measures nothing about
    /// the setting: it gives byte-identical output with scene-change detection on and off, which
    /// is true and useless.
    ///
    /// The whole frame moves every frame, so motion search has plenty to find and a scene-change
    /// detector has to decide whether the picture is new, which is exactly the decision that
    /// screen-content mode gets wrong on this content.
    fn churn(w: usize, h: usize, n: u32, out: &mut Vec<u8>) {
        out.resize(w * h * 4, 0);
        // A large, fast pan: sixteen pixels a frame in both axes.
        let (dx, dy) = (n as usize * 16, n as usize * 11);
        for (i, px) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let (x, y) = ((i % w) + dx, (i / w) + dy);
            // Structure at several scales, so there is something to predict and something to
            // lose: broad blocks, a grid, and a fine texture.
            let block = if (x / 64 + y / 64) % 2 == 0 {
                0x20u8
            } else {
                0xc0
            };
            let grid = if x % 32 < 3 || y % 32 < 3 { 0x40 } else { 0 };
            let grain = (((x * 2_654_435_761) ^ (y * 40_503)) >> 9) as u8 & 0x1f;
            let v = block.wrapping_add(grid).wrapping_add(grain);
            *px = [v, v, v, 255];
        }
    }

    /// What running an encoder across a generated sequence produced.
    struct Run {
        /// Bits per second, averaged from frame 8 onward so the opening IDR and the frames while
        /// rate control settles do not skew it.
        kbps: u32,
        /// Keyframes over every frame in the run, opening IDR included.
        keys: u32,
        /// The lowest and highest quantiser OpenH264 reported for any frame in the run.
        qp_lo: u32,
        qp_hi: u32,
    }

    /// Feed `frames` pictures from `gen` through `enc` at 640x480, retargeting to `kbps` before
    /// each one, and report what came out.
    fn run(
        enc: &mut OpenH264Encoder,
        gen: fn(usize, usize, u32, &mut Vec<u8>),
        kbps: u32,
        frames: u32,
    ) -> Run {
        let (w, h) = (640usize, 480usize);
        let mut buf = Vec::new();
        let (mut bytes, mut counted) = (0u64, 0u64);
        let mut keys = 0u32;
        let (mut qp_lo, mut qp_hi) = (u32::MAX, 0u32);
        for n in 0..frames {
            gen(w, h, n, &mut buf);
            let f = Frame {
                data: buf.clone(),
                width: w as u32,
                height: h as u32,
                timestamp_ms: u64::from(n) * 33,
            };
            enc.set_target(kbps, 30);
            let out = enc.encode(&f).expect("encode");
            if let Some(qp) = enc.last_frame_qp() {
                qp_lo = qp_lo.min(qp);
                qp_hi = qp_hi.max(qp);
            }
            if let Some(e) = &out {
                if e.is_keyframe {
                    keys += 1;
                }
            }
            // Skip the opening IDR and the settling frames after it.
            if n >= 8 {
                bytes += out.map_or(0, |e| e.data.len() as u64);
                counted += 1;
            }
        }
        Run {
            kbps: u32::try_from(bytes * 8 * 30 / counted / 1000).unwrap_or(u32::MAX),
            keys,
            qp_lo,
            qp_hi,
        }
    }

    #[test]
    fn the_quantiser_band_is_the_configured_one_and_both_ends_are_reachable() {
        // The defect this guards is invisible from the outside.
        //
        // `EncoderConfig::default()` sets `QpRange::new(0, 51)`, and OpenH264 reads `iMinQp <= 0`
        // as licence to substitute its own defaults. Under screen-content mode that is `[26, 35]`
        // (`encoder_ext.cpp:375-380`), nine steps of quantiser against the ~90 that `[12, 51]`
        // offers, about 2.8x of rate-control authority. As camera content, the substitution is
        // `[GOM_MIN_QP_MODE, MAX_LOW_BR_QP]` = `[12, 42]`: wider, but still not
        // `[QP_MIN, QP_MAX]` = `[16, 46]`, the band the ladder is tuned against, so leaving
        // `.qp(...)` unset would still be wrong.
        //
        // Both ends have to be independently reachable, or a substitution is back without anyone
        // asking for it: `qp_hi` beyond 42 on a starved budget proves the configured ceiling is in
        // force rather than camera mode's own 42; `qp_lo` at exactly the configured floor on a
        // generous one proves the same for the low end against the substitution's 12.
        let mut starved =
            OpenH264Encoder::new_tuned(MIN_BITRATE_KBPS * 1000, 30.0, 300, 2, Some(SLICE_BYTES))
                .expect("encoder");
        let starved_run = run(&mut starved, churn, MIN_BITRATE_KBPS, 40);
        assert!(
            starved_run.qp_hi > 42,
            "the configured ceiling must be reachable, not camera mode's substituted 42: \
             observed qp_hi={}",
            starved_run.qp_hi
        );

        let mut lavish =
            OpenH264Encoder::new_tuned(4_000_000, 30.0, 300, 2, Some(SLICE_BYTES)).expect("enc");
        let lavish_run = run(&mut lavish, desktop, 4_000, 40);
        assert_eq!(
            lavish_run.qp_lo,
            u32::from(QP_MIN),
            "the configured floor must be reachable, not camera mode's substituted 12"
        );
    }

    /// Content that moves the way a game moves must not be coded as a keyframe every frame.
    ///
    /// Measured in a real session: a game at 720p with a 1186 kbps budget produced 15303 kbps
    /// over 30 frames (64 kB a frame, against an `idr_bytes` of 65849), so the average frame cost
    /// what a keyframe costs, with `plis=0` proving the viewer had not asked for any of them.
    /// Thirteen times the budget, and no bitrate the ladder can set makes a difference to an
    /// encoder that codes every frame as intra.
    ///
    /// The mechanism, from reading OpenH264's source rather than guessing at it: screen-content
    /// mode forces scene-change detection on regardless of what this crate asks for
    /// (`encoder_ext.cpp:292-295`); the detector reports a scene change on full-screen motion
    /// because block matching fails against every available reference
    /// (`wels_preprocess.cpp:1096-1260`); a reported scene change is coded as an IDR
    /// (`encoder.cpp:341-350`); and that IDR's quantiser is clipped to a ceiling of 40 and budgeted
    /// at four times an ordinary frame regardless of `QP_MAX` (`ratectl.cpp:403-474`). This is
    /// why the encoder runs as `CameraVideoRealTime` with `scene_change_detect(false)` instead of
    /// `ScreenContentRealTime`; the control below builds screen-content mode to show the defect
    /// is still there when asked for.
    #[test]
    fn continuous_motion_is_not_coded_as_a_keyframe_every_frame() {
        let mut ours =
            OpenH264Encoder::new_tuned(1_000_000, 30.0, 300, 2, Some(SLICE_BYTES)).expect("enc");
        let ours_run = run(&mut ours, churn, 1_000, 26);
        assert_eq!(ours_run.keys, 1, "only the opening IDR should appear");
        assert!(
            ours_run.kbps < 1_000 * 3 / 2,
            "asked for 1000 kbps on continuous motion and produced {}",
            ours_run.kbps
        );

        // The control: this file's own configuration, with only the usage type put back to
        // screen content, so the comparison isolates that one field.
        let mut screen = OpenH264Encoder::from_config(
            OpenH264Encoder::config(1_000_000, 30.0, 300, 2, Some(SLICE_BYTES))
                .usage_type(UsageType::ScreenContentRealTime),
            1_000_000,
            30.0,
            300,
            2,
        )
        .expect("enc");
        let screen_run = run(&mut screen, churn, 1_000, 26);
        assert!(
            screen_run.keys > 26 / 2,
            "screen-content mode codes continuous motion as an IDR nearly every frame, which is \
             why this encoder does not use it: keys={}/26",
            screen_run.keys
        );
    }

    #[test]
    fn an_ultrawide_rung_reaches_the_encoder_at_the_size_the_ladder_priced() {
        // The ladder bounds height and lets width follow from the source's aspect ratio, so a
        // 5120x1440 panel at the 720p rung is captured at 2560x720. A 1920 width cap in the
        // encoder on top of that would, because `fit_within` preserves aspect ratio, drag the
        // height down with it, to **1920x540**.
        //
        // One rung below what the controller priced, paced and measures, invisibly: every number
        // in the system would say 720p and the viewer would receive 540p.
        let mut e = OpenH264Encoder::new(1_000_000, 30.0, 300).expect("encoder");
        let (w, h) = (2560u32, 720u32);
        let frame = Frame {
            data: vec![0u8; w as usize * h as usize * 4],
            width: w,
            height: h,
            timestamp_ms: 0,
        };
        e.encode(&frame).expect("encode");
        assert_eq!(
            e.last_dims,
            Some((w, h)),
            "an ultrawide rung must not be silently re-scaled below itself"
        );
    }

    #[test]
    fn clamps_to_something_usable() {
        // A ladder rung priced near zero would otherwise configure OpenH264 with a few kbps,
        // which does not degrade gracefully: it produces a picture that looks broken rather
        // than small.
        let mut e = OpenH264Encoder::new(1_000_000, 30.0, 60).expect("encoder");
        e.set_target(1, 30);
        assert_eq!(target(&e), MIN_BITRATE_KBPS);

        e.set_target(u32::MAX, 30);
        assert_eq!(target(&e), MAX_BITRATE_KBPS);
    }

    #[test]
    fn a_retargeted_encoder_still_encodes() {
        // Retargeting reaches into OpenH264 through the raw API. If that left the encoder in a bad
        // state the symptom would be a session that dies on the next frame.
        let mut e = OpenH264Encoder::new(1_000_000, 30.0, 60).expect("encoder");
        e.encode(&frame(0)).expect("before");
        for (kbps, fps) in [(400u32, 15u32), (2_000, 60), (900, 30)] {
            e.set_target(kbps, fps);
            let out = e.encode(&frame(kbps as u8)).expect("after retarget");
            assert!(out.is_some(), "must still produce output at {kbps}/{fps}");
        }
    }
}
