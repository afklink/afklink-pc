//! What the encoder should be told the frame rate is, and the proof that the fast half matters.
//!
//! Run: `cargo run --release -p afklink-encode --example fps_tracking`.
//!
//! ## The question
//!
//! OpenH264's rate control divides the bitrate by the frame rate to get a per-frame allowance. WGC
//! delivers a frame only when the screen changes, so the rate the encoder is *fed* at is routinely
//! a fraction of the rung's nominal 30, and an encoder told 30 while fed 12 spends 12/30 of the
//! budget and produces a softer picture than the link paid for.
//!
//! Telling it the measured rate instead fixes that and creates a worse hazard: a rate measured
//! while the screen was still is a tiny denominator, and when motion resumes every frame of the
//! first second is handed `kbps / 2` bits. That is a fifteen-fold overshoot into the send queue,
//! which is strictly worse than the underspend it cures.
//!
//! So the tracked rate this bench validates is asymmetric: it rises on the very next frame from
//! the instantaneous inter-arrival rate, and falls only on a completed one-second window, clamped
//! throughout into `[1, rung fps]`. `afklink_core::agent::encode_loop` implements exactly this;
//! [`Tracker`] below is the same arithmetic on a virtual clock so the two cases can be replayed in
//! a second instead of in real time.
//!
//! ## What is measured
//!
//! Both cases run 1080p content through the *production* [`OpenH264Encoder`] at a 4000 kbps budget.
//!
//!   (a) steady 12 fps for 5 s: how much of the budget is actually spent.
//!   (b) 1 s of a still screen at 2 fps, then 2 s of motion at 30 fps: the worst 500 ms window,
//!       against half a second of budget.
//!
//! Four policies. `rung fps` (labelled "shipped") always tells it 30. `tracked` is the policy the
//! agent uses. `ideal (no floor)` is `tracked` without the half-rung floor: not shippable, but it
//! is the ceiling on what any frame-rate policy could recover, which is what makes the `tracked`
//! number readable. `window only` is the naive repair with no fast attack, present because the hazard it
//! walks into is the reason the attack exists.
//!
//! ## Measured on this machine (1920x1080, 4 threads, budget 4000 kbps)
//!
//! ```text
//! (a) steady 12 fps for 5 s          whole run   after 1st window
//!     churn   rung fps (shipped)         47%          23%
//!     churn   tracked                    53%          30%
//!     churn   ideal (no floor)           54%          31%
//!     churn   timestamp mode             67%          51%
//!     desktop rung fps (shipped)         40%          33%
//!     desktop tracked                    66%          66%
//!     desktop ideal (no floor)           75%          77%
//!     desktop timestamp mode             68%          63%
//!
//! (b) 1 s still @2 fps, then 30 fps of churn    worst 500 ms window
//!     rung fps (shipped)                       1.52x
//!     tracked                                  1.28x
//!     ideal (no floor)                         2.57x
//!     window only                              4.58x
//!     timestamp mode                           1.69x
//! ```
//!
//! Three readings, in the order they decide things.
//!
//! **The underspend is real and this recovers most of it.** On desktop content the fixed rate
//! spends a third of the budget it was given; `tracked` spends two thirds, and the unfloored ideal
//! (the most any policy could get) is 77%. The remaining quarter is not the frame rate: the
//! quantiser is still 38 to 39 at 12 fps, so the encoder is not short of anything it can use, and
//! the content between frames 83 ms apart is simply expensive. On `churn` the gain is small for a
//! different reason: at 4 Mbps a panning 1080p scene already sits near the QP 46 ceiling, and an
//! encoder with no quality left spends the same bits whatever rate it believes in.
//!
//! **The attack is the whole of case (b).** Without it the tracked rate is still 2 fps when motion
//! resumes and every frame of the next second is handed 2 Mbit: 4.58x. With it, only the one frame
//! that resumes motion is mispriced, and the floor bounds even that to 1.28x, better than the
//! fixed rate manages.
//!
//! **The floor costs 11 points of (a) and buys half of (b).** 66% against 77%, for 1.28x against
//! 2.57x. When both targets cannot be met, the side that does not overshoot wins, and this is that
//! side.
//!
//! ## RC_TIMESTAMP_MODE, measured and not adopted
//!
//! OpenH264 will do this itself: `RC_TIMESTAMP_MODE` budgets from the timestamps handed to
//! `encode_at`, which this pipeline already passes, so switching is one line. It is better than
//! `tracked` on (a), decisively so on `churn` (51% against 30%), and worse on (b), 1.69x against
//! 1.28x. It is not at least as good on both: it has no clamp
//! to the rung, so nothing bounds the allowance it derives from a long timestamp gap, which is
//! exactly the transition this whole mechanism exists to survive. `RC_BITRATE_MODE` with an
//! explicit, clamped frame rate stays. Worth revisiting if the send queue ever stops being the
//! binding constraint.

use openh264::encoder::{
    BitRate, Encoder as RawEncoder, EncoderConfig, FrameRate, IntraFramePeriod, Profile, QpRange,
    RateControlMode, UsageType,
};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::{OpenH264API, Timestamp};

use afklink_core::traits::Encoder;
use afklink_core::types::Frame;
use afklink_encode::{OpenH264Encoder, DEFAULT_GOP_FRAMES};

const W: usize = 1920;
const H: usize = 1080;
/// The budget both cases run at.
///
/// Four megabits, which is `usage_mode`'s 1080p figure, and it has to be roughly that generous or
/// the bench measures nothing. At 1000 kbps a 1080p frame of either content pins the quantiser at
/// its 46 ceiling, and an encoder with no quality left to give spends the same bits whatever it
/// believes the frame rate is — the underspend this bench exists to measure only exists while rate
/// control still has room to move. That is itself worth knowing: on a link too thin for the rung,
/// the frame rate handed over changes nothing, and the ladder's `coarse` arm is the thing that
/// matters instead.
const BUDGET_KBPS: u32 = 4_000;
/// The rung's nominal cadence — the clamp, and what shipped as the only answer.
const RUNG_FPS: u32 = 30;

/// A content generator: fills `buf` with a `w`x`h` BGRA frame for tick `n`.
type Gen = fn(usize, usize, u32, &mut Vec<u8>);

/// A structured picture panning fast, which is what a game presents — and the only content here on
/// which the budget actually binds. See the note on `desktop`.
fn churn(w: usize, h: usize, n: u32, out: &mut Vec<u8>) {
    out.resize(w * h * 4, 0);
    let (dx, dy) = (n as usize * 16, n as usize * 11);
    for (i, px) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = ((i % w) + dx, (i / w) + dy);
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

/// Something shaped like a remote desktop: flat ground, text-like rows, and a video pane.
///
/// The same generator `examples/usage_mode.rs` uses. Copied rather than shared because an example
/// cannot import another example, and a shape that differs between the two benches would make the
/// numbers in their headers incomparable.
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

/// Which frame rate the encoder is told about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// What shipped: the rung's nominal rate, whatever is actually arriving.
    Rung,
    /// Fast to rise, slow to fall, floored at half the rung. The one adopted.
    Tracked,
    /// Fast to rise, slow to fall, *no* floor — the exact rate the encoder is being fed. Not
    /// shippable (it is `window only`'s hazard with one frame's warning instead of a second's), but
    /// it is the ceiling on what any frame-rate policy can recover, which is what makes the
    /// `tracked` number readable.
    Ideal,
    /// The naive repair: the one-second window in both directions, no attack.
    WindowOnly,
}

/// The production frame-rate tracker, on a virtual clock.
///
/// Mirrors `afklink_core::agent::encode_loop` line for line: the sliding one-second window may only
/// lower the belief, the instantaneous inter-arrival rate may raise it immediately, the result is
/// clamped into `[1, rung fps]`, and the rung's own rate stands in until the first window closes.
struct Tracker {
    policy: Policy,
    arrival_fps: f32,
    known: bool,
    committed: u32,
    window_start_ms: u64,
    window_count: u32,
    last_ms: Option<u64>,
}

/// The same 15% deadband the agent applies, so the `SetOption` call count matches too.
const FPS_DEADBAND_PCT: u64 = 15;

impl Tracker {
    fn new(policy: Policy) -> Self {
        Self {
            policy,
            arrival_fps: 0.0,
            known: false,
            committed: 0,
            window_start_ms: 0,
            window_count: 0,
            last_ms: None,
        }
    }

    /// One arrival at `now_ms`. Returns the frame rate to hand the encoder.
    fn on_frame(&mut self, now_ms: u64) -> u32 {
        if self.policy == Policy::Rung {
            return RUNG_FPS;
        }
        let gap = self.last_ms.map(|prev| now_ms.saturating_sub(prev));
        self.last_ms = Some(now_ms);

        self.window_count += 1;
        let elapsed = now_ms.saturating_sub(self.window_start_ms);
        if elapsed >= 1_000 {
            let windowed = self.window_count as f32 / (elapsed as f32 / 1_000.0);
            self.arrival_fps = if self.known {
                self.arrival_fps.min(windowed)
            } else {
                windowed
            };
            self.known = true;
            self.window_start_ms = now_ms;
            self.window_count = 0;
        }

        let want = if self.known {
            if matches!(self.policy, Policy::Tracked | Policy::Ideal) {
                if let Some(gap) = gap {
                    let secs = (gap as f32 / 1_000.0).max(0.001);
                    self.arrival_fps = self.arrival_fps.max(1.0 / secs);
                }
            }
            // The floor is half the rung, not 1. A frame arriving after a long quiet gap is
            // encoded against whatever the tracker believed *before* it arrived, and the gap that
            // preceded it says nothing about the rate that follows — so the one frame that resumes
            // motion is always priced on a stale, low number. Bounding the belief at half the rung
            // bounds that one frame's allowance at twice nominal, which is the whole of the
            // transition cost. `window only` in case (b) is what this costs without the floor.
            let floor = if self.policy == Policy::Tracked {
                (RUNG_FPS / 2).max(1)
            } else {
                1
            };
            (self.arrival_fps.round() as u32).clamp(floor, RUNG_FPS)
        } else {
            RUNG_FPS
        };

        if self.committed == 0
            || u64::from(want.abs_diff(self.committed)) * 100
                >= u64::from(self.committed) * FPS_DEADBAND_PCT
        {
            self.committed = want;
        }
        self.committed
    }
}

/// One frame's worth of virtual time: when it arrives, and which tick of content it shows.
struct Arrival {
    at_ms: u64,
    tick: u32,
}

/// One phase of a case: a delivery rate, a frame count, and whether the screen is moving.
///
/// `still` is not cosmetic. A still screen is *why* WGC delivers two frames in a second, so a
/// "still" phase that kept advancing the content would be measuring a moving screen that the
/// capturer happened to sample slowly — a different and much rarer thing.
#[derive(Clone, Copy)]
struct Phase {
    fps: u32,
    frames: u32,
    still: bool,
}

/// Build the arrival schedule for a case: a list of (time, content tick) pairs.
fn schedule(phases: &[Phase]) -> Vec<Arrival> {
    let mut out = Vec::new();
    let mut t = 0u64;
    let mut frozen = 0u32;
    for p in phases {
        let interval = 1_000 / u64::from(p.fps);
        for _ in 0..p.frames {
            // Content advances on the wall clock rather than on the frame count: a moving screen
            // sampled at 12 fps has moved 2.5 ticks' worth between frames, which is what makes each
            // frame more expensive than the same content at 30.
            let tick = if p.still { frozen } else { (t / 33) as u32 };
            out.push(Arrival { at_ms: t, tick });
            t += interval;
            if !p.still {
                frozen = (t / 33) as u32;
            }
        }
    }
    out
}

/// One run's per-frame `(arrival time, bits)`, and the mean quantiser over it.
///
/// The quantiser is on the line because it is what separates "the encoder had room and was not
/// given it" from "the encoder had nothing left to give" — and the second of those is why the
/// `churn` rows barely move.
struct Run {
    samples: Vec<(u64, u64)>,
    qp: f64,
}

/// Run a schedule through the production encoder.
fn run(policy: Policy, gen: Gen, phases: &[Phase], warmup: u32) -> Run {
    let mut enc = OpenH264Encoder::new(BUDGET_KBPS * 1_000, RUNG_FPS as f32, DEFAULT_GOP_FRAMES)
        .expect("encoder");
    let mut tracker = Tracker::new(policy);
    let mut buf = Vec::new();

    // Start the stream before the measurement, so the opening IDR — which is 50 to 85 kB whatever
    // the budget, because OpenH264 clips its quantiser at 40 — does not land inside a measured
    // window and swamp everything else in it.
    for n in 0..warmup {
        gen(W, H, n, &mut buf);
        let _ = enc.encode(&Frame {
            data: buf.clone(),
            width: W as u32,
            height: H as u32,
            timestamp_ms: u64::from(n) * 33,
        });
    }

    let base = u64::from(warmup) * 33;
    let mut out = Vec::new();
    let (mut qp_sum, mut qp_n) = (0u64, 0u64);
    for a in schedule(phases) {
        let fps = tracker.on_frame(a.at_ms);
        enc.set_target(BUDGET_KBPS, fps);
        gen(W, H, a.tick + warmup, &mut buf);
        let frame = Frame {
            data: buf.clone(),
            width: W as u32,
            height: H as u32,
            timestamp_ms: base + a.at_ms,
        };
        let bits = match enc.encode(&frame) {
            Ok(Some(ef)) => ef.data.len() as u64 * 8,
            _ => 0,
        };
        if let Some(q) = enc.last_frame_qp() {
            qp_sum += u64::from(q);
            qp_n += 1;
        }
        out.push((a.at_ms, bits));
    }
    Run {
        samples: out,
        qp: if qp_n > 0 {
            qp_sum as f64 / qp_n as f64
        } else {
            f64::NAN
        },
    }
}

/// Share of the budget actually spent over a span of virtual time.
fn spend(samples: &[(u64, u64)], from_ms: u64, to_ms: u64) -> f64 {
    let bits: u64 = samples
        .iter()
        .filter(|(t, _)| *t >= from_ms && *t < to_ms)
        .map(|(_, b)| *b)
        .sum();
    let secs = (to_ms - from_ms) as f64 / 1_000.0;
    bits as f64 / secs / f64::from(BUDGET_KBPS) / 1_000.0
}

/// The worst 500 ms of production in the run, as a multiple of half a second of budget.
///
/// A window rather than a mean because the thing being guarded is the send queue, and a queue is
/// filled by a burst regardless of what the average around it says.
fn worst_window(samples: &[(u64, u64)], span_ms: u64) -> f64 {
    let allowed = f64::from(BUDGET_KBPS) * 1_000.0 * span_ms as f64 / 1_000.0;
    let mut worst: f64 = 0.0;
    for &(start, _) in samples {
        let bits: u64 = samples
            .iter()
            .filter(|(t, _)| *t >= start && *t < start + span_ms)
            .map(|(_, b)| *b)
            .sum();
        worst = worst.max(bits as f64 / allowed);
    }
    worst
}

/// The same two cases under `RC_TIMESTAMP_MODE`, which budgets from the timestamps rather than from
/// a frame rate anybody has to supply.
///
/// A separate encoder rather than a flag on the production one: adopting the mode is the decision
/// this arm exists to inform, and it should not be half-adopted to measure it. The configuration is
/// otherwise the production one (`afklink-encode/src/lib.rs`, `OpenH264Encoder::config`).
fn run_timestamp_mode(gen: Gen, phases: &[Phase], warmup: u32) -> Vec<(u64, u64)> {
    let config = EncoderConfig::new()
        .profile(Profile::Baseline)
        .bitrate(BitRate::from_bps(BUDGET_KBPS * 1_000))
        .max_frame_rate(FrameRate::from_hz(RUNG_FPS as f32))
        .rate_control_mode(RateControlMode::Timestamp)
        .usage_type(UsageType::CameraVideoRealTime)
        .intra_frame_period(IntraFramePeriod::from_num_frames(DEFAULT_GOP_FRAMES))
        .num_threads(4)
        .skip_frames(false)
        .qp(QpRange::new(16, 46))
        .scene_change_detect(false)
        .adaptive_quantization(false)
        .background_detection(false)
        .debug(false)
        .max_slice_len(4096);
    let mut enc = RawEncoder::with_api_config(OpenH264API::from_source(), config).expect("encoder");
    let mut buf = Vec::new();
    for n in 0..warmup {
        gen(W, H, n, &mut buf);
        let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&buf, (W, H)));
        let _ = enc.encode_at(&yuv, Timestamp::from_millis(u64::from(n) * 33));
    }
    let base = u64::from(warmup) * 33;
    let mut out = Vec::new();
    for a in schedule(phases) {
        gen(W, H, a.tick + warmup, &mut buf);
        let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&buf, (W, H)));
        let bits = enc
            .encode_at(&yuv, Timestamp::from_millis(base + a.at_ms))
            .map(|bs| bs.to_vec().len() as u64 * 8)
            .unwrap_or(0);
        out.push((a.at_ms, bits));
    }
    out
}

fn main() {
    // (a) A partly-moving screen: WGC hands over 12 frames a second at a rung that says 30.
    let steady = [Phase {
        fps: 12,
        frames: 60,
        still: false,
    }];
    // (b) A still screen barely producing frames, then motion at the rung's full rate.
    let resume = [
        Phase {
            fps: 2,
            frames: 2,
            still: true,
        },
        Phase {
            fps: 30,
            frames: 60,
            still: false,
        },
    ];

    println!("1080p, {BUDGET_KBPS} kbps budget, rung {RUNG_FPS} fps\n");
    println!("(a) steady 12 fps for 5 s          whole run   after 1st window");
    for (content, gen) in [("churn  ", churn as Gen), ("desktop", desktop)] {
        for (label, policy) in [
            ("rung fps (shipped)", Policy::Rung),
            ("tracked           ", Policy::Tracked),
            ("ideal (no floor)  ", Policy::Ideal),
            ("window only       ", Policy::WindowOnly),
        ] {
            let r = run(policy, gen, &steady, 30);
            println!(
                "    {content} {label}   {:>5.0}%       {:>5.0}%     qp {:.1}",
                spend(&r.samples, 0, 5_000) * 100.0,
                spend(&r.samples, 1_000, 5_000) * 100.0,
                r.qp
            );
        }
        let ts = run_timestamp_mode(gen, &steady, 30);
        println!(
            "    {content} timestamp mode       {:>5.0}%       {:>5.0}%",
            spend(&ts, 0, 5_000) * 100.0,
            spend(&ts, 1_000, 5_000) * 100.0
        );
    }

    println!("\n(b) 1 s still @2 fps, then 30 fps of churn    worst 500 ms window");
    for (label, policy) in [
        ("rung fps (shipped)", Policy::Rung),
        ("tracked           ", Policy::Tracked),
        ("ideal (no floor)  ", Policy::Ideal),
        ("window only       ", Policy::WindowOnly),
    ] {
        let r = run(policy, churn, &resume, 30);
        println!(
            "    {label}                       {:>5.2}x     qp {:.1}",
            worst_window(&r.samples, 500),
            r.qp
        );
    }
    let ts = run_timestamp_mode(churn, &resume, 30);
    println!(
        "    timestamp mode                           {:>5.2}x",
        worst_window(&ts, 500)
    );
}
