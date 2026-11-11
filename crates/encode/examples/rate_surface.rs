//! Measures the encoder's rate surface under controlled conditions.
//!
//! `cargo run -p afklink-encode --example rate_surface --release > surface.csv`
//!
//! The encoder below is configured with `UsageType::CameraVideoRealTime`, matching production.
//! A surface measured in screen-content mode does not describe production.
//!
//! ## Why this exists
//!
//! The quality ladder needs to answer "what would a frame cost at a different resolution, frame
//! rate or quantiser". Fitting those exponents from recorded sessions fails outright:
//! `R^2 = 0.17`, not one coefficient significant, and `corr(log(pixels), qp) = +0.78`, because
//! the *controller* chose the operating
//! points, so resolution and quantiser moved together and cannot be separated. Observational data
//! produced by the thing being modelled cannot identify the model.
//!
//! So vary them independently, on fixed content, with rate control taken out of the loop.
//!
//! ## How the quantiser is held
//!
//! `QpRange::new(q, q)` pins `iMinQp == iMaxQp`, so OpenH264 has no freedom left and every frame is
//! coded at exactly `q`. The bitrate target is then irrelevant to the outcome, which is the point:
//! what comes out is the content's cost at that quantiser and nothing else.
//!
//! Note the trap: a zero in *either* bound makes OpenH264 silently substitute a default range
//! (`[26, 35]` for screen content, `encoder_ext.cpp:375-380`, or `[12, 42]` for camera content,
//! `GOM_MIN_QP_MODE`, `MAX_LOW_BR_QP`, `encoder_ext.cpp:381-386`), so `q` must never be 0
//! regardless of usage type.
//!
//! ## How the interval is varied
//!
//! Not by waiting but by advancing the content. A frame that follows a 250 ms gap has to describe
//! 250 ms of motion, and that, not wall-clock time, is what costs bits. Each step of `advance`
//! moves the scene by one 33 ms tick's worth, so `advance = 8` is what a frame arriving 264 ms
//! after its predecessor must carry.

use openh264::encoder::{
    BitRate, Encoder as Oh264Encoder, EncoderConfig, FrameRate, IntraFramePeriod, Profile, QpRange,
    RateControlMode, UsageType,
};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::{OpenH264API, Timestamp};

/// The ladder's encoded sizes for a 3:2 source, as `Rung::size_for` computes them.
const SIZES: &[(u32, u32)] = &[
    (1620, 1080),
    (1350, 900),
    (1080, 720),
    (810, 540),
    (540, 360),
];

/// Quantisers to sample, inside the range the encoder is configured to allow.
const QPS: &[u8] = &[18, 22, 26, 30, 34, 38, 42, 46];

/// Content advance between encoded frames, in 33 ms ticks. 1 is 30 fps; 12 is 2.5 fps.
const ADVANCES: &[u32] = &[1, 2, 4, 8, 12];

/// Frames encoded per cell, and how many of them to discard while the encoder settles.
const FRAMES: u32 = 14;
const WARMUP: u32 = 4;

/// Two workloads, because a desktop and a video window have different costs and the ladder has to
/// serve both. `motion` scales how much of the frame is the moving pane.
fn render(w: usize, h: usize, tick: u32, video_share: f64, buf: &mut Vec<u8>) {
    buf.resize(w * h * 4, 0);
    let scroll = (tick as usize) * 3;
    let vw = (w as f64 * video_share) as usize;
    let vh = (h as f64 * video_share) as usize;
    let (vx0, vy0) = (w / 2 - vw / 2, h / 2 - vh / 2);
    for (i, px) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = (i % w, i / w);
        // Desktop: flat ground, a sidebar, a title bar, and text-like rows that scroll.
        let mut v: u8 = if x < w / 6 { 0x2b } else { 0xf2 };
        if (h / 18..h / 11).contains(&y) && x >= w / 6 {
            v = 0xd8;
        }
        if y > h / 10 && x > w / 6 + 24 && (y + scroll) % 22 < 9 {
            let row = (y + scroll) / 22;
            if (row * 37 + x / 7) % 11 < 7 {
                v = 0x33;
            }
        }
        // A video pane: continuous tone with real motion. Expensive but compressible, unlike
        // noise, which is incompressible and measures H.264's worst case rather than this product.
        if vw > 0 && (vx0..vx0 + vw).contains(&x) && (vy0..vy0 + vh).contains(&y) {
            let u = x - vx0 + (tick as usize) * 5;
            let t = y - vy0 + (tick as usize) * 2;
            let wave = ((u * u / 64 + t * t / 48) % 256) as u8;
            let grain = (((u * 2_654_435_761) ^ (t * 40_503)) >> 7) as u8 & 0x1f;
            v = wave.wrapping_add(grain);
        }
        *px = [v, v, v, 255];
    }
}

fn cell(w: u32, h: u32, qp: u8, advance: u32, video_share: f64) -> (f64, f64) {
    let config = EncoderConfig::new()
        .profile(Profile::Baseline)
        // A target far above anything the content can produce, so rate control never binds and the
        // pinned quantiser is the only thing deciding. `RateControlMode::Off` looked like the
        // cleaner choice and was not: under it OpenH264 ignores `iMinQp`/`iMaxQp` entirely, and the
        // first run of this sweep produced byte-for-byte identical output at QP 18 and QP 46 — a
        // broken axis that would have become the next false premise if the fit had not shown a
        // coefficient of exactly zero.
        .bitrate(BitRate::from_bps(50_000_000))
        .max_frame_rate(FrameRate::from_hz(30.0))
        .rate_control_mode(RateControlMode::Bitrate)
        .usage_type(UsageType::CameraVideoRealTime)
        .scene_change_detect(false)
        .intra_frame_period(IntraFramePeriod::from_num_frames(100_000))
        .num_threads(4)
        .skip_frames(false)
        .qp(QpRange::new(qp, qp))
        .adaptive_quantization(false)
        .background_detection(false)
        .max_slice_len(4096)
        .debug(false);
    let mut enc =
        Oh264Encoder::with_api_config(OpenH264API::from_source(), config).expect("encoder");

    let mut buf = Vec::new();
    let mut bytes = 0u64;
    let mut micros = 0u128;
    let mut counted = 0u64;
    for n in 0..FRAMES {
        let tick = n * advance;
        render(w as usize, h as usize, tick, video_share, &mut buf);
        let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&buf, (w as usize, h as usize)));
        let started = std::time::Instant::now();
        let bs = enc
            .encode_at(&yuv, Timestamp::from_millis(u64::from(tick) * 33))
            .expect("encode");
        let spent = started.elapsed();
        let len = bs.to_vec().len() as u64;
        if n >= WARMUP {
            bytes += len;
            micros += spent.as_micros();
            counted += 1;
        }
    }
    (
        bytes as f64 / counted as f64,
        micros as f64 / counted as f64 / 1000.0,
    )
}

fn main() {
    println!("content,w,h,pixels,qp,advance,interval_ms,bytes_per_frame,encode_ms");
    for (label, share) in [("desktop", 0.0), ("mixed", 0.33), ("video", 1.0)] {
        for &(w, h) in SIZES {
            for &qp in QPS {
                for &advance in ADVANCES {
                    let (bpf, ms) = cell(w, h, qp, advance, share);
                    println!(
                        "{label},{w},{h},{},{qp},{advance},{},{bpf:.1},{ms:.3}",
                        w * h,
                        advance * 33
                    );
                }
            }
        }
    }
}
