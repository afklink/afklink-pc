//! What the encode thread costs per frame, and what frame rate that permits.
//!
//! Build profile dominates: a *debug* build measures 1.8 fps against 28 in release. The scaling
//! loop it spends its time in is a bounds-checked scan over 8.6M pixels, the shape debug punishes
//! hardest.
//!
//! ## What this measures
//!
//! Capture and encode run on separate threads, so the pipeline's frame rate is the *slower* of
//! the two stages, not their sum. This bench owns the encode thread's half:
//!
//!   BGRA -> I420   a full pass over the frame, scalar in the `openh264` crate
//!   H.264          OpenH264, camera real-time, scene-change detection off
//!
//! The capture half (the GPU->CPU copy and the scale) is `afklink-capture`,
//! `examples/capture_bench.rs`, and has to be read alongside this one. Scaling runs *there*
//! because with it here the two stages are unbalanced: 15 ms on this thread against 8 on that
//! one, so the encode thread sets the rate while a third of the machine's capacity sits idle.
//!
//! Run with:  cargo run --release --example pipeline_bench -p afklink-encode
//!
//! Release is not optional. See above.

use std::time::Instant;

use afklink_core::traits::Encoder;
use afklink_core::types::Frame;
use afklink_encode::{OpenH264Encoder, DEFAULT_BITRATE_BPS, DEFAULT_FPS, DEFAULT_GOP_FRAMES};
use openh264::formats::{BgraSliceU8, YUVBuffer};

const FRAMES: usize = 30;

/// The resolutions worth knowing the cost of.
///
/// 1620x1080 is not a typo: it is what a 3600x2400 panel (a 3:2 display at 200% scaling) becomes
/// when fitted into the 1920x1080 cap — height-limited, so narrower than 1920.
const SIZES: &[(u32, u32, &str)] = &[
    (1280, 720, "720p"),
    (1620, 1080, "1080p (3:2 source)"),
    (1920, 1080, "1080p (16:9 source)"),
];

fn main() -> anyhow::Result<()> {
    println!(
        "cpu: {} logical cores\n",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );

    println!("encode thread, per frame:");
    println!("  resolution             convert   encode     total    ceiling   bits/frame");
    for &(w, h, label) in SIZES {
        let convert_ms = bench_convert(w, h);
        let total = bench_encode(w, h, None, None)?;
        println!(
            "  {label:<21} {convert_ms:6.2}   {:6.2}   {:6.2} ms  {:5.1} fps   {:5.1} kB",
            total.ms_per_frame - convert_ms,
            total.ms_per_frame,
            1000.0 / total.ms_per_frame,
            total.kb_per_frame,
        );
    }

    // OpenH264 parallelises by slicing the frame, so a speed-up costs bits: a slice cannot
    // predict across its own boundary. Both columns matter — at 3 Mbps a 20% bitrate rise is
    // 600 kbps a phone has to receive over a relay.
    println!("\nencoder threads (1620x1080):");
    let mut baseline_kb = 0.0;
    for threads in [1u16, 2, 4, 6] {
        let r = bench_encode(1620, 1080, Some(threads), None)?;
        if threads == 1 {
            baseline_kb = r.kb_per_frame;
        }
        println!(
            "  {threads} thread(s)   {:6.2} ms   {:5.1} kB/frame  ({:+.1}% bits)",
            r.ms_per_frame,
            r.kb_per_frame,
            100.0 * (r.kb_per_frame - baseline_kb) / baseline_kb.max(f64::EPSILON)
        );
    }

    // The same question, with something for those threads to divide.
    //
    // Left to itself on screen content OpenH264 emits one slice per frame, so extra threads have
    // nothing to do. That is what the table above shows: threads cannot help until there is
    // something to divide.
    //
    // The cap has a second use. Measured on a real session, a hard 1080p frame reached about 110
    // kB against a 1756 kbps budget, and one of those is several hundred milliseconds of send
    // queue on a relayed link. That is exactly what trips the capturer's latency ramp and produces
    // the drops people report while watching video.
    //
    // Both columns matter: a slice cannot predict across its own boundary, so any speed-up is paid
    // for in bits, and at these bitrates a 20% rise is bandwidth a phone on a relay does not have.
    println!("\nforced slices (1620x1080, 4 threads):");
    for slice_kb in [4u32, 8, 16, 32] {
        let r = bench_encode(1620, 1080, Some(4), Some(slice_kb * 1024))?;
        println!(
            "  <= {slice_kb:2} kB/slice  {:6.2} ms   {:5.1} kB/frame  ({:+.1}% bits)",
            r.ms_per_frame,
            r.kb_per_frame,
            100.0 * (r.kb_per_frame - baseline_kb) / baseline_kb.max(f64::EPSILON)
        );
    }

    // Does a mismatched `max_frame_rate` waste the bitrate budget?
    //
    // The encoder is built once with `DEFAULT_FPS` and never retargeted when the quality ladder
    // lowers the rung's frame rate. If OpenH264's bitrate-mode rate control allocates bits per
    // frame as `bitrate / max_frame_rate`, then feeding 12 frames to an encoder configured for 30
    // spends 12/30 of the budget and no more — a softer picture for no reason, and a send rate
    // that looks to the quality controller like a link nobody is using.
    //
    // Measured here rather than argued: configure one encoder for 30 and one for the rate it is
    // actually fed, give both the same content at the same rate, and compare what comes out.
    println!("\nbitrate actually used, 1 Mbps target, fed at 12 fps:");
    for configured in [30u32, 12] {
        let r = bench_fps_mismatch(1620, 1080, configured, 12)?;
        let label = if configured == 12 {
            "matched"
        } else {
            "mismatched"
        };
        println!(
            "  max_frame_rate {configured:>2} ({label:<10})  {:6.0} kbps out   {:5.1} kB/frame   {} of {} frames skipped",
            r.0, r.1, r.2, r.3
        );
    }

    // What a quality change would cost if it went through a new encoder.
    //
    // The agent retargets in place (`Encoder::set_target` through the crate's `raw_api`); this
    // is the cost that avoids. A rebuild also forces an IDR, and an IDR is a bitrate spike
    // arriving exactly when the network is already struggling.
    println!("\nquality change, if it needs a new encoder:");
    let t = Instant::now();
    const REBUILDS: usize = 5;
    for _ in 0..REBUILDS {
        let enc = OpenH264Encoder::with_defaults()?;
        std::hint::black_box(&enc);
    }
    println!(
        "  construct encoder   {:6.2} ms",
        t.elapsed().as_secs_f64() * 1000.0 / REBUILDS as f64
    );

    // Plus the first frame through it, which is an IDR and allocates the internal buffers.
    let mut enc = OpenH264Encoder::with_defaults()?;
    let first = Frame {
        data: synth(1620, 1080, 0),
        width: 1620,
        height: 1080,
        timestamp_ms: 0,
    };
    let t = Instant::now();
    let idr = enc.encode(&first)?;
    println!(
        "  first frame (IDR)   {:6.2} ms   {:5.1} kB  ({:.1}x a steady frame)",
        t.elapsed().as_secs_f64() * 1000.0,
        idr.as_ref().map_or(0.0, |f| f.data.len() as f64 / 1024.0),
        idr.as_ref().map_or(0.0, |f| f.data.len() as f64 / 1024.0) / 8.0,
    );

    // Can we shed bitrate *without* touching the encoder?
    //
    // This matters because the only other lever needs a new encoder, and that costs the IDR
    // measured above — a 12x burst sent precisely when the link is already congested. But the
    // agent decides how many frames to feed, and OpenH264 budgets bits per frame from
    // `bitrate / max_frame_rate`. If that budget is per-frame rather than per-second, then
    // feeding fewer frames spends proportionally fewer bits, with no reconfiguration, no
    // keyframe, and no code in the encoder at all.
    //
    // Asserted nowhere: measured here, by handing the same content timestamps at 30, 15 and 8
    // fps and reading what comes out.
    println!("\nbitrate by feed rate (encoder configured for {DEFAULT_FPS} fps, 3 Mbps):");
    for fed_fps in [30u64, 15, 8] {
        let r = bench_feed_rate(1620, 1080, fed_fps)?;
        println!(
            "  fed at {fed_fps:2} fps   {:5.1} kB/frame   -> {:5.2} Mbps actual",
            r,
            r * 1024.0 * 8.0 * fed_fps as f64 / 1_000_000.0
        );
    }

    Ok(())
}

/// Encode at `fed_fps` with the encoder configured for `configured_fps`.
///
/// Returns (kbps actually produced, kB per frame). The only difference between the two runs is
/// the number handed to `max_frame_rate`, so any gap between them is attributable to that alone.
fn bench_fps_mismatch(
    w: u32,
    h: u32,
    configured_fps: u32,
    fed_fps: u64,
) -> anyhow::Result<(f64, f64, usize, usize)> {
    let mut enc =
        OpenH264Encoder::new_with_threads(1_000_000, configured_fps as f32, DEFAULT_GOP_FRAMES, 1)?;
    enc.set_max_resolution(w, h);
    let step_ms = 1000 / fed_fps;

    let frames: Vec<Frame> = (0..FRAMES)
        .map(|i| Frame {
            data: synth(w as usize, h as usize, i),
            width: w,
            height: h,
            timestamp_ms: (i as u64) * step_ms,
        })
        .collect();

    // Skip the IDR: it is twelve times a steady frame and would swamp a 30-frame average.
    let _ = enc.encode(&frames[0])?;

    let mut bytes = 0usize;
    let mut counted = 0usize;
    let mut skipped = 0usize;
    for f in &frames[1..] {
        match enc.encode(f)? {
            Some(out) => bytes += out.data.len(),
            // The encoder declined to emit anything for this frame — its rate control decided it
            // could not afford it. Counted, because whether a mismatched `max_frame_rate` causes
            // this is the open question the bench exists to answer.
            None => skipped += 1,
        }
        counted += 1;
    }
    let per_frame_kb = bytes as f64 / counted.max(1) as f64 / 1024.0;
    let kbps = per_frame_kb * 1024.0 * 8.0 * fed_fps as f64 / 1000.0;
    Ok((kbps, per_frame_kb, skipped, counted))
}

/// Average kB/frame when frames arrive at `fed_fps`, timestamps spaced accordingly.
fn bench_feed_rate(w: u32, h: u32, fed_fps: u64) -> anyhow::Result<f64> {
    let mut enc = OpenH264Encoder::with_defaults()?;
    enc.set_max_resolution(w, h);
    let step_ms = 1000 / fed_fps;

    let frames: Vec<Frame> = (0..FRAMES)
        .map(|i| Frame {
            data: synth(w as usize, h as usize, i),
            width: w,
            height: h,
            timestamp_ms: (i as u64) * step_ms,
        })
        .collect();

    // Skip the IDR: it is 12x a steady frame and would dominate a 30-frame average.
    let _ = enc.encode(&frames[0])?;

    let mut bytes = 0usize;
    let mut counted = 0usize;
    for f in &frames[1..] {
        if let Some(out) = enc.encode(f)? {
            bytes += out.data.len();
        }
        counted += 1;
    }
    Ok(bytes as f64 / counted.max(1) as f64 / 1024.0)
}

struct Bench {
    ms_per_frame: f64,
    kb_per_frame: f64,
}

fn bench_convert(w: u32, h: u32) -> f64 {
    let data = synth(w as usize, h as usize, 0);
    let t = Instant::now();
    for _ in 0..FRAMES {
        let bgra = BgraSliceU8::new(&data, (w as usize, h as usize));
        let yuv = YUVBuffer::from_bgra8_source(bgra);
        std::hint::black_box(&yuv);
    }
    t.elapsed().as_secs_f64() * 1000.0 / FRAMES as f64
}

fn bench_encode(
    w: u32,
    h: u32,
    threads: Option<u16>,
    max_slice_len: Option<u32>,
) -> anyhow::Result<Bench> {
    let mut enc = match threads {
        Some(n) => OpenH264Encoder::new_tuned(
            DEFAULT_BITRATE_BPS,
            DEFAULT_FPS,
            DEFAULT_GOP_FRAMES,
            n,
            max_slice_len,
        )?,
        None => OpenH264Encoder::with_defaults()?,
    };
    enc.set_max_resolution(w, h);

    // Distinct content per frame. Encoding the same buffer repeatedly measures the skip path
    // rather than the encoder — OpenH264 would emit a skip frame and return in microseconds,
    // which is real behaviour but not the one a moving screen exercises.
    let frames: Vec<Frame> = (0..FRAMES)
        .map(|i| Frame {
            data: synth(w as usize, h as usize, i),
            width: w,
            height: h,
            timestamp_ms: (i as u64) * 16,
        })
        .collect();

    // One warm-up: the first encode allocates the encoder's buffers and is an IDR, so counting it
    // would charge one-off costs to the steady state.
    let _ = enc.encode(&frames[0])?;

    let t = Instant::now();
    let mut bytes = 0usize;
    for f in &frames {
        if let Some(out) = enc.encode(f)? {
            bytes += out.data.len();
        }
    }
    let elapsed = t.elapsed().as_secs_f64() * 1000.0;

    Ok(Bench {
        ms_per_frame: elapsed / FRAMES as f64,
        kb_per_frame: bytes as f64 / FRAMES as f64 / 1024.0,
    })
}

/// A frame that looks enough like a desktop to cost what a desktop costs.
///
/// Flat ground, a window, and a band of one-pixel stripes standing in for text. Uniform noise
/// would be the wrong shape of input: it defeats the intra prediction screen content is full of,
/// and would make the encoder look slower than it is in practice. `phase` shifts everything a few
/// pixels per frame so successive frames differ, which is what makes inter prediction work.
fn synth(w: usize, h: usize, phase: usize) -> Vec<u8> {
    let mut data = vec![0u8; w * h * 4];
    let shift = (phase * 7) % 64;
    for y in 0..h {
        let row = y * w * 4;
        let bg = 24 + (y * 40 / h) as u8;
        for x in 0..w {
            let i = row + x * 4;
            let in_window = x > w / 6 && x < w * 5 / 6 && y > h / 8 && y < h * 7 / 8;
            let text = in_window && (y / 3 + shift) % 11 < 2;
            let (b, g, r) = if text {
                if (x + shift).is_multiple_of(3) {
                    (30, 30, 34)
                } else {
                    (238, 238, 240)
                }
            } else if in_window {
                (250, 250, 252)
            } else {
                (bg, bg, bg + 6)
            };
            data[i] = b;
            data[i + 1] = g;
            data[i + 2] = r;
            data[i + 3] = 255;
        }
    }
    data
}
