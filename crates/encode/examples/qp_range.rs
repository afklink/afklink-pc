//! Measures what the quantiser range is actually worth, so the regression test can assert a
//! number rather than a hope.
//!
//! Run: `cargo run -p afklink-encode --example qp_range --release`

use openh264::encoder::{
    BitRate, Encoder as Oh264Encoder, EncoderConfig, FrameRate, IntraFramePeriod, Profile, QpRange,
    RateControlMode, UsageType,
};
use openh264::formats::{BgraSliceU8, YUVBuffer};
use openh264::{OpenH264API, Timestamp};

/// Something shaped like a desktop: flat ground, panels, and text-like rows that scroll.
///
/// Not pure high-frequency noise such as `(x*13) ^ (y*7)`: that is incompressible, drives every
/// macroblock to intra, and produces 400 kB per 720p frame at every target. It measures H.264's
/// worst case, not this product's workload, and a quantiser has almost no leverage over it. A remote desktop is mostly flat with hard edges, which is precisely the
/// content QP *can* trade against.
fn frame(w: usize, h: usize, n: u32, buf: &mut Vec<u8>) {
    buf.resize(w * h * 4, 0);
    let scroll = (n as usize) * 3;
    for (i, px) in buf.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let x = i % w;
        let y = i / w;

        // Flat desktop ground, with a sidebar panel and a content pane.
        let mut v: u8 = if x < w / 6 { 0x2b } else { 0xf2 };
        // Window chrome: a title bar and a border.
        if (40..64).contains(&y) && x >= w / 6 {
            v = 0xd8;
        }
        // Text-like rows in the content pane: thin dark runs on a light ground, scrolling.
        let row = (y + scroll) / 22;
        let within = (y + scroll) % 22;
        if y > 70 && x > w / 6 + 24 && within < 9 {
            let run = (row * 37 + x / 7) % 11;
            if run < 7 {
                v = 0x33;
            }
        }
        // A video pane: continuous tone with real motion, which is the content the failing
        // sessions were actually carrying and the only part of a desktop a quantiser has much
        // room to trade against. Expensive but compressible, unlike noise.
        let (vx0, vy0, vw, vh) = (w / 2, 140, w / 3, h / 3);
        if (vx0..vx0 + vw).contains(&x) && (vy0..vy0 + vh).contains(&y) {
            let u = x - vx0 + (n as usize) * 5;
            let t = y - vy0 + (n as usize) * 2;
            let wave = ((u * u / 64 + t * t / 48) % 256) as u8;
            let grain = (((u * 2654435761) ^ (t * 40503)) >> 7) as u8 & 0x1f;
            v = wave.wrapping_add(grain);
        }

        // A cursor, so something moves independently of everything else.
        let cx = w / 2 + ((n as usize * 11) % 200);
        let cy = h - 120;
        if x.abs_diff(cx) < 6 && y.abs_diff(cy) < 9 {
            v = 0x00;
        }
        px[0] = v;
        px[1] = v;
        px[2] = v;
        px[3] = 255;
    }
}

fn run(label: &str, qp: Option<(u8, u8)>, kbps: u32, (w, h): (usize, usize)) -> (u64, u32) {
    let cfg = EncoderConfig::new()
        .profile(Profile::Baseline)
        .bitrate(BitRate::from_bps(kbps * 1000))
        .max_frame_rate(FrameRate::from_hz(30.0))
        .rate_control_mode(RateControlMode::Bitrate)
        .usage_type(UsageType::CameraVideoRealTime)
        .scene_change_detect(false)
        .intra_frame_period(IntraFramePeriod::from_num_frames(300))
        .num_threads(4)
        .skip_frames(false)
        .max_slice_len(4096)
        .adaptive_quantization(false)
        .background_detection(false)
        .debug(false);
    let cfg = match qp {
        Some((lo, hi)) => cfg.qp(QpRange::new(lo, hi)),
        None => cfg,
    };
    let mut enc =
        Oh264Encoder::with_api_config(OpenH264API::from_source(), cfg).expect("build encoder");

    let mut buf = Vec::new();
    let mut bytes = 0u64;
    let mut counted = 0u32;
    let mut last_qp = 0u32;
    for n in 0..40u32 {
        frame(w, h, n, &mut buf);
        let yuv = YUVBuffer::from_bgra8_source(BgraSliceU8::new(&buf, (w, h)));
        let bs = enc
            .encode_at(&yuv, Timestamp::from_millis(u64::from(n) * 33))
            .expect("encode");
        // Skip the first ten: the IDR and rate control settling.
        if n >= 10 {
            bytes += bs.to_vec().len() as u64;
            counted += 1;
        }
        let _ = &mut last_qp;
    }
    let mean = (bytes / u64::from(counted)) as u32;
    let produced_kbps = (bytes * 8 / u64::from(counted)) as u32 * 30 / 1000;
    println!(
        "{w}x{h} {label:<28} target {kbps:>5} kbps -> mean frame {mean:>7} B, produced ~{produced_kbps:>5} kbps"
    );
    (bytes / u64::from(counted), produced_kbps)
}

fn main() {
    println!("screen-content real time, skip_frames(false), 40 frames, last 30 counted\n");
    // The decisive check that OpenH264's substitution really is [26, 35].
    //
    // The substitution itself cannot be observed through this crate: `ParamValidationExt` logs it
    // at WELS_LOG_INFO during `initialize_ext`, and the crate only raises the trace level with
    // `set_option` *after* that call returns, so the line is filtered by the default WARNING level
    // no matter what `.debug()` is set to. So prove it by behaviour instead — if the default really
    // is rewritten to [26, 35], then asking for exactly [26, 35] must produce identical output.
    println!("-- the substituted range, identified by behaviour --");
    for kbps in [200u32, 6_000] {
        let (a, _) = run("default qp (crate 0..51)", None, kbps, (640, 480));
        let (b, _) = run("explicit qp 26..35", Some((26, 35)), kbps, (640, 480));
        println!(
            "   identical: {}   (if so, the default IS [26,35])\n",
            if a == b { "yes" } else { "NO" }
        );
    }

    println!("-- what the range is worth --");
    for size in [(1280usize, 720usize), (640, 480)] {
        for kbps in [200u32, 600, 2_000, 6_000] {
            run("default qp (crate 0..51)", None, kbps, size);
            run("explicit qp 16..46", Some((16, 46)), kbps, size);
        }
        println!();
    }
}
