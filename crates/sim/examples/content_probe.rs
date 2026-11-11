//! What a scenario's content costs the real encoder, second by second, at a fixed budget.
//!
//! `cargo run -p afklink-sim --release --example content_probe -- <scenario.toml> [kbps] [fps] [secs]`
//!
//! The calibration tool for the synthetic desktop: a recording says what a real screen cost
//! (`idr_bytes`, the `kbps` and `avg_qp` of quiet and busy seconds), and this says what the
//! scenario's content costs on the same encoder, with the capture pacing and scaling the simulator
//! applies but no network and no controller. Defaults: 4000 kbps, 60 fps, 20 s.

use std::sync::Arc;
use std::time::Duration;

use afklink_core::quality::{QualityTarget, Rung};
use afklink_core::traits::Encoder;
use afklink_encode::OpenH264Encoder;
use afklink_sim::encode_loop::Capturer;
use afklink_sim::Scenario;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(path) = args.first() else {
        eprintln!("usage: content_probe <scenario.toml> [kbps] [fps] [secs]");
        std::process::exit(2);
    };
    let kbps: u32 = args.get(1).map_or(Ok(4000), |v| v.parse())?;
    let fps: u32 = args.get(2).map_or(Ok(60), |v| v.parse())?;
    let secs: f64 = args.get(3).map_or(Ok(20.0), |v| v.parse())?;
    // `noenc` as a fifth argument times the content alone: what drawing and pacing cost.
    let encode = args.get(4).is_none_or(|v| v != "noenc");
    let wall = std::time::Instant::now();
    let scenario = Scenario::load(std::path::Path::new(path))?;
    let mut source = scenario.content.build(scenario.seed)?;
    let target = Arc::new(QualityTarget::new(Rung { max_h: 1080, fps }));
    target.set_target_kbps(kbps);
    let mut capturer = Capturer::new();
    let mut enc = OpenH264Encoder::with_defaults()?;
    let end = Duration::from_secs_f64(secs);

    println!("{} at {kbps} kbps, {fps} fps", scenario.name);
    println!(" sec frames   kbps  max_frame  mean_qp  keys");
    let mut sec = 0u64;
    let (mut frames, mut bytes, mut max_frame, mut qp_sum, mut qp_n, mut keys) =
        (0u32, 0usize, 0usize, 0u64, 0u32, 0u32);
    let mut first_idr = None;
    let flush = |sec: u64,
                 frames: u32,
                 bytes: usize,
                 max_frame: usize,
                 qp_sum: u64,
                 qp_n: u32,
                 keys: u32| {
        println!(
            "{sec:>4} {frames:>6} {:>6} {max_frame:>10} {:>8} {keys:>5}",
            bytes * 8 / 1000,
            if qp_n > 0 {
                format!("{:.1}", qp_sum as f64 / f64::from(qp_n))
            } else {
                "-".to_string()
            }
        );
    };
    for (t, frame) in source.by_ref() {
        if t >= end {
            break;
        }
        while t.as_secs() > sec {
            flush(sec, frames, bytes, max_frame, qp_sum, qp_n, keys);
            sec += 1;
            (frames, bytes, max_frame, qp_sum, qp_n, keys) = (0, 0, 0, 0, 0, 0);
        }
        let Some(mut scaled) = capturer.on_frame(t, frame, &target)? else {
            continue;
        };
        scaled.timestamp_ms = t.as_millis() as u64;
        if !encode {
            frames += 1;
            continue;
        }
        enc.set_target(kbps, fps);
        if let Some(ef) = enc.encode(&scaled)? {
            frames += 1;
            bytes += ef.data.len();
            max_frame = max_frame.max(ef.data.len());
            if ef.is_keyframe {
                keys += 1;
                first_idr.get_or_insert(ef.data.len());
            } else if let Some(qp) = enc.last_frame_qp() {
                qp_sum += u64::from(qp);
                qp_n += 1;
            }
        }
    }
    flush(sec, frames, bytes, max_frame, qp_sum, qp_n, keys);
    println!("first IDR: {} bytes", first_idr.unwrap_or(0));
    println!("wall: {:.2} s", wall.elapsed().as_secs_f64());
    Ok(())
}
