//! Replays recorded per-frame telemetry through the ported `FrameDropper` and reports what it
//! would have said.
//!
//! `cargo run -p afklink-core --example frame_dropper_replay --release -- <log> [<log> ...]`
//!
//! ## Why this exists
//!
//! The port has a falsification criterion that is not a unit test: it fails if, replayed against
//! the forced-budget calibration recordings, it cannot bound the accumulator below 3 s of target,
//! or if on a static-desktop recording it causes any descent at all. Unit tests establish that the
//! arithmetic matches
//! libwebrtc. Only a recording establishes that the arithmetic says the right thing about this
//! product's own traffic — a still Windows desktop, a ten-second GOP, keyframes of 40 to 67 kB,
//! and a capture API that hands over six frames a second when nothing is moving.
//!
//! `ladder_replay` cannot do this job. It reads `pipeline` lines, which are one-second
//! aggregates, and the whole point of a bit bucket is what happens inside a second.
//!
//! ## What it consumes
//!
//! The per-frame `frame` line, which the agent emits under `AFKLINK_CALIBRATE=1`:
//!
//! ```text
//! INFO frame w=1620 h=1080 px=1749600 bytes=330 qp="34" key=false gap_ms=10 \
//!      encode_us=8408 budget_kbps=1388 fps_cfg=30 estimate_kbps=600 in_flight=0 rtt_ms="0"
//! ```
//!
//! ## One approximation
//!
//! `leak` must be called once per frame the *capturer offers*, and the log records only frames the
//! encoder *produced*. The two differ when the encode loop drains to newest and discards stale
//! frames — `dropped_stale` on the `pipeline` line, which is 0 throughout the calibration
//! recording, so on this recording they are the same thing.
//!
//! Rather than assume that in general, the leak is driven from the wall clock instead: `leak`'s
//! whole invariant is that the drain per wall-clock second equals the target, so over a gap of
//! `dt` at an offered rate of `fps` there are `dt · fps` leaks, and calling it that many times
//! reproduces the correct total drain whether or not every offered frame was encoded. The
//! fractional remainder is carried, so no drain is lost to rounding across a long run.

use afklink_core::frame_dropper::FrameDropper;

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!("{key}="))? + key.len() + 1;
    let rest = &line[at..];
    Some(if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()?
    } else {
        rest.split(' ').next()?
    })
}

/// One encoded frame, as the `frame` log line carries it.
#[derive(Debug, Clone, Copy)]
struct FrameRow {
    bytes: usize,
    key: bool,
    gap_ms: u32,
    budget_kbps: u32,
}

fn parse(line: &str) -> Option<FrameRow> {
    if !line.contains(" frame ") || !line.contains("gap_ms=") {
        return None;
    }
    Some(FrameRow {
        bytes: field(line, "bytes")?.parse().ok()?,
        key: field(line, "key")? == "true",
        gap_ms: field(line, "gap_ms")?.parse().ok()?,
        budget_kbps: field(line, "budget_kbps")?.parse().ok()?,
    })
}

/// What the replay observed, per distinct budget the sweep dictated.
#[derive(Debug, Default, Clone, Copy)]
struct Segment {
    frames: u64,
    keyframes: u64,
    bytes: u64,
    wall_ms: u64,
    max_fullness: f32,
    max_ratio: f32,
    /// Ticks (frames) on which fullness was above 1.0 — the bucket over half a second of
    /// allowance, which is the condition a controller would act on.
    over_frames: u64,
    max_accumulator_kbits: f32,
}

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!(
            "usage: frame_dropper_replay <log> [<log> ...]\n\
             \n\
             Reads per-frame `frame` lines (AFKLINK_CALIBRATE=1) and reports what the ported\n\
             FrameDropper would have said about each budget the sweep held."
        );
        std::process::exit(2);
    }

    for path in &paths {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: {e}");
                continue;
            }
        };
        let rows: Vec<FrameRow> = text.lines().filter_map(parse).collect();
        if rows.is_empty() {
            println!("\n{path}: no per-frame lines (was AFKLINK_CALIBRATE=1 set?)");
            continue;
        }

        println!("\n=== {path} — {} frames ===", rows.len());

        let mut dropper = FrameDropper::new();
        let mut leak_debt = 0.0f64;
        // The offered rate over a sliding second, reconstructed from arrival gaps the same way the
        // encode thread measures it live.
        let mut window_ms = 0u64;
        let mut window_frames = 0u32;
        let mut offered_fps = 30u32;

        // Keyed by the budget the sweep dictated, which is what makes the segments comparable.
        let mut segments: Vec<(u32, Segment)> = Vec::new();

        for r in &rows {
            window_ms += u64::from(r.gap_ms);
            window_frames += 1;
            if window_ms >= 1000 {
                offered_fps =
                    ((f64::from(window_frames) * 1000.0 / window_ms as f64).round() as u32).max(1);
                window_ms = 0;
                window_frames = 0;
            }

            dropper.set_rates(r.budget_kbps as f32, offered_fps as f32);

            // Drain the wall clock that passed before this frame. See the module note.
            leak_debt += f64::from(r.gap_ms) * f64::from(offered_fps) / 1000.0;
            while leak_debt >= 1.0 {
                dropper.leak(offered_fps);
                leak_debt -= 1.0;
            }

            dropper.fill(r.bytes, !r.key);

            // A new segment whenever the dictated budget changes, which is what the sweep varies
            // and therefore what makes two stretches comparable.
            if segments
                .last()
                .is_none_or(|(kbps, _)| *kbps != r.budget_kbps)
            {
                segments.push((r.budget_kbps, Segment::default()));
            }
            let Some((_, seg)) = segments.last_mut() else {
                continue;
            };
            seg.frames += 1;
            seg.keyframes += u64::from(r.key);
            seg.bytes += r.bytes as u64;
            seg.wall_ms += u64::from(r.gap_ms);
            seg.max_fullness = seg.max_fullness.max(dropper.fullness());
            seg.max_ratio = seg.max_ratio.max(dropper.drop_ratio());
            seg.max_accumulator_kbits = seg.max_accumulator_kbits.max(dropper.accumulator_kbits());
            if dropper.fullness() > 1.0 {
                seg.over_frames += 1;
            }
        }

        println!(
            "{:>7} {:>7} {:>6} {:>4} {:>8} {:>8} {:>9} {:>9} {:>7}",
            "budget",
            "frames",
            "wall_s",
            "idr",
            "produced",
            "max_full",
            "max_ratio",
            "max_acc",
            "over%"
        );
        let mut worst_fullness = 0.0f32;
        let mut worst_accumulator_over_cap = 0.0f32;
        for (kbps, s) in &segments {
            let wall_s = s.wall_ms as f64 / 1000.0;
            let produced_kbps = if wall_s > 0.0 {
                s.bytes as f64 * 8.0 / wall_s / 1000.0
            } else {
                0.0
            };
            let over_pct = if s.frames > 0 {
                s.over_frames as f64 * 100.0 / s.frames as f64
            } else {
                0.0
            };
            println!(
                "{kbps:>7} {:>7} {:>6.1} {:>4} {:>8.0} {:>8.2} {:>9.2} {:>9.0} {:>6.0}%",
                s.frames,
                wall_s,
                s.keyframes,
                produced_kbps,
                s.max_fullness,
                s.max_ratio,
                s.max_accumulator_kbits,
                over_pct
            );
            worst_fullness = worst_fullness.max(s.max_fullness);
            // The cap is 3 s of target; the bucket's own maximum is 0.5 s. So the cap is reached at
            // a fullness of 6.0, and anything above that would mean the cap is not holding.
            worst_accumulator_over_cap =
                worst_accumulator_over_cap.max(s.max_accumulator_kbits / (*kbps as f32 * 3.0));
        }

        // The two falsification criteria, evaluated rather than described.
        println!();
        let bounded = worst_accumulator_over_cap <= 1.0 + 1e-3;
        println!(
            "accumulator bounded below 3 s of target: {}  (worst was {:.2}x the cap)",
            if bounded { "yes" } else { "NO" },
            worst_accumulator_over_cap
        );
        println!(
            "worst fullness across the recording: {worst_fullness:.2}  \
             (1.0 = half a second of allowance in the bucket)"
        );
        if worst_fullness <= 1.0 {
            println!("-> this recording would have produced no descent from this signal");
        } else {
            println!(
                "-> this signal would have fired on this recording; read the table for where, and \
                 check it against what the link was actually doing before wiring it to the ladder"
            );
        }
    }
}
