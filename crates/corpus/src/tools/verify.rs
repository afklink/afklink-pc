//! Encode a scenario the way a session would, and say what it costs.
//!
//! Each file is read, paced by the capturer's own deadline scheduler (`afklink_capture::pace`,
//! on the scenario's timestamps rather than a clock), scaled by the capturer's `Scaler`, and fed to
//! the production encoder (`OpenH264Encoder::new`, the shipped configuration) retargeted every
//! frame like the encode loop does. What comes out is the encoder's own answer to the content:
//! bytes per frame, the quantiser it chose, and the rate per second.
//!
//! Two kinds of target: fixed budgets (one encoder per budget, all fed the same frames), or the
//! per-second budget and rung of a live session log replayed on the scenario (`--replay-log`), for
//! a like-for-like comparison with what that session's encoder reported.
//!
//! The frame dropper and the queue guard of the real encode loop are not modelled: this measures
//! the content and the encoder, not the controller.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use afklink_capture::pace;
use afklink_core::scale::Scaler;
use afklink_core::traits::Encoder;
use afklink_core::types::Frame;
use afklink_encode::{OpenH264Encoder, DEFAULT_GOP_FRAMES};
use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::reader::Reader;

/// What the encoder is asked for, as a function of scenario time.
#[derive(Debug, Clone)]
pub enum Target {
    Fixed {
        kbps: u32,
        max_h: u32,
        fps: u32,
    },
    /// Per-second steps from a session log: `(kbps, max_h, fps, logged_kbps, logged_qp)`.
    Replay {
        label: String,
        steps: Vec<LogSecond>,
    },
}

/// One `pipeline` line of an agent log.
#[derive(Debug, Clone, Serialize)]
pub struct LogSecond {
    pub time: String,
    pub budget_kbps: u32,
    pub max_h: u32,
    pub fps: u32,
    pub kbps: u32,
    pub avg_qp: Option<f64>,
    pub offered_fps: Option<f64>,
    pub encode_fps: Option<f64>,
}

impl Target {
    fn at(&self, t_us: u64) -> (u32, u32, u32) {
        match self {
            Self::Fixed { kbps, max_h, fps } => (*kbps, *max_h, *fps),
            Self::Replay { steps, .. } => {
                let i = ((t_us / 1_000_000) as usize).min(steps.len().saturating_sub(1));
                let s = &steps[i];
                (s.budget_kbps, s.max_h, s.fps)
            }
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Fixed { kbps, max_h, fps } => format!("{max_h}p{fps} @ {kbps} kbps"),
            Self::Replay { label, .. } => label.clone(),
        }
    }

    fn seconds(&self) -> Option<f64> {
        match self {
            Self::Fixed { .. } => None,
            Self::Replay { steps, .. } => Some(steps.len() as f64),
        }
    }
}

/// Per-target results for one scenario.
#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub target: String,
    pub offered: u64,
    pub admitted: u64,
    pub encoded: u64,
    pub skipped: u64,
    pub first_frame_bytes: u64,
    pub keyframes: u64,
    /// Mean bytes per encoded frame, the opening IDR excluded.
    pub bytes_per_frame: f64,
    pub max_frame_bytes: u64,
    pub kbps_mean: f64,
    pub kbps_p50: f64,
    pub kbps_p90: f64,
    pub kbps_max: f64,
    pub qp_p10: f64,
    pub qp_p50: f64,
    pub qp_p90: f64,
    /// Share of encoded frames at the configured floor (16) and ceiling (46).
    pub qp_floor_share: f64,
    pub qp_ceiling_share: f64,
    pub encode_ms_mean: f64,
    /// Per second: `(kbps, mean QP, encoded frames)`.
    pub per_second: Vec<(f64, Option<f64>, u32)>,
    /// For a replay, the log's own numbers for the same seconds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub logged: Vec<LogSecond>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioReport {
    pub scenario: String,
    pub file: PathBuf,
    pub duration_s: f64,
    pub targets: Vec<TargetReport>,
}

struct Run {
    target: Target,
    enc: OpenH264Encoder,
    current: Option<(u32, u32)>,
    next_due: Option<Instant>,
    offered: u64,
    admitted: u64,
    encoded: u64,
    skipped: u64,
    keyframes: u64,
    first_bytes: Option<u64>,
    frames: Vec<(u64, u64, Option<u32>)>,
    encode_time: Duration,
}

/// Encode one scenario against every target.
pub fn run(path: &Path, targets: &[Target], limit_s: Option<f64>) -> Result<ScenarioReport> {
    let mut reader = Reader::open(path)?;
    let meta = reader.metadata().clone();
    let duration_us = reader.duration_us().unwrap_or(0);
    let limit_us = targets
        .iter()
        .filter_map(Target::seconds)
        .chain(limit_s)
        .map(|s| (s * 1e6) as u64)
        .min()
        .unwrap_or(u64::MAX)
        .min(duration_us.max(1));

    let mut runs = Vec::new();
    for t in targets {
        let (kbps, _, fps) = t.at(0);
        runs.push(Run {
            enc: OpenH264Encoder::new(kbps * 1000, fps as f32, DEFAULT_GOP_FRAMES)?,
            target: t.clone(),
            current: None,
            next_due: None,
            offered: 0,
            admitted: 0,
            encoded: 0,
            skipped: 0,
            keyframes: 0,
            first_bytes: None,
            frames: Vec::new(),
            encode_time: Duration::ZERO,
        });
    }
    let base = Instant::now();
    let mut scaler = Scaler::new();
    let mut scaled: Vec<u8> = Vec::new();
    let mut scaled_for: Option<(u64, u32)> = None;
    let started = Instant::now();

    while let Some(f) = reader.next_frame()? {
        if f.t_us >= limit_us {
            break;
        }
        let now = base + Duration::from_micros(f.t_us);
        for run in &mut runs {
            let (kbps, max_h, fps) = run.target.at(f.t_us);
            run.offered += 1;
            let interval = Duration::from_micros(1_000_000 / u64::from(fps.max(1)));
            let (decision, due) = pace::admit(now, run.next_due, interval);
            run.next_due = Some(due);
            if decision == pace::Admission::Early {
                continue;
            }
            run.admitted += 1;
            // Scale as the capturer does: straight from the stored frame, which is the screen at
            // full resolution (or already the top rung, passed through untouched at that height).
            if scaled_for != Some((f.index, max_h)) {
                scaler
                    .fit_into(f.data, f.width, f.height, u32::MAX / 2, max_h, &mut scaled)
                    .context("scale")?;
                scaled_for = Some((f.index, max_h));
            }
            let (w, h) = afklink_core::scale::fit_within(f.width, f.height, u32::MAX / 2, max_h);
            if run.current != Some((max_h, fps)) {
                tracing::debug!(
                    scenario = %meta.scenario,
                    target = %run.target.label(),
                    t_s = f.t_us as f64 / 1e6,
                    w,
                    h,
                    fps,
                    kbps,
                    "encoder target changed"
                );
                run.current = Some((max_h, fps));
            }
            run.enc.set_target(kbps, fps);
            let frame = Frame {
                data: std::mem::take(&mut scaled),
                width: w,
                height: h,
                timestamp_ms: f.t_us / 1000,
            };
            let t0 = Instant::now();
            let out = run.enc.encode(&frame);
            run.encode_time += t0.elapsed();
            scaled = frame.data;
            match out? {
                Some(e) => {
                    let qp = run.enc.last_frame_qp();
                    run.encoded += 1;
                    if e.is_keyframe {
                        run.keyframes += 1;
                    }
                    run.first_bytes.get_or_insert(e.data.len() as u64);
                    run.frames.push((f.t_us, e.data.len() as u64, qp));
                }
                None => run.skipped += 1,
            }
        }
    }
    let dur_s = (limit_us.min(duration_us) as f64 / 1e6).max(1e-3);
    let mut reports = Vec::new();
    for run in runs {
        reports.push(summarise(run, dur_s));
    }
    tracing::info!(
        scenario = %meta.scenario,
        targets = targets.len(),
        wall_s = started.elapsed().as_secs_f64(),
        "encoded"
    );
    Ok(ScenarioReport {
        scenario: meta.scenario,
        file: path.to_path_buf(),
        duration_s: dur_s,
        targets: reports,
    })
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

fn summarise(run: Run, dur_s: f64) -> TargetReport {
    let secs = dur_s.ceil().max(1.0) as usize;
    let mut per: Vec<(u64, Vec<u32>, u32)> = vec![(0, Vec::new(), 0); secs];
    for (t, bytes, qp) in &run.frames {
        let i = ((*t / 1_000_000) as usize).min(secs - 1);
        per[i].0 += bytes;
        if let Some(q) = qp {
            per[i].1.push(*q);
        }
        per[i].2 += 1;
    }
    let per_second: Vec<(f64, Option<f64>, u32)> = per
        .iter()
        .map(|(b, qps, n)| {
            let q = (!qps.is_empty())
                .then(|| qps.iter().map(|q| f64::from(*q)).sum::<f64>() / qps.len() as f64);
            (*b as f64 * 8.0 / 1000.0, q, *n)
        })
        .collect();
    let mut kbps: Vec<f64> = per_second.iter().map(|p| p.0).collect();
    kbps.sort_by(f64::total_cmp);
    let mut qps: Vec<f64> = run
        .frames
        .iter()
        .filter_map(|(_, _, q)| q.map(f64::from))
        .collect();
    qps.sort_by(f64::total_cmp);
    let rest: Vec<u64> = run.frames.iter().skip(1).map(|f| f.1).collect();
    let bytes_per_frame = if rest.is_empty() {
        0.0
    } else {
        rest.iter().sum::<u64>() as f64 / rest.len() as f64
    };
    let total_bytes: u64 = run.frames.iter().map(|f| f.1).sum();
    let share = |pred: &dyn Fn(f64) -> bool| {
        if qps.is_empty() {
            0.0
        } else {
            qps.iter().filter(|q| pred(**q)).count() as f64 / qps.len() as f64
        }
    };
    let logged = match &run.target {
        Target::Replay { steps, .. } => steps.clone(),
        Target::Fixed { .. } => Vec::new(),
    };
    TargetReport {
        target: run.target.label(),
        offered: run.offered,
        admitted: run.admitted,
        encoded: run.encoded,
        skipped: run.skipped,
        first_frame_bytes: run.first_bytes.unwrap_or(0),
        keyframes: run.keyframes,
        bytes_per_frame,
        max_frame_bytes: run.frames.iter().map(|f| f.1).max().unwrap_or(0),
        kbps_mean: total_bytes as f64 * 8.0 / 1000.0 / dur_s,
        kbps_p50: percentile(&kbps, 0.5),
        kbps_p90: percentile(&kbps, 0.9),
        kbps_max: kbps.last().copied().unwrap_or(0.0),
        qp_p10: percentile(&qps, 0.1),
        qp_p50: percentile(&qps, 0.5),
        qp_p90: percentile(&qps, 0.9),
        qp_floor_share: share(&|q| q <= 16.0),
        qp_ceiling_share: share(&|q| q >= 46.0),
        encode_ms_mean: if run.encoded + run.skipped == 0 {
            0.0
        } else {
            run.encode_time.as_secs_f64() * 1000.0 / (run.encoded + run.skipped) as f64
        },
        per_second,
        logged,
    }
}

/// One rung of a rescale check.
#[derive(Debug, Clone, Serialize)]
pub struct RescaleRow {
    pub max_h: u32,
    /// PSNR of the two-step picture against the direct one, over B, G and R.
    pub psnr_db: f64,
    pub direct_kbps: f64,
    pub two_step_kbps: f64,
    pub direct_qp_p50: f64,
    pub two_step_qp_p50: f64,
}

/// What storing at the top rung costs a lower rung: for every full-resolution frame `next` yields,
/// scale it straight to each rung (what the live capturer does) and via the 1080p picture (what a
/// simulator fed a top-rung file does), then compare the pictures and what the production encoder
/// makes of each at the same budget.
pub fn rescale_check(
    mut next: impl FnMut(&mut Vec<u8>) -> Result<bool>,
    src_w: u32,
    src_h: u32,
    top_h: u32,
    rungs: &[u32],
    kbps: u32,
    fps: u32,
) -> Result<Vec<RescaleRow>> {
    struct Acc {
        max_h: u32,
        direct: OpenH264Encoder,
        two: OpenH264Encoder,
        sq_err: f64,
        samples: f64,
        bytes: (u64, u64),
        qps: (Vec<f64>, Vec<f64>),
    }
    let mut accs = Vec::new();
    for &h in rungs {
        accs.push(Acc {
            max_h: h,
            direct: OpenH264Encoder::new(kbps * 1000, fps as f32, DEFAULT_GOP_FRAMES)?,
            two: OpenH264Encoder::new(kbps * 1000, fps as f32, DEFAULT_GOP_FRAMES)?,
            sq_err: 0.0,
            samples: 0.0,
            bytes: (0, 0),
            qps: (Vec::new(), Vec::new()),
        });
    }
    let (mut s1, mut s2, mut s3) = (Scaler::new(), Scaler::new(), Scaler::new());
    let (mut full, mut top, mut d, mut t) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut n = 0u64;
    while next(&mut full)? {
        let (tw, th) = s1.fit_into(&full, src_w, src_h, u32::MAX / 2, top_h, &mut top)?;
        for a in &mut accs {
            let (w, h) = s2.fit_into(&full, src_w, src_h, u32::MAX / 2, a.max_h, &mut d)?;
            let (w2, h2) = s3.fit_into(&top, tw, th, u32::MAX / 2, a.max_h, &mut t)?;
            anyhow::ensure!(
                (w, h) == (w2, h2),
                "rung sizes differ: {w}x{h} vs {w2}x{h2}"
            );
            for (p, q) in d.as_chunks::<4>().0.iter().zip(t.as_chunks::<4>().0) {
                for c in 0..3 {
                    let e = f64::from(p[c]) - f64::from(q[c]);
                    a.sq_err += e * e;
                }
                a.samples += 3.0;
            }
            for (enc, data, bytes, qps) in [
                (&mut a.direct, &mut d, &mut a.bytes.0, &mut a.qps.0),
                (&mut a.two, &mut t, &mut a.bytes.1, &mut a.qps.1),
            ] {
                enc.set_target(kbps, fps);
                let frame = Frame {
                    data: std::mem::take(data),
                    width: w,
                    height: h,
                    timestamp_ms: n * 1000 / u64::from(fps),
                };
                let out = enc.encode(&frame)?;
                *data = frame.data;
                if let Some(e) = out {
                    *bytes += e.data.len() as u64;
                    if let Some(q) = enc.last_frame_qp() {
                        qps.push(f64::from(q));
                    }
                }
            }
        }
        n += 1;
    }
    anyhow::ensure!(n > 0, "no frames to check");
    let secs = n as f64 / f64::from(fps);
    let mut rows = Vec::new();
    for mut a in accs {
        a.qps.0.sort_by(f64::total_cmp);
        a.qps.1.sort_by(f64::total_cmp);
        let mse = a.sq_err / a.samples.max(1.0);
        rows.push(RescaleRow {
            max_h: a.max_h,
            psnr_db: if mse == 0.0 {
                f64::INFINITY
            } else {
                10.0 * (255.0 * 255.0 / mse).log10()
            },
            direct_kbps: a.bytes.0 as f64 * 8.0 / 1000.0 / secs,
            two_step_kbps: a.bytes.1 as f64 * 8.0 / 1000.0 / secs,
            direct_qp_p50: percentile(&a.qps.0, 0.5),
            two_step_qp_p50: percentile(&a.qps.1, 0.5),
        });
    }
    tracing::info!(frames = n, rungs = rungs.len(), "rescale check done");
    Ok(rows)
}

/// Parse a rung label like `1080p@30`.
fn parse_rung(s: &str) -> Option<(u32, u32)> {
    let (h, fps) = s.split_once("p@")?;
    Some((h.parse().ok()?, fps.parse().ok()?))
}

/// The `pipeline` lines of an agent log between two `HH:MM:SS` times (inclusive), one per second.
pub fn read_log_window(log: &Path, from: &str, to: &str) -> Result<Vec<LogSecond>> {
    let text = std::fs::read_to_string(log).with_context(|| format!("read {}", log.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains(": pipeline ") {
            continue;
        }
        let Some(time) = line.get(11..19) else {
            continue;
        };
        if time < from || time > to {
            continue;
        }
        let field = |key: &str| -> Option<&str> {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
                .map(|v| v.trim_matches('"'))
        };
        let Some((max_h, fps)) = field("rung").and_then(parse_rung) else {
            tracing::debug!(time, "pipeline line without a rung; skipped");
            continue;
        };
        let Some(budget) = field("budget_kbps").and_then(|v| v.parse().ok()) else {
            continue;
        };
        out.push(LogSecond {
            time: time.to_string(),
            budget_kbps: budget,
            max_h,
            fps,
            kbps: field("kbps").and_then(|v| v.parse().ok()).unwrap_or(0),
            avg_qp: field("avg_qp").and_then(|v| v.parse().ok()),
            offered_fps: field("offered_fps").and_then(|v| v.parse().ok()),
            encode_fps: field("encode_fps").and_then(|v| v.parse().ok()),
        });
    }
    if out.is_empty() {
        bail!(
            "no pipeline lines between {from} and {to} in {}",
            log.display()
        );
    }
    tracing::debug!(seconds = out.len(), from, to, "log window read");
    Ok(out)
}

/// A human-readable table of reports.
#[must_use]
pub fn format_table(reports: &[ScenarioReport]) -> String {
    let mut s = String::new();
    s.push_str(
        "| scenario | target | offered/s | encoded/s | IDR kB | B/frame | kbps mean | kbps p50 / p90 / max | QP p10 / p50 / p90 | at 16 / 46 |\n",
    );
    s.push_str("|---|---|---|---|---|---|---|---|---|---|\n");
    for r in reports {
        for t in &r.targets {
            s.push_str(&format!(
                "| {} | {} | {:.1} | {:.1} | {:.1} | {:.0} | {:.0} | {:.0} / {:.0} / {:.0} | {:.1} / {:.1} / {:.1} | {:.0}% / {:.0}% |\n",
                r.scenario,
                t.target,
                t.offered as f64 / r.duration_s,
                t.encoded as f64 / r.duration_s,
                t.first_frame_bytes as f64 / 1000.0,
                t.bytes_per_frame,
                t.kbps_mean,
                t.kbps_p50,
                t.kbps_p90,
                t.kbps_max,
                t.qp_p10,
                t.qp_p50,
                t.qp_p90,
                t.qp_floor_share * 100.0,
                t.qp_ceiling_share * 100.0,
            ));
        }
    }
    s
}

/// Side-by-side seconds of a replay: the log's kbps/QP and the corpus's under the same budget.
#[must_use]
pub fn format_replay(report: &TargetReport) -> String {
    let mut s = String::from("| second | rung | budget | log kbps | log QP | corpus kbps | corpus QP | corpus frames |\n|---|---|---|---|---|---|---|---|\n");
    for (i, l) in report.logged.iter().enumerate() {
        let (kbps, qp, n) = report.per_second.get(i).copied().unwrap_or((0.0, None, 0));
        s.push_str(&format!(
            "| {} | {}p{} | {} | {} | {} | {:.0} | {} | {} |\n",
            l.time,
            l.max_h,
            l.fps,
            l.budget_kbps,
            l.kbps,
            l.avg_qp.map_or("-".into(), |q| format!("{q:.1}")),
            kbps,
            qp.map_or("-".into(), |q| format!("{q:.1}")),
            n
        ));
    }
    s
}
