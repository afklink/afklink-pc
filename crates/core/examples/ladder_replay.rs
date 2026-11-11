//! Replays a recorded session through the real quality ladder and reports what it would decide.
//!
//! `cargo run -p afklink-core --example ladder_replay --release -- <log> [<log> ...]`
//!
//! The agent logs every input the ladder consumes (quantiser, queue, encode time, spend ratio,
//! estimate) once a second, so a recorded session can be pushed back through the *actual*
//! `QualityController` and the trajectory read off before anyone tries the change on a real link.
//!
//! It is a replay, not a simulation: the measurements were produced at whatever rung was live, so
//! it cannot predict the exact trajectory. It shows the *shape* soundly: a ladder that descends
//! when nothing is wrong, one that cannot climb back, how far down it goes. Rung-change counts of
//! two controllers on one recording are not comparable to the last unit. Limits:
//!
//! - **The budget** reaches the ladder only through the recomputed `spend_ratio`; a bigger budget
//!   shows as a smaller spend ratio, never as the traffic that would have kept the estimate up, so
//!   an improvement shows as a lower bound.
//! - **Production at a counterfactual rung**: the content-priced climb reads production measured at
//!   the recording's rung as if it were the replayed rung's, and may refuse a climb the live
//!   controller would have costed correctly.
//! - **After a brake or a re-anchor** the recorded estimate, queue and egress describe a session
//!   that went differently: the replay is exact up to the first re-anchor and a pessimistic bound
//!   after it (substituting the re-anchored estimate is no bound, as the queue shows the collapse).
//! - **Old logs** printed a missing receiver report as `0.00`; freshness is then guessed (loss, a
//!   NACK or a changed round trip), which can only under-count reports, so the silence arm is off
//!   for them. Newer logs mark a stale report as `rtt_ms="-"`.
//!
//! What it replays and prints: one receiver report per recorded second; every re-anchor with its
//! trigger (`pause-resume`, `clean-collapse`, `outage-resume`) and evidence; every move of the
//! loss/round-trip brake and of its baseline (20 ms or more, or a reset); path changes as
//! `note_path_change`; background holds (`bg_hold_ms=`) as a frozen controller resumed with
//! `resume_after_hold`; every drain with its reason, with the viewer's `vv` counts fed to
//! `QualityController::note_viewer_frames`; and every probe target with its capacity evidence (what
//! str0m would then probe is closed in the simulator, `crates/sim`). With
//! `RUST_LOG=afklink_core=debug` the controller's own reasons go to stderr, each after a trace line
//! naming the recorded second.
//!
//! The quality profile: `--profile builtin` (this build's `QualityPolicy::fallback`), `--profile
//! <file.json>` (`{id, v, values}`), `--profiles-dir <dir>` (each session on the profile its log
//! names, `<dir>/<id>.v<v>.json`), otherwise the contract's reference vector
//! (`contract/packages/protocol/vectors/quality-profile-reference.json`), named in each header.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use afklink_core::quality::{
    opening_probe_target_kbps_with, BrakeEvent, DrainEvent, Feedback, Quality, QualityController,
    QualityPolicy, Reanchor, ReceiverReport, Rung, ViewerFrames, TICK,
};

/// One second of a recorded session, as the `pipeline` log line carries it.
#[derive(Debug, Clone)]
struct Row {
    avg_qp: Option<f32>,
    encode_ms: f32,
    queue_ms: u32,
    estimate_kbps: u32,
    spend_ratio: f32,
    /// What the encoder put on the wire in this window, keyframes included. Used only to estimate
    /// the drain rate for logs recorded before the agent measured egress itself.
    produced_kbps: u32,
    /// What actually left the socket, when the log carries it.
    ///
    /// `None` for every session recorded before this column existed, and that absence is the most
    /// consequential limitation this harness has. It is the denominator of the ladder's
    /// conservation check and of the budget's exploration bound, and for want of it this tool used
    /// to substitute the *drain* — `max(produced, 1.1 x estimate, 120)` — which is structurally at
    /// least as large as production. That silently disabled both of those mechanisms in every
    /// replay, so the harness reported identical trajectories for a controller with and without
    /// them and looked like validation while testing nothing.
    egress_kbps: Option<u32>,
    /// Whether `queue_ms` came from the log's `queue_age_ms` — a measurement — or from the older
    /// `queue_ms`, which was bytes divided by an estimate and has to be undone before use.
    ///
    /// Without this the harness applied the un-division to logs that already carry the measured
    /// age, which is a correction for an error those logs do not contain.
    queue_measured: bool,
    idr_bytes: u32,
    rung_fps: u32,
    rung_h: u32,
    /// `HH:MM:SS` from the line, for reading the replay against the recording.
    ts: String,
    /// The receiver's round trip as the line printed it; `None` for `-`.
    rtt_ms: Option<u32>,
    /// The receiver's loss in percent; `None` for `-` (no report in the interval — only printed by
    /// logs that have `brake=` on the line) or when the column is absent.
    loss_pct: Option<f32>,
    /// NACKs in the second.
    nacks: u32,
    /// Whether the line is from a build that prints `loss_pct="-"` for a missing report.
    reports_marked: bool,
    /// Whether the transport reported the media path changing since the previous `pipeline` line:
    /// `media path changed` (ICE moved the media to another candidate pair) or `ICE path restored`.
    /// Replayed as `QualityController::note_path_change` on this second's first tick, as the live
    /// control task does when `Peer::path_changes` moves.
    path_changed: bool,
    /// The line says a background hold was in progress (`bg_hold_ms=` a number, not `-`): the live
    /// controller was frozen through it — not ticked, its receiver reports not read — and resumed
    /// after it with `QualityController::resume_after_hold`. Replayed the same way. Absent from
    /// logs before the hold existed, where it is never set.
    bg_hold: bool,
    /// The line's time of day in seconds, for placing the viewer's reports in it.
    at_s: f64,
    /// Frames sent in the second (`encode_fps` less `discarded`); `None` on logs without them.
    sent_frames: Option<u32>,
    /// The viewer's `vv` reports that arrived in the second this row covers: (tick, report).
    viewer: Vec<(usize, ViewerFrames)>,
}

/// One `viewer` debug line: when it was logged, frames received since the previous report, and the
/// viewer's clock moved since it.
#[derive(Debug, Clone, Copy)]
struct ViewerLine {
    at_s: f64,
    d_recv: Option<u64>,
    d_ct_ms: Option<u64>,
}

/// A log line's time of day in seconds (`2026-10-11T20:41:55.024Z ...`).
fn time_of_day(line: &str) -> Option<f64> {
    let h: f64 = line.get(11..13)?.parse().ok()?;
    let m: f64 = line.get(14..16)?.parse().ok()?;
    let s: f64 = line.get(17..26)?.trim_end_matches('Z').parse().ok()?;
    Some(h * 3600.0 + m * 60.0 + s)
}

fn parse_viewer(line: &str) -> Option<ViewerLine> {
    // The app's session files name the target (`afklink_core::viewer_report: viewer`), the bench's
    // agent logs do not (`DEBUG viewer session=`).
    let named = line.contains("viewer_report: viewer ") || line.contains(" viewer session=");
    if !named || !line.contains(" d_recv=") {
        return None;
    }
    Some(ViewerLine {
        at_s: time_of_day(line)?,
        d_recv: field(line, "d_recv").and_then(|v| v.parse().ok()),
        d_ct_ms: field(line, "d_ct_ms").and_then(|v| v.parse().ok()),
    })
}

/// Place the session's viewer reports on the ticks of the rows they arrived in, as the live
/// control task hands them over: on the first tick at or after the report, with its age. Cumulative
/// counts from the per-report deltas (the first report counts from zero).
fn place_viewer_reports(rows: &mut [Row], lines: &[ViewerLine]) {
    let ticks = (Duration::from_secs(1).as_millis() / TICK.as_millis()) as usize;
    let tick_s = TICK.as_secs_f64();
    let mut received = 0u64;
    let mut clock_ms = 0u64;
    let mut first = true;
    let mut row = 0usize;
    for l in lines {
        if !first {
            received += l.d_recv.unwrap_or(0);
            clock_ms += l.d_ct_ms.unwrap_or(1_000);
        }
        first = false;
        while row < rows.len() && rows[row].at_s < l.at_s {
            row += 1;
        }
        let Some(r) = rows.get_mut(row) else {
            break;
        };
        let into = (l.at_s - (r.at_s - 1.0)).clamp(0.0, 1.0);
        let tick = ((into / tick_s).ceil() as usize).clamp(1, ticks) - 1;
        let age = ((tick + 1) as f64 * tick_s - into).max(0.0);
        r.viewer.push((
            tick,
            ViewerFrames {
                received,
                viewer_ms: Some(clock_ms),
                age: Duration::from_secs_f64(age),
            },
        ));
    }
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(&format!("{key}="))? + key.len() + 1;
    let rest = &line[at..];
    Some(if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()?
    } else {
        rest.split(' ').next()?
    })
}

fn parse(line: &str) -> Option<Row> {
    if !line.contains("pipeline") || !line.contains("spend_ratio=") {
        return None;
    }
    let rung = field(line, "rung")?;
    let (h, fps) = rung.split_once("p@")?;
    let qp = field(line, "avg_qp")?;
    // `queue_age_ms` is the current field; `queue_ms` is what older logs called the *inferred*
    // metric (bytes divided by the estimate). Both are accepted: a parser that knows only one
    // name reads every log with the other as zero rows and reports "0 session(s)" with exit 0. A
    // diagnostic that silently finds nothing is worse than no diagnostic, which is why `main`
    // refuses to be quiet about it too.
    //
    // `queue_age_ms` is preferred because it is a measurement. See the note in `main` about what a
    // reconstructed value is worth.
    let measured = field(line, "queue_age_ms");
    let queue = measured.or_else(|| field(line, "queue_ms"))?;
    Some(Row {
        queue_measured: measured.is_some(),
        avg_qp: (qp != "-").then(|| qp.parse().ok()).flatten(),
        encode_ms: field(line, "encode_ms")?.parse().ok()?,
        queue_ms: queue.parse().ok()?,
        estimate_kbps: field(line, "estimate_kbps")?.parse().ok()?,
        spend_ratio: field(line, "spend_ratio")?.parse().ok()?,
        produced_kbps: field(line, "kbps")?.parse().ok()?,
        egress_kbps: field(line, "egress_kbps").and_then(|v| v.parse().ok()),
        idr_bytes: field(line, "idr_bytes")?.parse().ok()?,
        rung_fps: fps.parse().ok()?,
        rung_h: h.parse().ok()?,
        ts: line.get(11..19).unwrap_or("").to_string(),
        rtt_ms: field(line, "rtt_ms").and_then(|v| v.parse().ok()),
        loss_pct: field(line, "loss_pct").and_then(|v| v.parse().ok()),
        nacks: field(line, "nacks")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        reports_marked: line.contains(" brake="),
        path_changed: false,
        bg_hold: field(line, "bg_hold_ms").is_some_and(|v| v != "-"),
        at_s: time_of_day(line).unwrap_or(0.0),
        sent_frames: field(line, "encode_fps")
            .and_then(|v| v.parse::<f32>().ok())
            .map(|fps| {
                let discarded: u32 = field(line, "discarded")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                (fps.round() as u32).saturating_sub(discarded)
            }),
        viewer: Vec::new(),
    })
}

/// Whether a log line is the transport saying the media path changed. See `Row::path_changed`.
fn is_path_change(line: &str) -> bool {
    line.contains("media path changed:") || line.contains("ICE path restored")
}

/// The receiver report a recorded second stands for, if any. See the module note on freshness.
///
/// On an old log a second guessed stale yields no report at all rather than a stale one, so the
/// silence arm is never fed a guess.
///
/// On a marked log `rtt_ms=0` is the counter's default before str0m ever emitted
/// `MediaEgressStats` — which it only does for a stream that has sent RTP — so it means *no report
/// at all*, not a fresh report of a zero round trip. A session that never connects prints
/// `rtt_ms=0 loss_pct=0.00` on every line; read as reports, they make its ICE traffic look like
/// media and put a 0 ms sample into the next session's round-trip baseline.
fn report_for(row: &Row, prev: Option<&Row>) -> Option<ReceiverReport> {
    if row.reports_marked {
        if row.rtt_ms == Some(0) {
            return None;
        }
        return Some(ReceiverReport {
            rtt_ms: row.rtt_ms,
            loss: row.loss_pct.map(|l| l / 100.0),
            nacks: row.nacks,
        });
    }
    // `rtt_ms` of 0 is the counter's default before any report arrived.
    let rtt_seen = row.rtt_ms.is_some_and(|r| r > 0);
    let fresh = rtt_seen
        && (row.loss_pct.is_some_and(|l| l > 0.0)
            || row.nacks > 0
            || prev.is_none_or(|p| p.rtt_ms != row.rtt_ms));
    fresh.then(|| ReceiverReport {
        rtt_ms: row.rtt_ms,
        loss: Some(row.loss_pct.unwrap_or(0.0) / 100.0),
        nacks: row.nacks,
    })
}

/// Split a log into sessions at each `session_request`: the CLI's output, an old daily file, or a
/// session's own file from the desktop app (`%APPDATA%\AFKLink\logs\sessions\…`), which holds its
/// one request. Rows before any request are a session too: a file that starts in the middle of one
/// — a session's file opened when the log was switched on during it, a daily file that began at UTC
/// midnight.
/// One recorded session: its seconds, and the quality profile its log says it ran on (`None` for a
/// log older than the `quality profile` line).
struct Recorded {
    rows: Vec<Row>,
    profile: Option<String>,
}

fn sessions(text: &str) -> Vec<Recorded> {
    let mut out: Vec<(Vec<Row>, Vec<ViewerLine>, Option<String>)> = Vec::new();
    // A path change seen since the last row, for the next one.
    let mut path_changed = false;
    for line in text.lines() {
        if line.contains("session_request ") {
            out.push((Vec::new(), Vec::new(), None));
            path_changed = false;
        }
        if line.contains("quality profile session=") {
            if out.is_empty() {
                out.push((Vec::new(), Vec::new(), None));
            }
            if let Some(cur) = out.last_mut() {
                cur.2 = field(line, "profile").map(str::to_string);
            }
        }
        if is_path_change(line) {
            path_changed = true;
        }
        if let Some(v) = parse_viewer(line) {
            if out.is_empty() {
                out.push((Vec::new(), Vec::new(), None));
            }
            if let Some(cur) = out.last_mut() {
                cur.1.push(v);
            }
        }
        if let Some(mut row) = parse(line) {
            if out.is_empty() {
                out.push((Vec::new(), Vec::new(), None));
            }
            row.path_changed = std::mem::take(&mut path_changed);
            if let Some(cur) = out.last_mut() {
                cur.0.push(row);
            }
        }
    }
    out.retain(|s| !s.0.is_empty());
    out.into_iter()
        .map(|(mut rows, viewer, profile)| {
            place_viewer_reports(&mut rows, &viewer);
            Recorded { rows, profile }
        })
        .collect()
}

/// The contract's reference profile, read from the repository at run time (not compiled in).
fn reference_vector_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(afklink_core::quality_policy::REFERENCE_VECTOR)
}

/// `^[a-z][a-z0-9-]{0,31}\.v[0-9]+$`, the contract's profile label.
fn is_profile_label(label: &str) -> bool {
    let Some((id, v)) = label.rsplit_once(".v") else {
        return false;
    };
    let mut head = id.chars();
    id.len() <= 32
        && head.next().is_some_and(|c| c.is_ascii_lowercase())
        && head.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !v.is_empty()
        && v.chars().all(|c| c.is_ascii_digit())
}

/// A profile file (`{id, v, values}`), checked as the agent checks a server's profile.
fn load_profile(path: &Path) -> Result<(String, QualityPolicy), String> {
    let profile = afklink_core::quality_policy::load_profile_file(path)?;
    Ok((profile.label(), profile.policy))
}

/// `--profile builtin`: this build's compiled fallback, under its own label.
const BUILTIN_ARG: &str = "builtin";

/// Which profile each session replays on: see the module note.
struct Profiles {
    /// `--profile`: every session on this one.
    fixed: Option<(String, QualityPolicy)>,
    /// `--profiles-dir`: each session on the one its log names.
    dir: Option<PathBuf>,
    reference: (String, QualityPolicy),
}

impl Profiles {
    /// The profile for a session whose log names `recorded`, and how it was chosen, for the
    /// header line.
    fn for_session(&self, recorded: Option<&str>) -> Result<(String, QualityPolicy), String> {
        if let Some((label, policy)) = &self.fixed {
            return Ok((format!("{label} (--profile)"), policy.clone()));
        }
        if recorded == Some(afklink_core::quality_policy::FALLBACK_LABEL) {
            return Ok((
                format!(
                    "{} (this build's fallback)",
                    afklink_core::quality_policy::FALLBACK_LABEL
                ),
                QualityPolicy::fallback(),
            ));
        }
        if let (Some(dir), Some(label)) = (&self.dir, recorded) {
            // The label is the log's text: only a label of the contract's shape becomes a file
            // name, so a doctored line cannot reach outside the directory (`../x.v1`, `C:\…`).
            if !is_profile_label(label) {
                return Err(format!(
                    "the log names profile {label:?}, which is no label (<id>.v<n>); not looked up"
                ));
            }
            let (found, policy) = load_profile(&dir.join(format!("{label}.json")))?;
            if found != label {
                return Err(format!("{label}.json in {} is {found}", dir.display()));
            }
            return Ok((format!("{label} (--profiles-dir)"), policy));
        }
        let why = match recorded {
            None => "reference vector; the log names none".to_string(),
            Some(l) => format!("reference vector; the log names {l}"),
        };
        Ok((
            format!("{} ({why})", self.reference.0),
            self.reference.1.clone(),
        ))
    }
}

fn replay(rows: &[Row], label: &str, profile: &str, policy: &QualityPolicy) {
    // The source the sessions were recorded on. The ladder prices rungs against it.
    let mut c = QualityController::with_policy(3600, 2400, Quality::Balanced, policy.clone());
    // What the agent tells congestion control at session start, before capture has reported the
    // screen: the probe target with nothing measured (the ladder's ceiling, for the opening), for a
    // guessed 1920x1080. The controller's probe targets are compared against it, as they are live.
    c.probe_target_sent(opening_probe_target_kbps_with(
        policy,
        1920,
        1080,
        Quality::Balanced,
    ));
    // Every probe target the controller would have sent, by recorded second.
    let mut probe_targets: Vec<(usize, u32, u32)> = Vec::new();
    let ticks_per_row = (Duration::from_secs(1).as_millis() / TICK.as_millis()) as u32;

    let mut occupancy: BTreeMap<String, u32> = BTreeMap::new();
    let mut changes: Vec<(usize, Rung, &'static str)> = Vec::new();
    let mut lowest = policy.ladder[0];
    // What the controller told congestion control and what its brake did, by recorded second.
    let mut reanchors: Vec<(usize, Reanchor)> = Vec::new();
    let mut brakes: Vec<(usize, BrakeEvent)> = Vec::new();
    // What the controller made of the estimate against its capacity evidence, second by second:
    // the transitions, and how many seconds ended in each state.
    let mut collapse_changes: Vec<(usize, &'static str, u32, u32)> = Vec::new();
    let mut collapse_seconds: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut last_view = "-";
    // The round-trip baseline the brake judges against, by recorded second, whenever it moves by
    // at least `BASE_MOVE_MS` or appears/disappears: a path change resetting it, a path step
    // re-basing it, or the thirty-report minimum ageing out. And the transport's path changes.
    const BASE_MOVE_MS: u32 = 20;
    let mut base_moves: Vec<(usize, Option<u32>, Option<u32>)> = Vec::new();
    let mut last_base: Option<u32> = None;
    let mut path_changes: Vec<usize> = Vec::new();
    // Background holds: (first held second, seconds held), and the seconds of the one in progress.
    let mut holds: Vec<(usize, u32)> = Vec::new();
    let mut held_secs = 0u32;
    // Drain mode as the replayed controller ran it, by recorded second and tick; and what was sent,
    // cumulative, for the viewer's reports to be read against. `AFKLINK_REPLAY_VIEWER=off` replays
    // without the viewer's reports: the controller's drain decisions as they were before it read them.
    let mut drains: Vec<(usize, usize, DrainEvent)> = Vec::new();
    let viewer_on = !std::env::var("AFKLINK_REPLAY_VIEWER").is_ok_and(|v| v == "off");
    let mut sent_frames = 0u64;
    let mut sent_bytes = 0u64;

    // The live agent subtracts keyframe bytes from the rate the ladder sees, because an IDR lands
    // inside one window and reads there as several times the link's capacity. The log does not
    // carry a per-window keyframe total, so approximate it the only way the line allows: a change
    // in `idr_bytes` means this window contained that keyframe.
    let mut prev_idr = 0u32;
    for (sec, row) in rows.iter().enumerate() {
        // A second of a background hold: the live controller was frozen through it — not ticked,
        // its receiver reports not read — so the replayed one is too. Only the path changing is
        // still heard, as live. The second still counts at the rung, which the hold kept.
        if row.bg_hold {
            if held_secs == 0 {
                tracing::trace!(sec, ts = %row.ts, "background hold: the replayed controller is frozen");
            }
            held_secs += 1;
            if row.path_changed {
                c.note_path_change("replayed");
                path_changes.push(sec);
            }
            let cur = c.current();
            *occupancy
                .entry(format!("{}p@{}", cur.max_h, cur.fps))
                .or_default() += 1;
            continue;
        }
        if held_secs > 0 {
            // Resumed as live, with the recorded estimate as str0m's now, and the hold's re-anchor
            // decided on the same tick, as the agent does (its transport applies it right before the
            // resumed video's first frame). Listed with the others.
            let held = Duration::from_secs(u64::from(held_secs));
            holds.push((sec - held_secs as usize, held_secs));
            held_secs = 0;
            if c.resume_after_hold(held, row.estimate_kbps).reanchor_due {
                c.reanchor_after_hold(row.estimate_kbps);
            }
            if c.take_bwe_reanchor().is_some() {
                if let Some(r) = c.last_reanchor() {
                    reanchors.push((sec, r));
                }
            }
            if let Some(ev) = c.take_brake_event() {
                brakes.push((sec, ev));
            }
        }
        let key_kbps = if row.idr_bytes != prev_idr {
            prev_idr = row.idr_bytes;
            row.idr_bytes * 8 / 1000
        } else {
            0
        };
        let inter_kbps = row.produced_kbps.saturating_sub(key_kbps);
        tracing::trace!(sec, ts = %row.ts, "replaying recorded second");

        // One receiver report per recorded second, handed over on its first tick — the live agent
        // hands over one per str0m stats event, which is also once a second.
        let mut report = report_for(row, sec.checked_sub(1).map(|p| &rows[p]));
        let estimate_kbps = row.estimate_kbps;
        if row.path_changed {
            c.note_path_change("replayed");
            path_changes.push(sec);
        }

        // The recorded second is one controller tick's worth of evidence repeated across the
        // ticks it spans. Crude, and it is the honest crude: the log has no finer resolution.
        for tick in 0..ticks_per_row {
            // What the recording sent this second, spread over its ticks, and the viewer's reports
            // that arrived on this one. See the module note on drain mode.
            if let Some(frames) = row.sent_frames {
                let n = u64::from(ticks_per_row);
                let k = tick as u64;
                sent_frames += u64::from(frames) / n + u64::from(k < u64::from(frames) % n);
                sent_bytes += u64::from(row.produced_kbps) * 1000 / 8 / n;
                c.note_frames_sent(sent_frames, sent_bytes);
            }
            if viewer_on {
                for (_, v) in row.viewer.iter().filter(|(t, _)| *t == tick as usize) {
                    c.note_viewer_frames(*v);
                }
            }
            // The live agent divides by measured egress, not by the estimate. Recorded logs from
            // before that change carry no egress column on the pipeline line, so approximate the
            // drain by the larger of the estimate and what was actually produced — production is a
            // demonstrated lower bound on what the socket accepted.
            let drain =
                afklink_core::quality::drain_kbps(inter_kbps.max(row.produced_kbps), estimate_kbps);
            let fb = Feedback {
                estimate_kbps,
                drain_kbps: drain,
                produced_kbps: inter_kbps,
                // The measurement when the log has it, the drain when it does not — and the
                // session header says which, because the two give different answers for
                // structural reasons rather than by a little. See `Row::egress_kbps`.
                egress_kbps: row.egress_kbps.unwrap_or(drain),
                // Nor a per-window sample count. The rate is the best available proxy.
                qp_samples: row.rung_fps,
                // Reconstructed, and it has to be, because the field in these recordings is a
                // *different quantity* from the one the ladder now reads.
                //
                // The logs carry `queue_ms` as it was computed at the time: `bytes x 8 / (1.1 x
                // estimate)`. The ladder now reads str0m's `first_unsent()` age directly, with no
                // estimate anywhere in it. Replaying the recorded number would be replaying the
                // very error that was removed — on a static desktop the estimate collapsed to 139
                // kbps and 17 524 bytes read as 922 ms, when the same link drained 40 817 bytes in
                // 367 ms, which is 890 kbps.
                //
                // So undo the bad divisor and apply the better one: multiply back by the estimate
                // that was used and divide by the drain the traffic demonstrates. This is an
                // approximation of a measurement that was never taken, and it is marked as such
                // wherever this harness reports on a log without `queue_age_ms`.
                //
                // Only for those logs. A log carrying `queue_age_ms` carries the measurement
                // itself, and putting it through the correction above is applying a repair to an
                // error it does not contain — it shrinks a genuine queue by `produced / 1.1 x
                // estimate` on exactly the windows where production overran, which are the windows
                // that matter most.
                queue_age_ms: if row.queue_measured {
                    row.queue_ms
                } else {
                    (u64::from(row.queue_ms) * u64::from(estimate_kbps.max(1)) * 11
                        / 10
                        / u64::from(drain.max(1))) as u32
                },
                avg_qp: row.avg_qp,
                encode_ms: row.encode_ms,
                // Recomputed against the budget *this* controller just decided, not taken from
                // the log — and that difference is what lets this harness see a whole class of
                // fault.
                //
                // `spend_ratio` is production over allowance. Replaying the recorded value feeds
                // back the allowance the *old* budget rule chose, so any change to that rule is
                // invisible here: the numbers go round the loop unchanged and the tool reports an
                // identical trajectory. A harness neutral to the fix and to the fault alike is
                // worse than useless, because it looks like validation.
                //
                // Recomputed, the loop closes: a budget that collapses on a still screen produces
                // a spend ratio far above 1.0 the moment content moves, which is the signature of
                // that fault and is now visible offline.
                //
                // Production is still the recorded one. The encoder cannot be replayed, so this
                // remains a replay and not a simulation: it answers "what would the controller
                // decide, given what this pipeline produced and the budget this controller would
                // have set", which is the question that has actually been getting the wrong answer.
                spend_ratio: match c.encoder_target_kbps() {
                    0 => 0.0,
                    budget => row.produced_kbps as f32 / budget as f32,
                },
                rung_fps_hint: c.current().fps as f32,
                // The recorded line does not carry the encoder's quantiser ceiling, so no floor is
                // learned in a replay. That is honest rather than convenient: the floor exists to
                // separate "out of quality and still over budget" from ordinary jitter, and
                // guessing the ceiling would recreate exactly the conflation that made the first
                // version of that measurement shed rungs on healthy links.
                qp_ceiling: None,
                // The recorded line carries `dropped_rate` as a counter rather than a ratio, and
                // only from the commit that added the brake. Zero here means the replayed ladder
                // never sees the throttled arm, which is honest for older recordings and one more
                // reason this harness cannot stand in for a session.
                drop_ratio: 0.0,
                report: report.take(),
            };
            if let Some(r) = c.tick(fb, TICK) {
                changes.push((sec, r, c.last_move_reason()));
                if r.max_h < lowest.max_h || (r.max_h == lowest.max_h && r.fps < lowest.fps) {
                    lowest = r;
                }
            }
            if c.take_bwe_reanchor().is_some() {
                if let Some(r) = c.last_reanchor() {
                    reanchors.push((sec, r));
                }
            }
            if let Some(ev) = c.take_brake_event() {
                brakes.push((sec, ev));
            }
            if let Some(ev) = c.take_drain_event() {
                drains.push((sec, tick as usize, ev));
            }
            // The replay's peer never refuses. What str0m would have done with the target — the
            // probes it would have sent or not — is not in the recording; this is only what the
            // controller would have asked for.
            if let Some(kbps) = c.take_probe_target() {
                c.probe_target_sent(kbps);
                probe_targets.push((sec, kbps, c.capacity_kbps()));
            }
        }
        let cur = c.current();
        *occupancy
            .entry(format!("{}p@{}", cur.max_h, cur.fps))
            .or_default() += 1;
        let view = c.collapse_state();
        *collapse_seconds.entry(view).or_default() += 1;
        if view != last_view {
            collapse_changes.push((sec, view, estimate_kbps, c.capacity_kbps()));
            last_view = view;
        }
        let base = c.rtt_base_ms();
        let moved = match (last_base, base) {
            (Some(a), Some(b)) => a.abs_diff(b) >= BASE_MOVE_MS,
            (None, None) => false,
            _ => true,
        };
        if moved {
            base_moves.push((sec, last_base, base));
            last_base = base;
        }
    }

    println!(
        "\n=== {label}: {} s replayed === profile {profile}",
        rows.len()
    );
    // Say what this replay is worth before saying what it found. A reader who does not know the
    // denominator was fabricated will read the trajectory as a prediction, and for two mechanisms
    // it is not one.
    if rows.iter().all(|r| r.egress_kbps.is_none()) {
        for line in [
            "no egress column in this log, so the conservation check and the budget's",
            "exploration bound are both DISABLED in this replay: the drain that stands in",
            "for egress is never below production. Changes to either mechanism cannot show",
            "up here. Record a new session to test them.",
        ] {
            println!("  !! {line}");
        }
    }
    if rows.iter().any(|r| !r.queue_measured) {
        println!(
            "  !! this log predates `queue_age_ms`, so the queue fed to the ladder is \
             reconstructed from bytes-over-estimate rather than measured."
        );
    }
    let recorded: BTreeMap<String, u32> = rows.iter().fold(BTreeMap::new(), |mut m, r| {
        *m.entry(format!("{}p@{}", r.rung_h, r.rung_fps))
            .or_default() += 1;
        m
    });
    println!("  what actually ran : {recorded:?}");
    println!("  what the ladder would do: {occupancy:?}");
    println!("  rung changes: {}", changes.len());
    for (sec, r, why) in changes.iter().take(40) {
        let row = &rows[*sec];
        println!(
            "    t={sec:>3}s {} -> {}p@{:<3} {:<12} qp={:<5} queue={:<6} est={:<5} spend={:.2} \
             enc_ms={:.1}",
            row.ts,
            r.max_h,
            r.fps,
            why,
            row.avg_qp.map_or("-".to_string(), |q| format!("{q:.1}")),
            row.queue_ms,
            row.estimate_kbps,
            row.spend_ratio,
            row.encode_ms
        );
    }
    if changes.len() > 40 {
        println!("    ... {} more", changes.len() - 40);
    }
    println!("  lowest reached: {}p@{}", lowest.max_h, lowest.fps);
    if held_secs > 0 {
        holds.push((rows.len() - held_secs as usize, held_secs));
    }
    println!(
        "  background holds (controller frozen, resumed after): {}{}",
        holds.len(),
        if holds.is_empty() {
            String::new()
        } else {
            format!(
                ", {} s held: {}",
                holds.iter().map(|&(_, s)| s).sum::<u32>(),
                holds
                    .iter()
                    .map(|&(sec, s)| format!("{} for {s} s", rows[sec].ts))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );

    println!("  re-anchors: {}", reanchors.len());
    let opt = |v: Option<u32>| v.map_or("-".to_string(), |v| v.to_string());
    for (sec, r) in &reanchors {
        println!(
            "    t={sec:>3}s {} {:<14} {} -> {} kbps ({:.2}x; capacity {}) rtt {}/{} loss {}",
            rows[*sec].ts,
            r.trigger.as_str(),
            r.estimate_kbps,
            r.kbps,
            f64::from(r.kbps) / f64::from(r.estimate_kbps.max(1)),
            r.capacity_kbps,
            opt(r.rtt_ms),
            opt(r.rtt_base_ms),
            r.loss_pct.map_or("-".to_string(), |l| format!("{l:.2}%")),
        );
    }
    // Seconds ending with the estimate under half the capacity evidence, by what the controller
    // made of it: `clean` is held (descent arms masked), anything else is why it was not.
    println!("  collapse seconds: {collapse_seconds:?}");
    for (sec, view, est, cap) in collapse_changes.iter().take(60) {
        println!(
            "    t={sec:>3}s {} collapse={view:<11} est={est:<5} capacity={cap}",
            rows[*sec].ts
        );
    }
    if collapse_changes.len() > 60 {
        println!("    ... {} more", collapse_changes.len() - 60);
    }
    let engaged = brakes
        .iter()
        .filter(|(_, e)| matches!(e, BrakeEvent::Engaged(_)))
        .count();
    println!("  brake: {engaged} episode(s), {} event(s)", brakes.len());
    for (sec, ev) in brakes.iter().take(40) {
        let (what, d) = match ev {
            BrakeEvent::Engaged(d) => ("engaged", d),
            BrakeEvent::Tightened(d) => ("tightened", d),
            BrakeEvent::Released(d) => ("released", d),
        };
        println!(
            "    t={sec:>3}s {} {what:<9} {:<11} loss={:<6} rtt={:<5} base={:<5} budget {} -> {}",
            rows[*sec].ts,
            d.cause.as_str(),
            d.loss_pct.map_or("-".to_string(), |l| format!("{l:.2}")),
            d.rtt_ms.map_or("-".to_string(), |v| v.to_string()),
            d.rtt_base_ms.map_or("-".to_string(), |v| v.to_string()),
            d.before_kbps,
            d.after_kbps
        );
    }
    if brakes.len() > 40 {
        println!("    ... {} more", brakes.len() - 40);
    }
    let entered = drains
        .iter()
        .filter(|(_, _, e)| matches!(e, DrainEvent::Entered { .. }))
        .count();
    println!(
        "  drain mode: {entered} episode(s){}",
        if viewer_on {
            " (with the viewer's reports)"
        } else {
            " (without the viewer's reports: AFKLINK_REPLAY_VIEWER=off)"
        }
    );
    for (sec, tick, ev) in drains.iter().take(60) {
        let at = format!(
            "{}+{}ms",
            rows[*sec].ts,
            *tick as u64 * TICK.as_millis() as u64
        );
        match ev {
            DrainEvent::Entered {
                rtt_ms, by_silence, ..
            } => println!(
                "    t={sec:>4}s {at:<15} entered  rtt={rtt_ms} by_silence={by_silence}"
            ),
            DrainEvent::Left {
                why,
                rtt_ms,
                held_ms,
                resume_kbps,
                ..
            } => println!(
                "    t={sec:>4}s {at:<15} left     why={why} rtt={} held_ms={held_ms} resume_kbps={resume_kbps}",
                opt(*rtt_ms)
            ),
        }
    }
    if drains.len() > 60 {
        println!("    ... {} more", drains.len() - 60);
    }
    println!(
        "  transport path changes: {}{}",
        path_changes.len(),
        if path_changes.is_empty() {
            String::new()
        } else {
            format!(
                " at {}",
                path_changes
                    .iter()
                    .map(|s| rows[*s].ts.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    println!(
        "  round-trip baseline moves (>= {BASE_MOVE_MS} ms, or set/reset): {}",
        base_moves.len()
    );
    for (sec, from, to) in base_moves.iter().take(40) {
        let row = &rows[*sec];
        println!(
            "    t={sec:>3}s {} {} -> {} (rtt {})",
            row.ts,
            opt(*from),
            opt(*to),
            opt(row.rtt_ms)
        );
    }
    if base_moves.len() > 40 {
        println!("    ... {} more", base_moves.len() - 40);
    }
    // What congestion control would have been told to probe towards: twice the capacity evidence,
    // between the floor and the ladder's ceiling. str0m's periodic ALR probe goes to twice this.
    let (lo, hi) = probe_targets
        .iter()
        .fold((u32::MAX, 0), |(lo, hi), &(_, k, _)| (lo.min(k), hi.max(k)));
    println!(
        "  probe target: {} update(s){}",
        probe_targets.len(),
        if probe_targets.is_empty() {
            String::new()
        } else {
            format!(", {lo}..{hi} kbps")
        }
    );
    for (sec, kbps, cap) in probe_targets.iter().take(30) {
        println!(
            "    t={sec:>3}s {} -> {kbps} kbps (capacity {cap})",
            rows[*sec].ts
        );
    }
    if probe_targets.len() > 30 {
        println!("    ... {} more", probe_targets.len() - 30);
    }
}

fn main() {
    let usage =
        "usage: ladder_replay [--profile <file.json> | --profile builtin | --profiles-dir <dir>] \
                 <log> [<log> ...]";
    let mut args = Vec::new();
    let mut fixed_path = None;
    let mut dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--profile" => fixed_path = it.next().map(PathBuf::from),
            "--profiles-dir" => dir = it.next().map(PathBuf::from),
            _ => args.push(a),
        }
    }
    if args.is_empty() || (fixed_path.is_some() && dir.is_some()) {
        eprintln!("{usage}");
        std::process::exit(2);
    }
    let load_or_exit = |path: &Path| {
        load_profile(path).unwrap_or_else(|e| {
            eprintln!("!! {e}");
            std::process::exit(2);
        })
    };
    let profiles = Profiles {
        fixed: fixed_path.as_deref().map(|path| {
            if path == Path::new(BUILTIN_ARG) {
                (
                    afklink_core::quality_policy::FALLBACK_LABEL.to_string(),
                    QualityPolicy::fallback(),
                )
            } else {
                load_or_exit(path)
            }
        }),
        dir,
        reference: load_or_exit(&reference_vector_path()),
    };
    // The controller's own lines, on request: see the module note. No timestamps — they would be
    // the replay's wall clock, not the recording's; the trace line per second carries that.
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .without_time()
            .with_writer(std::io::stderr)
            .init();
    }
    let mut failures = 0usize;
    for path in &args {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("{path}: {e}");
                continue;
            }
        };
        let sessions = sessions(&text);
        println!("\n######## {path}: {} session(s)", sessions.len());
        // A log with pipeline lines that yields no rows means the parser and the log have drifted
        // apart, which is exactly what happened when `queue_ms` became `queue_age_ms`: three
        // sessions replayed as "0 session(s)" and the tool exited successfully. Say so, loudly,
        // and name the first line it could not read, because the alternative is trusting a silent
        // zero.
        let pipeline_lines = text.lines().filter(|l| l.contains("pipeline")).count();
        if sessions.is_empty() && pipeline_lines > 0 {
            eprintln!(
                "!! {path}: {pipeline_lines} pipeline lines and not one parsed — the log format \
                 and this parser have drifted. First one:"
            );
            if let Some(l) = text.lines().find(|l| l.contains("pipeline")) {
                eprintln!("   {l}");
            }
            failures += 1;
        }
        for (i, s) in sessions.iter().enumerate() {
            let (profile, policy) = match profiles.for_session(s.profile.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    // The log names a profile this replay cannot have: say so and replay on the
                    // reference rather than skip the session, and exit non-zero at the end.
                    eprintln!(
                        "!! {path} session {}: {e}; replaying on the reference",
                        i + 1
                    );
                    failures += 1;
                    (
                        format!("{} (reference vector; {e})", profiles.reference.0),
                        profiles.reference.1.clone(),
                    )
                }
            };
            replay(
                &s.rows,
                &format!("{path} session {}", i + 1),
                &profile,
                &policy,
            );
        }
    }
    if failures > 0 {
        // Non-zero, so a script or a future session cannot mistake a drifted parser for a clean run.
        std::process::exit(1);
    }
}
