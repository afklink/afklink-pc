//! The summary: a detail block per run and one table for all of them.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::metrics::Summary;

fn opt(v: Option<f64>, prec: usize) -> String {
    v.map_or_else(|| "-".to_string(), |v| format!("{v:.prec$}"))
}

/// Everything one run measured, readable on its own.
#[must_use]
pub fn detail(s: &Summary) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "=== {}: {:.0} s simulated in {:.2} s wall ({:.0}x; encoder {:.2} s of it), connected after {:.0} ms; viewer str0m {}",
        s.name,
        s.sim_secs,
        s.wall_secs,
        s.speed(),
        s.wall_encode_secs,
        s.connect_ms,
        s.viewer_str0m
    );
    let rungs: Vec<String> = s
        .rung_time
        .iter()
        .map(|(r, t)| format!("{}p@{} {:.1}s", r.max_h, r.fps, t))
        .collect();
    let _ = writeln!(o, "  time at rung      : {}", rungs.join(", "));
    let _ = writeln!(
        o,
        "  rung changes      : {} (lowest {}p@{})",
        s.rung_changes.len(),
        s.lowest.max_h,
        s.lowest.fps
    );
    for (t, r, why) in s.rung_changes.iter().take(30) {
        let _ = writeln!(o, "      t={t:>6.1}s -> {}p@{} ({why})", r.max_h, r.fps);
    }
    if s.rung_changes.len() > 30 {
        let _ = writeln!(o, "      ... {} more", s.rung_changes.len() - 30);
    }
    let _ = writeln!(o, "  re-anchors        : {}", s.reanchors.len());
    for (t, trigger, est, kbps) in s.reanchors.iter().take(20) {
        let _ = writeln!(
            o,
            "      t={t:>6.1}s {trigger:<14} estimate {est} -> {kbps} kbps"
        );
    }
    let _ = writeln!(
        o,
        "  brake             : {} episode(s), {} event(s)",
        s.brake_engaged, s.brake_events
    );
    let _ = writeln!(o, "  collapse seconds  : {:?}", s.collapse_seconds);
    let _ = writeln!(o, "  estimate collapses: {}", s.collapses.len());
    for c in s.collapses.iter().take(20) {
        let _ = writeln!(
            o,
            "      t={:>6.1}s {} -> {} kbps (sent {} kbps in the 500 ms before; 0.85x that is {})",
            c.at.saturating_sub(std::time::Duration::from_secs_f64(s.connect_ms / 1e3))
                .as_secs_f64(),
            c.from_kbps,
            c.to_kbps,
            c.egress_before_kbps,
            c.egress_before_kbps * 85 / 100
        );
    }
    let traj: Vec<String> = s
        .estimate_trajectory
        .iter()
        .map(|(t, e)| format!("{t:.0}s:{e}"))
        .collect();
    let _ = writeln!(
        o,
        "  estimate kbps     : min/p50/max {}; every 5 s: {}",
        s.estimate
            .map_or_else(|| "-".to_string(), |[a, b, c]| format!("{a}/{b}/{c}")),
        traj.join(" ")
    );
    let _ = writeln!(
        o,
        "  freezes           : >100 ms {}, >250 ms {}, >500 ms {}; longest {:.0} ms, {:.2} s stalled in all",
        s.freezes[0], s.freezes[1], s.freezes[2], s.stall_max_ms, s.stall_total_s
    );
    let _ = writeln!(
        o,
        "  capture->receive  : p50/p95/max {} ms; first frame at {} ms",
        s.latency_ms.map_or_else(
            || "-".to_string(),
            |[a, b, c]| format!("{a:.0}/{b:.0}/{c:.0}")
        ),
        opt(s.first_frame_ms, 0)
    );
    let _ = writeln!(
        o,
        "  frames            : captured {}, encoded {} ({} keyframes), received {}, displayed {}, never arrived {}",
        s.frames_captured, s.frames_encoded, s.keyframes, s.frames_received, s.frames_displayed, s.frames_lost
    );
    let _ = writeln!(
        o,
        "  withheld          : bit bucket {}, queue gate {}, breaker discards {} (resyncs {}), frames on a broken reference {}",
        s.dropped_rate, s.skipped_queue, s.discarded, s.resyncs, s.broken_reference_frames
    );
    let _ = writeln!(
        o,
        "  quality/bytes     : mean QP {}, encoded {:.2} MB ({:.0} kbps), on the wire {:.2} MB, viewer PLIs {}, NACKs {}",
        opt(s.mean_qp, 1),
        s.encoded_bytes as f64 / 1e6,
        s.encoded_bytes as f64 * 8.0 / s.sim_secs.max(1e-9) / 1000.0,
        s.egress_bytes as f64 / 1e6,
        s.plis_viewer,
        s.nacks
    );
    // Keyframes per recovery, counted as in the recorded session's analysis
    // (`metrics::recoveries`).
    let mut per: BTreeMap<usize, usize> = BTreeMap::new();
    for r in &s.recoveries {
        *per.entry(r.keyframes).or_default() += 1;
    }
    let per = per
        .iter()
        .map(|(k, n)| format!("{k}:{n}"))
        .collect::<Vec<_>>()
        .join(" ");
    let _ = writeln!(
        o,
        "  keyframes         : {:.2} MB in {}; recoveries {} (keyframes:count {}); requests held by the window {}",
        s.keyframe_bytes as f64 / 1e6,
        s.keyframes,
        s.recoveries.len(),
        if per.is_empty() { "-" } else { per.as_str() },
        s.kf_suppressed
    );
    let l = &s.link_up;
    let mean_sojourn = if l.sojourn_samples > 0 {
        l.sojourn_total.as_secs_f64() * 1e3 / l.sojourn_samples as f64
    } else {
        0.0
    };
    let _ = writeln!(
        o,
        "  uplink            : {} pkts, dropped queue {} / loss {} / outage {}; bottleneck sojourn mean {:.1} ms, max {:.1} ms",
        l.sent_packets,
        l.dropped_queue,
        l.dropped_loss,
        l.dropped_outage,
        mean_sojourn,
        l.max_sojourn.as_secs_f64() * 1e3
    );
    let d = &s.link_down;
    let _ = writeln!(
        o,
        "  downlink          : {} pkts, dropped queue {} / loss {}",
        d.sent_packets, d.dropped_queue, d.dropped_loss
    );
    if !s.holds.is_empty() {
        let _ = writeln!(o, "  background holds  : {}", s.holds.len());
    }
    let rung = |r: Option<afklink_core::quality::Rung>| {
        r.map_or_else(|| "-".to_string(), |r| format!("{}p@{}", r.max_h, r.fps))
    };
    for h in &s.holds {
        let reanchors: Vec<String> = h
            .reanchors
            .iter()
            .map(|(t, est, kbps)| format!("{t} {est}->{kbps}"))
            .collect();
        let _ = writeln!(
            o,
            "      hidden {:.1}s, held {:.1}-{:.1}s: on the wire {} kbps, {} media frames; rung {} -> {}; \
             first frame {} ms after visible; re-anchor {}; brakes {}, moves {} ({} down) in 10 s; fed egress max {} kbps; \
             in 10 s after: estimate min {} kbps (at resume {}, evidence {}), queue max {} ms, {} frames \
             withheld by the queue guard, longest stall {:.0} ms; budget {} kbps at the hide, {} min / {} \
             mean from 1 s to 10 s after; brakes in the grace {}, brake at resume {}; held {:.1} s after \
             the hide, {} kB on the wire while hidden",
            h.hidden_s,
            h.held_s,
            h.visible_s,
            h.egress_held_kbps,
            h.media_frames_held,
            rung(h.rung_before),
            rung(h.rung_after),
            opt(h.first_frame_ms, 0),
            if reanchors.is_empty() {
                "-".to_string()
            } else {
                reanchors.join(", ")
            },
            h.brakes_after,
            h.moves_after,
            h.downs_after,
            h.max_feedback_egress_after_kbps,
            h.estimate_min_after_kbps
                .map_or_else(|| "-".to_string(), |e| e.to_string()),
            h.estimate_at_resume,
            h.capacity_at_resume,
            h.queue_max_after_ms,
            h.skipped_queue_after,
            h.stall_max_after_ms,
            h.budget_at_hide_kbps,
            h.budget_min_after_kbps
                .map_or_else(|| "-".to_string(), |b| b.to_string()),
            h.budget_mean_after_kbps,
            h.brakes_in_grace,
            h.brake_at_resume,
            h.held_s - h.hidden_s,
            h.egress_hidden_bytes / 1_000
        );
    }
    o
}

/// One row per run.
#[must_use]
pub fn table(runs: &[Summary]) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{:<22} {:>6} {:>6} {:>5} | {:>6} {:>4} {:>9} | {:>4} {:>5} | {:>11} | {:>14} | {:>5} {:>7} | {:>16} {:>4}",
        "scenario",
        "sim_s",
        "wall_s",
        "x",
        "top%",
        "chg",
        "lowest",
        "rea",
        "brake",
        "frz>100/250/500",
        "lat p50/95/max",
        "qp",
        "MB",
        "est min/p50/max",
        "coll"
    );
    for s in runs {
        // The share at the rung the run opened on: the top of its own ladder (1080p60 on the
        // reference, 720p30 on the agent's compiled fallback), or of the pinned ladder (1080p30 on
        // a 1080 pin, on either).
        let top = s
            .rung_time
            .iter()
            .find(|(r, _)| *r == s.ladder_top)
            .map_or(0.0, |(_, t)| *t);
        let _ = writeln!(
            o,
            "{:<22} {:>6.0} {:>6.2} {:>5.0} | {:>5.0}% {:>4} {:>9} | {:>4} {:>5} | {:>11} | {:>14} | {:>5} {:>7.2} | {:>16} {:>4}",
            truncate(&s.name, 22),
            s.sim_secs,
            s.wall_secs,
            s.speed(),
            100.0 * top / s.sim_secs.max(1e-9),
            s.rung_changes.len(),
            format!("{}p@{}", s.lowest.max_h, s.lowest.fps),
            s.reanchors.len(),
            format!("{}/{}", s.brake_engaged, s.brake_events),
            format!("{}/{}/{}", s.freezes[0], s.freezes[1], s.freezes[2]),
            s.latency_ms
                .map_or_else(|| "-".to_string(), |[a, b, c]| format!("{a:.0}/{b:.0}/{c:.0}")),
            opt(s.mean_qp, 1),
            s.encoded_bytes as f64 / 1e6,
            s.estimate
                .map_or_else(|| "-".to_string(), |[a, b, c]| format!("{a}/{b}/{c}")),
            s.collapses.len(),
        );
    }
    o
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars()
            .take(n.saturating_sub(1))
            .chain(std::iter::once('~'))
            .collect()
    }
}
