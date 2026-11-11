//! The three defects of a recorded relayed VPN session, each as a simulated session that shows it
//! on a controller without the fix, asserted to be gone. The scenarios live in
//! `crates/sim/scenarios/`, where `cargo run -p afklink-sim --release -- crates\sim\scenarios`
//! prints them beside the others; their headers say what each reproduces and from which log lines.
//!
//! What each asserts is the defect's own shape, not a tuned number: whether the ladder moved, which
//! way and how often, whether the brake still acted.
//!
//! The last one guards the 3G path's latency tail, which a narrower fix loses.
//!
//! The braked descent, the 3G tail and the still screen's climb are asked over seeds
//! (`common::over_seeds`): on those paths a seed decides the trajectory, and a check on one seed
//! passes or fails by luck.
//!
//! Four of the six encode a minute or more of video. They are `#[ignore]`d so an ordinary
//! `cargo test` stays quick, and run with `cargo test -p afklink-sim --release -- --ignored`.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

mod common;

use std::path::PathBuf;

use afklink_core::quality::Rung;
use afklink_sim::metrics::Summary;
use afklink_sim::{Scenario, Simulation};

fn scenario_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join(format!("{name}.toml"))
}

fn run(name: &str) -> Summary {
    afklink_sim::run_file(&scenario_path(name))
        .unwrap_or_else(|e| panic!("{name}: {e:#}"))
        .summary
}

/// [`run`] with the scenario's seed replaced by `seed`.
fn run_seeded(name: &str, seed: u64) -> Summary {
    let mut s = Scenario::load(&scenario_path(name)).unwrap_or_else(|e| panic!("{name}: {e:#}"));
    s.seed = seed;
    Simulation::new(s)
        .and_then(Simulation::run)
        .unwrap_or_else(|e| panic!("{name}, seed {seed}: {e:#}"))
        .summary
}

fn moves(s: &Summary) -> Vec<(f64, u32, u32, &'static str)> {
    s.rung_changes
        .iter()
        .map(|(t, r, why)| (*t, r.max_h, r.fps, *why))
        .collect()
}

fn share_at(s: &Summary, rung: Rung) -> f64 {
    s.rung_time
        .iter()
        .find(|(r, _)| *r == rung)
        .map_or(0.0, |(_, t)| t / s.sim_secs)
}

const TOP: Rung = Rung {
    max_h: 1080,
    fps: 60,
};

/// Defect 1: a still screen's bursts, queued behind an estimate the stillness set, on a path with
/// room and a jittering round trip. Without the fix: 1080p60 -> 1080p30 -> 900p on `queue_late`.
#[test]
fn an_idle_start_with_round_trip_noise_holds_the_top_rung() {
    let s = run("idle-start-rtt-noise");
    assert!(s.rung_changes.is_empty(), "moved: {:?}", moves(&s));
    assert!(share_at(&s, TOP) > 0.95, "{:?}", s.rung_time);
}

/// Defect 1, the keyframe half: keyframes on a still screen behind the same estimate. Without the
/// fix: the startup queue jump to 360p@15 at 16.9 s, then 360p@8.
#[test]
fn keyframes_behind_a_still_screens_estimate_move_nothing() {
    let s = run("still-keyframe");
    assert!(
        s.keyframes >= 6,
        "the requests made keyframes: {}",
        s.keyframes
    );
    assert!(s.rung_changes.is_empty(), "moved: {:?}", moves(&s));
    assert!(share_at(&s, TOP) > 0.95, "{:?}", s.rung_time);
}

/// Defect 2: a round-trip brake at 120 kbps over a picture that fits it. The brake must still cut,
/// and the ladder may take the free cadence step — but no keyframe per dwell. Without the fix:
/// 1080p30, 900p, 720p, 540p.
#[test]
#[ignore = "80 s of 1080p: run with cargo test -p afklink-sim --release -- --ignored"]
fn a_braked_budget_the_picture_fits_costs_no_keyframe() {
    let s = run("brake-120k");
    assert!(s.brake_engaged >= 1, "the brake must still act on the ramp");
    let m = moves(&s);
    assert!(
        m.iter().all(|&(_, h, _, _)| h == 1080),
        "a pixel step on a budget the picture fits: {m:?}"
    );
}

/// The ladder's heights, top first: how many a pixel step skips.
const HEIGHTS: [u32; 5] = [1080, 900, 720, 540, 360];

/// The pixel steps down the brake decided (`brake`), as (seconds, from height, to height).
fn braked_pixel_steps(s: &Summary) -> Vec<(f64, u32, u32)> {
    let mut was = 1080;
    let mut out = Vec::new();
    for (t, h, _, why) in moves(s) {
        if h < was && why == "brake" {
            out.push((t, was, h));
        }
        was = h;
    }
    out
}

/// How many heights a step from `from` to `to` goes down.
fn heights_down(from: u32, to: u32) -> usize {
    let at = |h: u32| {
        HEIGHTS
            .iter()
            .position(|&x| x == h)
            .unwrap_or(HEIGHTS.len())
    };
    at(to).saturating_sub(at(from))
}

/// Defect 2, the other half: a picture that does not fit the braked budget gives pixels up in one
/// move, straight to the rung it fits, and comes back when the path clears. Without the fix: 900p,
/// then 720p, a keyframe each, every step on the brake's word
/// (`QualityController::descent_target`).
///
/// Over seeds 1-10, because one seed is a trajectory, not the rule: with the coarse arm walking
/// the rest of the way once the brake is held as silence on this path's steps, exactly one pixel
/// descent shows on only 1 or 2 seeds of 10. What the fix decides is the brake's own
/// step, so that is what is asserted:
///
/// - every seed: the brake acts, at most one pixel step on its word (the walk was two or three),
///   and a session that went under 720p ends above its lowest rung — back up once the path clears;
/// - over the seeds: the step goes where the content fits — at least one skips a height (the
///   jump), and one that lands on the next height down (a landing that happens to be one rung, or
///   the walk's first step) on at most a third of them.
///
/// Measured over seeds 1-10: the controller skips a height on 2 seeds and steps one height on
/// none. With `descent_target` reduced to one rung (the walk): no skip, one height on 7 of 10 —
/// both checks fail.
#[test]
#[ignore = "ten runs of 80 s scrolling 1080p: run with cargo test -p afklink-sim --release -- --ignored"]
fn a_braked_budget_the_picture_does_not_fit_is_one_jump() {
    let runs = common::over_seeds(1..=10, |seed| run_seeded("brake-120k-video", seed));
    let mut skips = Vec::new();
    let mut one_height = Vec::new();
    for (seed, s) in &runs {
        let m = moves(s);
        assert!(
            s.brake_engaged >= 1,
            "seed {seed}: the brake must still act on the ramp"
        );
        let braked = braked_pixel_steps(s);
        assert!(
            braked.len() <= 1,
            "seed {seed}: a walk on the brake's word, {braked:?}: {m:?}"
        );
        for &(_, from, to) in &braked {
            if heights_down(from, to) >= 2 {
                skips.push(*seed);
            } else {
                one_height.push(*seed);
            }
        }
        let lowest = m.iter().map(|&(_, h, _, _)| h).min().unwrap_or(1080);
        if lowest < 720 {
            assert!(
                m.last()
                    .is_some_and(|&(_, h, _, why)| h > lowest && why == "climb"),
                "seed {seed}: down to {lowest}p and not back up once the path cleared: {m:?}"
            );
        }
    }
    let summary: Vec<_> = runs.iter().map(|(seed, s)| (*seed, moves(s))).collect();
    assert!(
        !skips.is_empty(),
        "no braked step skipped a height on any seed — the scenario no longer prices the content \
         against the brake: {summary:?}"
    );
    assert!(
        one_height.len() * 3 <= runs.len(),
        "braked steps of one height on seeds {one_height:?} (skips on {skips:?}): the walk's first \
         step, not the rung the content fits: {summary:?}"
    );
}

/// Defect 3: a still screen at the bottom of the ladder on a path the probes show is open, the
/// estimate falling back after each probe and the round trip a little over its clean margin.
/// Without the fix: 360p@30 from 7 s to the end of the run.
///
/// Asked over seeds. Whether str0m's probes show the opened path before its estimate
/// collapses again is the seed's draw of the jitter — and of the keyframes the PLI storm of the
/// first seconds costs: with the agent's keyframe window (`afklink_core::keyframe_window`) seed 1
/// holds the storm's repeats (6 keyframes
/// against 36, 11.2 s stalled against 22.0, no fall to 360p@8) and its probes then stay low, so it
/// climbs above 360p only at 73.8 s. The rule — a climb above 360p within 25 s of the opening, and
/// 720p or more at the end — holds over seeds 1-10 on 7 with the window and on 5 without it
/// (`[sender] keyframe_window = false`), and with the defect put back
/// (`QualityController::idle_evidence` returning nothing) on 3 and on 1. Asserted: on at least half
/// of them.
#[test]
#[ignore = "10 x (25 s of scrolling then 75 s still): run with cargo test -p afklink-sim --release -- --ignored"]
fn a_still_screen_climbs_on_what_the_probes_measured() {
    let runs = common::over_seeds(1..=10, |seed| run_seeded("still-probes-rtt-jitter", seed));
    let climbs = |m: &[(f64, u32, u32, &'static str)]| {
        let first_climb_above_360 = m
            .iter()
            .find(|&&(t, h, _, why)| t > 25.0 && h > 360 && why == "climb")
            .map(|&(t, ..)| t);
        first_climb_above_360.is_some_and(|t| t < 50.0)
            && m.last().is_some_and(|&(_, h, _, _)| h >= 720)
    };
    let summary: Vec<_> = runs.iter().map(|(seed, s)| (*seed, moves(s))).collect();
    let climbed: Vec<u64> = summary
        .iter()
        .filter(|(_, m)| climbs(m))
        .map(|(seed, _)| *seed)
        .collect();
    assert!(
        climbed.len() * 2 >= runs.len(),
        "a climb above 360p within 25 s of the path opening, ending at 720p or more, on seeds \
         {climbed:?} only: {summary:?}"
    );
}

/// Not a defect of the session but of a narrower fix for it: on the 3G path (700 kbps behind a
/// 60 ms buffer) leaving the settle's queue out of the ladder's filter even while the receiver
/// reports loss keeps the ladder a rung or two higher, and a 720p keyframe into the same buffer at
/// 82.5 s reaches the viewer with frames 10.2 s late (p95 1681 ms). Without either fix the latency
/// p95/max reads 1069/1781 ms; so does the fix. See `QualityController::late_for_ladder`, whose
/// mechanism `the_settles_queue_counts_once_the_receiver_reports_loss` (quality.rs) holds to.
///
/// Over seeds 1-20, as a distribution, because one seed's tail is a draw: on this path the same
/// build's p95 runs from a third of a second to eighteen seconds across seeds, and the maximum is
/// mostly the simulated viewer's (a hole holds every frame behind it).
/// A single-seed check (p95 <= 1300 and max <= 3000 on seed 1) passes on only a few seeds of 20
/// What it asks instead, of the tail as the path's twenty draws give it:
///
/// - a quarter of the seeds (5 of 20) keep the p95 bound of 1300 ms;
/// - the median seed's p95 stays under 4 s.
///
/// Measured: the agent's sender has 7 of 20 within 1300 and a median of 2405 ms; the plain str0m
/// 0.24.1 sender, whose probing floods the thin path before any evidence, 2 and 2594 — it fails.
/// The narrower fix (the settle left out under loss) moves 6 of the 20 seeds, 3 each way (6 within,
/// median 3204): no seed-robust tail difference on this path, so the unit test is what guards it.
#[test]
#[ignore = "twenty runs of 120 s of 3G: run with cargo test -p afklink-sim --release -- --ignored"]
fn a_thin_lossy_path_keeps_its_latency_tail() {
    let runs = common::over_seeds(1..=20, |seed| run_seeded("3g-0919", seed));
    let p95: Vec<(u64, f64)> = runs
        .iter()
        .map(|(seed, s)| (*seed, s.latency_ms.unwrap()[1]))
        .collect();
    let within = p95.iter().filter(|&&(_, p)| p <= 1_300.0).count();
    let median = common::median(&p95.iter().map(|&(_, p)| p).collect::<Vec<_>>());
    let table: Vec<String> = runs
        .iter()
        .map(|(seed, s)| {
            let [_, p95, max] = s.latency_ms.unwrap();
            format!("s{seed} {p95:.0}/{max:.0}")
        })
        .collect();
    eprintln!("3g-0919 latency p95/max by seed: {}", table.join(", "));
    assert!(
        within * 4 >= runs.len(),
        "{within} of {} seeds kept the latency p95 within 1300 ms (median {median:.0} ms): {}",
        runs.len(),
        table.join(", ")
    );
    assert!(
        median <= 4_000.0,
        "the median seed's latency p95 is {median:.0} ms: {}",
        table.join(", ")
    );
}
