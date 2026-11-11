//! The viewer's repeated keyframe requests on a long round trip (`scenarios/pli-repeat-290ms.toml`),
//! with the agent's keyframe window (`afklink_core::keyframe_window`) and without it
//! (`[sender] keyframe_window = false`), each seed both ways.
//!
//! Without it a recovery costs two keyframes or more: the viewer's repeat 200 ms after its first
//! request leaves before the first keyframe can reach it across a 290 ms round trip — in a recorded
//! session 294 of 380 recoveries at two keyframes, 67 at three, 13 at four to nine. With
//! it the repeat is answered by the keyframe already on its way; what that may cost — a lost
//! keyframe asked for again a little later — is bounded too.
//!
//! Asked over seeds (`common::over_seeds`): a seed is one draw of where the bursts fall, and once
//! the two runs of a seed send different keyframes their losses differ too, so a stall is compared
//! over the seeds rather than run by run.
//!
//! Forty seconds of 1080p60, eight times: `#[ignore]`d with the other long tests, run with
//! `cargo test -p afklink-sim --release -- --ignored`.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

mod common;

use std::path::PathBuf;

use afklink_sim::metrics::Summary;
use afklink_sim::{Scenario, Simulation};

const SEEDS: [u64; 4] = [1011, 1, 2, 3];

fn run(seed: u64, window: bool) -> Summary {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("pli-repeat-290ms.toml");
    let mut s = Scenario::load(&path).unwrap_or_else(|e| panic!("{e:#}"));
    s.seed = seed;
    s.sender.keyframe_window = window;
    Simulation::new(s)
        .and_then(Simulation::run)
        .unwrap_or_else(|e| panic!("seed {seed}, keyframe window {window}: {e:#}"))
        .summary
}

/// Keyframes per recovery, the recoveries that start in the run's last two seconds left out (their
/// keyframe may fall past its end).
fn per_recovery(s: &Summary) -> Vec<usize> {
    s.recoveries
        .iter()
        .filter(|r| r.at_s < s.sim_secs - 2.0)
        .map(|r| r.keyframes)
        .collect()
}

fn share(v: &[usize], keep: impl Fn(usize) -> bool) -> f64 {
    v.iter().filter(|k| keep(**k)).count() as f64 / v.len().max(1) as f64
}

fn line(s: &Summary) -> String {
    format!(
        "recoveries {:?} keyframes {} ({:.2} MB) PLIs {} held {} stalled {:.2} s freezes>250 {} \
         lowest {}p@{}",
        per_recovery(s),
        s.keyframes,
        s.keyframe_bytes as f64 / 1e6,
        s.plis_viewer,
        s.kf_suppressed,
        s.stall_total_s,
        s.freezes[1],
        s.lowest.max_h,
        s.lowest.fps
    )
}

#[test]
#[ignore = "8 x 40 s of 1080p60: run with cargo test -p afklink-sim --release -- --ignored"]
fn on_a_long_round_trip_a_recovery_costs_one_keyframe() {
    let runs = common::over_seeds(SEEDS, |seed| (run(seed, true), run(seed, false)));
    let mut report = String::new();
    for (seed, (on, off)) in &runs {
        report.push_str(&format!(
            "\n  seed {seed:>4} window on : {}\n  seed {seed:>4} window off: {}",
            line(on),
            line(off)
        ));
    }
    eprintln!("{report}");
    let pooled = |on: bool| -> Vec<usize> {
        runs.iter()
            .flat_map(|(_, (a, b))| per_recovery(if on { a } else { b }))
            .collect()
    };
    let (k_on, k_off) = (pooled(true), pooled(false));
    let sum = |f: &dyn Fn(&Summary) -> f64, on: bool| -> f64 {
        runs.iter()
            .map(|(_, (a, b))| f(if on { a } else { b }))
            .sum()
    };

    // The path makes recoveries, and without the window they cost what the session's did.
    assert!(k_off.len() >= 15, "too few recoveries to judge:{report}");
    assert!(
        runs.iter().all(|(_, (_, off))| off.kf_suppressed == 0),
        "{report}"
    );
    assert!(
        share(&k_off, |k| k >= 2) >= 0.5,
        "without the window the repeat costs a keyframe of its own:{report}"
    );

    // With it, one keyframe a recovery — the repeat held — while a keyframe lost on its way still
    // gets another: the viewer asks again after the window.
    assert!(
        runs.iter()
            .all(|(_, (on, _))| on.recoveries.is_empty() || on.kf_suppressed > 0),
        "{report}"
    );
    assert!(
        share(&k_on, |k| k == 1) >= 0.7,
        "with the window a recovery costs one keyframe:{report}"
    );
    let median = |k: &[usize]| common::median(&k.iter().map(|&k| k as f64).collect::<Vec<_>>());
    assert!(
        median(&k_on) <= 1.0 && median(&k_off) >= 2.0,
        "the median recovery: one keyframe against two or more:{report}"
    );
    let bytes = |s: &Summary| s.keyframe_bytes as f64;
    assert!(
        sum(&bytes, true) <= 0.75 * sum(&bytes, false),
        "a quarter of the keyframe bytes saved at least:{report}"
    );

    // What it may cost: a keyframe lost on its way is asked for again only once the window has
    // passed, where without it every repeat brings one at once. Here that is at its dearest — NACK
    // off, so any packet of a keyframe lost loses it, and loss that does not grow with the bytes
    // sent, so fewer keyframes buy no fewer bursts — and measured at 44.4 s stalled over the four
    // seeds against 42.4 without the window (keyframes 30 against 75, 2.3 MB against 5.3). Bounded
    // here at a seventh more.
    let stalled = |s: &Summary| s.stall_total_s;
    assert!(
        sum(&stalled, true) <= sum(&stalled, false) * 1.15,
        "stalled no more than a seventh longer:{report}"
    );
}
