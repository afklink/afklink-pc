//! The agent's compiled fallback (`QualityPolicy::safe`, what a session runs on when the server sent
//! no profile) on the path that showed its estimate spiralling down: vpn-wifi-1011, a 290 ms round
//! trip whose delay spikes every few seconds and almost never loses a packet.
//!
//! str0m cuts to 0.85x of what was acknowledged on each delay overuse and grows back slowly. With the
//! encoder spending 80% of the estimate (the first safe profile) and the pacer draining at 1.1x of
//! it, every spike was a cut the next ones never let it regain: on the first 60 s the estimate's
//! median was 866 kbps and the rung 720p30 for 61% of it, 540p from 41 s, 360p30 later (the whole
//! run: 13% at 720p30, median 435), with no loss at all. At 90%, as the reference spends, the same 60
//! s hold 720p30 throughout at a median of ~2950 (the reference itself, at 1080p60: ~5900).
//!
//! The first 60 s of the scenario only: about 12 s in a release build. A debug build takes minutes
//! over the 1080p source, so it is `#[ignore]`d with the other video tests of this crate and run
//! with `cargo test -p afklink-sim --release -- --ignored`.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

use std::path::PathBuf;
use std::time::Duration;

use afklink_core::quality::{QualityPolicy, Rung};
use afklink_sim::{Scenario, Simulation};

#[test]
#[ignore = "60 s of 1080p content: run with cargo test -p afklink-sim --release -- --ignored"]
fn the_safe_profile_keeps_its_estimate_on_a_spiky_vpn_path() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scenarios")
        .join("vpn-wifi-1011.toml");
    let mut s = Scenario::load(&path).unwrap_or_else(|e| panic!("{e:#}"));
    s.duration = Duration::from_secs(60);
    let out = Simulation::with_policy(s, QualityPolicy::fallback())
        .and_then(Simulation::run)
        .unwrap_or_else(|e| panic!("vpn-wifi-1011 on the safe profile: {e:#}"))
        .summary;
    let top = Rung {
        max_h: 720,
        fps: 30,
    };
    let at_top = out
        .rung_time
        .iter()
        .find(|(r, _)| *r == top)
        .map_or(0.0, |(_, t)| t / out.sim_secs);
    let [lo, p50, hi] = out.estimate.expect("estimates were recorded");
    eprintln!(
        "vpn-wifi-1011, 60 s, safe: 720p30 {at_top:.2} of the run, estimate min/p50/max \
         {lo}/{p50}/{hi}, moves {:?}, brakes {}",
        out.rung_changes, out.brake_engaged
    );
    assert!(
        p50 >= 2_000,
        "the estimate spiralled: median {p50} kbps (the spiral's was 866, the reference's ~5900)"
    );
    assert!(
        at_top >= 0.9,
        "720p30 for {at_top:.2} of the run: {:?}",
        out.rung_changes
    );
}
