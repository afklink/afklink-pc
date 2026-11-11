//! The processor as the limit: a machine whose encoder needs 13.3 ms a frame whatever the cadence,
//! on a link with room for everything — a recorded handheld at its heaviest (ten seconds measured
//! 13.2-15.6 ms a frame at 1080p@30), held there. Past the 12.5 ms line of 60 fps
//! (`ENCODE_BUDGET_SHARE` in `afklink_core::quality`), inside the 25 ms of 30.
//!
//! The simulator models encode time as a fixed cost plus a cost per megapixel of the encoded frame
//! (`afklink_sim::encode_loop::EncodeCost`) and nothing else: no content, no cadence, no thermal
//! drift. That is the shape this asks about — a frame costs the same at 30 fps as at 60 — and the
//! one the recording's 1080p@30 seconds showed. Before the climb gate (`ENCODE_CLIMB_SHARE` in
//! `afklink_core::quality`) the ladder climbed back into 1080p@60 every time the dwell allowed and
//! was shed again two seconds after the settle: 60 -> 30 -> 60 -> 30 for the whole run.
//!
//! 320x180 rather than the handheld's 1920x1080, so a debug build runs it in seconds: every rung
//! then encodes the source's own 320x180, and the cost per megapixel is set for 13.3 ms at that
//! size. The gate scales by pixels, which are equal here, so the question is the cadence step's
//! alone.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

use std::path::Path;

use afklink_core::quality::Rung;
use afklink_sim::{Scenario, Simulation};

/// 1.0 ms + 213.5 ms/Mpx x 0.0576 Mpx = 13.3 ms a frame, keyframes 1.8x. A smooth scroll redrawn on
/// every refresh, so every tick has frames to time; 20 Mbps and 40 ms, so the link never says no.
const SCENARIO: &str = r#"
duration_s = 30
seed = 1

[content]
kind = "desktop"
width = 320
height = 180
refresh_hz = 60

[[content.phases]]
kind = "scroll"
secs = 30.0
px_per_frame = 2

[link]
rtt_ms = 40

[link.up]
kbps = 20000
queue_ms = 300

[link.down]
kbps = 20000

[encoder]
threads = 1
base_ms = 1.0
per_mpx_ms = 213.5
"#;

const SIXTY: Rung = Rung {
    max_h: 1080,
    fps: 60,
};
const THIRTY: Rung = Rung {
    max_h: 1080,
    fps: 30,
};

#[test]
fn an_encoder_too_slow_for_60_fps_is_not_climbed_back_into() {
    let s = Scenario::parse(SCENARIO, Path::new("."), "cpu-bound-13ms").unwrap();
    let out = Simulation::new(s).unwrap().run().unwrap();
    let moves: Vec<(f64, u32, u32, &str)> = out
        .summary
        .rung_changes
        .iter()
        .map(|(t, r, why)| (*t, r.max_h, r.fps, *why))
        .collect();
    let at = |rung: Rung| {
        out.summary
            .rung_time
            .iter()
            .find(|(r, _)| *r == rung)
            .map_or(0.0, |(_, t)| t / out.summary.sim_secs)
    };
    eprintln!(
        "cpu-bound-13ms: moves {moves:?}, 1080p@60 {:.2} and 1080p@30 {:.2} of the run",
        at(SIXTY),
        at(THIRTY)
    );
    // The processor is the limit and says so: one cadence step, early.
    assert!(
        moves
            .first()
            .is_some_and(|&(t, h, fps, why)| t < 10.0 && h == 1080 && fps == 30 && why == "down"),
        "13.3 ms a frame at 60 fps must shed the cadence: {moves:?}"
    );
    // And then holds: no climb back into the rung it was shed for, no cycle.
    assert_eq!(
        moves.len(),
        1,
        "climbed back into 1080p@60 on an encoder that still needs 13.3 ms a frame there: {moves:?}"
    );
    assert!(
        at(THIRTY) > 0.75 && at(SIXTY) < 0.25,
        "1080p@30 {:.2}, 1080p@60 {:.2} of the run: {moves:?}",
        at(THIRTY),
        at(SIXTY)
    );
}
