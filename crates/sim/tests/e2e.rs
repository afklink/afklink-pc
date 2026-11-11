//! One short session end to end: two str0m peers, a lossy link, the real encoder and controller.
//! The assertion that matters is the first: a scenario and a seed are a session, byte for byte.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

use std::path::Path;

use afklink_sim::{Scenario, Simulation};

/// Small and short so a debug build runs it in seconds: 640x360, a few seconds of typing and a
/// scroll, a 2 Mbps / 40 ms path with a little random loss so the seed has something to decide.
const SCENARIO: &str = r#"
duration_s = 3
seed = 11

[content]
kind = "desktop"
width = 640
height = 360
refresh_hz = 30

[[content.phases]]
kind = "typing"
secs = 1.0
cps = 8.0

[[content.phases]]
kind = "scroll"
secs = 0.5
px_per_frame = 4

[link]
rtt_ms = 40

[link.up]
kbps = 2000
queue_ms = 200
loss = 0.01

[link.down]
kbps = 2000

[encoder]
threads = 1
"#;

fn run() -> afklink_sim::RunOutput {
    let s = Scenario::parse(SCENARIO, Path::new("."), "e2e").unwrap();
    Simulation::new(s).unwrap().run().unwrap()
}

#[test]
fn a_scenario_and_a_seed_are_a_session() {
    let a = run();
    let b = run();
    if let Some((x, y)) = a.log.iter().zip(&b.log).find(|(x, y)| x != y) {
        panic!("two runs of one scenario and seed diverged:\n  {x}\n  {y}");
    }
    assert_eq!(a.log.len(), b.log.len());
    assert_eq!(a.summary.frames_encoded, b.summary.frames_encoded);
    assert_eq!(a.summary.link_up, b.summary.link_up);

    // And it is a session, not an empty loop: it connected, frames crossed, the controller ran.
    assert!(
        a.summary.connect_ms > 0.0 && a.summary.connect_ms < 2_000.0,
        "{}",
        a.summary.connect_ms
    );
    assert!(
        a.summary.frames_displayed > 10,
        "{:?}",
        a.summary.frames_displayed
    );
    assert!(a.summary.latency_ms.is_some());
    assert!(a.summary.link_up.sent_packets > 50);

    // The per-second line is the agent's, readable by `ladder_replay`: the session marker, and the
    // fields it parses, with `HH:MM:SS` where it slices the timestamp.
    assert!(a.log.iter().any(|l| l.contains("session_request ")));
    let pipeline: Vec<&String> = a.log.iter().filter(|l| l.contains(" pipeline ")).collect();
    assert!(pipeline.len() >= 2, "{}", pipeline.len());
    for key in [
        "rung=",
        "avg_qp=",
        "queue_age_ms=",
        "encode_ms=",
        "estimate_kbps=",
        "spend_ratio=",
        "kbps=",
        "egress_kbps=",
        "idr_bytes=",
        "rtt_ms=",
        "loss_pct=",
        "nacks=",
        "brake=",
    ] {
        assert!(
            pipeline[0].contains(key),
            "{key} missing from {}",
            pipeline[0]
        );
    }
    assert_eq!(pipeline[0].get(13..14), Some(":"));
}
