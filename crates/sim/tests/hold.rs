//! The background hold end to end (`afklink_core::bg_hold`): the viewer's page hidden, the agent's own hold cell and control-side freeze, the
//! capture stopped and started again — over two real str0m peers and the real controller.
//!
//! What is asserted is the hold's rule, not a tuned number: nothing but str0m's padding on the wire
//! while held, no media frame, the same rung after, no brake, no re-anchor down, the first frame of
//! the screen as it is shortly after the page is back, and the controller never handed the hold's
//! padding in one window. And what the resume's restart of str0m is for (a bench run shows the
//! collapse without it): on a clean path no estimate collapse after the resume, nothing withheld by
//! the queue guard, no stall past the first frame. The ten-minute runs encode a minute of video
//! around the hold and are `#[ignore]`d like the defect scenarios:
//! `cargo test -p afklink-sim --release -- --ignored`.
#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

mod common;

use std::path::Path;

use afklink_sim::metrics::{HoldSummary, Summary};
use afklink_sim::{Scenario, Simulation};

/// A clean 4 Mbps path, 40 ms round trip.
const CLEAN: &str = r#"
[link]
rtt_ms = 40

[link.up]
kbps = 4000
queue_ms = 200

[link.down]
kbps = 4000
"#;

/// A path with room whose round trip jitters by up to 120 ms each way, as a recorded relayed VPN
/// path did: str0m reads the jitter as overuse while only padding is acknowledged,
/// so a hold of minutes walks its estimate down to the padding rate.
const JITTERY: &str = r#"
[link]
rtt_ms = 200

[link.up]
kbps = 4000
queue_ms = 600
jitter_ms = 120

[link.down]
kbps = 5000
queue_ms = 300
jitter_ms = 120
"#;

/// A recorded iPhone path: a Cloudflare relay, 150 ms round trip, room
/// for the video and more.
const RELAYED: &str = r#"
[link]
rtt_ms = 150

[link.up]
kbps = 6000
queue_ms = 300

[link.down]
kbps = 6000
"#;

/// A scenario: `content` (TOML of a `[content]` table) over `link`, `secs` long, the page hidden
/// over `hidden`.
fn scenario(content: &str, link: &str, secs: u32, hidden: Option<(u32, u32)>) -> String {
    asleep_scenario(content, link, secs, hidden, "")
}

/// [`scenario`], with `viewer` lines added to its `[viewer]` table: how the page sleeps while
/// hidden (`afklink_sim::scenario::AsleepViewer`).
fn asleep_scenario(
    content: &str,
    link: &str,
    secs: u32,
    hidden: Option<(u32, u32)>,
    viewer: &str,
) -> String {
    let hidden = hidden.map_or_else(String::new, |(a, b)| format!("hidden = [[{a}, {b}]]\n"));
    format!(
        r#"
duration_s = {secs}
seed = 7

{content}

{link}

[viewer]
{hidden}{viewer}
[encoder]
threads = 1
"#
    )
}

/// A desktop someone is working on: typing, and a short scroll, over and over.
const MOVING: &str = r#"
[content]
kind = "desktop"
width = 640
height = 360
refresh_hz = 30

[[content.phases]]
kind = "typing"
secs = 2.0
cps = 8.0

[[content.phases]]
kind = "scroll"
secs = 1.0
px_per_frame = 4
"#;

/// A desktop nobody touches: one frame at the start, nothing after.
const STILL: &str = r#"
[content]
kind = "static"
width = 640
height = 360
"#;

/// A video playing on and on in a tenth of the screen: the link loaded, the picture affordable at
/// the top rung.
const PLAYING: &str = r#"
[content]
kind = "desktop"
width = 640
height = 360
refresh_hz = 30

[[content.phases]]
kind = "noise"
secs = 600.0
fraction = 0.1
fps = 30
"#;

/// A video pane playing for three seconds in five: what keeps a link loaded.
const VIDEO: &str = r#"
[content]
kind = "desktop"
width = 640
height = 360
refresh_hz = 30

[[content.phases]]
kind = "noise"
secs = 3.0
fraction = 0.4
fps = 30

[[content.phases]]
kind = "typing"
secs = 2.0
cps = 8.0
"#;

fn run(toml: &str) -> Summary {
    let s = Scenario::parse(toml, Path::new("."), "hold").unwrap();
    Simulation::new(s).unwrap().run().unwrap().summary
}

/// [`run`] with the scenario's seed replaced by `seed`.
fn run_seeded(toml: &str, seed: u64) -> Summary {
    let mut s = Scenario::parse(toml, Path::new("."), "hold").unwrap();
    s.seed = seed;
    Simulation::new(s)
        .and_then(Simulation::run)
        .unwrap_or_else(|e| panic!("seed {seed}: {e:#}"))
        .summary
}

/// Moves down the ladder in `[from_s, to_s]`, seconds into the session, each against the rung
/// before it — the opening rung before the first move. [`HoldSummary::downs_after`]'s count, for
/// any window of any run.
fn downs_between(s: &Summary, from_s: f64, to_s: f64) -> usize {
    // The runs are on the reference profile ([`Simulation::new`]).
    let policy = afklink_sim::reference_policy().expect("the reference profile");
    let ladder = &policy.ladder;
    let index = |r| ladder.iter().position(|l| *l == r).unwrap_or(ladder.len());
    let mut was = policy.start_rung();
    let mut downs = 0;
    for &(t, r, _) in &s.rung_changes {
        if t > to_s {
            break;
        }
        if t >= from_s && index(r) > index(was) {
            downs += 1;
        }
        was = r;
    }
    downs
}

/// When a hold begins after the page is hidden, in seconds: the grace and a tick, for a page that
/// stays awake (and reports) while hidden.
const AFTER_THE_GRACE: std::ops::RangeInclusive<f64> = 10.0..=10.5;

/// The same for a page that sleeps while hidden: its receiver's silence past
/// `afklink_core::bg_hold::BG_HOLD_ASLEEP_AFTER`, counted from its last report before the hide —
/// two seconds and up to a report interval and a tick more.
const ASLEEP: std::ops::RangeInclusive<f64> = 2.0..=3.5;

/// What every hold must come to, whatever the content and the path: begun `began` seconds after the
/// page was hidden, `first_within_ms` from the page visible again to the first frame of the screen
/// as it is. And the same rung for ten seconds after it, which [`assert_hold_keeps_the_rung`] adds
/// where the path itself lets the ladder hold one.
fn assert_hold(
    h: &HoldSummary,
    what: &str,
    began: std::ops::RangeInclusive<f64>,
    first_within_ms: f64,
) {
    assert_eq!(
        h.media_frames_held, 0,
        "{what}: media sent while held: {h:?}"
    );
    // str0m's padding target is 50 kbps of padding; on the wire, in packets of a few dozen bytes
    // with their RTP and SRTP headers, it is ~102 kbps — exactly what a still screen with no hold
    // sends in this simulator (measured beside it). Nothing on top of that.
    assert!(
        h.egress_held_kbps <= 120,
        "{what}: {} kbps on the wire while held; str0m's padding alone is ~102: {h:?}",
        h.egress_held_kbps
    );
    assert_eq!(h.brakes_after, 0, "{what}: a brake after the hold: {h:?}");
    // Every re-anchor up — but the hold's own restart, which may restart an estimate the hold left
    // standing at that same value: it is for str0m's acknowledged-rate history, not the estimate.
    // Decided on the resume tick, it is never down and never past the larger of the evidence from
    // before the hold and the estimate.
    for &(trigger, est, kbps) in &h.reanchors {
        if trigger == "hold-resume" {
            assert_eq!(est, h.estimate_at_resume, "{what}: {h:?}");
            assert!(
                kbps >= est && kbps <= h.capacity_at_resume.max(est),
                "{what}: the hold's restart at {kbps} against the estimate {est} and the evidence \
                 {}: {h:?}",
                h.capacity_at_resume
            );
        } else {
            assert!(
                kbps > est,
                "{what}: a re-anchor down ({trigger} {est} -> {kbps})"
            );
        }
    }
    let first = h
        .first_frame_ms
        .unwrap_or_else(|| panic!("{what}: no frame after the hold: {h:?}"));
    assert!(
        first <= first_within_ms,
        "{what}: the first frame came {first:.0} ms after the page was back"
    );
    assert!(
        h.max_feedback_egress_after_kbps < 20_000,
        "{what}: the controller was fed {} kbps in one tick after the hold — the hold's padding at \
         once",
        h.max_feedback_egress_after_kbps
    );
    // The grace, or the page asleep: when the hold began after the page was hidden.
    let grace = h.held_s - h.hidden_s;
    assert!(
        began.contains(&grace),
        "{what}: the hold began {grace:.1} s after the page was hidden, not in {began:?}"
    );
}

/// The same rung before the hold and for ten seconds after it, with no move at all in between.
fn assert_hold_keeps_the_rung(h: &HoldSummary, what: &str) {
    assert_eq!(h.rung_after, h.rung_before, "{what}: the rung moved: {h:?}");
    assert_eq!(h.moves_after, 0, "{what}: {h:?}");
}

/// What the resume's restart of str0m is for, on a clean path with the link loaded before the
/// hold: one restart, decided on the resume tick; for ten seconds after it the estimate never
/// under half the evidence from before the hold, at most `withheld` frames held back by the queue
/// guard (the resume keyframe's own burst, where the content makes one), and no stall the viewer
/// sees after the first resumed frame.
///
/// Without the restart the hold leaves str0m's acknowledged rate at the padding's, and the first
/// overuse cuts the estimate to 0.85 times that: on the bench 13305 -> 66 kbps 2.8 s after
/// the resume and a second frozen; here, [`a_playing_video_resumes_without_an_estimate_collapse`]
/// before it, 3205 -> 207 kbps, a 1363 ms queue, 39 frames withheld and a 921 ms stall.
fn assert_no_collapse_after(h: &HoldSummary, what: &str, withheld: u64) {
    let restarts = h
        .reanchors
        .iter()
        .filter(|(t, ..)| *t == "hold-resume")
        .count();
    assert_eq!(restarts, 1, "{what}: one restart per hold: {h:?}");
    let floor = h.capacity_at_resume / 2;
    let least = h
        .estimate_min_after_kbps
        .unwrap_or_else(|| panic!("{what}: no tick after the resume: {h:?}"));
    assert!(
        least >= floor,
        "{what}: the estimate fell to {least} kbps after the resume, under half the {} the path \
         carried before the hold: {h:?}",
        h.capacity_at_resume
    );
    assert!(
        h.skipped_queue_after <= withheld,
        "{what}: {} frames withheld by the queue guard after the resume (up to {withheld} allowed): \
         {h:?}",
        h.skipped_queue_after
    );
    assert!(
        h.stall_max_after_ms <= 100.0,
        "{what}: a {:.0} ms stall after the resume: {h:?}",
        h.stall_max_after_ms
    );
}

/// A short hold over a moving desktop, short enough for a debug build: held, quiet, resumed at the
/// same rung with a keyframe of the screen as it is. And a hide shorter than the grace changes
/// nothing at all.
#[test]
fn a_short_hold_over_a_moving_desktop_is_quiet_and_resumes_at_the_same_rung() {
    let s = run(&scenario(MOVING, CLEAN, 40, Some((4, 34))));
    assert_eq!(s.holds.len(), 1, "{:?}", s.holds);
    assert_hold(&s.holds[0], "moving, 20 s held", AFTER_THE_GRACE, 1_000.0);
    assert_hold_keeps_the_rung(&s.holds[0], "moving, 20 s held");
    assert_no_collapse_after(&s.holds[0], "moving, 20 s held", 0);
}

/// The bench's hold run in the simulator: a video playing on a clean 4 Mbps path, the page hidden
/// for thirty seconds — twenty of them held — and back. str0m is restarted right before the resumed
/// keyframe, so its estimate stays where the hold left it: the first frame in half a second, the
/// same rung, and no collapse, no queue, no stall after it.
#[test]
fn a_playing_video_resumes_without_an_estimate_collapse() {
    let s = run(&scenario(PLAYING, CLEAN, 45, Some((4, 34))));
    assert_eq!(s.holds.len(), 1, "{:?}", s.holds);
    let h = &s.holds[0];
    assert_hold(h, "playing, 20 s held", AFTER_THE_GRACE, 500.0);
    assert_hold_keeps_the_rung(h, "playing, 20 s held");
    assert_no_collapse_after(h, "playing, 20 s held", 0);
    assert!(
        s.collapses.is_empty(),
        "an estimate collapse in a session that only looked away: {:?}",
        s.collapses
    );
}

/// What a page that sleeps while hidden must come to: nothing of its silence read as the path's.
/// No brake in the grace, none as the controller resumes, the hold's restart of str0m made, and
/// the budget from the second after the resume as it was when the page was hidden — no ramp out of
/// a brake. And the same picture: rung, no collapse, no stall.
fn assert_sleep_is_no_outage(h: &HoldSummary, what: &str) {
    assert_eq!(h.brakes_in_grace, 0, "{what}: braked in the grace: {h:?}");
    assert_eq!(h.brake_at_resume, "-", "{what}: resumed braked: {h:?}");
    let least = h
        .budget_min_after_kbps
        .unwrap_or_else(|| panic!("{what}: no tick after the resume: {h:?}"));
    assert!(
        u64::from(least) * 10 >= u64::from(h.budget_at_hide_kbps) * 9,
        "{what}: the budget fell to {least} kbps after the resume, from {} as the page was \
         hidden: {h:?}",
        h.budget_at_hide_kbps
    );
    assert_hold_keeps_the_rung(h, what);
    assert_no_collapse_after(h, what, 0);
    // Held once the receiver has been silent two seconds, not after ten: on the
    // wire while hidden, at most the video until then and str0m's padding after.
    let hidden_s = h.visible_s - h.hidden_s;
    let most_kbit = f64::from(h.budget_at_hide_kbps) * ASLEEP.end() + 120.0 * hidden_s;
    assert!(
        (h.egress_hidden_bytes as f64) * 8.0 / 1_000.0 <= most_kbit,
        "{what}: {} kB on the wire while hidden {hidden_s:.0} s, more than {:.0} kB: {h:?}",
        h.egress_hidden_bytes / 1_000,
        most_kbit / 8.0
    );
}

/// A recorded iPhone viewer: Telegram's WebView sleeps the moment its page is
/// hidden — no receiver report, no transport-wide feedback, no ICE consent answer — and its relay
/// over TCP keeps what was sent to it; it wakes 0.8 s before its `vis`, and its first receiver
/// report reads the 11 s it slept as round trip. In the recording the silence brake took the
/// grace's budget from 5851 to 247 kbps, the hold froze it so, the resume came back braked and
/// refused the restart (`no-report`), and the budget took ten seconds to grow back. Here, without
/// the fix, the same: braked in the grace, resumed braked, no restart, the budget 144-439 kbps for
/// ten seconds against 1697 when the page was hidden. With it the page is held as asleep two
/// seconds into its silence.
#[test]
fn a_page_that_sleeps_while_hidden_is_no_outage() {
    let s = run(&asleep_scenario(
        PLAYING,
        RELAYED,
        60,
        Some((10, 40)),
        "asleep_when_hidden = true\n",
    ));
    assert_eq!(s.holds.len(), 1, "{:?}", s.holds);
    let h = &s.holds[0];
    assert_hold(h, "asleep, hidden 30 s", ASLEEP, 500.0);
    assert_sleep_is_no_outage(h, "asleep, hidden 30 s");
    assert_eq!(s.brake_engaged, 0, "a brake in a session that only slept");
}

/// The same page behind a UDP path, which loses what was sent to it asleep, and waking only 0.1 s
/// before its `vis`: its first report after the resume reads the whole interval lost. Before the
/// fix: braked in the grace, resumed braked, then braked again on that loss — to 120 kbps, with the
/// capacity evidence cut to it. The first frame waits on the viewer's receiver, which holds it
/// behind the lost packets for a second (1.3-1.4 s after the page is back, before the fix too).
#[test]
#[ignore = "a minute of video around a sleep: cargo test -p afklink-sim --release -- --ignored"]
fn a_page_that_sleeps_behind_udp_is_no_outage() {
    let s = run(&asleep_scenario(
        PLAYING,
        RELAYED,
        60,
        Some((10, 40)),
        "asleep_when_hidden = true\nasleep_backlog = \"drop\"\nwake_before_visible_ms = 100\n",
    ));
    assert_eq!(s.holds.len(), 1, "{:?}", s.holds);
    let h = &s.holds[0];
    assert_hold(h, "asleep behind UDP, hidden 30 s", ASLEEP, 1_500.0);
    assert_sleep_is_no_outage(h, "asleep behind UDP, hidden 30 s");
    assert_eq!(s.brake_engaged, 0, "a brake in a session that only slept");
}

/// A hide shorter than the grace is no hold: no mark of one, and nothing withheld.
#[test]
fn a_hide_shorter_than_the_grace_is_no_hold() {
    let s = run(&scenario(STILL, CLEAN, 20, Some((3, 9))));
    assert!(s.holds.is_empty(), "{:?}", s.holds);
}

/// Ten minutes hidden over a moving desktop — typing and scrolling — against the same session with
/// the page never hidden: less on the wire (light content: its media is little more than the
/// padding floor both share), and the same picture after.
#[test]
#[ignore = "a minute of video around ten minutes held: cargo test -p afklink-sim --release -- --ignored"]
fn ten_minutes_hidden_over_a_moving_desktop() {
    let held = run(&scenario(MOVING, CLEAN, 640, Some((15, 615))));
    let baseline = run(&scenario(MOVING, CLEAN, 640, None));
    assert_eq!(held.holds.len(), 1);
    let h = &held.holds[0];
    assert_hold(h, "moving, 10 min held", AFTER_THE_GRACE, 1_000.0);
    assert_hold_keeps_the_rung(h, "moving, 10 min held");
    eprintln!(
        "moving: held {} kbps, baseline {} kB vs held {} kB on the wire; first frame {:?} ms; \
         estimate {} at the resume, evidence {}; {:?}",
        h.egress_held_kbps,
        baseline.egress_bytes / 1_000,
        held.egress_bytes / 1_000,
        h.first_frame_ms,
        h.estimate_at_resume,
        h.capacity_at_resume,
        h.reanchors
    );
    assert!(held.egress_bytes < baseline.egress_bytes);
}

/// Ten minutes hidden over a playing video pane on a clean path, against the same session never
/// hidden: a fraction of the bytes — the padding floor instead of the video — and the same picture.
///
/// The pane's own rhythm collapses str0m's estimate at its typing-to-video turns in the session
/// never hidden as well (2 s of typing leave the acknowledged rate at the typing's), so the bound
/// after the resume is on what the viewer sees: no stall past 250 ms (882 ms before the resume's
/// restart, from the collapse to 189 kbps the keyframe provoked) and the queue guard's withholding
/// near the resume keyframe's own burst (55 frames before) — over seeds 1-10, each against its own
/// session never hidden, because the pane moves the ladder by itself: it pegs the encoder at its QP
/// ceiling and climbs and falls between 1080p@30 and @60 (and lower) every few tens of seconds,
/// 16-18 downs in the ten minutes never hidden on every seed. So:
///
/// - every seed: the hold's own rules ([`assert_hold`]), one restart of str0m, no stall past
///   250 ms after the first resumed frame;
/// - over the seeds: the median of the frames the queue guard withheld in the ten seconds after the
///   resume at most 40, and no more downs in those ten seconds than the session never hidden made
///   in the same ten seconds of the content — the ten after the hold began, where the held one
///   froze its controller — give or take two;
/// - the test's own seed, 7: a quarter of the bytes or less over the ten minutes.
///
/// A single-seed check (no down and at most 20 withheld) holds on only 2-3 of seeds 1-10
/// Measured: downs held / never hidden 4/4; withheld median 16 (16-27); stall at
/// most 134 ms. With the restart refused: no restart on any seed, stalls of 261-3147 ms on all
/// ten, withheld median 65, and 4/4 downs — the downs never tell the defect apart, the stall and
/// the restart do.
#[test]
#[ignore = "ten seeds of a minute of video around ten minutes held: cargo test -p afklink-sim --release -- --ignored"]
fn ten_minutes_hidden_over_a_playing_video() {
    const OWN_SEED: u64 = 7;
    let runs = common::over_seeds(1..=10, |seed| {
        let held = run_seeded(&scenario(VIDEO, CLEAN, 640, Some((15, 615))), seed);
        // Never hidden: the whole ten minutes where the bytes are compared, else the content up to
        // ten seconds past the hold's start (the same moves as the whole run's, to the tick).
        let secs = if seed == OWN_SEED { 640 } else { 45 };
        let baseline = run_seeded(&scenario(VIDEO, CLEAN, secs, None), seed);
        (held, baseline)
    });
    let mut held_downs = 0;
    let mut never_hidden_downs = 0;
    let mut withheld = Vec::new();
    let mut table = Vec::new();
    for (seed, (held, baseline)) in &runs {
        let what = format!("video, 10 min held, seed {seed}");
        assert_eq!(held.holds.len(), 1, "{what}: {:?}", held.holds);
        let h = &held.holds[0];
        assert_hold(h, &what, AFTER_THE_GRACE, 1_000.0);
        let restarts = h
            .reanchors
            .iter()
            .filter(|(t, ..)| *t == "hold-resume")
            .count();
        assert_eq!(restarts, 1, "{what}: one restart per hold: {h:?}");
        assert!(
            h.stall_max_after_ms <= 250.0,
            "{what}: a {:.0} ms stall after the resume: {h:?}",
            h.stall_max_after_ms
        );
        assert!(
            baseline.sim_secs >= h.held_s + 10.0,
            "{what}: the session never hidden ends before the window it is compared over"
        );
        let same_content = downs_between(baseline, h.held_s, h.held_s + 10.0);
        held_downs += h.downs_after;
        never_hidden_downs += same_content;
        withheld.push(h.skipped_queue_after as f64);
        table.push(format!(
            "s{seed}: downs {}/{same_content}, withheld {}, stall {:.0} ms, estimate min {:?}",
            h.downs_after, h.skipped_queue_after, h.stall_max_after_ms, h.estimate_min_after_kbps
        ));
        if *seed == OWN_SEED {
            eprintln!(
                "video: held {} kbps, baseline {} kB vs held {} kB on the wire; first frame {:?} \
                 ms; estimate {} at the resume, evidence {}; {:?}",
                h.egress_held_kbps,
                baseline.egress_bytes / 1_000,
                held.egress_bytes / 1_000,
                h.first_frame_ms,
                h.estimate_at_resume,
                h.capacity_at_resume,
                h.reanchors
            );
            assert!(
                held.egress_bytes * 4 < baseline.egress_bytes,
                "held {} bytes against {} never hidden",
                held.egress_bytes,
                baseline.egress_bytes
            );
        }
    }
    eprintln!(
        "video, 10 min held, by seed (downs held/never hidden in the same 10 s of content): {}",
        table.join("; ")
    );
    let withheld_median = common::median(&withheld);
    assert!(
        withheld_median <= 40.0,
        "the queue guard withheld a median {withheld_median} frames in the ten seconds after the \
         resume: {}",
        table.join("; ")
    );
    assert!(
        held_downs <= never_hidden_downs + 2,
        "{held_downs} downs in the ten seconds after the hold against {never_hidden_downs} in the \
         same ten seconds of the content never hidden: {}",
        table.join("; ")
    );
}

/// Ten minutes hidden over a still desktop: the capture started again delivers the screen as it is
/// — nothing else would ever replace the picture from before the hold — and nothing else changes.
#[test]
#[ignore = "ten minutes of str0m in virtual time: cargo test -p afklink-sim --release -- --ignored"]
fn ten_minutes_hidden_over_a_still_desktop() {
    let held = run(&scenario(STILL, CLEAN, 640, Some((15, 615))));
    let baseline = run(&scenario(STILL, CLEAN, 640, None));
    assert_eq!(held.holds.len(), 1);
    let h = &held.holds[0];
    assert_hold(h, "still, 10 min held", AFTER_THE_GRACE, 1_000.0);
    assert_hold_keeps_the_rung(h, "still, 10 min held");
    eprintln!(
        "still: held {} kbps, baseline {} kB vs held {} kB on the wire; first frame {:?} ms; {:?}",
        h.egress_held_kbps,
        baseline.egress_bytes / 1_000,
        held.egress_bytes / 1_000,
        h.first_frame_ms,
        h.reanchors
    );
}

/// Ten minutes hidden on a jittery path, a video pane loading the link before: str0m reads the
/// jitter under padding as overuse and walks its estimate down through the hold, and the resume
/// raises it back to the evidence from before — the hold's own re-anchor, up, to the rung's clamp.
///
/// The rung is not asserted here: on this path the ladder does not hold one even when the page is
/// never hidden — that session walks from 1080p60 to 360p@8 and oscillates there (35 moves in 640 s)
/// — so the comparison is with it: the held session moves less.
#[test]
#[ignore = "ten minutes of str0m on a jittery path: cargo test -p afklink-sim --release -- --ignored"]
fn ten_minutes_hidden_on_a_jittery_path_restores_the_estimate() {
    let held = run(&scenario(VIDEO, JITTERY, 630, Some((30, 620))));
    let baseline = run(&scenario(VIDEO, JITTERY, 630, None));
    assert_eq!(held.holds.len(), 1);
    let h = &held.holds[0];
    // The keyframe crosses a 200 ms path with up to 240 ms of jitter.
    assert_hold(
        h,
        "video, jittery path, 10 min held",
        AFTER_THE_GRACE,
        1_500.0,
    );
    assert!(
        held.rung_changes.len() < baseline.rung_changes.len(),
        "held {:?} against never hidden {:?}",
        held.rung_changes,
        baseline.rung_changes
    );
    assert!(
        h.estimate_at_resume * 2 <= h.capacity_at_resume,
        "the hold's silence walked the estimate down: {h:?}"
    );
    assert!(
        h.reanchors
            .iter()
            .any(|&(t, est, kbps)| t == "hold-resume" && kbps > est),
        "the estimate is raised back on the resume: {h:?}"
    );
    eprintln!(
        "jittery: held {} kbps; estimate {} at the resume, evidence {}; re-anchors {:?}; first \
         frame {:?} ms",
        h.egress_held_kbps,
        h.estimate_at_resume,
        h.capacity_at_resume,
        h.reanchors,
        h.first_frame_ms
    );
}
