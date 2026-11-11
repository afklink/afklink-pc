//! The planner against a simulated Windows (`sim`): virtual cursor, virtual clock, Windows' pointer
//! ballistics (linear with the display scale and the speed slider, or an acceleration curve), inputs
//! showing a couple of milliseconds late. Nothing here touches Windows.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::sim::SimCursor;
use super::*;
use crate::fakerinput::absolute_wire;
use crate::RelCarry;

/// One `r` per animation frame: the viewer's pace.
const FRAME: Duration = Duration::from_millis(16);

/// The planner and a simulated PC, and a path that does what the plans say — the camera's counts
/// through the same carry the HID path keeps.
struct Rig {
    sim: SimCursor,
    sync: CursorSync,
    carry: RelCarry,
    held: bool,
    path: RelPath,
    plans: Vec<Plan>,
    camera_counts: Vec<(i32, i32)>,
    /// The number the next move carries (`r.s`), for a viewer that numbers them; `None`: unnumbered.
    next_s: Option<u32>,
}

impl Rig {
    fn new(dpi: u32) -> Self {
        Self::with(dpi, |_| {})
    }

    fn with(dpi: u32, set: impl FnOnce(&mut SimCursor)) -> Self {
        let now = Instant::now();
        let mut sim = SimCursor::new(dpi, now);
        set(&mut sim);
        let mut sync = CursorSync::new();
        sync.begin_session(&mut sim, now);
        Self {
            sim,
            sync,
            carry: RelCarry::default(),
            held: false,
            path: RelPath::Hid,
            plans: Vec::new(),
            camera_counts: Vec::new(),
            next_s: None,
        }
    }

    /// One `r`, one frame after the last: the hand's `(dx, dy)` in px of the screen, and the viewer's
    /// pointer (the pixel it is over) when the viewer sends one.
    fn frame(&mut self, hand: (f64, f64), target: Option<(i32, i32)>) -> Plan {
        self.sim.advance(FRAME);
        self.send(hand, target)
    }

    fn event(&self, hand: (f64, f64), target: Option<(i32, i32)>) -> RelEvent {
        let (w, h) = (f64::from(self.sim.width), f64::from(self.sim.height));
        RelEvent {
            dx: hand.0 / w,
            dy: hand.1 / h,
            x: target.map(|t| (f64::from(t.0) + 0.5) / w),
            y: target.map(|t| (f64::from(t.1) + 0.5) / h),
            s: None,
        }
    }

    fn send(&mut self, hand: (f64, f64), target: Option<(i32, i32)>) -> Plan {
        let mut event = self.event(hand, target);
        if let Some(s) = self.next_s {
            event.s = Some(s);
            self.next_s = Some(s + 1);
        }
        self.send_event(event)
    }

    /// What a cursor report taken now would say does not show yet: the planner's answer for a fresh
    /// look at the simulated cursor.
    fn unshown(&mut self) -> Option<u32> {
        let now = self.sim.now;
        let look = self.sim.look().unwrap();
        self.sync.unshown((look.x, look.y), now)
    }

    fn send_event(&mut self, event: RelEvent) -> Plan {
        let now = self.sim.now;
        let plan = self
            .sync
            .plan(event, self.held, self.path, &mut self.sim, now);
        match plan {
            Plan::Camera => {
                let (cx, cy) = self
                    .carry
                    .step(event.dx, event.dy, self.sim.width, self.sim.height);
                self.camera_counts.push((cx, cy));
                if (cx, cy) != (0, 0) {
                    self.sim.send_counts(cx, cy);
                }
            }
            Plan::Absolute {
                px,
                py,
                width,
                height,
            } => {
                let (x, y) = absolute_wire(px, py, width, height);
                self.sim.send_absolute_wire(x, y);
            }
            Plan::Relative { cx, cy } => self.sim.send_counts(cx, cy),
            Plan::Nothing => {}
        }
        self.plans.push(plan);
        plan
    }

    /// Where the cursor is, everything sent so far having shown.
    fn settled(&mut self) -> (i32, i32) {
        self.sim.advance(FRAME);
        self.sim.position()
    }

    fn absolute_plans(&self) -> usize {
        self.plans
            .iter()
            .filter(|p| matches!(p, Plan::Absolute { .. }))
            .count()
    }
}

fn off(p: (i32, i32), intended: V) -> V {
    (f64::from(p.0) - intended.0, f64::from(p.1) - intended.1)
}

fn dist(p: (i32, i32), intended: V) -> f64 {
    len(off(p, intended))
}

/// The probe's finding, the reason this module exists: at 150 % Windows moves 1.5 px per count, and the old
/// path sent the physical pixels as counts. Now 150 px of hand is 150 px of cursor at any scale —
/// and every frame on the way is where the hand is, within what whole counts allow.
#[test]
fn exact_travel_at_every_display_scale() {
    for dpi in [96, 120, 144, 192] {
        let s = f64::from(dpi) / 96.0;
        let mut r = Rig::new(dpi);
        let start = r.sim.position();
        let mut intended = pixel(start);
        for _ in 0..10 {
            r.sim.advance(FRAME);
            let on_the_way = dist(r.sim.position(), intended);
            assert!(
                on_the_way <= 1.0 + s / 2.0,
                "{dpi} dpi: {on_the_way:.2} px off on the way"
            );
            let plan = r.send((15.0, 0.0), None);
            assert!(matches!(plan, Plan::Relative { .. }), "{plan:?}");
            intended.0 += 15.0;
        }
        let end = r.settled();
        assert!(
            (end.0 - start.0 - 150).abs() <= 1 && end.1 == start.1,
            "{dpi} dpi: {start:?} -> {end:?}, not 150 px right"
        );

        // A slow diagonal: under a count per frame at 200 %.
        let start = r.settled();
        for _ in 0..60 {
            r.frame((0.7, -0.35), None);
        }
        let end = r.settled();
        let error = dist(end, (f64::from(start.0) + 42.0, f64::from(start.1) - 21.0));
        assert!(
            error <= 1.0 + s / 2.0,
            "{dpi} dpi: a slow stroke ends {error:.2} px off ({start:?} -> {end:?})"
        );
    }
}

/// The pointer-speed slider multiplies Windows' gain with EPP off: the documented table takes it
/// out.
#[test]
fn the_speed_slider_is_taken_out() {
    for speed in [1, 6, 10, 14, 20] {
        let mut r = Rig::with(144, |sim| sim.speed = speed);
        let start = r.sim.position();
        for _ in 0..10 {
            r.frame((0.0, 15.0), None);
        }
        let end = r.settled();
        let gain = 1.5 * speed_factor(speed);
        assert!(
            f64::from((end.1 - start.1 - 150).abs()) <= 1.0 + gain / 2.0,
            "speed {speed}: {start:?} -> {end:?}"
        );
    }
}

/// EPP on: Windows' gain grows with each report's size, and nothing says by how much. The planner
/// learns it from its own moves, extrapolating past the sizes learned so far along their slope; the
/// feedback carries it until then. From the stroke's first frame and through every change of speed
/// the cursor is never ahead of the hand by more than a count (2.3–2.8 px at 20–40 px a frame, and
/// the cursor sits on whole pixels) — the old "flies further" — and behind it by more than that only
/// in the first frames of a sudden faster hand, by at most a quarter of a frame's motion; the error
/// does not ring, and the stroke ends where the hand did.
#[test]
fn with_acceleration_the_cursor_converges_on_the_hand_without_ringing() {
    let mut r = Rig::with(144, |sim| {
        sim.epp = true;
        sim.warp(100, 1200);
    });
    let start = r.sim.position();
    let mut intended = pixel(start);
    // 20 frames each: 2340 px in all, well inside the screen.
    let speeds = [4.0, 12.0, 30.0, 8.0, 2.0, 20.0, 40.0, 1.0];
    let mut ringing = 0;
    for speed in speeds {
        // The side the cursor was last off by more than 2 px: ahead or behind.
        let mut last_ahead: Option<bool> = None;
        for i in 0..20 {
            r.sim.advance(FRAME);
            let e = off(r.sim.position(), intended).0;
            assert!(e <= 3.5, "{e} px ahead of the hand at {speed} px a frame");
            let behind = if i < 3 { 3.5f64.max(speed / 4.0) } else { 3.5 };
            assert!(
                -e <= behind,
                "{} px behind the hand at {speed} px a frame, frame {i} (learned {})",
                -e,
                r.sync.gain.bins_text()
            );
            if e.abs() > 2.0 {
                let ahead = e > 0.0;
                if last_ahead.is_some_and(|was| was != ahead) {
                    ringing += 1;
                }
                last_ahead = Some(ahead);
            }
            r.send((speed, 0.0), None);
            intended.0 += speed;
        }
    }
    let end = r.settled();
    assert!(ringing <= 1, "the error changed sides {ringing} times");
    let error = dist(end, intended);
    assert!(error <= 3.0, "the stroke ends {error:.2} px off");
    let (gain, source) = r.sync.gain.typical();
    assert_eq!(source, GainSource::Learned);
    assert!(gain > 0.5, "{gain}");
}

/// A gain the model has wrong by 1.6× (Windows doing something the table does not say): a drag whose
/// target starts 60 px off closes the gap without overshooting it, in steps no bigger than a hand's.
#[test]
fn a_wrong_gain_closes_the_gap_without_overshoot() {
    let mut r = Rig::with(144, |sim| sim.extra_gain = 1.6);
    r.held = true;
    let start = r.sim.position();
    let mut target = (start.0 + 60, start.1);
    let mut gaps = Vec::new();
    let mut last = start;
    for _ in 0..40 {
        r.sim.advance(FRAME);
        let now = r.sim.position();
        gaps.push(f64::from(target.0 - now.0));
        // No single move is a jump: the hand's 2 px and a correction of at most 3, both 1.6 times
        // what the model thinks, and a count of rounding.
        assert!((now.0 - last.0).abs() <= 11, "a {} px step", now.0 - last.0);
        last = now;
        r.send((2.0, 0.0), Some(target));
        target.0 += 2;
    }
    let settled = r.settled();
    let final_gap = f64::from(target.0 - 2 - settled.0);
    assert!(
        final_gap.abs() <= 2.0,
        "{final_gap} px from the target at the end"
    );
    assert!(
        gaps.iter().all(|g| *g >= -2.0),
        "the cursor overshot the target: {gaps:?}"
    );
    assert_eq!(
        r.absolute_plans(),
        0,
        "a held button never moves absolutely"
    );
}

/// `GetCursorPos` reflecting a move only after the next frame (a slow machine): moves in flight are
/// counted as done, so nothing is corrected twice and nothing overshoots.
#[test]
fn a_slow_reflection_is_not_corrected_twice() {
    let mut r = Rig::with(144, |sim| sim.delay = Duration::from_millis(25));
    let start = r.sim.position();
    let mut intended = pixel(start);
    let mut worst = 0.0f64;
    for k in 1..=40 {
        r.sim.advance(FRAME);
        r.send((12.0, 0.0), None);
        intended.0 += 12.0;
        // Everything but the last two sends has shown by now (none of the first two).
        let shown_sends = f64::from(k - 2).max(0.0);
        let ahead = off(
            r.sim.position(),
            (f64::from(start.0) + 12.0 * shown_sends, intended.1),
        )
        .0;
        worst = worst.max(ahead.abs());
    }
    r.sim.advance(Duration::from_millis(60));
    let end = r.sim.position();
    assert!(
        worst <= 1.0,
        "the cursor was {worst:.1} px off the sends that had shown"
    );
    assert!(dist(end, intended) <= 1.5, "{end:?} vs {intended:?}");
}

/// The PC's own mouse (or a game's warp) moves the cursor mid-stroke: the aim moves with it, and the
/// hand carries on from there — nothing drags the cursor back to where the old aim was.
#[test]
fn someone_elses_motion_re_anchors_the_aim() {
    let mut r = Rig::new(144);
    for _ in 0..5 {
        r.frame((10.0, 0.0), None);
    }
    let before = r.settled();
    r.sim.warp(before.0 + 200, before.1 - 50);
    let moved = r.sim.position();
    for _ in 0..5 {
        r.frame((10.0, 0.0), None);
    }
    let end = r.settled();
    let error = dist(end, (f64::from(moved.0) + 50.0, f64::from(moved.1)));
    assert!(error <= 1.5, "{moved:?} + 50 px -> {end:?}");
    assert_eq!(r.sync.stats.external, 1, "{:?}", r.sync.stats);
}

/// Our moves reach nothing (UIPI drops `SendInput` over an elevated window and answers yes): the aim
/// does not run away from the cursor, so when moves reach it again it does not leap to catch up the
/// ones that were lost — it moves with the hand from where it is.
#[test]
fn moves_that_move_nothing_re_anchor_instead_of_winding_up() {
    let mut r = Rig::new(144);
    r.sim.deaf = true;
    for _ in 0..8 {
        r.frame((10.0, 0.0), None);
    }
    assert!(r.sync.stats.no_effect >= 1, "{:?}", r.sync.stats);
    r.sim.deaf = false;
    let from = r.settled();
    let mut last = from;
    for _ in 0..10 {
        r.frame((10.0, 0.0), None);
        let now = r.sim.position();
        assert!(now.0 - last.0 <= 10 + 5 + 2, "a leap: {last:?} -> {now:?}");
        last = now;
    }
    let end = r.settled();
    assert!(
        dist(end, (f64::from(from.0) + 100.0, f64::from(from.1))) <= 2.0,
        "{from:?} + 100 px -> {end:?}"
    );
}

/// The aim is clamped to the screen: pushing past the edge winds nothing up, and the way back starts
/// at once.
#[test]
fn the_aim_stops_at_the_edge() {
    let mut r = Rig::new(144);
    r.sim.warp(3580, 1000);
    for _ in 0..10 {
        r.frame((20.0, 0.0), None);
    }
    assert_eq!(r.settled().0, 3599);
    for _ in 0..3 {
        r.frame((-10.0, 0.0), None);
    }
    let end = r.settled();
    assert!((end.0 - 3569).abs() <= 1, "{end:?}");

    // And the top-left corner.
    r.sim.warp(15, 12);
    for _ in 0..5 {
        r.frame((-10.0, -10.0), None);
    }
    assert_eq!(r.settled(), (0, 0));
    r.frame((6.0, 3.0), None);
    let end = r.settled();
    assert!(dist(end, (6.0, 3.0)) <= 1.0, "{end:?}");
}

/// A camera turn: the game hides the cursor and keeps it at the centre; the camera's counts are
/// today's, byte for byte. When the cursor shows again (where the game put it back, as Lineage 2
/// does), exact moves start from there — not from where the aim was before the turn.
#[test]
fn a_camera_turn_moves_as_before_and_the_cursor_is_re_anchored_after_it() {
    let mut r = Rig::new(144);
    for _ in 0..4 {
        r.frame((10.0, 0.0), None);
    }
    let before_turn = r.settled();
    r.sim.showing = false;
    r.sim.warp(1800, 1200);
    let deltas = [
        (13.7, -2.2),
        (0.4, 0.4),
        (-7.25, 1.1),
        (31.0, 0.0),
        (0.2, 0.3),
    ];
    let mut reference = RelCarry::default();
    let mut want = Vec::new();
    for d in deltas {
        let plan = r.frame(d, Some((1000, 1000)));
        assert_eq!(plan, Plan::Camera, "a hidden cursor is the camera's");
        want.push(reference.step(d.0 / 3600.0, d.1 / 2400.0, 3600, 2400));
    }
    assert_eq!(
        r.camera_counts, want,
        "the camera's counts are exactly today's"
    );

    // The game shows the cursor where it was before the turn.
    r.sim.showing = true;
    r.sim.warp(before_turn.0, before_turn.1);
    for _ in 0..3 {
        r.frame((10.0, 5.0), None);
    }
    let end = r.settled();
    let error = dist(
        end,
        (
            f64::from(before_turn.0) + 30.0,
            f64::from(before_turn.1) + 15.0,
        ),
    );
    assert!(error <= 1.5, "{before_turn:?} + (30, 15) -> {end:?}");
}

/// Everything that is not a visible cursor on the captured screen is the camera's.
#[test]
fn hidden_suppressed_offscreen_and_unreadable_cursors_are_the_cameras() {
    let sets: [fn(&mut SimCursor); 3] = [
        |s| s.showing = false,
        |s| s.suppressed = true,
        |s| s.unreadable = true,
    ];
    for set in sets {
        let mut r = Rig::new(144);
        set(&mut r.sim);
        assert_eq!(r.frame((5.0, 0.0), Some((10, 10))), Plan::Camera);
        assert_eq!(r.frame((5.0, 0.0), None), Plan::Camera);
    }
    // Off the captured screen: on a second monitor to its left.
    let mut r = Rig::new(144);
    struct Offscreen(SimCursor);
    impl CursorWorld for Offscreen {
        fn look(&mut self) -> Result<CursorLook, String> {
            let mut l = self.0.look()?;
            l.x = -300;
            Ok(l)
        }
        fn screen(&mut self) -> (i32, i32) {
            self.0.screen()
        }
        fn settings(&mut self) -> Result<PointerSettings, String> {
            self.0.settings()
        }
        fn foreground(&mut self) -> usize {
            self.0.foreground()
        }
        fn describe_foreground(&mut self, window: usize) -> ForegroundInfo {
            self.0.describe_foreground(window)
        }
    }
    let mut world = Offscreen(SimCursor::new(144, r.sim.now));
    let event = r.event((5.0, 0.0), Some((10, 10)));
    let now = r.sim.now;
    assert_eq!(
        r.sync.plan(event, false, RelPath::Hid, &mut world, now),
        Plan::Camera
    );
}

/// The desktop game mode without pointer capture: with no button held the cursor is put on the
/// pointer's pixel (exactly, 2188 included — the probe's miss); a drag moves it relatively, following the
/// pointer; and after the button, the pointer's pixel again.
#[test]
fn point_then_drag_then_point() {
    let mut r = Rig::new(144);
    for target in [
        (2188, 1372),
        (2188, 1522),
        (2038, 1372),
        (0, 0),
        (3599, 2399),
        (1, 2398),
    ] {
        let plan = r.frame((3.0, -1.0), Some(target));
        assert!(matches!(plan, Plan::Absolute { .. }), "{plan:?}");
        assert_eq!(r.settled(), target, "the cursor is on the pointer's pixel");
    }
    // Pointing at where the cursor already is sends nothing.
    assert_eq!(r.frame((0.2, 0.0), Some((1, 2398))), Plan::Nothing);

    let mut target = (1500, 900);
    r.frame((0.0, 0.0), Some(target));
    assert_eq!(r.settled(), target);
    r.held = true;
    for _ in 0..12 {
        target = (target.0 + 20, target.1 - 7);
        let plan = r.frame((20.0, -7.0), Some(target));
        assert!(
            matches!(plan, Plan::Relative { .. } | Plan::Nothing),
            "a drag moves relatively: {plan:?}"
        );
        let now = r.settled();
        assert!(
            dist(now, pixel(target)) <= 1.5,
            "the drag follows the pointer: {now:?} vs {target:?}"
        );
    }
    r.held = false;
    let plan = r.frame((5.0, 0.0), Some((700, 700)));
    assert!(matches!(plan, Plan::Absolute { .. }), "{plan:?}");
    assert_eq!(r.settled(), (700, 700));
}

/// With a button held the target decides where the cursor goes, whatever the hand's delta says: here
/// the viewer's `dx` is 0 while its pointer moves 25 px a frame.
#[test]
fn a_held_button_follows_the_target_not_the_hand() {
    let mut r = Rig::new(144);
    r.held = true;
    let start = r.sim.position();
    let mut target = start;
    for _ in 0..30 {
        target.0 += 25;
        r.frame((0.0, 0.0), Some(target));
    }
    let end = r.settled();
    assert!(dist(end, pixel(target)) <= 1.5, "{end:?} vs {target:?}");
    assert_eq!(r.absolute_plans(), 0);
}

/// A message with half a target is moved as if it had none (the contract refuses it; this is the
/// last line): exact, never absolute.
#[test]
fn half_a_target_is_no_target() {
    let mut r = Rig::new(144);
    let start = r.sim.position();
    let mut event = r.event((15.0, 0.0), None);
    event.x = Some(0.9);
    r.sim.advance(FRAME);
    let plan = r.send_event(event);
    assert!(matches!(plan, Plan::Relative { .. }), "{plan:?}");
    let end = r.settled();
    assert!((end.0 - start.0 - 15).abs() <= 1, "{start:?} -> {end:?}");
}

/// Point mode's absolute report lands on every pixel of the common screen widths — Windows maps
/// FakerInput's `0..32767` as `floor(X · width / 32768)`, the probe's data — and 2188 on 3600 px is no longer
/// 2187.
#[test]
fn the_absolute_report_lands_on_every_pixel() {
    for size in [
        3600, 2400, 1920, 1080, 2560, 1440, 3840, 2160, 5120, 1366, 768, 7680,
    ] {
        for p in 0..size {
            let (x, _) = absolute_wire(p, 0, size, 1);
            assert_eq!(
                i64::from(x) * i64::from(size) / 32768,
                i64::from(p),
                "{p} of {size} -> {x}"
            );
        }
    }
    assert_eq!(absolute_wire(2188, 1372, 3600, 2400), (19920, 18739));
    assert_ne!(absolute_wire(2188, 0, 3600, 2400).0, 19915, "E1's miss");
    // Off the screen: its edge.
    assert_eq!(
        absolute_wire(-5, 99_999, 3600, 2400).0,
        absolute_wire(0, 0, 3600, 2400).0
    );
}

/// The display scale changes mid-session (the owner changes it in Settings): the planner reads it
/// within a second, says so, re-anchors, and moves exactly at the new scale.
#[test]
fn a_settings_change_is_picked_up() {
    let mut r = Rig::new(144);
    for _ in 0..5 {
        r.frame((10.0, 0.0), None);
    }
    r.sim.dpi = 192;
    let reads = r.sim.settings_reads;
    r.sim.advance(Duration::from_millis(1100));
    let start = r.settled();
    for _ in 0..10 {
        r.frame((15.0, 0.0), None);
    }
    let end = r.settled();
    assert!(r.sim.settings_reads > reads);
    assert_eq!(r.sync.settings.map(|s| s.dpi), Some(192));
    assert!((end.0 - start.0 - 150).abs() <= 1, "{start:?} -> {end:?}");
}

/// A send that failed re-anchors the next move on the real cursor.
#[test]
fn a_failed_send_re_anchors() {
    let mut r = Rig::new(144);
    r.frame((10.0, 0.0), None);
    // The report never went out.
    r.sync.failed("simulated");
    r.sim.drain();
    let from = r.sim.position();
    r.frame((10.0, 0.0), None);
    let end = r.settled();
    assert!((end.0 - from.0 - 10).abs() <= 1, "{from:?} -> {end:?}");
    assert!(r.sync.aim.is_some());
}

/// An `m` (the tablet mode, the desktop viewer's mouse) onto pixel `p`: the planner's books, and the
/// report the path sends — onto `landed`, which is `p` for FakerInput's report 4 and may be a pixel
/// short for `SendInput`'s edge-aimed event.
fn m(r: &mut Rig, p: (i32, i32), landed: (i32, i32), path: RelPath) -> (i32, i32) {
    let now = r.sim.now;
    let t = (
        (f64::from(p.0) + 0.5) / f64::from(r.sim.width),
        (f64::from(p.1) + 0.5) / f64::from(r.sim.height),
    );
    let (px, py, width, height) = r.sync.absolute(t, path, &mut r.sim, now).unwrap();
    let (x, y) = absolute_wire(landed.0, landed.1, width, height);
    r.sim.send_absolute_wire(x, y);
    (px, py)
}

/// An `m` between exact moves (the owner switching from the tablet mode to the trackpad mode, or the
/// desktop viewer's mouse between game-mode moves) is neither taken for someone else's motion nor
/// fought: exact mode carries on from where the `m` put the cursor, with no re-anchor line — on
/// either path, a `SendInput` `m` a pixel short included.
#[test]
fn an_m_between_exact_moves_is_neither_someone_elses_motion_nor_fought() {
    for (path, short) in [(RelPath::Hid, 0), (RelPath::SendInput, 1)] {
        let mut r = Rig::new(144);
        for _ in 0..5 {
            r.frame((10.0, 0.0), None);
        }
        r.sim.advance(FRAME);
        let (px, py) = m(&mut r, (2500, 600), (2500 - short, 600), path);
        assert_eq!((px, py), (2500, 600));
        assert!(r.sync.aim.is_none(), "the aim is forgotten");
        for _ in 0..5 {
            r.frame((10.0, 0.0), None);
        }
        let end = r.settled();
        let want = (f64::from(2500 - short) + 50.0, 600.0);
        assert!(dist(end, want) <= 1.5, "{path:?}: {end:?} vs {want:?}");
        assert_eq!(r.sync.stats.external, 0, "{path:?}: {:?}", r.sync.stats);
        assert_eq!(r.sync.stats.reanchors, 0, "{path:?}: {:?}", r.sync.stats);
        assert_eq!(r.sync.stats.no_effect, 0, "{path:?}");
    }
}

/// A point move after an `m` is measured against where the `m` meant the cursor to be, and a drag
/// of `m`s (a button held) keeps the planner out of it: nothing is planned, only counted.
#[test]
fn m_is_counted_per_path_and_a_point_move_after_it_starts_from_it() {
    let mut r = Rig::new(144);
    r.held = true;
    for i in 0..10 {
        r.sim.advance(FRAME);
        m(
            &mut r,
            (1000 + 20 * i, 800),
            (1000 + 20 * i, 800),
            RelPath::Hid,
        );
    }
    r.sim.advance(FRAME);
    m(&mut r, (1300, 800), (1300, 800), RelPath::SendInput);
    assert_eq!((r.sync.stats.m_hid, r.sync.stats.m_sendinput), (10, 1));
    assert!(r.plans.is_empty(), "an m is not planned");
    r.held = false;
    let plan = r.frame((1.0, 0.0), Some((1400, 800)));
    assert!(matches!(plan, Plan::Absolute { .. }), "{plan:?}");
    assert_eq!(r.settled(), (1400, 800));
    assert_eq!(r.sync.stats.external, 0);
}

/// The screen size unknown: nothing to aim at, and nothing kept.
#[test]
fn an_m_with_no_screen_is_nothing_to_aim_at() {
    let mut r = Rig::new(144);
    r.frame((10.0, 0.0), None);
    r.sim.width = 0;
    let now = r.sim.now;
    assert_eq!(
        r.sync.absolute((0.5, 0.5), RelPath::Hid, &mut r.sim, now),
        None
    );
    assert!(r.sync.aim.is_none() && r.sync.last_seen.is_none() && r.sync.pending.is_empty());
}

/// A writer the log-capture tests read back.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What `f` logs at `level` and above, on this thread.
fn logged(level: tracing::Level, f: impl FnOnce()) -> String {
    let capture = Capture::default();
    let writer = capture.clone();
    let ours = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish(),
    );
    // See `typing::tests::logged`: a second live dispatcher makes tracing ask every one of them.
    let _second = tracing::Dispatch::new(tracing_subscriber::registry());
    tracing::dispatcher::with_default(&ours, f);
    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    log
}

/// Nothing per move at `debug`: three seconds of a stroke with a camera turn in it are a handful of
/// lines — the settings, the mode changes, one aggregate a second — and every move is at `trace`.
#[test]
fn moves_are_traced_and_aggregated_never_debugged_one_by_one() {
    let debug = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new(144);
        for i in 0..200 {
            r.sim.showing = !(80..100).contains(&i);
            r.frame((3.0, 1.0), None);
        }
        r.sync.release(r.sim.now);
    });
    let lines = debug.lines().count();
    assert!(lines <= 14, "{lines} debug lines:\n{debug}");
    assert!(debug.contains("cursor sync: pointer settings"), "{debug}");
    assert!(debug.contains("session start"), "{debug}");
    assert!(debug.contains("cursor sync: mode"), "{debug}");
    assert!(
        debug.contains("to=\"camera\"") || debug.contains("to=camera"),
        "{debug}"
    );
    assert!(
        debug.contains("cursor sync "),
        "the aggregate line: {debug}"
    );
    assert!(debug.contains("resid_max_px"), "{debug}");
    assert!(!debug.contains("exact move"), "a move at debug:\n{debug}");

    let trace = logged(tracing::Level::TRACE, || {
        let mut r = Rig::new(144);
        r.frame((3.0, 1.0), None);
        r.frame((3.0, 1.0), Some((100, 100)));
    });
    assert!(trace.contains("cursor sync: exact move"), "{trace}");
}

/// `m` per path and the router's ordering waits (a button that waited for an `m` to show) are in
/// the per-second line; no `m` is said at `debug` on its own.
#[test]
fn m_and_order_waits_are_aggregated_never_debugged_one_by_one() {
    let debug = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new(144);
        for i in 0..30 {
            r.sim.advance(FRAME);
            let p = (1000 + i, 900);
            m(&mut r, p, p, RelPath::Hid);
        }
        for _ in 0..3 {
            r.sim.advance(FRAME);
            m(&mut r, (700, 700), (700, 700), RelPath::SendInput);
        }
        let now = r.sim.now;
        r.sync.order_waited(Duration::from_micros(1800), false, now);
        r.sync.order_waited(Duration::from_millis(8), true, now);
        r.sync.release(r.sim.now);
    });
    let lines: Vec<&str> = debug
        .lines()
        .filter(|l| l.contains("cursor sync "))
        .collect();
    assert_eq!(lines.len(), 1, "{debug}");
    for field in [
        "m_hid=30",
        "m_sendinput=3",
        "order_waits=2",
        "order_wait_max_ms=8.0",
        "order_timeouts=1",
    ] {
        assert!(lines[0].contains(field), "{field}: {debug}");
    }
    assert!(!debug.contains("absolute position"), "{debug}");

    let trace = logged(tracing::Level::TRACE, || {
        let mut r = Rig::new(144);
        r.sim.advance(FRAME);
        m(&mut r, (10, 10), (10, 10), RelPath::Hid);
    });
    assert!(
        trace.contains("cursor sync: absolute position (m)"),
        "{trace}"
    );
}

/* ── Game-only mode: the game's client area as the space ── */

/// A windowed game on the 3600×2400 screen: its client area 3576×2268 at +12+47 (the title bar and
/// borders around it are not the picture the viewer sees).
const CLIENT: Space = Space {
    left: 12,
    top: 47,
    width: 3576,
    height: 2268,
};

/// The mapping: a fraction of the picture is the same fraction of the client area, offset by where
/// it is on screen — every pixel of it, the corners, out-of-range fractions clamped to it, and a
/// window partly off the screen clamped to the screen.
#[test]
fn a_point_of_the_game_picture_maps_into_the_client_area() {
    let map = |t: V| map_point(t, Some(CLIENT), 3600, 2400);
    assert_eq!(map((0.0, 0.0)), (12, 47), "the client area's first pixel");
    assert_eq!(map((1.0, 1.0)), (3587, 2314), "its last");
    assert_eq!(map((0.5, 0.5)), (12 + 1788, 47 + 1134));
    assert_eq!(map((0.25, 0.75)), (12 + 894, 47 + 1701));
    assert_eq!(map((-0.5, 1.5)), (12, 2314), "clamped to the area");
    assert_eq!(map((f64::NAN, 0.0)), (12, 47), "not a number: its origin");
    // The viewer's pixel centres, column by column and row by row, land on their own pixel.
    for p in 0..CLIENT.width {
        let t = ((f64::from(p) + 0.5) / f64::from(CLIENT.width), 0.5);
        assert_eq!(map(t).0, 12 + p, "column {p}");
    }
    for p in 0..CLIENT.height {
        let t = (0.5, (f64::from(p) + 0.5) / f64::from(CLIENT.height));
        assert_eq!(map(t).1, 47 + p, "row {p}");
    }
    // Report 4 onto a mapped pixel lands on it (Windows' `floor(X · width / 32768)`).
    for t in [(0.0, 0.0), (1.0, 1.0), (0.5, 0.5), (0.123, 0.987)] {
        let (px, py) = map(t);
        let (x, y) = absolute_wire(px, py, 3600, 2400);
        assert_eq!(
            (
                (i64::from(x) * 3600 / 32768) as i32,
                (i64::from(y) * 2400 / 32768) as i32
            ),
            (px, py)
        );
    }
    // Partly off the screen (the absolute paths reach the primary monitor only): cut to it.
    let off = Space {
        left: -100,
        top: 2000,
        width: 1000,
        height: 1000,
    };
    assert_eq!(map_point((0.0, 1.0), Some(off), 3600, 2400), (0, 2399));
    assert_eq!(map_point((1.0, 0.0), Some(off), 3600, 2400), (899, 2000));
    // Entirely off it: the whole screen rather than nowhere.
    let gone = Space {
        left: 5000,
        top: 0,
        width: 100,
        height: 100,
    };
    assert_eq!(target_bounds(Some(gone), 3600, 2400), (0, 0, 3599, 2399));
    // No space: exactly today's pixel.
    for t in [(0.0, 0.0), (0.5, 0.5), (0.9999, 0.3)] {
        assert_eq!(map_point(t, None, 3600, 2400), target_pixel(t, 3600, 2400));
    }
    assert_eq!(Space::from_edges(12, 47, 3588, 2315), Some(CLIENT));
    assert_eq!(Space::from_edges(10, 10, 10, 20), None);
}

/// `m` and a point move (`r` with `x`, `y`) put the cursor on the mapped pixel through report 4.
#[test]
fn in_game_only_mode_m_and_point_moves_land_in_the_client_area() {
    let mut r = Rig::new(144);
    r.sync.set_space(Some(CLIENT), r.sim.now);
    for (t, want) in [
        ((0.5, 0.5), (1800, 1181)),
        ((0.0, 0.0), (12, 47)),
        ((1.0, 1.0), (3587, 2314)),
    ] {
        r.sim.advance(FRAME);
        let now = r.sim.now;
        let (px, py, width, height) = r.sync.absolute(t, RelPath::Hid, &mut r.sim, now).unwrap();
        assert_eq!((px, py, width, height), (want.0, want.1, 3600, 2400));
        let (x, y) = absolute_wire(px, py, width, height);
        r.sim.send_absolute_wire(x, y);
        assert_eq!(r.settled(), want);
    }
    r.sim.advance(FRAME);
    let plan = r.send_event(RelEvent {
        dx: 0.0,
        dy: 0.0,
        x: Some(0.25),
        y: Some(0.75),
        s: None,
    });
    assert_eq!(
        plan,
        Plan::Absolute {
            px: 906,
            py: 1748,
            width: 3600,
            height: 2400
        }
    );
    assert_eq!(r.settled(), (906, 1748));
}

/// The trackpad's exact moves keep the cursor in the client area: pushing past its edge stops at the
/// edge (not the screen's), and a cursor found outside it — on the title bar — is brought in.
#[test]
fn in_game_only_mode_the_cursor_is_kept_in_the_client_area() {
    let mut r = Rig::new(144);
    r.sync.set_space(Some(CLIENT), r.sim.now);
    r.sim.warp(3500, 1000);
    for _ in 0..30 {
        r.frame((20.0, 0.0), None);
    }
    let end = r.settled();
    assert!(
        (end.0 - 3587).abs() <= 1,
        "the client's right edge, not the screen's: {end:?}"
    );
    for _ in 0..3 {
        r.frame((-10.0, 0.0), None);
    }
    let back = r.settled();
    assert!(
        (f64::from(back.0) - (3587.0 - 30.0 * 3576.0 / 3600.0)).abs() <= 1.5,
        "the way back starts at once: {back:?}"
    );
    for _ in 0..40 {
        r.frame((-15.0, -40.0), None);
    }
    let corner = r.settled();
    assert!(
        (corner.1 - 47).abs() <= 1,
        "the client's top edge, above it the title bar: {corner:?}"
    );

    // The cursor on the title bar (the PC's own mouse put it there): moves bring it in.
    r.sim.warp(600, 20);
    for _ in 0..20 {
        r.frame((2.0, 0.0), None);
    }
    let inside = r.settled();
    assert!(inside.1 >= 46, "brought into the client area: {inside:?}");

    // A drag (a button held, the pointer's target moving) out past the corner: the aim stops at the
    // client area's corner, and so does the cursor.
    r.sim.warp(3400, 2200);
    r.frame((1.0, 1.0), None);
    r.held = true;
    for i in 1..=30 {
        let p = ((3400 + 20 * i).min(3599), (2200 + 20 * i).min(2399));
        r.frame((20.0, 20.0), Some(p));
        let aim = r.sync.aim.unwrap();
        assert!(
            (12.0..=3587.0).contains(&aim.0) && (47.0..=2314.0).contains(&aim.1),
            "frame {i}: the aim {aim:?} left the client area"
        );
    }
    assert_eq!(r.sync.aim, Some((3587.0, 2314.0)));
    let dragged = r.settled();
    assert!(
        (dragged.0 - 3587).abs() <= 2 && (dragged.1 - 2314).abs() <= 2,
        "the drag ends at the client area's corner: {dragged:?}"
    );
}

/// The hand's `dx` is a fraction of the picture: in a small window it moves the cursor that share
/// of the window, not of the screen. The camera's counts are not touched.
#[test]
fn in_game_only_mode_the_hand_is_a_fraction_of_the_client_area_and_the_camera_is_untouched() {
    let mut r = Rig::new(144);
    let small = Space {
        left: 100,
        top: 100,
        width: 1800,
        height: 1200,
    };
    r.sync.set_space(Some(small), r.sim.now);
    r.sim.warp(500, 500);
    let start = r.settled();
    // A tenth of the picture, as the viewer sends it (a fraction of what it shows).
    let event = RelEvent {
        dx: 0.1,
        dy: 0.0,
        x: None,
        y: None,
        s: None,
    };
    for _ in 0..4 {
        r.sim.advance(FRAME);
        r.send_event(RelEvent {
            dx: event.dx / 4.0,
            ..event
        });
    }
    let end = r.settled();
    assert!(
        (end.0 - start.0 - 180).abs() <= 1,
        "180 px (a tenth of 1800), not 360: {start:?} -> {end:?}"
    );

    // Hidden by the game: the camera's counts, exactly as before (the path's own carry against the
    // physical screen).
    r.sim.showing = false;
    let plan = r.frame((36.0, 0.0), None);
    assert_eq!(plan, Plan::Camera);
    assert_eq!(r.camera_counts.last(), Some(&(36, 0)));
}

/// Where a press would land: the move just sent while it is on its way (a tap is `m`, `d`, `u` back
/// to back), then the cursor itself.
#[test]
fn a_press_is_judged_where_the_move_before_it_puts_the_cursor() {
    let mut r = Rig::new(144);
    r.sim.advance(FRAME);
    let now = r.sim.now;
    let start = r.sim.position();
    r.sync.absolute((0.5, 0.5), RelPath::Hid, &mut r.sim, now);
    assert_eq!(
        r.sync.press_target(&mut r.sim, now),
        Some((1800, 1200)),
        "the `m` is on its way: its pixel, not the cursor's"
    );
    r.sim.advance(Duration::from_millis(50));
    let later = r.sim.now;
    assert_eq!(
        r.sync.press_target(&mut r.sim, later),
        Some(start),
        "long after (nothing was sent to the simulated PC here): where the cursor is"
    );

    // An exact move on its way: its aim.
    r.frame((30.0, 0.0), None);
    let aim = r.sync.aim.unwrap();
    let now = r.sim.now;
    assert_eq!(
        r.sync.press_target(&mut r.sim, now),
        Some((aim.0.round() as i32, aim.1.round() as i32))
    );
    r.sim.unreadable = true;
    r.sim.advance(Duration::from_millis(50));
    let now = r.sim.now;
    assert_eq!(r.sync.press_target(&mut r.sim, now), None, "unreadable");
}

/// The foreground's elevation, for the text's route: looked at afresh, not from the 200 ms cache.
#[test]
fn the_foreground_elevation_is_read_afresh() {
    let mut r = Rig::new(144);
    let now = r.sim.now;
    let e = r.sync.foreground_elevation(&mut r.sim, now).unwrap();
    assert!(!e.blocks_sendinput());
    r.sim.foreground = 0x20;
    r.sim.foreground_elevated = true;
    let e = r.sync.foreground_elevation(&mut r.sim, now).unwrap();
    assert!(e.foreground && !e.agent && e.blocks_sendinput());
    assert_eq!(e.exe, "ScrydeGame.bin");
    r.sim.foreground = 0;
    assert_eq!(r.sync.foreground_elevation(&mut r.sim, now), None);
}

/// The space is said at session start and when it changes, at most once a second (a window being
/// dragged changes it on every move).
#[test]
fn the_coordinate_space_is_said_on_changes_at_most_once_a_second() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new(144);
        let now = r.sim.now;
        r.sync.set_space(Some(CLIENT), now);
        r.sync.set_space(Some(CLIENT), now);
        for i in 0..50 {
            let moved = Space {
                left: 12 + i,
                ..CLIENT
            };
            r.sync
                .set_space(Some(moved), now + FRAME * u32::try_from(i).unwrap());
        }
        r.sync.set_space(None, now + Duration::from_secs(2));
    });
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("coordinate space"))
        .collect();
    assert_eq!(lines.len(), 3, "{log}");
    assert!(lines[0].contains("session start"), "{log}");
    assert!(lines[1].contains("3576x2268 at 12,47"), "{log}");
    assert!(
        lines[2].contains("primary monitor") && lines[2].contains("changes_since_last_line"),
        "{log}"
    );
}

/// The foreground window's exe and elevation are said when it changes — what explains a `SendInput`
/// that cannot reach an elevated window.
#[test]
fn the_foreground_window_is_said_when_it_changes() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new(144);
        r.frame((1.0, 0.0), None);
        r.sim.foreground = 0x20;
        r.sim.foreground_elevated = true;
        r.sim.advance(Duration::from_millis(300));
        r.frame((1.0, 0.0), None);
        r.frame((1.0, 0.0), None);
    });
    let changes: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("foreground window changed"))
        .collect();
    assert_eq!(changes.len(), 2, "{log}");
    assert!(changes[1].contains("ScrydeGame.bin"), "{log}");
    assert!(changes[1].contains("elevated=true"), "{log}");
}

/// A change of the cursor's visibility is said with the mouse buttons held then on either path and
/// the HID router's last button change — a cursor hidden with nothing held is a button the game still
/// thinks down; the session's first look and an unchanged one say nothing.
#[test]
fn a_change_of_the_cursors_visibility_is_said_with_the_buttons_held() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new(144);
        let now = r.sim.now;
        r.sync.note_visibility(true, 0, now);
        r.sync.note_visibility(true, 0, now + FRAME);
        r.sync.hid_buttons(2, Some((2, true, now + FRAME)));
        r.sync.note_visibility(false, 0, now + FRAME * 2);
        r.sync.hid_buttons(0, Some((2, false, now + FRAME * 3)));
        // The right button is up, the cursor still hidden: what a missed release looks like.
        r.sync.note_visibility(false, 1, now + FRAME * 4);
        r.sync.hid_buttons(0, None);
        r.sync.note_visibility(true, 1, now + FRAME * 5);
    });
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("cursor visibility changed"))
        .collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(
        lines[0].contains("visible=false")
            && lines[0].contains("buttons_held=right")
            && lines[0].contains("last_hid_button=right down"),
        "{log}"
    );
    assert!(
        lines[1].contains("visible=true")
            && lines[1].contains("buttons_held=left")
            && lines[1].contains("sendinput=left")
            && lines[1].contains("last_hid_button=right up"),
        "{log}"
    );
    assert_eq!(hid_button_names(0), "-");
    assert_eq!(hid_button_names(7), "left+right+middle");
}

// The moves a cursor report may acknowledge (`CursorSync::unshown`): only those the cursor shows,
// so the viewer's marker never steps back by a move.

/// A numbered move is not shown while its report is on its way: right after the send and 1 ms
/// later the cursor report must not claim it; 2 ms after it the cursor shows it, and it may.
#[test]
fn a_move_does_not_show_until_the_cursor_shows_it() {
    let mut r = Rig::new(144);
    r.next_s = Some(0);
    for k in 0..30u32 {
        r.sim.advance(FRAME);
        let plan = r.send((15.0, 0.0), None);
        assert!(matches!(plan, Plan::Relative { .. }), "{plan:?}");
        assert_eq!(r.unshown(), Some(k), "move {k} just sent");
        r.sim.advance(Duration::from_millis(1));
        assert_eq!(r.unshown(), Some(k), "move {k}, 1 ms after its report");
        r.sim.advance(Duration::from_millis(2));
        assert_eq!(r.unshown(), None, "move {k} shows 2 ms after its report");
    }
    // The point move (report 4) is waited for the same way.
    r.sim.advance(FRAME);
    let plan = r.send((1.0, 0.0), Some((2500, 700)));
    assert!(matches!(plan, Plan::Absolute { .. }), "{plan:?}");
    assert_eq!(r.unshown(), Some(30));
    r.sim.drain();
    assert_eq!(r.unshown(), None);
}

/// A stroke polled as the cursor report polls it — a move every 16 ms, a poll every 33 ms — on a PC
/// that shows a report 2 ms after it (as measured) and on a slow one that shows it 25 ms after (two moves in
/// flight at once): at every poll, every move below the answer has shown on the cursor and the move
/// it names has not; with no answer, every move sent has shown. Polls do land in the window
/// (about one in eight at 2 ms: the step back the viewer saw).
#[test]
fn every_poll_names_exactly_the_first_move_the_cursor_does_not_show() {
    for delay_ms in [2, 25] {
        let mut r = Rig::with(144, |sim| sim.delay = Duration::from_millis(delay_ms));
        r.next_s = Some(0);
        let (mut sent, mut in_window, mut polls) = (0u32, 0u32, 0u32);
        for t in 1..=2000u32 {
            r.sim.advance(Duration::from_millis(1));
            if t % 16 == 0 {
                let plan = r.send((15.0, 0.0), None);
                assert!(matches!(plan, Plan::Relative { .. }), "{plan:?}");
                sent += 1;
            }
            if t % 33 == 1 {
                polls += 1;
                let answer = r.unshown();
                let shown = u32::try_from(r.sim.applied.len()).unwrap();
                match answer {
                    Some(u) => {
                        assert_eq!(u, shown, "{delay_ms} ms, at {t} ms: {shown} shown");
                        assert!(u < sent);
                        in_window += 1;
                    }
                    None => assert_eq!(shown, sent, "{delay_ms} ms, at {t} ms"),
                }
            }
        }
        assert!(
            in_window * 16 >= polls,
            "{delay_ms} ms: {in_window} of {polls} polls found a move on its way"
        );
    }
}

/// The limit: a move Windows never shows — it ate it (UIPI over an elevated window; the screen's
/// edge) — is taken as shown 40 ms after its report, like the planner's own books take it.
#[test]
fn a_move_the_cursor_never_shows_is_given_up_after_40_ms() {
    let mut r = Rig::new(144);
    r.next_s = Some(0);
    r.frame((10.0, 0.0), None);
    r.sim.drain();
    assert_eq!(r.unshown(), None);
    r.sim.deaf = true;
    r.sim.advance(FRAME);
    r.send((10.0, 0.0), None);
    assert_eq!(r.unshown(), Some(1));
    r.sim.advance(REFLECT_TIMEOUT - Duration::from_millis(1));
    assert_eq!(r.unshown(), Some(1), "39 ms: still waited for");
    r.sim.advance(Duration::from_millis(1));
    assert_eq!(r.unshown(), None, "40 ms: given up");
}

/// Windows or a game changing the move: the cursor moving otherwise than the move says (a game
/// warping it; Windows moving it half as far as the model says) is the move having shown; a game
/// hiding the cursor for a camera turn takes every move in flight off the books — nothing is waited
/// for.
#[test]
fn a_move_changed_on_its_way_or_a_hidden_cursor_is_not_waited_for() {
    let mut r = Rig::new(144);
    r.next_s = Some(0);
    r.frame((15.0, 0.0), None);
    r.sim.warp(2000, 1500);
    assert_eq!(
        r.unshown(),
        None,
        "the cursor moved: the move counts as shown"
    );
    r.sim.drain();

    r.sim.extra_gain = 0.5;
    r.sim.advance(FRAME);
    r.send((30.0, 0.0), None);
    assert_eq!(r.unshown(), Some(1));
    r.sim.drain();
    assert_eq!(r.unshown(), None, "half as far, and shown");
    r.sim.extra_gain = 1.0;

    // The game hides the cursor (a camera turn): the next move is the camera's, and nothing in
    // flight is waited for any more.
    r.sim.advance(FRAME);
    r.send((15.0, 0.0), None);
    assert_eq!(r.unshown(), Some(2));
    r.sim.showing = false;
    let plan = r.send((15.0, 0.0), None);
    assert_eq!(plan, Plan::Camera);
    assert_eq!(r.unshown(), None);
}

/// A move the HID router queued behind a click or a key does not show until the router sends it:
/// waited for while queued, then while in flight; given up after 250 ms in the queue (a queue
/// dropped without a release the planner heard of), and dropped with a release.
#[test]
fn a_queued_move_is_waited_for_until_it_shows() {
    let mut r = Rig::new(144);
    let now = r.sim.now;
    r.sync.queued(5, now);
    r.sync.queued(6, now);
    assert_eq!(r.unshown(), Some(5));
    r.sim.advance(Duration::from_millis(30));
    assert_eq!(r.unshown(), Some(5), "30 ms: a tap's minimum hold");
    // The router sends them now: out of the queue, in flight.
    r.next_s = Some(5);
    r.send((10.0, 0.0), None);
    assert_eq!(r.unshown(), Some(5), "in flight");
    r.send((10.0, 0.0), None);
    assert_eq!(r.unshown(), Some(5));
    assert!(r.sync.queued.is_empty());
    r.sim.drain();
    assert_eq!(r.unshown(), None, "both shown");

    // Never sent: given up after the bound.
    r.sync.queued(9, r.sim.now);
    r.sim.advance(QUEUED_MAX - Duration::from_millis(1));
    assert_eq!(r.unshown(), Some(9));
    r.sim.advance(Duration::from_millis(1));
    assert_eq!(r.unshown(), None);
    assert_eq!(r.sync.stats.queued_expired, 1);

    // Dropped with the router's queue on a release.
    r.sync.queued(12, r.sim.now);
    assert_eq!(r.unshown(), Some(12));
    r.sync.release(r.sim.now);
    assert_eq!(r.unshown(), None);
}

/// A viewer that numbers no moves, and the `m` the planner keeps books for: nothing is numbered, so
/// nothing holds the report back, in flight or not. A numbered move behind an `m` in flight is
/// waited for until both have shown.
#[test]
fn unnumbered_moves_and_m_never_hold_a_report() {
    let mut r = Rig::new(144);
    r.frame((15.0, 0.0), None);
    assert!(!r.sync.pending.is_empty(), "in flight");
    assert_eq!(r.unshown(), None, "an old viewer's move");
    r.sim.drain();
    r.sim.advance(FRAME);
    m(&mut r, (2500, 600), (2500, 600), RelPath::Hid);
    assert_eq!(r.unshown(), None, "an m");
    r.next_s = Some(3);
    r.send((10.0, 0.0), None);
    assert_eq!(r.unshown(), Some(3), "behind the m");
    r.sim.drain();
    assert_eq!(r.unshown(), None);
}

/// The polls that found a move on its way are counted in the per-second line, never said at `debug`
/// one by one; each is at `trace`.
#[test]
fn moves_not_shown_yet_are_aggregated_never_debugged_one_by_one() {
    let stroke = |r: &mut Rig| {
        r.next_s = Some(0);
        for t in 1..=1500u32 {
            r.sim.advance(Duration::from_millis(1));
            if t % 16 == 0 {
                r.send((3.0, 0.0), None);
            }
            if t % 16 == 1 {
                r.unshown();
            }
        }
        r.sync.release(r.sim.now);
    };
    let debug = logged(tracing::Level::DEBUG, || stroke(&mut Rig::new(144)));
    assert!(!debug.contains("does not show yet"), "{debug}");
    let seconds: Vec<&str> = debug
        .lines()
        .filter(|l| l.contains("unshown_polls="))
        .collect();
    assert!(
        seconds.iter().any(|l| !l.contains("unshown_polls=0 ")),
        "{debug}"
    );
    let trace = logged(tracing::Level::TRACE, || stroke(&mut Rig::new(144)));
    assert!(trace.contains("does not show yet"), "{trace}");
}
