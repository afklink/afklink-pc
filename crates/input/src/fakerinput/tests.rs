//! All default tests use an output-only fake: no Windows input or device calls.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::wheel::WheelCarry;
use std::collections::VecDeque;

#[derive(Default)]
struct FakeDriver {
    reports: Vec<Report>,
    failures: VecDeque<bool>,
}

impl Driver for FakeDriver {
    fn write(&mut self, report: &Report) -> Result<()> {
        // Record even a failed write: delivery may have preceded the failure.
        self.reports.push(*report);
        if self.failures.pop_front().unwrap_or(false) {
            bail!("simulated driver refusal");
        }
        Ok(())
    }
}

#[cfg(windows)]
#[test]
fn direct_mouse_matches_ordinary_hid_report_bytes() {
    let mut ordinary = State::new(FakeDriver::default());
    let mut direct = HidMouse::default();
    let mut reports = Vec::new();
    let started = Instant::now();
    for button in [2, 1, 0] {
        ordinary.button(button, true).unwrap();
        direct
            .press(button, |mask| {
                reports.push(mouse(mask, 0, 0, 0, 0));
                Ok(())
            })
            .unwrap();
    }
    ordinary.movement(240, -53).unwrap();
    for (x, y) in HidMouse::motion_reports(240, -53) {
        reports.push(mouse(direct.buttons(), x, y, 0, 0));
    }
    for delta in [-30.0, -160.0, 45.0, 55.0] {
        ordinary.wheel(0.0, delta, WheelMode::Pixel).unwrap();
        let (wheel, pan) = direct.wheel_step(0.0, delta, 0, true, started).unwrap();
        for (w, p) in HidMouse::wheel_reports(wheel, pan) {
            reports.push(mouse(direct.buttons(), 0, 0, w, p));
        }
    }
    for button in [1, 2, 0] {
        ordinary.button(button, false).unwrap();
        direct
            .release([button], |mask| {
                reports.push(mouse(mask, 0, 0, 0, 0));
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(reports, ordinary.driver.reports);
    assert_eq!(reports[0][3], 0x02);
    assert_eq!(reports.last().unwrap()[3], 0);
}

#[test]
fn keyboard_report_matches_native_wrapper_and_physical_keys() {
    let mut state = State::new(FakeDriver::default());
    state.key(key("ControlRight").unwrap(), true).unwrap();
    state.key(key("KeyW").unwrap(), true).unwrap();
    let report = state.driver.reports.last().unwrap();
    assert_eq!(&report[..11], &[0x40, 9, 1, 16, 0, 0x1a, 0, 0, 0, 0, 0]);
    assert!(report[11..].iter().all(|b| *b == 0));
    assert_eq!(key("Enter"), Some(Key::Usage(0x28)));
    assert_eq!(key("NumpadEnter"), Some(Key::Usage(0x58)));
    assert_eq!(key("ArrowUp"), Some(Key::Usage(0x52)));
    assert_eq!(key("ShiftRight"), Some(Key::Modifier(32)));
    assert_eq!(key("KeyQ"), Some(Key::Usage(0x14)));
    assert_eq!(key("IntlBackslash"), Some(Key::Usage(0x64)));
    assert_eq!(key("F13"), None); // Outside the upstream usage range; SendInput fallback.
    assert_eq!(key("Unidentified"), None);
}

#[test]
fn button_layout_and_signed_relative_motion_keep_held_buttons() {
    let mut state = State::new(FakeDriver::default());
    state.button(1, true).unwrap(); // protocol middle -> HID bit 2
    state.button(2, true).unwrap(); // protocol right -> HID bit 1
    state.relative(-0.01, 0.02, 1000, 1000).unwrap();
    assert_eq!(
        &state.driver.reports.last().unwrap()[..10],
        &[0x40, 8, 3, 6, 246, 255, 20, 0, 0, 0]
    );
    state.release().unwrap();
    assert_eq!(
        &state.driver.reports.last().unwrap()[..10],
        &[0x40, 8, 3, 0, 0, 0, 0, 0, 0, 0]
    );
    let count = state.driver.reports.len();
    state.release().unwrap();
    assert_eq!(state.driver.reports.len(), count);
}

#[test]
fn fractional_motion_and_large_steps_preserve_total_delta() {
    let mut state = State::new(FakeDriver::default());
    for _ in 0..10 {
        state.relative(0.0001, -0.0001, 1000, 1000).unwrap();
    }
    state.movement(70_000, -70_000).unwrap();
    let total = state.driver.reports.iter().fold((0i32, 0i32), |(x, y), r| {
        (
            x + i32::from(i16::from_le_bytes([r[4], r[5]])),
            y + i32::from(i16::from_le_bytes([r[6], r[7]])),
        )
    });
    assert_eq!(total, (70_001, -70_001));
    assert!(state
        .driver
        .reports
        .iter()
        .all(|r| i16::from_le_bytes([r[4], r[5]]) != i16::MIN));
}

#[test]
fn non_finite_relative_motion_is_rejected() {
    // Relative motion and the game wheel guard against a non-number that would poison their carry.
    let mut state = State::new(FakeDriver::default());
    assert!(state.relative(f64::NAN, 0.0, 1000, 1000).is_err());
    assert!(state.relative(0.0, f64::INFINITY, 1000, 1000).is_err());
    assert!(state.wheel(f64::NAN, 0.0, WheelMode::Pixel).is_err());
    assert!(state
        .wheel(0.0, f64::NEG_INFINITY, WheelMode::Line)
        .is_err());
    assert!(state.driver.reports.is_empty());
    assert_eq!(state.mouse.wheel_carry(), WheelCarry::default());
}

/// `(buttons, wheel, pan)` of every report so far, checking each is a relative mouse report that
/// moves nothing.
fn wheel_reports(state: &State<FakeDriver>) -> Vec<(u8, i8, i8)> {
    state
        .driver
        .reports
        .iter()
        .map(|r| {
            assert_eq!(&r[..3], &[0x40, 8, 3], "a relative mouse report");
            assert_eq!(&r[4..8], &[0; 4], "a wheel report moves nothing");
            assert!(r[10..].iter().all(|b| *b == 0));
            (r[3], i8::from_le_bytes([r[8]]), i8::from_le_bytes([r[9]]))
        })
        .collect()
}

#[test]
fn a_slow_scroll_turns_the_wheel_once_per_hundred_pixels() {
    // A careful two-finger scroll: ten messages of 10 px each. Rounded one by one it would turn the
    // wheel never (or ten times); carried, it turns once, on the tenth.
    let mut state = State::new(FakeDriver::default());
    for _ in 0..9 {
        state.wheel(0.0, 10.0, WheelMode::Pixel).unwrap();
    }
    assert!(state.driver.reports.is_empty(), "90 px is not a notch yet");
    state.wheel(0.0, 10.0, WheelMode::Pixel).unwrap();
    // dy > 0 scrolls down: HID Wheel -1, as SendInput's `wheelData = -dy`.
    assert_eq!(wheel_reports(&state), vec![(0, -1, 0)]);
    assert_eq!(state.mouse.wheel_carry(), WheelCarry::default());
    // And up.
    state.wheel(0.0, -100.0, WheelMode::Pixel).unwrap();
    assert_eq!(wheel_reports(&state)[1], (0, 1, 0));
}

#[test]
fn a_change_of_direction_does_not_owe_the_old_direction_its_fraction() {
    let mut state = State::new(FakeDriver::default());
    state.wheel(0.0, 90.0, WheelMode::Pixel).unwrap();
    state.wheel(0.0, -60.0, WheelMode::Pixel).unwrap();
    assert!(state.driver.reports.is_empty());
    state.wheel(0.0, -40.0, WheelMode::Pixel).unwrap();
    assert_eq!(
        wheel_reports(&state),
        vec![(0, 1, 0)],
        "100 px back up is one notch up, not 190"
    );
}

#[test]
fn horizontal_scroll_is_ac_pan_and_both_axes_share_a_report() {
    let mut state = State::new(FakeDriver::default());
    state.wheel(250.0, 0.0, WheelMode::Pixel).unwrap();
    assert_eq!(wheel_reports(&state), vec![(0, 0, 2)], "dx > 0 pans right");
    assert!((state.mouse.wheel_carry().pan - 0.5).abs() < 1e-9);
    state.wheel(-3.0, 3.0, WheelMode::Line).unwrap();
    // Left: the change of direction drops the +0.5; three lines are one notch either way.
    assert_eq!(wheel_reports(&state)[1], (0, -1, -1));
    // Pages: five notches each.
    state.wheel(0.0, -1.0, WheelMode::Page).unwrap();
    assert_eq!(wheel_reports(&state)[2], (0, 5, 0));
}

#[test]
fn a_big_turn_is_split_into_reports_of_127_and_a_huge_one_is_clamped() {
    let mut state = State::new(FakeDriver::default());
    state.wheel(0.0, -30_000.0, WheelMode::Pixel).unwrap();
    assert_eq!(
        wheel_reports(&state),
        vec![(0, 127, 0), (0, 127, 0), (0, 46, 0)],
        "300 notches up"
    );
    let mut state = State::new(FakeDriver::default());
    state.wheel(-1e12, 1e12, WheelMode::Pixel).unwrap();
    let reports = wheel_reports(&state);
    assert_eq!(reports.len(), 4, "at most four reports per message");
    let (wheel, pan) = reports.iter().fold((0i32, 0i32), |(w, p), r| {
        (w + i32::from(r.1), p + i32::from(r.2))
    });
    assert_eq!((wheel, pan), (-508, -508));
    assert!(reports.iter().all(|r| r.1 != i8::MIN && r.2 != i8::MIN));
}

#[test]
fn wheel_reports_keep_held_buttons_down() {
    let mut state = State::new(FakeDriver::default());
    state.button(2, true).unwrap(); // right -> HID bit 2
    state.wheel(0.0, 100.0, WheelMode::Pixel).unwrap();
    assert_eq!(wheel_reports(&state)[1], (2, -1, 0));
}

#[test]
fn release_forgets_the_unfinished_notch_and_sends_nothing_for_it() {
    let mut state = State::new(FakeDriver::default());
    state.wheel(0.0, 90.0, WheelMode::Pixel).unwrap();
    state.release().unwrap();
    assert!(
        state.driver.reports.is_empty(),
        "the wheel holds nothing to release"
    );
    assert_eq!(state.mouse.wheel_carry(), WheelCarry::default());
    state.wheel(0.0, 10.0, WheelMode::Pixel).unwrap();
    assert!(
        state.driver.reports.is_empty(),
        "the next gesture starts from zero"
    );
}

#[test]
fn a_failed_wheel_report_is_not_replayed() {
    let mut state = State::new(FakeDriver::default());
    state.driver.failures.push_back(true);
    assert!(state.wheel(0.0, 100.0, WheelMode::Pixel).is_err());
    assert!(state.failed);
    state.release().unwrap();
    assert_eq!(
        state.driver.reports.len(),
        1,
        "no neutral report, no replay"
    );
}

#[test]
fn the_wheel_path_log_tells_a_path_change_from_a_reason_change() {
    let t0 = Instant::now();
    let mut log = PathLog::new("wheel");
    assert_eq!(log.note(Via::SendInput, "desktop", t0), Change::Path);
    assert_eq!(log.note(Via::SendInput, "desktop", t0), Change::Same);
    let ms = |n| t0 + Duration::from_millis(n);
    assert_eq!(log.note(Via::Hid, "game", ms(10)), Change::Path);
    assert_eq!(log.note(Via::Hid, "game", ms(20)), Change::Same);
    // Same path, another reason: logged, and told apart from a path change.
    assert_eq!(log.note(Via::Hid, "game again", ms(30)), Change::Reason);
    assert_eq!(
        log.note_about(Via::Hid, "game again", Some("Taskmgr.exe"), ms(35)),
        Change::Same,
        "another foreground window alone is not a change"
    );
    assert_eq!(log.note(Via::SendInput, "blocked", ms(40)), Change::Path);
    // Three changes inside the quiet window went to trace and are counted for the next line.
    assert_eq!(log.quiet, 3);
    assert_eq!(
        log.note(Via::Hid, "game", t0 + Duration::from_secs(3)),
        Change::Path
    );
    assert_eq!(log.quiet, 0);
}

#[test]
fn release_helpers_report_who_holds_each_key_and_button() {
    // Releases are routed to the path that pressed: these are the checks that routing uses.
    let mut state = State::new(FakeDriver::default());
    state.key(key("KeyA").unwrap(), true).unwrap();
    state.key(key("ShiftLeft").unwrap(), true).unwrap();
    state.key(key("AudioVolumeUp").unwrap(), true).unwrap();
    state.button(2, true).unwrap();
    assert!(state.holds_key(key("KeyA").unwrap()));
    assert!(state.holds_key(key("ShiftLeft").unwrap()));
    assert!(state.holds_key(key("AudioVolumeUp").unwrap()));
    assert!(!state.holds_key(key("KeyB").unwrap()));
    assert!(state.holds_button(2));
    assert!(!state.holds_button(0));
    assert!(!state.holds_button(9)); // an unsupported id is held by no one
}

#[test]
fn usage_overflow_is_detected_only_past_six_distinct_keys() {
    let mut state = State::new(FakeDriver::default());
    for usage in 4..10 {
        assert!(!state.usage_overflows(usage));
        state.key(Key::Usage(usage), true).unwrap();
    }
    assert!(state.usage_overflows(10)); // a genuinely new seventh key overflows
    assert!(!state.usage_overflows(4)); // a repeat of a held key never overflows
}

#[test]
fn sixth_key_is_preserved_when_seventh_is_rejected() {
    let mut state = State::new(FakeDriver::default());
    for usage in 4..10 {
        state.key(Key::Usage(usage), true).unwrap();
    }
    state.key(Key::Modifier(2), true).unwrap();
    let count = state.driver.reports.len();
    assert!(state.key(Key::Usage(10), true).is_err());
    assert_eq!(state.driver.reports.len(), count);
    assert_eq!(state.held.keys.len(), 6);
    state.key(Key::Usage(4), false).unwrap();
    state.key(Key::Usage(10), true).unwrap();
    state.release().unwrap();
    assert_eq!(&state.driver.reports.last().unwrap()[3..11], &[0; 8]);
}

#[test]
fn system_sequences_are_rejected_regardless_of_press_order() {
    for delete in [0x4c, 0x63] {
        for sequence in [
            [Key::Modifier(1), Key::Modifier(64), Key::Usage(delete)],
            [Key::Usage(delete), Key::Modifier(64), Key::Modifier(1)],
        ] {
            let mut state = State::new(FakeDriver::default());
            state.key(sequence[0], true).unwrap();
            state.key(sequence[1], true).unwrap();
            assert!(state.key(sequence[2], true).is_err());
            assert_eq!(state.driver.reports.len(), 2);
            state.release().unwrap();
        }
    }
    let mut state = State::new(FakeDriver::default());
    state.key(key("KeyL").unwrap(), true).unwrap();
    assert!(state.key(key("MetaRight").unwrap(), true).is_err());
}

#[test]
fn failed_down_and_up_remain_pending_until_neutral_succeeds() {
    let mut state = State::new(FakeDriver::default());
    state.driver.failures.push_back(true);
    assert!(state.key(Key::Usage(4), true).is_err());
    assert!(state.held.dirty_keyboard);
    state.driver.failures.push_back(true);
    assert!(state.release().is_err());
    assert!(state.held.dirty_keyboard);
    state.release().unwrap();
    assert!(!state.held.dirty_keyboard);
    assert!(!state.failed);
    state.key(Key::Modifier(1), true).unwrap();
    state.driver.failures.push_back(true);
    assert!(state.key(Key::Modifier(1), false).is_err());
    assert_eq!(state.held.modifiers, 1);
    state.release().unwrap();
    assert_eq!(state.held.modifiers, 0);
}

#[test]
fn cleanup_attempts_every_report_family_even_after_failure() {
    let mut state = State::new(FakeDriver::default());
    state.key(Key::Usage(4), true).unwrap();
    state.key(key("AudioVolumeDown").unwrap(), true).unwrap();
    assert_eq!(
        &state.driver.reports.last().unwrap()[..6],
        &[0x40, 4, 2, 32, 0, 0]
    );
    state.button(0, true).unwrap();
    state.driver.failures.extend([true, false, false]);
    assert!(state.release().is_err());
    assert!(state.held.dirty_keyboard);
    assert!(!state.held.dirty_media);
    assert!(!state.held.dirty_mouse);
    assert_eq!(state.driver.reports.len(), 6);
    state.release().unwrap();
    assert_eq!(state.driver.reports.len(), 7);
    state.release().unwrap();
    assert_eq!(state.driver.reports.len(), 7);
}

#[test]
fn failed_move_is_not_replayed_by_cleanup() {
    let mut state = State::new(FakeDriver::default());
    state.button(2, true).unwrap();
    state.driver.failures.push_back(true);
    assert!(state.movement(50_000, 0).is_err());
    state.release().unwrap();
    assert_eq!(state.driver.reports.len(), 3);
    assert_eq!(&state.driver.reports.last().unwrap()[3..10], &[0; 7]);
}

#[test]
fn idle_cleanup_emits_nothing() {
    let mut state = State::new(FakeDriver::default());
    state.relative(0.0001, 0.0, 1000, 1000).unwrap();
    state.release().unwrap();
    assert!(state.driver.reports.is_empty());
    assert_eq!(state.rel, RelCarry::default());
}

#[test]
fn fakerinput_collections_are_recognised_by_ids_and_caps() {
    use Collection::*;
    const VID: u16 = 0xfe0f;
    const PID: u16 = 0x00ff;
    // FakerInput 0.1.1 as the owner's PC enumerates it (ROOT\SYSTEM\0003, HID\SYSTEM&COL01..06):
    // keyboard, consumer control, two mice, then the two vendor collections.
    let driver = [
        ((0x0001, 0x0006, 0), Other),
        ((0x000c, 0x0001, 0), Other),
        ((0x0001, 0x0002, 0), Other),
        ((0x0001, 0x0002, 0), Other),
        ((0xff00, 0x0001, 65), Control),
        ((0xff00, 0x0002, 65), Api),
    ];
    for ((page, usage, out), want) in driver {
        assert_eq!(
            classify(VID, PID, page, usage, out),
            want,
            "{page:04x}:{usage:04x}"
        );
    }
    // The same usages under anyone else's VID/PID are not ours — a vendor-defined collection of a
    // real headset or keyboard is never opened for writing.
    for (vid, pid) in [(0x046d, 0xc52b), (VID, 0x0100), (0xfe0e, PID), (0, 0)] {
        assert!(!is_fakerinput(vid, pid), "{vid:04x}:{pid:04x}");
        assert_eq!(classify(vid, pid, 0xff00, 1, 65), Foreign);
        assert_eq!(classify(vid, pid, 0xff00, 2, 65), Foreign);
        assert_eq!(classify(vid, pid, 0x0001, 6, 0), Foreign);
    }
    assert!(is_fakerinput(VID, PID));
    // A vendor collection with another output length: a driver this client does not speak to.
    assert_eq!(classify(VID, PID, 0xff00, 1, 64), Incompatible);
    assert_eq!(classify(VID, PID, 0xff00, 2, 0), Incompatible);
    // Other usages on the vendor page, and the vendor usages on another page, are neither.
    assert_eq!(classify(VID, PID, 0xff00, 3, 65), Other);
    assert_eq!(classify(VID, PID, 0xff01, 1, 65), Other);
    assert_eq!(classify(VID, PID, 0x0001, 1, 65), Other);
    // The names the probe's log line uses.
    for (kind, name) in [
        (Foreign, "foreign"),
        (Other, "other"),
        (Control, "control"),
        (Api, "api"),
        (Incompatible, "incompatible"),
    ] {
        assert_eq!(kind.name(), name);
    }
}

#[cfg(windows)]
#[test]
#[ignore = "read-only probe of installed Windows hardware; sends no input"]
fn probe_installed_driver_without_input() -> Result<()> {
    // What discovery sees, collection by collection: FakerInput's are found by the VID/PID its
    // attributes report and by their caps, never by the interface path (a root-enumerated device's
    // path carries no VID/PID). Zero-access opens only; nothing is opened for writing here.
    let survey = platform::survey()?;
    eprintln!(
        "HID interfaces: {} (not opened {}, attributes unreadable {}, no path {}); FakerInput's: {}",
        survey.interfaces, survey.unopened, survey.unreadable, survey.pathless, survey.ours
    );
    for found in &survey.collections {
        eprintln!(
            "  {:04x}:{:04x} output={:<3} {:<12} {}",
            found.usage_page,
            found.usage,
            found.output_len,
            found.kind.name(),
            found.path()
        );
    }
    // Opens the two vendor collections and reads the API feature; writes no report.
    let available = crate::fakerinput_available()?;
    eprintln!("FakerInput compatible device available: {available}");
    // Construction and Drop must be neutral when no input was injected.
    let _selected = crate::create_input_injector();
    Ok(())
}

/// A move toward pixel `target` of the simulated 3600×2400 screen (the viewer's pointer inside it),
/// with the hand's `dx` in px.
fn rel_toward(dx_px: f64, target: Option<(i32, i32)>) -> InputMessage {
    InputMessage::Rel {
        dx: dx_px / 3600.0,
        dy: 0.0,
        s: None,
        x: target.map(|t| (f64::from(t.0) + 0.5) / 3600.0),
        y: target.map(|t| (f64::from(t.1) + 0.5) / 2400.0),
    }
}

/// Every report of this id the device got.
fn reports_with_id(h: &fake::Harness, id: u8) -> Vec<Report> {
    h.world()
        .log
        .iter()
        .filter_map(|(_, out)| match out {
            fake::Out::Report(r) if r[0] == 0x40 && r[2] == id => Some(*r),
            _ => None,
        })
        .collect()
}

/// The HID path moves as the cursor-sync planner says: a visible cursor with a target and no button
/// goes onto the pointer's pixel with the absolute report (report 4, buttons 0); with a button held
/// it moves by relative reports that carry the button, 20 px of hand being 20 px of cursor at 150 %.
#[test]
fn hid_moves_go_where_the_cursor_sync_planner_says() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(rel_toward(4.0, Some((2188, 1372)))).unwrap();
    let absolute = reports_with_id(&h, 4);
    assert_eq!(absolute.len(), 1);
    let (x, y) = absolute_wire(2188, 1372, 3600, 2400);
    let [xl, xh] = x.to_le_bytes();
    let [yl, yh] = y.to_le_bytes();
    assert_eq!(absolute[0][..10], [0x40, 7, 4, 0, xl, xh, yl, yh, 0, 0]);
    assert!(absolute[0][10..].iter().all(|b| *b == 0));
    assert!(
        reports_with_id(&h, 3).is_empty(),
        "no relative report for a point move"
    );
    assert_eq!(h.cursor_at(), (2188, 1372));

    h.button(0, true).unwrap();
    for i in 1..=5 {
        h.at(16 + 16 * i);
        let step = i32::try_from(i).unwrap() * 20;
        h.inject(rel_toward(20.0, Some((2188 + step, 1372))))
            .unwrap();
    }
    assert_eq!(
        reports_with_id(&h, 4).len(),
        1,
        "no absolute report while a button is held"
    );
    let moves: Vec<Report> = reports_with_id(&h, 3)
        .into_iter()
        .filter(|r| r[4..8] != [0; 4])
        .collect();
    assert_eq!(moves.len(), 5, "one relative report per move");
    assert!(
        moves.iter().all(|r| r[3] == 1),
        "the held button rides along"
    );
    let at = h.cursor_at();
    assert!((at.0 - 2288).abs() <= 1 && at.1 == 1372, "{at:?}");

    // The button up: the next move points again.
    h.at(200);
    h.button(0, false).unwrap();
    h.at(216);
    h.inject(rel_toward(1.0, Some((100, 2000)))).unwrap();
    assert_eq!(reports_with_id(&h, 4).len(), 2);
    assert_eq!(h.cursor_at(), (100, 2000));
}

/// A hidden cursor — a game turning its camera — gets the camera's relative counts exactly as before
/// the planner: the fraction times the screen, the remainder carried, whatever target rides along.
#[test]
fn a_hidden_cursor_moves_the_hid_camera_exactly_as_before() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.world().cursor.as_mut().unwrap().sim.showing = false;
    let deltas = [
        (0.0137, -0.0022),
        (0.0004, 0.0004),
        (-0.00725, 0.0011),
        (0.031, 0.0),
        (0.0002, 0.0003),
        (0.0002, 0.0003),
    ];
    let mut reference = RelCarry::default();
    let mut want = Vec::new();
    for (i, (dx, dy)) in deltas.into_iter().enumerate() {
        h.at(16 * (u64::try_from(i).unwrap() + 1));
        h.inject(InputMessage::Rel {
            dx,
            dy,
            s: None,
            x: Some(0.5),
            y: Some(0.5),
        })
        .unwrap();
        let (x, y) = reference.step(dx, dy, 1000, 1000);
        if (x, y) != (0, 0) {
            want.push((i16::try_from(x).unwrap(), i16::try_from(y).unwrap()));
        }
    }
    let got: Vec<(i16, i16)> = h
        .world()
        .mouse_reports()
        .into_iter()
        .map(|(_, _, x, y, _)| (x, y))
        .collect();
    assert_eq!(got, want);
    assert!(reports_with_id(&h, 4).is_empty());
}

#[test]
fn the_absolute_report_has_upstreams_layout() {
    let mut state = State::new(FakeDriver::default());
    state.absolute(2188, 1372, 3600, 2400).unwrap();
    let report = state.driver.reports.last().unwrap();
    let (x, y) = absolute_wire(2188, 1372, 3600, 2400);
    assert_eq!((x, y), (19920, 18739));
    assert_eq!(report[..10], [0x40, 7, 4, 0, 0xd0, 0x4d, 0x33, 0x49, 0, 0]);
    assert!(report[10..].iter().all(|b| *b == 0));
    assert!(
        state.absolute(1, 1, 0, 2400).is_err(),
        "no screen, no report"
    );
    assert_eq!(state.driver.reports.len(), 1);
}

// The viewer's absolute position (`m`) through the driver.

/// An `m` onto the centre of pixel `p` of the simulated 3600×2400 screen.
fn m_at(p: (i32, i32)) -> InputMessage {
    InputMessage::Move {
        x: (f64::from(p.0) + 0.5) / 3600.0,
        y: (f64::from(p.1) + 0.5) / 2400.0,
    }
}

/// The device's mouse side, in order: `a` an absolute report, `b<bits>` a button change, `r` a
/// relative move, `w…` a wheel turn.
fn mouse_line(h: &fake::Harness) -> Vec<(u64, String)> {
    h.world()
        .device_timeline()
        .into_iter()
        .filter(|(_, what)| !what.starts_with('k'))
        .collect()
}

fn line(entries: &[(u64, &str)]) -> Vec<(u64, String)> {
    entries.iter().map(|&(at, s)| (at, s.to_owned())).collect()
}

fn sent_moves(h: &fake::Harness) -> usize {
    h.world()
        .count(|o| matches!(o, fake::Out::SendInput(InputMessage::Move { .. })))
}

/// Where HID may go, `m` is FakerInput's absolute report onto the pixel's centre — the point move's
/// report, byte for byte, buttons 0 — and nothing goes by SendInput; it lands on the pixel, edges
/// included.
#[test]
fn m_goes_as_report_4_onto_the_pixels_centre_where_hid_may_go() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(m_at((2188, 1372))).unwrap();
    let absolute = reports_with_id(&h, 4);
    assert_eq!(absolute.len(), 1);
    let (x, y) = absolute_wire(2188, 1372, 3600, 2400);
    let [xl, xh] = x.to_le_bytes();
    let [yl, yh] = y.to_le_bytes();
    assert_eq!(absolute[0][..10], [0x40, 7, 4, 0, xl, xh, yl, yh, 0, 0]);
    assert!(absolute[0][10..].iter().all(|b| *b == 0));
    assert_eq!(sent_moves(&h), 0, "nothing by SendInput");
    assert!(reports_with_id(&h, 3).is_empty(), "no relative report");
    assert_eq!(h.cursor_at(), (2188, 1372));

    // The edges, and fractions on a pixel's left edge or at the very end of the screen.
    let mut t = 16;
    for (m, want) in [
        (m_at((0, 0)), (0, 0)),
        (m_at((3599, 2399)), (3599, 2399)),
        (InputMessage::Move { x: 1.0, y: 1.0 }, (3599, 2399)),
        (InputMessage::Move { x: 0.25, y: 0.5 }, (900, 1200)),
        (InputMessage::Move { x: -0.5, y: 7.0 }, (0, 2399)),
    ] {
        t += 16;
        h.at(t);
        h.inject(m).unwrap();
        assert_eq!(h.cursor_at(), want);
    }
    assert_eq!(sent_moves(&h), 0);
}

/// Where HID may not go — the secure desktop, the lock screen, another session, a desktop that could
/// not be identified — `m` is today's SendInput event, and no absolute report is written.
#[test]
fn m_goes_by_sendinput_where_hid_may_not_go() {
    for target in [Target::Blocked, Target::Unknown] {
        let mut h = fake::Harness::new();
        h.world().target = target;
        h.inject(InputMessage::Move { x: 0.25, y: 0.75 }).unwrap();
        assert!(reports_with_id(&h, 4).is_empty(), "{target:?}");
        assert_eq!(sent_moves(&h), 1, "{target:?}");
        // A button after it goes by SendInput too, at once: nothing waits for a SendInput `m`.
        h.button(0, true).unwrap();
        assert!(!h.rt.typist.has_work(), "{target:?}");
        assert_eq!(
            h.world()
                .count(|o| matches!(o, fake::Out::SendInput(InputMessage::Down { .. }))),
            1,
            "{target:?}"
        );
    }
}

/// A failed `m` is not replayed (the next one replaces it). It leaves the mouse dirty, so the
/// recovery before the next input writes the neutral relative report — no motion, no button — and a
/// device that takes neither leaves `m` to SendInput for the rest of the session instead of failing
/// every one.
#[test]
fn a_failed_m_is_not_replayed_and_a_dead_device_leaves_m_to_sendinput() {
    let ids = |h: &fake::Harness| -> Vec<u8> {
        h.world()
            .log
            .iter()
            .filter_map(|(_, o)| match o {
                fake::Out::Report(r) => Some(r[2]),
                _ => None,
            })
            .collect()
    };
    let mut h = fake::Harness::new();
    h.world().failures.push_back(true);
    assert!(h.inject(InputMessage::Move { x: 0.5, y: 0.5 }).is_err());
    assert!(h.rt.state.failed);
    assert!(h.rt.unseen.is_none(), "nothing to wait for");
    h.at(16);
    h.inject(InputMessage::Move { x: 0.25, y: 0.25 }).unwrap();
    assert_eq!(
        ids(&h),
        [4, 3, 4],
        "the failed m, the neutral report, the next m"
    );
    assert_eq!(
        reports_with_id(&h, 3)[0][3..10],
        [0; 7],
        "neutral: no button, no motion"
    );
    assert!(!h.rt.broken);
    assert_eq!(sent_moves(&h), 0);

    let mut h = fake::Harness::new();
    h.world().failures.extend([true, true]);
    assert!(h.inject(InputMessage::Move { x: 0.5, y: 0.5 }).is_err());
    h.at(16);
    h.inject(InputMessage::Move { x: 0.25, y: 0.25 }).unwrap();
    assert!(h.rt.broken);
    assert_eq!(ids(&h), [4, 3], "the failed m and the failed cleanup");
    assert_eq!(sent_moves(&h), 1, "the next m by SendInput");
}

/// A tap of the tablet mode — `m`, `d`, `u` back to back: the press waits (in the queue) until the
/// cursor shows the `m` (2 ms in the simulated Windows), so it cannot click where the cursor was;
/// the release keeps its minimum hold after the press.
#[test]
fn a_tap_right_after_an_m_waits_for_the_m_to_show() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(m_at((2600, 400))).unwrap();
    h.button(0, true).unwrap();
    h.button(0, false).unwrap();
    assert!(
        reports_with_id(&h, 3).is_empty(),
        "the press waits for the m, not on this thread"
    );
    assert!(h.rt.typist.has_work());
    h.run();
    assert_eq!(mouse_line(&h), line(&[(16, "a"), (18, "b1"), (48, "b0")]));
    assert_eq!(
        h.world().order_waits,
        [(Duration::from_millis(2), false)],
        "one wait of 2 ms, counted for the per-second line"
    );
    assert_eq!(
        h.rt.tap_deferrals, 1,
        "the order wait is not a tap deferral"
    );
    assert!(h.rt.unseen.is_none() && h.rt.order_wait_since.is_none());
}

/// The desktop game mode's click: a point move (`r` with the pointer's `x`, `y`: report 4), then `d`
/// at once. The press waits for the point move to show exactly as after an `m` — same wait, same
/// bound, same count — so it cannot land where the cursor was.
#[test]
fn a_game_mode_click_right_after_a_point_move_waits_for_it_to_show() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(rel_toward(4.0, Some((2600, 400)))).unwrap();
    assert_eq!(reports_with_id(&h, 4).len(), 1, "a point move: report 4");
    h.button(0, true).unwrap();
    assert!(
        reports_with_id(&h, 3).is_empty(),
        "the press waits for the point move, not on this thread"
    );
    h.at(60);
    h.button(0, false).unwrap();
    h.run();
    assert_eq!(mouse_line(&h), line(&[(16, "a"), (18, "b1"), (60, "b0")]));
    assert_eq!(h.world().order_waits, [(Duration::from_millis(2), false)]);

    // A point move that never shows (a clipped cursor): the press goes at the bound, counted as a
    // wait that gave up.
    h.world().cursor.as_mut().unwrap().sim.deaf = true;
    h.at(100);
    h.inject(rel_toward(1.0, Some((500, 500)))).unwrap();
    assert_eq!(reports_with_id(&h, 4).len(), 2);
    h.button(0, true).unwrap();
    h.run();
    assert_eq!(mouse_line(&h).last(), Some(&(108, "b1".to_owned())));
    assert_eq!(
        h.world().order_waits,
        [(Duration::from_millis(2), false), (ORDER_WAIT_MAX, true)]
    );
}

/// The cursor never shows the `m` (clipped, moved by the PC's own mouse): the press waits at most
/// the bound, then goes anyway, said at `debug`.
#[test]
fn a_press_waits_no_longer_than_the_bound() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut h = fake::Harness::new();
        h.plan_moves(144);
        h.world().cursor.as_mut().unwrap().sim.deaf = true;
        h.at(16);
        h.inject(m_at((2600, 400))).unwrap();
        h.button(0, true).unwrap();
        h.run();
        assert_eq!(mouse_line(&h), line(&[(16, "a"), (24, "b1")]));
        assert_eq!(h.world().order_waits, [(ORDER_WAIT_MAX, true)]);
    });
    let timed_out: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("did not show the move in time"))
        .collect();
    assert_eq!(timed_out.len(), 1, "{log}");
    assert!(timed_out[0].contains("waited_ms=8.0"), "{log}");
}

/// Nothing waits when there is nothing to wait for: a press long after the `m`, a press where the
/// cursor already is (the desktop viewer's press is `m`, `d` onto the pixel the mouse is on), a move
/// of a pixel, or a cursor that cannot be read.
#[test]
fn a_press_goes_at_once_when_the_cursor_is_there_or_the_m_is_old() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(m_at((2600, 400))).unwrap();
    h.at(40);
    h.button(0, true).unwrap();
    h.at(80);
    h.button(0, false).unwrap();
    // The desktop viewer: the mouse moves a pixel, then presses where it is.
    h.at(96);
    h.inject(m_at((2601, 400))).unwrap();
    h.button(0, true).unwrap();
    h.at(150);
    h.button(0, false).unwrap();
    // The PC's own mouse moves the cursor away after an `m` has shown; a press long after it goes.
    h.at(200);
    h.inject(m_at((2000, 1000))).unwrap();
    h.at(205);
    assert_eq!(h.cursor_at(), (2000, 1000));
    h.world().cursor.as_mut().unwrap().sim.warp(100, 100);
    h.at(300);
    h.button(0, true).unwrap();
    assert!(!h.rt.typist.has_work(), "nothing ever waited");
    assert_eq!(
        mouse_line(&h),
        line(&[
            (16, "a"),
            (40, "b1"),
            (80, "b0"),
            (96, "a"),
            (96, "b1"),
            (150, "b0"),
            (200, "a"),
            (300, "b1")
        ])
    );
    assert!(h.world().order_waits.is_empty());

    // No cursor to read (the fake without a planner): the press goes at once, as before.
    let mut h = fake::Harness::new();
    h.inject(InputMessage::Move { x: 0.5, y: 0.5 }).unwrap();
    h.button(0, true).unwrap();
    assert!(!h.rt.typist.has_work());
    assert_eq!(mouse_line(&h), line(&[(0, "a"), (0, "b1")]));
}

/// A drag of the tablet mode or the desktop viewer's mouse: the button goes down on the relative
/// report's collection and stays there (report 3's button bit), every position goes as report 4
/// with buttons 0 — never relative counts — and the button comes up where the last `m` put the
/// cursor, after it has shown.
#[test]
fn a_drag_holds_the_button_on_report_3_and_moves_on_report_4() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(m_at((1000, 800))).unwrap();
    h.button(0, true).unwrap();
    h.run();
    let mut t = 16;
    for i in 1..=10 {
        t += 16;
        h.at(t);
        h.inject(m_at((1000 + 20 * i, 800))).unwrap();
    }
    // The finger lifts right after the last `m`.
    h.button(0, false).unwrap();
    h.run();
    assert_eq!(h.cursor_at(), (1200, 800));
    let got = mouse_line(&h);
    assert_eq!(got.first(), Some(&(16, "a".to_owned())));
    assert_eq!(got.get(1), Some(&(18, "b1".to_owned())));
    assert_eq!(got.iter().filter(|(_, w)| w == "a").count(), 11);
    assert!(
        got.iter().all(|(_, w)| w != "r"),
        "no relative motion: {got:?}"
    );
    assert_eq!(
        got.last(),
        Some(&(t + 2, "b0".to_owned())),
        "the release waits for the last m to show: {got:?}"
    );
    assert!(
        reports_with_id(&h, 4).iter().all(|r| r[3] == 0),
        "report 4 carries no button"
    );
    assert_eq!(h.world().order_waits.len(), 2, "the press and the release");
}

/// Whatever comes after a waiting button waits behind it, in order: an `m` right after a tap does
/// not move the cursor before the tap's press has landed where the first `m` put it.
#[test]
fn an_m_behind_a_waiting_tap_waits_its_turn() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(m_at((2600, 400))).unwrap();
    h.button(0, true).unwrap();
    h.button(0, false).unwrap();
    h.at(17);
    h.inject(m_at((300, 2000))).unwrap();
    assert_eq!(reports_with_id(&h, 4).len(), 1, "the second m waits");
    h.run();
    assert_eq!(
        mouse_line(&h),
        line(&[(16, "a"), (18, "b1"), (48, "b0"), (49, "a")])
    );
    assert_eq!(h.cursor_at(), (300, 2000));
}

/// `ra` while a press waits for its `m`: the press is dropped with the queue (it never went down),
/// and nothing about the `m` is left to wait for. `ra` writes no absolute report.
#[test]
fn ra_drops_a_waiting_press_and_writes_no_absolute_report() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(m_at((2600, 400))).unwrap();
    h.button(0, true).unwrap();
    h.release_all();
    h.run();
    assert_eq!(mouse_line(&h), line(&[(16, "a")]));
    assert!(h.rt.unseen.is_none() && h.rt.order_wait_since.is_none());
    assert!(h.world().order_waits.is_empty());
}

/// After an `m` the planner re-anchors exact mode on where the `m` put the cursor: an `r` of the
/// trackpad mode moves from there by exactly the hand's distance.
#[test]
fn an_r_after_an_m_moves_from_where_the_m_put_the_cursor() {
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(rel_toward(30.0, None)).unwrap();
    h.at(32);
    h.inject(m_at((1500, 900))).unwrap();
    let mut t = 32;
    for _ in 0..10 {
        t += 16;
        h.at(t);
        h.inject(rel_toward(15.0, None)).unwrap();
    }
    let at = h.cursor_at();
    assert!((at.0 - 1650).abs() <= 1 && at.1 == 900, "{at:?}");
}

/// A numbered move behind a tap's release (which waits out its minimum hold) is not on the cursor
/// until the router sends it: the cursor report's `ack` stays below it while it waits in the queue
/// and while its report is on its way, and may name it once the cursor shows it.
#[test]
fn a_move_queued_behind_a_tap_is_not_acknowledged_before_it_shows() {
    let numbered = |dx_px: f64, s: u32| InputMessage::Rel {
        dx: dx_px / 3600.0,
        dy: 0.0,
        s: Some(s),
        x: None,
        y: None,
    };
    let mut h = fake::Harness::new();
    h.plan_moves(144);
    h.at(16);
    h.inject(numbered(10.0, 0)).unwrap();
    assert_eq!(h.unshown(), Some(0), "its report is on its way");
    h.at(19);
    assert_eq!(h.unshown(), None, "shown 2 ms after its report");

    // A tap: the press goes at once, the release waits out the minimum hold, and the moves after it
    // wait behind it.
    h.button(0, true).unwrap();
    h.button(0, false).unwrap();
    h.inject(numbered(10.0, 1)).unwrap();
    h.at(25);
    h.inject(numbered(10.0, 2)).unwrap();
    assert_eq!(h.world().queued_moves, [1, 2]);
    assert_eq!(h.unshown(), Some(1), "queued behind the release");
    h.at(40);
    assert_eq!(h.unshown(), Some(1));
    let done = h.run();
    assert!(h.unshown().is_some(), "the last one just went: on its way");
    h.at(done + 3);
    assert_eq!(h.unshown(), None, "both shown");
    let moves = reports_with_id(&h, 3)
        .into_iter()
        .filter(|r| r[4..8] != [0; 4])
        .count();
    assert_eq!(moves, 3);
}

/// `m`'s path is said at `debug` when it changes (first on HID, then by SendInput for the blocked
/// desktop, with the reason), never per move; the per-second line counts `m` per path.
#[test]
fn m_says_its_path_on_a_change_and_nothing_per_move_at_debug() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut h = fake::Harness::new();
        h.plan_moves(144);
        for i in 0..100 {
            h.at(16 * (i + 1));
            h.inject(m_at((1000 + i32::try_from(i).unwrap(), 900)))
                .unwrap();
        }
        h.world().target = Target::Blocked;
        for i in 0..5 {
            h.at(2200 + 16 * i);
            h.inject(m_at((500, 500))).unwrap();
        }
        h.at(3500);
        h.inject(m_at((600, 600))).unwrap();
    });
    let paths: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("position (m) path"))
        .collect();
    assert_eq!(paths.len(), 2, "{log}");
    assert!(paths[0].contains("path=\"hid\""), "{log}");
    assert!(
        paths[1].contains("path=\"sendinput\"") && paths[1].contains("HID target blocked"),
        "{log}"
    );
    assert!(log.contains("m_hid="), "the per-second line: {log}");
    for per_move in ["HID absolute report", "cursor sync: absolute position"] {
        assert!(!log.contains(per_move), "{per_move} at debug:\n{log}");
    }
    let lines = log.lines().count();
    assert!(lines <= 12, "{lines} debug lines:\n{log}");
}

// The wheel the viewer did not mark `game`: smooth SendInput where it reaches, whole HID notches in
// game-only mode and to an elevated window.

/// A wheel not marked `game` — the desktop's: `dy` px down (negative: up), `dx` px right.
fn scroll(dx: f64, dy: f64) -> InputMessage {
    InputMessage::Wheel {
        dx,
        dy,
        mode: None,
        game: None,
    }
}

fn game_scroll(dy: f64) -> InputMessage {
    InputMessage::Wheel {
        dx: 0.0,
        dy,
        mode: None,
        game: Some(true),
    }
}

/// A foreground window that runs elevated, and whether the agent does too.
fn elevated(exe: &str, agent: bool) -> Option<crate::cursor_sync::Elevation> {
    Some(crate::cursor_sync::Elevation {
        foreground: true,
        agent,
        exe: exe.into(),
    })
}

/// `(wheel, pan)` of every relative mouse report with a wheel turn in it.
fn notches_sent(h: &fake::Harness) -> Vec<(i8, i8)> {
    reports_with_id(h, 3)
        .into_iter()
        .map(|r| (i8::from_le_bytes([r[8]]), i8::from_le_bytes([r[9]])))
        .filter(|&t| t != (0, 0))
        .collect()
}

fn sent_wheels(h: &fake::Harness) -> usize {
    h.world()
        .count(|o| matches!(o, fake::Out::SendInput(InputMessage::Wheel { .. })))
}

fn tally(sendinput: u32, hid_game: u32, hid_stepped: u32, notches: u32, resets: u32) -> WheelTally {
    WheelTally {
        sendinput,
        hid_game,
        hid_stepped,
        notches,
        resets,
    }
}

/// An ordinary window, both the window and the agent elevated, an elevation that cannot be read:
/// SendInput reaches all of them, so the wheel stays smooth there, exactly as before — it does not
/// even look at the target.
#[test]
fn a_wheel_not_marked_game_stays_smooth_where_sendinput_reaches() {
    for elevation in [
        None,
        elevated("Taskmgr.exe", true),
        Some(crate::cursor_sync::Elevation {
            foreground: false,
            agent: false,
            exe: "notepad.exe".into(),
        }),
    ] {
        let mut h = fake::Harness::new();
        h.world().elevation = elevation.clone();
        let looks = h.world().target_looks;
        for i in 0..3 {
            h.at(16 * i);
            h.inject(scroll(0.0, 3.0)).unwrap();
        }
        assert_eq!(sent_wheels(&h), 3, "{elevation:?}");
        assert!(reports_with_id(&h, 3).is_empty(), "{elevation:?}");
        assert_eq!(h.world().target_looks, looks, "no look at the target");
        assert_eq!(h.world().wheels, tally(3, 0, 0, 0, 0));
    }
}

/// A foreground window that runs elevated while the agent does not (Task Manager): SendInput cannot
/// reach it, so the wheel goes as whole HID notches, at SendInput's scale — 100 px, 3 lines or a
/// fifth of a page a notch — and nothing by SendInput.
#[test]
fn a_wheel_to_an_elevated_window_goes_in_whole_hid_notches() {
    let mut h = fake::Harness::new();
    h.world().elevation = elevated("Taskmgr.exe", false);
    h.inject(scroll(0.0, 100.0)).unwrap();
    h.at(16);
    h.inject(scroll(0.0, -200.0)).unwrap();
    h.at(32);
    h.inject(InputMessage::Wheel {
        dx: 0.0,
        dy: 3.0,
        mode: Some(1),
        game: None,
    })
    .unwrap();
    h.at(48);
    h.inject(InputMessage::Wheel {
        dx: 0.0,
        dy: -1.0,
        mode: Some(2),
        game: None,
    })
    .unwrap();
    // dy > 0 scrolls down: HID Wheel < 0, as SendInput's `wheelData = -dy`.
    assert_eq!(notches_sent(&h), [(-1, 0), (2, 0), (-1, 0), (5, 0)]);
    assert_eq!(sent_wheels(&h), 0, "nothing by SendInput");
    assert_eq!(h.world().wheels, tally(0, 0, 4, 9, 0));
}

/// Game-only mode: the wheel goes to the game in whole HID notches whatever the window's elevation
/// (a game reads the mouse directly); the mode off, it is smooth again.
#[test]
fn game_only_mode_sends_the_wheel_to_the_game_in_whole_notches() {
    let mut h = fake::Harness::new();
    h.rt.confine_to(QueueGate::Game(0x10));
    h.inject(scroll(0.0, -100.0)).unwrap();
    assert_eq!(notches_sent(&h), [(1, 0)]);
    assert_eq!(sent_wheels(&h), 0);
    h.rt.confine_to(QueueGate::Desktop);
    h.at(16);
    h.inject(scroll(0.0, -100.0)).unwrap();
    assert_eq!(notches_sent(&h).len(), 1);
    assert_eq!(sent_wheels(&h), 1, "smooth again");
}

/// Where HID may not go — the secure desktop, the lock screen, a desktop that cannot be identified —
/// or with the device unusable, a wheel meant for HID goes by SendInput, as every wheel did before.
#[test]
fn a_stepped_wheel_falls_back_to_sendinput_where_hid_may_not_go() {
    for target in [Target::Blocked, Target::Unknown] {
        let mut h = fake::Harness::new();
        h.world().elevation = elevated("Taskmgr.exe", false);
        h.world().target = target;
        h.inject(scroll(0.0, 100.0)).unwrap();
        h.rt.confine_to(QueueGate::Game(0x10));
        h.at(16);
        h.inject(scroll(0.0, 100.0)).unwrap();
        assert!(reports_with_id(&h, 3).is_empty(), "{target:?}");
        assert_eq!(sent_wheels(&h), 2, "{target:?}");
    }

    // A device that takes neither a report nor its neutral cleanup: everything by SendInput.
    let mut h = fake::Harness::new();
    h.world().elevation = elevated("Taskmgr.exe", false);
    h.world().failures.extend([true, true]);
    assert!(h.inject(InputMessage::Move { x: 0.5, y: 0.5 }).is_err());
    h.at(16);
    h.inject(scroll(0.0, 100.0)).unwrap();
    assert!(h.rt.broken);
    assert!(notches_sent(&h).is_empty());
    assert_eq!(sent_wheels(&h), 1);
}

/// A slow two-finger scroll over an elevated window: ten messages of 10 px turn the wheel once, on
/// the tenth; 250 px are two notches with 50 px carried, which the next 50 px complete.
#[test]
fn the_stepped_wheel_adds_small_deltas_up_to_whole_notches() {
    let mut h = fake::Harness::new();
    h.world().elevation = elevated("Taskmgr.exe", false);
    let mut t = 0;
    for _ in 0..9 {
        t += 16;
        h.at(t);
        h.inject(scroll(0.0, 10.0)).unwrap();
    }
    assert!(notches_sent(&h).is_empty(), "90 px is not a notch yet");
    t += 16;
    h.at(t);
    h.inject(scroll(0.0, 10.0)).unwrap();
    assert_eq!(notches_sent(&h), [(-1, 0)]);
    assert_eq!(h.rt.state.mouse.wheel_carry(), WheelCarry::default());

    t += 16;
    h.at(t);
    h.inject(scroll(0.0, 250.0)).unwrap();
    assert_eq!(notches_sent(&h)[1], (-2, 0));
    assert!(
        (h.rt.state.mouse.wheel_carry().wheel + 0.5).abs() < 1e-9,
        "50 px carried"
    );
    t += 16;
    h.at(t);
    h.inject(scroll(0.0, 50.0)).unwrap();
    assert_eq!(notches_sent(&h), [(-1, 0), (-2, 0), (-1, 0)]);
    assert_eq!(sent_wheels(&h), 0);
    assert_eq!(h.world().wheels, tally(0, 0, 12, 4, 0));
}

/// The unfinished notch is forgotten when the direction reverses, when the route changes (smooth in
/// between, or game-only mode to an elevated window) and after a pause of 300 ms — never before.
#[test]
fn the_stepped_wheel_forgets_its_remainder_on_reversal_route_change_and_pause() {
    let mut h = fake::Harness::new();
    h.world().elevation = elevated("Taskmgr.exe", false);
    // A change of direction: 90 px down, then back up — 100 px up is one notch up, not 190.
    h.inject(scroll(0.0, 90.0)).unwrap();
    h.at(16);
    h.inject(scroll(0.0, -60.0)).unwrap();
    assert!(notches_sent(&h).is_empty());
    h.at(32);
    h.inject(scroll(0.0, -40.0)).unwrap();
    assert_eq!(notches_sent(&h), [(1, 0)]);
    assert_eq!(h.world().wheels.resets, 1, "the reversal");

    // A change of route: an ordinary window takes the front for one smooth message.
    h.at(48);
    h.inject(scroll(0.0, 90.0)).unwrap();
    h.world().elevation = None;
    h.at(64);
    h.inject(scroll(0.0, 3.0)).unwrap();
    h.world().elevation = elevated("regedit.exe", false);
    h.at(80);
    h.inject(scroll(0.0, 10.0)).unwrap();
    assert_eq!(
        notches_sent(&h).len(),
        1,
        "the 90 px were dropped with the route"
    );
    assert_eq!(h.world().wheels.resets, 2);

    // Game-only mode, then an elevated window: both HID, but another route.
    h.rt.state.drop_wheel_carry("test");
    h.rt.confine_to(QueueGate::Game(0x10));
    h.at(96);
    h.inject(scroll(0.0, 90.0)).unwrap();
    h.rt.confine_to(QueueGate::Desktop);
    h.at(112);
    h.inject(scroll(0.0, 10.0)).unwrap();
    assert_eq!(notches_sent(&h).len(), 1);
    assert_eq!(h.world().wheels.resets, 3);

    // A pause: 90 px, and 10 px 300 ms later start afresh; 10 px 299 ms later still finish it.
    h.rt.state.drop_wheel_carry("test");
    h.at(1_000);
    h.inject(scroll(0.0, 90.0)).unwrap();
    h.at(1_300);
    h.inject(scroll(0.0, 10.0)).unwrap();
    assert_eq!(notches_sent(&h).len(), 1, "the pause dropped the 90 px");
    assert_eq!(h.world().wheels.resets, 4);
    h.rt.state.drop_wheel_carry("test");
    h.at(2_000);
    h.inject(scroll(0.0, 90.0)).unwrap();
    h.at(2_299);
    h.inject(scroll(0.0, 10.0)).unwrap();
    assert_eq!(notches_sent(&h), [(1, 0), (-1, 0)]);
    assert_eq!(h.world().wheels.resets, 4);
}

/// Horizontal scrolling is AC Pan, in whole notches too; both axes share a report.
#[test]
fn the_stepped_wheel_pans_horizontally() {
    let mut h = fake::Harness::new();
    h.world().elevation = elevated("Taskmgr.exe", false);
    h.inject(scroll(250.0, 0.0)).unwrap();
    assert_eq!(notches_sent(&h), [(0, 2)], "dx > 0 pans right");
    h.at(16);
    // Left: the change of direction drops the 50 px.
    h.inject(scroll(-100.0, 0.0)).unwrap();
    h.at(32);
    h.inject(scroll(100.0, 100.0)).unwrap();
    assert_eq!(notches_sent(&h), [(0, 2), (0, -1), (-1, 1)]);
    assert_eq!(sent_wheels(&h), 0);
}

/// The viewer's game-mode wheel is as it was: HID by the target whatever the window, its own scale,
/// and its remainder kept across a pause. Between it and a stepped wheel the route changes, which
/// forgets the remainder.
#[test]
fn the_game_wheel_is_as_it_was() {
    let mut h = fake::Harness::new();
    h.inject(game_scroll(90.0)).unwrap();
    h.at(1_000);
    h.inject(game_scroll(10.0)).unwrap();
    assert_eq!(notches_sent(&h), [(-1, 0)], "no pause for the game wheel");
    h.world().elevation = elevated("ScrydeGame.bin", false);
    h.at(1_016);
    h.inject(game_scroll(-100.0)).unwrap();
    assert_eq!(notches_sent(&h), [(-1, 0), (1, 0)]);
    assert_eq!(sent_wheels(&h), 0);
    assert_eq!(h.world().wheels, tally(0, 3, 0, 2, 0));

    // Game, then stepped: another route.
    h.at(1_032);
    h.inject(game_scroll(90.0)).unwrap();
    h.at(1_048);
    h.inject(scroll(0.0, 10.0)).unwrap();
    assert_eq!(notches_sent(&h).len(), 2);
    assert_eq!(h.world().wheels.resets, 1);
    // Blocked, it goes by SendInput as before.
    h.world().target = Target::Blocked;
    h.at(1_200);
    h.inject(game_scroll(100.0)).unwrap();
    assert_eq!(sent_wheels(&h), 1);
}

/// Each change of the wheel's route is said at `debug` with its reason — an elevated window with its
/// exe, back to smooth — and nothing per message; the planner's per-second line counts the wheel per
/// way, the HID notches and the dropped remainders.
#[test]
fn the_wheel_says_its_route_on_a_change_and_counts_per_second() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut h = fake::Harness::new();
        h.plan_moves(144);
        let mut t = 0;
        for _ in 0..30 {
            t += 16;
            h.at(t);
            h.inject(scroll(0.0, 4.0)).unwrap();
        }
        h.world().elevation = elevated("Taskmgr.exe", false);
        for i in 0..60 {
            t = 2_100 + 16 * i;
            h.at(t);
            h.inject(scroll(0.0, if i == 30 { -10.0 } else { 10.0 }))
                .unwrap();
        }
        h.world().elevation = None;
        for i in 0..30 {
            t = 4_300 + 16 * i;
            h.at(t);
            h.inject(scroll(0.0, 4.0)).unwrap();
        }
        h.at(6_000);
        h.inject(scroll(0.0, 4.0)).unwrap();
    });
    let paths: Vec<&str> = log.lines().filter(|l| l.contains("wheel path")).collect();
    assert_eq!(paths.len(), 3, "{log}");
    assert!(
        paths[0].contains("path=\"sendinput\"") && paths[0].contains("an ordinary window"),
        "{log}"
    );
    assert!(
        paths[1].contains("path=\"hid\"")
            && paths[1].contains("runs elevated and the agent does not")
            && paths[1].contains("foreground=\"Taskmgr.exe\""),
        "{log}"
    );
    assert!(
        paths[2].contains("path=\"sendinput\"") && paths[2].contains("cannot be read"),
        "{log}"
    );
    let seconds: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("wheel_hid_stepped="))
        .collect();
    assert!(
        seconds
            .iter()
            .any(|l| !l.contains("wheel_hid_stepped=0 ") && !l.contains("wheel_hid_notches=0 ")),
        "the per-second line counts the stepped wheel: {log}"
    );
    assert!(
        seconds.iter().any(|l| !l.contains("wheel_carry_resets=0 ")),
        "and its dropped remainders: {log}"
    );
    assert!(
        seconds.iter().any(|l| !l.contains("wheel_sendinput=0 ")),
        "and the smooth wheel: {log}"
    );
    // The per-message line: its message, then its first field.
    for per_message in [
        "wheel not marked game path=",
        "notches accumulated",
        "HID wheel report",
    ] {
        assert!(!log.contains(per_message), "{per_message} at debug:\n{log}");
    }
    let lines = log.lines().count();
    assert!(lines <= 16, "{lines} debug lines:\n{log}");

    let trace = logged(tracing::Level::TRACE, || {
        let mut h = fake::Harness::new();
        h.world().elevation = elevated("Taskmgr.exe", false);
        h.inject(scroll(0.0, 10.0)).unwrap();
    });
    assert!(
        trace.contains("wheel not marked game path=\"hid\""),
        "{trace}"
    );
    assert!(trace.contains("notches accumulated"), "{trace}");
}

/// A writer the log-capture tests read back.
#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
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

#[cfg(windows)]
#[test]
#[ignore = "drives the real HID mouse and keyboard; run manually with a safe focused target"]
fn manual_hid_key_and_relative_motion() -> Result<()> {
    let injector = FakerInputInjector::connect()?
        .ok_or_else(|| anyhow::anyhow!("FakerInput is not installed"))?;
    // Drop is also a release guard if an intermediate write fails.
    injector.inject(&InputMessage::Key {
        d: 1,
        code: "KeyW".into(),
        key: None,
        mods: None,
        src: None,
    })?;
    injector.inject(&InputMessage::Down { b: 2 })?;
    injector.inject(&InputMessage::Rel {
        dx: 0.01,
        dy: -0.01,
        s: None,
        x: None,
        y: None,
    })?;
    injector.release_all();
    Ok(())
}

/* ── The process-wide backend's ledger hints and a flood of unmapped codes (KB-6) ── */

#[cfg(windows)]
fn game_scope() -> InputScope {
    InputScope::Game(afklink_core::traits::GameScope {
        state: afklink_protocol::GameWindowState::Shown,
        window: None,
    })
}

#[cfg(windows)]
fn key_msg(d: u8, code: &str) -> InputMessage {
    InputMessage::Key {
        d,
        code: code.into(),
        key: None,
        mods: None,
        src: None,
    }
}

/// The backend confines input rather than dropping it, so the scope does not decide: a key either
/// path maps can hold, in game scope too, and so can a button; a code neither maps cannot. Pure:
/// no device is opened, nothing is injected.
#[cfg(windows)]
#[test]
fn the_backend_says_a_press_can_hold_when_a_path_maps_its_key() {
    let backend = SessionInputBackend::new();
    for scope in [InputScope::Desktop, game_scope()] {
        for code in ["KeyA", "ShiftLeft", "Enter", "NumpadEnter", "F5"] {
            assert!(backend.press_may_hold(&key_msg(1, code), &scope), "{code}");
        }
        assert!(backend.press_may_hold(&InputMessage::Down { b: 0 }, &scope));
        for code in ["", "Bogus", "F24x"] {
            assert!(
                !backend.press_may_hold(&key_msg(1, code), &scope),
                "{code:?}"
            );
        }
    }
}

/// Ten thousand distinct codes no path maps, on the desktop and in game-only mode: none reaches the
/// guard — its books and its key log's stay empty — and their line stops at the line gate's
/// burst. Nothing is injected: they return before either path (no device is open).
#[cfg(windows)]
#[test]
fn a_flood_of_unmapped_codes_never_reaches_the_guard_and_says_a_bounded_number_of_lines() {
    let backend = SessionInputBackend::new();
    let mut books = Vec::new();
    let log = logged(tracing::Level::DEBUG, || {
        for scope in [InputScope::Desktop, game_scope()] {
            // Presses alone, their releases never sent: what a flood leaves in the books.
            for i in 0..10_000 {
                let code = format!("Bogus{i}");
                backend.inject_scoped(&key_msg(1, &code), &scope).unwrap();
            }
            books.push(lock(&backend.guard).books());
            for i in 0..10_000 {
                let code = format!("Bogus{i}");
                backend.inject_scoped(&key_msg(0, &code), &scope).unwrap();
            }
        }
    });
    assert_eq!(books, [(0, 0, 0), (0, 0, 0)]);
    let lines = log.matches("unmapped key code").count();
    assert!(
        lines <= crate::line_gate::LineGate::BURST as usize,
        "{lines} lines:\n{log}"
    );
}

/// A key-up whose code no path maps stops before the guard too: whatever its books hold — here a
/// held and a blocked entry under such codes, as an older agent could have left — is left as it
/// is. (Reaching the guard, the key-up would take its code out of either book.) Nothing is
/// injected: the code maps to no key, and no device is open.
#[cfg(windows)]
#[test]
fn an_unmapped_key_up_stops_before_the_guard_and_leaves_its_books() {
    let backend = SessionInputBackend::new();
    lock(&backend.guard).book(&["Bogus", "KeyA"], &["Bogus2"]);
    for scope in [InputScope::Desktop, game_scope()] {
        for code in ["Bogus", "Bogus2"] {
            backend.inject_scoped(&key_msg(0, code), &scope).unwrap();
        }
        assert_eq!(lock(&backend.guard).books(), (2, 1, 0), "{scope:?}");
    }
}

/// A flood of presses that each go through `SendInput` instead of the device — a seventh
/// simultaneous key, and a key outside the device's descriptor (F13), pressed and released again
/// and again — says a bounded number of lines: the line gate's burst, the rest at `trace`.
#[test]
fn a_flood_of_presses_routed_via_sendinput_says_a_bounded_number_of_lines() {
    let mut h = fake::Harness::new();
    let log = logged(tracing::Level::DEBUG, || {
        for code in ["KeyA", "KeyB", "KeyC", "KeyD", "KeyE", "KeyF"] {
            h.key(code, true).unwrap();
        }
        for _ in 0..5_000 {
            for code in ["KeyG", "F13"] {
                h.key(code, true).unwrap();
                h.key(code, false).unwrap();
            }
        }
    });
    let lines = log.matches("seventh simultaneous key").count()
        + log.matches("key outside FakerInput descriptor").count();
    assert!(lines > 0, "the first are said:\n{log}");
    assert!(
        lines <= crate::line_gate::LineGate::BURST as usize,
        "{lines} lines for 10 000 presses"
    );
}
