//! The button watch through the real router on the fake world: a game that hides the cursor while
//! the right button is held ([`FakeGame`]) and loses the releases or presses a test tells it to.
#![allow(clippy::unwrap_used)]

use afklink_protocol::InputMessage;

use super::super::fake::{FakeGame, Harness, Out};
use super::super::{QueueGate, Target};
use super::{WatchTally, CHECK_AT, NORMAL_PAIRS_MIN};

/// The fake world's foreground window: the game's in these tests.
const GAME: usize = 0x10;
const NOTEPAD: usize = 0x20;
/// The right button: the protocol's id, and its HID bit.
const RIGHT: u8 = 2;

fn game_harness() -> Harness {
    let mut h = Harness::new();
    h.world().game = Some(FakeGame::right_button());
    h.rt.confine_to(QueueGate::Game(GAME));
    h
}

/// The hand turning the camera a little.
fn hand() -> InputMessage {
    InputMessage::Rel {
        dx: 0.01,
        dy: 0.0,
        s: None,
        x: None,
        y: None,
    }
}

/// A camera turn: the right button down at `at` ms, a move every 16 ms, up `held` ms later. Returns
/// when the release went.
fn turn(h: &mut Harness, at: u64, held: u64) -> u64 {
    h.at(at);
    h.button(RIGHT, true).unwrap();
    let mut t = at;
    while t + 16 < at + held {
        t += 16;
        h.at(t);
        h.inject(hand()).unwrap();
    }
    h.at(at + held);
    h.button(RIGHT, false).unwrap();
    at + held
}

/// `n` camera turns the game takes, each held 200 ms, 300 ms apart, from `from` ms; the clock is
/// moved on to when the last one has settled. Returns that time.
fn turns(h: &mut Harness, from: u64, n: u64) -> u64 {
    let mut t = from;
    for _ in 0..n {
        t = turn(h, t, 200) + 300;
    }
    h.at(t);
    t
}

/// The device's button changes and moves from `from` ms on (inclusive): `b<bits>` and `r`, as
/// `(ms, what)`.
fn mouse_since(h: &Harness, from: u64) -> Vec<(u64, String)> {
    h.world()
        .device_timeline()
        .into_iter()
        .filter(|(at, what)| *at >= from && !what.starts_with('k'))
        .collect()
}

/// Right-button presses on the device from `from` ms on (inclusive).
fn presses_since(h: &Harness, from: u64) -> usize {
    mouse_since(h, from)
        .iter()
        .filter(|(_, what)| what == "b2")
        .count()
}

fn visible(h: &Harness) -> bool {
    h.world().game.as_ref().unwrap().visible
}

fn lose_releases(h: &Harness, n: u32) {
    h.world().game.as_mut().unwrap().lose_releases = n;
}

fn check_ms() -> u64 {
    u64::try_from(CHECK_AT.as_millis()).unwrap()
}

/// What `f` logs at `level` and above, on this thread.
fn logged(level: tracing::Level, f: impl FnOnce()) -> String {
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

/// Turns the game takes: every pair is normal, nothing is re-sent, and every change gets its probe
/// (with who has the mouse, for the right button). The watch ends once the last one is decided.
#[test]
fn pairs_the_game_takes_are_counted_and_nothing_is_resent() {
    let mut h = game_harness();
    turns(&mut h, 0, 6);
    h.run();
    assert_eq!(h.rt.watch.normal_pairs(RIGHT), 6);
    let t = h.rt.watch.tally();
    assert_eq!(
        (
            t.presses,
            t.releases,
            t.normal_pairs,
            t.resent,
            t.missed_releases
        ),
        (6, 6, 6, 0, 0)
    );
    assert_eq!(presses_since(&h, 0), 6, "nothing more than the viewer's");
    let probes = h.world().probes.clone();
    assert_eq!(probes.len(), 12, "a probe per change: {probes:?}");
    assert!(probes
        .iter()
        .all(|&(_, game, detail)| game == GAME && detail));
    assert!(h.rt.watch.due().is_none(), "nothing watched any more");
}

/// The reported case: the game misses one release and the cursor stays hidden. 250 ms after the
/// release the press and the release go once more — the release after the minimum hold — and moves
/// that come meanwhile wait behind it; the game shows the cursor again, and the re-send counts as
/// one that helped.
#[test]
fn a_missed_release_is_sent_once_more_and_moves_wait_behind_it() {
    let mut h = game_harness();
    let t = turns(&mut h, 0, NORMAL_PAIRS_MIN.into());
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 400);
    h.at(released + check_ms() - 1);
    assert_eq!(presses_since(&h, released), 0, "not before 250 ms");
    assert!(!visible(&h), "the game still holds its button");

    h.at(released + check_ms());
    assert_eq!(
        mouse_since(&h, released + 1),
        [(released + 250, "b2".to_owned())],
        "the press goes once more at once"
    );
    // The hand moves on while the re-sent press is held: those moves wait behind its release.
    h.at(released + 255);
    h.inject(hand()).unwrap();
    h.at(released + 270);
    h.inject(hand()).unwrap();
    h.run();
    let after = mouse_since(&h, released + 1);
    assert_eq!(
        after.first(),
        Some(&(released + 250, "b2".to_owned())),
        "{after:?}"
    );
    assert_eq!(
        after.get(1),
        Some(&(released + 280, "b0".to_owned())),
        "{after:?}"
    );
    assert_eq!(after.len(), 4, "the pair and the two moves: {after:?}");
    assert!(
        after[2..]
            .iter()
            .all(|(at, what)| what == "r" && *at >= released + 280),
        "the moves after the re-sent release: {after:?}"
    );
    assert!(visible(&h), "the game took the re-sent release");
    let tally = h.rt.watch.tally();
    assert_eq!(
        (
            tally.missed_releases,
            tally.resent,
            tally.helped,
            tally.failed
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(
        h.rt.watch.normal_pairs(RIGHT),
        3,
        "a re-send is not a normal pair"
    );
    // Once only: nothing more is sent however long the clock runs.
    h.at(released + 3_000);
    assert_eq!(presses_since(&h, released), 1);
}

/// Fewer than three pairs the game took: the watch cannot tell a missed release from a game that
/// keeps the cursor hidden, and re-sends nothing (it says so).
#[test]
fn fewer_than_three_normal_pairs_resend_nothing() {
    let mut h = game_harness();
    let t = turns(&mut h, 0, u64::from(NORMAL_PAIRS_MIN) - 1);
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 200);
    h.at(released + 1_000);
    assert_eq!(presses_since(&h, released), 0);
    let tally = h.rt.watch.tally();
    assert_eq!(
        (tally.missed_releases, tally.not_resent, tally.resent),
        (1, 1, 0)
    );
}

/// Outside game-only mode nothing is watched at all; in it, a game window that lost the front before
/// the check gets nothing, and neither does a desktop HID may not drive.
#[test]
fn outside_game_only_mode_or_with_the_game_not_in_front_nothing_is_resent() {
    let mut h = game_harness();
    h.rt.confine_to(QueueGate::Desktop);
    let t = turns(&mut h, 0, 4);
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 200);
    h.at(released + 1_000);
    assert_eq!(presses_since(&h, released), 0);
    assert_eq!(h.rt.watch.tally(), WatchTally::default());
    assert!(h.world().probes.is_empty());

    let mut h = game_harness();
    let t = turns(&mut h, 0, 4);
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 200);
    h.at(released + 100);
    h.world().foreground = NOTEPAD;
    h.at(released + 1_000);
    assert_eq!(presses_since(&h, released), 0);
    let tally = h.rt.watch.tally();
    assert_eq!((tally.not_resent, tally.resent), (1, 0));

    // A UAC prompt took the input before the check.
    let mut h = game_harness();
    let t = turns(&mut h, 0, 4);
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 200);
    h.at(released + 100);
    h.world().target = Target::Blocked;
    h.at(released + 1_000);
    assert_eq!(presses_since(&h, released), 0);
    assert_eq!(h.rt.watch.tally().resent, 0);
}

/// «Держать ПКМ»: the right button held on purpose for seconds, the camera turning — no release, so
/// nothing to re-send, and the press hid the cursor, so no missed press either. And a missed release
/// while another button is held is left alone.
#[test]
fn a_button_held_on_purpose_or_another_held_is_left_alone() {
    let mut h = game_harness();
    let t = turns(&mut h, 0, 4);
    h.button(RIGHT, true).unwrap();
    let mut at = t;
    for _ in 0..300 {
        at += 16;
        h.at(at);
        h.inject(hand()).unwrap();
    }
    assert_eq!(presses_since(&h, t), 1, "the viewer's press only");
    let tally = h.rt.watch.tally();
    assert_eq!((tally.resent, tally.missed_presses), (0, 0));
    assert!(!visible(&h));
    h.at(at + 16);
    h.button(RIGHT, false).unwrap();
    h.at(at + 1_000);
    assert!(visible(&h));
    assert_eq!(h.rt.watch.normal_pairs(RIGHT), 5);

    // The left button goes down before the check of a missed right release: something is held.
    let mut h = game_harness();
    let t = turns(&mut h, 0, 4);
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 200);
    h.at(released + 100);
    h.button(0, true).unwrap();
    h.at(released + 1_000);
    assert_eq!(presses_since(&h, released), 0);
    let tally = h.rt.watch.tally();
    assert_eq!((tally.not_resent, tally.resent), (1, 0));
}

/// A re-sent release the game does not take either: a `warn`, and the button is left alone — however
/// long the cursor stays hidden — until the viewer presses it again; then its pairs are watched
/// again.
#[test]
fn a_resend_that_does_not_help_warns_once_and_waits_for_the_next_press() {
    let log = logged(tracing::Level::WARN, || {
        let mut h = game_harness();
        let t = turns(&mut h, 0, 4);
        lose_releases(&h, 2);
        let released = turn(&mut h, t, 200);
        h.at(released + 5_000);
        assert_eq!(presses_since(&h, released), 1, "one re-send, no more");
        assert!(!visible(&h));
        let tally = h.rt.watch.tally();
        assert_eq!((tally.resent, tally.helped, tally.failed), (1, 0, 1));

        // The viewer presses again (the game already holds its button, the cursor stays hidden) and
        // lets go: the game takes it and shows the cursor.
        let again = turn(&mut h, released + 5_000, 200);
        h.at(again + 1_000);
        assert!(visible(&h));
        assert_eq!(presses_since(&h, released), 2);
        // Watched again: the next missed release is re-sent.
        let t = turns(&mut h, again + 1_000, 1);
        lose_releases(&h, 1);
        let lost = turn(&mut h, t, 200);
        h.at(lost + 1_000);
        assert_eq!(presses_since(&h, lost), 1);
        assert!(visible(&h));
    });
    let warns: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("did not take the re-sent release"))
        .collect();
    assert_eq!(warns.len(), 1, "{log}");
    assert!(
        warns[0].contains("WARN") && warns[0].contains("button=right"),
        "{log}"
    );
}

/// A press the game misses — the cursor still shows 250 ms into a held turn — is only said, with the
/// moves made meanwhile; nothing goes again.
#[test]
fn a_missed_press_is_only_said() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut h = game_harness();
        let t = turns(&mut h, 0, 3);
        h.world().game.as_mut().unwrap().lose_presses = 1;
        let released = turn(&mut h, t, 600);
        h.at(released + 1_000);
        assert_eq!(presses_since(&h, t), 1, "the viewer's press only");
        let tally = h.rt.watch.tally();
        assert_eq!((tally.missed_presses, tally.resent), (1, 0));
        assert!(visible(&h));
    });
    let missed: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("seems to have missed a press"))
        .collect();
    assert_eq!(missed.len(), 1, "{log}");
    assert!(missed[0].contains("camera_moves=15"), "{log}");
}

/// The probe lines: one per change, at `debug`, saying how the cursor took it and what Windows says
/// of the buttons; for the right button who has the mouse. A missed release and its re-send say so.
#[test]
fn every_change_is_probed_and_a_resend_is_said() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut h = game_harness();
        let t = turns(&mut h, 0, 3);
        lose_releases(&h, 1);
        let released = turn(&mut h, t, 200);
        h.at(released + 1_000);
    });
    let probes: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("how the game took it"))
        .collect();
    assert_eq!(probes.len(), 10, "four pairs and the re-send: {log}");
    assert!(
        probes[0].contains("way=\"press\"")
            && probes[0].contains("cursor=hidden after 20.0 ms")
            && probes[0].contains("windows_buttons=right")
            && probes[0].contains("capture=\"none\""),
        "{log}"
    );
    assert!(
        probes[1].contains("way=\"release\"")
            && probes[1].contains("cursor=shown after 20.0 ms")
            && probes[1].contains("windows_buttons=-"),
        "{log}"
    );
    assert!(
        probes[7].contains("way=\"release\"") && probes[7].contains("no change by 50.0 ms: hidden"),
        "the missed one: {log}"
    );
    assert!(
        probes[8].contains("resent=true") && probes[9].contains("resent=true"),
        "{log}"
    );
    assert_eq!(
        log.lines()
            .filter(|l| l.contains("pressed and released once more"))
            .count(),
        1,
        "{log}"
    );
    assert_eq!(
        log.lines()
            .filter(|l| l.contains("the re-sent release worked"))
            .count(),
        1,
        "{log}"
    );
}

/// `ra` while a missed release waits for its check ends the watch: nothing is re-sent after it.
#[test]
fn release_all_ends_the_watch() {
    let mut h = game_harness();
    let t = turns(&mut h, 0, 4);
    lose_releases(&h, 1);
    let released = turn(&mut h, t, 200);
    h.at(released + 100);
    h.release_all();
    assert!(h.rt.watch.due().is_none());
    h.at(released + 1_000);
    assert_eq!(presses_since(&h, released + 1), 0);
    assert_eq!(
        h.world()
            .count(|o| matches!(o, Out::SendInput(InputMessage::Down { .. }))),
        0
    );
}

/// The planner hears of every button change the router makes, and of a neutral report.
#[test]
fn the_planner_hears_of_the_routers_buttons() {
    let mut h = game_harness();
    h.button(RIGHT, true).unwrap();
    h.at(100);
    h.button(RIGHT, false).unwrap();
    h.at(200);
    h.button(0, true).unwrap();
    h.release_all();
    assert_eq!(
        h.world().hid_buttons,
        [
            (2, Some((2, true))),
            (0, Some((2, false))),
            (1, Some((1, true))),
            (0, None)
        ]
    );
}
