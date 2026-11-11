//! The game guard against a fake PC: a foreground window the test sets, a `SetForegroundWindow` that
//! Windows refuses or grants, the windows under each pixel (the game's, an always-on-top window of
//! another program over part of it, a child of another process inside it), and the planner's press
//! target. Nothing here touches Windows.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_core::game::ScreenRect;
use afklink_core::traits::{GameFocus, GameInputWindow, GameScope, InputScope};
use afklink_protocol::{GameWindowState, InputMessage, KeySource, Mods};

use super::{Admission, GameGuard, GuardHost, Reach, WindowAt, FOCUS_ATTEMPT_EVERY};
use crate::cursor_sync::{Elevation, ForegroundInfo};

const GAME: usize = 0x40666;
const GAME_PID: u32 = 6888;
const NOTEPAD: usize = 0x20;
const NOTEPAD_PID: u32 = 4242;
const OVERLAY: usize = 0x30;
const OVERLAY_PID: u32 = 5151;
/// Another window of the game's own process: a dialog of the game.
const GAME_DIALOG: usize = 0x41000;

/// The game's client area: a windowed game at +12+47, 3576×2268.
fn client() -> ScreenRect {
    ScreenRect {
        left: 12,
        top: 47,
        right: 3588,
        bottom: 2315,
    }
}

fn game() -> InputScope {
    InputScope::Game(GameScope {
        state: GameWindowState::Shown,
        window: Some(GameInputWindow {
            hwnd: GAME,
            pid: GAME_PID,
            client: client(),
        }),
    })
}

fn not_shown(state: GameWindowState) -> InputScope {
    InputScope::Game(GameScope {
        state,
        window: None,
    })
}

struct FakePc {
    foreground: usize,
    /// `SetForegroundWindow` brings the window to the front (else Windows refuses, as it usually
    /// does a background program).
    grants: bool,
    attempts: Vec<usize>,
    target: Option<(i32, i32)>,
    /// An always-on-top window of another program over this rectangle (right, bottom exclusive).
    overlay: Option<(i32, i32, i32, i32)>,
    /// A child window of another process inside the game's window, over this rectangle.
    embedded: Option<(i32, i32, i32, i32)>,
    window_error: bool,
    elevation: Option<Elevation>,
    driver_open: bool,
    /// Mouse buttons the paths hold, as their books say.
    buttons: u32,
}

impl FakePc {
    fn new() -> Self {
        Self {
            foreground: GAME,
            grants: false,
            attempts: Vec::new(),
            target: Some((1000, 1000)),
            overlay: None,
            embedded: None,
            window_error: false,
            elevation: Some(Elevation {
                foreground: false,
                agent: false,
                exe: "notepad.exe".into(),
            }),
            driver_open: true,
            buttons: 0,
        }
    }
}

fn inside(r: Option<(i32, i32, i32, i32)>, px: i32, py: i32) -> bool {
    r.is_some_and(|(x0, y0, x1, y1)| (x0..x1).contains(&px) && (y0..y1).contains(&py))
}

impl GuardHost for FakePc {
    fn foreground(&mut self) -> usize {
        self.foreground
    }

    fn window_pid(&mut self, window: usize) -> u32 {
        match window {
            GAME | GAME_DIALOG => GAME_PID,
            OVERLAY => OVERLAY_PID,
            NOTEPAD => NOTEPAD_PID,
            _ => 0,
        }
    }

    fn describe(&mut self, window: usize) -> ForegroundInfo {
        assert!(
            window != GAME && window != GAME_DIALOG,
            "the game's own process is never opened"
        );
        let exe = if window == OVERLAY {
            "overlay.exe"
        } else {
            "notepad.exe"
        };
        ForegroundInfo {
            pid: NOTEPAD_PID,
            exe: Ok(exe.into()),
            elevated: Ok(false),
            agent_elevated: Ok(false),
        }
    }

    fn set_foreground(&mut self, window: usize) -> Result<bool, String> {
        self.attempts.push(window);
        if self.grants {
            self.foreground = window;
        }
        Ok(self.grants)
    }

    fn window_at(&mut self, px: i32, py: i32) -> Result<WindowAt, String> {
        if self.window_error {
            return Err("WindowFromPoint: no window there".into());
        }
        Ok(if inside(self.overlay, px, py) {
            WindowAt {
                hwnd: OVERLAY,
                pid: OVERLAY_PID,
                root: OVERLAY,
                root_pid: OVERLAY_PID,
            }
        } else if inside(self.embedded, px, py) {
            WindowAt {
                hwnd: 0x50,
                pid: OVERLAY_PID,
                root: GAME,
                root_pid: GAME_PID,
            }
        } else {
            WindowAt {
                hwnd: GAME,
                pid: GAME_PID,
                root: GAME,
                root_pid: GAME_PID,
            }
        })
    }

    fn press_target(&mut self) -> Option<(i32, i32)> {
        self.target
    }

    fn foreground_elevation(&mut self) -> Option<Elevation> {
        self.elevation.clone()
    }

    fn driver_open(&self) -> bool {
        self.driver_open
    }

    fn held_buttons(&mut self) -> u32 {
        self.buttons
    }
}

struct Rig {
    guard: GameGuard,
    pc: FakePc,
    t0: Instant,
    now: Instant,
}

impl Rig {
    fn new() -> Self {
        Self::with(GameGuard::default())
    }

    fn with(guard: GameGuard) -> Self {
        let t0 = Instant::now();
        Self {
            guard,
            pc: FakePc::new(),
            t0,
            now: t0,
        }
    }

    fn at(&mut self, ms: u64) {
        self.now = self.t0 + Duration::from_millis(ms);
    }

    fn admit(&mut self, event: InputMessage, scope: &InputScope) -> Admission {
        self.guard.admit(&event, scope, &mut self.pc, self.now)
    }

    /// Whether `event` in game scope goes through (as it is).
    fn passes(&mut self, event: InputMessage) -> bool {
        let admitted = self.admit(event.clone(), &game());
        match admitted.event {
            Some(out) => {
                assert_eq!(out, event, "passed unchanged");
                true
            }
            None => false,
        }
    }

    fn watch(&mut self, scope: &InputScope) -> (GameFocus, bool) {
        let InputScope::Game(game) = scope else {
            unreachable!("the watch runs in game-only mode")
        };
        self.guard.watch(game, &mut self.pc, self.now)
    }
}

fn key(code: &str, down: bool) -> InputMessage {
    key_from(code, down, None)
}

/// A key the viewer tagged as one of its own (`k.src`), or not.
fn key_from(code: &str, down: bool, src: Option<KeySource>) -> InputMessage {
    InputMessage::Key {
        d: u8::from(down),
        code: code.into(),
        key: None,
        mods: None,
        src,
    }
}

const CELL: Option<KeySource> = Some(KeySource::Cell);
const SHEET: Option<KeySource> = Some(KeySource::Sheet);

fn m(x: f64, y: f64) -> InputMessage {
    InputMessage::Move { x, y }
}

fn rel() -> InputMessage {
    InputMessage::Rel {
        dx: 0.01,
        dy: 0.0,
        s: None,
        x: None,
        y: None,
    }
}

fn text(t: &str) -> InputMessage {
    InputMessage::Text {
        text: t.into(),
        game: None,
    }
}

fn wheel() -> InputMessage {
    InputMessage::Wheel {
        dx: 0.0,
        dy: 100.0,
        mode: None,
        game: Some(true),
    }
}

/* ── The foreground gate ── */

/// The game has the front: everything goes. Another window takes it: moves, presses, key-downs,
/// the wheel, text and combos are dropped, everything held is released once, and releases always
/// pass; the game is asked back at most every two seconds, on the viewer's input only.
#[test]
fn input_goes_only_while_the_game_has_the_front_and_releases_always_pass() {
    let mut r = Rig::new();
    let first = r.admit(m(0.5, 0.5), &game());
    assert_eq!(first.event, Some(m(0.5, 0.5)));
    assert!(!first.release, "the session's first look: nothing held yet");
    assert!(r.passes(InputMessage::Down { b: 0 }));
    assert!(r.passes(key("KeyW", true)));
    assert!(r.passes(r_up_of_button()));

    // Notepad takes the front.
    r.at(100);
    r.pc.foreground = NOTEPAD;
    let lost = r.admit(rel(), &game());
    assert_eq!(lost.event, None, "a move into Notepad is dropped");
    assert!(lost.release, "what the game held is released at once");
    assert_eq!(r.pc.attempts, vec![GAME], "and the game asked back");
    for event in [
        m(0.2, 0.2),
        rel(),
        InputMessage::Down { b: 0 },
        key("KeyA", true),
        wheel(),
        text("hi"),
        InputMessage::Combo {
            name: "ctrl_alt_del".into(),
        },
    ] {
        let a = r.admit(event.clone(), &game());
        assert_eq!(a.event, None, "{event:?} goes nowhere while unfocused");
        assert!(!a.release, "released once, not per event");
    }
    // Releases pass: a button, the key held before, everything.
    for event in [
        InputMessage::Up { b: 0 },
        key("KeyW", false),
        key("KeyA", false),
        InputMessage::ReleaseAll,
    ] {
        assert_eq!(
            r.admit(event.clone(), &game()).event,
            Some(event.clone()),
            "{event:?} always passes"
        );
    }
    assert_eq!(r.pc.attempts.len(), 1, "one attempt per two seconds");

    // The focus watch looks, never asks.
    for ms in [500, 1_000, 3_000, 5_000] {
        r.at(ms);
        assert_eq!(r.watch(&game()), (GameFocus::Unfocused, false));
    }
    assert_eq!(r.pc.attempts.len(), 1, "the watch never asks the game back");

    // The viewer's next input, two seconds on: asked again. Windows grants it this time.
    r.at(5_100);
    r.pc.grants = true;
    assert_eq!(
        r.admit(rel(), &game()).event,
        None,
        "this move is still dropped"
    );
    assert_eq!(r.pc.attempts, vec![GAME, GAME]);
    assert_eq!(r.pc.foreground, GAME);
    let back = r.admit(m(0.5, 0.5), &game());
    assert_eq!(
        back.event,
        Some(m(0.5, 0.5)),
        "the game has the front again"
    );
    assert!(!back.release);
}

fn r_up_of_button() -> InputMessage {
    InputMessage::Up { b: 0 }
}

/// With the viewer idle, the focus watch alone sees the game lose the front and releases what is
/// held (a held W would auto-repeat into Notepad); a window that stops being shown releases too.
#[test]
fn the_focus_watch_releases_when_the_game_loses_the_front_with_no_input() {
    let mut r = Rig::new();
    assert!(r.passes(key("KeyW", true)));
    assert_eq!(r.watch(&game()), (GameFocus::Focused, false));
    r.pc.foreground = NOTEPAD;
    r.at(50);
    assert_eq!(r.watch(&game()), (GameFocus::Unfocused, true));
    assert_eq!(r.watch(&game()), (GameFocus::Unfocused, false), "once");
    // Another window after Notepad: still unfocused, nothing more to release.
    r.pc.foreground = 0;
    assert_eq!(r.watch(&game()), (GameFocus::Unfocused, false));
    r.pc.foreground = GAME;
    assert_eq!(r.watch(&game()), (GameFocus::Focused, false));
    // Minimized while focused.
    let minimized = not_shown(GameWindowState::Minimized);
    assert_eq!(r.watch(&minimized), (GameFocus::NotShown, true));
    assert!(r.pc.attempts.is_empty());
}

/// A dialog of the game's own in front: not the picture the viewer sees, so input is held back all
/// the same — and the game's process is not opened to say so (the fake PC fails the test if it is).
#[test]
fn a_window_of_the_games_own_process_in_front_is_not_the_game() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new();
        assert!(r.passes(m(0.5, 0.5)));
        r.pc.foreground = GAME_DIALOG;
        let a = r.admit(InputMessage::Down { b: 0 }, &game());
        assert_eq!(a.event, None);
        assert!(a.release);
        assert_eq!(r.watch(&game()), (GameFocus::Unfocused, false));
    });
    assert!(
        log.contains("another window of the game's own process has the front"),
        "{log}"
    );
    assert!(log.contains("game input: press dropped"), "{log}");
}

/// Absent, starting, minimized, not captured yet: nothing but releases, and no attempt to bring a
/// window that is not shown to the front.
#[test]
fn a_window_that_is_not_shown_takes_nothing_but_releases() {
    for state in [
        GameWindowState::Absent,
        GameWindowState::Starting,
        GameWindowState::Minimized,
    ] {
        let mut r = Rig::new();
        let scope = not_shown(state);
        for event in [
            m(0.5, 0.5),
            rel(),
            InputMessage::Down { b: 1 },
            key("KeyW", true),
            text("hi"),
            wheel(),
        ] {
            assert_eq!(r.admit(event, &scope).event, None, "{state:?}");
        }
        for event in [
            InputMessage::Up { b: 1 },
            key("KeyW", false),
            InputMessage::ReleaseAll,
        ] {
            assert_eq!(r.admit(event.clone(), &scope).event, Some(event));
        }
        assert!(r.pc.attempts.is_empty());
    }
}

/// Game-only mode turned on while the viewer holds something on the desktop: released, so a Win or
/// a Shift held there does not act in the game (or open Start on its release).
#[test]
fn entering_game_only_mode_releases_what_the_desktop_held() {
    let mut r = Rig::new();
    let a = r.admit(key("MetaLeft", true), &InputScope::Desktop);
    assert_eq!(
        a.event,
        Some(key("MetaLeft", true)),
        "on the desktop Win is Win"
    );
    assert!(!a.release);
    let a = r.admit(m(0.5, 0.5), &game());
    assert!(a.release, "entering the game releases the desktop's");
    assert_eq!(
        r.admit(key("MetaLeft", false), &game()).event,
        None,
        "that Win was released already: its release goes nowhere (no Start menu)"
    );
    // And back to the desktop: nothing to release.
    assert!(!r.admit(m(0.5, 0.5), &InputScope::Desktop).release);
}

/* ── Escape keys ── */

/// Every escape the owner listed is blocked, whichever key of the combination comes second; the
/// blocked key's release is dropped with it, the other key's passes: nothing is stranded.
#[test]
fn escape_keys_are_blocked_and_their_releases_dropped_with_them() {
    /// A key, down or up, and whether it passes.
    type Step = (&'static str, bool, bool);
    let cases: &[(&str, &[Step])] = &[
        (
            "Win alone",
            &[("MetaLeft", true, false), ("MetaLeft", false, false)],
        ),
        (
            "right Win",
            &[("MetaRight", true, false), ("MetaRight", false, false)],
        ),
        (
            "OS key",
            &[("OSLeft", true, false), ("OSLeft", false, false)],
        ),
        (
            "Win+D",
            &[
                ("MetaLeft", true, false),
                ("KeyD", true, false),
                ("KeyD", false, false),
                ("MetaLeft", false, false),
                ("KeyD", true, true),
                ("KeyD", false, true),
            ],
        ),
        (
            "Alt+Tab",
            &[
                ("AltLeft", true, true),
                ("Tab", true, false),
                ("Tab", true, false),
                ("Tab", false, false),
                ("AltLeft", false, true),
                ("Tab", true, true),
                ("Tab", false, true),
            ],
        ),
        (
            "Tab, then Alt",
            &[
                ("Tab", true, true),
                ("AltRight", true, false),
                ("Tab", true, true),
                ("AltRight", false, false),
                ("Tab", false, true),
            ],
        ),
        (
            "Alt+Esc",
            &[
                ("AltRight", true, true),
                ("Escape", true, false),
                ("Escape", false, false),
                ("AltRight", false, true),
            ],
        ),
        (
            "Ctrl+Esc",
            &[
                ("ControlLeft", true, true),
                ("Escape", true, false),
                ("Escape", false, false),
                ("ControlLeft", false, true),
                ("Escape", true, true),
                ("Escape", false, true),
            ],
        ),
        (
            "Ctrl+Shift+Esc",
            &[
                ("ControlRight", true, true),
                ("ShiftLeft", true, true),
                ("Escape", true, false),
                ("Escape", false, false),
                ("ShiftLeft", false, true),
                ("ControlRight", false, true),
            ],
        ),
        (
            "Esc, then Ctrl",
            &[
                ("Escape", true, true),
                ("ControlLeft", true, false),
                ("ControlLeft", false, false),
                ("Escape", false, true),
            ],
        ),
        (
            "Alt+F4 passes (not blocked for anyone)",
            &[
                ("AltLeft", true, true),
                ("F4", true, true),
                ("F4", true, true),
                ("F4", false, true),
                ("AltLeft", false, true),
            ],
        ),
        (
            "F4, then Alt: passes too",
            &[
                ("F4", true, true),
                ("AltRight", true, true),
                ("AltRight", false, true),
                ("F4", false, true),
            ],
        ),
        (
            "ordinary keys and Alt+Shift",
            &[
                ("KeyW", true, true),
                ("AltLeft", true, true),
                ("ShiftLeft", true, true),
                ("ShiftLeft", false, true),
                ("AltLeft", false, true),
                ("KeyW", false, true),
            ],
        ),
    ];
    for (name, steps) in cases {
        let mut r = Rig::new();
        for (i, &(code, down, passes)) in steps.iter().enumerate() {
            assert_eq!(
                r.passes(key(code, down)),
                passes,
                "{name}, step {i}: {code} {}",
                if down { "down" } else { "up" }
            );
        }
    }
}

/// The `combo` message (`ctrl_alt_del`, and any name a newer viewer may send) is blocked.
#[test]
fn combos_are_blocked() {
    let mut r = Rig::new();
    assert!(!r.passes(InputMessage::Combo {
        name: "ctrl_alt_del".into()
    }));
    assert!(!r.passes(InputMessage::Combo {
        name: "something_newer".into()
    }));
}

/// Alt+F4 is the one shortcut of GameGuard's list that passes, for a guest too: either way round, with either Alt, and right after an escape beside it
/// was blocked — the guard has one key list for every session, whoever is connected.
#[test]
fn alt_f4_passes_for_everyone_while_the_other_escapes_stay_blocked() {
    let mut r = Rig::new();
    for alt in ["AltLeft", "AltRight"] {
        assert!(r.passes(key(alt, true)));
        assert!(!r.passes(key("Tab", true)), "{alt}+Tab still blocked");
        assert!(!r.passes(key("Tab", false)));
        assert!(r.passes(key("F4", true)), "{alt}+F4 passes");
        assert!(r.passes(key("F4", false)));
        assert!(!r.passes(key("Escape", true)), "{alt}+Esc still blocked");
        assert!(!r.passes(key("Escape", false)));
        assert!(r.passes(key(alt, false)));
    }
    assert!(r.passes(key("F4", true)));
    assert!(r.passes(key("AltLeft", true)), "F4, then Alt");
    assert!(r.passes(key("AltLeft", false)));
    assert!(r.passes(key("F4", false)));
    assert_eq!(
        r.guard.stats.keys_blocked, 4,
        "Tab and Esc twice, nothing else"
    );
    // Nothing of it was held back as a dropped key either.
    assert_eq!(r.guard.stats.keys_dropped, 0);
}

/// A key's `mods` never decide: what counts is what is down on the PC through us. And `ra` forgets
/// both what was held and what was blocked, so Tab after it is Tab.
#[test]
fn combinations_are_judged_on_what_is_down_and_forgotten_on_release_all() {
    let mut r = Rig::new();
    let with_alt = InputMessage::Key {
        d: 1,
        code: "KeyQ".into(),
        key: None,
        mods: Some(Mods {
            alt: true,
            ..Mods::default()
        }),
        src: None,
    };
    assert!(r.passes(with_alt));
    assert!(r.passes(key("AltLeft", true)));
    assert!(!r.passes(key("Tab", true)));
    assert!(r.passes(InputMessage::ReleaseAll));
    assert!(r.passes(key("Tab", true)), "nothing is down after `ra`");
    assert!(r.passes(key("Tab", false)));
}

/// A Win key blocked in game-only mode whose release comes after the mode was turned off: dropped
/// all the same. A Win pressed on the desktop is the desktop's.
#[test]
fn a_blocked_keys_release_is_dropped_after_the_mode_is_off_too() {
    let mut r = Rig::new();
    assert!(!r.passes(key("MetaLeft", true)));
    assert_eq!(
        r.admit(key("MetaLeft", false), &InputScope::Desktop).event,
        None
    );
    assert_eq!(
        r.admit(key("MetaLeft", true), &InputScope::Desktop).event,
        Some(key("MetaLeft", true))
    );
    assert_eq!(
        r.admit(key("MetaLeft", false), &InputScope::Desktop).event,
        Some(key("MetaLeft", false))
    );
    // A lone Win release on the desktop passes as it always did.
    assert_eq!(
        r.admit(key("MetaRight", false), &InputScope::Desktop).event,
        Some(key("MetaRight", false))
    );
}

/* ── Text ── */

#[test]
fn text_goes_by_the_driver_in_game_only_mode_and_to_an_elevated_window() {
    let game_text = |t: &str| InputMessage::Text {
        text: t.into(),
        game: Some(true),
    };
    // Game-only: always the driver's typing.
    let mut r = Rig::new();
    assert_eq!(r.admit(text("gg"), &game()).event, Some(game_text("gg")));
    r.pc.driver_open = false;
    assert_eq!(
        r.admit(text("gg"), &game()).event,
        Some(game_text("gg")),
        "without the driver it goes by Unicode further down, as game text does"
    );

    let desktop = InputScope::Desktop;
    let elevated = |agent: bool| {
        Some(Elevation {
            foreground: true,
            agent,
            exe: "Taskmgr.exe".into(),
        })
    };
    // An ordinary window: Unicode, as ever.
    let mut r = Rig::new();
    assert_eq!(r.admit(text("hi"), &desktop).event, Some(text("hi")));
    // An elevated window, the driver open: typed through it.
    r.pc.elevation = elevated(false);
    assert_eq!(r.admit(text("hi"), &desktop).event, Some(game_text("hi")));
    // The same, no driver: Unicode (Windows may drop it; nothing else can reach it).
    r.pc.driver_open = false;
    assert_eq!(r.admit(text("hi"), &desktop).event, Some(text("hi")));
    // The agent elevated too: Unicode reaches it.
    r.pc.driver_open = true;
    r.pc.elevation = elevated(true);
    assert_eq!(r.admit(text("hi"), &desktop).event, Some(text("hi")));
    // Unreadable: Unicode.
    r.pc.elevation = None;
    assert_eq!(r.admit(text("hi"), &desktop).event, Some(text("hi")));
    // The viewer's game text stays game text.
    assert_eq!(
        r.admit(game_text("hi"), &desktop).event,
        Some(game_text("hi"))
    );
}

/// The decision text and the wheel share (the wheel takes it in the router): through the driver only
/// for a window that runs elevated while the agent does not, and only with the driver open.
#[test]
fn text_and_the_wheel_share_one_decision_on_the_foreground_windows_elevation() {
    let window = |foreground: bool, agent: bool| Elevation {
        foreground,
        agent,
        exe: "x.exe".into(),
    };
    for (elevation, driver_open, want) in [
        (Some(window(true, false)), true, Reach::Driver),
        (Some(window(true, false)), false, Reach::ElevatedNoDriver),
        (Some(window(true, true)), true, Reach::BothElevated),
        (Some(window(false, false)), true, Reach::Ordinary),
        // An elevated agent reaches an ordinary window too.
        (Some(window(false, true)), true, Reach::Ordinary),
        (None, true, Reach::Unknown),
        (None, false, Reach::Unknown),
    ] {
        assert_eq!(
            Reach::of(elevation.as_ref(), driver_open),
            want,
            "{elevation:?}, driver open: {driver_open}"
        );
    }
}

/// The guard passes the wheel as it comes, marked or not, on the desktop and to the focused game:
/// where it goes is the router's to decide when it is sent.
#[test]
fn the_guard_passes_the_wheel_unchanged() {
    let desktop_wheel = InputMessage::Wheel {
        dx: 0.0,
        dy: 4.0,
        mode: None,
        game: None,
    };
    let mut r = Rig::new();
    r.pc.elevation = Some(Elevation {
        foreground: true,
        agent: false,
        exe: "Taskmgr.exe".into(),
    });
    for event in [desktop_wheel, wheel()] {
        assert_eq!(
            r.admit(event.clone(), &InputScope::Desktop).event,
            Some(event.clone())
        );
        assert!(r.passes(event));
    }
}

/* ── Presses onto the game only ── */

#[test]
fn a_press_lands_only_on_a_window_of_the_games_process() {
    let mut r = Rig::new();
    // An always-on-top window of another program over the game's top-right corner, and a child
    // window of another process embedded in the game's window lower down.
    r.pc.overlay = Some((3000, 47, 3588, 400));
    r.pc.embedded = Some((100, 2000, 600, 2300));

    r.pc.target = Some((1800, 1181));
    assert!(r.passes(InputMessage::Down { b: 0 }), "the game's window");
    assert!(r.passes(InputMessage::Up { b: 0 }));

    r.pc.target = Some((3200, 200));
    assert!(
        !r.passes(InputMessage::Down { b: 0 }),
        "the overlay swallows no click"
    );
    assert!(
        r.passes(InputMessage::Up { b: 0 }),
        "the release passes all the same"
    );

    r.pc.target = Some((300, 2100));
    assert!(
        r.passes(InputMessage::Down { b: 2 }),
        "a child of another process inside the game's window is the game's"
    );
    assert!(r.passes(InputMessage::Up { b: 2 }));

    r.pc.target = None;
    assert!(
        !r.passes(InputMessage::Down { b: 0 }),
        "where it would land is unknown"
    );
    r.pc.target = Some((1800, 1181));
    r.pc.window_error = true;
    assert!(
        !r.passes(InputMessage::Down { b: 0 }),
        "the window there cannot be read"
    );
    // Moves are not presses: they are confined by the planner, not dropped here.
    assert!(r.passes(m(0.99, 0.01)));
}

/* ── Logs ── */

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

/// Transitions, attempts, blocks, dropped presses and the text's route at `debug`, and one
/// aggregate a second — never a line per event: three seconds of a moving finger with Notepad in
/// front are a handful of lines.
#[test]
fn every_decision_is_said_once_and_the_drops_are_aggregated() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new();
        r.pc.overlay = Some((3000, 47, 3588, 400));
        r.admit(m(0.5, 0.5), &game());
        r.pc.foreground = NOTEPAD;
        for i in 0..180 {
            r.at(i * 16);
            r.admit(rel(), &game());
        }
        r.pc.foreground = GAME;
        r.at(3_000);
        r.admit(key("MetaLeft", true), &game());
        r.admit(key("MetaLeft", false), &game());
        r.admit(key("AltLeft", true), &game());
        r.admit(key("Tab", true), &game());
        r.pc.target = Some((3200, 200));
        r.admit(InputMessage::Down { b: 0 }, &game());
        // A text no log word contains ("gg" is in `src="untagged"`).
        r.admit(text("qz9"), &game());
        r.admit(text("qz9"), &game());
        r.at(4_100);
        r.admit(m(0.5, 0.5), &game());
    });
    let lines = log.lines().count();
    assert!(lines <= 16, "{lines} debug lines:\n{log}");
    // The key log's line for the second of keys: the viewer's keyboard's only counted.
    assert!(log.contains("keys: presses"), "{log}");
    assert!(log.contains("other=1 dropped=2"), "{log}");
    for said in [
        "the game's window has the front",
        "another window has the front",
        "notepad.exe",
        "SetForegroundWindow",
        "key=MetaLeft",
        "combo=\"Win\"",
        "combo=\"Alt+Tab\"",
        "press dropped: another program's window is over the game",
        "overlay.exe",
        "text route",
        "moves_dropped=",
        "focus_attempts=",
        "keys_blocked=2",
        "presses_off_game=1",
    ] {
        assert!(log.contains(said), "{said:?} missing:\n{log}");
    }
    assert_eq!(
        log.matches("text route").count(),
        1,
        "said on a change only:\n{log}"
    );
    assert!(
        !log.contains("game input: held back"),
        "a drop at debug:\n{log}"
    );
    assert!(!log.contains("qz9"), "never the text:\n{log}");

    let trace = logged(tracing::Level::TRACE, || {
        let mut r = Rig::new();
        r.pc.foreground = NOTEPAD;
        r.admit(rel(), &game());
    });
    assert!(trace.contains("game input: held back"), "{trace}");
}

/* ── Which keys: the key log (`crate::key_log`) ── */

/// The game's window goes away a moment after the viewer's key cells.
/// The transition line says what was really down then (`released=true` alone is not "a key was
/// held"), and the flight recorder says which keys of ours came last — the viewer's own keyboard's
/// only counted.
#[test]
fn when_the_game_goes_away_the_log_says_what_was_held_and_which_of_our_keys_came_last() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new();
        assert!(r.passes(m(0.5, 0.5)));
        // The `l2` preset: the Alt+B cell, F1, and the fixed Ctrl held; a tap of the viewer's own
        // keyboard among them.
        r.at(100);
        for (code, down) in [
            ("AltLeft", true),
            ("KeyB", true),
            ("KeyB", false),
            ("AltLeft", false),
            ("F1", true),
            ("F1", false),
            ("ControlLeft", true),
        ] {
            assert!(r.passes(key_from(code, down, CELL)));
        }
        r.at(200);
        assert!(r.passes(key("KeyQ", true)));
        assert!(r.passes(key("KeyQ", false)));
        // A mouse button held too, on the paths' books.
        r.pc.buttons = 1;
        // The game quits: its window is gone.
        r.at(1_100);
        assert_eq!(
            r.watch(&not_shown(GameWindowState::Absent)),
            (GameFocus::NotShown, true)
        );
        // Shown again later, nothing held: released=false, and held_* all naught.
        r.pc.buttons = 0;
        r.at(9_000);
        assert_eq!(r.watch(&game()), (GameFocus::Focused, false));
    });
    let gone = log
        .lines()
        .find(|l| l.contains("cannot take input"))
        .unwrap_or_else(|| panic!("no transition line:\n{log}"));
    for said in [
        "from=\"focused\"",
        "state=\"absent\"",
        "released=true",
        "held_keys=0",
        "held_mods=1",
        "held_buttons=1",
        "held_ours=ControlLeft",
        "held_other=0",
        "releases were sent whether or not anything was held",
    ] {
        assert!(gone.contains(said), "{said:?} missing: {gone}");
    }
    let recorder = log
        .lines()
        .find(|l| l.contains("keys: the last of ours"))
        .unwrap_or_else(|| panic!("no recorder line:\n{log}"));
    for said in [
        "no longer shown",
        "recorded=7",
        "cell AltLeft down -1000ms, cell KeyB down -1000ms",
        "cell ControlLeft down -1000ms",
        "untagged_since_oldest=2",
        "untagged_last_ms=900",
    ] {
        assert!(recorder.contains(said), "{said:?} missing: {recorder}");
    }
    let back = log
        .lines()
        .find(|l| l.contains("the game's window has the front") && l.contains("not_shown"))
        .unwrap_or_else(|| panic!("no line for the window back:\n{log}"));
    for said in [
        "released=false",
        "held_keys=0",
        "held_mods=0",
        "held_ours=-",
    ] {
        assert!(back.contains(said), "{said:?} missing: {back}");
    }
    assert!(
        !log.contains("KeyQ"),
        "a key of the viewer's keyboard named:\n{log}"
    );
    assert_eq!(log.matches("keys: the last of ours").count(), 1, "{log}");
}

/// The game losing the front writes the recorder out too (the viewer may go on pressing while it is
/// held back, and push the keys before it out of the recorder); so does Alt+F4 let through, with the
/// F4 that made it.
#[test]
fn losing_the_front_and_alt_f4_write_the_recorder_out() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new();
        assert!(r.passes(key_from("Tab", true, SHEET)));
        assert!(r.passes(key_from("Tab", false, SHEET)));
        r.pc.foreground = NOTEPAD;
        r.at(50);
        assert_eq!(r.watch(&game()), (GameFocus::Unfocused, true));
        r.pc.foreground = GAME;
        r.at(100);
        assert_eq!(r.watch(&game()), (GameFocus::Focused, false));
        assert!(r.passes(key_from("AltLeft", true, CELL)));
        assert!(r.passes(key_from("F4", true, CELL)));
    });
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("keys: the last of ours"))
        .collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines[0].contains("lost the front"), "{}", lines[0]);
    assert!(
        lines[0].contains("sheet Tab down -50ms, sheet Tab up -50ms"),
        "{}",
        lines[0]
    );
    assert!(lines[1].contains("Alt+F4 let through"), "{}", lines[1]);
    assert!(
        lines[1].contains("cell AltLeft down -0ms, cell F4 down -0ms"),
        "{}",
        lines[1]
    );
    let passes = log
        .lines()
        .find(|l| l.contains("Alt+F4 passes"))
        .unwrap_or_else(|| panic!("{log}"));
    assert!(
        passes.contains("key=F4") && passes.contains("src=\"cell\""),
        "{passes}"
    );
}

/// A blocked key is said with the combination for every source, and with where it came from; the key
/// itself only when it is ours or a key of the combination — under a held Win, any key of the
/// viewer's keyboard is `-`.
#[test]
fn a_blocked_key_names_its_combination_and_source_but_not_a_key_of_the_viewers_keyboard() {
    let log = logged(tracing::Level::TRACE, || {
        let mut r = Rig::new();
        assert!(!r.passes(key("MetaLeft", true)));
        assert!(!r.passes(key("KeyR", true)));
        assert!(!r.passes(key("KeyR", true)), "its repeat");
        assert!(!r.passes(key("KeyR", false)));
        assert!(!r.passes(key_from("KeyE", true, CELL)));
        assert!(!r.passes(key("MetaLeft", false)));
        assert!(r.passes(key_from("AltLeft", true, CELL)));
        assert!(!r.passes(key_from("Tab", true, CELL)));
    });
    assert!(
        log.contains(r#"key=MetaLeft combo="Win" src="untagged""#),
        "{log}"
    );
    assert!(
        log.contains(r#"key=- combo="Win+key" src="untagged""#),
        "{log}"
    );
    assert!(
        log.contains(r#"key=KeyE combo="Win+key" src="cell""#),
        "{log}"
    );
    assert!(
        log.contains(r#"key=Tab combo="Alt+Tab" src="cell""#),
        "{log}"
    );
    assert!(
        !log.contains("KeyR"),
        "a key of the viewer's keyboard named:\n{log}"
    );
}

/// The key log's line a second, in any mode: on the desktop too, and between events when the cursor
/// poll asks.
#[test]
fn the_keys_line_goes_out_once_a_second_in_any_mode() {
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new();
        for code in ["KeyW", "KeyA"] {
            r.admit(key(code, true), &InputScope::Desktop);
            r.admit(key(code, false), &InputScope::Desktop);
        }
        r.admit(key_from("F5", true, CELL), &InputScope::Desktop);
        r.admit(key_from("F5", false, CELL), &InputScope::Desktop);
        r.at(999);
        r.guard.flush_keys_if_due(r.now);
        r.at(1_000);
        r.guard.flush_keys_if_due(r.now);
    });
    assert_eq!(log.matches("keys: presses").count(), 1, "{log}");
    let line = log
        .lines()
        .find(|l| l.contains("keys: presses"))
        .unwrap_or_else(|| panic!("no keys line:\n{log}"));
    assert!(line.contains("cells=F5 "), "{line}");
    assert!(line.contains("other=2"), "{line}");
    assert!(line.contains("ups=3"), "{line}");
    assert!(line.contains("window_ms=1000"), "{line}");
    assert!(!log.contains("KeyW") && !log.contains("KeyA"), "{log}");
}

/// Two seconds between attempts, whatever the viewer sends in between.
#[test]
fn the_game_is_asked_back_at_most_every_two_seconds() {
    let mut r = Rig::new();
    r.pc.foreground = NOTEPAD;
    let every = u64::try_from(FOCUS_ATTEMPT_EVERY.as_millis()).unwrap();
    for ms in (0..10_000).step_by(16) {
        r.at(ms);
        r.admit(rel(), &game());
    }
    let expected = usize::try_from(10_000 / every + 1).unwrap();
    assert!(
        (expected - 1..=expected).contains(&r.pc.attempts.len()),
        "{} attempts in 10 s",
        r.pc.attempts.len()
    );
}

/* ── A flood of distinct keys (KB-6) ── */

/// Ten thousand distinct key codes, on the desktop and then in game-only mode under a held Win
/// (where every new key is blocked as `Win+key`): the guard's books and its key log's stay at the
/// cap, the full book is warned once, and the per-event lines stop at the line gate's burst — the
/// rest are counted in the aggregate.
#[test]
fn a_flood_of_distinct_keys_keeps_the_books_and_the_lines_bounded() {
    use super::MAX_GUARD_KEYS;
    use crate::line_gate::LineGate;
    let mut books = Vec::new();
    let log = logged(tracing::Level::DEBUG, || {
        let mut r = Rig::new();
        for i in 0..10_000 {
            r.admit(key(&format!("C{i}"), true), &InputScope::Desktop);
        }
        books.push(r.guard.books());
        r.admit(InputMessage::ReleaseAll, &InputScope::Desktop);

        let mut r = Rig::new();
        assert!(!r.passes(key("MetaLeft", true)), "Win is blocked");
        for i in 0..10_000 {
            assert!(!r.passes(key(&format!("C{i}"), true)), "Win+key is blocked");
        }
        books.push(r.guard.books());
        // Past the cap a blocked key is not booked, so its release passes: nothing of it was down.
        assert!(r.passes(key("C9999", false)));
    });
    assert_eq!(
        books[0],
        (MAX_GUARD_KEYS, 0, MAX_GUARD_KEYS),
        "desktop: held at the cap"
    );
    assert_eq!(books[1], (0, MAX_GUARD_KEYS, 0), "game: blocked at the cap");
    assert_eq!(
        log.matches("book of keys is full").count(),
        2,
        "once a guard:\n{log}"
    );
    let blocked_lines = log.matches("game input: key blocked").count();
    assert!(
        blocked_lines <= LineGate::BURST as usize,
        "{blocked_lines} key-blocked lines"
    );
    let lines = log.lines().count();
    assert!(
        lines <= 40,
        "{lines} debug lines for 20 000 key messages:\n{log}"
    );
}
