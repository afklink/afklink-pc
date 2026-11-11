//! A fake world for the router's tests: a device that records every report, a SendInput path that
//! records what it is asked (and counts its wheels), the desktop's target, the foreground window's
//! elevation, keyboard layouts — US, Russian, German (AltGr,
//! Y and Z swapped) and French (dead keys, Shift for digits) — that answer as user32 would, and, when
//! a test asks for it, the real cursor-sync planner with a simulated cursor the reports move (which
//! `GetCursorPos` reads too), and a game that hides the cursor while its camera button is held
//! ([`FakeGame`], for the button watch). All on a virtual clock the test moves; nothing here touches
//! Windows.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use afklink_protocol::InputMessage;
use anyhow::{bail, Result};

use super::button_watch::ButtonProbe;
use super::typing::{Hkl, KeyState, Keyboard, LanguageHotkey, Produced, LALT, LCTRL, LSHIFT, RALT};
use super::{Driver, HidRuntime, Host, Report, SendInputPath, State, Target, TargetEval};
use crate::cursor_sync::sim::SimCursor;
use crate::cursor_sync::{
    target_pixel, CursorLook, CursorSync, CursorWorld, Elevation, Plan, RelEvent, RelPath,
    WheelTally,
};

/// A game that hides the cursor while one of its buttons is held — Lineage 2 turning its camera with
/// the right button — as the device's button reports tell it, [`Self::react`] later; and that does
/// not take the presses or releases a test tells it to lose.
pub(crate) struct FakeGame {
    /// The HID bit that turns the camera (2: the right button).
    pub(crate) bit: u8,
    /// How long after a report the cursor hides or shows.
    pub(crate) react: Duration,
    /// The next releases (presses) of the bit the game does not take.
    pub(crate) lose_releases: u32,
    pub(crate) lose_presses: u32,
    /// What the game believes of its button.
    pub(crate) down: bool,
    /// Whether it shows the cursor now.
    pub(crate) visible: bool,
    pending: VecDeque<(Instant, bool)>,
}

impl FakeGame {
    /// The right button turns the camera; the cursor hides or shows 20 ms after a report.
    pub(crate) fn right_button() -> Self {
        Self {
            bit: 2,
            react: Duration::from_millis(20),
            lose_releases: 0,
            lose_presses: 0,
            down: false,
            visible: true,
            pending: VecDeque::new(),
        }
    }

    /// The device's buttons went from `before` to `buttons` at `now`.
    fn report(&mut self, before: u8, buttons: u8, now: Instant) {
        let (was, is) = (before & self.bit != 0, buttons & self.bit != 0);
        if was == is {
            return;
        }
        if is {
            if self.lose_presses > 0 {
                self.lose_presses -= 1;
                return;
            }
            self.down = true;
            self.pending.push_back((now + self.react, false));
        } else {
            if self.lose_releases > 0 {
                self.lose_releases -= 1;
                return;
            }
            self.down = false;
            self.pending.push_back((now + self.react, true));
        }
    }

    fn settle(&mut self, now: Instant) {
        while let Some(&(at, visible)) = self.pending.front() {
            if at > now {
                break;
            }
            self.visible = visible;
            self.pending.pop_front();
        }
    }
}

/// The real cursor-sync planner and a simulated cursor the device's reports move, for a test that
/// wants its moves planned. Without it (the default) every move is the camera's, as before the
/// planner: the router's other tests see exactly the reports they always did.
pub(crate) struct Cursor {
    pub(crate) sync: CursorSync,
    pub(crate) sim: SimCursor,
}

pub(crate) const US: Hkl = Hkl(0x0409_0409);
pub(crate) const RU: Hkl = Hkl(0x0419_0419);
pub(crate) const DE: Hkl = Hkl(0x0407_0407);
pub(crate) const FR: Hkl = Hkl(0x040C_040C);
/// Another layout of the same language as [`US`] (its language id is 0409 too).
pub(crate) const US_INTL: Hkl = Hkl(0xF001_0409);

/// Something that happened, in order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Out {
    /// A report went to the device (recorded even when the write then failed: it may have landed).
    Report(Report),
    /// SendInput was asked to inject this.
    SendInput(InputMessage),
    /// SendInput released everything it held.
    SendInputRelease,
    /// A window was asked to switch its layout.
    Request(Hkl),
}

/// A key of a fake layout: what it makes plain, with Shift and with AltGr.
#[derive(Clone, Copy, Debug)]
pub(crate) enum O {
    N,
    C(char),
    /// A dead key for this character.
    D(char),
}

#[derive(Clone, Copy, Debug)]
struct FakeKey {
    scan: u16,
    vk: u8,
    normal: O,
    shift: O,
    altgr: O,
    /// Caps Lock turns its case.
    caps: bool,
}

pub(crate) struct FakeLayout {
    pub(crate) hkl: Hkl,
    keys: Vec<FakeKey>,
}

fn unit(c: char) -> u16 {
    u16::try_from(u32::from(c)).unwrap()
}

fn makes(o: O, ch: u16) -> bool {
    matches!(o, O::C(c) | O::D(c) if unit(c) == ch)
}

impl FakeLayout {
    /// `VkKeyScanExW`: plain first, then Shift, then AltGr — dead keys found too, as user32 does.
    fn vk_for_char(&self, ch: u16) -> Option<(u8, u8)> {
        for state in [0u8, 1, 6] {
            for key in &self.keys {
                let o = match state {
                    0 => key.normal,
                    1 => key.shift,
                    _ => key.altgr,
                };
                if makes(o, ch) {
                    return Some((key.vk, state));
                }
            }
        }
        None
    }

    fn scan_for_vk(&self, vk: u8) -> u16 {
        self.keys.iter().find(|k| k.vk == vk).map_or(0, |k| k.scan)
    }

    fn produces(&self, vk: u8, scan: u16, state: KeyState) -> Produced {
        let Some(key) = self.keys.iter().find(|k| k.vk == vk && k.scan == scan) else {
            return Produced::Other;
        };
        let shift = state.shift ^ (state.caps && key.caps);
        let o = match (state.altgr, shift) {
            (true, false) => key.altgr,
            (true, true) => O::N,
            (false, true) => key.shift,
            (false, false) => key.normal,
        };
        match o {
            O::C(c) => Produced::Char(unit(c)),
            O::D(_) => Produced::Dead,
            O::N => Produced::Other,
        }
    }

    fn key_mut(&mut self, scan: u16) -> &mut FakeKey {
        self.keys.iter_mut().find(|k| k.scan == scan).unwrap()
    }
}

// Key positions with their US virtual keys.
const ROW_Q: [(u16, u8); 10] = [
    (0x10, b'Q'),
    (0x11, b'W'),
    (0x12, b'E'),
    (0x13, b'R'),
    (0x14, b'T'),
    (0x15, b'Y'),
    (0x16, b'U'),
    (0x17, b'I'),
    (0x18, b'O'),
    (0x19, b'P'),
];
const ROW_A: [(u16, u8); 9] = [
    (0x1E, b'A'),
    (0x1F, b'S'),
    (0x20, b'D'),
    (0x21, b'F'),
    (0x22, b'G'),
    (0x23, b'H'),
    (0x24, b'J'),
    (0x25, b'K'),
    (0x26, b'L'),
];
const ROW_Z: [(u16, u8); 7] = [
    (0x2C, b'Z'),
    (0x2D, b'X'),
    (0x2E, b'C'),
    (0x2F, b'V'),
    (0x30, b'B'),
    (0x31, b'N'),
    (0x32, b'M'),
];
const DIGITS: [(u16, u8); 10] = [
    (0x02, b'1'),
    (0x03, b'2'),
    (0x04, b'3'),
    (0x05, b'4'),
    (0x06, b'5'),
    (0x07, b'6'),
    (0x08, b'7'),
    (0x09, b'8'),
    (0x0A, b'9'),
    (0x0B, b'0'),
];

/// Letter keys: Shift and Caps Lock make the capital.
fn letters(keys: &mut Vec<FakeKey>, positions: &[(u16, u8)], chars: &str) {
    for (&(scan, vk), c) in positions.iter().zip(chars.chars()) {
        keys.push(FakeKey {
            scan,
            vk,
            normal: O::C(c),
            shift: O::C(c.to_uppercase().next().unwrap()),
            altgr: O::N,
            caps: true,
        });
    }
}

/// Keys Caps Lock does not touch.
fn row(keys: &mut Vec<FakeKey>, positions: &[(u16, u8)], normal: &str, shifted: &str) {
    for ((&(scan, vk), n), s) in positions.iter().zip(normal.chars()).zip(shifted.chars()) {
        keys.push(FakeKey {
            scan,
            vk,
            normal: O::C(n),
            shift: O::C(s),
            altgr: O::N,
            caps: false,
        });
    }
}

fn key(keys: &mut Vec<FakeKey>, scan: u16, vk: u8, normal: O, shift: O) {
    keys.push(FakeKey {
        scan,
        vk,
        normal,
        shift,
        altgr: O::N,
        caps: false,
    });
}

pub(crate) fn us() -> FakeLayout {
    let mut k = Vec::new();
    letters(&mut k, &ROW_Q, "qwertyuiop");
    letters(&mut k, &ROW_A, "asdfghjkl");
    letters(&mut k, &ROW_Z, "zxcvbnm");
    row(&mut k, &DIGITS, "1234567890", "!@#$%^&*()");
    row(
        &mut k,
        &[
            (0x0C, 0xBD),
            (0x0D, 0xBB),
            (0x1A, 0xDB),
            (0x1B, 0xDD),
            (0x27, 0xBA),
            (0x28, 0xDE),
            (0x29, 0xC0),
            (0x2B, 0xDC),
            (0x33, 0xBC),
            (0x34, 0xBE),
            (0x35, 0xBF),
            (0x39, 0x20),
        ],
        "-=[];'`\\,./ ",
        "_+{}:\"~|<>? ",
    );
    FakeLayout { hkl: US, keys: k }
}

/// A second layout of US English (as US-International is): '£' on AltGr+3, which US lacks.
pub(crate) fn us_intl() -> FakeLayout {
    let mut layout = us();
    layout.hkl = US_INTL;
    layout.key_mut(0x04).altgr = O::C('£');
    layout
}

pub(crate) fn ru() -> FakeLayout {
    let mut k = Vec::new();
    let q: Vec<_> = ROW_Q
        .iter()
        .copied()
        .chain([(0x1A, 0xDB), (0x1B, 0xDD)])
        .collect();
    letters(&mut k, &q, "йцукенгшщзхъ");
    let a: Vec<_> = ROW_A
        .iter()
        .copied()
        .chain([(0x27, 0xBA), (0x28, 0xDE)])
        .collect();
    letters(&mut k, &a, "фывапролджэ");
    let z: Vec<_> = ROW_Z
        .iter()
        .copied()
        .chain([(0x33, 0xBC), (0x34, 0xBE)])
        .collect();
    letters(&mut k, &z, "ячсмитьбю");
    letters(&mut k, &[(0x29, 0xC0)], "ё");
    row(&mut k, &DIGITS, "1234567890", "!\"№;%:?*()");
    row(
        &mut k,
        &[(0x0C, 0xBD), (0x35, 0xBF), (0x39, 0x20)],
        "-. ",
        "_, ",
    );
    FakeLayout { hkl: RU, keys: k }
}

pub(crate) fn de() -> FakeLayout {
    let mut k = Vec::new();
    let mut q = ROW_Q;
    q[5] = (0x15, b'Z');
    letters(&mut k, &q, "qwertzuiop");
    letters(&mut k, &ROW_A, "asdfghjkl");
    let mut z = ROW_Z;
    z[0] = (0x2C, b'Y');
    letters(&mut k, &z, "yxcvbnm");
    row(&mut k, &DIGITS, "1234567890", "!\"§$%&/()=");
    row(
        &mut k,
        &[
            (0x0C, 0xDB),
            (0x33, 0xBC),
            (0x34, 0xBE),
            (0x35, 0xBD),
            (0x39, 0x20),
        ],
        "ß,.- ",
        "?;:_ ",
    );
    key(&mut k, 0x29, 0xDC, O::D('^'), O::C('°'));
    let mut layout = FakeLayout { hkl: DE, keys: k };
    for (scan, c) in [
        (0x10, '@'),
        (0x12, '€'),
        (0x08, '{'),
        (0x09, '['),
        (0x0A, ']'),
        (0x0B, '}'),
    ] {
        layout.key_mut(scan).altgr = O::C(c);
    }
    layout
}

pub(crate) fn fr() -> FakeLayout {
    let mut k = Vec::new();
    let mut q = ROW_Q;
    q[0] = (0x10, b'A');
    q[1] = (0x11, b'Z');
    letters(&mut k, &q, "azertyuiop");
    let a: Vec<_> = [(0x1E, b'Q')]
        .into_iter()
        .chain(ROW_A.iter().copied().skip(1))
        .chain([(0x27, b'M')])
        .collect();
    letters(&mut k, &a, "qsdfghjklm");
    let mut z: Vec<_> = ROW_Z.iter().copied().take(6).collect();
    z[0] = (0x2C, b'W');
    letters(&mut k, &z, "wxcvbn");
    // The digit row: symbols plain, digits with Shift.
    row(&mut k, &DIGITS, "&é\"'(-è_çà", "1234567890");
    key(&mut k, 0x1A, 0xDD, O::D('^'), O::D('¨'));
    row(
        &mut k,
        &[
            (0x1B, 0xBA),
            (0x28, 0xC0),
            (0x32, 0xBC),
            (0x33, 0xBE),
            (0x34, 0xBF),
            (0x35, 0xDF),
            (0x39, 0x20),
        ],
        "$ù,;:! ",
        "£%?./§ ",
    );
    let mut layout = FakeLayout { hkl: FR, keys: k };
    layout.key_mut(0x0B).altgr = O::C('@');
    layout
}

pub(crate) struct World {
    pub(crate) t0: Instant,
    pub(crate) now: Instant,
    pub(crate) log: Vec<(Duration, Out)>,
    /// The next writes fail when `true`.
    pub(crate) failures: VecDeque<bool>,
    pub(crate) target: Target,
    /// Modifiers SendInput holds (HID bits) and keys it holds (DOM codes).
    pub(crate) sendinput_mods: u8,
    pub(crate) sendinput_keys: Vec<String>,
    /// `other_key_pressed` calls that stopped the emulated repeat.
    pub(crate) repeat_stops: u32,
    /// Installed layouts, in Windows' order.
    pub(crate) layouts: Vec<FakeLayout>,
    pub(crate) focused: Hkl,
    pub(crate) focus_window: usize,
    pub(crate) caps: bool,
    /// The window takes `WM_INPUTLANGCHANGEREQUEST`, after this long.
    pub(crate) takes_request: bool,
    pub(crate) request_delay: Duration,
    /// Posting fails outright (an administrator window).
    pub(crate) request_refused: bool,
    pending: Option<(Hkl, Instant)>,
    pub(crate) hotkey: LanguageHotkey,
    /// The hotkey, pressed alone, moves to the next installed layout.
    pub(crate) hotkey_works: bool,
    chord: bool,
    /// The focused window reads a Caps Lock press at once (else never, in these tests).
    pub(crate) caps_follows_key: bool,
    /// At this look at the desktop, the input has gone to this desktop (a UAC prompt appearing
    /// between two looks).
    pub(crate) flip_at_look: Option<(usize, Target)>,
    /// Looks at the desktop so far.
    pub(crate) target_looks: usize,
    /// The keys of the last keyboard report, to see a key go down.
    last_keys: Vec<u8>,
    /// Moves planned by the real planner against a simulated cursor (see [`Cursor`]).
    pub(crate) cursor: Option<Cursor>,
    /// The ordering waits the router reported: how long a button waited for an absolute move, and
    /// whether it gave up.
    pub(crate) order_waits: Vec<(Duration, bool)>,
    /// The foreground window (`GetForegroundWindow`), for game-only mode's queue gate.
    pub(crate) foreground: usize,
    /// Whether the foreground window runs elevated, and the agent; `None`: unreadable. An ordinary
    /// window unless a test says otherwise.
    pub(crate) elevation: Option<Elevation>,
    /// The wheel as the paths counted it for the planner's per-second line: SendInput's own count
    /// and what the router told.
    pub(crate) wheels: WheelTally,
    /// The numbered moves the router said it queued behind other input, in order.
    pub(crate) queued_moves: Vec<u32>,
    /// A game hiding the cursor for its camera button (the button watch's tests).
    pub(crate) game: Option<FakeGame>,
    /// The buttons of the last relative-mouse report: what Windows' async key state says.
    pub(crate) device_buttons: u8,
    /// The button watch's probes: `(ms, game window, detail)`.
    pub(crate) probes: Vec<(u64, usize, bool)>,
    /// What the router told the planner of its buttons: `(held, change)`.
    pub(crate) hid_buttons: Vec<(u8, Option<(u8, bool)>)>,
}

impl World {
    fn record(&mut self, out: Out) {
        let at = self.now.saturating_duration_since(self.t0);
        self.log.push((at, out));
    }

    /// The game's cursor at the world's time; the simulated cursor, if any, shows what the game does.
    fn settle_game(&mut self) {
        let now = self.now;
        if let Some(game) = self.game.as_mut() {
            game.settle(now);
            let visible = game.visible;
            if let Some(cursor) = self.cursor.as_mut() {
                cursor.sim.showing = visible;
            }
        }
    }

    fn settle(&mut self) {
        if let Some((hkl, at)) = self.pending {
            if self.now >= at {
                self.focused = hkl;
                self.pending = None;
            }
        }
    }

    fn layout(&self, hkl: Hkl) -> Option<&FakeLayout> {
        self.layouts.iter().find(|l| l.hkl == hkl)
    }

    /// A Caps Lock key going down toggles the focused window's Caps Lock, if it reads it at once.
    fn watch_caps(&mut self, report: &Report) {
        let Some((_, keys)) = keyboard(report) else {
            return;
        };
        if self.caps_follows_key && keys.contains(&0x39) && !self.last_keys.contains(&0x39) {
            self.caps = !self.caps;
        }
        self.last_keys = keys;
    }

    /// Windows' language hotkey: its chord pressed with no other key, then everything released.
    fn watch_hotkey(&mut self, report: &Report) {
        let Some((mods, keys)) = keyboard(report) else {
            return;
        };
        let chord = match self.hotkey {
            LanguageHotkey::AltShift => LALT | LSHIFT,
            LanguageHotkey::CtrlShift => LCTRL | LSHIFT,
            LanguageHotkey::Grave => 0,
            LanguageHotkey::Off => return,
        };
        let pressed = if chord == 0 {
            mods == 0 && keys == [0x35]
        } else {
            keys.is_empty() && mods & chord == chord && mods & RALT == 0
        };
        if pressed {
            self.chord = true;
        } else if chord != 0 && !keys.is_empty() {
            // Another key in between: not the hotkey.
            self.chord = false;
        } else if self.chord && mods == 0 && keys.is_empty() {
            self.chord = false;
            if self.hotkey_works {
                let at = self
                    .layouts
                    .iter()
                    .position(|l| l.hkl == self.focused)
                    .unwrap_or(0);
                self.focused = self.layouts[(at + 1) % self.layouts.len()].hkl;
            }
        }
    }

    /// Every keyboard report so far: `(ms, modifiers, keys)`.
    pub(crate) fn keyboard_reports(&self) -> Vec<(u64, u8, Vec<u8>)> {
        self.log
            .iter()
            .filter_map(|(at, out)| match out {
                Out::Report(r) => keyboard(r).map(|(m, k)| (ms(*at), m, k)),
                _ => None,
            })
            .collect()
    }

    /// Every relative-mouse report so far: `(ms, buttons, x, y, wheel)`.
    pub(crate) fn mouse_reports(&self) -> Vec<(u64, u8, i16, i16, i8)> {
        self.log
            .iter()
            .filter_map(|(at, out)| match out {
                Out::Report(r) if r[0] == 0x40 && r[2] == 3 => Some((
                    ms(*at),
                    r[3],
                    i16::from_le_bytes([r[4], r[5]]),
                    i16::from_le_bytes([r[6], r[7]]),
                    i8::from_le_bytes([r[8]]),
                )),
                _ => None,
            })
            .collect()
    }

    /// Everything the device got, in order, as `(ms, what)`: `k` for a keyboard report with its
    /// keys, `b` for a button change, `r` for a move, `w` for a wheel turn with the modifiers of the
    /// keyboard report before it, `a` for an absolute report (report 4).
    pub(crate) fn device_timeline(&self) -> Vec<(u64, String)> {
        let mut mods = 0u8;
        let mut buttons = 0u8;
        let mut out = Vec::new();
        for (at, o) in &self.log {
            let Out::Report(r) = o else { continue };
            if let Some((m, keys)) = keyboard(r) {
                mods = m;
                out.push((ms(*at), format!("k{m:02x}{keys:?}")));
            } else if r[0] == 0x40 && r[2] == 4 {
                out.push((ms(*at), "a".to_owned()));
            } else if r[0] == 0x40 && r[2] == 3 {
                if r[3] != buttons {
                    buttons = r[3];
                    out.push((ms(*at), format!("b{buttons}")));
                }
                if r[4..8] != [0; 4] {
                    out.push((ms(*at), "r".to_owned()));
                }
                if r[8] != 0 {
                    out.push((ms(*at), format!("w+mods{mods:02x}")));
                }
            }
        }
        out
    }

    /// Keys that went down, in order, with the modifiers of the report that pressed them:
    /// `(ms, modifiers, usage)`.
    pub(crate) fn key_downs(&self) -> Vec<(u64, u8, u8)> {
        let mut before: Vec<u8> = Vec::new();
        let mut downs = Vec::new();
        for (at, mods, keys) in self.keyboard_reports() {
            for &k in &keys {
                if !before.contains(&k) {
                    downs.push((at, mods, k));
                }
            }
            before = keys;
        }
        downs
    }

    pub(crate) fn usages(&self) -> Vec<u8> {
        self.key_downs().into_iter().map(|(_, _, k)| k).collect()
    }

    /// What went by Unicode, in order.
    pub(crate) fn unicode(&self) -> String {
        self.log
            .iter()
            .filter_map(|(_, out)| match out {
                Out::SendInput(InputMessage::Text { text, .. }) => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn requests(&self) -> Vec<(u64, Hkl)> {
        self.log
            .iter()
            .filter_map(|(at, out)| match out {
                Out::Request(h) => Some((ms(*at), *h)),
                _ => None,
            })
            .collect()
    }

    pub(crate) fn count(&self, what: impl Fn(&Out) -> bool) -> usize {
        self.log.iter().filter(|(_, out)| what(out)).count()
    }

    /// When the last event of a kind happened, in ms.
    pub(crate) fn last_at(&self, what: impl Fn(&Out) -> bool) -> Option<u64> {
        self.log
            .iter()
            .filter(|(_, out)| what(out))
            .map(|(at, _)| ms(*at))
            .last()
    }
}

pub(crate) fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap()
}

/// A keyboard report's `(modifiers, keys)`.
pub(crate) fn keyboard(report: &Report) -> Option<(u8, Vec<u8>)> {
    (report[0] == 0x40 && report[2] == 1).then(|| {
        (
            report[3],
            report[5..11].iter().copied().filter(|&k| k != 0).collect(),
        )
    })
}

/// Is this a relative mouse report?
pub(crate) fn is_mouse(out: &Out) -> bool {
    matches!(out, Out::Report(r) if r[0] == 0x40 && r[2] == 3)
}

pub(crate) fn is_keyboard(out: &Out) -> bool {
    matches!(out, Out::Report(r) if keyboard(r).is_some())
}

type Shared = Arc<Mutex<World>>;

fn world(shared: &Shared) -> MutexGuard<'_, World> {
    shared.lock().unwrap()
}

pub(crate) struct FakeDevice(Shared);

impl Driver for FakeDevice {
    fn write(&mut self, report: &Report) -> Result<()> {
        let mut w = world(&self.0);
        w.record(Out::Report(*report));
        w.watch_hotkey(report);
        w.watch_caps(report);
        if w.failures.pop_front().unwrap_or(false) {
            bail!("simulated driver refusal");
        }
        let now = w.now;
        if report[2] == 3 {
            let before = std::mem::replace(&mut w.device_buttons, report[3]);
            if let Some(game) = w.game.as_mut() {
                game.report(before, report[3], now);
            }
        }
        if let Some(cursor) = w.cursor.as_mut() {
            // The report reaches the simulated Windows, which shows it a moment later.
            cursor.sim.now = cursor.sim.now.max(now);
            match report[2] {
                3 => cursor.sim.send_counts(
                    i32::from(i16::from_le_bytes([report[4], report[5]])),
                    i32::from(i16::from_le_bytes([report[6], report[7]])),
                ),
                4 => cursor.sim.send_absolute_wire(
                    u16::from_le_bytes([report[4], report[5]]),
                    u16::from_le_bytes([report[6], report[7]]),
                ),
                _ => {}
            }
        }
        Ok(())
    }
}

pub(crate) struct FakeSendInput(Shared);

impl SendInputPath for FakeSendInput {
    /// Recorded; a wheel is counted as the real path counts its own.
    fn inject(&self, event: &InputMessage) -> Result<()> {
        let mut w = world(&self.0);
        w.record(Out::SendInput(event.clone()));
        if matches!(event, InputMessage::Wheel { .. }) {
            let one = WheelTally {
                sendinput: 1,
                ..WheelTally::default()
            };
            w.wheels.add(one);
            let now = w.now;
            if let Some(cursor) = w.cursor.as_mut() {
                cursor.sync.count_wheel(one, now);
            }
        }
        Ok(())
    }

    fn release_all(&self) {
        let mut w = world(&self.0);
        w.sendinput_mods = 0;
        w.sendinput_keys.clear();
        w.record(Out::SendInputRelease);
    }

    fn holds_key(&self, code: &str) -> bool {
        world(&self.0).sendinput_keys.iter().any(|k| k == code)
    }

    fn holds_button(&self, _: u8) -> bool {
        false
    }

    fn other_key_pressed(&self, modifier: bool, was_held: bool) {
        if !(modifier && was_held) {
            world(&self.0).repeat_stops += 1;
        }
    }

    fn held_modifiers(&self) -> u8 {
        world(&self.0).sendinput_mods
    }

    fn plan_rel(&self, event: RelEvent, hid_held: bool, now: Instant) -> Plan {
        let mut w = world(&self.0);
        w.settle_game();
        match w.cursor.as_mut() {
            Some(Cursor { sync, sim }) => {
                sim.now = sim.now.max(now);
                sync.plan(event, hid_held, RelPath::Hid, sim, now)
            }
            None => Plan::Camera,
        }
    }

    fn rel_failed(&self, why: &'static str) {
        if let Some(cursor) = world(&self.0).cursor.as_mut() {
            cursor.sync.failed(why);
        }
    }

    /// Recorded; the planner, when there is one, holds the report's `ack` below it.
    fn rel_queued(&self, s: u32, now: Instant) {
        let mut w = world(&self.0);
        w.queued_moves.push(s);
        if let Some(cursor) = w.cursor.as_mut() {
            cursor.sync.queued(s, now);
        }
    }

    fn note_input(&self, now: Instant) {
        if let Some(Cursor { sync, sim }) = world(&self.0).cursor.as_mut() {
            sync.note_input(sim, now);
        }
    }

    /// With a planner, the planner's pixel on the simulated screen; without one, the pixel on the
    /// fake host's 1000×1000 screen, by the same function.
    fn plan_abs(&self, x: f64, y: f64, now: Instant) -> Option<(i32, i32, i32, i32)> {
        let mut w = world(&self.0);
        match w.cursor.as_mut() {
            Some(Cursor { sync, sim }) => {
                sim.now = sim.now.max(now);
                sync.absolute((x, y), RelPath::Hid, sim, now)
            }
            None => {
                let (px, py) = target_pixel((x.clamp(0.0, 1.0), y.clamp(0.0, 1.0)), 1000, 1000);
                Some((px, py, 1000, 1000))
            }
        }
    }

    fn order_waited(&self, waited: Duration, timed_out: bool, now: Instant) {
        let mut w = world(&self.0);
        w.order_waits.push((waited, timed_out));
        if let Some(cursor) = w.cursor.as_mut() {
            cursor.sync.order_waited(waited, timed_out, now);
        }
    }

    fn foreground_elevation(&self, _now: Instant) -> Option<Elevation> {
        world(&self.0).elevation.clone()
    }

    fn wheel_tally(&self, tally: WheelTally, now: Instant) {
        let mut w = world(&self.0);
        w.wheels.add(tally);
        if let Some(cursor) = w.cursor.as_mut() {
            cursor.sync.count_wheel(tally, now);
        }
    }

    /// Recorded; the planner, when there is one, keeps them for its visibility line.
    fn hid_buttons(&self, held: u8, change: Option<(u8, bool, Instant)>) {
        let mut w = world(&self.0);
        w.hid_buttons
            .push((held, change.map(|(bit, down, _)| (bit, down))));
        if let Some(cursor) = w.cursor.as_mut() {
            cursor.sync.hid_buttons(held, change);
        }
    }
}

pub(crate) struct FakeKeyboard(Shared);

impl Keyboard for FakeKeyboard {
    fn focused_layout(&mut self) -> Option<Hkl> {
        let mut w = world(&self.0);
        w.settle();
        Some(w.focused)
    }

    fn focus(&mut self) -> Option<usize> {
        Some(world(&self.0).focus_window)
    }

    fn installed_layouts(&mut self) -> Vec<Hkl> {
        world(&self.0).layouts.iter().map(|l| l.hkl).collect()
    }

    fn vk_for_char(&mut self, ch: u16, hkl: Hkl) -> Option<(u8, u8)> {
        world(&self.0).layout(hkl)?.vk_for_char(ch)
    }

    fn scan_for_vk(&mut self, vk: u8, hkl: Hkl) -> u16 {
        world(&self.0).layout(hkl).map_or(0, |l| l.scan_for_vk(vk))
    }

    fn produces(&mut self, vk: u8, scan: u16, state: KeyState, hkl: Hkl) -> Produced {
        world(&self.0)
            .layout(hkl)
            .map_or(Produced::Other, |l| l.produces(vk, scan, state))
    }

    fn caps_lock(&mut self) -> bool {
        world(&self.0).caps
    }

    fn request_layout(&mut self, hkl: Hkl) -> Result<(), &'static str> {
        let mut w = world(&self.0);
        if w.request_refused {
            return Err("refused");
        }
        w.record(Out::Request(hkl));
        if w.takes_request {
            let at = w.now + w.request_delay;
            w.pending = Some((hkl, at));
        }
        Ok(())
    }

    fn language_hotkey(&mut self) -> LanguageHotkey {
        world(&self.0).hotkey
    }
}

pub(crate) struct FakeHost {
    world: Shared,
    sendinput: FakeSendInput,
    keyboard: FakeKeyboard,
}

impl Host for FakeHost {
    fn evaluate_target(&mut self) -> TargetEval {
        let mut w = world(&self.world);
        w.target_looks += 1;
        if let Some((look, target)) = w.flip_at_look {
            if w.target_looks >= look {
                w.target = target;
            }
        }
        TargetEval {
            target: w.target,
            reason: "fake desktop",
        }
    }

    fn screen_size(&mut self) -> (i32, i32) {
        (1000, 1000)
    }

    /// The simulated cursor, as `GetCursorPos` would say at the world's time; without one, nothing
    /// to read (the router then does not wait for an absolute move).
    fn cursor_pos(&mut self) -> Result<(i32, i32), String> {
        let mut w = world(&self.world);
        let now = w.now;
        match w.cursor.as_mut() {
            Some(cursor) => {
                cursor.sim.now = cursor.sim.now.max(now);
                cursor.sim.look().map(|look| (look.x, look.y))
            }
            None => Err("no simulated cursor in this test".to_owned()),
        }
    }

    fn foreground(&mut self) -> usize {
        world(&self.world).foreground
    }

    fn sendinput(&self) -> &dyn SendInputPath {
        &self.sendinput
    }

    fn keyboard(&mut self) -> &mut dyn Keyboard {
        &mut self.keyboard
    }

    /// The virtual clock moves on; what is recorded after carries the later time.
    fn pause(&mut self, duration: Duration) {
        world(&self.world).now += duration;
    }

    /// The game's cursor (on the simulated one when there is one, else at 500,500), or the simulated
    /// cursor; with neither, nothing to read (the button watch then watches nothing).
    fn cursor_look(&mut self) -> Result<CursorLook, String> {
        let mut w = world(&self.world);
        w.settle_game();
        let now = w.now;
        let game = w.game.as_ref().map(|g| g.visible);
        match (w.cursor.as_mut(), game) {
            (Some(cursor), _) => {
                cursor.sim.now = cursor.sim.now.max(now);
                cursor.sim.look()
            }
            (None, Some(showing)) => Ok(CursorLook {
                x: 500,
                y: 500,
                showing,
                suppressed: false,
            }),
            (None, None) => Err("no simulated cursor in this test".to_owned()),
        }
    }

    /// Windows' async key state is the device's buttons; the rest is canned. Recorded.
    fn button_probe(&mut self, game: usize, detail: bool) -> ButtonProbe {
        let mut w = world(&self.world);
        let at = ms(w.now.saturating_duration_since(w.t0));
        w.probes.push((at, game, detail));
        let foreground = w.foreground;
        ButtonProbe {
            windows: w.device_buttons,
            capture: detail.then(|| "none".to_owned()),
            under: detail.then(|| format!("{game:#x} FakeGameWindow (the game's window)")),
            foreground: detail.then(|| format!("{foreground:#x} FakeGameWindow")),
        }
    }
}

pub(crate) type Rt = HidRuntime<FakeDevice, FakeHost>;

/// The router over the fake world, and the virtual clock.
pub(crate) struct Harness {
    pub(crate) shared: Shared,
    pub(crate) rt: Rt,
    pub(crate) now: Instant,
    t0: Instant,
}

impl Harness {
    /// US and Russian installed, US focused; the window takes a layout request after 15 ms;
    /// Alt+Shift switches.
    pub(crate) fn new() -> Self {
        Self::with(vec![us(), ru()], US)
    }

    pub(crate) fn with(layouts: Vec<FakeLayout>, focused: Hkl) -> Self {
        let t0 = Instant::now();
        let shared = Arc::new(Mutex::new(World {
            t0,
            now: t0,
            log: Vec::new(),
            failures: VecDeque::new(),
            target: Target::Allowed,
            sendinput_mods: 0,
            sendinput_keys: Vec::new(),
            repeat_stops: 0,
            layouts,
            focused,
            focus_window: 1,
            caps: false,
            takes_request: true,
            request_delay: Duration::from_millis(15),
            request_refused: false,
            pending: None,
            hotkey: LanguageHotkey::AltShift,
            hotkey_works: true,
            chord: false,
            caps_follows_key: false,
            flip_at_look: None,
            target_looks: 0,
            last_keys: Vec::new(),
            cursor: None,
            order_waits: Vec::new(),
            foreground: 0x10,
            elevation: Some(Elevation {
                foreground: false,
                agent: false,
                exe: "notepad.exe".into(),
            }),
            wheels: WheelTally::default(),
            queued_moves: Vec::new(),
            game: None,
            device_buttons: 0,
            probes: Vec::new(),
            hid_buttons: Vec::new(),
        }));
        let host = FakeHost {
            world: shared.clone(),
            sendinput: FakeSendInput(shared.clone()),
            keyboard: FakeKeyboard(shared.clone()),
        };
        Self {
            rt: HidRuntime::new(State::new(FakeDevice(shared.clone())), host),
            shared,
            now: t0,
            t0,
        }
    }

    pub(crate) fn world(&self) -> MutexGuard<'_, World> {
        world(&self.shared)
    }

    /// Plan moves with the real planner against a simulated 3600×2400 cursor at `dpi` (see
    /// [`Cursor`]).
    pub(crate) fn plan_moves(&mut self, dpi: u32) {
        let mut sim = SimCursor::new(dpi, self.now);
        let mut sync = CursorSync::new();
        sync.begin_session(&mut sim, self.now);
        self.world().cursor = Some(Cursor { sync, sim });
    }

    /// The lowest numbered move a cursor report taken now would say does not show yet: the
    /// planner's answer for a fresh look at the simulated cursor, at the world's time.
    pub(crate) fn unshown(&self) -> Option<u32> {
        let mut w = self.world();
        let now = w.now;
        let cursor = w.cursor.as_mut().unwrap();
        cursor.sim.now = cursor.sim.now.max(now);
        let look = cursor.sim.look().unwrap();
        cursor.sync.unshown((look.x, look.y), now)
    }

    /// Where the simulated cursor is, everything sent having shown.
    pub(crate) fn cursor_at(&self) -> (i32, i32) {
        let mut w = self.world();
        let now = w.now;
        let cursor = w.cursor.as_mut().unwrap();
        cursor.sim.now = cursor.sim.now.max(now);
        cursor.sim.drain();
        cursor.sim.position()
    }

    fn sync(&self) {
        self.world().now = self.now;
    }

    /// Move the clock to `ms` after the start, working the queue on the way.
    pub(crate) fn at(&mut self, ms: u64) {
        let end = self.t0 + Duration::from_millis(ms);
        assert!(end >= self.now, "the clock only goes forward");
        loop {
            self.sync();
            match self.rt.step(self.now) {
                Some(next) if next <= end => self.now = next,
                _ => break,
            }
        }
        self.now = end;
        self.sync();
    }

    /// Work the queue until it is empty; returns when that was, in ms.
    pub(crate) fn run(&mut self) -> u64 {
        loop {
            self.sync();
            match self.rt.step(self.now) {
                Some(next) => {
                    assert!(
                        next.saturating_duration_since(self.t0) < Duration::from_secs(600),
                        "the queue never drains"
                    );
                    self.now = next;
                }
                None => return ms(self.now.saturating_duration_since(self.t0)),
            }
        }
    }

    /// An event from the viewer, now.
    pub(crate) fn inject(&mut self, event: InputMessage) -> Result<()> {
        self.sync();
        self.rt.admit(&event, self.now)
    }

    pub(crate) fn game_text(&mut self, text: &str) {
        self.inject(InputMessage::Text {
            text: text.into(),
            game: Some(true),
        })
        .unwrap();
    }

    pub(crate) fn key(&mut self, code: &str, down: bool) -> Result<()> {
        self.key_from(code, down, None)
    }

    /// A key the viewer tagged as one of its own (`k.src`), or not (`None`).
    pub(crate) fn key_from(
        &mut self,
        code: &str,
        down: bool,
        src: Option<afklink_protocol::KeySource>,
    ) -> Result<()> {
        self.inject(InputMessage::Key {
            d: u8::from(down),
            code: code.into(),
            key: None,
            mods: None,
            src,
        })
    }

    pub(crate) fn button(&mut self, b: u8, down: bool) -> Result<()> {
        self.inject(if down {
            InputMessage::Down { b }
        } else {
            InputMessage::Up { b }
        })
    }

    pub(crate) fn release_all(&mut self) {
        self.sync();
        self.rt.release_all();
    }
}
