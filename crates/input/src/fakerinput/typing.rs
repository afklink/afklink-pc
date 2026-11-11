//! Game text typed as key presses through the HID driver: `text` with `game: true`.
//!
//! A game that reads the keyboard through raw input sees only keys and ignores `SendInput`'s
//! Unicode text, so a chat line from the viewer's game mode is typed one key at a time, on the PC's
//! own layout, through the FakerInput keyboard. [`super::HidRuntime::admit`] brings text here only
//! when it is marked `game`, the driver is open and HID may drive the desktop.
//!
//! A character becomes a key on the focused window's layout ([`Keyboard::focused_layout`]):
//! `VkKeyScanExW` gives the virtual key and Shift/AltGr, `MapVirtualKeyExW` the scan code,
//! [`scan_to_usage`] the HID usage, and `ToUnicodeEx` (flag 4, state untouched) checks the key really
//! makes it — refusing dead keys and retrying the other Shift under Caps Lock (including a Caps Lock
//! this agent just sent, [`Memory::caps_pressed`]). AltGr goes as left Ctrl + right Alt; keypad and
//! national extra keys count as not producible.
//!
//! A character only another installed layout types switches the window to it, as a person would:
//! `WM_INPUTLANGCHANGEREQUEST` first, then, unconfirmed after [`SWITCH_CONFIRM`], the user's own
//! language hotkey, at most once per layout and never again in a window where it did nothing.
//! Win+Space and the grave accent are never pressed (Start menu, game consoles). When nothing
//! works, the character goes by Unicode in its place.
//!
//! A worker ([`super::HidRuntime::step`]) types with [`MODIFIER_LEAD`], [`KEY_HOLD`] and [`KEY_GAP`];
//! `inject` only queues, so the session's event task never sleeps. Keys, clicks and further text
//! wait behind queued text so an Enter cannot overtake its line; moves and the wheel go at once
//! until a click or key waits, and then everything keeps its order (a wheel waits for held
//! modifiers, [`Typist::held_wheels`]). Queued input keeps its gaps up to [`MAX_REPLAY_GAP`].
//!
//! Before every report the worker reads the desktop afresh: on the secure desktop, another session
//! or an unconfirmed desktop, the queue is dropped and everything held released, so a queued Enter
//! never confirms a prompt. Each report carries the panel's held keys and restores them after; with
//! Ctrl, Alt or Win held (or Shift held through `SendInput`) the message goes by Unicode.
//!
//! Newlines are dropped and iOS typography becomes ASCII; emoji and control characters go by
//! Unicode. A failed write stops typing and, like `ra`, the session's end or a desktop HID may not
//! drive, drops the queue together with a full release, so no key-up is lost while its key is down.
//!
//! Logs never carry a character, key, scan code or usage, nor anything per character or report: a
//! chat line may be a password. Per message and per burst, counts only; path changes, Caps Lock and
//! layout switches at `debug`.

use std::collections::{BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use afklink_protocol::InputMessage;

use super::{check_keyboard, Driver, Host, State, Target};
use crate::key_log::{self, Names};

/// How far ahead of a key its modifiers change: pressed for it, or released for the next one.
pub(crate) const MODIFIER_LEAD: Duration = Duration::from_millis(10);
/// How long a typed key stays down: long enough for a game that polls the keyboard once a frame.
pub(crate) const KEY_HOLD: Duration = Duration::from_millis(30);
/// The pause after a typed key goes up, before the next character.
pub(crate) const KEY_GAP: Duration = Duration::from_millis(20);
/// How long a layout switch is waited for, per method and per press of the language hotkey.
pub(crate) const SWITCH_CONFIRM: Duration = Duration::from_millis(300);
/// How often the focused window's layout is looked at while a switch is being confirmed.
pub(crate) const SWITCH_POLL: Duration = Duration::from_millis(10);
/// A key or mouse button the viewer releases through the driver sooner than this after pressing it
/// is released this long after the press: a phone's Enter or Backspace tap, or a tap on the
/// trackpad, is down and up in one breath, and a game that polls once a frame never sees it.
pub(crate) const TAP_MIN_HOLD: Duration = Duration::from_millis(30);

/// The earliest time a confirmed HID press may be released. Each caller retains
/// its own queue and any additional policy about when a new press can start.
#[derive(Clone, Copy)]
pub struct PressHold(Instant);

impl PressHold {
    pub const MINIMUM: Duration = TAP_MIN_HOLD;

    pub fn new(at: Instant) -> Self {
        Self(at)
    }

    pub fn release_at(self) -> Instant {
        self.0 + Self::MINIMUM
    }

    pub(super) fn elapsed(self, now: Instant) -> Duration {
        now.saturating_duration_since(self.0)
    }
}
/// Characters the typing queue holds at most (about 13 s of typing); text beyond it goes by
/// Unicode, in its turn.
pub(crate) const MAX_QUEUED_CHARS: usize = 256;
/// Entries (texts and the input waiting behind them) the queue holds at most; past it, everything
/// queued is sent at once, in order, text by Unicode.
pub(crate) const MAX_QUEUED_JOBS: usize = 1024;
/// The longest gap kept between two queued events when they are replayed: a key held longer than
/// this while a line was typed is replayed held this long.
pub(crate) const MAX_REPLAY_GAP: Duration = Duration::from_secs(1);
/// How long a Caps Lock press sent through the driver is trusted over a read that does not show it
/// yet (the focused window has not read its key message).
pub(crate) const CAPS_SETTLE: Duration = Duration::from_millis(500);
/// Game wheels held for the typing's modifiers at most; past it the oldest is dropped (counted).
const MAX_HELD_WHEELS: usize = 64;
/// Layout switches tried for one character before it goes by Unicode (the focus may move under us).
const MAX_SWITCHES_PER_CHAR: u8 = 2;

/// HID keyboard modifier bits.
pub(crate) const LCTRL: u8 = 0x01;
pub(crate) const LSHIFT: u8 = 0x02;
pub(crate) const LALT: u8 = 0x04;
pub(crate) const RSHIFT: u8 = 0x20;
pub(crate) const RALT: u8 = 0x40;
const SHIFTS: u8 = LSHIFT | RSHIFT;
/// Ctrl, Alt and Win on either side: held, they turn a typed key into a shortcut.
const SHORTCUT_MODIFIERS: u8 = !SHIFTS;
/// AltGr, as a keyboard with one sends it.
const ALTGR: u8 = LCTRL | RALT;

/// A keyboard layout (`HKL`), as a number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Hkl(pub(crate) usize);

impl Hkl {
    /// The language id (the low word), which the log names a layout by: `0409` English (US),
    /// `0419` Russian.
    pub(crate) fn lang(self) -> u16 {
        (self.0 & 0xffff) as u16
    }
}

/// The key state [`Keyboard::produces`] asks about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyState {
    pub(crate) shift: bool,
    pub(crate) altgr: bool,
    pub(crate) caps: bool,
}

/// What a key makes, as `ToUnicodeEx` answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Produced {
    /// One UTF-16 unit.
    Char(u16),
    /// A dead key: it would wait for the next key.
    Dead,
    /// Nothing, or more than one unit.
    Other,
}

/// The keys that switch the input language, from `HKCU\Keyboard Layout\Toggle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LanguageHotkey {
    /// `1`, Windows' default: left Alt + Shift.
    AltShift,
    /// `2`: Ctrl + Shift.
    CtrlShift,
    /// `4`: the grave accent key. Never pressed (it opens games' consoles).
    Grave,
    /// `3` (none), or a value this build does not know.
    Off,
}

impl LanguageHotkey {
    fn name(self) -> &'static str {
        match self {
            Self::AltShift => "alt+shift",
            Self::CtrlShift => "ctrl+shift",
            Self::Grave => "grave",
            Self::Off => "none",
        }
    }
}

/// The setting as Windows stores it: `Language Hotkey`, else the older `Hotkey`, else Windows'
/// default (Alt+Shift). An unknown value presses nothing.
pub(crate) fn parse_hotkey(language_hotkey: Option<&str>, hotkey: Option<&str>) -> LanguageHotkey {
    match language_hotkey.or(hotkey).map(str::trim) {
        None => LanguageHotkey::AltShift,
        Some("1") => LanguageHotkey::AltShift,
        Some("2") => LanguageHotkey::CtrlShift,
        Some("4") => LanguageHotkey::Grave,
        Some(_) => LanguageHotkey::Off,
    }
}

/// The PC's keyboard layouts. The agent's is `layouts::WinKeyboard`; tests use fakes.
pub(crate) trait Keyboard {
    /// The layout of the thread that owns the focused window — the foreground thread's focus
    /// window, else its active window, else the foreground window. `None` when there is none.
    fn focused_layout(&mut self) -> Option<Hkl>;
    /// The focused window as a number, only to tell one window from another.
    fn focus(&mut self) -> Option<usize>;
    /// The installed layouts, in Windows' order (`GetKeyboardLayoutList`).
    fn installed_layouts(&mut self) -> Vec<Hkl>;
    /// `VkKeyScanExW`: the virtual key that types `ch` on `hkl`, and its shift state (1 Shift,
    /// 2 Ctrl, 4 Alt; 6 is AltGr).
    fn vk_for_char(&mut self, ch: u16, hkl: Hkl) -> Option<(u8, u8)>;
    /// `MapVirtualKeyExW(MAPVK_VK_TO_VSC_EX)`: the key's set-1 scan code, an `E0`/`E1` prefix in the
    /// high byte; 0 when it has none.
    fn scan_for_vk(&mut self, vk: u8, hkl: Hkl) -> u16;
    /// `ToUnicodeEx` with flag 4 (the keyboard state untouched): what the key makes in `state`.
    fn produces(&mut self, vk: u8, scan: u16, state: KeyState, hkl: Hkl) -> Produced;
    /// Whether Caps Lock is on, as the focused window's thread sees it.
    fn caps_lock(&mut self) -> bool;
    /// Ask the focused window (else the foreground one) to switch to `hkl`
    /// (`WM_INPUTLANGCHANGEREQUEST`). An error says why nothing was posted.
    fn request_layout(&mut self, hkl: Hkl) -> Result<(), &'static str>;
    /// The configured language hotkey.
    fn language_hotkey(&mut self) -> LanguageHotkey;
}

/// How one character is typed on one layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stroke {
    pub(crate) usage: u8,
    pub(crate) shift: bool,
    pub(crate) altgr: bool,
}

/// Why a layout cannot type a character.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unproducible {
    /// No key makes it (or it is outside the Basic Multilingual Plane).
    NoKey,
    /// Only with Ctrl or Alt alone, or another modifier the driver does not send.
    Modifiers,
    /// The key has no scan code.
    NoScanCode,
    /// The key is not one of the driver's typing keys.
    NotTypingKey,
    /// A dead key.
    DeadKey,
    /// The key does not make the character after all.
    Mismatch,
}

/// The HID usage of the key a set-1 scan code names — only for the keys that type characters: the
/// digit row, the letters, the punctuation, Space and the ISO key beside left Shift. Anything else —
/// an `E0` key, the keypad (whose keys change with Num Lock), the keys past the driver's descriptor
/// (it ends at usage 0x65) — is `None`: not producible.
pub(crate) fn scan_to_usage(scan: u16) -> Option<u8> {
    let usage = match scan {
        0x02..=0x0A => scan - 0x02 + 0x1E, // 1..9
        0x0B => 0x27,                      // 0
        0x0C => 0x2D,                      // Minus
        0x0D => 0x2E,                      // Equal
        0x10 => 0x14,                      // Q
        0x11 => 0x1A,                      // W
        0x12 => 0x08,                      // E
        0x13 => 0x15,                      // R
        0x14 => 0x17,                      // T
        0x15 => 0x1C,                      // Y
        0x16 => 0x18,                      // U
        0x17 => 0x0C,                      // I
        0x18 => 0x12,                      // O
        0x19 => 0x13,                      // P
        0x1A => 0x2F,                      // BracketLeft
        0x1B => 0x30,                      // BracketRight
        0x1E => 0x04,                      // A
        0x1F => 0x16,                      // S
        0x20 => 0x07,                      // D
        0x21 => 0x09,                      // F
        0x22 => 0x0A,                      // G
        0x23 => 0x0B,                      // H
        0x24 => 0x0D,                      // J
        0x25 => 0x0E,                      // K
        0x26 => 0x0F,                      // L
        0x27 => 0x33,                      // Semicolon
        0x28 => 0x34,                      // Quote
        0x29 => 0x35,                      // Backquote
        0x2B => 0x31,                      // Backslash (the ISO key there is scan 2B too)
        0x2C => 0x1D,                      // Z
        0x2D => 0x1B,                      // X
        0x2E => 0x06,                      // C
        0x2F => 0x19,                      // V
        0x30 => 0x05,                      // B
        0x31 => 0x11,                      // N
        0x32 => 0x10,                      // M
        0x33 => 0x36,                      // Comma
        0x34 => 0x37,                      // Period
        0x35 => 0x38,                      // Slash
        0x39 => 0x2C,                      // Space
        0x56 => 0x64,                      // IntlBackslash
        _ => return None,
    };
    Some(usage as u8)
}

/// How to type `ch` on `hkl` with Caps Lock `caps`, or why it cannot be typed there.
pub(crate) fn stroke_on(
    kb: &mut dyn Keyboard,
    ch: char,
    hkl: Hkl,
    caps: bool,
) -> Result<Stroke, Unproducible> {
    let unit = u16::try_from(u32::from(ch)).map_err(|_| Unproducible::NoKey)?;
    let (vk, state) = kb.vk_for_char(unit, hkl).ok_or(Unproducible::NoKey)?;
    let shift = state & 1 != 0;
    let altgr = match state & !1 {
        0 => false,
        6 => true,
        _ => return Err(Unproducible::Modifiers),
    };
    let scan = kb.scan_for_vk(vk, hkl);
    if scan == 0 {
        return Err(Unproducible::NoScanCode);
    }
    let usage = scan_to_usage(scan).ok_or(Unproducible::NotTypingKey)?;
    let mut makes = |shift| kb.produces(vk, scan, KeyState { shift, altgr, caps }, hkl);
    match makes(shift) {
        Produced::Char(c) if c == unit => {
            return Ok(Stroke {
                usage,
                shift,
                altgr,
            })
        }
        Produced::Dead => return Err(Unproducible::DeadKey),
        _ => {}
    }
    // Caps Lock turns the letter keys' case, and `VkKeyScanExW` does not know it is on: the other
    // Shift makes the character.
    if caps {
        match makes(!shift) {
            Produced::Char(c) if c == unit => {
                return Ok(Stroke {
                    usage,
                    shift: !shift,
                    altgr,
                })
            }
            Produced::Dead => return Err(Unproducible::DeadKey),
            _ => {}
        }
    }
    Err(Unproducible::Mismatch)
}

/// Layouts in the order they were last used, most recent first.
#[derive(Debug, Default)]
pub(crate) struct Recent(Vec<Hkl>);

impl Recent {
    const KEEP: usize = 8;

    pub(crate) fn touch(&mut self, hkl: Hkl) {
        self.0.retain(|&h| h != hkl);
        self.0.insert(0, hkl);
        self.0.truncate(Self::KEEP);
    }

    fn rank(&self, hkl: Hkl) -> usize {
        self.0.iter().position(|&h| h == hkl).unwrap_or(usize::MAX)
    }
}

/// The installed layout other than `current` (and those that already failed to switch) that types
/// `ch`: the most recently used first, then Windows' order.
pub(crate) fn find_layout(
    kb: &mut dyn Keyboard,
    ch: char,
    installed: &[Hkl],
    current: Hkl,
    failed: &[Hkl],
    recent: &Recent,
    caps: bool,
) -> Option<Hkl> {
    let mut candidates: Vec<(usize, usize, Hkl)> = installed
        .iter()
        .enumerate()
        .filter(|&(_, &h)| h != current && !failed.contains(&h))
        .map(|(i, &h)| (recent.rank(h), i, h))
        .collect();
    candidates.sort_unstable_by_key(|&(rank, i, _)| (rank, i));
    candidates
        .into_iter()
        .map(|(_, _, h)| h)
        .find(|&h| stroke_on(kb, ch, h, caps).is_ok())
}

/// Game text after the owner's normalisation.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Normalized {
    pub(crate) chars: Vec<char>,
    /// Line breaks dropped.
    pub(crate) newlines: usize,
    /// Typographic characters replaced with ASCII.
    pub(crate) replaced: usize,
}

/// Drop newlines (a chat line must not be sent early) and turn iOS typography into ASCII.
pub(crate) fn normalize(text: &str) -> Normalized {
    let mut out = Normalized {
        chars: Vec::with_capacity(text.len()),
        ..Normalized::default()
    };
    for c in text.chars() {
        let replacement = match c {
            '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                out.newlines += 1;
                continue;
            }
            '\u{2018}' | '\u{2019}' => "'",
            '\u{201C}' | '\u{201D}' => "\"",
            '\u{2013}' | '\u{2014}' => "-",
            '\u{2026}' => "...",
            '\u{A0}' => " ",
            c => {
                out.chars.push(c);
                continue;
            }
        };
        out.replaced += 1;
        out.chars.extend(replacement.chars());
    }
    out
}

/// Whether typing may use the driver right now, as the runtime sees it at each step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gate {
    /// HID may drive the desktop.
    Hid,
    /// The desktop could not be confirmed before the message started: the whole message goes by
    /// Unicode (which Windows gates on its own). Mid-message the runtime drops and releases instead.
    Unknown,
    /// The device stopped accepting writes: the rest goes by Unicode, with nothing written.
    Unusable,
}

/// Which way a message went, for the path line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TextPath {
    Hid,
    Unicode(&'static str),
}

/// Says which way game text goes, at `debug` when it changes and at `trace` otherwise: a phone sends
/// text as it is typed, a message a character, so one line per message would be one per keystroke.
#[derive(Debug, Default)]
pub(crate) struct PathLog {
    last: Option<TextPath>,
}

impl PathLog {
    pub(crate) fn note(&mut self, path: TextPath) {
        let (via, reason) = match path {
            TextPath::Hid => ("hid", "keys through the driver"),
            TextPath::Unicode(reason) => ("unicode", reason),
        };
        if self.last == Some(path) {
            tracing::trace!(via, reason, "game text path");
            return;
        }
        self.last = Some(path);
        tracing::debug!(via, reason, "game text path");
    }
}

/// What typing remembers between messages, for the life of the open device (the session).
#[derive(Debug, Default)]
pub(crate) struct Memory {
    pub(crate) recent: Recent,
    /// The window that last ignored `WM_INPUTLANGCHANGEREQUEST`: it gets the hotkey straight away.
    pub(crate) message_ignored_by: Option<usize>,
    /// Windows where the language hotkey changed nothing: never pressed there again.
    hotkey_failed: Vec<usize>,
    /// Those of them already said so at `debug` (then `trace`).
    hotkey_failed_said: Vec<usize>,
    pub(crate) path: PathLog,
    /// The Caps Lock state the last message typed with.
    caps_known: Option<bool>,
    /// Caps Lock presses sent through the driver since, and when the last one went.
    caps_presses: u32,
    caps_pressed_at: Option<Instant>,
}

impl Memory {
    /// A Caps Lock press went out through the driver (a panel key, queued or not).
    pub(crate) fn caps_pressed(&mut self, now: Instant) {
        self.caps_presses += 1;
        self.caps_pressed_at = Some(now);
        tracing::trace!(
            presses = self.caps_presses,
            "Caps Lock pressed through the driver: the next message expects it toggled"
        );
    }

    /// The Caps Lock state to type with: `read` (the focused window's own), unless a Caps Lock press
    /// this agent sent within [`CAPS_SETTLE`] should have toggled it and the window has not read that
    /// press yet — then the expected state.
    fn resolve_caps(&mut self, read: bool, now: Instant) -> (bool, &'static str) {
        let expected = match (self.caps_known, self.caps_pressed_at) {
            (Some(known), Some(at))
                if self.caps_presses > 0 && now.saturating_duration_since(at) < CAPS_SETTLE =>
            {
                Some(known ^ (self.caps_presses % 2 == 1))
            }
            _ => None,
        };
        let resolved = match expected {
            Some(want) if want != read => (
                want,
                "expected: the window has not read the driver's Caps Lock press yet",
            ),
            _ => (read, "read from the focused window"),
        };
        self.caps_known = Some(resolved.0);
        self.caps_presses = 0;
        self.caps_pressed_at = None;
        resolved
    }

    fn hotkey_failed_in(&self, window: Option<usize>) -> bool {
        window.is_some_and(|w| self.hotkey_failed.contains(&w))
    }

    fn note_hotkey_failed(&mut self, window: Option<usize>) {
        if let Some(w) = window {
            if !self.hotkey_failed.contains(&w) {
                self.hotkey_failed.push(w);
            }
        }
    }

    /// Whether this window's dead hotkey is said for the first time (then `debug`, later `trace`).
    fn first_say_hotkey_failed(&mut self, window: Option<usize>) -> bool {
        match window {
            Some(w) if !self.hotkey_failed_said.contains(&w) => {
                self.hotkey_failed_said.push(w);
                true
            }
            _ => false,
        }
    }
}

/// Why one character went by Unicode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    /// A control character, or one outside the Basic Multilingual Plane (emoji).
    Control,
    /// The focused window's layout could not be read.
    NoLayout,
    /// The panel holds its key.
    Held,
    /// The panel holds six keys: no room in the report.
    Rollover,
    /// The report would be a sequence Windows reserves.
    System,
    /// No installed layout types it.
    Unproducible,
    /// The layout that types it could not be switched to.
    SwitchFailed,
}

/// What typing did, for the burst's line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Characters typed as keys.
    pub(crate) hid: u32,
    /// Characters sent by Unicode, for any reason.
    pub(crate) unicode: u32,
    /// Of those: whole messages (Ctrl/Alt/Win held, target unknown, device unusable).
    pub(crate) whole: u32,
    /// Of those: the rest of a message after the device became unusable, or a queue sent at once.
    pub(crate) abandoned: u32,
    pub(crate) control: u32,
    pub(crate) no_layout: u32,
    pub(crate) held: u32,
    pub(crate) rollover: u32,
    pub(crate) system: u32,
    pub(crate) unproducible: u32,
    pub(crate) switch_failed: u32,
    /// Layout switches confirmed, and the time they took.
    pub(crate) switches: u32,
    pub(crate) switch_ms: u64,
    /// Language hotkey presses among them.
    pub(crate) hotkey_presses: u32,
}

impl Tally {
    fn count(&mut self, why: Why) {
        let slot = match why {
            Why::Control => &mut self.control,
            Why::NoLayout => &mut self.no_layout,
            Why::Held => &mut self.held,
            Why::Rollover => &mut self.rollover,
            Why::System => &mut self.system,
            Why::Unproducible => &mut self.unproducible,
            Why::SwitchFailed => &mut self.switch_failed,
        };
        *slot += 1;
    }

    fn add(&mut self, other: &Tally) {
        self.hid += other.hid;
        self.unicode += other.unicode;
        self.whole += other.whole;
        self.abandoned += other.abandoned;
        self.control += other.control;
        self.no_layout += other.no_layout;
        self.held += other.held;
        self.rollover += other.rollover;
        self.system += other.system;
        self.unproducible += other.unproducible;
        self.switch_failed += other.switch_failed;
        self.switches += other.switches;
        self.switch_ms += other.switch_ms;
        self.hotkey_presses += other.hotkey_presses;
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Text through the old path. Its error is only ever a log line: the text is not replayed.
fn send_unicode<H: Host>(host: &H, text: String) {
    if let Err(error) = host
        .sendinput()
        .inject(&InputMessage::Text { text, game: None })
    {
        tracing::debug!(%error, "game text: the Unicode fallback failed");
    }
}

/// What the runtime lends a text job for one step.
pub(super) struct Cx<'a, D, H> {
    pub(super) state: &'a mut State<D>,
    pub(super) host: &'a mut H,
    pub(super) memory: &'a mut Memory,
    pub(super) gate: Gate,
    /// A wheel waits for the typing's modifiers: let them up at the next character boundary.
    pub(super) yield_modifiers: bool,
}

/// What a step of a text job came to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Advance {
    /// Call again at this time.
    Wait(Instant),
    /// The message is typed (the held state is restored).
    Done,
    /// Typing must stop: the caller drops everything queued and releases everything held.
    Stopped(Stop),
}

/// Why typing stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// A driver write failed (it warned already).
    WriteFailed,
    /// A report would have been a sequence Windows reserves (it is never written).
    Refused,
    /// The desktop was no longer one HID may drive, looked at just before a report.
    Target,
}

impl Stop {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::WriteFailed => "a driver write failed while typing",
            Self::Refused => "a keyboard report was refused (a reserved key sequence)",
            Self::Target => "the desktop changed before a typed report",
        }
    }
}

/// One message being typed.
pub(crate) struct TextJob {
    chars: Vec<char>,
    /// The next character to type.
    next: usize,
    phase: Phase,
    /// When the phase is due.
    due: Instant,
    queued_at: Instant,
    /// The panel's held modifiers and keys when typing began: in every report, restored at the end.
    base_mods: u8,
    base_keys: BTreeSet<u8>,
    /// The modifiers in the last report.
    mods: u8,
    /// The device holds more than the panel's keys: a typed key or modifiers are down.
    extra: bool,
    caps: bool,
    installed: Vec<Hkl>,
    /// Layouts this message could not switch to.
    failed: Vec<Hkl>,
    /// Switches tried for the character at `next`.
    tries: u8,
    /// A key went down in this message (the emulated repeat was stopped).
    pressed: bool,
    tally: Tally,
}

enum Phase {
    Begin,
    Plan,
    /// The modifiers are set; the key goes down at `due`.
    Down(Stroke),
    /// The key is down; it goes up at `due`.
    Up,
    /// The held state is restored; the character at `next` goes by Unicode at `due`.
    Unicode,
    /// The held state is restored; everything from `next` goes by Unicode at `due`.
    Rest,
    Switch(Switch),
    /// Restore the held state.
    Finish,
    Done,
}

struct Switch {
    from: Hkl,
    to: Hkl,
    began: Instant,
    stage: Stage,
}

enum Stage {
    /// Post the request.
    Post,
    /// The request is posted; wait for the layout.
    Message { until: Instant },
    /// Press the hotkey: `report` is the next of its reports.
    Hotkey {
        hotkey: LanguageHotkey,
        report: usize,
        presses: usize,
        before: Option<Hkl>,
    },
    /// The hotkey is pressed; wait for the layout to change.
    HotkeyWait {
        until: Instant,
        hotkey: LanguageHotkey,
        presses: usize,
        before: Option<Hkl>,
    },
}

/// One press of the language hotkey: `(modifiers, wait after)` per report, ending all released.
/// The grave accent is never pressed: it opens the console of many raw-input games.
pub(super) fn hotkey_reports(hotkey: LanguageHotkey) -> &'static [(u8, Duration)] {
    const ALT_SHIFT: [(u8, Duration); 4] = [
        (LALT, MODIFIER_LEAD),
        (LALT | LSHIFT, KEY_HOLD),
        (LALT, MODIFIER_LEAD),
        (0, Duration::ZERO),
    ];
    const CTRL_SHIFT: [(u8, Duration); 4] = [
        (LCTRL, MODIFIER_LEAD),
        (LCTRL | LSHIFT, KEY_HOLD),
        (LCTRL, MODIFIER_LEAD),
        (0, Duration::ZERO),
    ];
    match hotkey {
        LanguageHotkey::AltShift => &ALT_SHIFT,
        LanguageHotkey::CtrlShift => &CTRL_SHIFT,
        LanguageHotkey::Grave | LanguageHotkey::Off => &[],
    }
}

/// For the log: a layout's language id, `0419`.
struct Lang(u16);

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

fn lang(hkl: Hkl) -> Lang {
    Lang(hkl.lang())
}

impl TextJob {
    pub(crate) fn new(chars: Vec<char>, now: Instant) -> Self {
        Self {
            chars,
            next: 0,
            phase: Phase::Begin,
            due: now,
            queued_at: now,
            base_mods: 0,
            base_keys: BTreeSet::new(),
            mods: 0,
            extra: false,
            caps: false,
            installed: Vec::new(),
            failed: Vec::new(),
            tries: 0,
            pressed: false,
            tally: Tally::default(),
        }
    }

    /// Characters not typed yet (a key down counts as typed).
    pub(crate) fn remaining(&self) -> usize {
        let typing = usize::from(matches!(self.phase, Phase::Up));
        self.chars.len().saturating_sub(self.next + typing)
    }

    pub(crate) fn len(&self) -> usize {
        self.chars.len()
    }

    pub(crate) fn tally(&self) -> &Tally {
        &self.tally
    }

    /// Typing has begun: the held state it types over is taken.
    pub(crate) fn started(&self) -> bool {
        !matches!(self.phase, Phase::Begin)
    }

    /// The device holds only the panel's keys and modifiers: nothing typed is down.
    pub(crate) fn clean(&self) -> bool {
        !self.extra
    }

    /// Everything due by `now`.
    pub(super) fn advance<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
    ) -> Advance {
        loop {
            if self.due > now {
                return Advance::Wait(self.due);
            }
            if cx.gate != Gate::Hid
                && !matches!(self.phase, Phase::Begin | Phase::Rest | Phase::Done)
            {
                if let Err(stop) = self.abandon(now, cx) {
                    return Advance::Stopped(stop);
                }
                continue;
            }
            let result = match std::mem::replace(&mut self.phase, Phase::Done) {
                Phase::Begin => {
                    self.begin(now, cx);
                    Ok(())
                }
                Phase::Plan => self.plan(now, cx),
                Phase::Down(stroke) => self.down(now, cx, stroke),
                Phase::Up => self.up(now, cx),
                Phase::Unicode => {
                    self.unicode(now, cx);
                    Ok(())
                }
                Phase::Rest => {
                    self.rest(now, cx);
                    Ok(())
                }
                Phase::Switch(switch) => self.switch(now, cx, switch),
                Phase::Finish => self.finish(now, cx),
                Phase::Done => return Advance::Done,
            };
            if let Err(stop) = result {
                return Advance::Stopped(stop);
            }
        }
    }

    /// Decide the message's path, and take the held state it types over.
    fn begin<D: Driver, H: Host>(&mut self, now: Instant, cx: &mut Cx<'_, D, H>) {
        self.due = now;
        let whole = match cx.gate {
            Gate::Unusable => Some("the device is unusable"),
            Gate::Unknown => Some("HID target unknown"),
            Gate::Hid => {
                let panel = cx.state.held.modifiers;
                let sendinput = cx.host.sendinput().held_modifiers();
                if (panel | sendinput) & SHORTCUT_MODIFIERS != 0 {
                    Some("Ctrl, Alt or Win held")
                } else if sendinput & SHIFTS != 0 {
                    Some("Shift held through SendInput")
                } else {
                    None
                }
            }
        };
        if let Some(reason) = whole {
            cx.memory.path.note(TextPath::Unicode(reason));
            let n = count(self.chars.len());
            send_unicode(cx.host, self.chars.iter().collect());
            self.tally.unicode += n;
            self.tally.whole += n;
            self.next = self.chars.len();
            self.phase = Phase::Done;
            return;
        }
        cx.memory.path.note(TextPath::Hid);
        self.base_mods = cx.state.held.modifiers;
        self.base_keys = cx.state.held.keys.clone();
        self.mods = self.base_mods;
        let kb = cx.host.keyboard();
        let read = kb.caps_lock();
        self.installed = kb.installed_layouts();
        let current = kb.focused_layout();
        let (caps, source) = cx.memory.resolve_caps(read, now);
        self.caps = caps;
        tracing::debug!(caps, source, "game text: Caps Lock");
        if let Some(current) = current {
            cx.memory.recent.touch(current);
        }
        tracing::trace!(
            chars = self.chars.len(),
            waited_ms = millis(now.saturating_duration_since(self.queued_at)),
            layouts = self.installed.len(),
            lang = %lang(current.unwrap_or(Hkl(0))),
            held_keys = self.base_keys.len(),
            "game text: typing through the driver"
        );
        self.phase = Phase::Plan;
    }

    /// The next character: how it is typed, or what must happen first.
    fn plan<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
    ) -> Result<(), Stop> {
        let Some(&ch) = self.chars.get(self.next) else {
            self.phase = Phase::Finish;
            return Ok(());
        };
        if cx.yield_modifiers && self.extra {
            // A wheel waits for the typing's modifiers: they go up now, it goes, and they come
            // back MODIFIER_LEAD ahead of this character.
            self.report(cx, self.base_mods, None)?;
            self.mods = self.base_mods;
            self.due = now + MODIFIER_LEAD;
            self.phase = Phase::Plan;
            return Ok(());
        }
        if ch.is_control() || u32::from(ch) > 0xFFFF {
            return self.by_unicode(now, cx, Why::Control);
        }
        let kb = cx.host.keyboard();
        let Some(current) = kb.focused_layout() else {
            return self.by_unicode(now, cx, Why::NoLayout);
        };
        match stroke_on(kb, ch, current, self.caps) {
            Ok(stroke) => {
                if self.base_keys.contains(&stroke.usage) {
                    return self.by_unicode(now, cx, Why::Held);
                }
                if self.base_keys.len() >= 6 {
                    return self.by_unicode(now, cx, Why::Rollover);
                }
                let need = self.need(stroke);
                let mut keys = self.base_keys.clone();
                keys.insert(stroke.usage);
                if check_keyboard(need, &keys).is_err() {
                    return self.by_unicode(now, cx, Why::System);
                }
                if self.mods != need {
                    self.report(cx, need, None)?;
                    self.mods = need;
                    self.due = now + MODIFIER_LEAD;
                }
                self.phase = Phase::Down(stroke);
                Ok(())
            }
            Err(_) => {
                if self.tries >= MAX_SWITCHES_PER_CHAR {
                    tracing::debug!(
                        tries = self.tries,
                        "game text: the layout keeps changing under the text; a character goes by \
                         Unicode"
                    );
                    return self.by_unicode(now, cx, Why::SwitchFailed);
                }
                let found = find_layout(
                    kb,
                    ch,
                    &self.installed,
                    current,
                    &self.failed,
                    &cx.memory.recent,
                    self.caps,
                );
                match found {
                    Some(to) => self.start_switch(now, cx, current, to),
                    None => {
                        // A layout that types it, but could not be switched to this message.
                        let why = if self
                            .failed
                            .iter()
                            .any(|&h| stroke_on(kb, ch, h, self.caps).is_ok())
                        {
                            Why::SwitchFailed
                        } else {
                            Why::Unproducible
                        };
                        self.by_unicode(now, cx, why)
                    }
                }
            }
        }
    }

    /// The modifiers a stroke needs over the panel's: a held Shift is lifted for a lowercase
    /// character, and kept (not doubled) for a capital.
    fn need(&self, stroke: Stroke) -> u8 {
        let mut mods = if !stroke.shift {
            self.base_mods & !SHIFTS
        } else if self.base_mods & SHIFTS != 0 {
            self.base_mods
        } else {
            self.base_mods | LSHIFT
        };
        if stroke.altgr {
            mods |= ALTGR;
        }
        mods
    }

    fn down<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        stroke: Stroke,
    ) -> Result<(), Stop> {
        self.report(cx, self.mods, Some(stroke.usage))?;
        self.due = now + KEY_HOLD;
        self.phase = Phase::Up;
        Ok(())
    }

    fn up<D: Driver, H: Host>(&mut self, now: Instant, cx: &mut Cx<'_, D, H>) -> Result<(), Stop> {
        self.report(cx, self.mods, None)?;
        self.tally.hid += 1;
        self.next += 1;
        self.tries = 0;
        self.due = now + KEY_GAP;
        self.phase = Phase::Plan;
        Ok(())
    }

    /// The character at `next` goes by Unicode: first the held state is restored, so no typing
    /// modifier is down under it, and the Unicode waits MODIFIER_LEAD after that.
    fn by_unicode<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        why: Why,
    ) -> Result<(), Stop> {
        self.tally.count(why);
        if self.extra {
            self.report(cx, self.base_mods, None)?;
            self.mods = self.base_mods;
            self.due = now + MODIFIER_LEAD;
        }
        self.phase = Phase::Unicode;
        Ok(())
    }

    fn unicode<D: Driver, H: Host>(&mut self, now: Instant, cx: &mut Cx<'_, D, H>) {
        if let Some(&ch) = self.chars.get(self.next) {
            send_unicode(cx.host, ch.to_string());
            self.tally.unicode += 1;
        }
        self.next += 1;
        self.tries = 0;
        self.due = now + KEY_GAP;
        self.phase = Phase::Plan;
    }

    /// Everything from `next` by Unicode, in one piece.
    fn rest<D: Driver, H: Host>(&mut self, now: Instant, cx: &mut Cx<'_, D, H>) {
        let n = count(self.chars.len().saturating_sub(self.next));
        if n > 0 {
            send_unicode(cx.host, self.chars.iter().skip(self.next).collect());
            self.tally.unicode += n;
            self.tally.abandoned += n;
        }
        self.next = self.chars.len();
        self.due = now;
        self.phase = Phase::Done;
    }

    /// Restore the held state, and let the modifier change settle before what waits behind.
    fn finish<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
    ) -> Result<(), Stop> {
        if self.extra {
            self.report(cx, self.base_mods, None)?;
            self.mods = self.base_mods;
            self.due = now + MODIFIER_LEAD;
        }
        self.phase = Phase::Done;
        Ok(())
    }

    /// The device became unusable mid-message: the rest goes by Unicode, in one piece. Nothing is
    /// written to a device that refuses writes; were it writable, the held state would be restored
    /// first and the rest would wait MODIFIER_LEAD after it, as for one character.
    fn abandon<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
    ) -> Result<(), Stop> {
        if matches!(self.phase, Phase::Up) {
            // The key is down: it was typed (the cleanup that marked the device unusable, or the
            // restore below, lets it up).
            self.tally.hid += 1;
            self.next += 1;
        }
        tracing::debug!(
            unusable = cx.gate == Gate::Unusable,
            rest = self.chars.len().saturating_sub(self.next),
            "game text: the rest of the message goes by Unicode"
        );
        self.due = now;
        if self.extra && cx.gate != Gate::Unusable {
            self.report(cx, self.base_mods, None)?;
            self.mods = self.base_mods;
            self.due = now + MODIFIER_LEAD;
        }
        self.phase = Phase::Rest;
        Ok(())
    }

    fn start_switch<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        from: Hkl,
        to: Hkl,
    ) -> Result<(), Stop> {
        self.tries += 1;
        // Nothing typed stays down across a switch: the hotkey needs a clean keyboard, and a Shift
        // left down would ride into the new layout's first character.
        if self.extra {
            self.report(cx, self.base_mods, None)?;
            self.mods = self.base_mods;
            self.due = now + MODIFIER_LEAD;
        }
        self.phase = Phase::Switch(Switch {
            from,
            to,
            began: now,
            stage: Stage::Post,
        });
        Ok(())
    }

    fn switch<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        mut sw: Switch,
    ) -> Result<(), Stop> {
        match sw.stage {
            Stage::Post => {
                let kb = cx.host.keyboard();
                let focus = kb.focus();
                if cx.memory.hotkey_failed_in(focus) {
                    // Neither the request nor the hotkey worked in this window before.
                    let loud = cx.memory.first_say_hotkey_failed(focus);
                    return self.switch_failed(
                        now,
                        cx,
                        sw,
                        "neither the request nor the language hotkey changed this window's \
                         layout before: its characters that need another layout go by Unicode \
                         for the rest of the session",
                        loud,
                    );
                }
                if focus.is_some() && focus == cx.memory.message_ignored_by {
                    tracing::debug!(
                        from = %lang(sw.from),
                        to = %lang(sw.to),
                        "keyboard layout switch: this window ignored the request before; the \
                         language hotkey instead"
                    );
                    return self.go_hotkey(now, cx, sw);
                }
                match kb.request_layout(sw.to) {
                    Ok(()) => {
                        tracing::trace!(
                            from = %lang(sw.from),
                            to = %lang(sw.to),
                            "keyboard layout switch requested (WM_INPUTLANGCHANGEREQUEST)"
                        );
                        sw.stage = Stage::Message {
                            until: now + SWITCH_CONFIRM,
                        };
                        self.due = now + SWITCH_POLL;
                        self.phase = Phase::Switch(sw);
                        Ok(())
                    }
                    Err(why) => {
                        tracing::debug!(
                            why,
                            from = %lang(sw.from),
                            to = %lang(sw.to),
                            "keyboard layout switch: the request was not posted; the language \
                             hotkey instead"
                        );
                        self.go_hotkey(now, cx, sw)
                    }
                }
            }
            Stage::Message { until } => {
                let kb = cx.host.keyboard();
                if kb.focused_layout() == Some(sw.to) {
                    self.switched(now, cx, sw, "message", 0);
                    return Ok(());
                }
                if now >= until {
                    cx.memory.message_ignored_by = kb.focus();
                    tracing::debug!(
                        waited_ms = millis(now.saturating_duration_since(sw.began)),
                        from = %lang(sw.from),
                        to = %lang(sw.to),
                        "keyboard layout switch: the window did not take the request; the \
                         language hotkey instead"
                    );
                    return self.go_hotkey(now, cx, sw);
                }
                self.due = now + SWITCH_POLL;
                self.phase = Phase::Switch(sw);
                Ok(())
            }
            Stage::Hotkey {
                hotkey,
                report,
                presses,
                before,
            } => {
                let reports = hotkey_reports(hotkey);
                let Some(&(mods, after)) = reports.get(report) else {
                    return self.switch_failed(now, cx, sw, "no language hotkey to press", true);
                };
                self.report(cx, mods, None)?;
                if report + 1 < reports.len() {
                    sw.stage = Stage::Hotkey {
                        hotkey,
                        report: report + 1,
                        presses,
                        before,
                    };
                    self.due = now + after;
                } else {
                    tracing::trace!(
                        target: crate::KEY_NAMES_TARGET,
                        hotkey = hotkey.name(),
                        presses = presses + 1,
                        "language hotkey pressed"
                    );
                    sw.stage = Stage::HotkeyWait {
                        until: now + SWITCH_CONFIRM,
                        hotkey,
                        presses: presses + 1,
                        before,
                    };
                    self.due = now + SWITCH_POLL;
                }
                self.phase = Phase::Switch(sw);
                Ok(())
            }
            Stage::HotkeyWait {
                until,
                hotkey,
                presses,
                before,
            } => {
                let kb = cx.host.keyboard();
                let current = kb.focused_layout();
                if current == Some(sw.to) {
                    self.switched(now, cx, sw, "hotkey", presses);
                    return Ok(());
                }
                if current != before {
                    if current.is_some_and(|c| c.lang() == sw.to.lang()) {
                        // The language was reached, but another of its layouts: the language
                        // hotkey chooses languages, not the layouts of one.
                        return self.switch_failed(
                            now,
                            cx,
                            sw,
                            "the language hotkey reached the layout's language but another of its \
                             layouts: it cannot choose between the layouts of one language",
                            true,
                        );
                    }
                    // The hotkey works but went to another language: press again, up to once per
                    // installed layout.
                    if presses < self.installed.len().max(1) {
                        sw.stage = Stage::Hotkey {
                            hotkey,
                            report: 0,
                            presses,
                            before: current,
                        };
                        self.due = now + KEY_GAP;
                        self.phase = Phase::Switch(sw);
                        return Ok(());
                    }
                    return self.switch_failed(
                        now,
                        cx,
                        sw,
                        "the language hotkey went round without reaching the layout",
                        true,
                    );
                }
                if now >= until {
                    let focus = kb.focus();
                    cx.memory.note_hotkey_failed(focus);
                    cx.memory.first_say_hotkey_failed(focus);
                    return self.switch_failed(
                        now,
                        cx,
                        sw,
                        "the language hotkey did not change the layout: it is not pressed in this \
                         window again this session",
                        true,
                    );
                }
                self.due = now + SWITCH_POLL;
                self.phase = Phase::Switch(sw);
                Ok(())
            }
        }
    }

    /// Switch by the user's language hotkey, pressed through the driver — when it may be.
    fn go_hotkey<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        mut sw: Switch,
    ) -> Result<(), Stop> {
        let kb = cx.host.keyboard();
        let hotkey = kb.language_hotkey();
        let refusal = match hotkey {
            LanguageHotkey::Off => Some("no language hotkey is set"),
            LanguageHotkey::Grave => Some(
                "the language hotkey is the grave accent, which opens the console of many games: \
                 never pressed",
            ),
            LanguageHotkey::AltShift | LanguageHotkey::CtrlShift
                if sw.to.lang() == sw.from.lang() =>
            {
                Some(
                    "the layout is another layout of the same language: the language hotkey \
                     switches languages, not layouts",
                )
            }
            _ if self.base_mods != 0 || !self.base_keys.is_empty() => {
                Some("keys are held: the language hotkey would not be pressed alone")
            }
            _ => None,
        };
        if let Some(why) = refusal {
            return self.switch_failed(now, cx, sw, why, true);
        }
        let before = kb.focused_layout();
        tracing::debug!(
            target: crate::KEY_NAMES_TARGET,
            hotkey = hotkey.name(),
            from = %lang(sw.from),
            to = %lang(sw.to),
            "keyboard layout switch: pressing the language hotkey through the driver"
        );
        sw.stage = Stage::Hotkey {
            hotkey,
            report: 0,
            presses: 0,
            before,
        };
        self.due = now;
        self.phase = Phase::Switch(sw);
        Ok(())
    }

    fn switched<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        sw: Switch,
        method: &'static str,
        presses: usize,
    ) {
        let ms = millis(now.saturating_duration_since(sw.began));
        cx.memory.recent.touch(sw.to);
        self.tally.switches += 1;
        self.tally.switch_ms += ms;
        self.tally.hotkey_presses += count(presses);
        tracing::debug!(
            method,
            ms,
            presses,
            from = %lang(sw.from),
            to = %lang(sw.to),
            layout = format_args!("{:08x}", sw.to.0 as u32),
            "keyboard layout switched for game text"
        );
        self.phase = Phase::Plan;
        self.due = now;
    }

    /// `loud`: said at `debug`; a failure already said for this window goes to `trace`.
    fn switch_failed<D: Driver, H: Host>(
        &mut self,
        now: Instant,
        cx: &mut Cx<'_, D, H>,
        sw: Switch,
        why: &'static str,
        loud: bool,
    ) -> Result<(), Stop> {
        self.failed.push(sw.to);
        let waited_ms = millis(now.saturating_duration_since(sw.began));
        if loud {
            tracing::debug!(
                why,
                waited_ms,
                from = %lang(sw.from),
                to = %lang(sw.to),
                "keyboard layout switch failed: characters that need that layout go by Unicode in \
                 this message"
            );
        } else {
            tracing::trace!(
                why,
                waited_ms,
                from = %lang(sw.from),
                to = %lang(sw.to),
                "keyboard layout switch not tried"
            );
        }
        self.due = now;
        self.by_unicode(now, cx, Why::SwitchFailed)
    }

    /// One keyboard report: the panel's held keys, the typed key if any, and `mods` — after a fresh
    /// look at the desktop. Nothing is logged per report: which reports carry which modifiers is the
    /// shape of the text.
    fn report<D: Driver, H: Host>(
        &mut self,
        cx: &mut Cx<'_, D, H>,
        mods: u8,
        typed: Option<u8>,
    ) -> Result<(), Stop> {
        let mut keys = self.base_keys.clone();
        if let Some(usage) = typed {
            keys.insert(usage);
        }
        if let Err(error) = check_keyboard(mods, &keys) {
            tracing::debug!(
                %error,
                "game text: a keyboard report was refused (a reserved key sequence), not written; \
                 typing stops"
            );
            return Err(Stop::Refused);
        }
        // The worker types unattended: a UAC prompt or the lock screen may have taken the input
        // since the last report.
        let eval = cx.host.evaluate_target();
        if eval.target != Target::Allowed {
            tracing::debug!(
                reason = eval.reason,
                "game text: the desktop is not one HID may drive; nothing more is typed"
            );
            return Err(Stop::Target);
        }
        if !self.pressed && (typed.is_some() || mods & !self.base_mods != 0) {
            // Like a physical keyboard's new key, the first key typed ends SendInput's emulated
            // repeat — once per message.
            self.pressed = true;
            cx.host.sendinput().other_key_pressed(false, false);
        }
        // A failed write has warned already (`State::write`).
        cx.state
            .typing_report(mods, &keys)
            .map_err(|_| Stop::WriteFailed)?;
        self.extra = mods != self.base_mods || typed.is_some();
        Ok(())
    }

    /// Everything left, at once: the held state restored (unless the device is unusable), then —
    /// MODIFIER_LEAD later, as for one character — the rest by Unicode, in one piece. For a queue
    /// that cannot wait for its worker.
    pub(super) fn flush<D: Driver, H: Host>(&mut self, cx: &mut Cx<'_, D, H>) {
        if matches!(self.phase, Phase::Done) {
            return;
        }
        if matches!(self.phase, Phase::Up) {
            // The key is down: the restore below releases it, and it was typed.
            self.tally.hid += 1;
            self.next += 1;
        }
        if self.extra && cx.gate != Gate::Unusable {
            match self.report(cx, self.base_mods, None) {
                Ok(()) => cx.host.pause(MODIFIER_LEAD),
                Err(stop) => tracing::debug!(
                    reason = stop.reason(),
                    "game text: restoring the held state failed while flushing"
                ),
            }
        }
        let n = count(self.chars.len().saturating_sub(self.next));
        if n > 0 {
            send_unicode(cx.host, self.chars.iter().skip(self.next).collect());
            self.tally.unicode += n;
            self.tally.abandoned += n;
        }
        self.next = self.chars.len();
        self.phase = Phase::Done;
    }
}

/// What waits in the queue.
pub(crate) enum Job {
    Text(Box<TextJob>),
    /// Input that waited behind text, or a release waiting out [`TAP_MIN_HOLD`]: routed as usual
    /// when its turn comes — not before `not_before`, and with the gap it arrived with.
    Event {
        event: InputMessage,
        not_before: Option<Instant>,
        arrived: Instant,
    },
}

impl Job {
    /// Text (typed or by Unicode) moves and the wheel may overtake; nothing else.
    fn is_text(&self) -> bool {
        matches!(
            self,
            Job::Text(_)
                | Job::Event {
                    event: InputMessage::Text { .. },
                    ..
                }
        )
    }
}

/// What the queue's head asks for now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    Empty,
    /// An event waits until then (its minimum hold, or the gap it arrived with).
    Wait(Instant),
    Event,
    Text,
}

/// What one burst (from the first entry queued until the queue drains) did.
#[derive(Debug, Default)]
struct Burst {
    messages: u32,
    chars: u32,
    tally: Tally,
    /// Short key and button taps held to the minimum.
    taps: u32,
    /// Which of them were keys of the viewer's own (`k.src`), by name; the other keys are counted,
    /// never named (`crate::key_log`).
    tap_keys: Names,
    tap_keys_other: u32,
    tap_buttons: u32,
    /// The shortest hold the viewer gave one of them, before it was held to the minimum.
    tap_shortest: Option<Duration>,
    wheels_dropped: u32,
}

impl Burst {
    /// One tap held to the minimum: `event` is its release, `held` how long the viewer held it.
    fn tap(&mut self, event: &InputMessage, held: Duration) {
        self.taps += 1;
        match event {
            InputMessage::Key { code, src, .. } if key_log::ours(*src) => self.tap_keys.add(code),
            InputMessage::Key { .. } => self.tap_keys_other += 1,
            _ => self.tap_buttons += 1,
        }
        self.tap_shortest = Some(self.tap_shortest.map_or(held, |s| s.min(held)));
    }

    /// The shortest hold, for the line: whole milliseconds, `-` for none.
    fn shortest_ms(&self) -> String {
        self.tap_shortest
            .map_or_else(|| "-".to_owned(), |d| d.as_millis().to_string())
    }
}

/// Game text waiting to be typed, with the input queued behind it. Lives in the runtime, under its
/// lock; the runtime's `step` works it.
#[derive(Default)]
pub(crate) struct Typist {
    pub(crate) queue: VecDeque<Job>,
    pub(crate) memory: Memory,
    /// Game wheels waiting for the typing's modifiers to go up, so none carries a capital's Shift.
    pub(crate) held_wheels: VecDeque<InputMessage>,
    /// The last queued event replayed: when it arrived, and when it went.
    replayed: Option<(Instant, Instant)>,
    /// When the event being replayed now arrived (a release deferred on its turn keeps it).
    pub(crate) replaying: Option<Instant>,
    burst: Burst,
    /// Bumped on every change of the queue, so the glue knows when to wake its worker.
    pub(crate) changes: u64,
}

/// For the log: which kind of input waits.
fn kind(event: &InputMessage) -> &'static str {
    match event {
        InputMessage::Key { .. } => "k",
        InputMessage::Down { .. } => "d",
        InputMessage::Up { .. } => "u",
        InputMessage::Combo { .. } => "combo",
        InputMessage::Text { .. } => "text",
        InputMessage::Rel { .. } => "r",
        InputMessage::Move { .. } => "m",
        InputMessage::Wheel { .. } => "w",
        _ => "other",
    }
}

impl Typist {
    pub(crate) fn has_work(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Only text waits (or nothing): moves and the wheel may go at once.
    pub(crate) fn only_text(&self) -> bool {
        self.queue.iter().all(Job::is_text)
    }

    /// The text at the head holds modifiers (or a key) of its own down right now.
    pub(crate) fn head_holds_modifiers(&self) -> bool {
        matches!(self.queue.front(), Some(Job::Text(job)) if !job.clean())
    }

    /// Characters queued and not typed yet.
    pub(crate) fn queued_chars(&self) -> usize {
        self.queue
            .iter()
            .map(|job| match job {
                Job::Text(job) => job.remaining(),
                Job::Event {
                    event: InputMessage::Text { text, .. },
                    ..
                } => text.chars().count(),
                Job::Event { .. } => 0,
            })
            .sum()
    }

    /// What the head asks for at `now`. A queued event waits for the gap it arrived with after the
    /// one replayed before it (capped at [`MAX_REPLAY_GAP`]).
    pub(crate) fn next(&self, now: Instant) -> Next {
        match self.queue.front() {
            None => Next::Empty,
            Some(Job::Text(_)) => Next::Text,
            Some(Job::Event {
                not_before: Some(at),
                ..
            }) => {
                if *at > now {
                    Next::Wait(*at)
                } else {
                    Next::Event
                }
            }
            Some(Job::Event { arrived, .. }) => match self.replayed {
                Some((prev_arrived, prev_went)) => {
                    let gap = arrived
                        .saturating_duration_since(prev_arrived)
                        .min(MAX_REPLAY_GAP);
                    let due = prev_went + gap;
                    if due > now {
                        Next::Wait(due)
                    } else {
                        Next::Event
                    }
                }
                None => Next::Event,
            },
        }
    }

    pub(crate) fn push_text(&mut self, text: Normalized, now: Instant) {
        tracing::trace!(
            chars = text.chars.len(),
            newlines_dropped = text.newlines,
            replaced = text.replaced,
            queued = self.queue.len(),
            "game text queued"
        );
        self.burst.messages += 1;
        self.burst.chars += count(text.chars.len());
        self.queue
            .push_back(Job::Text(Box::new(TextJob::new(text.chars, now))));
        self.changes += 1;
    }

    /// Input that must not overtake what is queued ahead of it.
    pub(crate) fn push_event(&mut self, event: InputMessage, now: Instant) {
        tracing::trace!(
            kind = kind(&event),
            queued = self.queue.len(),
            "input waits behind queued input"
        );
        self.queue.push_back(Job::Event {
            event,
            not_before: None,
            arrived: now,
        });
        self.changes += 1;
    }

    /// A game wheel that waits for the typing's modifiers to go up.
    pub(crate) fn hold_wheel(&mut self, event: InputMessage) {
        if self.held_wheels.len() >= MAX_HELD_WHEELS {
            self.held_wheels.pop_front();
            self.burst.wheels_dropped += 1;
            tracing::trace!("game wheel dropped: too many wait for the typing's modifiers");
        }
        tracing::trace!(
            held = self.held_wheels.len() + 1,
            "game wheel waits for the typing's modifiers"
        );
        self.held_wheels.push_back(event);
        self.changes += 1;
    }

    /// A release that waits until `at`, ahead of everything queued: it is the event being routed
    /// now (the queue's head, or nothing was queued), so nothing may overtake it. `held`: how long
    /// the viewer held the key or button, for the burst's line.
    pub(crate) fn defer_front(
        &mut self,
        event: InputMessage,
        at: Instant,
        now: Instant,
        held: Duration,
    ) {
        self.burst.tap(&event, held);
        self.wait_front(event, at, now);
    }

    /// An event that waits until `at` ahead of everything queued, as [`Self::defer_front`] but not a
    /// tap: a mouse button waiting for the absolute move before it to show (the router counts those
    /// itself).
    pub(crate) fn wait_front(&mut self, event: InputMessage, at: Instant, now: Instant) {
        self.queue.push_front(Job::Event {
            event,
            not_before: Some(at),
            arrived: self.replaying.unwrap_or(now),
        });
        self.changes += 1;
    }

    /// Take the head (a queued event is taken with its arrival time, for its replay).
    pub(crate) fn pop(&mut self) -> Option<Job> {
        let job = self.queue.pop_front();
        if job.is_some() {
            self.changes += 1;
        }
        job
    }

    /// A queued event went out at `now`: the next one keeps the gap it arrived with after it.
    pub(crate) fn note_replayed(&mut self, arrived: Instant, now: Instant) {
        self.replayed = Some((arrived, now));
    }

    /// A message is typed (the job was popped).
    pub(crate) fn finished(&mut self, job: &TextJob) {
        tracing::trace!(
            chars = job.len(),
            hid = job.tally().hid,
            unicode = job.tally().unicode,
            switches = job.tally().switches,
            "game text: message done"
        );
        self.burst.tally.add(job.tally());
    }

    /// Drop everything queued and every held wheel — the caller releases what is held on both
    /// paths — counting it.
    pub(crate) fn drop_all(&mut self, reason: &'static str) {
        if self.queue.is_empty() && self.held_wheels.is_empty() {
            return;
        }
        let (mut texts, mut chars, mut events) = (0_u32, 0_usize, 0_u32);
        for job in self.queue.drain(..) {
            match job {
                Job::Text(job) => {
                    texts += 1;
                    chars += job.remaining();
                    self.burst.tally.add(job.tally());
                }
                Job::Event { .. } => events += 1,
            }
        }
        let wheels = self.held_wheels.len();
        self.held_wheels.clear();
        self.changes += 1;
        tracing::debug!(
            reason,
            texts,
            chars,
            events,
            wheels,
            "game text: pending typing and the input queued behind it dropped"
        );
        self.idle();
    }

    /// The queue drained: one line for the burst.
    pub(crate) fn idle(&mut self) {
        self.replayed = None;
        let burst = std::mem::take(&mut self.burst);
        let t = burst.tally;
        if burst.messages > 0 {
            tracing::debug!(
                target: crate::KEY_NAMES_TARGET,
                messages = burst.messages,
                chars = burst.chars,
                hid = t.hid,
                unicode = t.unicode,
                whole = t.whole,
                abandoned = t.abandoned,
                control = t.control,
                no_layout = t.no_layout,
                held = t.held,
                rollover = t.rollover,
                reserved = t.system,
                unproducible = t.unproducible,
                switch_failed = t.switch_failed,
                switches = t.switches,
                switch_ms = t.switch_ms,
                hotkey_presses = t.hotkey_presses,
                tap_deferrals = burst.taps,
                tap_keys = %burst.tap_keys,
                tap_keys_other = burst.tap_keys_other,
                tap_buttons = burst.tap_buttons,
                tap_shortest_ms = %burst.shortest_ms(),
                wheels_dropped = burst.wheels_dropped,
                "game text typed"
            );
        } else if burst.taps > 0 {
            tracing::debug!(
                target: crate::KEY_NAMES_TARGET,
                tap_deferrals = burst.taps,
                tap_keys = %burst.tap_keys,
                tap_keys_other = burst.tap_keys_other,
                tap_buttons = burst.tap_buttons,
                tap_shortest_ms = %burst.shortest_ms(),
                "short taps held to the minimum through the driver (tap_keys: the viewer's own \
                 keys by name; its keyboard's only counted)"
            );
        }
    }
}

#[cfg(test)]
mod tests;
