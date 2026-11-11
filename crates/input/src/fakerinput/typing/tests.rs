//! Game text typed through the driver, on the fake world (`super::super::fake`): fake layouts, a
//! recording device and SendInput path, a virtual clock. Nothing here touches Windows.
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::sync::{Arc, Mutex};

use afklink_protocol::InputMessage;

use super::super::fake::{self, is_keyboard, is_mouse, Harness, Out, DE, FR, RU, US, US_INTL};
use super::super::{key as dom_key, Key, Target};
use super::*;
use crate::keymap::{code_to_vk, vk_to_scan};

// The usages the tests name.
const A: u8 = 0x04;
const B: u8 = 0x05;
const C: u8 = 0x06;
const D: u8 = 0x07;
const E: u8 = 0x08;
const F: u8 = 0x09;
const G: u8 = 0x0A;
const H: u8 = 0x0B;
const I: u8 = 0x0C;
const K: u8 = 0x0E;
const L: u8 = 0x0F;
const N: u8 = 0x11;
const O: u8 = 0x12;
const Q: u8 = 0x14;
const T: u8 = 0x17;
const W: u8 = 0x1A;
const Y: u8 = 0x1C;
const Z: u8 = 0x1D;
const DIGIT1: u8 = 0x1E;
const DIGIT2: u8 = 0x1F;
const DIGIT6: u8 = 0x23;
const ENTER: u8 = 0x28;
const SPACE: u8 = 0x2C;

fn stroke(usage: u8, shift: bool, altgr: bool) -> Result<Stroke, Unproducible> {
    Ok(Stroke {
        usage,
        shift,
        altgr,
    })
}

/// `stroke_on` against one fake layout.
fn on(layout: fake::FakeLayout, ch: char, caps: bool) -> Result<Stroke, Unproducible> {
    let hkl = layout.hkl;
    let mut h = Harness::with(vec![layout], hkl);
    stroke_on(h.rt.host.keyboard(), ch, hkl, caps)
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

/// Where in the log the first event of a kind is.
fn index_of(h: &Harness, what: impl Fn(&Out) -> bool) -> usize {
    h.world().log.iter().position(|(_, out)| what(out)).unwrap()
}

fn is_unicode(out: &Out) -> bool {
    matches!(out, Out::SendInput(InputMessage::Text { .. }))
}

fn wheel(game: bool) -> InputMessage {
    InputMessage::Wheel {
        dx: 0.0,
        dy: 100.0,
        mode: None,
        game: game.then_some(true),
    }
}

/// The device's mouse side, in order: button changes (`b<bits>`), moves (`r`), wheel turns (`w` with
/// the keyboard modifiers down at the time).
fn mouse_timeline(h: &Harness) -> Vec<(u64, String)> {
    h.world()
        .device_timeline()
        .into_iter()
        .filter(|(_, what)| !what.starts_with('k'))
        .collect()
}

fn line(entries: &[(u64, &str)]) -> Vec<(u64, String)> {
    entries.iter().map(|&(at, s)| (at, s.to_owned())).collect()
}

#[test]
fn the_typing_table_is_the_physical_key_table() {
    // The scan codes the layouts give back are typed as the same HID usages the viewer's physical
    // keys use: one table cannot drift from the other.
    let mut codes: Vec<String> = ('A'..='Z').map(|c| format!("Key{c}")).collect();
    codes.extend(('0'..='9').map(|c| format!("Digit{c}")));
    for code in [
        "Minus",
        "Equal",
        "BracketLeft",
        "BracketRight",
        "Backslash",
        "Semicolon",
        "Quote",
        "Backquote",
        "Comma",
        "Period",
        "Slash",
        "Space",
        "IntlBackslash",
    ] {
        codes.push(code.into());
    }
    for code in codes {
        let (vk, _) = code_to_vk(&code).unwrap();
        let scan = vk_to_scan(vk).unwrap();
        assert_eq!(
            scan_to_usage(scan).map(Key::Usage),
            dom_key(&code),
            "{code}"
        );
    }
    // Not typing keys: Enter, Backspace, Tab, Escape, the keypad (Num Lock changes it), E0 keys,
    // the Japanese and Brazilian extras past the descriptor.
    for scan in [
        0x1C, 0x0E, 0x0F, 0x01, 0x47, 0x4F, 0x52, 0x53, 0x37, 0xE01C, 0xE035, 0x73, 0x7D, 0x7E,
    ] {
        assert_eq!(scan_to_usage(scan), None, "{scan:#x}");
    }
}

#[test]
fn characters_map_to_physical_keys_on_each_layout() {
    // US.
    assert_eq!(on(fake::us(), 'a', false), stroke(A, false, false));
    assert_eq!(on(fake::us(), 'A', false), stroke(A, true, false));
    assert_eq!(on(fake::us(), '@', false), stroke(DIGIT2, true, false));
    assert_eq!(on(fake::us(), ' ', false), stroke(SPACE, false, false));
    assert_eq!(on(fake::us(), 'п', false), Err(Unproducible::NoKey));
    // Russian: its letters on the same physical keys.
    assert_eq!(on(fake::ru(), 'п', false), stroke(G, false, false));
    assert_eq!(on(fake::ru(), 'Т', false), stroke(N, true, false));
    assert_eq!(on(fake::ru(), '.', false), stroke(0x38, false, false));
    // German: Y and Z swap places; AltGr (left Ctrl + right Alt) on Q is '@'.
    assert_eq!(on(fake::de(), 'z', false), stroke(Y, false, false));
    assert_eq!(on(fake::de(), 'y', false), stroke(Z, false, false));
    assert_eq!(on(fake::de(), '@', false), stroke(Q, false, true));
    assert_eq!(on(fake::de(), '€', false), stroke(E, false, true));
    // French: A and Q swap, digits need Shift, 'é' is a key of its own.
    assert_eq!(on(fake::fr(), 'a', false), stroke(Q, false, false));
    assert_eq!(on(fake::fr(), '1', false), stroke(DIGIT1, true, false));
    assert_eq!(on(fake::fr(), 'é', false), stroke(DIGIT2, false, false));
    assert_eq!(on(fake::fr(), '@', false), stroke(0x27, false, true));
    // Beyond the Basic Multilingual Plane there is no key at all.
    assert_eq!(on(fake::us(), '🙂', false), Err(Unproducible::NoKey));
}

#[test]
fn caps_lock_and_dead_keys_are_checked_by_what_the_key_makes() {
    // Caps Lock on: the letter keys' case turns, so a lowercase letter needs Shift and a capital
    // does not; digits and punctuation do not turn.
    assert_eq!(on(fake::us(), 'a', true), stroke(A, true, false));
    assert_eq!(on(fake::us(), 'A', true), stroke(A, false, false));
    assert_eq!(on(fake::us(), '1', true), stroke(DIGIT1, false, false));
    assert_eq!(on(fake::us(), '!', true), stroke(DIGIT1, true, false));
    assert_eq!(on(fake::ru(), 'п', true), stroke(G, true, false));
    assert_eq!(on(fake::fr(), '1', true), stroke(DIGIT1, true, false));
    // Dead keys are never typed: they would wait for the next key.
    assert_eq!(on(fake::fr(), '^', false), Err(Unproducible::DeadKey));
    assert_eq!(on(fake::fr(), '¨', false), Err(Unproducible::DeadKey));
    assert_eq!(on(fake::de(), '^', false), Err(Unproducible::DeadKey));
    // A composed character has no key of its own.
    assert_eq!(on(fake::fr(), 'ê', false), Err(Unproducible::NoKey));
}

#[test]
fn normalisation_drops_newlines_and_makes_ios_typography_ascii() {
    let n = normalize("Hi\n“you” — it’s…\u{a0}ok\r\n‘x’–y");
    assert_eq!(
        n.chars.iter().collect::<String>(),
        "Hi\"you\" - it's... ok'x'-y"
    );
    assert_eq!(n.newlines, 3);
    assert_eq!(n.replaced, 9);
    assert!(normalize("\n\r\n").chars.is_empty());
    // Emoji and other characters stay: they go by Unicode later.
    assert_eq!(normalize("ok 🙂").chars.iter().collect::<String>(), "ok 🙂");
}

#[test]
fn the_language_hotkey_setting_reads_like_windows() {
    assert_eq!(parse_hotkey(None, None), LanguageHotkey::AltShift);
    assert_eq!(parse_hotkey(Some("1"), None), LanguageHotkey::AltShift);
    assert_eq!(
        parse_hotkey(Some("2"), Some("1")),
        LanguageHotkey::CtrlShift
    );
    assert_eq!(parse_hotkey(Some("3"), None), LanguageHotkey::Off);
    assert_eq!(parse_hotkey(Some("4"), None), LanguageHotkey::Grave);
    assert_eq!(parse_hotkey(None, Some("2")), LanguageHotkey::CtrlShift);
    assert_eq!(parse_hotkey(Some(" 1 "), None), LanguageHotkey::AltShift);
    assert_eq!(parse_hotkey(Some("7"), None), LanguageHotkey::Off);
}

#[test]
fn a_message_is_typed_one_paced_key_at_a_time() {
    let mut h = Harness::new();
    h.game_text("ab");
    assert!(
        h.world().log.is_empty(),
        "inject only queues: nothing is typed on the event task"
    );
    let done = h.run();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [
            (0, 0, vec![A]),
            (30, 0, vec![]),
            (50, 0, vec![B]),
            (80, 0, vec![]),
        ],
        "each key held KEY_HOLD, KEY_GAP between"
    );
    assert_eq!(done, 100, "the gap after the last key is waited out too");
    assert_eq!(w.unicode(), "");
}

#[test]
fn capitals_share_one_shift_set_ahead_of_the_key() {
    let mut h = Harness::new();
    h.game_text("ABc");
    let done = h.run();
    assert_eq!(
        h.world().keyboard_reports(),
        [
            (0, LSHIFT, vec![]),
            (10, LSHIFT, vec![A]),
            (40, LSHIFT, vec![]),
            (60, LSHIFT, vec![B]),
            (90, LSHIFT, vec![]),
            (110, 0, vec![]),
            (120, 0, vec![C]),
            (150, 0, vec![]),
        ]
    );
    assert_eq!(done, 170);
    // A message that ends on a capital restores the held state, MODIFIER_LEAD before what follows.
    let mut h = Harness::new();
    h.game_text("aB");
    let done = h.run();
    assert_eq!(h.world().keyboard_reports().last(), Some(&(110, 0, vec![])));
    assert_eq!(done, 120);
}

#[test]
fn held_panel_keys_ride_in_every_report_and_a_held_shift_is_lifted_for_lowercase() {
    let mut h = Harness::new();
    h.key("KeyW", true).unwrap();
    h.key("ShiftLeft", true).unwrap();
    h.at(100);
    h.game_text("aB");
    h.run();
    let reports: Vec<_> = h
        .world()
        .keyboard_reports()
        .into_iter()
        .filter(|(at, _, _)| *at >= 100)
        .collect();
    // Shift lifted 10 ms ahead of 'a', W held all along; Shift back for 'B'; at the end the device
    // holds what the panel holds.
    assert_eq!(
        reports,
        [
            (100, 0, vec![W]),
            (110, 0, vec![A, W]),
            (140, 0, vec![W]),
            (160, LSHIFT, vec![W]),
            (170, LSHIFT, vec![B, W]),
            (200, LSHIFT, vec![W]),
        ]
    );
    // The ledger is the panel's and never changed.
    assert_eq!(h.rt.state.held.modifiers, LSHIFT);
    assert_eq!(
        h.rt.state.held.keys.iter().copied().collect::<Vec<_>>(),
        [W]
    );
    assert!(h.rt.state.held.dirty_keyboard, "the panel still holds keys");
    // Its release is its own.
    h.at(300);
    h.key("KeyW", false).unwrap();
    h.key("ShiftLeft", false).unwrap();
    assert_eq!(h.world().keyboard_reports().last(), Some(&(300, 0, vec![])));
}

#[test]
fn ctrl_alt_or_win_held_on_either_path_sends_the_whole_message_by_unicode() {
    for code in ["ControlLeft", "AltRight", "MetaLeft"] {
        let mut h = Harness::new();
        h.key(code, true).unwrap();
        h.game_text("hi");
        h.run();
        let w = h.world();
        assert_eq!(w.unicode(), "hi", "{code} held on HID");
        assert_eq!(
            w.keyboard_reports().len(),
            1,
            "only the held key's own report"
        );
    }
    for mods in [LCTRL, LALT, 0x80, LSHIFT] {
        let mut h = Harness::new();
        h.world().sendinput_mods = mods;
        h.game_text("hi");
        h.run();
        let w = h.world();
        assert_eq!(w.unicode(), "hi", "{mods:#x} held through SendInput");
        assert!(w.keyboard_reports().is_empty());
    }
}

#[test]
fn a_held_key_or_a_full_rollover_sends_that_character_by_unicode() {
    let mut h = Harness::new();
    h.key("KeyA", true).unwrap();
    h.game_text("ab");
    h.run();
    assert_eq!(h.world().unicode(), "a");
    assert!(
        index_of(&h, is_unicode) < h.world().log.len() - 2,
        "'a' goes in its place, before 'b'"
    );
    assert_eq!(h.world().usages(), [A, B], "the held A, then the typed B");

    let mut h = Harness::new();
    for code in ["KeyQ", "KeyW", "KeyE", "KeyR", "KeyT", "KeyY"] {
        h.key(code, true).unwrap();
    }
    let before = h.world().keyboard_reports().len();
    h.game_text("a");
    h.run();
    assert_eq!(
        h.world().unicode(),
        "a",
        "six keys held: no room in the report"
    );
    assert_eq!(h.world().keyboard_reports().len(), before);
}

#[test]
fn caps_lock_on_types_lowercase_with_shift_and_capitals_without() {
    let mut h = Harness::new();
    h.world().caps = true;
    h.game_text("aB1");
    h.run();
    assert_eq!(
        h.world().key_downs(),
        [(10, LSHIFT, A), (70, 0, B), (120, 0, DIGIT1)]
    );
}

#[test]
fn a_dead_key_character_switches_layout_or_goes_by_unicode() {
    // On French '^' is dead; US types it with Shift+6.
    let mut h = Harness::with(vec![fake::fr(), fake::us()], FR);
    h.game_text("^");
    h.run();
    let w = h.world();
    assert_eq!(w.unicode(), "");
    assert_eq!(w.requests(), [(0, US)]);
    assert_eq!(w.key_downs(), [(30, LSHIFT, DIGIT6)]);
    assert_eq!(w.focused, US, "the switch is left in place");
    drop(w);

    // French alone: neither '^' nor 'ê' is typed as a key.
    let mut h = Harness::with(vec![fake::fr()], FR);
    h.game_text("^ê");
    h.run();
    assert_eq!(h.world().unicode(), "^ê");
    assert!(h.world().keyboard_reports().is_empty());
}

#[test]
fn altgr_is_left_ctrl_and_right_alt() {
    let mut h = Harness::with(vec![fake::de()], DE);
    h.game_text("@z");
    h.run();
    assert_eq!(
        h.world().keyboard_reports(),
        [
            (0, LCTRL | RALT, vec![]),
            (10, LCTRL | RALT, vec![Q]),
            (40, LCTRL | RALT, vec![]),
            (60, 0, vec![]),
            (70, 0, vec![Y]),
            (100, 0, vec![]),
        ]
    );
}

#[test]
fn mixed_text_switches_the_layout_once_and_keeps_its_order() {
    let mut h = Harness::new();
    h.game_text("hi привет");
    h.run();
    {
        let w = h.world();
        assert_eq!(w.unicode(), "");
        assert_eq!(w.usages(), [H, I, SPACE, G, H, B, D, T, N]);
        // The switch is asked for after the space went up, and confirmed by the next poll after the
        // window took it (15 ms): «п» goes down at 170.
        assert_eq!(w.requests(), [(150, RU)]);
        assert_eq!(w.key_downs()[3], (170, 0, G));
        assert_eq!(w.focused, RU, "left switched, as a person would");
    }
    // The next message needs Latin again: back to the most recently used layout that types it.
    let t = h.run();
    h.at(t + 100);
    h.game_text("ok");
    h.run();
    let w = h.world();
    assert_eq!(w.requests().last().map(|r| r.1), Some(US));
    assert_eq!(w.usages()[9..], [O, K]);
    assert_eq!(w.focused, US);
}

#[test]
fn a_window_that_ignores_the_request_gets_the_language_hotkey() {
    let mut h = Harness::new();
    h.world().takes_request = false;
    h.game_text("да");
    h.run();
    {
        let w = h.world();
        assert_eq!(w.requests(), [(0, RU)]);
        // Nothing changed within SWITCH_CONFIRM: Alt+Shift, alone, pressed and released.
        let hotkey: Vec<_> = w
            .keyboard_reports()
            .into_iter()
            .filter(|(_, _, keys)| keys.is_empty())
            .take(4)
            .collect();
        assert_eq!(
            hotkey,
            [
                (300, LALT, vec![]),
                (310, LALT | LSHIFT, vec![]),
                (340, LALT, vec![]),
                (350, 0, vec![]),
            ]
        );
        assert_eq!(w.key_downs(), [(360, 0, L), (410, 0, F)]);
        assert_eq!(w.unicode(), "");
    }
    // This window ignored the request once: the next switch goes straight to the hotkey.
    let t = h.run();
    h.at(t + 100);
    h.game_text("ok");
    h.run();
    let w = h.world();
    assert_eq!(
        w.requests().len(),
        1,
        "no second request to the same window"
    );
    assert_eq!(w.focused, US);
    assert_eq!(w.usages()[2..], [O, K]);
}

#[test]
fn when_no_switch_works_the_character_goes_by_unicode_in_its_place() {
    let mut h = Harness::new();
    {
        let mut w = h.world();
        w.takes_request = false;
        w.hotkey_works = false;
    }
    h.game_text("aдд b");
    h.run();
    let w = h.world();
    assert_eq!(w.unicode(), "дд");
    assert_eq!(
        w.usages(),
        [A, SPACE, B],
        "Latin still typed as keys, in order"
    );
    assert_eq!(w.requests().len(), 1, "one try per message for a layout");
    assert_eq!(
        w.count(
            |o| matches!(o, Out::Report(r) if fake::keyboard(r) == Some((LALT | LSHIFT, vec![])))
        ),
        1,
        "one hotkey press"
    );
    // The first «д» waited out the request (300 ms) and the hotkey (300 ms more).
    let first = w
        .log
        .iter()
        .find(|(_, o)| is_unicode(o))
        .map(|(at, _)| fake::ms(*at))
        .unwrap();
    assert_eq!(first, 50 + 300 + 50 + 300);
    drop(w);

    // No hotkey set: after the request times out, straight to Unicode.
    let mut h = Harness::new();
    {
        let mut w = h.world();
        w.takes_request = false;
        w.hotkey = LanguageHotkey::Off;
    }
    h.game_text("д");
    h.run();
    assert_eq!(h.world().unicode(), "д");
    assert!(h.world().keyboard_reports().is_empty());
    assert_eq!(
        h.world().last_at(is_unicode),
        Some(300),
        "SWITCH_CONFIRM, then Unicode"
    );

    // A refused request (an administrator window) goes to the hotkey at once.
    let mut h = Harness::new();
    h.world().request_refused = true;
    h.game_text("д");
    h.run();
    assert_eq!(h.world().key_downs(), [(60, 0, L)]);
}

#[test]
fn the_enter_after_a_line_waits_for_it_and_moves_wait_only_behind_a_key() {
    let mut h = Harness::new();
    h.game_text("ab");
    h.at(20);
    // Only text waits: the move goes at once, between typed keys.
    h.inject(rel()).unwrap();
    h.at(45);
    h.key("Enter", true).unwrap();
    h.key("Enter", false).unwrap();
    h.at(60);
    // Now a key waits: the move waits behind it.
    h.inject(rel()).unwrap();
    h.run();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [
            (0, 0, vec![A]),
            (30, 0, vec![]),
            (50, 0, vec![B]),
            (80, 0, vec![]),
            // The line is done at 100; the Enter follows, held its minimum.
            (100, 0, vec![ENTER]),
            (130, 0, vec![]),
        ]
    );
    let moves: Vec<_> = w
        .log
        .iter()
        .filter(|(_, o)| is_mouse(o))
        .map(|(at, _)| fake::ms(*at))
        .collect();
    // The second move came 15 ms after the Enter: it keeps that gap after the Enter went.
    assert_eq!(moves, [20, 145]);
}

#[test]
fn further_text_waits_behind_game_text() {
    let mut h = Harness::new();
    h.game_text("ab");
    h.at(1);
    h.inject(InputMessage::Text {
        text: "x".into(),
        game: None,
    })
    .unwrap();
    h.game_text("c");
    h.run();
    let w = h.world();
    assert_eq!(w.unicode(), "x");
    assert_eq!(w.last_at(is_unicode), Some(100), "after 'b', in its turn");
    assert_eq!(w.key_downs().last(), Some(&(100, 0, C)));
}

#[test]
fn release_all_mid_text_drops_the_rest() {
    let mut h = Harness::new();
    h.game_text("abcdef");
    h.at(1);
    h.key("Enter", true).unwrap();
    h.key("Enter", false).unwrap();
    h.at(60);
    h.release_all();
    h.run();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [
            (0, 0, vec![A]),
            (30, 0, vec![]),
            (50, 0, vec![B]),
            (60, 0, vec![]),
        ],
        "'b' released by the neutral report; nothing after it, no Enter"
    );
    assert_eq!(w.count(|o| matches!(o, Out::SendInputRelease)), 1);
    assert!(!h.rt.typist.has_work());
}

#[test]
fn a_failed_write_mid_text_stops_typing_without_a_replay() {
    let mut h = Harness::new();
    h.world().failures.extend([false, false, true]);
    h.game_text("abc");
    h.at(1);
    h.key("Enter", true).unwrap();
    h.run();
    {
        let w = h.world();
        assert_eq!(
            w.keyboard_reports(),
            [
                (0, 0, vec![A]),
                (30, 0, vec![]),
                (50, 0, vec![B]),
                (50, 0, vec![]),
            ],
            "the failed 'b' is never replayed; the neutral cleanup follows at once"
        );
        assert_eq!(w.count(|o| matches!(o, Out::SendInputRelease)), 1);
    }
    assert!(!h.rt.broken && !h.rt.state.failed, "the cleanup worked");

    // The cleanup failing too: the device is unusable, and later game text goes by Unicode.
    let mut h = Harness::new();
    h.world().failures.extend([true, true]);
    h.game_text("ab");
    h.run();
    assert!(h.rt.broken);
    h.game_text("cd");
    assert_eq!(h.world().unicode(), "cd");
    assert!(!h.rt.typist.has_work());
}

#[test]
fn the_emulated_repeat_is_stopped_once_per_message() {
    let mut h = Harness::new();
    h.game_text("abc");
    h.run();
    assert_eq!(h.world().repeat_stops, 1);
    h.game_text("de");
    h.run();
    assert_eq!(h.world().repeat_stops, 2);
    // A message sent whole by Unicode presses nothing through the driver.
    h.world().sendinput_mods = LCTRL;
    h.game_text("fg");
    h.run();
    assert_eq!(h.world().repeat_stops, 2);
}

#[test]
fn a_secure_desktop_mid_line_gets_nothing_not_even_the_queued_enter() {
    // The worker looks at the desktop afresh before every step: no cache lets a key through.
    for target in [Target::Blocked, Target::Unknown] {
        let mut h = Harness::new();
        h.game_text("abcdef");
        h.at(1);
        h.key("Enter", true).unwrap();
        h.key("Enter", false).unwrap();
        h.at(60);
        h.world().target = target;
        h.run();
        let w = h.world();
        assert_eq!(
            w.keyboard_reports(),
            [
                (0, 0, vec![A]),
                (30, 0, vec![]),
                (50, 0, vec![B]),
                // 'b' was down: released at once, so it cannot repeat into the prompt. Nothing
                // after that: no more letters, and no Enter to confirm anything.
                (60, 0, vec![]),
            ],
            "{target:?}"
        );
        assert_eq!(w.count(|o| matches!(o, Out::SendInputRelease)), 1);
        assert_eq!(w.unicode(), "", "nothing by Unicode either");
        drop(w);
        assert!(!h.rt.typist.has_work());
    }

    // The flip between the step's look and the report's own: the report is refused all the same.
    let mut h = Harness::new();
    h.game_text("abc");
    h.at(1);
    h.key("Enter", true).unwrap();
    h.at(40);
    // At 50 the step looks (allowed), then the report for 'b' looks: blocked by then.
    let looks = h.world().target_looks;
    h.world().flip_at_look = Some((looks + 2, Target::Blocked));
    h.run();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [(0, 0, vec![A]), (30, 0, vec![])],
        "'b' is never written, nor the Enter"
    );
    assert_eq!(w.unicode(), "");
    assert_eq!(w.count(|o| matches!(o, Out::SendInputRelease)), 1);
}

/// Game-only mode: the worker types into the game's window only. Another window taking the front
/// mid-line gets nothing — not the rest of the line, not the queued Enter — and what the typing held
/// is released; with the game's window not shown nothing queued goes at all. Outside the mode the
/// foreground window does not matter, as before.
#[test]
fn in_game_only_mode_queued_text_goes_only_while_the_game_has_the_front() {
    use super::super::QueueGate;
    const GAME: usize = 0x40666;
    const NOTEPAD: usize = 0x20;

    let mut h = Harness::new();
    h.world().foreground = GAME;
    h.rt.confine_to(QueueGate::Game(GAME));
    h.game_text("abcdef");
    h.at(1);
    h.key("Enter", true).unwrap();
    h.key("Enter", false).unwrap();
    h.at(60);
    h.world().foreground = NOTEPAD;
    h.run();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [
            (0, 0, vec![A]),
            (30, 0, vec![]),
            (50, 0, vec![B]),
            // The worker's next look sees Notepad in front: 'b' comes up at once by the neutral
            // report, and nothing after it goes.
            (60, 0, vec![]),
        ]
    );
    assert_eq!(w.count(|o| matches!(o, Out::SendInputRelease)), 1);
    assert_eq!(w.unicode(), "", "nothing by Unicode either");
    drop(w);
    assert!(!h.rt.typist.has_work());

    // The game's window not shown: nowhere.
    let mut h = Harness::new();
    h.rt.confine_to(QueueGate::Closed);
    h.game_text("ab");
    h.run();
    assert!(h.world().keyboard_reports().is_empty());
    assert_eq!(h.world().unicode(), "");
    assert!(!h.rt.typist.has_work());

    // Back in front: typed.
    let mut h = Harness::new();
    h.world().foreground = GAME;
    h.rt.confine_to(QueueGate::Game(GAME));
    h.game_text("ab");
    h.run();
    assert_eq!(h.world().usages(), vec![A, B]);

    // Outside the mode, as before: whatever window has the front.
    let mut h = Harness::new();
    h.world().foreground = NOTEPAD;
    h.game_text("ab");
    h.run();
    assert_eq!(h.world().usages(), vec![A, B]);
}

#[test]
fn game_text_goes_by_unicode_at_once_where_hid_may_not_go() {
    let mut h = Harness::new();
    h.world().target = Target::Blocked;
    h.game_text("hi");
    assert!(!h.rt.typist.has_work(), "nothing queued");
    let w = h.world();
    assert_eq!(w.unicode(), "hi");
    assert!(
        w.log.iter().any(|(_, o)| matches!(
            o,
            Out::SendInput(InputMessage::Text {
                game: Some(true),
                ..
            })
        )),
        "today's path, the message as it came"
    );
    drop(w);

    // Text not marked game keeps today's path with the device open.
    let mut h = Harness::new();
    h.inject(InputMessage::Text {
        text: "hi\n".into(),
        game: None,
    })
    .unwrap();
    assert_eq!(h.world().unicode(), "hi\n", "not normalised either");
    assert!(!h.rt.typist.has_work());
}

#[test]
fn a_newline_alone_types_nothing() {
    let mut h = Harness::new();
    h.game_text("\n");
    assert!(!h.rt.typist.has_work());
    h.run();
    assert!(h.world().log.is_empty());
}

#[test]
fn a_quick_tap_is_held_for_the_minimum_and_keeps_its_order() {
    let mut h = Harness::new();
    h.key("Enter", true).unwrap();
    h.at(2);
    h.key("Enter", false).unwrap();
    h.at(5);
    h.key("KeyA", true).unwrap();
    h.inject(rel()).unwrap();
    h.run();
    {
        let w = h.world();
        assert_eq!(
            w.keyboard_reports(),
            [(0, 0, vec![ENTER]), (30, 0, vec![]), (33, 0, vec![A])],
            "the release waits until the key was down 30 ms; the next key waits behind it, 3 ms \
             after it as it came"
        );
        assert_eq!(
            w.last_at(is_mouse),
            Some(33),
            "the move waits behind the release too"
        );
    }
    assert_eq!(h.rt.tap_deferrals, 1);
    // A key held longer is released at once.
    h.at(80);
    h.key("KeyA", false).unwrap();
    assert_eq!(h.world().keyboard_reports().last(), Some(&(80, 0, vec![])));
    assert_eq!(h.rt.tap_deferrals, 1);

    // `ra` while a release waits: everything is released now, and nothing waits any more.
    h.at(200);
    h.key("Space", true).unwrap();
    h.at(201);
    h.key("Space", false).unwrap();
    h.at(205);
    h.release_all();
    assert!(!h.rt.typist.has_work());
    h.at(300);
    assert_eq!(
        h.world().keyboard_reports()[4..],
        [(200, 0, vec![SPACE]), (205, 0, vec![])]
    );
}

/// The line for taps held to the minimum names the viewer's own keys (`k.src`), counts its
/// keyboard's keys and the buttons, and says the shortest hold the viewer gave one — never a key of
/// its keyboard by name.
#[test]
fn the_tap_line_names_our_keys_counts_the_rest_and_says_the_shortest_hold() {
    use afklink_protocol::KeySource;
    let log = logged(|| {
        let mut h = Harness::new();
        h.key_from("F1", true, Some(KeySource::Cell)).unwrap();
        h.at(4);
        h.key_from("F1", false, Some(KeySource::Cell)).unwrap();
        // Behind the waiting release: a tap of the viewer's own keyboard, and a click.
        h.at(5);
        h.key("KeyX", true).unwrap();
        h.at(6);
        h.key("KeyX", false).unwrap();
        h.at(7);
        h.button(0, true).unwrap();
        h.at(8);
        h.button(0, false).unwrap();
        h.run();
    });
    let line = log
        .lines()
        .find(|l| l.contains("short taps held to the minimum"))
        .unwrap_or_else(|| panic!("no tap line:\n{log}"));
    assert!(line.contains("tap_deferrals=3"), "{line}");
    assert!(line.contains("tap_keys=F1 "), "{line}");
    assert!(line.contains("tap_keys_other=1"), "{line}");
    assert!(line.contains("tap_buttons=1"), "{line}");
    let shortest: u64 = line
        .split("tap_shortest_ms=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no shortest hold: {line}"));
    assert!(shortest <= 4, "{line}");
    assert!(
        !log.contains("KeyX"),
        "a key of the viewer's keyboard named:\n{log}"
    );
}

#[test]
fn a_queue_that_cannot_wait_is_sent_at_once_in_order() {
    let mut h = Harness::new();
    h.game_text("Abc");
    h.at(1);
    // Shift is down for 'A': the wheel is held for it; the Enter queues.
    h.inject(wheel(true)).unwrap();
    h.key("Enter", true).unwrap();
    h.at(20);
    let now = h.now;
    h.rt.flush_unpaced(now, "test");
    assert!(!h.rt.typist.has_work());
    assert_eq!(
        mouse_timeline(&h),
        line(&[(30, "w+mods00")]),
        "the wheel goes after the Shift, before the Enter"
    );
    let w = h.world();
    assert_eq!(
        w.unicode(),
        "bc",
        "'A' was down: released and counted as typed"
    );
    let restore = w
        .log
        .iter()
        .position(|(_, o)| matches!(o, Out::Report(r) if fake::keyboard(r) == Some((0, vec![]))))
        .unwrap();
    let unicode = w.log.iter().position(|(_, o)| is_unicode(o)).unwrap();
    let enter = w
        .log
        .iter()
        .position(
            |(_, o)| matches!(o, Out::Report(r) if fake::keyboard(r) == Some((0, vec![ENTER]))),
        )
        .unwrap();
    assert!(restore < unicode && unicode < enter, "in order");
    assert_eq!(
        fake::ms(w.log[unicode].0) - fake::ms(w.log[restore].0),
        10,
        "the Unicode rest waits MODIFIER_LEAD after the modifiers went up"
    );
}

#[test]
fn text_over_the_queue_limit_goes_by_unicode_in_its_turn() {
    let mut h = Harness::new();
    h.game_text("ab");
    let long = "x".repeat(MAX_QUEUED_CHARS);
    h.game_text(&long);
    h.run();
    let w = h.world();
    assert_eq!(w.usages(), [A, B]);
    assert_eq!(w.unicode(), long);
    assert_eq!(w.last_at(is_unicode), Some(100), "after 'ab', in its turn");
}

/// A writer the log-capture test reads back.
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

/// Everything logged, at every level (trace included), while `f` runs on this thread — without
/// timestamps, so two runs compare line for line.
fn logged(f: impl FnOnce()) -> String {
    let capture = Capture::default();
    let writer = capture.clone();
    let ours = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish(),
    );
    // While only one dispatcher exists, tracing asks the registering thread's own default whether a
    // callsite is wanted: a line first reached on another test's thread (which has none) would be
    // cached as unwanted, and missing here. A second live dispatcher — nobody's default, it receives
    // nothing — makes tracing ask every live dispatcher instead.
    let _second = tracing::Dispatch::new(tracing_subscriber::registry());
    tracing::dispatcher::with_default(&ours, f);
    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    log
}

/// Nothing per character or per report reaches the log: the pattern of capitals, AltGr and
/// switches would be the shape of a password.
fn assert_no_per_character_trace(log: &str) {
    for leak in ["index=", "modifiers=", "key_down", "keyboard report"] {
        assert!(!log.contains(leak), "{leak:?} in the log:\n{log}");
    }
}

#[test]
fn typed_text_never_reaches_the_log() {
    let log = logged(|| {
        let mut h = Harness::new();
        // The window ignores the request, so every switch line and the hotkey are logged too.
        h.world().takes_request = false;
        h.game_text("секрет 🙂");
        h.key("Enter", true).unwrap();
        h.key("Enter", false).unwrap();
        let t = h.run();
        h.game_text("пароль");
        h.at(t + 45);
        h.release_all();
        h.run();
    });
    assert!(
        log.contains("game text typed") && log.contains("keyboard layout switched"),
        "the capture works:\n{log}"
    );
    for c in "секрет🙂пароль".chars() {
        assert!(!log.contains(c), "{c:?} reached the log:\n{log}");
    }
    assert!(
        !log.contains("\\u{"),
        "no escaped characters either:\n{log}"
    );
    assert_no_per_character_trace(&log);
}

#[test]
fn a_passwords_capitals_and_altgr_leave_no_trace_in_the_log() {
    // Two ASCII passwords of one length whose capitals, Shift symbols and AltGr sit in different
    // places: at every level, trace included, their logs are the same line for line.
    let type_on_german = |text: &'static str| {
        logged(move || {
            let mut h = Harness::with(vec![fake::de()], DE);
            h.game_text(text);
            h.run();
        })
    };
    let one = type_on_german("Pa$w0rd@Ex1");
    let other = type_on_german("p@A$W0RdeX1");
    assert!(one.contains("game text typed"), "the capture works:\n{one}");
    assert_no_per_character_trace(&one);
    assert_eq!(one, other, "the log shows the text's shape");
}

#[test]
fn every_report_typing_writes_is_a_keyboard_report() {
    // Typing never touches the mouse or the media keys, and ends where it began.
    let mut h = Harness::new();
    h.game_text("Hi, мир!");
    h.run();
    let w = h.world();
    assert!(w
        .log
        .iter()
        .all(|(_, o)| is_keyboard(o) || matches!(o, Out::Request(_))));
    assert_eq!(
        w.keyboard_reports().last().map(|r| (r.1, r.2.len())),
        Some((0, 0))
    );
    assert!(!h.rt.state.held.dirty_keyboard);
}

// Moves, clicks and the wheel around typing (review finding 1).

#[test]
fn a_tap_during_typing_lands_where_the_pointer_was_before_the_move_after_it() {
    let mut h = Harness::new();
    h.game_text("abc");
    h.at(10);
    h.button(0, true).unwrap();
    h.at(12);
    h.button(0, false).unwrap();
    h.at(15);
    h.inject(rel()).unwrap();
    assert!(
        h.world().mouse_reports().is_empty(),
        "the move waits behind the click"
    );
    h.run();
    // The line ends at 150; the click goes, held its minimum; then the move, 3 ms after the
    // release as it came.
    assert_eq!(
        mouse_timeline(&h),
        line(&[(150, "b1"), (180, "b0"), (183, "r")])
    );
}

#[test]
fn a_queued_button_release_is_not_outrun_by_a_drag() {
    let mut h = Harness::new();
    h.button(2, true).unwrap();
    h.at(5);
    h.game_text("ab");
    h.at(20);
    h.button(2, false).unwrap();
    h.at(25);
    h.inject(rel()).unwrap();
    h.at(30);
    h.inject(rel()).unwrap();
    h.run();
    // The right button (HID bit 2) comes up when the line is done, and only then do the moves go:
    // no camera turn with the button still down.
    assert_eq!(
        mouse_timeline(&h),
        line(&[(0, "b2"), (105, "b0"), (110, "r"), (115, "r")])
    );
}

#[test]
fn a_wheel_during_a_capital_waits_for_the_shift_to_go_up() {
    let mut h = Harness::new();
    h.game_text("AB");
    h.at(15);
    // 'A' is down with Shift: a game wheel and a desktop wheel come.
    h.inject(wheel(true)).unwrap();
    h.inject(wheel(false)).unwrap();
    h.run();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [
            (0, LSHIFT, vec![]),
            (10, LSHIFT, vec![A]),
            (40, LSHIFT, vec![]),
            // At the next character the typing lets Shift up for the wheels…
            (60, 0, vec![]),
            // …and presses it again MODIFIER_LEAD ahead of 'B'.
            (70, LSHIFT, vec![]),
            (80, LSHIFT, vec![B]),
            (110, LSHIFT, vec![]),
            (130, 0, vec![]),
        ]
    );
    drop(w);
    assert_eq!(
        mouse_timeline(&h),
        line(&[(60, "w+mods00")]),
        "the game wheel turns with no modifier down"
    );
    let w = h.world();
    let shift_up = w
        .log
        .iter()
        .position(|(at, o)| fake::ms(*at) == 60 && is_keyboard(o))
        .unwrap();
    let desktop_wheel = w
        .log
        .iter()
        .position(|(_, o)| matches!(o, Out::SendInput(InputMessage::Wheel { .. })))
        .unwrap();
    assert!(
        shift_up < desktop_wheel,
        "the desktop wheel, by SendInput, waits too"
    );
}

// Queued input keeps its timing (review finding 2).

#[test]
fn a_queued_tap_keeps_its_length() {
    let mut h = Harness::new();
    h.game_text("ab");
    h.at(10);
    h.button(0, true).unwrap();
    h.at(90);
    h.button(0, false).unwrap();
    h.run();
    assert_eq!(
        mouse_timeline(&h),
        line(&[(100, "b1"), (180, "b0")]),
        "held 80 ms, as it was"
    );

    // Released 2 ms after the press: replayed 2 ms apart, then held to the minimum.
    let mut h = Harness::new();
    h.game_text("ab");
    h.at(10);
    h.button(0, true).unwrap();
    h.at(12);
    h.button(0, false).unwrap();
    h.run();
    assert_eq!(mouse_timeline(&h), line(&[(100, "b1"), (130, "b0")]));
}

#[test]
fn a_key_held_while_a_line_was_typed_is_replayed_held_as_long_capped() {
    // 25 characters: the line takes 1250 ms. W held 900 ms meanwhile.
    let mut h = Harness::new();
    h.game_text("abcdefghijabcdefghijabcde");
    h.at(10);
    h.key("KeyW", true).unwrap();
    h.at(910);
    h.key("KeyW", false).unwrap();
    h.run();
    let w = h.world();
    let with_w: Vec<_> = w
        .keyboard_reports()
        .into_iter()
        .filter(|(_, _, keys)| keys.contains(&W))
        .collect();
    assert_eq!(with_w, [(1250, 0, vec![W])]);
    assert_eq!(w.keyboard_reports().last(), Some(&(2150, 0, vec![])));
    drop(w);

    // Q held 1.8 s while a 2-second line was typed: replayed held MAX_REPLAY_GAP.
    let mut h = Harness::new();
    h.game_text(&"abcdefghij".repeat(4));
    h.at(10);
    h.key("KeyQ", true).unwrap();
    h.at(1810);
    h.key("KeyQ", false).unwrap();
    h.run();
    let reports = h.world().keyboard_reports();
    assert!(reports.contains(&(2000, 0, vec![Q])));
    assert_eq!(reports.last(), Some(&(3000, 0, vec![])));
}

#[test]
fn a_quick_click_is_held_for_the_minimum_and_a_move_waits_behind_it() {
    let mut h = Harness::new();
    h.button(0, true).unwrap();
    h.at(3);
    h.button(0, false).unwrap();
    h.at(10);
    h.inject(rel()).unwrap();
    h.run();
    assert_eq!(
        mouse_timeline(&h),
        line(&[(0, "b1"), (30, "b0"), (37, "r")])
    );
    assert_eq!(h.rt.tap_deferrals, 1);
    // A click held longer is released at once.
    h.at(100);
    h.button(0, true).unwrap();
    h.at(150);
    h.button(0, false).unwrap();
    assert_eq!(mouse_timeline(&h).last(), Some(&(150, "b0".to_owned())));
    assert_eq!(h.rt.tap_deferrals, 1);
}

// Caps Lock (review finding 4).

#[test]
fn a_caps_lock_press_the_worker_sent_counts_for_the_next_message() {
    for window_read_it in [false, true] {
        let mut h = Harness::new();
        h.world().caps_follows_key = window_read_it;
        h.game_text("a");
        h.at(1);
        h.key("CapsLock", true).unwrap();
        h.at(2);
        h.key("CapsLock", false).unwrap();
        h.at(3);
        h.game_text("b");
        h.run();
        let downs = h.world().key_downs();
        // 'a' before the press, lowercase; Caps Lock down at 50, up at 80 (its minimum hold);
        // then 'b' with Caps Lock on: lowercase needs Shift.
        assert_eq!(
            downs,
            [(0, 0, A), (50, 0, 0x39), (90, LSHIFT, B)],
            "window read it: {window_read_it}"
        );
    }
}

// The language hotkey (review finding 7).

#[test]
fn the_grave_accent_hotkey_is_never_pressed() {
    let mut h = Harness::new();
    {
        let mut w = h.world();
        w.takes_request = false;
        w.hotkey = LanguageHotkey::Grave;
    }
    h.game_text("д");
    h.run();
    let w = h.world();
    assert!(
        w.keyboard_reports().is_empty(),
        "no grave key, no report at all"
    );
    assert_eq!(w.unicode(), "д");
    assert_eq!(
        w.last_at(is_unicode),
        Some(300),
        "the request's wait, then Unicode"
    );
}

#[test]
fn a_window_where_the_hotkey_changed_nothing_gets_unicode_straight_away() {
    let mut h = Harness::new();
    {
        let mut w = h.world();
        w.takes_request = false;
        w.hotkey_works = false;
    }
    h.game_text("д");
    let t = h.run();
    assert_eq!(t, 670);
    assert_eq!(h.world().last_at(is_unicode), Some(650));
    h.at(800);
    h.game_text("д");
    h.run();
    let w = h.world();
    assert_eq!(w.unicode(), "дд");
    assert_eq!(
        w.last_at(is_unicode),
        Some(800),
        "no request, no hotkey: at once"
    );
    assert_eq!(w.requests().len(), 1);
    assert_eq!(
        w.count(
            |o| matches!(o, Out::Report(r) if fake::keyboard(r) == Some((LALT | LSHIFT, vec![])))
        ),
        1,
        "the hotkey was pressed once, in the first message only"
    );
}

#[test]
fn another_layout_of_the_same_language_is_out_of_the_hotkeys_reach() {
    let mut h = Harness::with(vec![fake::us(), fake::us_intl()], US);
    h.world().takes_request = false;
    h.game_text("£");
    h.run();
    let w = h.world();
    assert_eq!(w.requests(), [(0, US_INTL)]);
    assert!(
        w.keyboard_reports().is_empty(),
        "no Alt+Shift: it switches languages"
    );
    assert_eq!(w.unicode(), "£");
    drop(w);

    // The request itself can reach it.
    let mut h = Harness::with(vec![fake::us(), fake::us_intl()], US);
    h.game_text("£");
    h.run();
    let w = h.world();
    assert_eq!(w.unicode(), "");
    assert_eq!(w.key_downs(), [(30, LCTRL | RALT, 0x20)]);
}

#[test]
fn characters_needing_a_layout_that_failed_to_switch_count_as_switch_failures() {
    let log = logged(|| {
        let mut h = Harness::new();
        {
            let mut w = h.world();
            w.takes_request = false;
            w.hotkey_works = false;
        }
        h.game_text("дд");
        h.run();
    });
    assert!(
        log.contains("switch_failed=2") && log.contains("unproducible=0"),
        "{log}"
    );
}

// The router without game text: as before (review finding 9).

#[test]
fn keys_buttons_moves_and_wheels_route_as_before() {
    let mut h = Harness::new();
    h.key("KeyW", true).unwrap();
    h.at(50);
    h.key("KeyW", false).unwrap();
    h.at(60);
    h.button(0, true).unwrap();
    h.at(100);
    h.button(0, false).unwrap();
    h.at(110);
    h.inject(rel()).unwrap();
    h.at(120);
    h.inject(wheel(true)).unwrap();
    h.at(130);
    h.inject(wheel(false)).unwrap();
    h.inject(InputMessage::Move { x: 0.5, y: 0.5 }).unwrap();
    h.inject(InputMessage::Text {
        text: "hi".into(),
        game: None,
    })
    .unwrap();
    assert!(h
        .inject(InputMessage::Combo {
            name: "ctrl_alt_del".into()
        })
        .is_err());
    h.key("F13", true).unwrap();
    h.key("F13", false).unwrap();
    assert!(!h.rt.typist.has_work(), "nothing ever waited");
    let w = h.world();
    assert_eq!(w.keyboard_reports(), [(0, 0, vec![W]), (50, 0, vec![])]);
    drop(w);
    // The absolute position goes as the absolute report.
    assert_eq!(
        mouse_timeline(&h),
        line(&[
            (60, "b1"),
            (100, "b0"),
            (110, "r"),
            (120, "w+mods00"),
            (130, "a")
        ])
    );
    let w = h.world();
    let sent: Vec<&str> = w
        .log
        .iter()
        .filter_map(|(_, o)| match o {
            Out::SendInput(InputMessage::Wheel { .. }) => Some("w"),
            Out::SendInput(InputMessage::Move { .. }) => Some("m"),
            Out::SendInput(InputMessage::Text { .. }) => Some("text"),
            Out::SendInput(InputMessage::Key { d: 1, .. }) => Some("F13 down"),
            Out::SendInput(InputMessage::Key { d: 0, .. }) => Some("F13 up"),
            _ => None,
        })
        .collect();
    assert_eq!(sent, ["w", "text", "F13 down", "F13 up"]);
}

#[test]
fn the_seventh_key_goes_by_sendinput_and_is_released_there() {
    let mut h = Harness::new();
    for code in ["KeyQ", "KeyW", "KeyE", "KeyR", "KeyT", "KeyY"] {
        h.key(code, true).unwrap();
    }
    h.key("KeyU", true).unwrap();
    h.at(100);
    h.key("KeyU", false).unwrap();
    let w = h.world();
    assert_eq!(w.keyboard_reports().len(), 6, "six keys on HID");
    let by_sendinput =
        w.count(|o| matches!(o, Out::SendInput(InputMessage::Key { code, .. }) if code == "KeyU"));
    assert_eq!(by_sendinput, 2, "the seventh, down and up, by SendInput");
}

#[test]
fn a_blocked_desktop_sends_presses_by_sendinput_and_releases_what_hid_held() {
    let mut h = Harness::new();
    h.key("KeyW", true).unwrap();
    h.world().target = Target::Blocked;
    // The desktop is looked at again once the cached look is 100 ms old.
    h.at(150);
    h.key("KeyA", true).unwrap();
    h.inject(rel()).unwrap();
    h.key("KeyW", false).unwrap();
    let w = h.world();
    assert_eq!(
        w.keyboard_reports(),
        [(0, 0, vec![W]), (150, 0, vec![])],
        "W released on the way into the blocked desktop; nothing pressed there"
    );
    assert_eq!(w.count(|o| matches!(o, Out::SendInputRelease)), 1);
    let sent = w.count(|o| {
        matches!(
            o,
            Out::SendInput(InputMessage::Key { .. } | InputMessage::Rel { .. })
        )
    });
    assert_eq!(sent, 3, "A, the move and W's (stray) release, by SendInput");
}

#[test]
fn a_device_that_stops_taking_writes_leaves_everything_to_sendinput() {
    let mut h = Harness::new();
    h.world().failures.extend([true, true]);
    h.key("KeyW", true).unwrap_err();
    h.at(10);
    h.key("KeyA", true).unwrap();
    assert!(h.rt.broken);
    h.inject(rel()).unwrap();
    h.button(0, true).unwrap();
    let w = h.world();
    assert_eq!(
        w.count(|o| matches!(o, Out::Report(_))),
        2,
        "the failed W and the failed cleanup"
    );
    assert_eq!(
        w.count(|o| matches!(o, Out::SendInput(_))),
        3,
        "A, the move and the click by SendInput"
    );
}
