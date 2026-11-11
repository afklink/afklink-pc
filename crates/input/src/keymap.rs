//! `KeyboardEvent.code` -> Windows Virtual-Key mapping, and the hardware scan
//! code each key is injected with.
//!
//! [`code_to_vk`] returns `(virtual_key, is_extended)`. Extended keys set
//! `KEYEVENTF_EXTENDEDKEY` (right-hand modifiers, arrows/navigation cluster,
//! numpad divide/enter, etc.) so the OS distinguishes them from their numpad
//! or left-hand twins.
//!
//! [`key_stroke`] turns that pair into what one `KEYBDINPUT` carries. A key sent by its Virtual-Key
//! alone with `wScan = 0` is never seen by games reading the keyboard through DirectInput or raw
//! input: they read the scan code. So every key with a single-byte set-1 scan code goes
//! by it (`KEYEVENTF_SCANCODE`, plus `KEYEVENTF_EXTENDEDKEY` for the `E0`-prefixed ones), and
//! Windows derives the Virtual-Key from it the way it does for a real keyboard.
//!
//! The scan code comes from a table ([`vk_to_scan`]), not from `MapVirtualKeyW`: the viewer's
//! `code` is a physical key position and [`code_to_vk`] names it by its US-layout Virtual-Key, so
//! the US table gives back that same physical key on any PC layout, where `MapVirtualKeyW` would go
//! through the PC's current layout (on AZERTY, `VK_A` is the key where QWERTY has Q). It is also
//! plain data, so it is tested without a keyboard.

/// Map a `KeyboardEvent.code` to `(VK, extended)`.
pub fn code_to_vk(code: &str) -> Option<(u16, bool)> {
    // Letters: KeyA..KeyZ -> 0x41..0x5A ('A'..'Z').
    if let Some(rest) = code.strip_prefix("Key") {
        if rest.len() == 1 {
            let c = rest.as_bytes()[0];
            if c.is_ascii_uppercase() {
                return Some((c as u16, false));
            }
        }
    }
    // Top-row digits: Digit0..Digit9 -> 0x30..0x39.
    if let Some(rest) = code.strip_prefix("Digit") {
        if rest.len() == 1 {
            let c = rest.as_bytes()[0];
            if c.is_ascii_digit() {
                return Some((c as u16, false));
            }
        }
    }
    // Function keys: F1..F24 -> 0x70.. .
    if let Some(rest) = code.strip_prefix('F') {
        if let Ok(n) = rest.parse::<u16>() {
            if (1..=24).contains(&n) {
                return Some((0x70 + (n - 1), false));
            }
        }
    }
    // Numpad digits: Numpad0..Numpad9 -> 0x60..0x69.
    if let Some(rest) = code.strip_prefix("Numpad") {
        if rest.len() == 1 {
            let c = rest.as_bytes()[0];
            if c.is_ascii_digit() {
                return Some((0x60 + (c - b'0') as u16, false));
            }
        }
    }

    let mapped: (u16, bool) = match code {
        // Whitespace / editing.
        "Enter" => (0x0D, false),
        "NumpadEnter" => (0x0D, true),
        "Escape" => (0x1B, false),
        "Backspace" => (0x08, false),
        "Tab" => (0x09, false),
        "Space" => (0x20, false),
        "CapsLock" => (0x14, false),

        // Modifiers.
        "ShiftLeft" => (0xA0, false),
        "ShiftRight" => (0xA1, false),
        "ControlLeft" => (0xA2, false),
        "ControlRight" => (0xA3, true),
        "AltLeft" => (0xA4, false),
        "AltRight" => (0xA5, true),
        "MetaLeft" | "OSLeft" => (0x5B, true),
        "MetaRight" | "OSRight" => (0x5C, true),
        "ContextMenu" => (0x5D, true),

        // Arrows (extended).
        "ArrowLeft" => (0x25, true),
        "ArrowUp" => (0x26, true),
        "ArrowRight" => (0x27, true),
        "ArrowDown" => (0x28, true),

        // Navigation cluster (extended).
        "Insert" => (0x2D, true),
        "Delete" => (0x2E, true),
        "Home" => (0x24, true),
        "End" => (0x23, true),
        "PageUp" => (0x21, true),
        "PageDown" => (0x22, true),

        // Punctuation / OEM keys (US layout).
        "Backquote" => (0xC0, false),
        "Minus" => (0xBD, false),
        "Equal" => (0xBB, false),
        "BracketLeft" => (0xDB, false),
        "BracketRight" => (0xDD, false),
        "Backslash" => (0xDC, false),
        "Semicolon" => (0xBA, false),
        "Quote" => (0xDE, false),
        "Comma" => (0xBC, false),
        "Period" => (0xBE, false),
        "Slash" => (0xBF, false),
        "IntlBackslash" => (0xE2, false),

        // Numpad operators.
        "NumpadAdd" => (0x6B, false),
        "NumpadSubtract" => (0x6D, false),
        "NumpadMultiply" => (0x6A, false),
        "NumpadDivide" => (0x6F, true),
        "NumpadDecimal" => (0x6E, false),
        "NumLock" => (0x90, true),

        // System keys.
        "PrintScreen" => (0x2C, true),
        "ScrollLock" => (0x91, false),
        "Pause" => (0x13, false),

        // Media / volume (best-effort).
        "AudioVolumeMute" => (0xAD, false),
        "AudioVolumeDown" => (0xAE, false),
        "AudioVolumeUp" => (0xAF, false),
        "MediaPlayPause" => (0xB3, false),
        "MediaStop" => (0xB2, false),
        "MediaTrackNext" => (0xB0, false),
        "MediaTrackPrevious" => (0xB1, false),

        _ => return None,
    };
    Some(mapped)
}

/// `KEYEVENTF_EXTENDEDKEY` (winuser.h). Plain bits, so [`key_stroke`] is built and tested anywhere.
pub const KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
/// `KEYEVENTF_KEYUP` (winuser.h).
pub const KEYEVENTF_KEYUP: u32 = 0x0002;
/// `KEYEVENTF_SCANCODE` (winuser.h): `wScan` names the key; Windows derives the Virtual-Key.
pub const KEYEVENTF_SCANCODE: u32 = 0x0008;

/// What one `KEYBDINPUT` carries for a key press or release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStroke {
    /// `wVk`. Ignored by Windows when `flags` has `KEYEVENTF_SCANCODE`; kept for the log.
    pub vk: u16,
    /// `wScan`: the set-1 make code (the low byte; `E0` is `KEYEVENTF_EXTENDEDKEY`), or 0.
    pub scan: u16,
    /// `dwFlags` bits.
    pub flags: u32,
}

impl KeyStroke {
    /// True when the key goes by its scan code (games see it), false when by Virtual-Key only.
    pub fn by_scan_code(&self) -> bool {
        self.flags & KEYEVENTF_SCANCODE != 0
    }
}

/// The `KEYBDINPUT` for pressing (`down`) or releasing a key [`code_to_vk`] mapped to `(vk,
/// extended)`: by its scan code where the key has a single-byte one, by Virtual-Key alone where it
/// has none (Pause, media keys).
pub fn key_stroke(vk: u16, extended: bool, down: bool) -> KeyStroke {
    let mut flags = 0;
    if extended {
        flags |= KEYEVENTF_EXTENDEDKEY;
    }
    if !down {
        flags |= KEYEVENTF_KEYUP;
    }
    match vk_to_scan(vk) {
        Some(scan) => KeyStroke {
            vk,
            scan,
            flags: flags | KEYEVENTF_SCANCODE,
        },
        None => KeyStroke { vk, scan: 0, flags },
    }
}

/// The set-1 scan code (make code, without the `E0` prefix) of the physical key a Virtual-Key names
/// on a US keyboard — the positions [`code_to_vk`] uses. `None` for keys with no single-byte code:
/// Pause (`E1 1D 45`) and the media keys, which go by Virtual-Key.
///
/// Where one scan code serves two keys, the extended flag tells them apart and [`code_to_vk`]
/// carries it: Enter / NumpadEnter (`1C`), Slash / NumpadDivide (`35`), the numpad digits and the
/// navigation cluster (`47`–`53`), left / right Ctrl (`1D`) and Alt (`38`).
pub fn vk_to_scan(vk: u16) -> Option<u16> {
    // Letters, by their US positions.
    const LETTERS: [u16; 26] = [
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, // A..M
        0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C, // N..Z
    ];
    // Numpad 0..9.
    const NUMPAD: [u16; 10] = [0x52, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49];
    // F13..F24.
    const F13_F24: [u16; 12] = [
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x76,
    ];
    let scan = match vk {
        0x41..=0x5A => LETTERS[usize::from(vk - 0x41)],
        // Top-row digits: 1..9 are 02..0A, 0 is 0B.
        0x31..=0x39 => vk - 0x31 + 0x02,
        0x30 => 0x0B,
        // F1..F10 are 3B..44; F11 and F12 were added later, at 57 and 58.
        0x70..=0x79 => vk - 0x70 + 0x3B,
        0x7A => 0x57,
        0x7B => 0x58,
        0x7C..=0x87 => F13_F24[usize::from(vk - 0x7C)],
        0x60..=0x69 => NUMPAD[usize::from(vk - 0x60)],

        0x1B => 0x01, // Escape
        0x08 => 0x0E, // Backspace
        0x09 => 0x0F, // Tab
        0x0D => 0x1C, // Enter (NumpadEnter with the extended flag)
        0x20 => 0x39, // Space
        0x14 => 0x3A, // CapsLock
        0x90 => 0x45, // NumLock (sent with the extended flag, as winuser.h's own example does)
        0x91 => 0x46, // ScrollLock
        0x2C => 0x37, // PrintScreen (extended)

        0xA0 => 0x2A,        // ShiftLeft
        0xA1 => 0x36,        // ShiftRight
        0xA2 | 0xA3 => 0x1D, // ControlLeft / ControlRight (extended)
        0xA4 | 0xA5 => 0x38, // AltLeft / AltRight (extended)
        0x5B => 0x5B,        // MetaLeft (extended)
        0x5C => 0x5C,        // MetaRight (extended)
        0x5D => 0x5D,        // ContextMenu (extended)

        // Navigation cluster and arrows (all extended).
        0x21 => 0x49, // PageUp
        0x22 => 0x51, // PageDown
        0x23 => 0x4F, // End
        0x24 => 0x47, // Home
        0x25 => 0x4B, // ArrowLeft
        0x26 => 0x48, // ArrowUp
        0x27 => 0x4D, // ArrowRight
        0x28 => 0x50, // ArrowDown
        0x2D => 0x52, // Insert
        0x2E => 0x53, // Delete

        // Punctuation, by US position.
        0xC0 => 0x29, // Backquote
        0xBD => 0x0C, // Minus
        0xBB => 0x0D, // Equal
        0xDB => 0x1A, // BracketLeft
        0xDD => 0x1B, // BracketRight
        0xDC => 0x2B, // Backslash
        0xBA => 0x27, // Semicolon
        0xDE => 0x28, // Quote
        0xBC => 0x33, // Comma
        0xBE => 0x34, // Period
        0xBF => 0x35, // Slash (NumpadDivide is 0x6F, extended)
        0xE2 => 0x56, // IntlBackslash

        // Numpad operators.
        0x6A => 0x37, // NumpadMultiply
        0x6D => 0x4A, // NumpadSubtract
        0x6B => 0x4E, // NumpadAdd
        0x6E => 0x53, // NumpadDecimal
        0x6F => 0x35, // NumpadDivide (extended)

        _ => return None,
    };
    Some(scan)
}

#[cfg(test)]
mod tests {
    use super::code_to_vk;

    #[test]
    fn letters_and_digits() {
        assert_eq!(code_to_vk("KeyA"), Some((0x41, false)));
        assert_eq!(code_to_vk("KeyZ"), Some((0x5A, false)));
        assert_eq!(code_to_vk("Digit0"), Some((0x30, false)));
        assert_eq!(code_to_vk("Digit9"), Some((0x39, false)));
    }

    #[test]
    fn function_keys() {
        assert_eq!(code_to_vk("F1"), Some((0x70, false)));
        assert_eq!(code_to_vk("F12"), Some((0x7B, false)));
        assert_eq!(code_to_vk("F24"), Some((0x87, false)));
        assert_eq!(code_to_vk("F25"), None);
    }

    #[test]
    fn extended_flags() {
        assert_eq!(code_to_vk("ArrowUp"), Some((0x26, true)));
        assert_eq!(code_to_vk("ControlRight"), Some((0xA3, true)));
        assert_eq!(code_to_vk("ControlLeft"), Some((0xA2, false)));
        assert_eq!(code_to_vk("NumpadDivide"), Some((0x6F, true)));
    }

    #[test]
    fn specials() {
        assert_eq!(code_to_vk("Enter"), Some((0x0D, false)));
        assert_eq!(code_to_vk("Space"), Some((0x20, false)));
        assert_eq!(code_to_vk("Nonsense"), None);
    }

    use super::{
        key_stroke, vk_to_scan, KeyStroke, KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP,
        KEYEVENTF_SCANCODE,
    };

    /// The stroke for a `KeyboardEvent.code`, as the injector builds it.
    fn stroke(code: &str, down: bool) -> KeyStroke {
        let (vk, extended) = code_to_vk(code).expect("mapped code");
        key_stroke(vk, extended, down)
    }

    /// Every code the viewer can send that the keymap knows (the aliases `OSLeft`/`OSRight` aside).
    fn all_codes() -> Vec<String> {
        let mut codes: Vec<String> = Vec::new();
        codes.extend(('A'..='Z').map(|c| format!("Key{c}")));
        codes.extend(('0'..='9').map(|c| format!("Digit{c}")));
        codes.extend((1..=24).map(|n| format!("F{n}")));
        codes.extend(('0'..='9').map(|c| format!("Numpad{c}")));
        for c in [
            "Enter",
            "NumpadEnter",
            "Escape",
            "Backspace",
            "Tab",
            "Space",
            "CapsLock",
            "ShiftLeft",
            "ShiftRight",
            "ControlLeft",
            "ControlRight",
            "AltLeft",
            "AltRight",
            "MetaLeft",
            "MetaRight",
            "ContextMenu",
            "ArrowLeft",
            "ArrowUp",
            "ArrowRight",
            "ArrowDown",
            "Insert",
            "Delete",
            "Home",
            "End",
            "PageUp",
            "PageDown",
            "Backquote",
            "Minus",
            "Equal",
            "BracketLeft",
            "BracketRight",
            "Backslash",
            "Semicolon",
            "Quote",
            "Comma",
            "Period",
            "Slash",
            "IntlBackslash",
            "NumpadAdd",
            "NumpadSubtract",
            "NumpadMultiply",
            "NumpadDivide",
            "NumpadDecimal",
            "NumLock",
            "PrintScreen",
            "ScrollLock",
        ] {
            codes.push(c.to_owned());
        }
        codes
    }

    #[test]
    fn game_keys_go_by_their_scan_codes() {
        // WASD, Space, Shift, Ctrl: what a game reads through DirectInput / raw input.
        assert_eq!(
            stroke("KeyW", true),
            KeyStroke {
                vk: 0x57,
                scan: 0x11,
                flags: KEYEVENTF_SCANCODE
            }
        );
        assert_eq!(stroke("KeyA", true).scan, 0x1E);
        assert_eq!(stroke("KeyS", true).scan, 0x1F);
        assert_eq!(stroke("KeyD", true).scan, 0x20);
        assert_eq!(stroke("Space", true).scan, 0x39);
        assert_eq!(stroke("ShiftLeft", true).scan, 0x2A);
        assert_eq!(stroke("ControlLeft", true).scan, 0x1D);
        assert_eq!(stroke("Digit1", true).scan, 0x02);
        assert_eq!(stroke("Digit0", true).scan, 0x0B);
        assert_eq!(stroke("F1", true).scan, 0x3B);
        assert_eq!(stroke("F11", true).scan, 0x57);
        assert_eq!(stroke("Escape", true).scan, 0x01);
    }

    #[test]
    fn a_release_is_the_same_key_with_keyup() {
        let up = stroke("KeyW", false);
        assert_eq!(up.scan, 0x11);
        assert_eq!(up.flags, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP);
    }

    #[test]
    fn extended_keys_carry_the_e0_flag_with_their_scan_code() {
        for (code, scan) in [
            ("ArrowUp", 0x48),
            ("ArrowDown", 0x50),
            ("ArrowLeft", 0x4B),
            ("ArrowRight", 0x4D),
            ("Home", 0x47),
            ("End", 0x4F),
            ("PageUp", 0x49),
            ("PageDown", 0x51),
            ("Insert", 0x52),
            ("Delete", 0x53),
            ("ControlRight", 0x1D),
            ("AltRight", 0x38),
            ("NumpadEnter", 0x1C),
            ("NumpadDivide", 0x35),
            ("MetaLeft", 0x5B),
        ] {
            let s = stroke(code, true);
            assert_eq!(s.scan, scan, "{code}");
            assert_eq!(
                s.flags,
                KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY,
                "{code} must be extended"
            );
        }
        // Their plain twins are not.
        for code in [
            "Numpad8",
            "Numpad1",
            "ControlLeft",
            "AltLeft",
            "Enter",
            "Slash",
        ] {
            assert_eq!(
                stroke(code, true).flags & KEYEVENTF_EXTENDEDKEY,
                0,
                "{code}"
            );
        }
    }

    #[test]
    fn keys_without_a_single_byte_scan_code_go_by_virtual_key() {
        // Pause is E1 1D 45; media keys are not in the set-1 table.
        for vk in [0x13_u16, 0xAD, 0xAE, 0xAF, 0xB3] {
            assert_eq!(vk_to_scan(vk), None);
            let s = key_stroke(vk, false, true);
            assert_eq!(
                s,
                KeyStroke {
                    vk,
                    scan: 0,
                    flags: 0
                }
            );
            assert!(!s.by_scan_code());
        }
    }

    #[test]
    fn every_mapped_key_has_a_scan_code_and_no_two_share_one() {
        // Two codes sharing (scan, extended) would press the same physical key: one of them wrong.
        let mut seen = std::collections::HashMap::new();
        for code in all_codes() {
            let s = stroke(&code, true);
            assert!(s.by_scan_code(), "{code} has no scan code");
            let pair = (s.scan, s.flags & KEYEVENTF_EXTENDEDKEY);
            if let Some(other) = seen.insert(pair, code.clone()) {
                panic!("{code} and {other} both press scan {:#04x}", s.scan);
            }
        }
    }
}
