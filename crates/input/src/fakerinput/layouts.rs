//! This PC's keyboard layouts, for typing game text as key presses (`super::typing`): which layout
//! the focused window types with, which key makes a character on a layout, and switching the focused
//! window's layout. Queries only — they never read what the local keyboard types — except
//! [`WinKeyboard::request_layout`], which posts the request the language bar itself would.

use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HWND, LPARAM, WIN32_ERROR, WPARAM};
use windows::Win32::Globalization::{
    GetACP, GetLocaleInfoW, LOCALE_IDEFAULTANSICODEPAGE, LOCALE_RETURN_NUMBER,
};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_SZ};
use windows::Win32::System::Threading::{AttachThreadInput, GetCurrentThreadId};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, GetKeyboardLayout, GetKeyboardLayoutList, MapVirtualKeyExW, ToUnicodeEx,
    VkKeyScanExW, HKL, MAPVK_VK_TO_VSC_EX,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetGUIThreadInfo, GetWindowThreadProcessId, PostMessageW, GUITHREADINFO,
    INPUTLANGCHANGE_SYSCHARSET, WM_INPUTLANGCHANGEREQUEST,
};

use super::typing::{parse_hotkey, Hkl, KeyState, Keyboard, LanguageHotkey, Produced};

/// Virtual keys the `ToUnicodeEx` state array marks (winuser.h).
const VK_SHIFT: usize = 0x10;
const VK_CONTROL: usize = 0x11;
const VK_MENU: usize = 0x12;
const VK_CAPITAL: usize = 0x14;
const VK_LSHIFT: usize = 0xA0;
const VK_LCONTROL: usize = 0xA2;
const VK_RMENU: usize = 0xA5;

/// `ToUnicodeEx` flag: do not change the keyboard state (Windows 10 1607 and later), so a dead key
/// asked about is not left pending for the user's next key.
const TOUNICODE_KEEP_STATE: u32 = 4;

/// The agent's [`Keyboard`]: the real layouts, through user32.
pub(crate) struct WinKeyboard;

fn handle(hkl: Hkl) -> HKL {
    HKL(hkl.0 as *mut core::ffi::c_void)
}

fn from_handle(hkl: HKL) -> Hkl {
    Hkl(hkl.0 as usize)
}

/// The foreground thread's GUI state was unreadable (the secure desktop, no foreground window):
/// said once per streak at `debug`, since the typing asks for every character.
static FOCUS_UNREADABLE: AtomicBool = AtomicBool::new(false);

/// The window with the keyboard focus: the foreground thread's focus window, else its active window,
/// else the foreground window.
fn focus_window() -> Option<HWND> {
    let mut info = GUITHREADINFO {
        cbSize: std::mem::size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a live GUITHREADINFO with `cbSize` set; thread 0 means the foreground thread.
    match unsafe { GetGUIThreadInfo(0, &mut info) } {
        Ok(()) => {
            if FOCUS_UNREADABLE.swap(false, Ordering::Relaxed) {
                tracing::debug!("focused window readable again");
            }
            if !info.hwndFocus.is_invalid() {
                return Some(info.hwndFocus);
            }
            if !info.hwndActive.is_invalid() {
                return Some(info.hwndActive);
            }
        }
        Err(error) => {
            if !FOCUS_UNREADABLE.swap(true, Ordering::Relaxed) {
                tracing::debug!(%error, "focused window unreadable; trying the foreground window");
            }
        }
    }
    // SAFETY: no arguments.
    let foreground = unsafe { GetForegroundWindow() };
    (!foreground.is_invalid()).then_some(foreground)
}

/// `INPUTLANGCHANGE_SYSCHARSET` when the layout's language uses the system's ANSI code page (a
/// window may refuse a layout its character set cannot show), else 0.
pub(super) fn charset_flag(hkl: Hkl) -> usize {
    let mut number = [0u16; 2];
    // SAFETY: `number` holds the DWORD `LOCALE_RETURN_NUMBER` writes (two UTF-16 units).
    let written = unsafe {
        GetLocaleInfoW(
            u32::from(hkl.lang()),
            LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
            Some(&mut number),
        )
    };
    if written == 0 {
        tracing::trace!(
            error = %windows::core::Error::from_thread(),
            "layout's code page unknown: the request goes without SYSCHARSET"
        );
        return 0;
    }
    let code_page = u32::from(number[0]) | (u32::from(number[1]) << 16);
    // SAFETY: no arguments.
    if code_page == unsafe { GetACP() } {
        INPUTLANGCHANGE_SYSCHARSET as usize
    } else {
        0
    }
}

/// Caps Lock's toggle, as this thread's input state has it.
fn own_caps() -> bool {
    // SAFETY: a plain virtual-key query; the low bit is the toggle.
    let state = unsafe { GetKeyState(VK_CAPITAL as i32) };
    state & 1 != 0
}

/// Undoes an `AttachThreadInput` when dropped — on every path out of the read.
struct Detach {
    me: u32,
    focused: u32,
}

impl Drop for Detach {
    fn drop(&mut self) {
        // SAFETY: the same two thread ids the attachment was made with.
        if !unsafe { AttachThreadInput(self.me, self.focused, false) }.as_bool() {
            tracing::debug!(
                error = %windows::core::Error::from_thread(),
                "Caps Lock: detaching from the focused window's thread failed"
            );
        }
    }
}

/// One value under `HKCU\Keyboard Layout\Toggle`, or `None` when it is not there.
fn toggle_value(name: PCWSTR) -> Option<String> {
    match checked_toggle_value(name) {
        Ok(value) => value,
        Err(status) => {
            // not-a-key-name: Win32 registry status code.
            tracing::debug!(
                code = status.0,
                "reading the language hotkey setting failed; treated as absent"
            );
            None
        }
    }
}

fn checked_toggle_value(name: PCWSTR) -> Result<Option<String>, WIN32_ERROR> {
    let mut buffer = [0u16; 16];
    let mut bytes = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: `buffer` and `bytes` describe a live buffer; the key and value names are static,
    // NUL-terminated wide strings.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Keyboard Layout\\Toggle"),
            name,
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status.is_err() {
        return Err(status);
    }
    let units = (bytes as usize / 2).min(buffer.len());
    let text = String::from_utf16_lossy(&buffer[..units]);
    Ok(Some(text.trim_end_matches('\0').to_owned()))
}

pub(super) fn language_hotkey_setting() -> Result<LanguageHotkey, WIN32_ERROR> {
    let value = checked_toggle_value(w!("Language Hotkey"))?;
    let legacy = if value.is_none() {
        checked_toggle_value(w!("Hotkey"))?
    } else {
        None
    };
    Ok(parse_hotkey(value.as_deref(), legacy.as_deref()))
}

pub(super) fn caps_for_window(window: Option<HWND>) -> bool {
    let focused = window.map(|window| {
        // SAFETY: a window handle, possibly stale (the call then returns 0); no out pointer.
        unsafe { GetWindowThreadProcessId(window, None) }
    });
    // SAFETY: no arguments.
    let me = unsafe { GetCurrentThreadId() };
    let Some(focused) = focused.filter(|&t| t != 0 && t != me) else {
        tracing::trace!("Caps Lock: no other focused thread; this thread's own view");
        return own_caps();
    };
    // SAFETY: two thread ids; the attachment is undone by `Detach` below whatever happens.
    if !unsafe { AttachThreadInput(me, focused, true) }.as_bool() {
        tracing::debug!(
            error = %windows::core::Error::from_thread(),
            "Caps Lock: attaching to the focused window's thread failed; this thread's own view \
             (it may be stale)"
        );
        return own_caps();
    }
    let _detach = Detach { me, focused };
    own_caps()
}

impl Keyboard for WinKeyboard {
    fn focused_layout(&mut self) -> Option<Hkl> {
        let window = focus_window()?;
        // SAFETY: a window handle, possibly stale (the call then returns 0); no out pointer.
        let thread = unsafe { GetWindowThreadProcessId(window, None) };
        if thread == 0 {
            tracing::trace!("focused window's thread unavailable");
            return None;
        }
        // SAFETY: a thread id; returns that thread's active layout, or null.
        let hkl = unsafe { GetKeyboardLayout(thread) };
        if hkl.0.is_null() {
            tracing::trace!("focused thread's keyboard layout unavailable");
            return None;
        }
        Some(from_handle(hkl))
    }

    fn focus(&mut self) -> Option<usize> {
        focus_window().map(|window| window.0 as usize)
    }

    fn installed_layouts(&mut self) -> Vec<Hkl> {
        // SAFETY: the size query: no buffer.
        let count = unsafe { GetKeyboardLayoutList(None) };
        let count = usize::try_from(count).unwrap_or(0);
        if count == 0 {
            tracing::debug!(
                error = %windows::core::Error::from_thread(),
                "no keyboard layouts listed: characters the current layout cannot type go by Unicode"
            );
            return Vec::new();
        }
        let mut list = vec![HKL(std::ptr::null_mut()); count];
        // SAFETY: `list` is a live buffer of `count` handles.
        let got = unsafe { GetKeyboardLayoutList(Some(&mut list)) };
        let got = usize::try_from(got).unwrap_or(0);
        if got == 0 {
            // Counted a moment ago, none listed now: a layout removed in between, or a failure.
            tracing::debug!(
                counted = count,
                error = %windows::core::Error::from_thread(),
                "keyboard layouts listed as none: characters the current layout cannot type go by \
                 Unicode"
            );
        }
        list.truncate(got);
        list.into_iter().map(from_handle).collect()
    }

    fn vk_for_char(&mut self, ch: u16, hkl: Hkl) -> Option<(u8, u8)> {
        // SAFETY: plain values; the layout handle is only read.
        let scanned = unsafe { VkKeyScanExW(ch, handle(hkl)) };
        let [vk, state] = scanned.to_le_bytes();
        // -1 in both bytes: no key makes it.
        (vk != 0xff && state != 0xff).then_some((vk, state))
    }

    fn scan_for_vk(&mut self, vk: u8, hkl: Hkl) -> u16 {
        // SAFETY: plain values; the layout handle is only read.
        let scan =
            unsafe { MapVirtualKeyExW(u32::from(vk), MAPVK_VK_TO_VSC_EX, Some(handle(hkl))) };
        u16::try_from(scan).unwrap_or(0)
    }

    fn produces(&mut self, vk: u8, scan: u16, state: KeyState, hkl: Hkl) -> Produced {
        let mut keys = [0u8; 256];
        if state.shift {
            keys[VK_SHIFT] = 0x80;
            keys[VK_LSHIFT] = 0x80;
        }
        if state.altgr {
            keys[VK_CONTROL] = 0x80;
            keys[VK_LCONTROL] = 0x80;
            keys[VK_MENU] = 0x80;
            keys[VK_RMENU] = 0x80;
        }
        if state.caps {
            keys[VK_CAPITAL] = 0x01;
        }
        let mut out = [0u16; 8];
        // SAFETY: a live 256-byte key state and output buffer; flag 4 leaves the keyboard state
        // (and any pending dead key) untouched.
        let made = unsafe {
            ToUnicodeEx(
                u32::from(vk),
                u32::from(scan),
                &keys,
                &mut out,
                TOUNICODE_KEEP_STATE,
                Some(handle(hkl)),
            )
        };
        match made {
            n if n < 0 => Produced::Dead,
            1 => Produced::Char(out[0]),
            _ => Produced::Other,
        }
    }

    /// `GetKeyState` answers from the calling thread's own view of the keyboard, which a thread that
    /// reads no keyboard messages (this worker) never updates. Attached to the focused window's
    /// thread for the read, it answers from that thread's view: the one the typed keys meet. Always
    /// detached again; if attaching fails (an administrator window, a thread that is gone), the own
    /// view is read, and said.
    fn caps_lock(&mut self) -> bool {
        caps_for_window(focus_window())
    }

    fn request_layout(&mut self, hkl: Hkl) -> Result<(), &'static str> {
        let wparam = WPARAM(charset_flag(hkl));
        let lparam = LPARAM(hkl.0 as isize);
        let focus = focus_window();
        // SAFETY: no arguments.
        let foreground = unsafe { GetForegroundWindow() };
        let foreground =
            (!foreground.is_invalid() && Some(foreground) != focus).then_some(foreground);
        let mut outcome = Err("no window has the focus");
        for window in [focus, foreground].into_iter().flatten() {
            // SAFETY: a message with plain values; a stale or foreign window only fails the call.
            match unsafe { PostMessageW(Some(window), WM_INPUTLANGCHANGEREQUEST, wparam, lparam) } {
                Ok(()) => return Ok(()),
                Err(error) => {
                    // Access denied is UIPI: an administrator window does not take messages from us.
                    tracing::debug!(%error, "posting the keyboard layout request failed");
                    outcome = Err("the window refused the request (an administrator window?)");
                }
            }
        }
        outcome
    }

    fn language_hotkey(&mut self) -> LanguageHotkey {
        let language = toggle_value(w!("Language Hotkey"));
        let legacy = if language.is_none() {
            toggle_value(w!("Hotkey"))
        } else {
            None
        };
        let hotkey = parse_hotkey(language.as_deref(), legacy.as_deref());
        tracing::trace!(
            target: crate::KEY_NAMES_TARGET,
            language_hotkey = ?language,
            hotkey = ?legacy,
            parsed = ?hotkey,
            "language hotkey setting (HKCU\\Keyboard Layout\\Toggle)"
        );
        hotkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakerinput::typing::stroke_on;

    /// The real user32 answers on the US layout, read-only: `VkKeyScanExW`, `MapVirtualKeyExW` and
    /// `ToUnicodeEx` with flag 4 (which leaves the keyboard state alone). Nothing is typed, posted
    /// or attached.
    #[test]
    #[ignore = "reads this PC's installed keyboard layouts (English (US) needed); injects nothing"]
    fn the_us_layout_answers_as_typing_expects() {
        let mut kb = WinKeyboard;
        let installed = kb.installed_layouts();
        let Some(us) = installed
            .iter()
            .copied()
            .find(|hkl| hkl.0 as u32 == 0x0409_0409)
        else {
            eprintln!("English (US) is not installed here: nothing to check");
            return;
        };
        assert_eq!(kb.vk_for_char(u16::from(b'a'), us), Some((0x41, 0)));
        assert_eq!(kb.vk_for_char(u16::from(b'A'), us), Some((0x41, 1)));
        assert_eq!(kb.vk_for_char(u16::from(b'@'), us), Some((0x32, 1)));
        assert_eq!(kb.vk_for_char(0x043F, us), None, "'п' has no US key");
        assert_eq!(kb.scan_for_vk(0x41, us), 0x1E);
        assert_eq!(kb.scan_for_vk(0x0D, us), 0x1C, "Enter");
        let plain = KeyState {
            shift: false,
            altgr: false,
            caps: false,
        };
        let shifted = KeyState {
            shift: true,
            ..plain
        };
        let caps = KeyState {
            caps: true,
            ..plain
        };
        assert_eq!(
            kb.produces(0x41, 0x1E, plain, us),
            Produced::Char(u16::from(b'a'))
        );
        assert_eq!(
            kb.produces(0x41, 0x1E, shifted, us),
            Produced::Char(u16::from(b'A'))
        );
        assert_eq!(
            kb.produces(0x41, 0x1E, caps, us),
            Produced::Char(u16::from(b'A'))
        );
        assert_eq!(
            kb.produces(0x31, 0x02, caps, us),
            Produced::Char(u16::from(b'1')),
            "Caps Lock leaves digits alone"
        );
        let a = stroke_on(&mut kb, 'a', us, false).map(|s| (s.usage, s.shift, s.altgr));
        assert_eq!(a, Ok((0x04, false, false)));
        let at = stroke_on(&mut kb, '@', us, false).map(|s| (s.usage, s.shift, s.altgr));
        assert_eq!(at, Ok((0x1F, true, false)));
        let with_caps = stroke_on(&mut kb, 'a', us, true).map(|s| s.shift);
        assert_eq!(with_caps, Ok(true), "lowercase with Caps Lock needs Shift");
        assert!(stroke_on(&mut kb, 'п', us, false).is_err());
    }
}
