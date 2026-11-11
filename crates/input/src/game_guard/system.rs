//! The real [`GuardHost`]: this PC's foreground window, the window under a pixel, and the planner the
//! `SendInput` path keeps. Reads, but for one call: `SetForegroundWindow`, which the guard makes on
//! the viewer's input at most every two seconds. No process is opened here but through the planner's
//! foreground description (limited information only), and never the game's.

use std::ffi::c_void;
use std::time::Instant;

use windows::Win32::Foundation::{HWND, POINT};
use windows::Win32::UI::WindowsAndMessaging::{
    GetAncestor, GetForegroundWindow, GetWindowThreadProcessId, SetForegroundWindow,
    WindowFromPoint, GA_ROOT,
};

use super::{GuardHost, WindowAt};
use crate::cursor_sync::system::SystemCursor;
use crate::cursor_sync::{CursorWorld, Elevation, ForegroundInfo};
use crate::SendInputInjector;

/// This PC, for one event (or one look of the focus watch).
pub(crate) struct SystemGuard<'a> {
    /// The `SendInput` path, which keeps the cursor-sync planner both paths share.
    pub(crate) fallback: &'a SendInputInjector,
    /// The driver is open for the session.
    pub(crate) driver_open: bool,
    pub(crate) now: Instant,
}

/// The process that owns a window; 0 when it cannot be read (a window that is gone).
fn window_pid(window: HWND) -> u32 {
    let mut pid = 0u32;
    // SAFETY: any window handle may be asked about; a stale one answers 0.
    let thread = unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
    if thread == 0 {
        0
    } else {
        pid
    }
}

impl GuardHost for SystemGuard<'_> {
    fn foreground(&mut self) -> usize {
        // SAFETY: plain call.
        unsafe { GetForegroundWindow() }.0 as usize
    }

    fn window_pid(&mut self, window: usize) -> u32 {
        window_pid(HWND(window as *mut c_void))
    }

    fn describe(&mut self, window: usize) -> ForegroundInfo {
        SystemCursor.describe_foreground(window)
    }

    fn set_foreground(&mut self, window: usize) -> Result<bool, String> {
        // SAFETY: any window handle may be passed; a stale one is refused.
        Ok(unsafe { SetForegroundWindow(HWND(window as *mut c_void)) }.as_bool())
    }

    fn window_at(&mut self, px: i32, py: i32) -> Result<WindowAt, String> {
        // SAFETY: plain call with a point by value. In the agent's per-monitor DPI awareness the
        // point is in physical pixels, like the cursor and the planner's targets.
        let window = unsafe { WindowFromPoint(POINT { x: px, y: py }) };
        if window.0.is_null() {
            return Err(format!("WindowFromPoint({px}, {py}): no window there"));
        }
        // SAFETY: plain call on a live (or stale: then null) handle.
        let root = unsafe { GetAncestor(window, GA_ROOT) };
        let root = if root.0.is_null() { window } else { root };
        Ok(WindowAt {
            hwnd: window.0 as usize,
            pid: window_pid(window),
            root: root.0 as usize,
            root_pid: window_pid(root),
        })
    }

    fn press_target(&mut self) -> Option<(i32, i32)> {
        self.fallback.press_target(self.now)
    }

    fn foreground_elevation(&mut self) -> Option<Elevation> {
        self.fallback.foreground_elevation(self.now)
    }

    fn driver_open(&self) -> bool {
        self.driver_open
    }

    fn held_buttons(&mut self) -> u32 {
        // The paths' own books (the ledger, and the HID router's word to the planner): nothing is
        // read from Windows for it.
        self.fallback.held_button_bits().count_ones()
    }
}
