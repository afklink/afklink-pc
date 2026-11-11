//! «Управление не доходит» on the PC — the desktop app's half: the Windows toast, and the highlight
//! cleared once the window reads the driver installed. The recognition is the agent's
//! (`afklink_core`'s `input_reach`, over the input crate's reach watch: three presses in a row
//! dropped within two seconds by a window running as administrator, without the driver); the
//! highlight itself — the «Управление в играх» row in red over a lime «Установить» — is
//! `home::driver_row`, from `AgentState::input_not_reaching`.
//!
//! ## The toast
//!
//! «Управление не доходит до игры», «Установи драйвер в окне AFKLink» on the line under it (no
//! full stops, a line each: `TOAST_LINE_BREAK` in `afklink_i18n`) — at most once a session
//! ([`DriverToast`]), while the agent says the viewer's presses are blocked
//! (`AgentState::input_blocked`), and only while the main window is not on screen ([`Presence`]):
//! whoever looks at the window sees the red row already. Pressing the toast opens nothing
//! (`toast_identity`: no `CustomActivator` is registered), so the text says where to go. Held back
//! because the window is on screen, it goes out later in the same session if the window leaves the
//! screen while the presses are still blocked.
//!
//! ## «On screen», decided
//!
//! The main window is not on screen when it is hidden (in the tray), minimized, cloaked (on another
//! virtual desktop), on no monitor, or covered: less than [`ON_SCREEN_MIN_PCT`] of its drawn area is
//! left uncovered by the windows above it in the z-order — those that are visible, not minimized,
//! not cloaked, not click-through (`WS_EX_TRANSPARENT`: overlays) and not this app's own. Being the
//! foreground window is not asked: while the presses are blocked, the window in front is the one
//! running as administrator, never this app's — the question is whether ours still shows beside it
//! (a second monitor, a game in a window). Whatever cannot be read counts as not on screen: a toast
//! too many is cheaper than a hint nobody sees.
//!
//! ## Logs
//!
//! `debug`: the toast handed to Windows (for which sessions, why the window counts as not on screen),
//! held back (once a session, with how much of the window shows), and the highlight cleared because
//! the driver was read installed (`afklink_core`'s line, with the read). `trace`: each look at the
//! window. A failed toast is a `warn`.

use std::collections::HashSet;

use afklink_core::AgentControl;

use crate::fakerinput_setup::{DriverRead, DriverState};

/// The main window counts as on screen with at least this much of its area uncovered.
pub(crate) const ON_SCREEN_MIN_PCT: u32 = 50;

/// Where the main window is, for the toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    /// On screen, this much of it uncovered.
    OnScreen { visible_pct: u32 },
    /// Not on screen, and why.
    Away(&'static str),
}

/// What the toast does on one look of the state watcher.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ToastStep {
    /// Nothing: the presses are not blocked, nobody is connected, or every live session had its
    /// toast (or was told it is held back).
    Nothing,
    /// Show it, for these sessions: the window is not on screen, for this reason.
    Show {
        sessions: Vec<String>,
        why: &'static str,
    },
    /// Due for these sessions, but the window is on screen and its row says it: not now.
    HeldBack {
        sessions: Vec<String>,
        visible_pct: u32,
    },
}

/// Which sessions the toast went out for, across the state watcher's looks.
#[derive(Debug, Default)]
pub(crate) struct DriverToast {
    /// Sessions the toast went out for: never again for them.
    shown: HashSet<String>,
    /// Sessions it was held back for (the window on screen), so that is said once each.
    held: HashSet<String>,
}

impl DriverToast {
    /// One look: whether the presses are blocked now, the live sessions, and — asked only when the
    /// toast is due — where the main window is.
    pub(crate) fn poll(
        &mut self,
        blocked: bool,
        sessions: &[String],
        presence: impl FnOnce() -> Presence,
    ) -> ToastStep {
        self.shown.retain(|s| sessions.contains(s));
        self.held.retain(|s| sessions.contains(s));
        if !blocked {
            return ToastStep::Nothing;
        }
        let due: Vec<String> = sessions
            .iter()
            .filter(|s| !self.shown.contains(*s))
            .cloned()
            .collect();
        if due.is_empty() {
            return ToastStep::Nothing;
        }
        match presence() {
            Presence::Away(why) => {
                self.shown.extend(due.iter().cloned());
                ToastStep::Show { sessions: due, why }
            }
            Presence::OnScreen { visible_pct } => {
                let new: Vec<String> = due
                    .into_iter()
                    .filter(|s| self.held.insert(s.clone()))
                    .collect();
                if new.is_empty() {
                    ToastStep::Nothing
                } else {
                    ToastStep::HeldBack {
                        sessions: new,
                        visible_pct,
                    }
                }
            }
        }
    }
}

/// The window read the driver installed (its status read, or the read after an install): the
/// highlight has nothing left to ask for. Only while it is set — twice a second, a lock and a
/// compare otherwise — and not while the agent says presses are being dropped right now (`blocked`:
/// the driver read installed is then not open for the session, «Проверить» opens it; clearing now
/// would only see the agent set it again a second later).
pub(crate) fn clear_when_installed(control: &AgentControl, highlighted: bool, blocked: bool) {
    if !highlighted {
        return;
    }
    let read = crate::fakerinput_setup::last_read();
    let DriverRead::Read(state @ (DriverState::Installed | DriverState::InstalledExternal)) = read
    else {
        return;
    };
    if blocked {
        // Each of the agent's polls would undo it: said at trace, the agent's lines say the rest.
        tracing::trace!(
            driver = state.as_str(),
            "«Управление не доходит»: the driver reads installed, but presses are being dropped \
             now (not open for the session); the highlight stays until they are not"
        );
        return;
    }
    control.driver_installed(&format!(
        "the window read the driver {} (its last status read)",
        state.as_str()
    ));
}

/// Where the main window is ([`Presence`]; the module docs say how it is decided).
pub(crate) fn main_window_presence<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Presence {
    use tauri::Manager;
    let Some(w) = app.get_webview_window("main") else {
        return Presence::Away("there is no main window");
    };
    match w.is_visible() {
        Ok(true) => {}
        Ok(false) => return Presence::Away("hidden (in the tray)"),
        Err(e) => {
            tracing::debug!("driver toast: the main window's visibility unknown: {e}");
            return Presence::Away("its visibility could not be read");
        }
    }
    match w.is_minimized() {
        Ok(false) => {}
        Ok(true) => return Presence::Away("minimized"),
        Err(e) => {
            tracing::debug!("driver toast: whether the main window is minimized unknown: {e}");
            return Presence::Away("whether it is minimized could not be read");
        }
    }
    #[cfg(windows)]
    {
        match w.hwnd() {
            Ok(hwnd) => system::presence(hwnd.0 as usize),
            Err(e) => {
                tracing::debug!("driver toast: the main window's handle unknown: {e}");
                Presence::Away("its handle could not be read")
            }
        }
    }
    #[cfg(not(windows))]
    {
        Presence::OnScreen { visible_pct: 100 }
    }
}

/// A rectangle in screen pixels: left, top, right, bottom — right and bottom exclusive.
pub(crate) type Rect = (i32, i32, i32, i32);

/// How much of `ours`, in percent, no rectangle of `covers` covers (they may overlap each other).
/// Zero for an empty `ours`.
pub(crate) fn visible_percent(ours: Rect, covers: &[Rect]) -> u32 {
    let (l, t, r, b) = (
        i64::from(ours.0),
        i64::from(ours.1),
        i64::from(ours.2),
        i64::from(ours.3),
    );
    let total = (r - l).max(0) * (b - t).max(0);
    if total == 0 {
        return 0;
    }
    // Each cover clipped to ours; whatever falls outside it hides nothing of it.
    let clipped: Vec<(i64, i64, i64, i64)> = covers
        .iter()
        .map(|c| {
            (
                i64::from(c.0).max(l),
                i64::from(c.1).max(t),
                i64::from(c.2).min(r),
                i64::from(c.3).min(b),
            )
        })
        .filter(|c| c.0 < c.2 && c.1 < c.3)
        .collect();
    // The grid every edge makes: each cell is either wholly covered or wholly not.
    let mut xs: Vec<i64> = vec![l, r];
    let mut ys: Vec<i64> = vec![t, b];
    for c in &clipped {
        xs.extend([c.0, c.2]);
        ys.extend([c.1, c.3]);
    }
    xs.sort_unstable();
    xs.dedup();
    ys.sort_unstable();
    ys.dedup();
    let mut covered = 0i64;
    for x in xs.windows(2) {
        for y in ys.windows(2) {
            let (x0, x1, y0, y1) = (x[0], x[1], y[0], y[1]);
            if clipped
                .iter()
                .any(|c| c.0 <= x0 && x1 <= c.2 && c.1 <= y0 && y1 <= c.3)
            {
                covered += (x1 - x0) * (y1 - y0);
            }
        }
    }
    u32::try_from((total - covered) * 100 / total).unwrap_or(0)
}

/// The Win32 reads: the window's cloaking, monitor and bounds, and the windows above it. Reads only.
#[cfg(windows)]
mod system {
    use std::ffi::c_void;
    use std::mem::size_of;

    use windows::Win32::Foundation::{HWND, RECT};
    use windows::Win32::Graphics::Dwm::{
        DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS,
    };
    use windows::Win32::Graphics::Gdi::{MonitorFromWindow, MONITOR_DEFAULTTONULL};
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindow, GetWindowLongW, GetWindowRect, GetWindowThreadProcessId, IsIconic,
        IsWindowVisible, GWL_EXSTYLE, GW_HWNDPREV, WS_EX_TRANSPARENT,
    };

    use super::{visible_percent, Presence, Rect, ON_SCREEN_MIN_PCT};

    /// More windows above ours than any desktop has: a z-order that changes under the walk cannot
    /// make it endless.
    const MAX_ABOVE: usize = 2048;

    pub(super) fn presence(hwnd: usize) -> Presence {
        let h = HWND(hwnd as *mut c_void);
        if cloaked(h) {
            return Presence::Away("cloaked (on another virtual desktop)");
        }
        // SAFETY: a plain call on a window this process owns.
        if unsafe { MonitorFromWindow(h, MONITOR_DEFAULTTONULL) }.is_invalid() {
            return Presence::Away("on no monitor");
        }
        let Some(ours) = bounds(h) else {
            return Presence::Away("its bounds could not be read");
        };
        // SAFETY: a plain call.
        let own_pid = unsafe { GetCurrentProcessId() };
        let mut covers = Vec::new();
        let mut walked = 0usize;
        // SAFETY: plain calls; a window gone meanwhile ends the walk with an error.
        let mut above = unsafe { GetWindow(h, GW_HWNDPREV) };
        while let Ok(w) = above {
            if w.is_invalid() || walked >= MAX_ABOVE {
                break;
            }
            walked += 1;
            if hides(w, own_pid) {
                if let Some(r) = bounds(w) {
                    covers.push(r);
                }
            }
            // SAFETY: as above.
            above = unsafe { GetWindow(w, GW_HWNDPREV) };
        }
        let visible_pct = visible_percent(ours, &covers);
        tracing::trace!(
            walked,
            covering = covers.len(),
            visible_pct,
            "driver toast: the main window's share left uncovered"
        );
        if visible_pct < ON_SCREEN_MIN_PCT {
            Presence::Away("covered by other windows")
        } else {
            Presence::OnScreen { visible_pct }
        }
    }

    /// A window above ours that hides what is under it: shown, not minimized, not cloaked, not
    /// click-through, not this app's.
    fn hides(w: HWND, own_pid: u32) -> bool {
        // SAFETY: plain calls; a gone window reads false / 0.
        if !unsafe { IsWindowVisible(w) }.as_bool() || unsafe { IsIconic(w) }.as_bool() {
            return false;
        }
        // SAFETY: as above.
        let ex_style = unsafe { GetWindowLongW(w, GWL_EXSTYLE) } as u32;
        if ex_style & WS_EX_TRANSPARENT.0 != 0 || cloaked(w) {
            return false;
        }
        let mut pid = 0u32;
        // SAFETY: a live u32 for the answer.
        unsafe { GetWindowThreadProcessId(w, Some(&mut pid)) };
        pid != own_pid
    }

    fn cloaked(w: HWND) -> bool {
        let mut value = 0u32;
        // SAFETY: `value` is a live u32 of the size given.
        unsafe {
            DwmGetWindowAttribute(
                w,
                DWMWA_CLOAKED,
                (&mut value as *mut u32).cast(),
                size_of::<u32>() as u32,
            )
        }
        .is_ok_and(|()| value != 0)
    }

    /// What DWM draws of the window, else its window rectangle.
    fn bounds(w: HWND) -> Option<Rect> {
        let mut r = RECT::default();
        // SAFETY: a live RECT of the size given.
        let dwm = unsafe {
            DwmGetWindowAttribute(
                w,
                DWMWA_EXTENDED_FRAME_BOUNDS,
                (&mut r as *mut RECT).cast(),
                size_of::<RECT>() as u32,
            )
        };
        if dwm.is_err() {
            // SAFETY: a live RECT.
            unsafe { GetWindowRect(w, &mut r) }.ok()?;
        }
        Some((r.left, r.top, r.right, r.bottom))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    const AWAY: Presence = Presence::Away("hidden (in the tray)");
    const SHOWN: Presence = Presence::OnScreen { visible_pct: 80 };

    /// Once a session: blocked again in the same session, no second toast.
    #[test]
    fn the_toast_goes_out_once_a_session() {
        let mut t = DriverToast::default();
        let live = ids(&["s1"]);
        assert_eq!(
            t.poll(true, &live, || AWAY),
            ToastStep::Show {
                sessions: live.clone(),
                why: "hidden (in the tray)"
            }
        );
        assert_eq!(t.poll(true, &live, || AWAY), ToastStep::Nothing);
        assert_eq!(t.poll(false, &live, || AWAY), ToastStep::Nothing);
        assert_eq!(
            t.poll(true, &live, || AWAY),
            ToastStep::Nothing,
            "blocked again later in the same session"
        );
        // The next session is told again.
        let next = ids(&["s2"]);
        assert_eq!(
            t.poll(true, &next, || AWAY),
            ToastStep::Show {
                sessions: next,
                why: "hidden (in the tray)"
            }
        );
    }

    /// Not blocked, or nobody connected: nothing — and the window is not even looked at.
    #[test]
    fn nothing_while_not_blocked_or_without_a_session() {
        let mut t = DriverToast::default();
        let looked = std::cell::Cell::new(false);
        let look = || {
            looked.set(true);
            AWAY
        };
        assert_eq!(t.poll(false, &ids(&["s1"]), look), ToastStep::Nothing);
        assert_eq!(
            t.poll(true, &[], || {
                looked.set(true);
                AWAY
            }),
            ToastStep::Nothing
        );
        assert!(!looked.get());
    }

    /// Only while the window is not on screen: on screen, the toast is held back (said once); it
    /// goes out if the window leaves the screen while the presses are still blocked.
    #[test]
    fn the_toast_waits_while_the_window_is_on_screen() {
        let mut t = DriverToast::default();
        let live = ids(&["s1"]);
        assert_eq!(
            t.poll(true, &live, || SHOWN),
            ToastStep::HeldBack {
                sessions: live.clone(),
                visible_pct: 80
            }
        );
        assert_eq!(
            t.poll(true, &live, || SHOWN),
            ToastStep::Nothing,
            "held back once"
        );
        assert_eq!(
            t.poll(true, &live, || Presence::Away("covered by other windows")),
            ToastStep::Show {
                sessions: live,
                why: "covered by other windows"
            }
        );
    }

    /// A rectangle's share left uncovered, overlapping covers counted once.
    #[test]
    fn the_uncovered_share_of_the_window() {
        let ours = (0, 0, 400, 600);
        assert_eq!(visible_percent(ours, &[]), 100);
        // A full-screen game over it.
        assert_eq!(visible_percent(ours, &[(-10, -10, 3840, 2160)]), 0);
        // Its left half covered, twice over.
        assert_eq!(
            visible_percent(ours, &[(0, 0, 200, 600), (-50, 100, 150, 500)]),
            50
        );
        // A taskbar strip across its bottom.
        assert_eq!(visible_percent(ours, &[(-1000, 540, 3000, 700)]), 90);
        // Elsewhere on the screen: nothing of it hidden.
        assert_eq!(visible_percent(ours, &[(500, 0, 900, 600)]), 100);
        // Four quarters, a gap in the middle.
        let quarters = [
            (0, 0, 190, 290),
            (210, 0, 400, 290),
            (0, 310, 190, 600),
            (210, 310, 400, 600),
        ];
        // 400×600 less four 190×290: 19 600 of 240 000 pixels.
        assert_eq!(visible_percent(ours, &quarters), 8);
        // An empty window shows nothing.
        assert_eq!(visible_percent((10, 10, 10, 50), &[]), 0);
    }
}
