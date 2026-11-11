//! The pairing code stays out of the video.
//!
//! The pairing panel — `PairingDialog`, a dialog inside the main window — shows a live code and its
//! QR. Anyone connected while it is open saw them in the stream, and a guest could redeem the code
//! from another account of his own. So while the panel is open (or a code is shown) the main window
//! is left out of every screen capture with `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`: on
//! Windows 10 2004 (build 19041) and later a viewer sees whatever is behind the window, as if it
//! were not there; on an older Windows the same call succeeds and acts as `WDA_MONITOR` (Microsoft's
//! documentation of the function) — the window is black in the capture. Where the value is refused
//! outright, `WDA_MONITOR` itself is set. The person at the PC sees the window as ever. When the
//! panel closes, the window is in the video again.
//!
//! The panel lives in the main window, so the whole window is left out while it is open — there is
//! no window of the panel's own to leave out alone. The request window (`pair-request`), where
//! «Разрешить» is pressed, is never left out: an owner connected from elsewhere answers there.
//!
//! It is put on before the code can arrive — when the window asks for one (`request_pairing`, and
//! held on [`OPENING_HOLD`] whatever the state says meanwhile) — and looked at again whenever the
//! window reads its status and every half second for the state watcher, which also takes it off once
//! the panel is closed. What to do is decided by [`step`], a pure function; [`CaptureGuard::sync`]
//! carries it out. Logged at each change (`debug`, with the mode in effect on this Windows), each
//! failure (`warn`, once until what is wanted changes), and a main window whose handle cannot be read
//! while the shield is wanted (`warn`, once per opening of the panel: the code may be in the video).
//!
//! # Only on the main thread
//!
//! Every look runs on the main thread (Tauri's event loop, which owns the window): `get_status` and
//! `request_pairing` are commands without `async`, so they run there already, and the state watcher —
//! a task on the async runtime — hands its look over ([`CaptureGuard::post`]) instead of taking it,
//! and goes on without waiting. A look asked for anywhere else is handed over too, said once
//! (`warn`: it must not happen). And the guard's lock is never held across a call into Tauri: the
//! window and its handle are read first, then the lock is taken for the decision and the call to
//! Windows.
//!
//! Why: from any other thread `window.hwnd()` posts a request to the event loop and waits until the
//! main thread answers it. A look from the state watcher with the lock held across that wait, while
//! the main thread, in `get_status`, waits for the same lock, deadlocks both: the window
//! «Не отвечает» and the PC gone from the server, on idle PCs (one as soon as 24 s after its first
//! connection). Handed-over looks wait one at a time ([`Posted`]): a main thread that is busy
//! does not pile them up, and the one waiting takes the latest word when it runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager, Runtime};

/// How long after the window asks for a code the shield stays on whatever the agent's state says:
/// the state says the panel is open only once the orchestrator has taken the request, and a look in
/// between — the state watcher's, a status read — must not take the shield off just before the code
/// comes. Far longer than the orchestrator takes; short enough that a request nobody took (the
/// agent stopped) does not keep the window out of the video.
const OPENING_HOLD: Duration = Duration::from_secs(3);

/// The first build of Windows 10 version 2004, where `WDA_EXCLUDEFROMCAPTURE` leaves a window out;
/// before it the value acts as `WDA_MONITOR`.
const EXCLUDE_FROM_CAPTURE_BUILD: u32 = 19_041;

/// What is on the main window now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shield {
    /// In the video, as every window.
    Off,
    /// Left out of captures (`WDA_EXCLUDEFROMCAPTURE`, Windows 10 2004 and later).
    Excluded,
    /// Black in captures: `WDA_MONITOR`, or `WDA_EXCLUDEFROMCAPTURE` on a Windows before 2004.
    Blacked,
    /// Wanted, and refused: in the video. Not tried again until what is wanted changes.
    FailedOn,
    /// Taking it off was refused: out of the video still. Not tried again until it is wanted on.
    FailedOff,
}

impl Shield {
    fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Excluded => "excluded",
            Self::Blacked => "blacked",
            Self::FailedOn => "failed_on",
            Self::FailedOff => "failed_off",
        }
    }
}

/// What [`CaptureGuard::sync`] does about the main window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// It is as wanted already (or a failure is not to be retried yet).
    Nothing,
    /// Not wanted, and in the video without a call: noted as off.
    NoteOff,
    /// Put the shield on.
    On,
    /// Take it off.
    Off,
}

/// What to do about the window `hwnd` given what was last done (`last`: the window it was done to,
/// and how it ended) and whether the shield is `want`ed. A window made anew (another handle) starts
/// in the video. A refusal is not retried while what is wanted stays the same: a failed «on» is
/// noted off when it is no longer wanted (no call: it is in the video), a failed «off» is tried
/// again when the shield is wanted once more.
fn step(last: Option<(usize, Shield)>, hwnd: usize, want: bool) -> Step {
    let now = last.filter(|(h, _)| *h == hwnd).map(|(_, s)| s);
    match (now, want) {
        (None | Some(Shield::Off | Shield::FailedOff), true) => Step::On,
        (None | Some(Shield::FailedOn), false) => Step::NoteOff,
        (Some(Shield::Excluded | Shield::Blacked), false) => Step::Off,
        (Some(Shield::Off | Shield::FailedOff), false)
        | (Some(Shield::Excluded | Shield::Blacked | Shield::FailedOn), true) => Step::Nothing,
    }
}

/// Whether the shield is wanted now: the state says so (`state_wants`), or a request for a code is
/// fresh (`opening_until`, [`OPENING_HOLD`]). The second answer says the hold has run out (to be
/// forgotten).
fn wanted_now(state_wants: bool, opening_until: Option<Instant>, now: Instant) -> (bool, bool) {
    match opening_until {
        Some(until) if now < until => (true, false),
        Some(_) => (state_wants, true),
        None => (state_wants, false),
    }
}

/// Whether the main window must stay out of the video: the pairing panel is open, or a code is on
/// it (`pairing_panel`: `afklink_core::pairing::PairingPanel::kind`).
pub(crate) fn wanted(pairing_panel: &str, code_shown: bool) -> bool {
    pairing_panel != "closed" || code_shown
}

/// What the guard knows.
#[derive(Debug, Default)]
struct Inner {
    /// The main window's affinity as last set, by its handle.
    last: Option<(usize, Shield)>,
    /// Until when a request for a code keeps the shield on ([`OPENING_HOLD`]).
    opening_until: Option<Instant>,
    /// The shield was wanted at the last look: a change to wanted starts a new opening.
    wanted: bool,
    /// The handle-unknown warning was said for this opening.
    handle_warned: bool,
}

/// The look handed to the main thread and not run yet — at most one at a time ([`CaptureGuard::post`]).
/// A word given while one waits is left for it: it takes the latest when it runs.
#[derive(Debug, Default)]
struct Posted {
    /// A look is waiting on the main thread.
    waiting: AtomicBool,
    /// The latest word for it: whether the shield is wanted.
    want: AtomicBool,
}

impl Posted {
    /// Leave `want` for the look; true when one is to be handed over (none is waiting), false when
    /// the one waiting takes it.
    ///
    /// The word is stored before the swap, and [`Self::take`] swaps before it reads: whichever swap
    /// comes second sees the other's, so a word is never left with no look to take it.
    fn offer(&self, want: bool) -> bool {
        self.want.store(want, Ordering::SeqCst);
        !self.waiting.swap(true, Ordering::SeqCst)
    }

    /// The look runs: the latest word. An offer from here on hands over a new look.
    fn take(&self) -> bool {
        self.waiting.swap(false, Ordering::SeqCst);
        self.want.load(Ordering::SeqCst)
    }

    /// The look offered was not handed over after all: none is waiting.
    fn withdraw(&self) {
        self.waiting.store(false, Ordering::SeqCst);
    }
}

/// The main window's affinity, kept in step with the pairing panel (see the module).
#[derive(Debug, Default)]
pub(crate) struct CaptureGuard {
    inner: Mutex<Inner>,
    /// The look handed to the main thread, if one waits ([`Self::post`]).
    posted: Posted,
    /// Handing a look to the main thread was refused: said once, until one is handed over again.
    post_refused: AtomicBool,
    /// [`Self::sync`] was asked for off the main thread: said once a run.
    off_main_said: AtomicBool,
}

impl CaptureGuard {
    /// The window asked for a code: the shield goes on now, and stays at least [`OPENING_HOLD`].
    pub(crate) fn opening<R: Runtime>(&self, app: &AppHandle<R>) {
        afklink_core::lock(&self.inner).opening_until = Some(Instant::now() + OPENING_HOLD);
        self.sync(app, true, "the pairing panel asks for a code");
    }

    /// Have the main thread look ([`Self::sync`]) — from any thread, without waiting for it: the
    /// look is posted to the event loop (`run_on_main_thread`), never waited on. While one posted
    /// earlier still waits, none is added: that one takes `want` when it runs ([`Posted`]). The state
    /// watcher's way, twice a second (`why`: who asks, for the log).
    pub(crate) fn post<R: Runtime>(&self, app: &AppHandle<R>, want: bool, why: &'static str) {
        if !self.posted.offer(want) {
            tracing::trace!(
                why,
                want,
                "pairing shield: a look waits on the main thread already; it takes this word"
            );
            return;
        }
        let handle = app.clone();
        let posted = app.run_on_main_thread(move || {
            let Some(guard) = handle.try_state::<CaptureGuard>() else {
                tracing::debug!(why, "pairing shield: no guard for the main thread's look");
                return;
            };
            let want = guard.posted.take();
            if !crate::main_thread::is_current() {
                // Only a runtime that runs the task where it is asked (the tests' mock). Taken here
                // all the same: no lock is held across the window calls, so the worst is a wait.
                tracing::trace!(why, "pairing shield: the main thread's look runs elsewhere");
            }
            guard.sync_here(&handle, want, why);
        });
        match posted {
            Ok(()) => {
                if self.post_refused.swap(false, Ordering::SeqCst) {
                    tracing::debug!(
                        why,
                        want,
                        "pairing shield: the main thread takes its looks again"
                    );
                }
            }
            Err(e) => {
                self.posted.withdraw();
                if !self.post_refused.swap(true, Ordering::SeqCst) {
                    tracing::warn!(
                        why,
                        want,
                        "pairing shield: its look not handed to the main thread ({e}); the main \
                         window's capture affinity is not kept in step meanwhile (said once, until \
                         one is handed over again)"
                    );
                }
            }
        }
    }

    /// The window closed the panel: a request for a code does not hold the shield on now; the next
    /// look at the state takes it off.
    pub(crate) fn closing(&self) {
        if afklink_core::lock(&self.inner)
            .opening_until
            .take()
            .is_some()
        {
            tracing::trace!("pairing shield: the panel closed; the hold of its request ends");
        }
    }

    /// Put the main window out of the video (`want`) or back in it, if it is not so already ([`step`];
    /// `why`: who asks, for the log). Off is not taken while a request for a code is fresh
    /// ([`Self::opening`]).
    ///
    /// On the main thread only (see the module): asked for anywhere else, the look is handed to it
    /// ([`Self::post`]) and this returns at once — said once a run, at `warn`, for it must not happen.
    pub(crate) fn sync<R: Runtime>(&self, app: &AppHandle<R>, want: bool, why: &'static str) {
        if !crate::main_thread::is_current() {
            if !self.off_main_said.swap(true, Ordering::SeqCst) {
                let thread = std::thread::current();
                tracing::warn!(
                    why,
                    want,
                    thread = thread.name().unwrap_or("unnamed"),
                    "pairing shield: a look asked for off the main thread; handed to the main \
                     thread instead (a window call from here waits for the main thread, and the \
                     lock held across that wait can hang the app; said once a run)"
                );
            }
            self.post(app, want, why);
            return;
        }
        self.sync_here(app, want, why);
    }

    /// [`Self::sync`]'s work, where it is called: the main window and its handle read first, with no
    /// lock held — a Tauri call, which off the main thread would wait for it — then, under the lock,
    /// the decision, the call to Windows and its record.
    fn sync_here<R: Runtime>(&self, app: &AppHandle<R>, want: bool, why: &'static str) {
        let handle = app
            .get_webview_window("main")
            .map(|window| window.hwnd().map(|hwnd| hwnd.0 as usize));
        let mut inner = afklink_core::lock(&self.inner);
        let (want, hold_over) = wanted_now(want, inner.opening_until, Instant::now());
        if hold_over {
            inner.opening_until = None;
        }
        if want && !inner.wanted {
            // A new opening of the panel: a handle that cannot be read is said again.
            inner.handle_warned = false;
        }
        inner.wanted = want;
        let Some(handle) = handle else {
            tracing::trace!(why, want, "pairing shield: no main window");
            return;
        };
        let hwnd = match handle {
            Ok(hwnd) => hwnd,
            Err(e) if want && !inner.handle_warned => {
                inner.handle_warned = true;
                tracing::warn!(
                    why,
                    "pairing shield not put on: the main window's handle cannot be read ({e}); the \
                     pairing code may be in the video of whoever is connected (said once while the \
                     panel is open)"
                );
                return;
            }
            Err(e) => {
                tracing::debug!(
                    why,
                    want,
                    "pairing shield: the main window's handle unknown: {e}"
                );
                return;
            }
        };
        let from = inner.last.filter(|(h, _)| *h == hwnd).map(|(_, s)| s);
        let set = match step(inner.last, hwnd, want) {
            Step::Nothing => return,
            Step::NoteOff => {
                inner.last = Some((hwnd, Shield::Off));
                return;
            }
            Step::On => system::shield(hwnd),
            Step::Off => system::unshield(hwnd).map(|()| Shield::Off),
        };
        match set {
            Ok(shield) => {
                tracing::debug!(
                    why,
                    from = from.map_or("-", Shield::as_str),
                    to = shield.as_str(),
                    windows_build = ?windows_build(),
                    read_back = %system::read_back(hwnd),
                    "pairing shield: {}",
                    match shield {
                        Shield::Excluded =>
                            "the main window is left out of screen capture while the pairing \
                             panel is open (a viewer sees what is behind it)",
                        Shield::Blacked =>
                            "the main window is black in screen capture while the pairing panel is \
                             open (this Windows cannot leave it out)",
                        Shield::Off | Shield::FailedOn | Shield::FailedOff =>
                            "the main window is in the video again",
                    }
                );
                inner.last = Some((hwnd, shield));
            }
            Err(e) => {
                tracing::warn!(
                    why,
                    want,
                    "pairing shield not {}: {e}; {}",
                    if want { "put on" } else { "taken off" },
                    if want {
                        "the pairing code is in the video of whoever is connected"
                    } else {
                        "the main window stays out of the video"
                    }
                );
                // Not tried again every half second: until what is wanted changes ([`step`]).
                inner.last = Some((
                    hwnd,
                    if want {
                        Shield::FailedOn
                    } else {
                        Shield::FailedOff
                    },
                ));
            }
        }
    }
}

/// This Windows' build, read once (`pair_prompt::windows_build`); `None` when it cannot be read.
fn windows_build() -> Option<u32> {
    static BUILD: OnceLock<Option<u32>> = OnceLock::new();
    *BUILD.get_or_init(|| match crate::pair_prompt::windows_build() {
        Ok(build) => Some(build),
        Err(e) => {
            tracing::debug!("pairing shield: the Windows build unknown ({e})");
            None
        }
    })
}

/// What `WDA_EXCLUDEFROMCAPTURE` does on `build`: leaves the window out from Windows 10 2004 on,
/// blacks it before (as `WDA_MONITOR`). An unknown build is taken as a current one.
fn exclude_acts_as(build: Option<u32>) -> Shield {
    match build {
        Some(b) if b < EXCLUDE_FROM_CAPTURE_BUILD => Shield::Blacked,
        _ => Shield::Excluded,
    }
}

#[cfg(windows)]
mod system {
    use std::ffi::c_void;

    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowDisplayAffinity, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR,
        WDA_NONE,
    };

    use super::Shield;

    fn hwnd(window: usize) -> HWND {
        HWND(window as *mut c_void)
    }

    /// Leave the window out of captures — black in them on a Windows before 2004, where the value
    /// acts so ([`super::exclude_acts_as`]); `WDA_MONITOR` where the value is refused.
    pub(super) fn shield(window: usize) -> Result<Shield, String> {
        // SAFETY: a window of this process; a stale handle is refused.
        match unsafe { SetWindowDisplayAffinity(hwnd(window), WDA_EXCLUDEFROMCAPTURE) } {
            Ok(()) => Ok(super::exclude_acts_as(super::windows_build())),
            Err(excluded) => {
                tracing::debug!(
                    "pairing shield: WDA_EXCLUDEFROMCAPTURE refused ({excluded}); trying \
                     WDA_MONITOR"
                );
                // SAFETY: as above.
                unsafe { SetWindowDisplayAffinity(hwnd(window), WDA_MONITOR) }
                    .map(|()| Shield::Blacked)
                    .map_err(|monitor| {
                        format!("WDA_EXCLUDEFROMCAPTURE: {excluded}; WDA_MONITOR: {monitor}")
                    })
            }
        }
    }

    pub(super) fn unshield(window: usize) -> Result<(), String> {
        // SAFETY: as above.
        unsafe { SetWindowDisplayAffinity(hwnd(window), WDA_NONE) }
            .map_err(|e| format!("WDA_NONE: {e}"))
    }

    /// The affinity Windows reports for the window, for the log.
    pub(super) fn read_back(window: usize) -> String {
        let mut affinity = 0u32;
        // SAFETY: an out pointer to a local.
        match unsafe { GetWindowDisplayAffinity(hwnd(window), &mut affinity) } {
            Ok(()) => format!("{affinity:#x}"),
            Err(e) => format!("unread ({e})"),
        }
    }
}

#[cfg(not(windows))]
mod system {
    use super::Shield;

    pub(super) fn shield(_window: usize) -> Result<Shield, String> {
        Err("not on this platform".into())
    }

    pub(super) fn unshield(_window: usize) -> Result<(), String> {
        Ok(())
    }

    pub(super) fn read_back(_window: usize) -> String {
        "-".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Out of the video while the panel is anything but closed, or a code is shown.
    #[test]
    fn the_window_is_shielded_while_the_panel_is_open_or_a_code_shows() {
        assert!(!wanted("closed", false));
        for open in ["open", "redeemed", "paired"] {
            assert!(wanted(open, false), "{open}");
        }
        assert!(
            wanted("closed", true),
            "a code on screen, whatever the panel says"
        );
    }

    const W: usize = 0x1234;

    /// On and off as wanted, and nothing when it is so already.
    #[test]
    fn the_shield_goes_on_and_off_as_wanted() {
        assert_eq!(step(None, W, true), Step::On, "a window never touched");
        assert_eq!(step(None, W, false), Step::NoteOff, "in the video already");
        assert_eq!(step(Some((W, Shield::Off)), W, true), Step::On);
        assert_eq!(step(Some((W, Shield::Off)), W, false), Step::Nothing);
        for on in [Shield::Excluded, Shield::Blacked] {
            assert_eq!(step(Some((W, on)), W, true), Step::Nothing, "{on:?}");
            assert_eq!(step(Some((W, on)), W, false), Step::Off, "{on:?}");
        }
    }

    /// A refusal is not retried while what is wanted stays: a failed «on» is noted off without a
    /// call once not wanted (and tried again the next time it is), a failed «off» is tried again
    /// only when the shield is wanted once more.
    #[test]
    fn a_failure_is_not_retried_until_what_is_wanted_changes() {
        assert_eq!(step(Some((W, Shield::FailedOn)), W, true), Step::Nothing);
        assert_eq!(step(Some((W, Shield::FailedOn)), W, false), Step::NoteOff);
        assert_eq!(
            step(Some((W, Shield::Off)), W, true),
            Step::On,
            "then tried again"
        );
        assert_eq!(step(Some((W, Shield::FailedOff)), W, false), Step::Nothing);
        assert_eq!(step(Some((W, Shield::FailedOff)), W, true), Step::On);
    }

    /// A main window made anew (another handle) starts in the video: what was done to the old one
    /// says nothing of it.
    #[test]
    fn a_window_made_anew_is_judged_afresh() {
        let other = 0x9999;
        assert_eq!(step(Some((W, Shield::Excluded)), other, true), Step::On);
        assert_eq!(
            step(Some((W, Shield::Excluded)), other, false),
            Step::NoteOff
        );
        assert_eq!(step(Some((W, Shield::FailedOn)), other, true), Step::On);
    }

    /// A request for a code holds the shield on for three seconds whatever the state says; after
    /// that the state decides, and the hold is said to be over; `closing` (no hold) is the state's
    /// word at once.
    #[test]
    fn a_request_holds_the_shield_for_three_seconds() {
        let t0 = Instant::now();
        let until = Some(t0 + OPENING_HOLD);
        assert_eq!(wanted_now(false, until, t0), (true, false));
        assert_eq!(
            wanted_now(false, until, t0 + OPENING_HOLD - Duration::from_millis(1)),
            (true, false)
        );
        assert_eq!(wanted_now(false, until, t0 + OPENING_HOLD), (false, true));
        assert_eq!(wanted_now(true, until, t0 + OPENING_HOLD), (true, true));
        // Closed (the hold taken): the state's word.
        assert_eq!(wanted_now(false, None, t0), (false, false));
        assert_eq!(wanted_now(true, None, t0), (true, false));
        assert_eq!(OPENING_HOLD, Duration::from_secs(3));
    }

    /// One look waits on the main thread at a time: a word given while it waits is left for it, and
    /// it takes the latest; once it ran — or was not handed over after all — the next word hands
    /// over a new one.
    #[test]
    fn one_look_waits_on_the_main_thread_and_takes_the_latest_word() {
        let posted = Posted::default();
        assert!(posted.offer(true), "none waits: hand one over");
        assert!(!posted.offer(false), "one waits: it takes this");
        assert!(!posted.offer(true));
        assert!(!posted.offer(false));
        assert!(!posted.take(), "the latest word");
        assert!(posted.offer(true), "it ran: the next is handed over");
        posted.withdraw();
        assert!(posted.offer(false), "not handed over: none waits");
        assert!(!posted.take());
    }

    /// What the call does by the Windows build: left out from 2004 (19041) on, black before.
    #[test]
    fn the_mode_in_effect_follows_the_windows_build() {
        assert_eq!(exclude_acts_as(Some(18_363)), Shield::Blacked, "1909");
        assert_eq!(exclude_acts_as(Some(19_041)), Shield::Excluded, "2004");
        assert_eq!(exclude_acts_as(Some(26_100)), Shield::Excluded, "24H2");
        assert_eq!(exclude_acts_as(None), Shield::Excluded);
    }
}
