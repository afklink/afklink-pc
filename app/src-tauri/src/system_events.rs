//! What Windows says about the session and the power state, and the goodbye to the backend each
//! word calls for (`afklink_core::goodbye`).
//!
//! | Windows says                                        | the agent                                |
//! |-----------------------------------------------------|------------------------------------------|
//! | `WM_QUERYENDSESSION` (log off, shut down, restart;   | goodbye `shutdown`, at once; the live    |
//! | the Restart Manager closing apps)                   | sessions carry on                        |
//! | `WM_ENDSESSION`, the session ends                   | live sessions ended, then goodbye        |
//! |                                                     | `shutdown` if not said yet               |
//! | `WM_ENDSESSION`, the end was cancelled              | welcome back: reconnect                  |
//! | `WM_POWERBROADCAST` `PBT_APMSUSPEND`                 | goodbye `sleep`, at once                 |
//! | `PBT_APMRESUMEAUTOMATIC` / `PBT_APMRESUMESUSPEND`   | welcome back: reconnect                  |
//!
//! `WM_QUERYENDSESSION` is the earliest word of a shutdown, while the network is still up — later,
//! a VPN may already be gone and the goodbye with it. It is always
//! answered TRUE: nothing here keeps the session from ending. The goodbye waits at most
//! [`afklink_core::GOODBYE_BUDGET`] inside the message, well within the seconds Windows allows for an
//! answer (and the two it allows a suspend).
//!
//! It is only a question, though: another application may refuse, and the end is then cancelled
//! (`WM_ENDSESSION` FALSE). So the live sessions are ended — the input released, the journal's
//! «Приложение закрыто», `session_end agent_ended` — only when the end is certain: `WM_ENDSESSION`
//! TRUE here, or the app's own exit (`RunEvent::Exit`, the tray's «Выход», an update's exit). By
//! then the goodbye has closed the connection, so their ends go nowhere and the server ends them as
//! `agent_disconnected` with `goodbye:shutdown` (ending them at the question would cut every viewer
//! off on a shutdown that is then cancelled).
//!
//! Heard by a hidden window of this app's own, on a thread of its own:
//! - a GUI process gets no console control events (`CTRL_SHUTDOWN_EVENT`, `CTRL_LOGOFF_EVENT` go
//!   only to processes that have not loaded user32);
//! - tao (Tauri's window layer) does not handle `WM_QUERYENDSESSION` at all, ends its loop on
//!   `WM_ENDSESSION` (that is `RunEvent::Exit`, where the exit's own goodbye finds this one said),
//!   and its windows live on the main thread, which may be busy when Windows asks;
//! - a message-only window (`HWND_MESSAGE`) gets no broadcasts, so this is a hidden top-level popup,
//!   as Chromium's power monitor makes one; `RegisterSuspendResumeNotification` asks for the
//!   suspend and resume messages besides, which modern-standby systems send only to those who ask.

use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use std::sync::OnceLock;

use afklink_core::GoodbyeReason;
#[cfg(windows)]
use afklink_core::{AgentControl, GOODBYE_BUDGET};

/// The window messages and their parameters, as `windows` defines them (held to it by a test).
const WM_QUERYENDSESSION: u32 = 0x0011;
const WM_ENDSESSION: u32 = 0x0016;
const WM_POWERBROADCAST: u32 = 0x0218;
const PBT_APMSUSPEND: usize = 0x0004;
const PBT_APMRESUMESUSPEND: usize = 0x0007;
const PBT_APMRESUMEAUTOMATIC: usize = 0x0012;
const ENDSESSION_CLOSEAPP: u32 = 0x0000_0001;
const ENDSESSION_CRITICAL: u32 = 0x4000_0000;
const ENDSESSION_LOGOFF: u32 = 0x8000_0000;

/// Set at the first word that the Windows session is ending, cleared if the end is cancelled: the
/// exit that follows (`RunEvent::Exit`) is then a shutdown's, not the owner's quit.
static SESSION_ENDING: AtomicBool = AtomicBool::new(false);

/// What kind of session end Windows announced (`lParam` of `WM_QUERYENDSESSION`/`WM_ENDSESSION`).
/// No flag at all is a shutdown or a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndFlags {
    pub(crate) logoff: bool,
    pub(crate) close_app: bool,
    pub(crate) critical: bool,
}

impl EndFlags {
    fn from_lparam(lparam: isize) -> Self {
        // The flags are the low 32 bits.
        let bits = lparam as u32;
        Self {
            logoff: bits & ENDSESSION_LOGOFF != 0,
            close_app: bits & ENDSESSION_CLOSEAPP != 0,
            critical: bits & ENDSESSION_CRITICAL != 0,
        }
    }

    /// For the log.
    fn what(self) -> &'static str {
        match (self.close_app, self.logoff, self.critical) {
            (true, _, _) => "an installer or the Restart Manager closing apps",
            (_, true, _) => "a log off",
            (_, _, true) => "a forced shutdown (critical: Windows does not wait for answers)",
            _ => "a shutdown or a restart",
        }
    }
}

/// One word from Windows that matters to the agent's presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemEvent {
    /// `WM_QUERYENDSESSION`: the session is about to end.
    SessionEnding(EndFlags),
    /// `WM_ENDSESSION`: the session ends now (`ending`), or its end was cancelled.
    SessionEnd { ending: bool, flags: EndFlags },
    /// `PBT_APMSUSPEND`: the system is going to sleep.
    Suspending,
    /// `PBT_APMRESUMEAUTOMATIC` (`automatic`) or `PBT_APMRESUMESUSPEND`: it is back.
    Resumed { automatic: bool },
}

/// The window message `msg` as a [`SystemEvent`], or `None` when it is not one.
pub(crate) fn classify(msg: u32, wparam: usize, lparam: isize) -> Option<SystemEvent> {
    match msg {
        WM_QUERYENDSESSION => Some(SystemEvent::SessionEnding(EndFlags::from_lparam(lparam))),
        WM_ENDSESSION => Some(SystemEvent::SessionEnd {
            ending: wparam != 0,
            flags: EndFlags::from_lparam(lparam),
        }),
        WM_POWERBROADCAST => match wparam {
            PBT_APMSUSPEND => Some(SystemEvent::Suspending),
            PBT_APMRESUMEAUTOMATIC => Some(SystemEvent::Resumed { automatic: true }),
            PBT_APMRESUMESUSPEND => Some(SystemEvent::Resumed { automatic: false }),
            _ => None,
        },
        _ => None,
    }
}

/// What the agent does about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Response {
    /// Say goodbye with this reason (and hold off reconnecting); the live sessions carry on — a
    /// shutdown asked about may yet be cancelled, and a sleep is no exit.
    Goodbye(GoodbyeReason),
    /// The process is leaving for certain: end every live session, then say goodbye (if not said
    /// yet) with this reason.
    Leave(GoodbyeReason),
    /// The reason for being away is over: reconnect (`why`, for the log).
    WelcomeBack(&'static str),
}

/// The response to `event`; also notes a session end for [`exit_reason`].
pub(crate) fn respond(event: SystemEvent) -> Response {
    match event {
        SystemEvent::SessionEnding(_) => {
            SESSION_ENDING.store(true, Ordering::SeqCst);
            Response::Goodbye(GoodbyeReason::Shutdown)
        }
        SystemEvent::SessionEnd { ending: true, .. } => {
            SESSION_ENDING.store(true, Ordering::SeqCst);
            Response::Leave(GoodbyeReason::Shutdown)
        }
        SystemEvent::SessionEnd { ending: false, .. } => {
            SESSION_ENDING.store(false, Ordering::SeqCst);
            Response::WelcomeBack("Windows cancelled the end of the session")
        }
        SystemEvent::Suspending => Response::Goodbye(GoodbyeReason::Sleep),
        SystemEvent::Resumed { .. } => Response::WelcomeBack("the system resumed from sleep"),
    }
}

/// The goodbye's reason for the app's exit (`RunEvent::Exit`): a shutdown's when Windows is ending
/// the session (tao ends its loop on `WM_ENDSESSION`), else the owner's quit. An update's exit and a
/// shutdown said theirs before it, and find it said.
pub(crate) fn exit_reason() -> GoodbyeReason {
    if SESSION_ENDING.load(Ordering::SeqCst) {
        GoodbyeReason::Shutdown
    } else {
        GoodbyeReason::Quit
    }
}

/// The agent the window's procedure answers for. Set once, by [`start`].
#[cfg(windows)]
static CONTROL: OnceLock<AgentControl> = OnceLock::new();

/// Hear Windows from now on, on a thread of its own; `control` says the goodbyes and welcomes back.
/// Failing to (which only a broken system does) is logged and costs only the goodbyes.
#[cfg(windows)]
pub(crate) fn start(control: AgentControl) {
    if CONTROL.set(control).is_err() {
        tracing::warn!("system events: started twice; the first listener stays");
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("afklink-system-events".into())
        .spawn(win::run);
    if let Err(e) = spawned {
        tracing::warn!(
            "system events: the listening thread did not start ({e}): no goodbye at shutdown or \
             sleep; the backend learns of them from its heartbeat"
        );
    }
}

#[cfg(not(windows))]
pub(crate) fn start(_control: afklink_core::AgentControl) {
    tracing::debug!("system events: not on Windows; nothing to listen to");
}

/// Act on `event`, from the window's procedure: log it, then say goodbye or welcome back.
#[cfg(windows)]
fn handle(event: SystemEvent) {
    match event {
        SystemEvent::SessionEnding(flags) => tracing::info!(
            ?flags,
            what = flags.what(),
            "Windows: the session is about to end (WM_QUERYENDSESSION)"
        ),
        SystemEvent::SessionEnd {
            ending: true,
            flags,
        } => tracing::info!(
            ?flags,
            what = flags.what(),
            "Windows: the session is ending (WM_ENDSESSION)"
        ),
        SystemEvent::SessionEnd {
            ending: false,
            flags,
        } => tracing::info!(
            ?flags,
            "Windows: the end of the session was cancelled (WM_ENDSESSION, FALSE)"
        ),
        SystemEvent::Suspending => {
            tracing::info!("Windows: the system is going to sleep (PBT_APMSUSPEND)");
        }
        SystemEvent::Resumed { automatic } => tracing::info!(
            automatic,
            "Windows: the system resumed ({})",
            if automatic {
                "PBT_APMRESUMEAUTOMATIC"
            } else {
                "PBT_APMRESUMESUSPEND: someone is at the PC"
            }
        ),
    }
    // The run state's word for it (`afklink_core::run_state`), first — the process may not live to
    // the exit's own record: a session ending is this process's `os_shutdown` from its first word;
    // a cancelled end takes it back. Sleep is no exit.
    match event {
        SystemEvent::SessionEnding(_) => afklink_core::run_state::record_exit(
            afklink_core::run_state::ExitKind::OsShutdown,
            "WM_QUERYENDSESSION",
        ),
        SystemEvent::SessionEnd { ending: true, .. } => afklink_core::run_state::record_exit(
            afklink_core::run_state::ExitKind::OsShutdown,
            "WM_ENDSESSION",
        ),
        SystemEvent::SessionEnd { ending: false, .. } => {
            afklink_core::run_state::take_back_exit("WM_ENDSESSION FALSE: the end was cancelled");
        }
        SystemEvent::Suspending | SystemEvent::Resumed { .. } => {}
    }
    let Some(control) = CONTROL.get() else {
        tracing::warn!("system events: no agent to tell");
        return;
    };
    match respond(event) {
        // Both log their outcomes themselves and are bounded by the budgets.
        Response::Goodbye(reason) => {
            let outcome = control.goodbye_blocking(reason, GOODBYE_BUDGET);
            tracing::debug!(
                reason = reason.as_str(),
                outcome = outcome.kind(),
                "system events: goodbye done, the live sessions carry on (a shutdown asked about \
                 may be cancelled; a sleep is no exit); answering Windows"
            );
        }
        Response::Leave(reason) => {
            let outcome = control.leave_blocking(reason, GOODBYE_BUDGET);
            tracing::debug!(
                reason = reason.as_str(),
                outcome = outcome.kind(),
                "system events: Windows ends the session: the live sessions ended, goodbye done; \
                 answering Windows"
            );
        }
        Response::WelcomeBack(why) => {
            control.welcome_back(why);
        }
    }
}

#[cfg(windows)]
mod win {
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Power::RegisterSuspendResumeNotification;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
        TranslateMessage, DEVICE_NOTIFY_WINDOW_HANDLE, MSG, WNDCLASSW, WS_EX_NOACTIVATE, WS_POPUP,
    };

    use super::{classify, handle};

    const CLASS: PCWSTR = w!("AFKLinkSystemEvents");

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if let Some(event) = classify(msg, wparam.0, lparam.0) {
            handle(event);
            // WM_QUERYENDSESSION: TRUE, the session may end. WM_POWERBROADCAST: TRUE, the documented
            // answer. WM_ENDSESSION: 0, processed.
            return LRESULT(if msg == super::WM_ENDSESSION { 0 } else { 1 });
        }
        // SAFETY: the default handling of any other message of this window, with its own arguments.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    /// The thread: the window, the registration, and the message loop for the process's life.
    pub(super) fn run() {
        // SAFETY: the module handle of this executable; nothing is freed.
        let module = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("system events: GetModuleHandleW failed ({e}); not listening");
                return;
            }
        };
        let instance = HINSTANCE::from(module);
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: CLASS,
            ..Default::default()
        };
        // SAFETY: a filled class description whose strings are static.
        if unsafe { RegisterClassW(&class) } == 0 {
            tracing::warn!(
                "system events: RegisterClassW failed ({}); not listening",
                std::io::Error::last_os_error()
            );
            return;
        }
        // SAFETY: the class just registered; no parent, menu or creation data. A top-level popup,
        // never shown (no WS_VISIBLE) nor activated: a message-only window would get no broadcasts.
        let hwnd = match unsafe {
            CreateWindowExW(
                WS_EX_NOACTIVATE,
                CLASS,
                w!("AFKLink system events"),
                WS_POPUP,
                0,
                0,
                0,
                0,
                None,
                None,
                Some(instance),
                None,
            )
        } {
            Ok(hwnd) => hwnd,
            Err(e) => {
                tracing::warn!("system events: CreateWindowExW failed ({e}); not listening");
                return;
            }
        };
        // Suspend and resume straight to this window too: on a modern-standby system only those
        // who ask hear them. Without it the broadcast still comes on ordinary sleep.
        // SAFETY: our own window, alive for the process's life; the registration is never undone.
        match unsafe {
            RegisterSuspendResumeNotification(HANDLE(hwnd.0), DEVICE_NOTIFY_WINDOW_HANDLE)
        } {
            Ok(_) => {
                tracing::debug!("system events: registered for suspend and resume notifications")
            }
            Err(e) => tracing::warn!(
                "system events: RegisterSuspendResumeNotification failed ({e}); the sleep \
                 broadcast is still heard on ordinary sleep"
            ),
        }
        tracing::info!(
            "system events: listening for the end of the Windows session, sleep and resume (the \
             goodbye to the backend)"
        );
        let mut msg = MSG::default();
        loop {
            // SAFETY: a message for this thread into our own MSG.
            let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
            match got.0 {
                0 => {
                    tracing::debug!("system events: WM_QUIT; the listening thread ends");
                    return;
                }
                -1 => {
                    tracing::warn!(
                        "system events: GetMessageW failed ({}); the listening thread ends",
                        std::io::Error::last_os_error()
                    );
                    return;
                }
                _ => {
                    // SAFETY: the message GetMessageW just filled.
                    unsafe {
                        let _ = TranslateMessage(&msg);
                        let _ = DispatchMessageW(&msg);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every word maps to its event and its response; anything else is not one.
    #[test]
    fn windows_words_map_to_goodbyes_and_welcomes() {
        let shutdown = classify(WM_QUERYENDSESSION, 0, 0).expect("an event");
        assert_eq!(
            shutdown,
            SystemEvent::SessionEnding(EndFlags {
                logoff: false,
                close_app: false,
                critical: false,
            })
        );
        assert_eq!(
            respond(shutdown),
            Response::Goodbye(GoodbyeReason::Shutdown),
            "only the goodbye: the question may be answered no by another application, and the \
             live sessions must outlive a cancelled shutdown"
        );
        assert_eq!(
            exit_reason(),
            GoodbyeReason::Shutdown,
            "the exit is a shutdown's"
        );

        // A log off, flagged in the high bit; as a negative isize, the way it arrives on 32 bits.
        let logoff = classify(WM_QUERYENDSESSION, 0, ENDSESSION_LOGOFF as i32 as isize);
        assert!(matches!(
            logoff,
            Some(SystemEvent::SessionEnding(EndFlags { logoff: true, .. }))
        ));
        assert!(matches!(
            classify(
                WM_QUERYENDSESSION,
                0,
                (ENDSESSION_CLOSEAPP | ENDSESSION_CRITICAL) as isize
            ),
            Some(SystemEvent::SessionEnding(EndFlags {
                close_app: true,
                critical: true,
                logoff: false
            }))
        ));

        let cancelled = classify(WM_ENDSESSION, 0, 0).expect("an event");
        assert!(matches!(
            cancelled,
            SystemEvent::SessionEnd { ending: false, .. }
        ));
        assert!(matches!(respond(cancelled), Response::WelcomeBack(_)));
        assert_eq!(
            exit_reason(),
            GoodbyeReason::Quit,
            "cancelled: a later exit is a quit"
        );

        let ending = classify(WM_ENDSESSION, 1, 0).expect("an event");
        assert_eq!(
            respond(ending),
            Response::Leave(GoodbyeReason::Shutdown),
            "the end is certain: the sessions end, then the goodbye"
        );
        assert_eq!(exit_reason(), GoodbyeReason::Shutdown);
        // Back to the owner's quit for whatever runs after this test.
        respond(SystemEvent::SessionEnd {
            ending: false,
            flags: EndFlags::from_lparam(0),
        });

        let suspend = classify(WM_POWERBROADCAST, PBT_APMSUSPEND, 0).expect("an event");
        assert_eq!(suspend, SystemEvent::Suspending);
        assert_eq!(respond(suspend), Response::Goodbye(GoodbyeReason::Sleep));
        for (pbt, automatic) in [
            (PBT_APMRESUMEAUTOMATIC, true),
            (PBT_APMRESUMESUSPEND, false),
        ] {
            let resumed = classify(WM_POWERBROADCAST, pbt, 0).expect("an event");
            assert_eq!(resumed, SystemEvent::Resumed { automatic });
            assert!(matches!(respond(resumed), Response::WelcomeBack(_)));
        }
        // Battery and power-setting broadcasts, and any other message, are not ours.
        assert_eq!(classify(WM_POWERBROADCAST, 0x000A, 0), None);
        assert_eq!(classify(WM_POWERBROADCAST, 0x8013, 0), None);
        assert_eq!(classify(0x0010, 0, 0), None, "WM_CLOSE");
        assert_eq!(exit_reason(), GoodbyeReason::Quit);

        // A shutdown asked about and then cancelled by another application: no step of it ends a
        // live session, and the agent reconnects.
        let asked = respond(classify(WM_QUERYENDSESSION, 0, 0).expect("an event"));
        let cancelled = respond(classify(WM_ENDSESSION, 0, 0).expect("an event"));
        assert_eq!(asked, Response::Goodbye(GoodbyeReason::Shutdown));
        assert!(matches!(cancelled, Response::WelcomeBack(_)));
        assert!(
            ![asked, cancelled]
                .iter()
                .any(|r| matches!(r, Response::Leave(_))),
            "nothing ends the sessions"
        );
        assert_eq!(exit_reason(), GoodbyeReason::Quit);
    }

    /// The numbers here are Windows' own.
    #[cfg(windows)]
    #[test]
    fn the_constants_are_windows_own() {
        use windows::Win32::UI::WindowsAndMessaging as wm;
        assert_eq!(WM_QUERYENDSESSION, wm::WM_QUERYENDSESSION);
        assert_eq!(WM_ENDSESSION, wm::WM_ENDSESSION);
        assert_eq!(WM_POWERBROADCAST, wm::WM_POWERBROADCAST);
        assert_eq!(PBT_APMSUSPEND as u32, wm::PBT_APMSUSPEND);
        assert_eq!(PBT_APMRESUMESUSPEND as u32, wm::PBT_APMRESUMESUSPEND);
        assert_eq!(PBT_APMRESUMEAUTOMATIC as u32, wm::PBT_APMRESUMEAUTOMATIC);
        assert_eq!(ENDSESSION_CLOSEAPP, wm::ENDSESSION_CLOSEAPP);
        assert_eq!(ENDSESSION_CRITICAL, wm::ENDSESSION_CRITICAL);
        assert_eq!(ENDSESSION_LOGOFF, wm::ENDSESSION_LOGOFF);
    }
}
