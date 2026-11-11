//! Before the single-instance lock: whether a running AFKLink answers at all.
//!
//! The single-instance plugin hands a second launch to the running instance with `SendMessageW`
//! (`WM_COPYDATA` to its hidden window), which waits for as long as that instance's main thread
//! does not take it. A first instance hung in its main thread («Не отвечает») so holds every later
//! launch forever — a process with no window and no log line, and the owner's next try adds
//! another.
//!
//! So first, with nothing taken yet:
//!
//! 1. the plugin's lock (the named mutex `{identifier}-sim`) is looked for: none, no running
//!    instance — the plugin will make this one the first;
//! 2. the plugin's window (`{identifier}-sic` / `{identifier}-siw`) is looked for, and its owner's
//!    exe read: a window that is not this exe's — any program can make one of that name — is said
//!    (`warn`) and left alone, and this launch goes on (a window anyone can make must not be a way
//!    to keep AFKLink from starting);
//! 3. a `WM_NULL` is sent to it with `SendMessageTimeoutW` (`SMTO_ABORTIFHUNG`, at most
//!    [`PROBE_TIMEOUT`]). It answers: the plugin hands the launch over as usual. It does not: this
//!    launch says so in the log and exits ([`EXIT_HUNG_INSTANCE`]) rather than hang behind it. A
//!    window Windows already counts as hung (no messages taken for 5 s) fails at once; a first
//!    instance merely busy — its WebView2 starting cold at sign-in while the owner clicks the icon —
//!    has the whole timeout to answer.
//!
//! On the main thread before Tauri starts: a wait of at most [`PROBE_TIMEOUT`], nothing held.

use std::path::Path;
use std::time::{Duration, Instant};

/// Tauri's identifier (`tauri.conf.json`), which names the plugin's window; a test keeps them equal.
pub(crate) const IDENTIFIER: &str = "com.afklink.agent";

/// How long the running instance has to answer. Its main thread answers within milliseconds when it
/// is idle, and within a few seconds when it is busy starting (WebView2's cold start at sign-in); a
/// main thread Windows counts as hung fails at once (`SMTO_ABORTIFHUNG`), so this is for one that is
/// stuck yet still taking messages now and then.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The exit code of a launch that found the running instance hung.
pub(crate) const EXIT_HUNG_INSTANCE: i32 = 4;

/// What the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Probe {
    /// No running instance (its lock is not held): this is the first.
    NoInstance,
    /// The lock is held but there is no window to hand the launch to.
    NoWindow,
    /// The window is another program's (its owner's exe, when read; why it was not): left alone.
    Foreign { pid: u32, image: String },
    /// The running instance answered, after this long.
    Answers { after: Duration },
    /// It did not answer within the time (or Windows already knows it hung): `error` is Windows'
    /// word for why.
    Unanswered { error: String, after: Duration },
}

/// Probe the running instance, named as the plugin names its lock and window after `identifier`;
/// `our_exe` is the exe a window of ours runs.
pub(crate) fn probe(identifier: &str, our_exe: &Path, timeout: Duration) -> Probe {
    probe_window(
        &format!("{identifier}-sim"),
        &format!("{identifier}-sic"),
        &format!("{identifier}-siw"),
        our_exe,
        timeout,
    )
}

#[cfg(windows)]
fn probe_window(mutex: &str, class: &str, title: &str, our_exe: &Path, timeout: Duration) -> Probe {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{CloseHandle, GetLastError, LPARAM, WPARAM};
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, GetWindowThreadProcessId, SendMessageTimeoutW, SMTO_ABORTIFHUNG, SMTO_BLOCK,
        WM_NULL,
    };

    // SAFETY: a NUL-terminated name that outlives the call.
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(mutex)) } {
        Ok(handle) => {
            // SAFETY: ours, closed once.
            if let Err(e) = unsafe { CloseHandle(handle) } {
                tracing::debug!("instance probe: the lock's handle not closed: {e}");
            }
        }
        Err(e) => {
            tracing::trace!("instance probe: the single-instance lock not open ({e})");
            return Probe::NoInstance;
        }
    }
    // SAFETY: two valid, NUL-terminated wide strings that outlive the call.
    let found = unsafe { FindWindowW(&HSTRING::from(class), &HSTRING::from(title)) };
    let Ok(hwnd) = found else {
        return Probe::NoWindow;
    };
    let mut pid = 0u32;
    // SAFETY: `hwnd` came from FindWindowW (one gone since makes the call return 0); `pid` outlives
    // the call.
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    match crate::updater::process_image(pid) {
        Ok(Some(image)) if crate::updater::same_file(&image, our_exe) => {}
        Ok(Some(image)) => {
            return Probe::Foreign {
                pid,
                image: image.display().to_string(),
            }
        }
        Ok(None) => return Probe::NoWindow,
        Err(e) => {
            return Probe::Foreign {
                pid,
                image: format!("not read: {e}"),
            }
        }
    }
    let started = Instant::now();
    let mut result = 0usize;
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: `hwnd` came from FindWindowW (a window that is gone makes the call fail, which is
    // handled); WM_NULL carries nothing; `result` outlives the call.
    let answered = unsafe {
        SendMessageTimeoutW(
            hwnd,
            WM_NULL,
            WPARAM(0),
            LPARAM(0),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            ms,
            Some(&mut result),
        )
    };
    let after = started.elapsed();
    if answered.0 != 0 {
        Probe::Answers { after }
    } else {
        // SAFETY: reads this thread's last error, set by the call above.
        let error = unsafe { GetLastError() };
        Probe::Unanswered {
            error: format!("{error:?}"),
            after,
        }
    }
}

#[cfg(not(windows))]
fn probe_window(
    _mutex: &str,
    _class: &str,
    _title: &str,
    _our_exe: &Path,
    _timeout: Duration,
) -> Probe {
    Probe::NoInstance
}

/// What a launch does after the probe: go on, or exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Then {
    GoOn,
    Exit,
}

/// Say what the probe found, and whether this launch goes on.
pub(crate) fn judge(found: &Probe, timeout: Duration) -> Then {
    match found {
        Probe::NoInstance => {
            tracing::debug!("instance probe: no running AFKLink; this is the first instance");
            Then::GoOn
        }
        Probe::NoWindow => {
            tracing::debug!(
                "instance probe: the single-instance lock is held but no AFKLink window answers to \
                 its name; the lock decides"
            );
            Then::GoOn
        }
        Probe::Foreign { pid, image } => {
            tracing::warn!(
                pid,
                %image,
                "instance probe: a window under AFKLink's single-instance name belongs to another \
                 program; not probed — this launch goes on"
            );
            Then::GoOn
        }
        Probe::Answers { after } => {
            tracing::debug!(
                after_ms = after.as_millis() as u64,
                "instance probe: a running AFKLink answers; the single-instance lock hands this \
                 launch to it"
            );
            Then::GoOn
        }
        Probe::Unanswered { error, after } => {
            tracing::error!(
                %error,
                after_ms = after.as_millis() as u64,
                timeout_ms = timeout.as_millis() as u64,
                exit_code = EXIT_HUNG_INSTANCE,
                "instance probe: the running AFKLink did not answer within {} s (its window thread \
                 is stuck, or Windows counts it as hung): this launch exits rather than wait behind \
                 it; the running one is left as it is",
                timeout.as_secs()
            );
            Then::Exit
        }
    }
}

/// Probe before the single-instance plugin, say what was found, and exit when the running instance
/// does not answer. `flush` closes the log on the way out.
pub(crate) fn check_or_exit(flush: impl FnOnce()) {
    let found = match std::env::current_exe() {
        Ok(exe) => probe(IDENTIFIER, &exe, PROBE_TIMEOUT),
        Err(e) => {
            tracing::warn!(
                "instance probe: this exe's path is unknown ({e}); not probed — the single-instance \
                 lock decides"
            );
            return;
        }
    };
    if judge(&found, PROBE_TIMEOUT) == Then::Exit {
        flush();
        std::process::exit(EXIT_HUNG_INSTANCE);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, PeekMessageW,
        RegisterClassW, MSG, PM_REMOVE, WINDOW_EX_STYLE, WNDCLASSW, WS_OVERLAPPED,
    };

    /// The window's names follow the identifier Tauri is built with.
    #[test]
    fn the_identifier_is_tauris() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json");
        assert_eq!(conf["identifier"].as_str(), Some(IDENTIFIER));
    }

    fn this_exe() -> std::path::PathBuf {
        std::env::current_exe().expect("this exe")
    }

    /// The plugin's lock `{id}-sim`, held while the value lives.
    struct Lock(HANDLE);
    impl Lock {
        fn take(id: &str) -> Self {
            use windows::Win32::System::Threading::CreateMutexW;
            // SAFETY: a NUL-terminated name that outlives the call; default security.
            let handle = unsafe { CreateMutexW(None, true, &HSTRING::from(format!("{id}-sim"))) }
                .expect("mutex");
            Self(handle)
        }
    }
    impl Drop for Lock {
        fn drop(&mut self) {
            // SAFETY: ours, released and closed once.
            unsafe {
                let _ = windows::Win32::System::Threading::ReleaseMutex(self.0);
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    unsafe extern "system" fn proc(h: HWND, m: u32, w: WPARAM, l: LPARAM) -> LRESULT {
        // SAFETY: the default procedure for this window's own messages.
        unsafe { DefWindowProcW(h, m, w, l) }
    }

    /// A window `id` on a thread of its own, which goes through `phases` — `(pumps, how long)`: it
    /// takes its messages, or is stuck (sleeps) — then destroys it.
    fn window(id: &str, phases: Vec<(bool, Duration)>) -> std::thread::JoinHandle<()> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let class = HSTRING::from(format!("{id}-sic"));
        let title = HSTRING::from(format!("{id}-siw"));
        let handle = std::thread::spawn(move || {
            // SAFETY: a class and a window of this test's own, on this thread, destroyed below.
            unsafe {
                let instance = GetModuleHandleW(PCWSTR::null()).expect("module");
                let wc = WNDCLASSW {
                    lpfnWndProc: Some(proc),
                    hInstance: instance.into(),
                    lpszClassName: PCWSTR(class.as_ptr()),
                    ..Default::default()
                };
                assert_ne!(RegisterClassW(&wc), 0, "class registered");
                let hwnd = CreateWindowExW(
                    WINDOW_EX_STYLE(0),
                    &class,
                    &title,
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    None,
                    None,
                    Some(instance.into()),
                    None,
                )
                .expect("window");
                ready_tx.send(()).expect("ready");
                let mut msg = MSG::default();
                for (pumps, lasting) in phases {
                    if pumps {
                        let until = Instant::now() + lasting;
                        while Instant::now() < until {
                            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                                DispatchMessageW(&msg);
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    } else {
                        std::thread::sleep(lasting);
                    }
                }
                let _ = DestroyWindow(hwnd);
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the window is up");
        handle
    }

    /// No lock: no instance, even with a window of that name about (the window alone is
    /// anyone's to make).
    #[test]
    fn no_lock_is_no_instance() {
        let id = format!("afklink-probe-test-nolock-{}", std::process::id());
        assert_eq!(
            probe(&id, &this_exe(), Duration::from_millis(200)),
            Probe::NoInstance
        );
        let stuck = window(&id, vec![(false, Duration::from_secs(1))]);
        assert_eq!(
            probe(&id, &this_exe(), Duration::from_millis(200)),
            Probe::NoInstance
        );
        stuck.join().expect("window");
    }

    /// A window whose thread pumps its messages answers; one whose thread is stuck does not, and
    /// the probe gives up at its timeout instead of hanging; with the lock and no window, the lock
    /// decides.
    #[test]
    fn a_stuck_window_is_unanswered_and_a_live_one_answers() {
        let pid = std::process::id();
        let live = format!("afklink-probe-test-live-{pid}");
        let _lock = Lock::take(&live);
        assert_eq!(
            probe(&live, &this_exe(), Duration::from_millis(200)),
            Probe::NoWindow
        );
        let pumping = window(&live, vec![(true, Duration::from_secs(3))]);
        assert!(
            matches!(
                probe(&live, &this_exe(), Duration::from_secs(2)),
                Probe::Answers { .. }
            ),
            "a pumping window answers"
        );
        pumping.join().expect("live window");

        let stuck = format!("afklink-probe-test-stuck-{pid}");
        let _lock = Lock::take(&stuck);
        let blocked = window(&stuck, vec![(false, Duration::from_secs(2))]);
        let started = Instant::now();
        let found = probe(&stuck, &this_exe(), Duration::from_millis(300));
        match &found {
            Probe::Unanswered { after, .. } => {
                assert!(*after < Duration::from_millis(1500), "{after:?}")
            }
            other => panic!("a stuck window does not answer: {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert_eq!(judge(&found, Duration::from_millis(300)), Then::Exit);
        blocked.join().expect("stuck window");
    }

    /// A first instance busy for a few seconds (WebView2's cold start), then taking its messages
    /// again, is waited for — it answers, and this launch goes on to be handed to it. Only a probe
    /// past the whole timeout exits.
    #[test]
    fn a_busy_first_instance_is_waited_for_within_the_longer_timeout() {
        const { assert!(PROBE_TIMEOUT.as_secs() >= 10) };
        let id = format!("afklink-probe-test-busy-{}", std::process::id());
        let _lock = Lock::take(&id);
        let busy = window(
            &id,
            vec![
                (false, Duration::from_secs(3)),
                (true, Duration::from_secs(2)),
            ],
        );
        let found = probe(&id, &this_exe(), PROBE_TIMEOUT);
        match &found {
            Probe::Answers { after } => {
                assert!(*after >= Duration::from_secs(2), "it was busy: {after:?}");
                assert!(*after < PROBE_TIMEOUT, "{after:?}");
            }
            other => panic!("a busy instance answers within the timeout: {other:?}"),
        }
        assert_eq!(judge(&found, PROBE_TIMEOUT), Then::GoOn);
        busy.join().expect("busy window");
    }

    /// A stuck window under the plugin's names that is not this exe's — any program can make
    /// one — is not probed, and the launch goes on.
    #[test]
    fn a_window_of_another_program_is_left_alone_and_the_launch_goes_on() {
        let id = format!("afklink-probe-test-foreign-{}", std::process::id());
        let _lock = Lock::take(&id);
        let stuck = window(&id, vec![(false, Duration::from_secs(1))]);
        let other_exe = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        let started = Instant::now();
        let found = probe(&id, other_exe, Duration::from_secs(5));
        assert!(
            matches!(found, Probe::Foreign { pid, .. } if pid == std::process::id()),
            "{found:?}"
        );
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "not waited for"
        );
        assert_eq!(judge(&found, PROBE_TIMEOUT), Then::GoOn);
        stuck.join().expect("window");
    }
}
