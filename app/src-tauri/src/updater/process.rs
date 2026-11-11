//! The Windows process calls the update needs: wait for a process by id, end one, and the named lock
//! that says a watchdog is alive.

use std::time::{Duration, Instant};

/// The name of the lock a running watchdog holds (the session's namespace: the app runs per user
/// session). Its existence is how the app knows a watchdog is at work; creating it is how a second
/// watchdog knows to stand down.
#[cfg(windows)]
const WATCHDOG_LOCK: &str = "Local\\AFKLink-update-watchdog";

/// How a wait for a process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    /// It exited after `waited`.
    Exited { waited: Duration },
    /// No such process (already gone).
    NotRunning,
    /// Still running when the time was up.
    TimedOut,
    /// It could not be waited for; why.
    Failed(String),
}

impl WaitOutcome {
    pub(crate) fn gone(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::NotRunning)
    }
}

/// A process opened by id: synchronize, terminate, and read its exit code.
#[cfg(windows)]
pub(crate) struct Process {
    handle: windows::Win32::Foundation::HANDLE,
    pid: u32,
}

// SAFETY: a process handle is a kernel object reference, usable from any thread.
#[cfg(windows)]
unsafe impl Send for Process {}

#[cfg(windows)]
impl Process {
    /// Open `pid` to wait for it, end it and read its exit code and image (the watchdog's).
    /// `Ok(None)` when there is no such process.
    pub(crate) fn open(pid: u32) -> Result<Option<Self>, String> {
        use windows::Win32::System::Threading::{
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };
        Self::open_with(
            pid,
            PROCESS_SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        )
    }

    /// Open `pid` only to wait for it ([`Self::wait`]) — no right to end it.
    pub(crate) fn open_to_wait(pid: u32) -> Result<Option<Self>, String> {
        use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
        Self::open_with(pid, PROCESS_SYNCHRONIZE)
    }

    /// Open `pid` only to read its image ([`Self::image`]).
    pub(crate) fn open_to_read(pid: u32) -> Result<Option<Self>, String> {
        use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;
        Self::open_with(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    }

    fn open_with(
        pid: u32,
        access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
    ) -> Result<Option<Self>, String> {
        use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
        use windows::Win32::System::Threading::OpenProcess;
        // SAFETY: plain call; the handle is owned by the returned value and closed on drop.
        match unsafe { OpenProcess(access, false, pid) } {
            Ok(handle) => Ok(Some(Self { handle, pid })),
            Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => Ok(None),
            Err(e) => Err(format!("open process {pid}: {e}")),
        }
    }

    /// The full path of its exe (`QueryFullProcessImageNameW`): opened with
    /// `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub(crate) fn image(&self) -> Result<std::path::PathBuf, String> {
        use windows::core::PWSTR;
        use windows::Win32::System::Threading::{QueryFullProcessImageNameW, PROCESS_NAME_WIN32};
        let mut buffer = vec![0u16; 32_768];
        let mut len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        // SAFETY: `buffer` is live and `len` holds its length in characters; a valid handle.
        unsafe {
            QueryFullProcessImageNameW(
                self.handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut len,
            )
        }
        .map_err(|e| format!("process {}: its image not read: {e}", self.pid))?;
        let len = usize::try_from(len).unwrap_or(0).min(buffer.len());
        Ok(std::path::PathBuf::from(String::from_utf16_lossy(
            &buffer[..len],
        )))
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// When it was created (`GetProcessTimes`, 100 ns since 1601): opened with
    /// `PROCESS_QUERY_LIMITED_INFORMATION`.
    pub(crate) fn created(&self) -> Result<u64, String> {
        created_of(self.handle).map_err(|e| format!("process {}: {e}", self.pid))
    }

    /// Wait up to `timeout` for it to exit: `true` if it has.
    pub(crate) fn wait(&self, timeout: Duration) -> Result<bool, String> {
        use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::WaitForSingleObject;
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: a valid handle opened with SYNCHRONIZE.
        let event = unsafe { WaitForSingleObject(self.handle, ms) };
        if event == WAIT_OBJECT_0 {
            Ok(true)
        } else if event == WAIT_TIMEOUT {
            Ok(false)
        } else {
            Err(format!(
                "wait for process {}: {}",
                self.pid,
                std::io::Error::last_os_error()
            ))
        }
    }

    /// Whether it is still running.
    pub(crate) fn alive(&self) -> bool {
        matches!(self.wait(Duration::ZERO), Ok(false))
    }

    /// Its exit code, once it has exited.
    pub(crate) fn exit_code(&self) -> Option<u32> {
        use windows::Win32::System::Threading::GetExitCodeProcess;
        const STILL_ACTIVE: u32 = 259;
        let mut code = 0u32;
        // SAFETY: a valid handle opened with PROCESS_QUERY_LIMITED_INFORMATION; `code` outlives it.
        match unsafe { GetExitCodeProcess(self.handle, &mut code) } {
            Ok(()) if code != STILL_ACTIVE => Some(code),
            _ => None,
        }
    }

    /// End it (exit code 1) and wait up to `timeout` for it to be gone.
    pub(crate) fn kill(&self, timeout: Duration) -> Result<(), String> {
        use windows::Win32::System::Threading::TerminateProcess;
        // SAFETY: a valid handle opened with PROCESS_TERMINATE.
        if let Err(e) = unsafe { TerminateProcess(self.handle, 1) } {
            // Already exiting is the usual reason; the wait below says whether it is gone.
            tracing::debug!(pid = self.pid, "TerminateProcess: {e}");
        }
        if self.wait(timeout)? {
            Ok(())
        } else {
            Err(format!(
                "process {} still running {} s after it was ended",
                self.pid,
                timeout.as_secs()
            ))
        }
    }
}

#[cfg(windows)]
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle is ours, closed once.
        if let Err(e) = unsafe { windows::Win32::Foundation::CloseHandle(self.handle) } {
            tracing::debug!(pid = self.pid, "process handle not closed: {e}");
        }
    }
}

/// The creation time of the process behind `handle` (100 ns since 1601).
#[cfg(windows)]
fn created_of(handle: windows::Win32::Foundation::HANDLE) -> Result<u64, String> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: a valid handle with the right to query; the four out-values outlive the call.
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(|e| format!("its creation time not read: {e}"))?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// When this process was created (100 ns since 1601).
#[cfg(windows)]
pub(crate) fn this_process_created() -> Result<u64, String> {
    // SAFETY: the pseudo-handle of this process; nothing to close.
    created_of(unsafe { windows::Win32::System::Threading::GetCurrentProcess() })
        .map_err(|e| format!("this process: {e}"))
}

/// Whether `a` and `b` name the same file: both resolved (`canonicalize`), else compared as written
/// without regard to case (Windows' paths).
pub(crate) fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy()),
    }
}

/// The exe of process `pid`; `Ok(None)` when there is no such process.
#[cfg(windows)]
pub(crate) fn image_of(pid: u32) -> Result<Option<std::path::PathBuf>, String> {
    match Process::open_to_read(pid)? {
        Some(p) => p.image().map(Some),
        None => Ok(None),
    }
}

#[cfg(not(windows))]
pub(crate) fn image_of(pid: u32) -> Result<Option<std::path::PathBuf>, String> {
    Err(format!(
        "process {pid}: reading an image is implemented on Windows only"
    ))
}

/// Wait for process `pid` to exit, up to `timeout` (a handle with the right to wait, no more).
#[cfg(windows)]
pub(crate) fn wait_for_exit(pid: u32, timeout: Duration) -> WaitOutcome {
    let started = Instant::now();
    match Process::open_to_wait(pid) {
        Ok(None) => WaitOutcome::NotRunning,
        Ok(Some(p)) => match p.wait(timeout) {
            Ok(true) => WaitOutcome::Exited {
                waited: started.elapsed(),
            },
            Ok(false) => WaitOutcome::TimedOut,
            Err(e) => WaitOutcome::Failed(e),
        },
        Err(e) => WaitOutcome::Failed(e),
    }
}

#[cfg(not(windows))]
pub(crate) fn wait_for_exit(pid: u32, timeout: Duration) -> WaitOutcome {
    let _ = (pid, timeout, Instant::now());
    WaitOutcome::Failed("waiting for a process is implemented on Windows only".into())
}

/// The watchdog's lock, held for the watchdog's life.
#[cfg(windows)]
pub(crate) struct WatchdogLock(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl WatchdogLock {
    /// Take the lock. `Ok(None)`: another watchdog holds it.
    pub(crate) fn acquire() -> Result<Option<Self>, String> {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows::Win32::System::Threading::CreateMutexW;
        let name = HSTRING::from(WATCHDOG_LOCK);
        // SAFETY: a NUL-terminated name that outlives the call; default security.
        let handle = unsafe { CreateMutexW(None, true, &name) }
            .map_err(|e| format!("create {WATCHDOG_LOCK}: {e}"))?;
        // SAFETY: read right after the call that set it.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: our handle to the existing object, closed once.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            return Ok(None);
        }
        Ok(Some(Self(handle)))
    }
}

#[cfg(windows)]
impl Drop for WatchdogLock {
    fn drop(&mut self) {
        // SAFETY: the handle is ours; releasing a mutex this thread owns, then closing it once.
        unsafe {
            let _ = windows::Win32::System::Threading::ReleaseMutex(self.0);
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

/// Whether a watchdog holds its lock right now.
#[cfg(windows)]
pub(crate) fn watchdog_alive() -> bool {
    use windows::core::HSTRING;
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    let name = HSTRING::from(WATCHDOG_LOCK);
    // SAFETY: a NUL-terminated name that outlives the call.
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, &name) } {
        Ok(handle) => {
            // SAFETY: ours, closed once.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
            true
        }
        Err(_) => false,
    }
}

#[cfg(not(windows))]
pub(crate) fn watchdog_alive() -> bool {
    false
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_process_that_exits_is_waited_for_and_its_code_read() {
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "exit", "7"])
            .spawn()
            .unwrap();
        let p = Process::open(child.id()).unwrap().unwrap();
        assert!(p.wait(Duration::from_secs(10)).unwrap());
        assert!(!p.alive());
        assert_eq!(p.exit_code(), Some(7));
        let _ = child.wait();
    }

    #[test]
    fn a_running_process_is_ended() {
        // `ping` itself, not through `cmd /c`: ending cmd.exe left its `ping` child running with
        // the test binary's stderr, and the test run waited ~25 s for it. Nothing inherited either.
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let p = Process::open(child.id()).unwrap().unwrap();
        assert!(p.alive());
        assert_eq!(
            wait_for_exit(child.id(), Duration::from_millis(50)),
            WaitOutcome::TimedOut
        );
        p.kill(Duration::from_secs(10)).unwrap();
        assert_eq!(p.exit_code(), Some(1));
        let _ = child.wait();
    }

    /// A process's image and creation time are read; a child is created after this
    /// process. (Ending only this exe's older process: `updater::tests`.)
    #[test]
    fn a_process_image_and_creation_time_are_read() {
        let own = image_of(std::process::id())
            .expect("read")
            .expect("this process runs");
        assert!(same_file(&own, &std::env::current_exe().expect("this exe")));
        let mut child = std::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let p = Process::open(child.id()).unwrap().unwrap();
        let its = p.image().expect("its image");
        assert!(!same_file(&its, &own), "{}", its.display());
        let ours = this_process_created().expect("this process's creation time");
        assert!(p.created().expect("its creation time") > ours);
        p.kill(Duration::from_secs(10)).unwrap();
        let _ = child.wait();
    }

    #[test]
    fn no_such_process_is_not_running() {
        // Process ids are multiples of four; this one is never handed out.
        assert_eq!(Process::open(3).unwrap().map(|p| p.pid()), None);
        assert_eq!(
            wait_for_exit(3, Duration::from_secs(1)),
            WaitOutcome::NotRunning
        );
    }
}
