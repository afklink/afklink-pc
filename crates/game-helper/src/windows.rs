//! The helper on Windows: its directory and token, the app's signal, the process snapshot, the
//! windows, the launch, the focus, and closing a hung game.

use std::mem::size_of;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use windows::core::{BOOL, HSTRING, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_ELEVATION_REQUIRED,
    ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES, FILETIME, HANDLE, HWND, LPARAM, WAIT_OBJECT_0,
    WAIT_TIMEOUT, WPARAM,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid, TokenElevation,
    TokenIntegrityLevel, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetPriorityClass,
    GetProcessTimes, OpenEventW, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    SetPriorityClass, TerminateProcess, WaitForSingleObject, ABOVE_NORMAL_PRIORITY_CLASS,
    BELOW_NORMAL_PRIORITY_CLASS, HIGH_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    SYNCHRONIZATION_SYNCHRONIZE,
};
use windows::Win32::UI::Accessibility::{CUIAutomation8, IUIAutomation, IUIAutomation2};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetForegroundWindow, GetGUIThreadInfo, GetWindowTextW,
    GetWindowThreadProcessId, IsHungAppWindow, IsIconic, IsWindow, IsWindowVisible, PostMessageW,
    SetForegroundWindow, ShowWindowAsync, GUITHREADINFO, GUI_INMENUMODE, GUI_POPUPMENUMODE,
    GUI_SYSTEMMENUMODE, SW_RESTORE, WM_CLOSE,
};

use crate::log::{unix_ms, HelperLog, Level, Log};
use crate::record::{file_name, same_path, Record, RunLevel};
use crate::supervisor::{
    slow_tick, CloseRequest, ClosedWindow, Desktop, FocusMethod, FocusOutcome, Foreground,
    GameProcess, GameWindow, HelperState, LaunchError, Observation, Signal, StateFile, Supervisor,
    TerminateOutcome, POLL, STATE_FORMAT, TERMINATE_EXIT_CODE,
};
use crate::{RECORD_FILE, SIGNAL_NAME, STATE_FILE, STATE_REFRESH, USER_DIR};

/// Exit codes, for the task's history: the helper otherwise runs until the task stops it.
const EXIT_NO_DIRECTORY: i32 = 3;
const EXIT_NO_RECORD: i32 = 4;
const EXIT_NO_COM: i32 = 5;

/// After TerminateProcess the helper's tick waits at most this long for the exit code: Windows ends
/// a process asynchronously, usually within milliseconds; one stuck in the kernel is seen to go on
/// the following ticks.
const TERMINATE_WAIT: Duration = Duration::from_millis(500);

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: each Handle owns one open kernel handle; a failed close leaves nothing to do.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct Com;
impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: paired on this thread with a successful CoInitializeEx.
        unsafe { CoUninitialize() };
    }
}

/// The token is elevated: the helper runs from a HIGHEST task (or UAC is off altogether).
fn token_elevated() -> Result<bool, String> {
    let mut token = HANDLE::default();
    // SAFETY: this process's own token, query access, a live output.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("open the process token: {e}"))?;
    let token = Handle(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0;
    // SAFETY: a TOKEN_ELEVATION-sized output for TokenElevation.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    }
    .map_err(|e| format!("read the token's elevation: {e}"))?;
    Ok(elevation.TokenIsElevated != 0)
}

/// A process token's integrity level: the last sub-authority of its mandatory label's SID.
/// `process` needs `PROCESS_QUERY_LIMITED_INFORMATION`.
fn integrity_of(process: HANDLE) -> Result<u32, String> {
    let mut token = HANDLE::default();
    // SAFETY: an open process handle (or the current pseudo-handle), query access, a live output.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("open its token: {e}"))?;
    let token = Handle(token);
    // A TOKEN_MANDATORY_LABEL and the SID it points to (at most 68 bytes), 8-byte aligned.
    let mut buffer = [0u64; 16];
    let mut len = 0;
    // SAFETY: a writable buffer of the size given, aligned for TOKEN_MANDATORY_LABEL.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast()),
            size_of_val(&buffer) as u32,
            &mut len,
        )
    }
    .map_err(|e| format!("read its integrity level: {e}"))?;
    let size = size_of_val(&buffer);
    let written = len as usize;
    if written < size_of::<TOKEN_MANDATORY_LABEL>() || written > size {
        return Err(format!(
            "its integrity level came as {written} bytes (a label takes {}, the buffer {size})",
            size_of::<TOKEN_MANDATORY_LABEL>()
        ));
    }
    // SAFETY: `written` bytes at the start of the buffer are Windows' TOKEN_MANDATORY_LABEL —
    // checked above to be at least its size and within the buffer, which is 8-byte aligned for it.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid };
    let start = buffer.as_ptr() as usize;
    let at = sid.0 as usize;
    if sid.0.is_null() || at < start || at >= start + written {
        return Err(format!(
            "its integrity label's SID is not inside what Windows wrote ({at:#x}, the buffer at \
             {start:#x}, {written} bytes)"
        ));
    }
    // SAFETY: a non-null pointer into the bytes Windows wrote, in the live buffer; IsValidSid
    // only reads the SID's header and sub-authorities, which Windows wrote there with it.
    if !unsafe { IsValidSid(sid) }.as_bool() {
        return Err("its integrity label's SID is not valid".to_string());
    }
    // SAFETY: a SID IsValidSid accepted, in the live buffer: its count and its sub-authorities
    // (indices below the count) are inside it.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        if count == 0 {
            return Err("its integrity label has no sub-authority".to_string());
        }
        Ok(*GetSidSubAuthority(sid, u32::from(count - 1)))
    }
}

fn process_integrity(pid: u32) -> Result<u32, String> {
    // SAFETY: only the limited query right, which OpenProcessToken accepts.
    let process = Handle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|e| format!("not opened ({e})"))?,
    );
    integrity_of(process.0)
}

/// An integrity level as Windows names it, with its value.
fn integrity_name(rid: u32) -> String {
    let name = match rid {
        0x0000 => "untrusted",
        0x1000 => "low",
        0x2000 => "medium",
        0x2100 => "medium plus",
        0x3000 => "high",
        0x4000 => "system",
        0x5000 => "protected process",
        _ => "other",
    };
    format!("{name} ({rid:#x})")
}

/// The app's signal, opened and closed again on every tick: holding it would keep the object alive
/// after the app is gone, and the signal must fail closed.
fn read_signal() -> Signal {
    // SAFETY: a named object in this session's namespace, opened for waiting only.
    match unsafe {
        OpenEventW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            &HSTRING::from(SIGNAL_NAME),
        )
    } {
        Ok(handle) => {
            let handle = Handle(handle);
            // SAFETY: a zero timeout on the handle just opened: a test, not a wait.
            match unsafe { WaitForSingleObject(handle.0, 0) } {
                WAIT_OBJECT_0 => Signal::Allowed,
                WAIT_TIMEOUT => Signal::NotSet,
                other => Signal::Unreadable(format!(
                    "wait answered {:#x}: {}",
                    other.0,
                    std::io::Error::last_os_error()
                )),
            }
        }
        Err(e) if e.code() == ERROR_FILE_NOT_FOUND.to_hresult() => Signal::Absent,
        Err(e) => Signal::Unreadable(e.to_string()),
    }
}

/// A process priority class as Task Manager names it.
fn priority_name(class: u32) -> String {
    [
        (IDLE_PRIORITY_CLASS, "idle"),
        (BELOW_NORMAL_PRIORITY_CLASS, "below normal"),
        (NORMAL_PRIORITY_CLASS, "normal"),
        (ABOVE_NORMAL_PRIORITY_CLASS, "above normal"),
        (HIGH_PRIORITY_CLASS, "high"),
    ]
    .into_iter()
    .find(|(flag, _)| flag.0 == class)
    .map_or_else(|| format!("{class:#x}"), |(_, name)| name.to_string())
}

/// The helper's own priority class, said at its start — and raised to normal when it is below. The
/// setup registers its task at priority 5 (normal); at Task Scheduler's default, 7 (below normal),
/// the helper's ticks took 16–25 s under a full CPU, and the game it launched ran below normal too.
/// A task at 7 is an older setup's or one changed by hand (the app asks for the setup again over a
/// record without the priority).
fn note_priority(log: &mut impl Log) {
    // SAFETY: this process's own pseudo-handle, a read-only query.
    let class = unsafe { GetPriorityClass(GetCurrentProcess()) };
    if class == 0 {
        log.line(
            Level::Warn,
            &format!(
                "this process's priority class not read: {}",
                std::io::Error::last_os_error()
            ),
        );
        return;
    }
    if class != IDLE_PRIORITY_CLASS.0 && class != BELOW_NORMAL_PRIORITY_CLASS.0 {
        log.line(
            Level::Info,
            &format!("priority class {}", priority_name(class)),
        );
        return;
    }
    // SAFETY: this process's own pseudo-handle; raising a class to normal needs no privilege.
    match unsafe { SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS) } {
        Ok(()) => log.line(
            Level::Warn,
            &format!(
                "priority class {} (its task's priority is below normal): raised to normal, so \
                 ticks stay short on a loaded PC",
                priority_name(class)
            ),
        ),
        Err(e) => log.line(
            Level::Warn,
            &format!(
                "priority class {} (its task's priority is below normal) not raised to normal \
                 ({e}): ticks may take seconds on a loaded PC",
                priority_name(class)
            ),
        ),
    }
}

fn session_of(pid: u32) -> Result<u32, windows::core::Error> {
    let mut id = 0;
    // SAFETY: a query with a live output.
    unsafe { ProcessIdToSessionId(pid, &mut id) }?;
    Ok(id)
}

/// Why a process's path is not known.
enum Unknown {
    /// It ended in the meantime: skip it.
    Gone,
    /// It is there and cannot be read: maybe the game.
    Denied,
}

fn unknown(e: &windows::core::Error) -> Unknown {
    if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
        Unknown::Denied
    } else {
        // ERROR_INVALID_PARAMETER (no such process) and the like: it is not there any more.
        Unknown::Gone
    }
}

fn process_path(pid: u32) -> Result<String, windows::core::Error> {
    // SAFETY: only the limited query right, which Windows grants for most processes.
    let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }?);
    image_path(process.0)
}

/// The full path of an open process's exe.
fn image_path(process: HANDLE) -> Result<String, windows::core::Error> {
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer is writable for `len` characters; the caller keeps the process open.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }?;
    Ok(String::from_utf16_lossy(&buffer[..len as usize]))
}

/// When an open process started, in 100 ns units since 1601.
fn started_at(process: HANDLE) -> Result<u64, windows::core::Error> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four live outputs; the caller keeps the process open (limited query right).
    unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) }?;
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

/// An ended process's exit code; `None` when it cannot be read.
fn exit_code(process: HANDLE) -> Option<u32> {
    let mut code = 0;
    // SAFETY: a live output; the caller keeps the process open.
    unsafe { GetExitCodeProcess(process, &mut code) }
        .ok()
        .map(|()| code)
}

fn text(buffer: &[u16]) -> String {
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

fn class_of(hwnd: HWND) -> String {
    let mut class = [0u16; 256];
    // SAFETY: a writable buffer of its own size.
    let len = unsafe { GetClassNameW(hwnd, &mut class) }.max(0) as usize;
    String::from_utf16_lossy(&class[..len.min(class.len())])
}

/// A window's title. For another process's window Windows reads it without a message to the
/// window: a hung one cannot hold the caller.
fn title_of(hwnd: HWND) -> String {
    let mut title = [0u16; 512];
    // SAFETY: a writable buffer of its own size.
    let len = unsafe { GetWindowTextW(hwnd, &mut title) }.max(0) as usize;
    String::from_utf16_lossy(&title[..len.min(title.len())])
}

fn pid_of(hwnd: HWND) -> (u32, u32) {
    let mut pid = 0;
    // SAFETY: a read-only query with a live output.
    let thread = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    (pid, thread)
}

/// AFKLink's own processes: `afklink-app.exe`, the portable `AFKLink-<version>….exe`, the
/// `AFKLink.exe` the bot sends.
fn is_afklink(exe: &str) -> bool {
    let name = file_name(exe).to_ascii_lowercase();
    name.starts_with("afklink") && name.ends_with(".exe")
}

struct Search<'a> {
    record: &'a Record,
    pids: &'a [u32],
    foreground: HWND,
    window: Option<HWND>,
}

unsafe extern "system" fn find_window(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: EnumWindows is synchronous; `data` points to its caller's live Search.
    let search = unsafe { &mut *(data.0 as *mut Search<'_>) };
    let (pid, _) = pid_of(hwnd);
    // SAFETY: a read-only query.
    if !search.pids.contains(&pid) || !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        return BOOL(1);
    }
    if search.record.class_matches(&class_of(hwnd))
        // The one in front, if two match: no switching between two of the game's windows.
        && (search.window.is_none() || hwnd == search.foreground)
    {
        search.window = Some(hwnd);
    }
    BOOL(1)
}

/// The visible top-level windows of some processes: what a hung game's `WM_CLOSE` goes to.
struct Owned<'a> {
    pids: &'a [u32],
    found: Vec<(HWND, u32)>,
}

unsafe extern "system" fn list_owned(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: EnumWindows is synchronous; `data` points to its caller's live Owned.
    let owned = unsafe { &mut *(data.0 as *mut Owned<'_>) };
    let (pid, _) = pid_of(hwnd);
    // SAFETY: a read-only query.
    if owned.pids.contains(&pid) && unsafe { IsWindowVisible(hwnd) }.as_bool() {
        owned.found.push((hwnd, pid));
    }
    BOOL(1)
}

struct WindowsDesktop {
    session: u32,
    automation: Option<IUIAutomation>,
    child: Option<Child>,
    /// The game's processes whose integrity level has been said ([`Self::note_integrity`]).
    integrity_noted: Vec<u32>,
}

impl WindowsDesktop {
    /// The caller keeps this thread's COM apartment alive while the desktop lives. UI Automation
    /// that does not start leaves SetForegroundWindow as the only way, and says so.
    fn new(log: &mut impl Log) -> Result<Self, String> {
        // SAFETY: this process's own id.
        let session = session_of(unsafe { GetCurrentProcessId() })
            .map_err(|e| format!("this process's session: {e}"))?;
        let automation = match uia() {
            Ok(a) => Some(a),
            Err(e) => {
                log.line(
                    Level::Warn,
                    &format!(
                        "UI Automation unavailable ({e}): focus can only be tried with \
                         SetForegroundWindow"
                    ),
                );
                None
            }
        };
        Ok(Self {
            session,
            automation,
            child: None,
            integrity_noted: Vec::new(),
        })
    }

    /// The integrity level of each of the game's processes about to be closed, once per process,
    /// beside the helper's own: a `WM_CLOSE` refused (UIPI) or a TerminateProcess denied is then
    /// told from the log. Kernel queries only — nothing waits on the game.
    fn note_integrity(&mut self, pids: &[u32], notes: &mut Vec<String>) {
        self.integrity_noted.retain(|pid| pids.contains(pid));
        let fresh: Vec<u32> = pids
            .iter()
            .copied()
            .filter(|pid| !self.integrity_noted.contains(pid))
            .collect();
        if fresh.is_empty() {
            return;
        }
        // SAFETY: this process's own pseudo-handle, which needs no closing.
        let own = integrity_of(unsafe { GetCurrentProcess() })
            .map_or_else(|e| format!("not read ({e})"), integrity_name);
        for pid in fresh {
            let game =
                process_integrity(pid).map_or_else(|e| format!("not read ({e})"), integrity_name);
            notes.push(format!(
                "integrity level of pid {pid}: {game}; of the helper: {own}"
            ));
            self.integrity_noted.push(pid);
        }
    }

    /// Wait up to `within` for a window of `pid` to be in front.
    fn front_within(pid: u32, within: Duration) -> bool {
        let until = Instant::now() + within;
        loop {
            // SAFETY: a read-only query.
            let front = unsafe { GetForegroundWindow() };
            if !front.is_invalid() && pid_of(front).0 == pid {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// One of the game's processes as it is now: in this session, its full path one of the record's
    /// two exes, and when it started. `Err`: why it is not (gone, another session or exe, unread).
    fn game_process(&self, record: &Record, pid: u32) -> Result<GameProcess, String> {
        match session_of(pid) {
            Ok(session) if session == self.session => {}
            Ok(session) => return Err(format!("in another Windows session ({session})")),
            Err(e) => return Err(format!("its session not read ({e})")),
        }
        // SAFETY: only the limited query right.
        let process = Handle(
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
                .map_err(|e| format!("not opened ({e})"))?,
        );
        let path = image_path(process.0).map_err(|e| format!("its path not read ({e})"))?;
        if !record.is_game_exe(&path) {
            return Err(format!("not the game's exe any more ({path})"));
        }
        let started = started_at(process.0).map_err(|e| format!("its start not read ({e})"))?;
        Ok(GameProcess { pid, path, started })
    }

    fn foreground(&self, game: &[u32]) -> Foreground {
        // SAFETY: a read-only query.
        let front = unsafe { GetForegroundWindow() };
        if front.is_invalid() {
            return Foreground::Nothing;
        }
        let (pid, thread) = pid_of(front);
        if pid == 0 {
            return Foreground::Nothing;
        }
        if game.contains(&pid) {
            return Foreground::Game;
        }
        let window = front.0 as usize;
        let exe = match process_path(pid) {
            Ok(path) => path,
            Err(e) => {
                return Foreground::Unreadable {
                    window,
                    error: e.to_string(),
                }
            }
        };
        let name = file_name(&exe).to_string();
        if is_afklink(&exe) {
            return Foreground::AfkLink { exe: name };
        }
        let mut info = GUITHREADINFO {
            cbSize: size_of::<GUITHREADINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: a correctly sized output for the front window's thread.
        if unsafe { GetGUIThreadInfo(thread, &mut info) }.is_ok()
            && info.flags.0 & (GUI_INMENUMODE.0 | GUI_POPUPMENUMODE.0 | GUI_SYSTEMMENUMODE.0) != 0
        {
            return Foreground::Menu { exe: name };
        }
        Foreground::Other { window, exe: name }
    }
}

fn uia() -> Result<IUIAutomation, String> {
    // SAFETY: the in-process UI Automation client; COM is initialized on this thread.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|e| e.to_string())?;
    let bounded: IUIAutomation2 =
        windows::core::Interface::cast(&automation).map_err(|e| e.to_string())?;
    // SAFETY: only this client's timeouts: a hung game cannot hold the helper's loop.
    unsafe {
        bounded
            .SetConnectionTimeout(500)
            .map_err(|e| e.to_string())?;
        bounded
            .SetTransactionTimeout(500)
            .map_err(|e| e.to_string())?;
    }
    Ok(automation)
}

impl Desktop for WindowsDesktop {
    fn signal(&mut self) -> Signal {
        read_signal()
    }

    fn now(&mut self) -> Instant {
        Instant::now()
    }

    fn observe(&mut self, record: &Record) -> Result<Observation, String> {
        let launched_exit = match self.child.as_mut().map(|c| (c.id(), c.try_wait())) {
            None | Some((_, Ok(None))) => None,
            Some((pid, Ok(Some(status)))) => {
                self.child = None;
                Some((pid, status.code()))
            }
            Some((pid, Err(_))) => {
                self.child = None;
                Some((pid, None))
            }
        };
        let names = [
            file_name(&record.launch_exe).to_lowercase(),
            file_name(&record.window_exe).to_lowercase(),
        ];
        // SAFETY: a process snapshot; no process memory is read.
        let snapshot = Handle(
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
                .map_err(|e| format!("process snapshot: {e}"))?,
        );
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut game_pids = Vec::new();
        let mut loader_pids = Vec::new();
        let mut unreadable = Vec::new();
        // SAFETY: a correctly sized entry and a live snapshot.
        let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        loop {
            match next {
                Ok(()) => {}
                Err(e) if e.code() == ERROR_NO_MORE_FILES.to_hresult() => break,
                Err(e) => return Err(format!("process list: {e}")),
            }
            let pid = entry.th32ProcessID;
            if names.contains(&text(&entry.szExeFile).to_lowercase()) {
                let path = session_of(pid)
                    .map_err(|e| unknown(&e))
                    .and_then(|session| {
                        if session == self.session {
                            process_path(pid).map(Some).map_err(|e| unknown(&e))
                        } else {
                            Ok(None)
                        }
                    });
                match path {
                    Ok(Some(path)) if record.is_game_exe(&path) => {
                        game_pids.push(pid);
                        if record.is_loader(&path) {
                            loader_pids.push(pid);
                        }
                    }
                    // Another session's, or the same name in another folder: not the game.
                    Ok(_) | Err(Unknown::Gone) => {}
                    Err(Unknown::Denied) => unreadable.push(pid),
                }
            }
            // SAFETY: as above.
            next = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        game_pids.sort_unstable();
        loader_pids.sort_unstable();
        unreadable.sort_unstable();
        // SAFETY: a read-only query.
        let front = unsafe { GetForegroundWindow() };
        let mut search = Search {
            record,
            pids: &game_pids,
            foreground: front,
            window: None,
        };
        // SAFETY: the callback reads windows and the live Search only.
        unsafe {
            EnumWindows(
                Some(find_window),
                LPARAM((&mut search as *mut Search<'_>) as isize),
            )
        }
        .map_err(|e| format!("window list: {e}"))?;
        let window = search.window.map(|hwnd| GameWindow {
            id: hwnd.0 as usize,
            pid: pid_of(hwnd).0,
            // SAFETY: a read-only query.
            minimized: unsafe { IsIconic(hwnd) }.as_bool(),
        });
        let foreground = self.foreground(&game_pids);
        Ok(Observation {
            game_pids,
            loader_pids,
            unreadable,
            window,
            foreground,
            launched_exit,
        })
    }

    fn close_windows(&mut self, record: &Record, pids: &[u32]) -> CloseRequest {
        let mut request = CloseRequest::default();
        for &pid in pids {
            match self.game_process(record, pid) {
                Ok(process) => request.processes.push(process),
                Err(why) => request.skipped.push((pid, why)),
            }
        }
        let confirmed: Vec<u32> = request.processes.iter().map(|p| p.pid).collect();
        if confirmed.is_empty() {
            return request;
        }
        self.note_integrity(&confirmed, &mut request.notes);
        let mut owned = Owned {
            pids: &confirmed,
            found: Vec::new(),
        };
        // SAFETY: the callback reads windows into the live Owned only.
        if let Err(e) = unsafe {
            EnumWindows(
                Some(list_owned),
                LPARAM((&mut owned as *mut Owned<'_>) as isize),
            )
        } {
            request.windows_error = Some(e.to_string());
        }
        for (hwnd, pid) in owned.found {
            let class = class_of(hwnd);
            let title = title_of(hwnd);
            // The supervisor read the signal right before this call; the processes and windows
            // were checked since, which a loaded PC can make slow: read again before each message.
            let signal = read_signal();
            // Handles are reused: still that process's window right before the message.
            let (owner, thread) = pid_of(hwnd);
            let posted = if signal != Signal::Allowed {
                Err(format!(
                    "the app's signal went off right before it: {}",
                    signal.describe()
                ))
            } else if owner == pid {
                // SAFETY: a message posted, not sent, to a window of the game's process just
                // checked: a hung window cannot hold the helper. WM_CLOSE is what its close
                // button does — the game decides.
                unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)) }.map_err(|e| {
                    // Why it may be refused, for the next report: whose thread the window is, and
                    // whether Windows takes it for hung (a read of its state, no message to it).
                    // SAFETY: a read-only query.
                    let hung = unsafe { IsHungAppWindow(hwnd) }.as_bool();
                    format!(
                        "{e}; the window's thread {thread} of pid {owner}, IsHungAppWindow: {}",
                        if hung { "yes" } else { "no" }
                    )
                })
            } else {
                Err("the window was gone before the message".to_string())
            };
            request.windows.push(ClosedWindow {
                pid,
                window: hwnd.0 as usize,
                class,
                title,
                posted,
            });
        }
        request
    }

    fn terminate(&mut self, record: &Record, process: &GameProcess) -> TerminateOutcome {
        let pid = process.pid;
        // SAFETY: the rights to end, read and wait for this one process — used only after the
        // checks below, on this same handle: while it is open, its id names no other process.
        let handle = match unsafe {
            OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        } {
            Ok(handle) => Handle(handle),
            // Refused the right to end it. Still the same process: a refusal; else it is gone.
            Err(e) if e.code() == ERROR_ACCESS_DENIED.to_hresult() => {
                return match self.game_process(record, pid) {
                    Ok(now) if now.started == process.started => {
                        TerminateOutcome::Denied(e.to_string())
                    }
                    Ok(now) => TerminateOutcome::NotTheGame(format!(
                        "its id is another process's now ({})",
                        now.path
                    )),
                    Err(why) => TerminateOutcome::NotTheGame(why),
                };
            }
            Err(e) => return TerminateOutcome::NotTheGame(format!("not there any more ({e})")),
        };
        match session_of(pid) {
            Ok(session) if session == self.session => {}
            Ok(session) => {
                return TerminateOutcome::NotTheGame(format!(
                    "in another Windows session ({session})"
                ))
            }
            Err(e) => return TerminateOutcome::NotTheGame(format!("its session not read ({e})")),
        }
        match image_path(handle.0) {
            Ok(path) if same_path(&path, &process.path) && record.is_game_exe(&path) => {}
            Ok(path) => {
                return TerminateOutcome::NotTheGame(format!("another exe now ({path})"));
            }
            Err(e) => return TerminateOutcome::NotTheGame(format!("its path not read ({e})")),
        }
        match started_at(handle.0) {
            Ok(started) if started == process.started => {}
            Ok(_) => {
                return TerminateOutcome::NotTheGame(
                    "its id is another process's now (another start time)".to_string(),
                )
            }
            Err(e) => return TerminateOutcome::NotTheGame(format!("its start not read ({e})")),
        }
        // SAFETY: a zero-timeout test on our own handle.
        if unsafe { WaitForSingleObject(handle.0, 0) } == WAIT_OBJECT_0 {
            return TerminateOutcome::AlreadyEnded(exit_code(handle.0));
        }
        // SAFETY: the game's own process, checked on this very handle just above.
        if let Err(e) = unsafe { TerminateProcess(handle.0, TERMINATE_EXIT_CODE) } {
            return if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
                TerminateOutcome::Denied(e.to_string())
            } else {
                TerminateOutcome::Failed(e.to_string())
            };
        }
        // SAFETY: a short wait on our own handle: the tick is held at most this long.
        match unsafe { WaitForSingleObject(handle.0, TERMINATE_WAIT.as_millis() as u32) } {
            WAIT_OBJECT_0 => TerminateOutcome::Ended(exit_code(handle.0)),
            _ => TerminateOutcome::Requested,
        }
    }

    fn launch(&mut self, exe: &str) -> Result<u32, LaunchError> {
        let path = Path::new(exe);
        let mut command = Command::new(path);
        if let Some(folder) = path.parent() {
            command.current_dir(folder);
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // At normal priority, as from Explorer: a process started without a priority class
            // takes the helper's own when that is below normal, and a task registered at the
            // default priority runs the helper, and so the game, below normal.
            .creation_flags(NORMAL_PRIORITY_CLASS.0);
        match command.spawn() {
            Ok(child) => {
                let pid = child.id();
                // Kept for its exit code only (the log's); dropping it does not end the game.
                self.child = Some(child);
                Ok(pid)
            }
            Err(e) if e.raw_os_error() == Some(ERROR_ELEVATION_REQUIRED.0 as i32) => {
                Err(LaunchError::ElevationRequired)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(LaunchError::NotFound(e.to_string()))
            }
            Err(e) => Err(LaunchError::Other(e.to_string())),
        }
    }

    fn focus(&mut self, record: &Record, window: GameWindow) -> FocusOutcome {
        let refused = |detail: String| FocusOutcome {
            method: None,
            detail,
        };
        let hwnd = HWND(window.id as *mut _);
        // Handles are reused: check it is still the game's window right before acting.
        // SAFETY: read-only queries.
        if !unsafe { IsWindow(Some(hwnd)) }.as_bool() {
            return refused("the game's window closed before the try".into());
        }
        let (pid, _) = pid_of(hwnd);
        let still_game = session_of(pid).is_ok_and(|s| s == self.session)
            && process_path(pid).is_ok_and(|p| record.is_game_exe(&p))
            && record.class_matches(&class_of(hwnd));
        if !still_game {
            return refused("the window is not the game's any more".into());
        }
        let mut steps = Vec::new();
        if window.minimized {
            // SAFETY: restore the game's own, just checked, window; no input is synthesized.
            let was_visible = unsafe { ShowWindowAsync(hwnd, SW_RESTORE) }.as_bool();
            steps.push(format!("restored (ShowWindowAsync={was_visible})"));
        }
        // SAFETY: activate the game's window. No input is synthesized, no input queue attached, no
        // foreground lock changed: Windows grants it or refuses (and flashes the taskbar button).
        let granted = unsafe { SetForegroundWindow(hwnd) }.as_bool();
        if Self::front_within(pid, Duration::from_millis(150)) {
            steps.push(format!("SetForegroundWindow={granted}, in front"));
            return FocusOutcome {
                method: Some(FocusMethod::SetForeground),
                detail: steps.join("; "),
            };
        }
        steps.push(format!("SetForegroundWindow={granted}, not in front"));
        match &self.automation {
            None => steps.push("UI Automation unavailable".into()),
            Some(automation) => {
                // SAFETY: UI Automation's own focus call on the checked window, with the
                // client's bounded timeouts.
                let set = unsafe { automation.ElementFromHandle(hwnd) }
                    .and_then(|element| unsafe { element.SetFocus() });
                match set {
                    Ok(()) if Self::front_within(pid, Duration::from_millis(250)) => {
                        steps.push("UI Automation SetFocus ok, in front".into());
                        return FocusOutcome {
                            method: Some(FocusMethod::Uia),
                            detail: steps.join("; "),
                        };
                    }
                    Ok(()) => steps.push("UI Automation SetFocus ok, not in front".into()),
                    Err(e) => steps.push(format!("UI Automation SetFocus: {e}")),
                }
            }
        }
        refused(steps.join("; "))
    }
}

/// The directory the helper writes in: its install directory when it runs elevated (only
/// administrators write there), else `user\` beside it, which the setup made writable for the
/// owner — a helper without rights cannot write into Program Files, and an elevated one never
/// writes where the owner's other programs could.
fn data_dir(install: &Path, elevated: bool) -> PathBuf {
    if elevated {
        install.to_path_buf()
    } else {
        install.join(USER_DIR)
    }
}

/// Where the helper writes, and whether it counts itself elevated there: by its token; when the
/// token cannot be read, by the run level the record gives its task (HIGHEST → the install
/// directory, the only one such an installation has; LUA → `user\`). With neither, `user\`, where
/// an unelevated helper writes. The third value is the line that says so in the log, when the
/// token was not read.
fn data_place(
    install: &Path,
    token: &Result<bool, String>,
    record_level: Option<RunLevel>,
) -> (PathBuf, bool, Option<String>) {
    match (token, record_level) {
        (Ok(elevated), _) => (data_dir(install, *elevated), *elevated, None),
        (Err(e), Some(level)) => {
            let elevated = level == RunLevel::Highest;
            let dir = data_dir(install, elevated);
            let why = format!(
                "the token's elevation not read ({e}): writes in {} by the record's run level {}",
                dir.display(),
                level.as_str()
            );
            (dir, elevated, Some(why))
        }
        (Err(e), None) => {
            let dir = data_dir(install, false);
            let why = format!(
                "the token's elevation not read ({e}) and no readable record: writes in {}, where \
                 a helper without rights would",
                dir.display()
            );
            (dir, false, Some(why))
        }
    }
}

/// `state.json`, through a temporary file. A state that cannot be serialized writes no file — an
/// empty one would read as a broken state — and comes back as the error the caller logs.
fn write_state(dir: &Path, state: &StateFile) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::other(format!("the state not serialized: {e}")))?;
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, dir.join(STATE_FILE))
}

/// The `state.json` the helper's last run left in `dir`: `Ok(None)` when there is none (the first
/// start after a setup, which removes it).
fn previous_state(dir: &Path) -> Result<Option<StateFile>, String> {
    match std::fs::read(dir.join(STATE_FILE)) {
        Ok(bytes) => StateFile::parse(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{STATE_FILE} not read: {e}")),
    }
}

fn state_only(state: HelperState, reason: &str, elevated: bool) -> StateFile {
    let now = unix_ms(SystemTime::now());
    StateFile {
        format: STATE_FORMAT,
        state,
        reason: reason.to_string(),
        since_ms: now,
        updated_ms: now,
        pid: std::process::id(),
        elevated,
        launches: 0,
        failed_starts: 0,
        focus_set_foreground: 0,
        focus_uia: 0,
        focus_refused: 0,
        launch_pending: false,
        failed_launch_since_ms: None,
    }
}

pub(crate) fn run() -> i32 {
    let Some(install) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    else {
        return EXIT_NO_DIRECTORY;
    };
    // The record first — it is in the install directory, which everyone reads: when the token
    // cannot be read, its run level says where this helper can write (a HIGHEST installation has
    // no `user\`, so guessing «unelevated» would leave it without a log and a state).
    let record = std::fs::read(install.join(RECORD_FILE))
        .map_err(|e| format!("{RECORD_FILE} not read: {e}"))
        .and_then(|bytes| Record::parse(&bytes));
    let token = token_elevated();
    let (dir, elevated, place_note) =
        data_place(&install, &token, record.as_ref().ok().map(|r| r.run_level));
    let mut log = HelperLog::new(&dir);
    log.line(
        Level::Info,
        &format!(
            "started: pid {}, version {}, elevated {}, exe dir {}, writes in {}",
            std::process::id(),
            env!("CARGO_PKG_VERSION"),
            match &token {
                Ok(elevated) => elevated.to_string(),
                Err(_) => format!("unknown (taken as {elevated})"),
            },
            install.display(),
            dir.display()
        ),
    );
    if let Some(note) = place_note {
        log.line(Level::Warn, &note);
    }
    // One helper per Windows session (the task's IgnoreNew covers the task; this covers the exe
    // started by hand). Held until the process ends.
    // SAFETY: a session-local named mutex with default security, owned by this process.
    let _instance = match unsafe {
        CreateMutexW(
            None,
            false,
            &HSTRING::from(r"Local\AFKLink.GameHelper.Instance"),
        )
    } {
        Ok(handle) => {
            let existed = std::io::Error::last_os_error().raw_os_error()
                == Some(ERROR_ALREADY_EXISTS.0 as i32);
            let handle = Handle(handle);
            if existed {
                log.line(
                    Level::Info,
                    "another helper runs in this Windows session: this one exits",
                );
                return 0;
            }
            Some(handle)
        }
        Err(e) => {
            log.line(
                Level::Warn,
                &format!("single-instance lock not taken ({e}); running without it"),
            );
            None
        }
    };
    note_priority(&mut log);
    let record = match record {
        Ok(record) => record,
        Err(e) => {
            log.line(
                Level::Error,
                &format!("{e}: nothing can be launched; the owner has to confirm the setup again"),
            );
            if let Err(e) = write_state(&dir, &state_only(HelperState::NeedsSetup, &e, elevated)) {
                log.line(Level::Warn, &format!("{STATE_FILE} not written: {e}"));
            }
            return EXIT_NO_RECORD;
        }
    };
    log.line(
        Level::Info,
        &format!(
            "record: launch {}, game window {} with class {}, run level {} ({}), written at {} ms",
            record.launch_exe,
            record.window_exe,
            record.window_class,
            record.run_level.as_str(),
            record.run_level_why,
            record.written_ms
        ),
    );
    // SAFETY: COM for this thread, paired with Com's drop.
    if let Err(e) = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.ok() {
        log.line(Level::Error, &format!("COM not initialized: {e}"));
        return EXIT_NO_COM;
    }
    let _com = Com;
    let mut desktop = match WindowsDesktop::new(&mut log) {
        Ok(desktop) => desktop,
        Err(e) => {
            log.line(Level::Error, &format!("desktop not readable: {e}"));
            return EXIT_NO_COM;
        }
    };
    let mut supervisor = Supervisor::new(record, Instant::now());
    // What the last run left for the app's window — «Игра не запускается» lasts until the game
    // runs, not until this process ends. Read before this run's first write replaces it.
    match previous_state(&dir) {
        Ok(Some(previous)) => supervisor.carry_over(&previous, SystemTime::now(), &mut log),
        Ok(None) => log.line(
            Level::Debug,
            &format!(
                "no {STATE_FILE} from a last run in {} (the first start after the setup): no \
                 failed-launch mark to carry over",
                dir.display()
            ),
        ),
        Err(e) => log.line(
            Level::Warn,
            &format!(
                "the last run's state not read ({e}): no failed-launch mark carried over; the app \
                 shows «Игра не запускается» again only if the helper gives up again"
            ),
        ),
    }
    let mut last_write: Option<Instant> = None;
    let mut write_failed = false;
    loop {
        let now = Instant::now();
        supervisor.tick(now, read_signal(), &mut desktop, &mut log);
        let due = last_write.is_none_or(|at| now.duration_since(at) >= STATE_REFRESH);
        if supervisor.take_dirty() || due {
            let state = supervisor.state_file(now, SystemTime::now(), std::process::id(), elevated);
            match write_state(&dir, &state) {
                Ok(()) => {
                    if write_failed {
                        log.line(Level::Info, &format!("{STATE_FILE} written again"));
                    }
                    write_failed = false;
                }
                Err(e) if !write_failed => {
                    write_failed = true;
                    log.line(
                        Level::Warn,
                        &format!(
                            "{STATE_FILE} not written in {}: {e}; the app shows an old state",
                            dir.display()
                        ),
                    );
                }
                Err(_) => {}
            }
            last_write = Some(now);
        }
        // Its actions read the signal again each; the line says how stale the tick's own read got.
        if let Some(line) = slow_tick(now.elapsed()) {
            log.line(Level::Warn, &line);
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use crate::record::RECORD_FORMAT;

    /// Reads processes and windows only: nothing is launched, focused or registered.
    #[test]
    fn the_snapshot_matches_the_full_path_and_the_signal_fails_closed() {
        // SAFETY: COM for this test thread, paired with Com's drop.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .unwrap();
        let _com = Com;
        let mut lines = Vec::new();
        struct Lines<'a>(&'a mut Vec<String>);
        impl Log for Lines<'_> {
            fn line(&mut self, _: Level, message: &str) {
                self.0.push(message.to_string());
            }
        }
        let mut desktop = WindowsDesktop::new(&mut Lines(&mut lines)).unwrap();
        let exe = std::env::current_exe().unwrap();
        let mut record = Record {
            format: RECORD_FORMAT,
            helper_sha256: "0".repeat(64),
            sid: "S-1-5-21-1-2-3-1001".into(),
            launch_exe: exe
                .with_file_name("not-the-test.exe")
                .to_string_lossy()
                .into_owned(),
            window_exe: exe.to_string_lossy().into_owned(),
            window_class: "AFKLink.Nonexistent.TestWindow".into(),
            run_level: RunLevel::Lua,
            run_level_why: "test".into(),
            written_ms: 0,
            task_priority: Some(crate::TASK_PRIORITY),
        };
        let seen = desktop.observe(&record).unwrap();
        assert!(seen.game_pids.contains(&std::process::id()));
        assert!(seen.loader_pids.is_empty(), "the window exe is no loader");
        assert!(seen.window.is_none());
        // What a closing would be about: read only — nothing is posted or ended here.
        let me = desktop.game_process(&record, std::process::id()).unwrap();
        assert!(same_path(&me.path, &exe.to_string_lossy()), "{me:?}");
        assert!(me.started > 0);
        // As the launch exe of another window exe: a loader.
        let as_loader = Record {
            launch_exe: exe.to_string_lossy().into_owned(),
            window_exe: exe
                .with_file_name("not-the-test.bin")
                .to_string_lossy()
                .into_owned(),
            ..record.clone()
        };
        let seen = desktop.observe(&as_loader).unwrap();
        assert!(seen.loader_pids.contains(&std::process::id()));
        assert!(desktop
            .game_process(
                &Record {
                    window_exe: as_loader.window_exe.clone(),
                    launch_exe: exe
                        .with_file_name("also-not-the-test.exe")
                        .to_string_lossy()
                        .into_owned(),
                    ..record.clone()
                },
                std::process::id()
            )
            .is_err_and(|why| why.contains("not the game's exe")));
        record.window_exe = exe
            .parent()
            .unwrap()
            .join("another-directory")
            .join(exe.file_name().unwrap())
            .to_string_lossy()
            .into_owned();
        assert!(
            !desktop
                .observe(&record)
                .unwrap()
                .game_pids
                .contains(&std::process::id()),
            "the same exe name in another folder is not the game"
        );
        // The app is not running in a test: no signal object, nothing allowed.
        assert!(matches!(read_signal(), Signal::Absent | Signal::NotSet));
        assert!(is_afklink(
            r"C:\Users\Player\Downloads\AFKLink-0.2.0-dev-3a3bc46.exe"
        ));
        assert!(is_afklink("afklink-app.exe"));
        assert!(!is_afklink("notepad.exe"));
        assert_eq!(priority_name(NORMAL_PRIORITY_CLASS.0), "normal");
        assert_eq!(priority_name(BELOW_NORMAL_PRIORITY_CLASS.0), "below normal");
        assert_eq!(priority_name(0x1234), "0x1234");
        assert_eq!(data_dir(Path::new(r"C:\h"), true), PathBuf::from(r"C:\h"));
        assert_eq!(
            data_dir(Path::new(r"C:\h"), false),
            PathBuf::from(r"C:\h\user")
        );
    }

    /// The token decides where the helper writes; unread, the record's run level does — a HIGHEST
    /// installation has no `user\` — and the log says so.
    #[test]
    fn an_unread_token_writes_where_the_records_run_level_says() {
        let install = Path::new(r"C:\h");
        let user = PathBuf::from(r"C:\h\user");
        assert_eq!(
            data_place(install, &Ok(true), Some(RunLevel::Lua)),
            (install.to_path_buf(), true, None)
        );
        assert_eq!(
            data_place(install, &Ok(false), Some(RunLevel::Highest)),
            (user.clone(), false, None)
        );
        let unread: Result<bool, String> = Err("access denied".into());
        let (dir, elevated, note) = data_place(install, &unread, Some(RunLevel::Highest));
        assert_eq!((dir, elevated), (install.to_path_buf(), true));
        assert!(
            note.as_deref()
                .is_some_and(|n| n.contains("access denied") && n.contains("highest")),
            "{note:?}"
        );
        let (dir, elevated, note) = data_place(install, &unread, Some(RunLevel::Lua));
        assert_eq!((dir, elevated), (user.clone(), false));
        assert!(note.is_some_and(|n| n.contains("lua")));
        let (dir, elevated, note) = data_place(install, &unread, None);
        assert_eq!((dir, elevated), (user, false));
        assert!(note.is_some_and(|n| n.contains("no readable record")));
    }

    /// A state is written whole through its temporary file, which does not stay behind.
    #[test]
    fn the_state_is_written_whole() {
        let dir = std::env::temp_dir().join(format!(
            "afklink-helper-state-{}-{}",
            std::process::id(),
            unix_ms(SystemTime::now())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // None yet: the first start after a setup.
        assert_eq!(previous_state(&dir), Ok(None));
        let state = state_only(HelperState::NeedsSetup, "test", false);
        write_state(&dir, &state).unwrap();
        let read = StateFile::parse(&std::fs::read(dir.join(STATE_FILE)).unwrap()).unwrap();
        assert_eq!(read, state);
        assert!(!dir.join(format!("{STATE_FILE}.tmp")).exists());
        // The next run reads it back, the failed-launch mark with it.
        let marked = StateFile {
            state: HelperState::GaveUp,
            failed_launch_since_ms: Some(1_790_000_000_000),
            ..state
        };
        write_state(&dir, &marked).unwrap();
        assert_eq!(previous_state(&dir), Ok(Some(marked)));
        std::fs::write(dir.join(STATE_FILE), b"{ half").unwrap();
        assert!(previous_state(&dir).is_err_and(|e| e.contains("unreadable")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// This test process's own integrity level, read both ways: through its pseudo-handle and
    /// through its id, as a game's is read before it is closed.
    #[test]
    fn the_integrity_level_of_this_process_is_read_both_ways() {
        // SAFETY: this process's own pseudo-handle.
        let own = integrity_of(unsafe { GetCurrentProcess() }).unwrap();
        assert!(
            [0x2000, 0x2100, 0x3000, 0x4000].contains(&own),
            "{}",
            integrity_name(own)
        );
        // SAFETY: this process's own id.
        assert_eq!(process_integrity(unsafe { GetCurrentProcessId() }), Ok(own));
        // No such process: said, not a level.
        assert!(process_integrity(u32::MAX - 2).is_err_and(|e| e.starts_with("not opened")));
    }

    #[test]
    fn integrity_levels_are_named_as_windows_names_them() {
        for (rid, name) in [
            (0x0000, "untrusted (0x0)"),
            (0x1000, "low (0x1000)"),
            (0x2000, "medium (0x2000)"),
            (0x2100, "medium plus (0x2100)"),
            (0x3000, "high (0x3000)"),
            (0x4000, "system (0x4000)"),
            (0x5000, "protected process (0x5000)"),
            (0x2010, "other (0x2010)"),
        ] {
            assert_eq!(integrity_name(rid), name);
        }
    }
}
