//! The Win32 reads the probes share. Nothing here opens a process for more than
//! `PROCESS_QUERY_LIMITED_INFORMATION` (plus `SYNCHRONIZE` when `game_watch` is asked to wait for exit
//! codes), writes to another process or window, sends a window message, or injects input.
//!
//! Window reads — `GetClassNameW`, `GetWindowTextW`, `GetWindowRect`, `IsIconic`, `IsWindowVisible`,
//! `GetWindowThreadProcessId`, `GetWindowPlacement`, `DwmGetWindowAttribute` — read what the window
//! manager keeps and send nothing to the window's process: `GetWindowTextW` on another process's
//! window returns the stored caption without a `WM_GETTEXT`.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Serialize, Serializer};
use serde_json::{json, Map, Value};
use windows::core::{w, BOOL, PCWSTR, PWSTR};
use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessCommandLineInformation};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME, HANDLE, HWND, LPARAM, POINT, RECT,
    UNICODE_STRING,
};
use windows::Win32::Graphics::Dwm::{
    DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS,
};
use windows::Win32::Graphics::Gdi::{
    ClientToScreen, GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
    TokenIntegrityLevel, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{GetLocalTime, GetSystemTimeAsFileTime};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};
use windows::Win32::UI::HiDpi::{
    GetAwarenessFromDpiAwarenessContext, GetDpiForWindow, GetThreadDpiAwarenessContext,
    GetWindowDpiAwarenessContext, SetProcessDpiAwarenessContext, SetThreadDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, DPI_AWARENESS_PER_MONITOR_AWARE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetClientRect, GetForegroundWindow, GetWindow, GetWindowLongW,
    GetWindowPlacement, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId, IsIconic,
    IsWindow, IsWindowVisible, GWL_EXSTYLE, GWL_STYLE, GW_OWNER, WINDOWPLACEMENT, WS_EX_LAYERED,
    WS_EX_TOPMOST, WS_EX_TRANSPARENT,
};

use super::{area, stamp, Rect};

/// A kernel handle these probes opened and close.
pub(super) struct Owned(pub(super) HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this owns one live kernel handle, never a pseudo handle.
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            println!("probe: CloseHandle failed: {}", error_text(&error));
        }
    }
}

/// Print a line and keep it for the JSON's `notes`.
pub(super) fn note(who: &str, notes: &mut Vec<String>, line: String) {
    println!("{who}: {line}");
    notes.push(line);
}

/// A Windows error as `0x80070005 Access is denied.`: the code first, since the message is localized
/// (this PC's is Russian).
pub(super) fn error_text(error: &windows::core::Error) -> String {
    let message = error.message();
    let code = error.code().0 as u32;
    if message.trim().is_empty() {
        format!("{code:#010x}")
    } else {
        format!("{code:#010x} {}", message.trim_end())
    }
}

pub(super) fn hex<S: Serializer>(v: &usize, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:#x}"))
}

pub(super) fn hex32<S: Serializer>(v: &u32, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:#010x}"))
}

pub(super) fn hwnd_of(hwnd: usize) -> HWND {
    HWND(hwnd as *mut c_void)
}

fn rect_of(r: RECT) -> Rect {
    [r.left, r.top, r.right, r.bottom]
}

/// Local wall-clock time, `yyyy-mm-dd hh:mm:ss`.
pub(super) fn local_time() -> String {
    // SAFETY: returns a value; no pointers.
    let t = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    )
}

/// Now as a FILETIME count (100 ns since 1601, UTC): the clock process creation and exit times use.
pub(super) fn now_filetime() -> u64 {
    // SAFETY: returns a value; no pointers.
    filetime(unsafe { GetSystemTimeAsFileTime() })
}

fn filetime(ft: FILETIME) -> u64 {
    (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)
}

/// A FILETIME count as ms after `epoch` (another FILETIME count); negative before it.
pub(super) fn filetime_ms_after(ft: u64, epoch: u64) -> f64 {
    (ft as i128 - epoch as i128) as f64 / 10_000.0
}

/// An environment variable's text; `None` when unset, an error when it is not valid Unicode.
pub(super) fn env_text(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow!("{name} is unreadable: {error}")),
    }
}

/// Where a probe's JSON goes: `AFK_PROBE_OUT`, else
/// `agent\target\<prefix>-<local yyyymmdd-hhmmss>.json`.
pub(super) fn output_path(prefix: &str) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AFK_PROBE_OUT").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    // SAFETY: returns a value; no pointers.
    let t = unsafe { GetLocalTime() };
    let name = format!(
        "{prefix}-{}.json",
        stamp(t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond)
    );
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("the crate directory has no workspace two levels above it")?;
    Ok(workspace.join("target").join(name))
}

pub(super) fn write_json(path: &Path, record: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(record).context("serializing the probe record")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// The calling thread's DPI awareness: the value (-1 invalid, 0 unaware, 1 system, 2 per monitor)
/// and its name.
fn thread_awareness() -> (i32, &'static str) {
    // SAFETY: plain calls on the thread's own context.
    let value = unsafe { GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()) }.0;
    (value, awareness_name(value))
}

fn awareness_name(value: i32) -> &'static str {
    match value {
        0 => "unaware",
        1 => "system aware",
        2 => "per-monitor aware",
        _ => "invalid",
    }
}

/// Make this process — and the calling thread, which the test harness created before — per-monitor
/// DPI aware (v2) before anything reads a coordinate, so every rectangle is in physical pixels,
/// whatever the window's own awareness (a DPI-unaware game at 150 % is the common case). What
/// happened, for the record.
pub(super) fn make_dpi_aware(who: &str, notes: &mut Vec<String>) -> Value {
    let before = thread_awareness();
    // SAFETY: plain call with a predefined context.
    let set = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let set_text = match &set {
        Ok(()) => "ok".to_owned(),
        Err(error) => error_text(error),
    };
    if set.is_err() {
        note(
            who,
            notes,
            format!(
                "SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2): {set_text} (already set in \
                 this process?); setting the thread's"
            ),
        );
    }
    let mut thread_set = Value::Null;
    if thread_awareness().0 != DPI_AWARENESS_PER_MONITOR_AWARE.0 {
        // SAFETY: plain call with a predefined context.
        let previous =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        thread_set = json!(if previous.0.is_null() {
            format!("failed: {}", std::io::Error::last_os_error())
        } else {
            "ok".to_owned()
        });
    }
    let now = thread_awareness();
    if now.0 != DPI_AWARENESS_PER_MONITOR_AWARE.0 {
        note(
            who,
            notes,
            format!(
                "this thread is {} rather than per-monitor aware: rectangles may be scaled",
                now.1
            ),
        );
    }
    json!({
        "before": before.1,
        "set_process": set_text,
        "set_thread": thread_set,
        "now": now.1,
    })
}

fn reg_text(value: PCWSTR) -> Value {
    let mut buffer = [0u16; 256];
    let mut bytes = (buffer.len() * 2) as u32;
    // SAFETY: `buffer` is live and `bytes` holds its size in bytes.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            value,
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if status == ERROR_SUCCESS {
        json!(wide_text(&buffer))
    } else {
        json!({ "error": format!("RegGetValueW: {}", status.0) })
    }
}

fn reg_dword(value: PCWSTR) -> Value {
    let mut data = 0u32;
    let mut bytes = size_of::<u32>() as u32;
    // SAFETY: `data` is a live u32 and `bytes` its size.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
            value,
            RRF_RT_REG_DWORD,
            None,
            Some((&mut data as *mut u32).cast()),
            Some(&mut bytes),
        )
    };
    if status == ERROR_SUCCESS {
        json!(data)
    } else {
        json!({ "error": format!("RegGetValueW: {}", status.0) })
    }
}

/// The Windows build, from the registry (`GetVersionEx` answers what the manifest lets it).
/// `IncludeSecondaryWindows` needs 26100 (24H2).
pub(super) fn os_version() -> Value {
    json!({
        "product": reg_text(w!("ProductName")),
        "edition": reg_text(w!("EditionID")),
        "display_version": reg_text(w!("DisplayVersion")),
        "build": reg_text(w!("CurrentBuild")),
        "ubr": reg_dword(w!("UBR")),
    })
}

/// This probe's own process: pid, integrity, elevation.
pub(super) fn own_process() -> Value {
    // SAFETY: plain call.
    let pid = unsafe { GetCurrentProcessId() };
    // SAFETY: the pseudo handle of this process; it needs no closing.
    let mut facts = token_facts(unsafe { GetCurrentProcess() });
    if let Value::Object(map) = &mut facts {
        map.insert("pid".into(), json!(pid));
    }
    facts
}

/// One process from a snapshot: no process is opened for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProcEntry {
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) exe: String,
}

/// Every process's id, parent id and exe file name, from a toolhelp snapshot (no process is opened;
/// the full path is not in it).
pub(super) fn snapshot() -> std::result::Result<Vec<ProcEntry>, String> {
    // SAFETY: plain call; the handle is owned below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot: {}", error_text(&e)))?;
    let snap = Owned(snap);
    // SAFETY: a plain-data struct; all zeroes is a valid value, `dwSize` is set next.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut list = Vec::new();
    // SAFETY: `entry` is live with `dwSize` set.
    let mut step = unsafe { Process32FirstW(snap.0, &mut entry) };
    while step.is_ok() {
        list.push(ProcEntry {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            exe: wide_text(&entry.szExeFile),
        });
        // SAFETY: as above.
        step = unsafe { Process32NextW(snap.0, &mut entry) };
    }
    match step {
        // The walk ends with ERROR_NO_MORE_FILES; anything else cut it short.
        Err(error) if error.code() != ERROR_NO_MORE_FILES.to_hresult() => Err(format!(
            "walking the process snapshot: {}",
            error_text(&error)
        )),
        _ => Ok(list),
    }
}

/// A NUL-terminated UTF-16 buffer as text.
pub(super) fn wide_text(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

/// Exe file names by pid, from process snapshots: no process is opened. A pid it does not know makes
/// it take a fresh snapshot, at most every half second.
pub(super) struct ExeNames {
    map: HashMap<u32, String>,
    taken: Option<Instant>,
    /// The last snapshot's failure, if the last one failed.
    pub(super) error: Option<String>,
}

impl ExeNames {
    pub(super) fn new() -> Self {
        let mut names = Self {
            map: HashMap::new(),
            taken: None,
            error: None,
        };
        names.refresh();
        names
    }

    pub(super) fn refresh(&mut self) {
        self.taken = Some(Instant::now());
        match snapshot() {
            Ok(list) => {
                self.map = list.into_iter().map(|p| (p.pid, p.exe)).collect();
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    pub(super) fn get(&mut self, pid: u32) -> Option<String> {
        let stale = self
            .taken
            .is_none_or(|t| t.elapsed() >= Duration::from_millis(500));
        if !self.map.contains_key(&pid) && stale {
            self.refresh();
        }
        self.map.get(&pid).cloned()
    }
}

/// Open a process for `PROCESS_QUERY_LIMITED_INFORMATION` — the least an open can ask for, and all
/// these probes ever ask of the game — plus `SYNCHRONIZE` when `synchronize` (`game_watch`'s opt-in
/// wait for the exit code).
pub(super) fn open_limited(pid: u32, synchronize: bool) -> std::result::Result<Owned, String> {
    let (access, name) = if synchronize {
        (
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            "QUERY_LIMITED_INFORMATION | SYNCHRONIZE",
        )
    } else {
        (
            PROCESS_QUERY_LIMITED_INFORMATION,
            "QUERY_LIMITED_INFORMATION",
        )
    };
    // SAFETY: plain call; the handle is owned by the result.
    unsafe { OpenProcess(access, false, pid) }
        .map(Owned)
        .map_err(|e| format!("OpenProcess({name}): {}", error_text(&e)))
}

/// The process's full exe path (`QueryFullProcessImageNameW`, limited rights suffice).
pub(super) fn image_path(process: &Owned) -> std::result::Result<String, String> {
    let mut buffer = [0u16; 1024];
    let mut len = buffer.len() as u32;
    // SAFETY: `buffer` is live and `len` holds its length in characters.
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut len,
        )
    }
    .map_err(|e| format!("QueryFullProcessImageNameW: {}", error_text(&e)))?;
    Ok(String::from_utf16_lossy(&buffer[..len as usize]))
}

/// The process's creation and exit times as FILETIME counts (the exit time is 0 while it runs).
pub(super) fn process_times(process: &Owned) -> std::result::Result<(u64, u64), String> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: four live FILETIMEs.
    unsafe { GetProcessTimes(process.0, &mut created, &mut exited, &mut kernel, &mut user) }
        .map_err(|e| format!("GetProcessTimes: {}", error_text(&e)))?;
    Ok((filetime(created), filetime(exited)))
}

/// The process's command line, through `NtQueryInformationProcess(ProcessCommandLineInformation)`,
/// which limited rights allow (Windows 8.1+). Only ever asked of WerFault, whose command line names
/// the process it reports on (`-p <pid>`).
pub(super) fn command_line(process: &Owned) -> std::result::Result<String, String> {
    let mut needed = 0u32;
    // SAFETY: a size query: no buffer, a live length output. It fails by design and says the size.
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if needed == 0 {
        return Err(format!(
            "NtQueryInformationProcess(ProcessCommandLineInformation) size: NTSTATUS {:#010x}",
            status.0 as u32
        ));
    }
    // u64s: aligned for the UNICODE_STRING at the start.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(size_of::<u64>()).max(2)];
    let len = (buffer.len() * size_of::<u64>()) as u32;
    // SAFETY: `buffer` is live and `len` bytes long.
    let status = unsafe {
        NtQueryInformationProcess(
            process.0,
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast(),
            len,
            &mut needed,
        )
    };
    if status.is_err() {
        return Err(format!(
            "NtQueryInformationProcess(ProcessCommandLineInformation): NTSTATUS {:#010x}",
            status.0 as u32
        ));
    }
    // SAFETY: the call wrote a UNICODE_STRING at the start of `buffer`, which is aligned for it.
    let text = unsafe { &*buffer.as_ptr().cast::<UNICODE_STRING>() };
    if text.Buffer.is_null() || text.Length == 0 {
        return Ok(String::new());
    }
    let start = buffer.as_ptr() as usize;
    let end = start + len as usize;
    let at = text.Buffer.0 as usize;
    let bytes = usize::from(text.Length);
    if at < start || at + bytes > end {
        return Err("the command line points outside the buffer it was written to".to_owned());
    }
    // SAFETY: checked just above to lie inside `buffer`, which is alive.
    let chars = unsafe { std::slice::from_raw_parts(text.Buffer.0, bytes / 2) };
    Ok(String::from_utf16_lossy(chars))
}

/// A process's exe path, creation time, integrity and elevation, through one handle opened for
/// `PROCESS_QUERY_LIMITED_INFORMATION` and closed before this returns. Each fact is best effort and
/// says why when it could not be read. `epoch` (a FILETIME count) makes the creation time relative.
pub(super) fn process_facts(pid: u32, epoch: u64) -> Value {
    match open_limited(pid, false) {
        Ok(process) => process_facts_on(&process, epoch),
        Err(error) => json!({ "open_error": error }),
    }
}

/// [`process_facts`] through a handle the caller holds (with at least limited rights).
pub(super) fn process_facts_on(process: &Owned, epoch: u64) -> Value {
    let mut facts = Map::new();
    match image_path(process) {
        Ok(path) => facts.insert("path".into(), json!(path)),
        Err(error) => facts.insert("path_error".into(), json!(error)),
    };
    match process_times(process) {
        Ok((created, _)) => facts.insert(
            "created_ms".into(),
            json!(filetime_ms_after(created, epoch)),
        ),
        Err(error) => facts.insert("created_error".into(), json!(error)),
    };
    if let Value::Object(token) = token_facts(process.0) {
        facts.extend(token);
    }
    Value::Object(facts)
}

/// Integrity and elevation from the process's token, opened for `TOKEN_QUERY` only.
pub(super) fn token_facts(process: HANDLE) -> Value {
    let mut token = HANDLE::default();
    // SAFETY: `token` receives a handle owned below.
    if let Err(error) = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } {
        return json!({ "token_error": format!("OpenProcessToken(TOKEN_QUERY): {}", error_text(&error)) });
    }
    let token = Owned(token);
    let mut facts = Map::new();
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elevation` is a live TOKEN_ELEVATION of the size given.
    match unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    } {
        Ok(()) => facts.insert("elevated".into(), json!(elevation.TokenIsElevated != 0)),
        Err(error) => facts.insert("elevation_error".into(), json!(error_text(&error))),
    };
    match integrity(token.0) {
        Ok(rid) => {
            facts.insert("integrity".into(), json!(integrity_name(rid)));
            facts.insert("integrity_rid".into(), json!(format!("{rid:#06x}")));
        }
        Err(error) => {
            facts.insert("integrity_error".into(), json!(error));
        }
    }
    Value::Object(facts)
}

/// The token's mandatory-label RID (0x2000 medium, 0x3000 high, …).
fn integrity(token: HANDLE) -> std::result::Result<u32, String> {
    let mut len = 0u32;
    // The size query fails by design (ERROR_INSUFFICIENT_BUFFER) and says how much to allocate; only
    // a failure that says nothing is one.
    // SAFETY: a size query: no buffer, a live length output.
    if let Err(error) =
        unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut len) }
    {
        if len == 0 {
            return Err(format!(
                "GetTokenInformation(TokenIntegrityLevel) size: {}",
                error_text(&error)
            ));
        }
    }
    let mut buffer = vec![0u64; (len as usize).div_ceil(size_of::<u64>()).max(1)];
    // SAFETY: `buffer` is live, aligned for the label and at least `len` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .map_err(|e| {
        format!(
            "GetTokenInformation(TokenIntegrityLevel): {}",
            error_text(&e)
        )
    })?;
    // SAFETY: the call above wrote a TOKEN_MANDATORY_LABEL (and its SID) into `buffer`.
    let sid = unsafe { &*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() }
        .Label
        .Sid;
    // SAFETY: `sid` points into `buffer`, still alive; these read its header.
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if count.is_null() {
        return Err("the integrity SID is unreadable".to_owned());
    }
    // SAFETY: non-null, into `buffer`.
    let count = unsafe { *count };
    if count == 0 {
        return Err("the integrity SID has no sub-authority".to_owned());
    }
    // SAFETY: the last sub-authority of the SID in `buffer`.
    let rid = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid.is_null() {
        return Err("the integrity SID's RID is unreadable".to_owned());
    }
    // SAFETY: non-null, into `buffer`.
    Ok(unsafe { *rid })
}

fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x0000..=0x0fff => "untrusted",
        0x1000..=0x1fff => "low",
        0x2000..=0x20ff => "medium",
        0x2100..=0x2fff => "medium plus",
        0x3000..=0x3fff => "high",
        0x4000..=0x4fff => "system",
        _ => "protected",
    }
}

/// One top-level window as the window manager describes it; no message is sent to its process.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub(super) struct WinFacts {
    #[serde(serialize_with = "hex")]
    pub(super) hwnd: usize,
    pub(super) pid: u32,
    pub(super) thread: u32,
    pub(super) class: String,
    pub(super) title: String,
    pub(super) visible: bool,
    pub(super) minimized: bool,
    /// `DWMWA_CLOAKED`: 0 not cloaked, else why (1 by the app, 2 by the shell — e.g. another virtual
    /// desktop —, 4 inherited from its owner); `None` when unreadable.
    pub(super) cloaked: Option<u32>,
    /// `GetWindowRect`: for a framed window it includes the invisible resize borders.
    pub(super) rect: Option<Rect>,
    /// `DWMWA_EXTENDED_FRAME_BOUNDS`: what is actually drawn.
    pub(super) frame: Option<Rect>,
    #[serde(serialize_with = "hex32")]
    pub(super) style: u32,
    #[serde(serialize_with = "hex32")]
    pub(super) ex_style: u32,
    /// The owner window (0: none). Owned windows are a game's dialogs and pop-ups.
    #[serde(serialize_with = "hex")]
    pub(super) owner: usize,
}

impl WinFacts {
    /// Where the window is drawn: the DWM frame when known, else its window rectangle.
    pub(super) fn bounds(&self) -> Option<Rect> {
        self.frame.or(self.rect)
    }

    /// Actually on screen: visible, not minimized, not cloaked, not empty.
    pub(super) fn shown(&self) -> bool {
        self.visible
            && !self.minimized
            && self.cloaked.unwrap_or(0) == 0
            && self.bounds().is_some_and(|b| area(b) > 0)
    }

    pub(super) fn topmost(&self) -> bool {
        self.ex_style & WS_EX_TOPMOST.0 != 0
    }

    /// Layered and transparent to input: an overlay (a game overlay, a screen recorder's frame),
    /// usually invisible where it has nothing to draw.
    pub(super) fn click_through(&self) -> bool {
        let both = WS_EX_LAYERED.0 | WS_EX_TRANSPARENT.0;
        self.ex_style & both == both
    }
}

/// Every top-level window, top of the z-order first (`EnumWindows`' order).
pub(super) fn top_level_windows() -> std::result::Result<Vec<usize>, String> {
    let mut list: Vec<usize> = Vec::new();
    // SAFETY: the callback only pushes into `list`, which outlives this synchronous call.
    unsafe {
        EnumWindows(
            Some(collect_window),
            LPARAM(&mut list as *mut Vec<usize> as isize),
        )
    }
    .map_err(|e| format!("EnumWindows: {}", error_text(&e)))?;
    Ok(list)
}

unsafe extern "system" fn collect_window(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the `&mut Vec<usize>` `top_level_windows` passed, alive for the enumeration.
    let list = unsafe { &mut *(data.0 as *mut Vec<usize>) };
    list.push(hwnd.0 as usize);
    BOOL(1)
}

/// The window's process id (0 when the window is gone).
pub(super) fn window_pid(hwnd: usize) -> u32 {
    let mut pid = 0u32;
    // SAFETY: plain call with a live output.
    unsafe { GetWindowThreadProcessId(hwnd_of(hwnd), Some(&mut pid)) };
    pid
}

pub(super) fn foreground() -> usize {
    // SAFETY: plain call.
    unsafe { GetForegroundWindow() }.0 as usize
}

/// The handle still names a window.
pub(super) fn window_alive(hwnd: usize) -> bool {
    // SAFETY: plain call; any value is accepted.
    unsafe { IsWindow(Some(hwnd_of(hwnd))) }.as_bool()
}

/// `IsWindowVisible`: the cheap first filter before reading everything else.
pub(super) fn window_visible(hwnd: usize) -> bool {
    // SAFETY: plain call; any value is accepted.
    unsafe { IsWindowVisible(hwnd_of(hwnd)) }.as_bool()
}

pub(super) fn window_facts(hwnd: usize) -> WinFacts {
    let h = hwnd_of(hwnd);
    let mut pid = 0u32;
    // SAFETY: plain call with a live output.
    let thread = unsafe { GetWindowThreadProcessId(h, Some(&mut pid)) };
    let mut class = [0u16; 256];
    // SAFETY: a live buffer; the call writes at most its length.
    let c = unsafe { GetClassNameW(h, &mut class) };
    let mut title = [0u16; 512];
    // SAFETY: as above.
    let n = unsafe { GetWindowTextW(h, &mut title) };
    let mut cloaked = 0u32;
    // SAFETY: `cloaked` is a live u32 of the size given.
    let cloaked = unsafe {
        DwmGetWindowAttribute(
            h,
            DWMWA_CLOAKED,
            (&mut cloaked as *mut u32).cast(),
            size_of::<u32>() as u32,
        )
    }
    .map(|()| cloaked)
    .ok();
    let mut r = RECT::default();
    // SAFETY: a live RECT.
    let rect = unsafe { GetWindowRect(h, &mut r) }
        .map(|()| rect_of(r))
        .ok();
    let mut f = RECT::default();
    // SAFETY: a live RECT of the size given.
    let frame = unsafe {
        DwmGetWindowAttribute(
            h,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            (&mut f as *mut RECT).cast(),
            size_of::<RECT>() as u32,
        )
    }
    .map(|()| rect_of(f))
    .ok();
    // SAFETY: plain calls; 0 is a possible answer and is recorded as such.
    let (style, ex_style) =
        unsafe { (GetWindowLongW(h, GWL_STYLE), GetWindowLongW(h, GWL_EXSTYLE)) };
    // SAFETY: plain call; no owner reads as an error, recorded as 0.
    let owner = unsafe { GetWindow(h, GW_OWNER) }.map_or(0, |o| o.0 as usize);
    WinFacts {
        hwnd,
        pid,
        thread,
        class: String::from_utf16_lossy(&class[..c.max(0) as usize]),
        title: String::from_utf16_lossy(&title[..n.max(0) as usize]),
        // SAFETY: plain calls.
        visible: unsafe { IsWindowVisible(h) }.as_bool(),
        // SAFETY: plain call.
        minimized: unsafe { IsIconic(h) }.as_bool(),
        cloaked,
        rect,
        frame,
        style: style as u32,
        ex_style: ex_style as u32,
        owner,
    }
}

/// What the capture target needs on top of [`window_facts`]: its client area on screen, its monitor,
/// its DPI and DPI awareness, its placement (where it goes back to when restored).
pub(super) fn window_extra(hwnd: usize) -> Value {
    let h = hwnd_of(hwnd);
    let mut client = RECT::default();
    // SAFETY: a live RECT.
    let client_screen = match unsafe { GetClientRect(h, &mut client) } {
        Ok(()) => {
            let mut top_left = POINT {
                x: client.left,
                y: client.top,
            };
            let mut bottom_right = POINT {
                x: client.right,
                y: client.bottom,
            };
            // SAFETY: live POINTs.
            let ok = unsafe { ClientToScreen(h, &mut top_left).as_bool() }
                && unsafe { ClientToScreen(h, &mut bottom_right).as_bool() };
            if ok {
                json!([top_left.x, top_left.y, bottom_right.x, bottom_right.y])
            } else {
                json!({ "error": format!("ClientToScreen: {}", std::io::Error::last_os_error()) })
            }
        }
        Err(error) => json!({ "error": format!("GetClientRect: {}", error_text(&error)) }),
    };
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: plain call, then a live MONITORINFO with `cbSize` set.
    let monitor =
        if unsafe { GetMonitorInfoW(MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST), &mut info) }
            .as_bool()
        {
            json!({ "rect": rect_of(info.rcMonitor), "work": rect_of(info.rcWork) })
        } else {
            json!({ "error": format!("GetMonitorInfoW: {}", std::io::Error::last_os_error()) })
        };
    // SAFETY: plain calls on a window handle; a gone window reads 0 / invalid.
    let (dpi, awareness) = unsafe {
        (
            GetDpiForWindow(h),
            GetAwarenessFromDpiAwarenessContext(GetWindowDpiAwarenessContext(h)).0,
        )
    };
    let mut placement = WINDOWPLACEMENT {
        length: size_of::<WINDOWPLACEMENT>() as u32,
        ..Default::default()
    };
    // SAFETY: a live WINDOWPLACEMENT with `length` set.
    let placement = match unsafe { GetWindowPlacement(h, &mut placement) } {
        Ok(()) => json!({
            "show_cmd": placement.showCmd,
            "normal_rect": rect_of(placement.rcNormalPosition),
        }),
        Err(error) => json!({ "error": format!("GetWindowPlacement: {}", error_text(&error)) }),
    };
    json!({
        "client_rect_screen": client_screen,
        "monitor": monitor,
        "dpi": dpi,
        "dpi_awareness": awareness_name(awareness),
        "placement": placement,
    })
}
