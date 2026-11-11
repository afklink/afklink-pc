//! The real [`CursorWorld`]: this PC's cursor, screen, pointer settings and foreground window, read
//! in the calling thread's DPI awareness (the desktop app's whole process is per-monitor aware, so
//! physical pixels — the same ones `GetSystemMetrics` and `GetCursorInfo` answer in). Reads only:
//! nothing here moves, clicks or hooks anything.

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::OnceLock;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, POINT};
use windows::Win32::Graphics::Gdi::{MonitorFromPoint, MONITOR_DEFAULTTOPRIMARY};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::HiDpi::{
    GetAwarenessFromDpiAwarenessContext, GetDpiForMonitor, GetThreadDpiAwarenessContext,
    MDT_EFFECTIVE_DPI,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorInfo, GetForegroundWindow, GetSystemMetrics, GetWindowThreadProcessId,
    SystemParametersInfoW, CURSORINFO, CURSOR_SHOWING, CURSOR_SUPPRESSED, SM_CXSCREEN, SM_CYSCREEN,
    SPI_GETMOUSE, SPI_GETMOUSESPEED, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
};

use super::{CursorLook, CursorWorld, ForegroundInfo, PointerSettings};

/// This PC. Stateless: every call reads afresh.
pub(crate) struct SystemCursor;

impl CursorWorld for SystemCursor {
    fn look(&mut self) -> Result<CursorLook, String> {
        let mut info = CURSORINFO {
            cbSize: size_of::<CURSORINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: `info` is a live CURSORINFO we own, with `cbSize` set as the API requires.
        unsafe { GetCursorInfo(&mut info) }.map_err(|e| format!("GetCursorInfo: {e}"))?;
        Ok(CursorLook {
            x: info.ptScreenPos.x,
            y: info.ptScreenPos.y,
            // No shape to draw is no cursor to see, whatever the flag says.
            showing: info.flags.0 & CURSOR_SHOWING.0 != 0 && !info.hCursor.0.is_null(),
            suppressed: info.flags.0 & CURSOR_SUPPRESSED.0 != 0,
        })
    }

    fn screen(&mut self) -> (i32, i32) {
        // SAFETY: plain metric queries; no pointers involved.
        unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) }
    }

    fn settings(&mut self) -> Result<PointerSettings, String> {
        let mut mouse = [0i32; 3];
        // SAFETY: SPI_GETMOUSE writes three ints into `mouse`.
        unsafe {
            SystemParametersInfoW(
                SPI_GETMOUSE,
                0,
                Some(mouse.as_mut_ptr().cast()),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
        }
        .map_err(|e| format!("SPI_GETMOUSE: {e}"))?;
        let mut speed = 0i32;
        // SAFETY: SPI_GETMOUSESPEED writes one int into `speed`.
        unsafe {
            SystemParametersInfoW(
                SPI_GETMOUSESPEED,
                0,
                Some((&mut speed as *mut i32).cast()),
                SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
            )
        }
        .map_err(|e| format!("SPI_GETMOUSESPEED: {e}"))?;
        // The primary monitor: the captured one, whose top-left corner is the virtual screen's origin.
        // SAFETY: plain call.
        let monitor = unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) };
        let (mut dpi_x, mut dpi_y) = (0u32, 0u32);
        // SAFETY: two live u32 outputs. The answer follows the calling thread's DPI awareness: the
        // monitor's own DPI when per-monitor aware, the system's when system aware, 96 when unaware —
        // the same view the screen size and the cursor position are read in.
        unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y) }
            .map_err(|e| format!("GetDpiForMonitor: {e}"))?;
        Ok(PointerSettings {
            dpi: dpi_x,
            epp: mouse[2] != 0,
            speed: u32::try_from(speed).unwrap_or(0),
            thresholds: (mouse[0], mouse[1]),
            awareness: awareness(),
        })
    }

    fn foreground(&mut self) -> usize {
        // SAFETY: plain call.
        unsafe { GetForegroundWindow() }.0 as usize
    }

    fn describe_foreground(&mut self, window: usize) -> ForegroundInfo {
        let mut pid = 0u32;
        // SAFETY: any window handle may be asked about; a stale one answers 0.
        let thread =
            unsafe { GetWindowThreadProcessId(HWND(window as *mut c_void), Some(&mut pid)) };
        if thread == 0 || pid == 0 {
            const GONE: &str = "the window is gone";
            return ForegroundInfo {
                pid: 0,
                exe: Err(GONE.to_owned()),
                elevated: Err(GONE.to_owned()),
                agent_elevated: agent_elevated(),
            };
        }
        // SAFETY: plain call; the handle is owned below.
        match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(process) => {
                let process = Owned(process);
                ForegroundInfo {
                    pid,
                    exe: exe_name(process.0),
                    elevated: elevated(process.0),
                    agent_elevated: agent_elevated(),
                }
            }
            Err(error) => {
                let why = format!("OpenProcess: {error}");
                ForegroundInfo {
                    pid,
                    exe: Err(why.clone()),
                    elevated: Err(why),
                    agent_elevated: agent_elevated(),
                }
            }
        }
    }
}

/// The calling thread's DPI awareness, in words.
fn awareness() -> &'static str {
    // SAFETY: plain calls on the thread's own context.
    match unsafe { GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()) }.0 {
        0 => "unaware",
        1 => "system aware",
        2 => "per-monitor aware",
        _ => "invalid",
    }
}

/// A handle this module (or the cursor-shape reader, `crate::cursor_shape`) opened and closes.
pub(crate) struct Owned(pub(crate) HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this owns one live kernel handle, never a pseudo handle.
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            tracing::debug!(%error, "cursor sync: closing a process handle failed");
        }
    }
}

/// The process's exe file name (not the path: enough to say which program, and nothing about the
/// user's folders).
pub(crate) fn exe_name(process: HANDLE) -> Result<String, String> {
    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;
    // SAFETY: `buffer` is live and `size` holds its length in characters.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    }
    .map_err(|e| format!("QueryFullProcessImageNameW: {e}"))?;
    let path = String::from_utf16_lossy(buffer.get(..size as usize).unwrap_or(&[]));
    Ok(path
        .rsplit(['\\', '/'])
        .next()
        .map_or_else(|| path.clone(), str::to_owned))
}

/// Whether a process's token is elevated.
fn elevated(process: HANDLE) -> Result<bool, String> {
    let mut token = HANDLE::default();
    // SAFETY: `token` receives a handle owned below.
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }
        .map_err(|e| format!("OpenProcessToken: {e}"))?;
    let token = Owned(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0u32;
    // SAFETY: `elevation` is a live TOKEN_ELEVATION of the size given.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    }
    .map_err(|e| format!("GetTokenInformation(TokenElevation): {e}"))?;
    Ok(elevation.TokenIsElevated != 0)
}

/// Whether this agent runs elevated; read once.
fn agent_elevated() -> Result<bool, String> {
    static AGENT: OnceLock<Result<bool, String>> = OnceLock::new();
    AGENT
        .get_or_init(|| {
            // SAFETY: the pseudo handle of this process; it needs no closing.
            elevated(unsafe { GetCurrentProcess() })
        })
        .clone()
}
