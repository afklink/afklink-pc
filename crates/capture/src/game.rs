//! The Windows half of «only the game window» (`afklink_core::game`): the window list the finder
//! reads, the WGC capture of the game's window cropped to its client area, and the window list the
//! desktop app's picker shows.
//!
//! ## What is touched, and what never is
//!
//! Window reads — `EnumWindows`, `GetClassNameW`, `GetWindowTextW`, `IsWindowVisible`, `IsIconic`,
//! `GetWindowThreadProcessId`, `DwmGetWindowAttribute`, `GetWindowRect`, `GetClientRect`,
//! `ClientToScreen`, `GetWindowDpiAwarenessContext`, `GetDpiForWindow`, `MonitorFromWindow` — read
//! what the window manager keeps and send nothing to the window's process. A process is opened only
//! when its exe is named like the bound game's (a process snapshot names every process without
//! opening any), and then for `PROCESS_QUERY_LIMITED_INFORMATION` alone, to read its full exe path —
//! once per process, cached. Games with a kernel anti-cheat are the expected case: nothing here
//! reads a game's memory, hooks it, or sends it input.
//!
//! ## Why `windows-capture`, with the capture item made here
//!
//! The same crate as the monitor capture: it recreates the frame pool when the window's size
//! changes (borderless → windowed arrives as one resize), crops on the GPU
//! (`Frame::buffer_crop` copies only the client area out of the texture), and sets the cursor,
//! `IsBorderRequired` and `IncludeSecondaryWindows` explicitly — each only where this Windows has the
//! property (`crate::session_options`). What it cannot do is say why a window could not be
//! captured: its own `Window` conversion reports every `CreateForWindow` failure as
//! `ItemConvertFailed`. So the capture item is made here ([`GameItem`]), and the exact error is kept
//! for the log.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use afklink_core::game::{
    client_crop, CaptureGeometry, ClientCrop, Crop, DpiAwareness, GameBinding, GateSend, OwnRects,
    ScreenRect, WindowCapture, WindowCaptureBackend, WindowCaptureContext, WindowDpi,
    WindowGeometry, WindowInfo, WindowSource,
};
use afklink_core::scale::Scaler;
use afklink_core::sync::lock;
use afklink_core::types::Frame;
use windows::core::{BOOL, PWSTR};
use windows::Graphics::Capture::GraphicsCaptureItem;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, HANDLE, HWND, LPARAM, POINT, RECT,
};
use windows::Win32::Graphics::Dwm::{
    DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS,
};
use windows::Win32::Graphics::Gdi::{ClientToScreen, MonitorFromWindow, MONITOR_DEFAULTTONEAREST};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::UI::HiDpi::GetThreadDpiAwarenessContext;
use windows::Win32::UI::HiDpi::{
    AreDpiAwarenessContextsEqual, GetAwarenessFromDpiAwarenessContext, GetDpiForMonitor,
    GetDpiForWindow, GetWindowDpiAwarenessContext, SetThreadDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
    DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED, MDT_EFFECTIVE_DPI,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetClientRect, GetWindow, GetWindowLongW, GetWindowRect,
    GetWindowTextW, GetWindowThreadProcessId, IsIconic, IsWindowVisible, GWL_EXSTYLE, GW_OWNER,
    WS_EX_TOOLWINDOW,
};
use windows_capture::capture::{CaptureControl, Context as WgcContext, GraphicsCaptureApiHandler};
use windows_capture::frame::Frame as WgcFrame;
use windows_capture::graphics_capture_api::InternalCaptureControl;
use windows_capture::settings::{
    ColorFormat, DirtyRegionSettings, GraphicsCaptureItemType, MinimumUpdateIntervalSettings,
    Settings,
};
use windows_capture::window::Window;

use crate::pace;
use crate::session_options::{self, Resolved, SessionOption};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/* ── Win32 reads ───────────────────────────────────────────────────────────────────────────── */

fn hwnd_of(hwnd: usize) -> HWND {
    HWND(hwnd as *mut c_void)
}

/// A Windows error as `0x80070005 Access is denied.`: the code first, since the message is
/// localized.
pub(crate) fn error_text(error: &windows::core::Error) -> String {
    let code = error.code().0 as u32;
    let message = error.message();
    if message.trim().is_empty() {
        format!("{code:#010x}")
    } else {
        format!("{code:#010x} {}", message.trim_end())
    }
}

fn wide_text(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

fn screen_rect(r: RECT) -> ScreenRect {
    ScreenRect {
        left: r.left,
        top: r.top,
        right: r.right,
        bottom: r.bottom,
    }
}

/// Make the calling thread per-monitor DPI aware, so every rectangle it reads is in physical pixels
/// — what a window capture's frames are in — whatever the process's own awareness and the window's
/// (a DPI-unaware game on a 150 % display is the common case).
fn per_monitor_dpi_for_this_thread(who: &str) {
    // SAFETY: a plain call with a predefined context; it changes only this thread.
    let previous =
        unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    if previous.0.is_null() {
        tracing::warn!(
            who,
            "this thread could not be made per-monitor DPI aware ({}); window rectangles may be \
             scaled and the game's crop off",
            std::io::Error::last_os_error()
        );
    } else {
        tracing::debug!(
            who,
            "thread made per-monitor DPI aware: rectangles in physical pixels"
        );
    }
}

/// Every top-level window, top of the z-order first.
fn top_level_windows() -> Result<Vec<usize>, String> {
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

fn window_pid(hwnd: usize) -> u32 {
    let mut pid = 0u32;
    // SAFETY: a plain call with a live output.
    unsafe { GetWindowThreadProcessId(hwnd_of(hwnd), Some(&mut pid)) };
    pid
}

fn class_name(hwnd: usize) -> String {
    let mut class = [0u16; 256];
    // SAFETY: a live buffer; the call writes at most its length.
    let n = unsafe { GetClassNameW(hwnd_of(hwnd), &mut class) };
    String::from_utf16_lossy(&class[..n.max(0) as usize])
}

fn title(hwnd: usize) -> String {
    let mut title = [0u16; 512];
    // SAFETY: as above. Another process's window: the stored caption, no WM_GETTEXT.
    let n = unsafe { GetWindowTextW(hwnd_of(hwnd), &mut title) };
    String::from_utf16_lossy(&title[..n.max(0) as usize])
}

fn cloaked(hwnd: usize) -> bool {
    let mut value = 0u32;
    // SAFETY: `value` is a live u32 of the size given.
    unsafe {
        DwmGetWindowAttribute(
            hwnd_of(hwnd),
            DWMWA_CLOAKED,
            (&mut value as *mut u32).cast(),
            size_of::<u32>() as u32,
        )
    }
    .is_ok_and(|()| value != 0)
}

/// What DWM draws of the window, else its window rectangle.
fn drawn_bounds(hwnd: usize) -> Option<ScreenRect> {
    let h = hwnd_of(hwnd);
    let mut r = RECT::default();
    // SAFETY: a live RECT of the size given.
    let dwm = unsafe {
        DwmGetWindowAttribute(
            h,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            (&mut r as *mut RECT).cast(),
            size_of::<RECT>() as u32,
        )
    };
    if dwm.is_ok() {
        return Some(screen_rect(r));
    }
    // SAFETY: a live RECT.
    unsafe { GetWindowRect(h, &mut r) }
        .ok()
        .map(|()| screen_rect(r))
}

fn area(r: Option<ScreenRect>) -> u64 {
    r.filter(|r| !r.is_empty())
        .map_or(0, |r| r.width().unsigned_abs() * r.height().unsigned_abs())
}

/// Where the window is: its drawn bounds (what a window capture's frame shows), its client area,
/// the DPI it draws at and its monitor's, and — for a window Windows stretches — its own rectangles
/// (`afklink_core::game::client_crop` works its crop out from them). The bounds and client area
/// are physical pixels on a per-monitor aware thread. Read on every frame: a few window-manager
/// reads, no message to the window.
///
/// A stretched window's own rectangles failing to read is not the geometry failing: it comes back
/// without them, and with why (the second value). `client_crop` then moves every edge in from the
/// client area Windows reports, and the frames keep flowing — rather than every frame refused and
/// the viewer's picture frozen over a read the crop can do without. The reason changes rarely and
/// is read on every frame: the caller says it once per change ([`OwnRectsNote`]).
pub fn window_geometry(hwnd: usize) -> Result<(WindowGeometry, Option<String>), String> {
    let h = hwnd_of(hwnd);
    let mut bounds = RECT::default();
    // SAFETY: a live RECT of the size given.
    unsafe {
        DwmGetWindowAttribute(
            h,
            DWMWA_EXTENDED_FRAME_BOUNDS,
            (&mut bounds as *mut RECT).cast(),
            size_of::<RECT>() as u32,
        )
    }
    .map_err(|e| {
        format!(
            "DwmGetWindowAttribute(EXTENDED_FRAME_BOUNDS): {}",
            error_text(&e)
        )
    })?;
    let client = client_on_screen(h)?;
    let dpi = window_dpi(h);
    let (own, own_unread) = match dpi.stretch().map(|_| own_rects(h)) {
        Some(Ok(own)) => (Some(own), None),
        Some(Err(why)) => (None, Some(why)),
        None => (None, None),
    };
    Ok((
        WindowGeometry {
            bounds: screen_rect(bounds),
            client,
            dpi,
            own,
        },
        own_unread,
    ))
}

/// [`window_geometry`] read under per-monitor-v2 DPI awareness on the calling thread itself. The
/// WGC dispatcher window can restore its own DPI context during a callback, so a consumer that
/// reads geometry on the callback thread (a `FrameGate::bounded` one) uses this to stay in the
/// physical pixels WGC frames are in.
pub fn window_geometry_physical(hwnd: usize) -> Result<(WindowGeometry, Option<String>), String> {
    with_physical_dpi(|| window_geometry(hwnd))
}

fn with_physical_dpi<T>(read: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let physical = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2;
    // SAFETY: a query of the calling thread and comparison with a predefined context.
    let is_physical =
        unsafe { AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(), physical).as_bool() };
    if is_physical {
        return read();
    }
    // SAFETY: changes only this thread and the prior context is restored below.
    let previous = unsafe { SetThreadDpiAwarenessContext(physical) };
    if previous.is_invalid() {
        return Err("could not set physical pixels for window geometry".into());
    }
    tracing::trace!(target: afklink_core::EMBED_LOG_TARGET, "window geometry entered per-monitor v2 context");
    let result = read();
    // SAFETY: restores the context returned above on the same thread.
    if unsafe { SetThreadDpiAwarenessContext(previous) }.is_invalid() {
        return Err("could not restore DPI context after window geometry".into());
    }
    result
}

#[cfg(test)]
mod physical_dpi_tests {
    use super::*;
    use windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_UNAWARE;

    #[test]
    fn callback_reads_and_crops_in_physical_context_then_restores_dispatcher() {
        let rect = |left, top, right, bottom| ScreenRect {
            left,
            top,
            right,
            bottom,
        };
        // A 1920×1080 DPI-unaware game, as measured on a 150 % display.
        let bounds = rect(677, 30, 3559, 1698);
        let physical_client = rect(678, 77, 3558, 1697);
        let logical_client = rect(452, 51, 2372, 1131);
        // SAFETY: only the test thread changes context, then restores it before asserting.
        let original = unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_UNAWARE) };
        let geometry = with_physical_dpi(|| {
            // SAFETY: queries this thread and compares it with a predefined context.
            let physical = unsafe {
                AreDpiAwarenessContextsEqual(
                    GetThreadDpiAwarenessContext(),
                    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
                )
                .as_bool()
            };
            Ok(WindowGeometry {
                bounds,
                client: if physical {
                    physical_client
                } else {
                    logical_client
                },
                dpi: WindowDpi {
                    awareness: DpiAwareness::Unaware,
                    window: 96,
                    monitor: 144,
                },
                own: Some(OwnRects {
                    window_px: rect(666, 30, 3570, 1709),
                    window: rect(444, 20, 2380, 1139),
                    client: logical_client,
                }),
            })
        });
        // SAFETY: same thread; restore its original state for other tests.
        let restored = unsafe {
            let context = GetThreadDpiAwarenessContext();
            SetThreadDpiAwarenessContext(original);
            AreDpiAwarenessContextsEqual(context, DPI_AWARENESS_CONTEXT_UNAWARE).as_bool()
        };
        assert!(!original.is_invalid());
        assert!(restored);
        let geometry = geometry.unwrap();
        assert_eq!(geometry.client, physical_client);
        let crop = client_crop(2882, 1668, &geometry).unwrap().crop;
        assert_eq!((crop.w, crop.h), (2878, 1618));
        assert!(crop.y >= 48);
    }
}

/// Why a stretched window's own rectangles could not be read, said once per change: the geometry is
/// read on every frame (and on every finder poll), the reason changes rarely.
#[derive(Default)]
pub struct OwnRectsNote {
    last: Option<String>,
}

impl OwnRectsNote {
    /// Note this read's reason (`None`: read, or not needed); a change is said at `debug`.
    pub fn note(&mut self, who: &str, hwnd: usize, unread: Option<&str>) {
        if self.last.as_deref() == unread {
            return;
        }
        match unread {
            Some(why) => tracing::debug!(
                who,
                hwnd = %format!("{hwnd:#x}"),
                "the stretched game window's own rectangles could not be read ({why}): its crop \
                 moves every edge in a pixel past the filter's reach from the client area Windows \
                 reports, and the frames keep flowing"
            ),
            None => tracing::debug!(
                who,
                hwnd = %format!("{hwnd:#x}"),
                "the game window's own rectangles read again (or are not needed: not stretched)"
            ),
        }
        self.last = unread.map(str::to_string);
    }
}

/// The client area on screen, in the units of this thread's DPI awareness.
fn client_on_screen(h: HWND) -> Result<ScreenRect, String> {
    let mut client = RECT::default();
    // SAFETY: a live RECT.
    unsafe { GetClientRect(h, &mut client) }
        .map_err(|e| format!("GetClientRect: {}", error_text(&e)))?;
    let mut origin = POINT { x: 0, y: 0 };
    // SAFETY: a live POINT.
    if !unsafe { ClientToScreen(h, &mut origin) }.as_bool() {
        return Err(format!(
            "ClientToScreen: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ScreenRect {
        left: origin.x,
        top: origin.y,
        right: origin.x.saturating_add(client.right - client.left),
        bottom: origin.y.saturating_add(client.bottom - client.top),
    })
}

/// The window rectangle, in the units of this thread's DPI awareness.
fn window_on_screen(h: HWND) -> Result<ScreenRect, String> {
    let mut r = RECT::default();
    // SAFETY: a live RECT.
    unsafe { GetWindowRect(h, &mut r) }
        .map(|()| screen_rect(r))
        .map_err(|e| format!("GetWindowRect: {}", error_text(&e)))
}

/// How the window handles the display's scale, the DPI it draws at, and the DPI of the monitor it
/// is mostly on (as this per-monitor aware thread sees it: the monitor's own). A DPI that cannot be
/// read is 0, and the crop then takes the client area as Windows reports it.
fn window_dpi(h: HWND) -> WindowDpi {
    // SAFETY: plain calls on a window handle; a gone window reads an invalid context and DPI 0.
    let (context, window) = unsafe { (GetWindowDpiAwarenessContext(h), GetDpiForWindow(h)) };
    // SAFETY: plain call.
    let monitor = unsafe { MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) };
    let (mut x, mut y) = (0u32, 0u32);
    // SAFETY: two live u32 outputs.
    let monitor = match unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) } {
        Ok(()) => x,
        Err(e) => {
            // Read on every frame: the 0 itself reaches the log, in the crop line said on every
            // change (`dpi`, and why the reported client area was taken).
            tracing::trace!(
                "the game window's monitor DPI is unreadable: {}",
                error_text(&e)
            );
            0
        }
    };
    WindowDpi {
        awareness: awareness_of(context),
        window,
        monitor,
    }
}

fn awareness_of(context: DPI_AWARENESS_CONTEXT) -> DpiAwareness {
    // SAFETY: plain calls on a context handle; an invalid one compares unequal and reads -1.
    unsafe {
        if AreDpiAwarenessContextsEqual(context, DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED).as_bool()
        {
            return DpiAwareness::UnawareGdiScaled;
        }
        if AreDpiAwarenessContextsEqual(context, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
            .as_bool()
        {
            return DpiAwareness::PerMonitorV2;
        }
        match GetAwarenessFromDpiAwarenessContext(context).0 {
            0 => DpiAwareness::Unaware,
            1 => DpiAwareness::System,
            2 => DpiAwareness::PerMonitor,
            _ => DpiAwareness::Unknown,
        }
    }
}

/// A stretched window's rectangles as `client_crop` needs them: its whole window rectangle as this
/// per-monitor aware thread reads it, and its window and client rectangles in its own units — read
/// with this thread switched to the window's DPI awareness for the three calls, then back. In its
/// own units they are the integers the window itself works in; a per-monitor aware thread gets them
/// times the stretch, each edge rounded, which is what put the title bar's row into the crop.
fn own_rects(h: HWND) -> Result<OwnRects, String> {
    let window_px = window_on_screen(h)?;
    // SAFETY: plain calls; the context is the window's own, valid while the window is.
    let previous = unsafe { SetThreadDpiAwarenessContext(GetWindowDpiAwarenessContext(h)) };
    if previous.0.is_null() {
        return Err(format!(
            "switching to the window's DPI awareness: {}",
            std::io::Error::last_os_error()
        ));
    }
    let own = window_on_screen(h).and_then(|window| {
        client_on_screen(h).map(|client| OwnRects {
            window_px,
            window,
            client,
        })
    });
    // SAFETY: as above; `previous` is the context this thread had.
    let restored = unsafe { SetThreadDpiAwarenessContext(previous) };
    if restored.0.is_null() {
        // Never seen; the thread would read every later rectangle in the window's units. Back to
        // per-monitor awareness, as the thread was made at its start.
        per_monitor_dpi_for_this_thread("game window geometry (restoring)");
        return Err(format!(
            "switching back from the window's DPI awareness: {}",
            std::io::Error::last_os_error()
        ));
    }
    own
}

/// A kernel handle opened here and closed on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this owns one live kernel handle.
        if let Err(e) = unsafe { CloseHandle(self.0) } {
            tracing::debug!("CloseHandle failed: {}", error_text(&e));
        }
    }
}

/// Every process's id and exe file name, from a snapshot: no process is opened.
fn process_names() -> Result<HashMap<u32, String>, String> {
    // SAFETY: a plain call; the handle is owned below.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot: {}", error_text(&e)))?;
    let snap = Owned(snap);
    // SAFETY: a plain-data struct; all zeroes is valid, and `dwSize` is set next.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut names = HashMap::new();
    // SAFETY: `entry` is live with `dwSize` set.
    let mut step = unsafe { Process32FirstW(snap.0, &mut entry) };
    while step.is_ok() {
        names.insert(entry.th32ProcessID, wide_text(&entry.szExeFile));
        // SAFETY: as above.
        step = unsafe { Process32NextW(snap.0, &mut entry) };
    }
    match step {
        Err(e) if e.code() != ERROR_NO_MORE_FILES.to_hresult() => {
            Err(format!("walking the process snapshot: {}", error_text(&e)))
        }
        _ => Ok(names),
    }
}

/// A process's full exe path, through a handle opened for `PROCESS_QUERY_LIMITED_INFORMATION` only
/// and closed before this returns.
fn exe_path(pid: u32) -> Result<String, String> {
    // SAFETY: a plain call; the handle is owned below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| format!("OpenProcess(QUERY_LIMITED_INFORMATION): {}", error_text(&e)))?;
    let process = Owned(process);
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

/* ── The finder's window list ──────────────────────────────────────────────────────────────── */

/// The window list the finder reads, on the game capture's thread.
pub struct Win32Windows {
    own_pid: u32,
    /// Full exe paths of processes named like the bound exe, by pid: read once per process.
    paths: HashMap<u32, Result<String, String>>,
    dpi_ready: bool,
    own_note: OwnRectsNote,
}

impl Win32Windows {
    pub fn new() -> Self {
        Self {
            // SAFETY: a plain call.
            own_pid: unsafe { GetCurrentProcessId() },
            paths: HashMap::new(),
            dpi_ready: false,
            own_note: OwnRectsNote::default(),
        }
    }

    fn path_of(&mut self, pid: u32) -> Result<String, String> {
        self.paths
            .entry(pid)
            .or_insert_with(|| {
                let path = exe_path(pid);
                match &path {
                    Ok(p) => tracing::debug!(
                        pid,
                        path = %p,
                        "game finder: read the exe path of a process named like the game \
                         (limited information only)"
                    ),
                    Err(e) => tracing::debug!(
                        pid,
                        "game finder: the exe path of a process named like the game could not be \
                         read: {e}"
                    ),
                }
                path
            })
            .clone()
    }
}

impl Default for Win32Windows {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowSource for Win32Windows {
    fn windows(&mut self, binding: &GameBinding) -> Result<Vec<WindowInfo>, String> {
        if !self.dpi_ready {
            per_monitor_dpi_for_this_thread("game finder");
            self.dpi_ready = true;
        }
        let exe_file = binding.exe_file_name().to_lowercase();
        let names = process_names()?;
        let named_like: HashSet<u32> = names
            .iter()
            .filter(|(_, name)| name.to_lowercase() == exe_file)
            .map(|(pid, _)| *pid)
            .collect();
        // A process that is gone takes its path with it (a pid can be reused).
        self.paths.retain(|pid, _| named_like.contains(pid));

        let mut out = Vec::new();
        for hwnd in top_level_windows()? {
            let pid = window_pid(hwnd);
            if pid == 0 || pid == self.own_pid {
                continue;
            }
            let class = class_name(hwnd);
            let exe_like = named_like.contains(&pid);
            if !exe_like && !binding.class_matches(&class) {
                continue;
            }
            let exe_path = exe_like.then(|| self.path_of(pid));
            let h = hwnd_of(hwnd);
            out.push(WindowInfo {
                hwnd,
                pid,
                class,
                title: title(hwnd),
                exe_name: names.get(&pid).cloned().unwrap_or_default(),
                exe_path,
                // SAFETY: plain calls; a gone window reads false.
                visible: unsafe { IsWindowVisible(h) }.as_bool(),
                // SAFETY: as above.
                minimized: unsafe { IsIconic(h) }.as_bool(),
                cloaked: cloaked(hwnd),
                area: area(drawn_bounds(hwnd)),
            });
        }
        Ok(out)
    }

    fn geometry(&mut self, hwnd: usize) -> Result<WindowGeometry, String> {
        let (geometry, own_unread) = window_geometry(hwnd)?;
        self.own_note
            .note("game finder", hwnd, own_unread.as_deref());
        Ok(geometry)
    }
}

/* ── The picker's list ─────────────────────────────────────────────────────────────────────── */

/// A window the owner can bind as the game.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowChoice {
    pub hwnd: usize,
    pub pid: u32,
    pub exe_path: String,
    pub exe_name: String,
    pub class: String,
    pub title: String,
}

/// The shell's own windows: never a game.
const SHELL_CLASSES: [&str; 4] = [
    "Progman",
    "WorkerW",
    "Shell_TrayWnd",
    "Shell_SecondaryTrayWnd",
];

/// A window without a title this small is not a game's.
const UNTITLED_MIN_AREA: u64 = 320 * 240;

/// The windows the desktop app's picker offers: visible, on this desktop, not owned by another
/// window, not a tool window, not the shell's, not this app's own — each with its exe's full path
/// (a window whose path cannot be read cannot be bound, and is left out).
pub fn list_windows() -> Result<Vec<WindowChoice>, String> {
    // SAFETY: a plain call.
    let own_pid = unsafe { GetCurrentProcessId() };
    let names = process_names()?;
    let mut paths: HashMap<u32, Result<String, String>> = HashMap::new();
    let mut out = Vec::new();
    let mut unreadable = 0u32;
    for hwnd in top_level_windows()? {
        let h = hwnd_of(hwnd);
        // SAFETY: plain calls; a gone window reads false / 0.
        let visible = unsafe { IsWindowVisible(h) }.as_bool();
        // SAFETY: as above.
        let owned = unsafe { GetWindow(h, GW_OWNER) }.is_ok_and(|o| !o.is_invalid());
        // SAFETY: as above.
        let ex_style = unsafe { GetWindowLongW(h, GWL_EXSTYLE) } as u32;
        if !visible || owned || ex_style & WS_EX_TOOLWINDOW.0 != 0 || cloaked(hwnd) {
            continue;
        }
        let pid = window_pid(hwnd);
        if pid == 0 || pid == own_pid {
            continue;
        }
        let class = class_name(hwnd);
        if SHELL_CLASSES.contains(&class.as_str()) {
            continue;
        }
        let title = title(hwnd);
        if title.trim().is_empty() && area(drawn_bounds(hwnd)) < UNTITLED_MIN_AREA {
            continue;
        }
        match paths.entry(pid).or_insert_with(|| exe_path(pid)).clone() {
            Ok(exe_path) => out.push(WindowChoice {
                hwnd,
                pid,
                exe_name: names
                    .get(&pid)
                    .cloned()
                    .unwrap_or_else(|| afklink_core::game::exe_file_name(&exe_path).to_string()),
                exe_path,
                class,
                title,
            }),
            Err(e) => {
                unreadable += 1;
                tracing::debug!(
                    pid,
                    class = %class,
                    "game picker: a window left out, its exe path could not be read: {e}"
                );
            }
        }
    }
    out.sort_by(|a, b| {
        (a.exe_name.to_lowercase(), a.title.to_lowercase())
            .cmp(&(b.exe_name.to_lowercase(), b.title.to_lowercase()))
    });
    tracing::debug!(
        listed = out.len(),
        left_out_unreadable = unreadable,
        "game picker: windows listed"
    );
    Ok(out)
}

/* ── The WGC window capture ────────────────────────────────────────────────────────────────── */

/// The game window as a capture item: `CreateForWindow` made here, so its exact error reaches the
/// log (the crate would report `ItemConvertFailed` and nothing else).
struct GameItem {
    hwnd: usize,
    error: Arc<Mutex<Option<String>>>,
}

impl TryFrom<GameItem> for GraphicsCaptureItemType {
    type Error = windows::core::Error;

    fn try_from(item: GameItem) -> Result<Self, Self::Error> {
        let made = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
            // SAFETY: a window handle is any value; a stale one fails with an error.
            .and_then(|interop| unsafe {
                interop.CreateForWindow::<GraphicsCaptureItem>(hwnd_of(item.hwnd))
            });
        match made {
            Ok(capture_item) => Ok(GraphicsCaptureItemType::Window((
                capture_item,
                Window::from_raw_hwnd(item.hwnd as *mut c_void),
            ))),
            Err(e) => {
                *lock(&item.error) = Some(error_text(&e));
                Err(e)
            }
        }
    }
}

/// What the window handler is constructed with.
pub struct WindowFlags {
    ctx: WindowCaptureContext,
}

/// The frame handler of the game window's capture: pace, crop to the client area, scale to the rung,
/// and hand the frame to the gate — or drop it. An uncropped frame never goes out.
pub struct WindowHandler {
    ctx: WindowCaptureContext,
    start: Instant,
    scratch: Vec<u8>,
    scaler: Scaler,
    next_due: Option<Instant>,
    /// A bounded consumer's target as of the last frame: a new one restarts the pacing.
    last_source_target: Option<Arc<afklink_core::quality::QualityTarget>>,
    /// The last crop, the frame size it was for and the window's DPIs, so a change of any is logged
    /// once.
    last_crop: Option<(Crop, (u32, u32), WindowDpi)>,
    /// Why a stretched window's own rectangles could not be read, said once per change.
    own_note: OwnRectsNote,
    last_scaled: Option<(u32, u32)>,
    /// Frames dropped in a row because they could not be cropped: the first reason and how many.
    refusing: Option<(String, u64)>,
    sent: u64,
}

impl WindowHandler {
    fn refuse(&mut self, why: String) {
        if self.ctx.gate.has_target_source()
            && self.ctx.gate.invalidate_bounded(self.ctx.generation)
        {
            tracing::debug!(target: afklink_core::EMBED_LOG_TARGET, "window crop refused; the bounded consumer's capture invalidated");
        }
        match &mut self.refusing {
            Some((_, n)) => {
                *n += 1;
                tracing::trace!(%why, "game frame dropped");
            }
            None => {
                tracing::debug!(
                    hwnd = %format!("{:#x}", self.ctx.hwnd),
                    "game frames are dropped rather than sent uncropped: {why}"
                );
                self.refusing = Some((why, 1));
            }
        }
    }

    fn end_refusal(&mut self) {
        if let Some((why, n)) = self.refusing.take() {
            tracing::debug!(
                dropped = n,
                first_reason = %why,
                "game frames crop again"
            );
        }
    }

    /// The crop, said once per change of it, of the frame's size or of the window's DPIs: what
    /// Windows reported, the window's scale, and for a stretched window the exact and the rounded
    /// edges, how far each edge moved in, and why.
    fn note_crop(&mut self, frame: (u32, u32), g: &WindowGeometry, plan: &ClientCrop) {
        let key = (plan.crop, frame, g.dpi);
        if self.last_crop == Some(key) {
            return;
        }
        if self.ctx.gate.has_target_source() {
            tracing::debug!(
                target: afklink_core::EMBED_LOG_TARGET,
                frame_w = frame.0,
                frame_h = frame.1,
                client_w = g.client.width(),
                client_h = g.client.height(),
                crop_w = plan.crop.w,
                crop_h = plan.crop.h,
                window_dpi = g.dpi.window,
                monitor_dpi = g.dpi.monitor,
                "bounded consumer's game capture geometry"
            );
        }
        let edges = |e: [f64; 4]| format!("[{:.2},{:.2},{:.2},{:.2}]", e[0], e[1], e[2], e[3]);
        let stretched = plan.stretched;
        tracing::debug!(
            hwnd = %format!("{:#x}", self.ctx.hwnd),
            frame = %format!("{}x{}", frame.0, frame.1),
            bounds = %g.bounds,
            client = %g.client,
            dpi = %g.dpi,
            scale = %stretched.map_or_else(|| "1".to_string(), |s| format!("{:.4}", s.scale)),
            window = %g.own.map_or_else(|| "-".to_string(), |o| o.window_px.to_string()),
            own_window = %g.own.map_or_else(|| "-".to_string(), |o| o.window.to_string()),
            own_client = %g.own.map_or_else(|| "-".to_string(), |o| o.client.to_string()),
            reported = %format!(
                "[{},{},{},{}]",
                plan.reported[0], plan.reported[1], plan.reported[2], plan.reported[3]
            ),
            exact = %stretched.and_then(|s| s.exact).map_or_else(|| "-".to_string(), edges),
            edges = %stretched.map_or_else(|| "-".to_string(), |s| edges(s.edges)),
            crop = %plan.crop,
            inset = %plan.inset_text(),
            on_screen = %plan.on_screen,
            from = ?self.last_crop.map(|(c, _, _)| c.to_string()),
            why = plan.why,
            "game frames cropped to the client area"
        );
        self.last_crop = Some(key);
    }
}

impl GraphicsCaptureApiHandler for WindowHandler {
    type Flags = WindowFlags;
    type Error = BoxError;

    fn new(ctx: WgcContext<Self::Flags>) -> Result<Self, Self::Error> {
        // This thread reads the window's rectangles on every frame: physical pixels, like the frame.
        per_monitor_dpi_for_this_thread("game window capture");
        let ctx = ctx.flags.ctx;
        tracing::debug!(
            hwnd = %format!("{:#x}", ctx.hwnd),
            generation = ctx.generation,
            "game window capture thread started"
        );
        Ok(Self {
            ctx,
            start: Instant::now(),
            scratch: Vec::new(),
            scaler: Scaler::new(),
            next_due: None,
            last_source_target: None,
            last_crop: None,
            own_note: OwnRectsNote::default(),
            last_scaled: None,
            refusing: None,
            sent: 0,
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut WgcFrame,
        capture_control: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        let source_target = self.ctx.gate.source_target();
        if match (&self.last_source_target, &source_target) {
            (Some(previous), Some(current)) => !Arc::ptr_eq(previous, current),
            (None, None) => false,
            _ => true,
        } {
            self.last_source_target.clone_from(&source_target);
            self.next_due = None;
        }
        let target = &self.ctx.target;
        let target = source_target.as_ref().unwrap_or(target);
        // The same pacing as the monitor's (`wgc::Handler`), before any work on the frame.
        target.note_offered();
        let now = Instant::now();
        let (decision, due) = pace::admit(now, self.next_due, target.min_frame_interval());
        self.next_due = Some(due);
        if decision == pace::Admission::Early {
            target.note_early();
            return Ok(());
        }
        // Stopped or replaced meanwhile: nothing of this capture passes, so do not spend on it.
        if !self.ctx.gate.admits(self.ctx.generation) {
            tracing::trace!("game frame of a capture no longer live; dropped");
            return Ok(());
        }

        let (fw, fh) = (frame.width(), frame.height());
        let read_geometry = if self.ctx.gate.has_target_source() {
            window_geometry_physical
        } else {
            window_geometry
        };
        let geometry = match read_geometry(self.ctx.hwnd) {
            Ok((g, own_unread)) => {
                // Not a refusal: the crop goes on without them (`window_geometry`).
                self.own_note
                    .note("game window capture", self.ctx.hwnd, own_unread.as_deref());
                g
            }
            Err(e) => {
                self.refuse(format!("the window's rectangles could not be read: {e}"));
                return Ok(());
            }
        };
        let plan = match client_crop(fw, fh, &geometry) {
            Ok(plan) => plan,
            Err(why) => {
                self.refuse(format!(
                    "{why} (frame {fw}x{fh}, bounds {}, client {}, dpi {})",
                    geometry.bounds, geometry.client, geometry.dpi
                ));
                return Ok(());
            }
        };
        self.end_refusal();
        self.note_crop((fw, fh), &geometry, &plan);
        let crop = plan.crop;
        let target = &self.ctx.target;
        let target = source_target.as_ref().unwrap_or(target);

        // The client area alone leaves the GPU: a copy of that rectangle into a staging texture.
        let buffer = frame
            .buffer_crop(crop.x, crop.y, crop.x + crop.w, crop.y + crop.h)
            .map_err(|e| -> BoxError { format!("crop the game frame: {e}").into() })?;
        let data = buffer.as_nopadding_buffer(&mut self.scratch);
        // The picture's real size, for the ladder: the client area, not the window.
        target.set_source(crop.w, crop.h);
        let max_w = u32::MAX / 2;
        let max_h = target.max_h();
        let mut pixels = Vec::new();
        let (w, h) = self
            .scaler
            .fit_into(data, crop.w, crop.h, max_w, max_h, &mut pixels)
            .map_err(|e| -> BoxError { format!("scale the game frame: {e:#}").into() })?;
        if self.last_scaled != Some((w, h)) {
            tracing::debug!(
                from = ?self.last_scaled,
                to = %format!("{w}x{h}"),
                source = %format!("{}x{}", crop.w, crop.h),
                max_h,
                "game frames scale to a new size"
            );
            self.last_scaled = Some((w, h));
        }

        let out = Frame {
            data: pixels,
            width: w,
            height: h,
            timestamp_ms: self.start.elapsed().as_millis() as u64,
        };
        // A bounded consumer's frame carries the target it was paced against; the agent's own
        // channel takes the frame alone, as it always has.
        let sent = if self.ctx.gate.has_target_source() {
            self.ctx
                .gate
                .send_live_with_target(self.ctx.generation, out, target)
        } else {
            self.ctx.gate.send_live(self.ctx.generation, out)
        };
        match sent {
            GateSend::Sent => {
                self.ctx
                    .gate
                    .sample_native(self.ctx.generation, data, crop.w, crop.h, now);
                self.sent += 1;
                // The pointer's space is the picture's own rectangle, not the client area Windows
                // reports: on a stretched window that one can start on the title bar's row
                // (`afklink_core::game`, «Input»).
                self.ctx.status.set_geometry(CaptureGeometry {
                    hwnd: self.ctx.hwnd,
                    client: plan.on_screen,
                    source: (crop.w, crop.h),
                });
                tracing::trace!(w, h, "game frame");
            }
            GateSend::Refused => {
                tracing::trace!(
                    "game frame refused: the capture was stopped or replaced meanwhile"
                );
            }
            GateSend::Closed => {
                tracing::debug!("game frame consumer gone; stopping the window capture");
                capture_control.stop();
            }
        }
        Ok(())
    }

    fn on_closed(&mut self) -> Result<(), Self::Error> {
        // The window went away (closed, the game exited). Not our own stop, which does not raise
        // this. The game capture's thread sees the capture end and goes black.
        tracing::debug!(
            hwnd = %format!("{:#x}", self.ctx.hwnd),
            generation = self.ctx.generation,
            frames = self.sent,
            "the game window's capture item closed (the window went away)"
        );
        Ok(())
    }
}

/// One running WGC window capture.
struct WgcWindowCapture {
    control: Option<CaptureControl<WindowHandler, BoxError>>,
    hwnd: usize,
}

impl WindowCapture for WgcWindowCapture {
    fn finished(&mut self) -> bool {
        self.control
            .as_ref()
            .is_none_or(CaptureControl::is_finished)
    }

    fn stop(mut self: Box<Self>) -> Option<String> {
        let control = self.control.take()?;
        if control.is_finished() {
            return Some(match control.wait() {
                Ok(()) => {
                    "the window's capture item closed, or its frame consumer is gone".to_string()
                }
                Err(e) => format!("the capture thread failed: {e}"),
            });
        }
        match control.stop() {
            Ok(()) => None,
            Err(e) => {
                tracing::debug!(
                    hwnd = %format!("{:#x}", self.hwnd),
                    "stopping the game window capture failed: {e}"
                );
                Some(format!("stopping it failed: {e}"))
            }
        }
    }
}

impl Drop for WgcWindowCapture {
    /// Never left running: a capture dropped without `stop` (a panic unwinding the game capture's
    /// thread) is stopped here.
    fn drop(&mut self) {
        if let Some(control) = self.control.take() {
            if let Err(e) = control.stop() {
                tracing::debug!(
                    hwnd = %format!("{:#x}", self.hwnd),
                    "stopping a dropped game window capture failed: {e}"
                );
            }
        }
    }
}

/// Starts WGC window captures of the game's window.
pub struct WgcWindowBackend;

impl WindowCaptureBackend for WgcWindowBackend {
    fn start(&mut self, ctx: WindowCaptureContext) -> anyhow::Result<Box<dyn WindowCapture>> {
        let hwnd = ctx.hwnd;
        tracing::debug!(
            hwnd = %format!("{hwnd:#x}"),
            generation = ctx.generation,
            "starting the game window capture (WGC CreateForWindow)"
        );
        let error = Arc::new(Mutex::new(None));
        // The cursor, no border, no secondary windows — each only where this Windows has the
        // property: a capture that refuses to start over a missing one would leave the viewer on
        // black for good (`session_options`, which logs what was set and what was not).
        let started = session_options::start::<WindowHandler, GameItem>(
            "game window",
            &SessionOption::ALL,
            |options: Resolved| {
                Settings::new(
                    GameItem {
                        hwnd,
                        error: error.clone(),
                    },
                    options.cursor,
                    options.border,
                    options.secondary,
                    // `Default`, as for the monitor: pacing is ours (`pace`), see `wgc::start`.
                    MinimumUpdateIntervalSettings::Default,
                    DirtyRegionSettings::Default,
                    ColorFormat::Bgra8,
                    WindowFlags { ctx: ctx.clone() },
                )
            },
        );
        match started {
            Ok(control) => Ok(Box::new(WgcWindowCapture {
                control: Some(control),
                hwnd,
            })),
            Err(e) => {
                let exact = lock(&error).take();
                Err(match exact {
                    Some(exact) => anyhow::anyhow!("{e}: CreateForWindow: {exact}"),
                    None => anyhow::anyhow!("{e}"),
                })
            }
        }
    }
}
