//! Does WGC, capturing the game's window, draw the game's cursor with its tip on the hotspot (the
//! pixel `GetCursorInfo` reports, where a click lands and where the viewer's cursor marker points)
//! when the game does not support the display's scale (Lineage 2, DPI-unaware, at 150 %)? Windows
//! may show such a game's cursor stretched; whether the capture still draws the tip on the hotspot
//! is the question.
//!
//! ## Run it
//!
//! From `agent\`, in an **unelevated** terminal, with the game running and in front:
//!
//! ```text
//! $env:AFK_PROBE_WINDOW = 'scrydegame'   # substring of the window's class, exe name or title
//! cargo test -p afklink-capture --release --lib cursor_capture_probe -- --ignored --nocapture
//! ```
//!
//! - `AFK_PROBE_WINDOW` (required): as for `window_capture_probe`.
//! - `AFK_PROBE_SECONDS`: how long to sample, default 20.
//! - `AFK_PROBE_OUT`: where the JSON goes (default `agent\target\cursor-probe-<yyyymmdd-hhmmss>.json`,
//!   local time); the pictures go to the folder of the same name without `.json`.
//!
//! ## What the person at the PC does
//!
//! Nothing at the terminal. The mouse over the game, held still for about 5 s in each of three
//! places — a plain spot (ground, sky), over an icon, over a dialog — without clicking.
//!
//! ## What it does
//!
//! Two WGC captures of the window (`CreateForWindow`, free-threaded frame pools read by this thread):
//! one with `IsCursorCaptureEnabled = true`, as the agent captures, and one with `false`. Where their
//! frames differ is the cursor as WGC draws it. Every 500 ms: `GetCursorInfo` (its position is the
//! hotspot; shown or not; the shape), the shape's picture (`GetIconInfo` and `GetDIBits` of the copies
//! it returns: size, hotspot, the box of the pixels it draws relative to the hotspot), the window's
//! DPI awareness and DPI and its monitor's, its DWM bounds (where a window capture's frame starts)
//! and client area; the newest frame of each capture, from which a 96×96 crop around the hotspot is
//! copied at full resolution; the pixels that differ between the two crops, and their box relative
//! to the hotspot. Each sample is a JSON row and a PNG of three panels — the crop with the cursor,
//! without it, and their difference (white), magnified ×4 — with the hotspot's pixel outlined red,
//! the picture's box drawn 1:1 at the hotspot green, and, when the window's DPI is not its monitor's,
//! that box scaled by their ratio blue.
//!
//! **It never** injects input, sends a message to the game, changes its focus, z-order or size, or
//! opens its process (its exe name comes from a process snapshot). WGC is DWM composition; it does
//! not read the game's memory.
//!
//! ## What to look at
//!
//! `summary.verdict` first (also printed): over the samples with the cursor shown and still over the
//! game's client area, the drawn cursor's box against the picture's box at the hotspot — 1:1 and
//! scaled — and `tip_offset`, how far the drawn box's top-left corner is from where the picture puts
//! it, in the frame's (the screen's) pixels. About 0,0 at one of the scales: WGC draws the tip on the
//! click point. Then the pictures: the red pixel should sit on the drawn tip. The scene moving under
//! a still cursor (animated water, a character) shows in the difference too: `diff_pixels` far above
//! the picture's own size means the box is not the cursor's alone — the pictures say which.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde_json::{json, Value};
use windows::core::Interface;
use windows::Graphics::Capture::{
    Direct3D11CaptureFrame, Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Graphics::SizeInt32;
use windows::Win32::Foundation::POINT;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_BOX, D3D11_CPU_ACCESS_READ,
    D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, MonitorFromPoint, ReleaseDC, BITMAP, BITMAPINFO,
    BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC, HGDIOBJ, MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::System::WinRT::Direct3D11::IDirect3DDxgiInterfaceAccess;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
use windows::Win32::UI::HiDpi::{
    GetAwarenessFromDpiAwarenessContext, GetDpiForMonitor, GetDpiForWindow,
    GetWindowDpiAwarenessContext, MDT_EFFECTIVE_DPI,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorInfo, GetIconInfo, CURSORINFO, CURSOR_SHOWING, HICON, ICONINFO,
};

use super::win::{
    env_text, error_text, hwnd_of, local_time, make_dpi_aware, note, output_path,
    top_level_windows, window_alive, window_facts, window_visible, write_json, ExeNames, WinFacts,
};
use super::window_capture::{create_device, create_item, winrt_device, write_png};
use super::{match_window, needle_of, parse_seconds, pick_candidate, Candidate, Matched};

const WHO: &str = "cursor_capture_probe";
const DEFAULT_SECONDS: u64 = 20;
const EVERY: Duration = Duration::from_millis(500);
const WAIT_FOR_WINDOW: Duration = Duration::from_secs(60);
/// The crop's side, in the frame's pixels (full resolution).
const CROP: i32 = 96;
/// The pictures' magnification, and the gap between their panels.
const ZOOM: usize = 4;
const GAP: usize = 8;
/// A channel that differs by more than this between the two captures makes the pixel the cursor's.
const DIFF_MIN: u8 = 40;
/// A difference smaller than this many pixels is not taken for a drawn cursor.
const DIFF_PIXELS_MIN: usize = 10;
const POOL_BUFFERS: i32 = 2;

/// `[left, top, right, bottom]`, inclusive: a box of pixels.
type PixelBox = [i32; 4];

#[test]
#[ignore = "captures the game's window around the cursor and saves pictures of it; run by hand with the owner, see the module docs"]
fn cursor_capture_probe() -> Result<()> {
    let Some(window) = env_text("AFK_PROBE_WINDOW")?.as_deref().and_then(needle_of) else {
        bail!(
            "AFK_PROBE_WINDOW is not set: set it to a substring of the window's class, exe name or \
             title, e.g. $env:AFK_PROBE_WINDOW = 'scrydegame', then run again"
        );
    };
    let seconds = parse_seconds(env_text("AFK_PROBE_SECONDS")?.as_deref(), DEFAULT_SECONDS)
        .map_err(anyhow::Error::msg)?;
    let out = output_path("cursor-probe")?;
    let pictures = out.with_extension("");
    println!(
        "{WHO}: window \"{window}\", {seconds} s; output {}, pictures {}",
        out.display(),
        pictures.display()
    );
    let mut notes = Vec::new();
    let started_local = local_time();
    // Before anything reads a coordinate: every rectangle and position in physical pixels.
    let dpi = make_dpi_aware(WHO, &mut notes);
    let run = run(&window, seconds, &pictures, &mut notes);
    let (outcome, record) = match run {
        Ok(record) => ("complete".to_owned(), record),
        Err(error) => (format!("{error:#}"), Value::Null),
    };
    let json = json!({
        "probe": "afklink-capture probe::cursor_capture",
        "format": 1,
        "started_local": started_local,
        "outcome": outcome,
        "config": {
            "window": window,
            "seconds": seconds,
            "every_ms": EVERY.as_millis() as u64,
            "crop": CROP,
            "zoom": ZOOM,
            "diff_min": DIFF_MIN,
            "out": out.display().to_string(),
            "pictures_dir": pictures.display().to_string(),
            "boxes": "[left, top, right, bottom], inclusive, relative to the hotspot's pixel \
                (0,0) unless named otherwise; frame pixels are the window capture's (its origin is \
                the window's DWM bounds' top-left corner)",
        },
        "dpi": dpi,
        "run": record,
        "notes": notes,
    });
    write_json(&out, &json)?;
    println!("{WHO}: written {}", out.display());
    if outcome != "complete" {
        bail!("{outcome}");
    }
    Ok(())
}

/// The run: the window, the two captures, the samples, the verdict.
fn run(needle: &str, seconds: u64, pictures: &Path, notes: &mut Vec<String>) -> Result<Value> {
    let _ro = Ro::init(notes);
    let (target, exe) = find_target(needle)?;
    println!(
        "{WHO}: target {:#x} class \"{}\" exe {} pid {}",
        target.hwnd,
        target.class,
        exe.as_deref().unwrap_or("?"),
        target.pid
    );
    let (device, context, _) = create_device().map_err(anyhow::Error::msg)?;
    let d3d = winrt_device(&device).map_err(anyhow::Error::msg)?;
    let mut with = Capture::start(&device, &d3d, target.hwnd, true, notes)
        .map_err(|e| anyhow::anyhow!("the capture with the cursor did not start: {e}"))?;
    let mut without = match Capture::start(&device, &d3d, target.hwnd, false, notes) {
        Ok(capture) => Some(capture),
        Err(error) => {
            note(
                WHO,
                notes,
                format!(
                    "the capture without the cursor did not start ({error}): crops only, no \
                     difference"
                ),
            );
            None
        }
    };
    let pictures_on = match std::fs::create_dir_all(pictures) {
        Ok(()) => true,
        Err(error) => {
            note(
                WHO,
                notes,
                format!(
                    "creating {} failed ({error}): no pictures",
                    pictures.display()
                ),
            );
            false
        }
    };
    println!();
    println!(
        "{WHO}: sampling for {seconds} s. At the PC: the mouse over the game, still for about 5 s \
         in each of three places (a plain spot, an icon, a dialog), no clicks."
    );
    println!();

    let begun = Instant::now();
    let mut samples = Vec::new();
    let mut shapes: Vec<(usize, Result<Shape, String>)> = Vec::new();
    let mut n = 0u32;
    while begun.elapsed() < Duration::from_secs(seconds) {
        let tick = Instant::now();
        n += 1;
        if !window_alive(target.hwnd) {
            note(WHO, notes, format!("sample {n}: the window is gone"));
            break;
        }
        let taken = sample(
            n,
            begun,
            &target,
            &context,
            &d3d,
            &mut with,
            without.as_mut(),
            &mut shapes,
            pictures_on.then_some(pictures),
            notes,
        );
        println!("{WHO}: {}", taken.line);
        samples.push(taken);
        std::thread::sleep(EVERY.saturating_sub(tick.elapsed()));
    }
    let verdict = verdict(&samples);
    println!("{WHO}: summary");
    for line in &verdict {
        println!("{WHO}:   - {line}");
    }
    Ok(json!({
        "target": { "window": target, "exe": exe },
        "captures": {
            "with_cursor_frames": with.frames,
            "without_cursor_frames": without.as_ref().map(|c| c.frames),
        },
        "shapes": shapes.iter().map(|(handle, shape)| json!({
            "shape": format!("{handle:#x}"),
            "picture": shape.as_ref().map_or_else(|e| json!({ "error": e }), Shape::record),
        })).collect::<Vec<_>>(),
        "summary": { "verdict": verdict },
        "samples": samples.iter().map(|s| s.record.clone()).collect::<Vec<_>>(),
    }))
}

/// `RoInitialize(MTA)` for this thread, balanced when dropped (after every WinRT object of the run).
struct Ro(bool);

impl Ro {
    fn init(notes: &mut Vec<String>) -> Self {
        // SAFETY: plain call; balanced in `drop` when it succeeded.
        match unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
            Ok(()) => Self(true),
            Err(error) => {
                note(
                    WHO,
                    notes,
                    format!(
                        "RoInitialize(MTA): {} (already initialised?)",
                        error_text(&error)
                    ),
                );
                Self(false)
            }
        }
    }
}

impl Drop for Ro {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances this thread's successful `RoInitialize`.
            unsafe { RoUninitialize() };
        }
    }
}

/// The visible top-level window matching `needle` the way `window_capture_probe` chooses it (a class
/// or exe match first, then one on screen, then the largest), waited for up to a minute.
fn find_target(needle: &str) -> Result<(WinFacts, Option<String>)> {
    let begun = Instant::now();
    let mut names = ExeNames::new();
    loop {
        let mut found: Vec<(WinFacts, Option<String>, Matched)> = Vec::new();
        for hwnd in top_level_windows().map_err(anyhow::Error::msg)? {
            if !window_visible(hwnd) {
                continue;
            }
            let facts = window_facts(hwnd);
            let exe = names.get(facts.pid);
            let matched = match_window(needle, &facts.class, exe.as_deref(), &facts.title);
            if matched.any() {
                found.push((facts, exe, matched));
            }
        }
        let candidates: Vec<Candidate> = found
            .iter()
            .map(|(f, _, m)| Candidate {
                matched: *m,
                minimized: f.minimized,
                cloaked: f.cloaked.unwrap_or(0) != 0,
                area: f.bounds().map_or(0, super::area),
            })
            .collect();
        if let Some(best) = pick_candidate(&candidates) {
            if found.len() > 1 {
                println!(
                    "{WHO}: {} windows match \"{needle}\"; taking {:#x}",
                    found.len(),
                    found[best].0.hwnd
                );
            }
            let (facts, exe, _) = found.swap_remove(best);
            return Ok((facts, exe));
        }
        if begun.elapsed() >= WAIT_FOR_WINDOW {
            bail!(
                "no visible top-level window's class, exe name or title contains \"{needle}\" \
                 within {} s",
                WAIT_FOR_WINDOW.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// One WGC capture of the window, read by this thread: no frame handler, the newest frame taken
/// when a sample wants it.
struct Capture {
    cursor: bool,
    pool: Direct3D11CaptureFramePool,
    session: GraphicsCaptureSession,
    /// Kept for as long as the session runs.
    _item: GraphicsCaptureItem,
    size: (i32, i32),
    /// Where crops are copied to, `CROP`×`CROP`.
    staging: ID3D11Texture2D,
    frames: u64,
}

impl Capture {
    fn start(
        device: &ID3D11Device,
        d3d: &IDirect3DDevice,
        hwnd: usize,
        cursor: bool,
        notes: &mut Vec<String>,
    ) -> std::result::Result<Self, String> {
        let item = create_item(hwnd)?;
        let size = item
            .Size()
            .map_err(|e| format!("the item's Size: {}", error_text(&e)))?;
        let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
            d3d,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            POOL_BUFFERS,
            size,
        )
        .map_err(|e| format!("CreateFreeThreaded: {}", error_text(&e)))?;
        let session = pool
            .CreateCaptureSession(&item)
            .map_err(|e| format!("CreateCaptureSession: {}", error_text(&e)))?;
        session
            .SetIsCursorCaptureEnabled(cursor)
            .map_err(|e| format!("IsCursorCaptureEnabled = {cursor}: {}", error_text(&e)))?;
        if let Err(error) = session.SetIsBorderRequired(false) {
            note(
                WHO,
                notes,
                format!(
                    "IsBorderRequired = false: {} (a yellow frame may show)",
                    error_text(&error)
                ),
            );
        }
        let staging = staging(device)?;
        session
            .StartCapture()
            .map_err(|e| format!("StartCapture: {}", error_text(&e)))?;
        println!(
            "{WHO}: capture {} the cursor started, {}x{}",
            if cursor { "with" } else { "without" },
            size.Width,
            size.Height
        );
        Ok(Self {
            cursor,
            pool,
            session,
            _item: item,
            size: (size.Width, size.Height),
            staging,
            frames: 0,
        })
    }

    /// The newest frame waiting, the older ones closed; `None` when none came since the last look,
    /// or when the window's size changed (the pool is recreated for it; the next frame is whole).
    fn newest(
        &mut self,
        d3d: &IDirect3DDevice,
        notes: &mut Vec<String>,
    ) -> Option<Direct3D11CaptureFrame> {
        let mut newest: Option<Direct3D11CaptureFrame> = None;
        loop {
            match self.pool.TryGetNextFrame() {
                Ok(frame) => {
                    self.frames += 1;
                    if let Some(old) = newest.replace(frame) {
                        close(&old, notes);
                    }
                }
                // No frame waiting: the call answers none.
                Err(error) if error.code().is_ok() => break,
                Err(error) => {
                    note(
                        WHO,
                        notes,
                        format!("TryGetNextFrame: {}", error_text(&error)),
                    );
                    break;
                }
            }
        }
        let frame = newest?;
        let content = match frame.ContentSize() {
            Ok(size) => (size.Width, size.Height),
            Err(error) => {
                note(WHO, notes, format!("ContentSize: {}", error_text(&error)));
                close(&frame, notes);
                return None;
            }
        };
        if content == self.size {
            return Some(frame);
        }
        close(&frame, notes);
        if content.0 > 0 && content.1 > 0 {
            let size = SizeInt32 {
                Width: content.0,
                Height: content.1,
            };
            match self.pool.Recreate(
                d3d,
                DirectXPixelFormat::B8G8R8A8UIntNormalized,
                POOL_BUFFERS,
                size,
            ) {
                Ok(()) => {
                    note(
                        WHO,
                        notes,
                        format!(
                            "the window's size changed to {}x{}: the pool is recreated",
                            content.0, content.1
                        ),
                    );
                    self.size = content;
                }
                Err(error) => note(
                    WHO,
                    notes,
                    format!("recreating the pool: {}", error_text(&error)),
                ),
            }
        }
        None
    }

    /// The frame's pixels inside `rect` (frame pixels, right and bottom exclusive, cut to the frame),
    /// tightly packed BGRA, and the part read.
    fn crop(
        &self,
        context: &ID3D11DeviceContext,
        frame: &Direct3D11CaptureFrame,
        rect: [i32; 4],
    ) -> std::result::Result<([i32; 4], Vec<u8>), String> {
        let texture: ID3D11Texture2D = frame
            .Surface()
            .and_then(|surface| surface.cast::<IDirect3DDxgiInterfaceAccess>())
            // SAFETY: a live surface's DXGI access interface.
            .and_then(|access| unsafe { access.GetInterface::<ID3D11Texture2D>() })
            .map_err(|e| format!("the frame's texture: {}", error_text(&e)))?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: a live texture and a live description.
        unsafe { texture.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(format!("unexpected texture format {}", desc.Format.0));
        }
        let w = i32::try_from(desc.Width).unwrap_or(0).min(self.size.0);
        let h = i32::try_from(desc.Height).unwrap_or(0).min(self.size.1);
        let r = [
            rect[0].clamp(0, w),
            rect[1].clamp(0, h),
            rect[2].clamp(0, w),
            rect[3].clamp(0, h),
        ];
        let (cw, ch) = (r[2] - r[0], r[3] - r[1]);
        if cw <= 0 || ch <= 0 || cw > CROP || ch > CROP {
            return Err(format!("the crop {rect:?} is not inside the {w}x{h} frame"));
        }
        let region = D3D11_BOX {
            left: r[0].unsigned_abs(),
            top: r[1].unsigned_abs(),
            front: 0,
            right: r[2].unsigned_abs(),
            bottom: r[3].unsigned_abs(),
            back: 1,
        };
        // SAFETY: two live textures of the same format; the region lies inside the source and fits
        // the CROP×CROP destination at its origin.
        unsafe {
            context.CopySubresourceRegion(
                &self.staging,
                0,
                0,
                0,
                0,
                &texture,
                0,
                Some(&region as *const D3D11_BOX),
            );
        }
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: a live staging texture with CPU read access, and a live output.
        unsafe { context.Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) }
            .map_err(|e| format!("mapping the staging texture: {}", error_text(&e)))?;
        let row = cw.unsigned_abs() as usize * 4;
        let pitch = mapped.RowPitch as usize;
        let read = if mapped.pData.is_null() || pitch < row {
            Err(format!(
                "the mapped texture is unusable (data null {}, row pitch {pitch} < {row})",
                mapped.pData.is_null()
            ))
        } else {
            let mut bgra = Vec::with_capacity(row * ch.unsigned_abs() as usize);
            for y in 0..ch.unsigned_abs() as usize {
                // SAFETY: the mapping holds CROP rows of `RowPitch` bytes; `y < ch <= CROP` and
                // `row <= pitch`, so this line lies inside it.
                let line = unsafe {
                    std::slice::from_raw_parts(mapped.pData.cast::<u8>().add(y * pitch), row)
                };
                bgra.extend_from_slice(line);
            }
            Ok((r, bgra))
        };
        // SAFETY: balances the successful `Map` above.
        unsafe { context.Unmap(&self.staging, 0) };
        read
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        let which = if self.cursor { "with" } else { "without" };
        if let Err(error) = self.session.Close() {
            println!(
                "{WHO}: closing the capture {which} the cursor: {}",
                error_text(&error)
            );
        }
        if let Err(error) = self.pool.Close() {
            println!(
                "{WHO}: closing the pool {which} the cursor: {}",
                error_text(&error)
            );
        }
    }
}

fn close(frame: &Direct3D11CaptureFrame, notes: &mut Vec<String>) {
    if let Err(error) = frame.Close() {
        note(
            WHO,
            notes,
            format!("closing a frame: {}", error_text(&error)),
        );
    }
}

/// A CPU-readable `CROP`×`CROP` BGRA texture, the crops' destination.
fn staging(device: &ID3D11Device) -> std::result::Result<ID3D11Texture2D, String> {
    let desc = D3D11_TEXTURE2D_DESC {
        Width: CROP.unsigned_abs(),
        Height: CROP.unsigned_abs(),
        MipLevels: 1,
        ArraySize: 1,
        Format: DXGI_FORMAT_B8G8R8A8_UNORM,
        SampleDesc: DXGI_SAMPLE_DESC {
            Count: 1,
            Quality: 0,
        },
        Usage: D3D11_USAGE_STAGING,
        BindFlags: 0,
        CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
        MiscFlags: 0,
    };
    let mut texture = None;
    // SAFETY: a live description and output.
    unsafe { device.CreateTexture2D(&desc, None, Some(&mut texture)) }
        .map_err(|e| format!("creating the staging texture: {}", error_text(&e)))?;
    texture.ok_or_else(|| "creating the staging texture returned none".to_owned())
}

/// The cursor now.
struct CursorNow {
    x: i32,
    y: i32,
    showing: bool,
    shape: usize,
}

fn cursor_now() -> std::result::Result<CursorNow, String> {
    let mut info = CURSORINFO {
        cbSize: std::mem::size_of::<CURSORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: a live CURSORINFO with `cbSize` set.
    unsafe { GetCursorInfo(&mut info) }
        .map_err(|e| format!("GetCursorInfo: {}", error_text(&e)))?;
    Ok(CursorNow {
        x: info.ptScreenPos.x,
        y: info.ptScreenPos.y,
        showing: info.flags.0 & CURSOR_SHOWING.0 != 0 && !info.hCursor.0.is_null(),
        shape: info.hCursor.0 as usize,
    })
}

/// A cursor's picture, read once per shape.
#[derive(Clone, Debug)]
struct Shape {
    width: i32,
    height: i32,
    hotspot: (i32, i32),
    color: bool,
    /// The drawn pixels' box relative to the hotspot; `None` when it draws none or is unreadable.
    drawn: Option<PixelBox>,
}

impl Shape {
    fn record(&self) -> Value {
        json!({
            "size": [self.width, self.height],
            "hotspot": [self.hotspot.0, self.hotspot.1],
            "color": self.color,
            "drawn_from_hotspot": self.drawn,
        })
    }
}

/// A bitmap `GetIconInfo` made for us, deleted when dropped.
struct Bitmap(HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        if self.0 .0.is_null() {
            return;
        }
        // SAFETY: a bitmap GetIconInfo created for this caller, selected into no DC.
        if !unsafe { DeleteObject(HGDIOBJ::from(self.0)) }.as_bool() {
            println!("{WHO}: deleting a copy of the cursor's bitmap failed");
        }
    }
}

/// The screen's DC, released when dropped.
struct ScreenDc(HDC);

impl Drop for ScreenDc {
    fn drop(&mut self) {
        // SAFETY: the DC GetDC(None) returned, released once.
        if unsafe { ReleaseDC(None, self.0) } == 0 {
            println!("{WHO}: releasing the screen DC failed");
        }
    }
}

fn bitmap_size(bitmap: &Bitmap) -> std::result::Result<(i32, i32), String> {
    let mut info = BITMAP::default();
    // SAFETY: a live bitmap handle and a live BITMAP of the size given.
    let wrote = unsafe {
        GetObjectW(
            HGDIOBJ::from(bitmap.0),
            std::mem::size_of::<BITMAP>() as i32,
            Some((&mut info as *mut BITMAP).cast()),
        )
    };
    if wrote == 0 {
        return Err("GetObjectW on the cursor's bitmap answered nothing".to_owned());
    }
    Ok((info.bmWidth, info.bmHeight))
}

/// A bitmap's pixels as 32-bit `0xAARRGGBB`, top row first.
fn bitmap_pixels(
    dc: &ScreenDc,
    bitmap: &Bitmap,
    (w, h): (i32, i32),
) -> std::result::Result<Vec<u32>, String> {
    if !(1..=1024).contains(&w) || !(1..=2048).contains(&h) {
        return Err(format!("a {w}x{h} bitmap is not read"));
    }
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w,
            biHeight: -h,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut out = vec![0u32; w.unsigned_abs() as usize * h.unsigned_abs() as usize];
    // SAFETY: `out` holds `h` rows of `w` 32-bit pixels, which a 32-bit BI_RGB request writes (no
    // colour table); `info` is a live BITMAPINFO.
    let lines = unsafe {
        GetDIBits(
            dc.0,
            bitmap.0,
            0,
            h.unsigned_abs(),
            Some(out.as_mut_ptr().cast()),
            &mut info,
            DIB_RGB_COLORS,
        )
    };
    if lines <= 0 {
        return Err(format!("GetDIBits read {lines} lines"));
    }
    Ok(out)
}

/// The box a picture draws, in its own pixels ([`drawn_box`]).
fn picture_drawn(
    mask: &Bitmap,
    mask_size: (i32, i32),
    color: Option<&Bitmap>,
    (width, height): (i32, i32),
) -> std::result::Result<Option<PixelBox>, String> {
    // SAFETY: plain call; a DC it answers is released by the guard.
    let dc = unsafe { GetDC(None) };
    if dc.0.is_null() {
        return Err("GetDC(None) answered no DC".to_owned());
    }
    let dc = ScreenDc(dc);
    let mask_pixels = bitmap_pixels(&dc, mask, mask_size)?;
    let color_pixels = match color {
        Some(c) => Some(bitmap_pixels(&dc, c, (width, height))?),
        None => None,
    };
    let side = |v: i32| v.unsigned_abs() as usize;
    Ok(drawn_box(
        side(width),
        side(height),
        color_pixels.as_deref(),
        &mask_pixels,
    ))
}

/// The shape's picture: size, hotspot, colour or monochrome, and the box it draws.
fn shape(handle: usize) -> std::result::Result<Shape, String> {
    let mut info = ICONINFO::default();
    // SAFETY: any handle may be asked about (a stale one fails); `info` is a live ICONINFO.
    unsafe { GetIconInfo(HICON(handle as *mut std::ffi::c_void), &mut info) }
        .map_err(|e| format!("GetIconInfo: {}", error_text(&e)))?;
    let mask = Bitmap(info.hbmMask);
    let color = (!info.hbmColor.0.is_null()).then_some(Bitmap(info.hbmColor));
    let mask_size = bitmap_size(&mask)?;
    let (width, height) = match &color {
        Some(c) => bitmap_size(c)?,
        None => (mask_size.0, mask_size.1 / 2),
    };
    let hotspot = (
        i32::try_from(info.xHotspot).unwrap_or(0),
        i32::try_from(info.yHotspot).unwrap_or(0),
    );
    let drawn =
        picture_drawn(&mask, mask_size, color.as_ref(), (width, height)).unwrap_or_else(|error| {
            println!("{WHO}: the cursor's pixels could not be read: {error}");
            None
        });
    Ok(Shape {
        width,
        height,
        hotspot,
        color: color.is_some(),
        drawn: drawn.map(|b| {
            [
                b[0] - hotspot.0,
                b[1] - hotspot.1,
                b[2] - hotspot.0,
                b[3] - hotspot.1,
            ]
        }),
    })
}

/// The window's DPI awareness in words, its DPI, and its monitor's (0: unknown).
fn window_dpi(hwnd: usize, at: (i32, i32)) -> (&'static str, u32, u32) {
    let h = hwnd_of(hwnd);
    // SAFETY: plain calls on a window handle; a gone window reads invalid / 0.
    let (awareness, dpi) = unsafe {
        (
            GetAwarenessFromDpiAwarenessContext(GetWindowDpiAwarenessContext(h)).0,
            GetDpiForWindow(h),
        )
    };
    // SAFETY: plain call.
    let monitor = unsafe { MonitorFromPoint(POINT { x: at.0, y: at.1 }, MONITOR_DEFAULTTONEAREST) };
    let (mut mx, mut my) = (0u32, 0u32);
    // SAFETY: two live outputs.
    let monitor_dpi = unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut mx, &mut my) }
        .map_or(0, |()| mx);
    let name = match awareness {
        0 => "unaware",
        1 => "system aware",
        2 => "per-monitor aware",
        _ => "invalid",
    };
    (name, dpi, monitor_dpi)
}

/// One sample: its line for the terminal and its JSON row, and what the verdict needs.
struct Sample {
    line: String,
    record: Value,
    /// Shown, over the client area, both crops read and a difference found.
    measured: Option<Measured>,
}

#[derive(Clone, Copy, Debug)]
struct Measured {
    /// The difference's box, and the picture's (1:1 and scaled), relative to the hotspot.
    drawn: PixelBox,
    picture: PixelBox,
    scaled: PixelBox,
    scale: f64,
}

#[allow(clippy::too_many_arguments)]
fn sample(
    n: u32,
    begun: Instant,
    target: &WinFacts,
    context: &ID3D11DeviceContext,
    d3d: &IDirect3DDevice,
    with: &mut Capture,
    without: Option<&mut Capture>,
    shapes: &mut Vec<(usize, Result<Shape, String>)>,
    pictures: Option<&Path>,
    notes: &mut Vec<String>,
) -> Sample {
    let t_ms = begun.elapsed().as_millis() as u64;
    let fail = |why: String| Sample {
        line: format!("#{n} +{:.1} s: {why}", t_ms as f64 / 1000.0),
        record: json!({ "n": n, "t_ms": t_ms, "skipped": why }),
        measured: None,
    };
    let cursor = match cursor_now() {
        Ok(c) => c,
        Err(error) => return fail(error),
    };
    let geometry = match crate::game::window_geometry(target.hwnd) {
        Ok((g, own_unread)) => {
            if let Some(why) = own_unread {
                note(
                    WHO,
                    notes,
                    format!("sample {n}: the window's own rectangles: {why}"),
                );
            }
            g
        }
        Err(error) => return fail(format!("the window's geometry: {error}")),
    };
    if !shapes.iter().any(|(h, _)| *h == cursor.shape) && cursor.shape != 0 {
        shapes.push((cursor.shape, shape(cursor.shape)));
    }
    let picture = shapes
        .iter()
        .find(|(h, _)| *h == cursor.shape)
        .and_then(|(_, s)| s.as_ref().ok())
        .cloned();
    let (awareness, dpi, monitor_dpi) = window_dpi(target.hwnd, (cursor.x, cursor.y));
    let scale = if dpi > 0 && monitor_dpi > 0 {
        f64::from(monitor_dpi) / f64::from(dpi)
    } else {
        1.0
    };
    let b = geometry.bounds;
    let c = geometry.client;
    let over_client =
        (c.left..c.right).contains(&cursor.x) && (c.top..c.bottom).contains(&cursor.y);
    // The hotspot in the frame, and the crop around it.
    let hot = (cursor.x - b.left, cursor.y - b.top);
    let rect = [
        hot.0 - CROP / 2,
        hot.1 - CROP / 2,
        hot.0 + CROP / 2,
        hot.1 + CROP / 2,
    ];
    let frame_with = with.newest(d3d, notes);
    let (frame_without, without) = match without {
        Some(capture) => (capture.newest(d3d, notes), Some(capture)),
        None => (None, None),
    };
    let crop_with = frame_with
        .as_ref()
        .map(|f| with.crop(context, f, rect))
        .transpose();
    let crop_without = match (&frame_without, &without) {
        (Some(f), Some(capture)) => capture.crop(context, f, rect).map(Some),
        _ => Ok(None),
    };
    if let Some(f) = &frame_with {
        close(f, notes);
    }
    if let Some(f) = &frame_without {
        close(f, notes);
    }
    let crop_with = match crop_with {
        Ok(Some(crop)) => crop,
        Ok(None) => return fail("no new frame with the cursor".to_owned()),
        Err(error) => return fail(format!("the crop with the cursor: {error}")),
    };
    let crop_without = crop_without.unwrap_or_else(|error| {
        note(
            WHO,
            notes,
            format!("#{n}: the crop without the cursor: {error}"),
        );
        None
    });
    let (r, with_px) = crop_with;
    let (cw, ch) = ((r[2] - r[0]) as usize, (r[3] - r[1]) as usize);
    // The hotspot in the crop.
    let hot_in = (hot.0 - r[0], hot.1 - r[1]);
    let same_rect = crop_without.as_ref().is_some_and(|(r2, _)| *r2 == r);
    let (diff, diff_pixels) = match &crop_without {
        Some((_, without_px)) if same_rect => diff_box(&with_px, without_px, cw, ch, DIFF_MIN),
        _ => (None, 0),
    };
    let rel = |p: PixelBox| {
        [
            p[0] - hot_in.0,
            p[1] - hot_in.1,
            p[2] - hot_in.0,
            p[3] - hot_in.1,
        ]
    };
    let drawn = diff.map(rel);
    let picture_box = picture.as_ref().and_then(|s| s.drawn);
    let scaled = picture_box.map(|p| scale_box(p, scale));
    let file = format!("{n:03}_t{:05.1}s.png", t_ms as f64 / 1000.0);
    let saved = pictures.map(|dir| {
        let marks = Marks {
            hotspot: hot_in,
            picture: picture_box.map(|p| shift(p, hot_in)),
            scaled: scaled
                .filter(|_| (scale - 1.0).abs() > 0.01)
                .map(|p| shift(p, hot_in)),
        };
        let without_px = crop_without
            .as_ref()
            .filter(|_| same_rect)
            .map(|(_, px)| px.as_slice());
        let (w, h, rgb) = panels(&with_px, without_px, cw, ch, &marks);
        write_png(&dir.join(&file), w, h, &rgb)
    });
    if let Some(Err(error)) = &saved {
        note(
            WHO,
            notes,
            format!("#{n}: picture {file} not written: {error}"),
        );
    }
    let measured = match (drawn, picture_box, scaled) {
        (Some(drawn), Some(picture), Some(scaled))
            if cursor.showing && over_client && diff_pixels >= DIFF_PIXELS_MIN =>
        {
            Some(Measured {
                drawn,
                picture,
                scaled,
                scale,
            })
        }
        _ => None,
    };
    let offset = |p: PixelBox| drawn.map(|d| [d[0] - p[0], d[1] - p[1]]);
    let line = format!(
        "#{n} +{:.1} s: cursor {},{} {} shape {:#x}; {}; dpi {dpi}/{monitor_dpi} ({awareness}); \
         drawn {} ({diff_pixels} px) vs picture {} — tip offset 1:1 {}, scaled {}",
        t_ms as f64 / 1000.0,
        cursor.x,
        cursor.y,
        if cursor.showing { "shown" } else { "hidden" },
        cursor.shape,
        if over_client {
            "over the client area"
        } else {
            "outside the client area"
        },
        box_text(drawn),
        box_text(picture_box),
        offset_text(picture_box.and_then(offset)),
        offset_text(scaled.and_then(offset)),
    );
    Sample {
        line,
        record: json!({
            "n": n,
            "t_ms": t_ms,
            "cursor": [cursor.x, cursor.y],
            "shown": cursor.showing,
            "shape": format!("{:#x}", cursor.shape),
            "over_client": over_client,
            "frame_origin": [b.left, b.top],
            "client": [c.left, c.top, c.right, c.bottom],
            "hotspot_in_frame": [hot.0, hot.1],
            "crop_in_frame": r,
            "awareness": awareness,
            "window_dpi": dpi,
            "monitor_dpi": monitor_dpi,
            "drawn_from_hotspot": drawn,
            "diff_pixels": diff_pixels,
            "picture_from_hotspot": picture_box,
            "picture_scaled_from_hotspot": scaled,
            "tip_offset_1to1": picture_box.and_then(offset),
            "tip_offset_scaled": scaled.and_then(offset),
            "without_cursor": crop_without.is_some(),
            "file": saved.as_ref().filter(|s| s.is_ok()).map(|_| file.clone()),
        }),
        measured,
    }
}

/// The verdict over the samples that measured something.
fn verdict(samples: &[Sample]) -> Vec<String> {
    let measured: Vec<Measured> = samples.iter().filter_map(|s| s.measured).collect();
    let mut lines = vec![format!(
        "{} samples; {} with the cursor shown over the client area and a drawn cursor found",
        samples.len(),
        measured.len()
    )];
    if measured.is_empty() {
        lines.push(
            "nothing measured: the cursor was not shown over the game, the capture without the \
             cursor did not run, or no difference was found — see the pictures"
                .to_owned(),
        );
        return lines;
    }
    let med = |f: &dyn Fn(&Measured) -> i32| {
        let mut v: Vec<i32> = measured.iter().map(f).collect();
        median(&mut v).unwrap_or(0)
    };
    let drawn = [
        med(&|m| m.drawn[0]),
        med(&|m| m.drawn[1]),
        med(&|m| m.drawn[2]),
        med(&|m| m.drawn[3]),
    ];
    let one = [
        med(&|m| m.drawn[0] - m.picture[0]),
        med(&|m| m.drawn[1] - m.picture[1]),
    ];
    let scaled = [
        med(&|m| m.drawn[0] - m.scaled[0]),
        med(&|m| m.drawn[1] - m.scaled[1]),
    ];
    let scale = measured.first().map_or(1.0, |m| m.scale);
    let picture = measured.first().map(|m| m.picture);
    lines.push(format!(
        "the drawn cursor (median) {} from the hotspot; the picture {} 1:1, {} scaled ×{scale:.2}",
        box_text(Some(drawn)),
        box_text(picture),
        box_text(measured.first().map(|m| m.scaled)),
    ));
    lines.push(format!(
        "tip offset (median, the drawn box's top-left from the picture's): 1:1 {}, scaled {}",
        offset_text(Some(one)),
        offset_text(Some(scaled))
    ));
    let near = |o: [i32; 2]| o[0].abs() <= 1 && o[1].abs() <= 1;
    lines.push(if near(one) || near(scaled) {
        "WGC draws the cursor's tip on the hotspot (within a pixel): the click point and the tip \
         in the picture are one"
            .to_owned()
    } else {
        format!(
            "WGC draws the cursor's tip off the hotspot by {} (1:1) / {} (scaled): the picture's \
             tip is not where the click lands — check the pictures",
            offset_text(Some(one)),
            offset_text(Some(scaled))
        )
    });
    lines
}

fn box_text(b: Option<PixelBox>) -> String {
    b.map_or_else(
        || "-".to_owned(),
        |b| format!("x {:+}..{:+}, y {:+}..{:+}", b[0], b[2], b[1], b[3]),
    )
}

fn offset_text(o: Option<[i32; 2]>) -> String {
    o.map_or_else(|| "-".to_owned(), |o| format!("{:+},{:+}", o[0], o[1]))
}

/// A box relative to the hotspot, as drawn if Windows stretches the picture by `scale` about the
/// hotspot: each pixel `p` covers `[p·s, (p+1)·s)`.
fn scale_box(b: PixelBox, scale: f64) -> PixelBox {
    let lo = |v: i32| (f64::from(v) * scale).floor() as i32;
    let hi = |v: i32| (f64::from(v + 1) * scale).ceil() as i32 - 1;
    [lo(b[0]), lo(b[1]), hi(b[2]), hi(b[3])]
}

/// A box relative to the hotspot, moved to the hotspot's place in a crop.
fn shift(b: PixelBox, to: (i32, i32)) -> PixelBox {
    [b[0] + to.0, b[1] + to.1, b[2] + to.0, b[3] + to.1]
}

fn median(v: &mut [i32]) -> Option<i32> {
    v.sort_unstable();
    v.get(v.len() / 2).copied()
}

/// The box of the pixels a cursor picture draws, in its own pixels — the agent's reader
/// (`afklink_input`'s `cursor_shape::drawn_box`), repeated here: the probes do not depend on the
/// input crate. A colour picture with alpha draws where alpha is not 0; one without, where its AND
/// mask is 0 or its colour is not black; a monochrome one (the mask twice as tall, AND above XOR)
/// where AND is 0 or XOR is 1.
fn drawn_box(width: usize, height: usize, color: Option<&[u32]>, mask: &[u32]) -> Option<PixelBox> {
    let at = |pixels: &[u32], x: usize, y: usize| pixels.get(y * width + x).copied();
    let set = |v: u32| v & 0x00ff_ffff != 0;
    let has_alpha = color.is_some_and(|c| c.iter().take(width * height).any(|v| v >> 24 != 0));
    let mut found: Option<PixelBox> = None;
    for y in 0..height {
        for x in 0..width {
            let drawn = match color {
                Some(c) if has_alpha => at(c, x, y).is_some_and(|v| v >> 24 != 0),
                Some(c) => !at(mask, x, y).is_none_or(set) || at(c, x, y).is_some_and(set),
                None => !at(mask, x, y).is_none_or(set) || at(mask, x, y + height).is_some_and(set),
            };
            if drawn {
                let (x, y) = (x as i32, y as i32);
                found = Some(match found {
                    None => [x, y, x, y],
                    Some(b) => [b[0].min(x), b[1].min(y), b[2].max(x), b[3].max(y)],
                });
            }
        }
    }
    found
}

/// Where two BGRA crops of `w`×`h` differ by more than `min` on a colour channel: the box of those
/// pixels in the crop, and how many there are.
fn diff_box(a: &[u8], b: &[u8], w: usize, h: usize, min: u8) -> (Option<PixelBox>, usize) {
    let mut found: Option<PixelBox> = None;
    let mut count = 0;
    for y in 0..h {
        for x in 0..w {
            let i = (y * w + x) * 4;
            let (Some(pa), Some(pb)) = (a.get(i..i + 3), b.get(i..i + 3)) else {
                continue;
            };
            if pa.iter().zip(pb).any(|(p, q)| p.abs_diff(*q) > min) {
                count += 1;
                let (x, y) = (x as i32, y as i32);
                found = Some(match found {
                    None => [x, y, x, y],
                    Some(f) => [f[0].min(x), f[1].min(y), f[2].max(x), f[3].max(y)],
                });
            }
        }
    }
    (found, count)
}

/// What the pictures mark, in crop pixels.
struct Marks {
    hotspot: (i32, i32),
    /// The picture's box 1:1 at the hotspot (green), and scaled (blue).
    picture: Option<PixelBox>,
    scaled: Option<PixelBox>,
}

/// Three panels side by side — the crop with the cursor, without it, and their difference (white
/// where they differ) — magnified [`ZOOM`] times, as RGB, with the marks drawn on each: the
/// hotspot's pixel outlined red, the picture's box green, the scaled box blue. With no crop without
/// the cursor, its two panels are grey.
fn panels(
    with: &[u8],
    without: Option<&[u8]>,
    w: usize,
    h: usize,
    marks: &Marks,
) -> (u32, u32, Vec<u8>) {
    let pw = w * ZOOM;
    let ph = h * ZOOM;
    let width = 3 * pw + 2 * GAP;
    let mut rgb = vec![32u8; width * ph * 3];
    let pixel = |src: &[u8], x: usize, y: usize| -> [u8; 3] {
        let i = (y * w + x) * 4;
        src.get(i..i + 3).map_or([0, 0, 0], |p| [p[2], p[1], p[0]])
    };
    for y in 0..ph {
        for x in 0..pw {
            let (sx, sy) = (x / ZOOM, y / ZOOM);
            let a = pixel(with, sx, sy);
            let (b, d) = match without {
                Some(src) => {
                    let b = pixel(src, sx, sy);
                    let differs = a.iter().zip(&b).any(|(p, q)| p.abs_diff(*q) > DIFF_MIN);
                    (b, if differs { [255, 255, 255] } else { [0, 0, 0] })
                }
                None => ([96, 96, 96], [96, 96, 96]),
            };
            for (panel, color) in [a, b, d].into_iter().enumerate() {
                let at = ((y * width) + panel * (pw + GAP) + x) * 3;
                if let Some(dst) = rgb.get_mut(at..at + 3) {
                    dst.copy_from_slice(&color);
                }
            }
        }
    }
    let mut outline = |b: PixelBox, color: [u8; 3]| {
        // A box of crop pixels: its magnified outline, on every panel.
        let (x0, y0) = (b[0] * ZOOM as i32, b[1] * ZOOM as i32);
        let (x1, y1) = ((b[2] + 1) * ZOOM as i32 - 1, (b[3] + 1) * ZOOM as i32 - 1);
        for panel in 0..3 {
            let base = (panel * (pw + GAP)) as i32;
            let mut put = |x: i32, y: i32| {
                if (0..pw as i32).contains(&x) && (0..ph as i32).contains(&y) {
                    let at = ((y as usize * width) + (base + x) as usize) * 3;
                    if let Some(dst) = rgb.get_mut(at..at + 3) {
                        dst.copy_from_slice(&color);
                    }
                }
            };
            for x in x0..=x1 {
                put(x, y0);
                put(x, y1);
            }
            for y in y0..=y1 {
                put(x0, y);
                put(x1, y);
            }
        }
    };
    if let Some(b) = marks.scaled {
        outline(b, [64, 128, 255]);
    }
    if let Some(b) = marks.picture {
        outline(b, [0, 220, 0]);
    }
    let (hx, hy) = marks.hotspot;
    outline([hx, hy, hx, hy], [255, 0, 0]);
    (width as u32, ph as u32, rgb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_difference_is_boxed_and_counted() {
        let (w, h) = (4, 3);
        let a = vec![10u8; w * h * 4];
        let mut b = a.clone();
        // (1, 0) and (3, 2) differ in blue and red by more than the threshold; (0, 1) barely.
        b[4] = 200;
        b[(2 * w + 3) * 4 + 2] = 0xff;
        b[w * 4 + 1] = 10 + DIFF_MIN;
        assert_eq!(diff_box(&a, &b, w, h, DIFF_MIN), (Some([1, 0, 3, 2]), 2));
        assert_eq!(diff_box(&a, &a, w, h, DIFF_MIN), (None, 0));
    }

    #[test]
    fn a_picture_scaled_about_its_hotspot_covers_whole_pixels() {
        // An arrow whose tip is its hotspot, 23 x 24 px down and right of it, at 150 %.
        assert_eq!(scale_box([0, 0, 22, 23], 1.5), [0, 0, 34, 35]);
        // A picture drawn above and left of the hotspot too.
        assert_eq!(scale_box([-6, -5, 25, 26], 1.5), [-9, -8, 38, 40]);
        assert_eq!(scale_box([-1, -1, 21, 22], 1.0), [-1, -1, 21, 22]);
    }

    #[test]
    fn the_drawn_box_follows_alpha_or_the_masks() {
        let mut color = [0u32; 9];
        color[4] = 0xff00_0000;
        assert_eq!(drawn_box(3, 3, Some(&color), &[0; 9]), Some([1, 1, 1, 1]));
        let w = 0x00ff_ffff;
        let mono = [w, 0, w, w, w, w, 0, 0, 0, 0, 0, w];
        assert_eq!(drawn_box(3, 2, None, &mono), Some([1, 0, 2, 1]));
    }

    #[test]
    fn the_panels_mark_the_hotspot_in_red_on_each() {
        let (w, h) = (2, 2);
        let with = vec![0u8; w * h * 4];
        let marks = Marks {
            hotspot: (1, 1),
            picture: None,
            scaled: None,
        };
        let (width, height, rgb) = panels(&with, Some(&with), w, h, &marks);
        assert_eq!(
            (width as usize, height as usize),
            (3 * w * ZOOM + 2 * GAP, h * ZOOM)
        );
        let at = |x: usize, y: usize| {
            let i = (y * width as usize + x) * 3;
            [rgb[i], rgb[i + 1], rgb[i + 2]]
        };
        // The hotspot's cell starts at (ZOOM, ZOOM) in each panel.
        for panel in 0..3 {
            assert_eq!(at(panel * (w * ZOOM + GAP) + ZOOM, ZOOM), [255, 0, 0]);
        }
        assert_eq!(at(0, 0), [0, 0, 0], "an unmarked pixel of the crop");
        assert_eq!(median(&mut [5, 1, 3]), Some(3));
        assert_eq!(median(&mut []), None);
    }
}
