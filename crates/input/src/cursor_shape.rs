//! What the cursor looks like and what it is over, for the cursor report's line per new shape
//! (`afklink_core::cursor_report::ShapeLog`, [`afklink_core::traits::CursorShape`]).
//!
//! The question it answers: does the game's cursor draw its tip where the click lands? `GetCursorInfo`'s position is the hotspot, the
//! pixel a click goes to; the picture is drawn with the hotspot on that position. So the line gives
//! the picture's size, its hotspot, and the box of the pixels it really draws, relative to the
//! hotspot — an arrow whose tip is its hotspot draws from `x +0, y +0` — and the window under the
//! cursor with its DPI awareness and its DPI against the monitor's: Windows draws an unaware window
//! stretched, and whether its cursor is stretched with it is the one link not checked yet.
//!
//! Reads only, once per new shape a session: `GetIconInfo` (copies of the cursor's bitmaps, deleted
//! here), `GetDIBits` of those copies, `WindowFromPoint`, the window's class, DPI awareness and DPI,
//! the monitor's DPI, and its process's exe name through a `PROCESS_QUERY_LIMITED_INFORMATION`
//! handle closed at once. Nothing is sent to the window. A part that cannot be read says why.
//!
//! [`drawn_box`] is pure, and tested on every platform.

/// The box of the pixels a cursor picture draws — left, top, right, bottom, inclusive, in the
/// picture's pixels — or `None` when it draws none.
///
/// `color` and `mask` are rows of 32-bit pixels as `GetDIBits` gives them (`0xAARRGGBB`), top row
/// first. A colour cursor (`color` given, `width`×`height`) with any alpha draws where alpha is not
/// 0; one without alpha draws where its AND mask is 0, and where the mask is 1 but the colour is not
/// black (Windows inverts the screen there). A monochrome cursor (no `color`) has a mask twice as
/// tall — the AND mask above the XOR mask — and draws where AND is 0 (black or white) or XOR is 1
/// (inverted). A mask pixel reads white (`0xFFFFFF`) for a 1 bit and black for a 0.
pub(crate) fn drawn_box(
    width: usize,
    height: usize,
    color: Option<&[u32]>,
    mask: &[u32],
) -> Option<(i32, i32, i32, i32)> {
    let at = |pixels: &[u32], x: usize, y: usize| pixels.get(y * width + x).copied();
    let set = |v: u32| v & 0x00ff_ffff != 0;
    let has_alpha = color.is_some_and(|c| c.iter().take(width * height).any(|v| v >> 24 != 0));
    let mut found: Option<(usize, usize, usize, usize)> = None;
    for y in 0..height {
        for x in 0..width {
            let drawn = match color {
                Some(c) if has_alpha => at(c, x, y).is_some_and(|v| v >> 24 != 0),
                Some(c) => {
                    let and = at(mask, x, y).is_none_or(set);
                    !and || at(c, x, y).is_some_and(set)
                }
                None => {
                    let and = at(mask, x, y).is_none_or(set);
                    let xor = at(mask, x, y + height).is_some_and(set);
                    !and || xor
                }
            };
            if drawn {
                found = Some(match found {
                    None => (x, y, x, y),
                    Some((l, t, r, b)) => (l.min(x), t.min(y), r.max(x), b.max(y)),
                });
            }
        }
    }
    let whole = |v: usize| i32::try_from(v).unwrap_or(i32::MAX);
    found.map(|(l, t, r, b)| (whole(l), whole(t), whole(r), whole(b)))
}

#[cfg(windows)]
pub(crate) use system::{class_of, describe, exe_of};

#[cfg(windows)]
mod system {
    use std::ffi::c_void;
    use std::mem::size_of;

    use afklink_core::traits::{CursorImage, CursorSample, CursorShape, CursorWindow};
    use windows::Win32::Foundation::{HWND, POINT};
    use windows::Win32::Graphics::Gdi::{
        DeleteObject, GetDC, GetDIBits, GetObjectW, MonitorFromPoint, ReleaseDC, BITMAP,
        BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC, HGDIOBJ,
        MONITOR_DEFAULTTONEAREST,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::UI::HiDpi::{
        AreDpiAwarenessContextsEqual, GetAwarenessFromDpiAwarenessContext, GetDpiForMonitor,
        GetDpiForWindow, GetWindowDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED, MDT_EFFECTIVE_DPI,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetClassNameW, GetIconInfo, GetWindowThreadProcessId, WindowFromPoint, HICON, ICONINFO,
    };

    use crate::cursor_sync::system::{exe_name, Owned};

    /// A picture larger than this on a side is not read pixel by pixel (Windows' largest cursor
    /// size is 256).
    const MAX_SIDE: i32 = 1024;

    /// The shape of `sample` and the window under it.
    pub(crate) fn describe(sample: &CursorSample) -> CursorShape {
        CursorShape {
            image: image(sample.shape),
            under: under((sample.x, sample.y)),
        }
    }

    /// A bitmap `GetIconInfo` made for us: ours to delete.
    struct Bitmap(HBITMAP);

    impl Drop for Bitmap {
        fn drop(&mut self) {
            if self.0 .0.is_null() {
                return;
            }
            // SAFETY: a bitmap GetIconInfo created for this caller, selected into no DC.
            if !unsafe { DeleteObject(HGDIOBJ::from(self.0)) }.as_bool() {
                tracing::debug!("cursor shape: deleting a copy of the cursor's bitmap failed");
            }
        }
    }

    /// The screen's DC, released when dropped.
    struct ScreenDc(HDC);

    impl Drop for ScreenDc {
        fn drop(&mut self) {
            // SAFETY: the DC GetDC(None) returned, released once.
            if unsafe { ReleaseDC(None, self.0) } == 0 {
                tracing::debug!("cursor shape: releasing the screen DC failed");
            }
        }
    }

    fn size_of_bitmap(bitmap: &Bitmap) -> Result<(i32, i32), String> {
        let mut info = BITMAP::default();
        // SAFETY: a live bitmap handle, and a live BITMAP of the size given.
        let wrote = unsafe {
            GetObjectW(
                HGDIOBJ::from(bitmap.0),
                size_of::<BITMAP>() as i32,
                Some((&mut info as *mut BITMAP).cast::<c_void>()),
            )
        };
        if wrote == 0 {
            return Err("GetObjectW on the cursor's bitmap answered nothing".to_owned());
        }
        Ok((info.bmWidth, info.bmHeight))
    }

    /// A bitmap's pixels as 32-bit `0xAARRGGBB`, top row first.
    fn pixels(dc: &ScreenDc, bitmap: &Bitmap, width: i32, height: i32) -> Result<Vec<u32>, String> {
        if !(1..=MAX_SIDE).contains(&width) || !(1..=2 * MAX_SIDE).contains(&height) {
            return Err(format!("a {width}x{height} bitmap is not read"));
        }
        let mut info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                // Negative: top-down rows.
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let count = usize::try_from(width).unwrap_or(0) * usize::try_from(height).unwrap_or(0);
        let mut out = vec![0u32; count];
        // SAFETY: `out` holds `height` rows of `width` 32-bit pixels, which a 32-bit BI_RGB
        // request writes (and no colour table); `info` is a live BITMAPINFO.
        let lines = unsafe {
            GetDIBits(
                dc.0,
                bitmap.0,
                0,
                height.unsigned_abs(),
                Some(out.as_mut_ptr().cast::<c_void>()),
                &mut info,
                DIB_RGB_COLORS,
            )
        };
        if lines <= 0 {
            return Err(format!("GetDIBits read {lines} lines"));
        }
        Ok(out)
    }

    fn image(shape: usize) -> Result<CursorImage, String> {
        if shape == 0 {
            return Err("no shape".to_owned());
        }
        let mut info = ICONINFO::default();
        // SAFETY: any handle may be asked about (a stale one fails); `info` is a live ICONINFO.
        unsafe { GetIconInfo(HICON(shape as *mut c_void), &mut info) }
            .map_err(|e| format!("GetIconInfo: {e}"))?;
        let mask = Bitmap(info.hbmMask);
        let color = (!info.hbmColor.0.is_null()).then_some(Bitmap(info.hbmColor));
        let mask_size = size_of_bitmap(&mask)?;
        let (width, height) = match &color {
            Some(c) => size_of_bitmap(c)?,
            // A monochrome cursor's mask is the AND mask above the XOR mask.
            None => (mask_size.0, mask_size.1 / 2),
        };
        let (hx, hy) = (
            i32::try_from(info.xHotspot).unwrap_or(i32::MAX),
            i32::try_from(info.yHotspot).unwrap_or(i32::MAX),
        );
        let drawn = drawn_relative(&mask, mask_size, color.as_ref(), (width, height))
            .map(|found| found.map(|(l, t, r, b)| (l - hx, t - hy, r - hx, b - hy)))
            .unwrap_or_else(|error| {
                tracing::debug!(
                    %error,
                    shape = %format!("{shape:#x}"),
                    "cursor shape: its pixels could not be read; its drawn box is unknown"
                );
                None
            });
        Ok(CursorImage {
            width,
            height,
            hotspot_x: hx,
            hotspot_y: hy,
            color: color.is_some(),
            drawn,
        })
    }

    /// The drawn box in the picture's pixels ([`super::drawn_box`]).
    fn drawn_relative(
        mask: &Bitmap,
        mask_size: (i32, i32),
        color: Option<&Bitmap>,
        (width, height): (i32, i32),
    ) -> Result<Option<(i32, i32, i32, i32)>, String> {
        // SAFETY: plain call; a DC it answers is released by its guard.
        let dc = unsafe { GetDC(None) };
        if dc.0.is_null() {
            return Err("GetDC(None) answered no DC".to_owned());
        }
        let dc = ScreenDc(dc);
        if mask_size.0 != width {
            return Err(format!(
                "the mask is {}x{}, the picture {width}x{height}",
                mask_size.0, mask_size.1
            ));
        }
        let mask_pixels = pixels(&dc, mask, mask_size.0, mask_size.1)?;
        let color_pixels = match color {
            Some(c) => Some(pixels(&dc, c, width, height)?),
            None => None,
        };
        let side = |v: i32| usize::try_from(v).unwrap_or(0);
        Ok(super::drawn_box(
            side(width),
            side(height),
            color_pixels.as_deref(),
            &mask_pixels,
        ))
    }

    /// The window under the cursor: its process's exe, its class, how it handles the display's
    /// scale, and the DPIs it and its monitor draw at.
    fn under(at: (i32, i32)) -> Result<CursorWindow, String> {
        let point = POINT { x: at.0, y: at.1 };
        // SAFETY: plain call.
        let hwnd = unsafe { WindowFromPoint(point) };
        if hwnd.0.is_null() {
            return Err(format!("no window at {},{}", at.0, at.1));
        }
        Ok(CursorWindow {
            hwnd: hwnd.0 as usize,
            exe: exe_of(hwnd),
            class: class_of(hwnd),
            awareness: awareness_of(hwnd),
            // SAFETY: plain call; a gone window answers 0.
            dpi: unsafe { GetDpiForWindow(hwnd) },
            monitor_dpi: monitor_dpi(point),
        })
    }

    /// The exe of the process that owns `hwnd` (opened for limited information), or why it is
    /// unknown. Also the button watch's (`crate::fakerinput::platform::button_probe`).
    pub(crate) fn exe_of(hwnd: HWND) -> String {
        let mut pid = 0u32;
        // SAFETY: plain call with a live output; a stale window answers 0.
        if unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) } == 0 || pid == 0 {
            return "unknown (the window is gone)".to_owned();
        }
        // SAFETY: plain call; the handle is owned and closed below.
        match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(process) => {
                let process = Owned(process);
                exe_name(process.0).unwrap_or_else(|error| format!("unknown, pid {pid} ({error})"))
            }
            Err(error) => format!("unknown, pid {pid} (OpenProcess: {error})"),
        }
    }

    /// The window's class name, or `unknown`. Also the button watch's.
    pub(crate) fn class_of(hwnd: HWND) -> String {
        let mut class = [0u16; 256];
        // SAFETY: a live buffer; the call writes at most its length.
        let n = unsafe { GetClassNameW(hwnd, &mut class) };
        if n <= 0 {
            return "unknown".to_owned();
        }
        String::from_utf16_lossy(class.get(..n as usize).unwrap_or(&[]))
    }

    fn awareness_of(hwnd: HWND) -> &'static str {
        // SAFETY: plain calls on a window handle; a gone window reads invalid.
        unsafe {
            let context = GetWindowDpiAwarenessContext(hwnd);
            if AreDpiAwarenessContextsEqual(context, DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED)
                .as_bool()
            {
                return "unaware (GDI scaled)";
            }
            if AreDpiAwarenessContextsEqual(context, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
                .as_bool()
            {
                return "per-monitor aware v2";
            }
            match GetAwarenessFromDpiAwarenessContext(context).0 {
                0 => "unaware",
                1 => "system aware",
                2 => "per-monitor aware",
                _ => "invalid",
            }
        }
    }

    /// The monitor's effective DPI as this thread sees it (per-monitor aware: its own); 0 unknown.
    fn monitor_dpi(point: POINT) -> u32 {
        // SAFETY: plain call.
        let monitor = unsafe { MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST) };
        let (mut x, mut y) = (0u32, 0u32);
        // SAFETY: two live u32 outputs.
        match unsafe { GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) } {
            Ok(()) => x,
            Err(error) => {
                tracing::debug!(%error, "cursor shape: the monitor's DPI is unreadable");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::drawn_box;

    const WHITE: u32 = 0x00ff_ffff;

    /// A monochrome 4×3 cursor: the AND mask above the XOR mask. Drawn: black where AND is 0 (row 0,
    /// x 1), inverted where XOR is 1 (row 2, x 3); transparent elsewhere.
    #[test]
    fn a_monochrome_cursor_draws_where_and_is_0_or_xor_is_1() {
        let w = WHITE;
        #[rustfmt::skip]
        let mask = [
            // AND
            w, 0, w, w,
            w, w, w, w,
            w, w, w, w,
            // XOR
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, w,
        ];
        assert_eq!(drawn_box(4, 3, None, &mask), Some((1, 0, 3, 2)));
        // All transparent: nothing drawn.
        let empty = [[w; 12], [0; 12]].concat();
        assert_eq!(drawn_box(4, 3, None, &empty), None);
    }

    /// A colour cursor with alpha draws where alpha is not 0, whatever its mask says.
    #[test]
    fn a_colour_cursor_with_alpha_draws_where_alpha_is_set() {
        let mut color = [0u32; 16];
        color[5] = 0xff10_2030; // (1, 1)
        color[10] = 0x0100_0000; // (2, 2), barely visible
        let mask = [0u32; 16];
        assert_eq!(drawn_box(4, 4, Some(&color), &mask), Some((1, 1, 2, 2)));
    }

    /// A colour cursor without alpha draws where its AND mask is 0, and where the mask is 1 but the
    /// colour is not black (inverted).
    #[test]
    fn a_colour_cursor_without_alpha_draws_by_its_mask() {
        let mut mask = [WHITE; 9];
        mask[4] = 0; // (1, 1): drawn in colour
        let mut color = [0u32; 9];
        color[2] = 0x0000_00ff; // (2, 0): mask 1, colour not black: inverted
        assert_eq!(drawn_box(3, 3, Some(&color), &mask), Some((1, 0, 2, 1)));
    }

    /// Short buffers never panic: a missing mask pixel reads transparent.
    #[test]
    fn short_buffers_read_as_transparent() {
        assert_eq!(drawn_box(4, 4, None, &[]), None);
        assert_eq!(drawn_box(4, 4, Some(&[]), &[]), None);
    }
}
