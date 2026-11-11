//! The main window's size and its first place on screen.
//!
//! **Its place**: on first show, the height fits the screen (never under 480) and the window is
//! centred. The window opens at 400×600 logical px
//! (`tauri.conf.json`) wherever Windows puts a new window. On a 1920×1080 screen at 175 % (a work
//! area of ~569 px) or 1366×768 at 125 % (~566) that is taller than the screen, and at 150 % (~672)
//! it fits only near the top: the bottom — the footer with «Приостановить доступ» — opens under the
//! taskbar. So once, at startup, before the owner sees it: a window that is wholly inside its
//! monitor's work area is left exactly where Windows put it (every ordinary setup); one that is not
//! is moved to the work area's centre, and made shorter first if it cannot fit at all — down to its
//! least height, under which it goes to the top, title bar reachable. Nothing is remembered between
//! launches, so every launch is a first show.
//!
//! **Its size at Windows' text size**: fitted to the content, with the default text size left
//! exactly as it is. WebView2 draws every CSS pixel larger by Windows'
//! «Размер текста» (Accessibility → Text size) on top of the display scale, so at 125 % the 400×600
//! window's page is 320×480 CSS px and the 340×480 minimum's 272×384 — where the main view scrolls
//! 93–122 px and words are cut. So the window's least and default sizes are the
//! 100 % ones times the text size ([`sizes`]): its page then has the CSS px it has at 100 %. Each is
//! capped by the room the monitor's work area leaves — the window fits the screen first — and
//! never under the 100 % one. At 100 % nothing changes: not one call.
//!
//! The text size is Windows' setting (`pair_prompt::text_scale_setting`), read at startup before the
//! place is decided. The page reports its pixel ratio ([`main_window_ratio`]) at load and whenever
//! it changes; a text size changed since is applied then: the least size follows — the window grows
//! to it when smaller, and is brought back inside the work area if that took it out — and the size
//! itself stays the owner's. Windows' setting decides rather than the page's ratio over the display
//! scale, which passes through wrong values while the window moves between monitors of different
//! scales (the two do not change at the same instant); the page's is used only when the setting
//! cannot be read, and a difference between the two at load is a warning in the log.

use std::sync::Mutex;

use tauri::{AppHandle, LogicalSize, Manager, PhysicalPosition, State, WebviewWindow};

use crate::pair_prompt::{text_scale_setting, Rect, TextScale};

/// The main window's label (`tauri.conf.json`).
pub(crate) const MAIN_WINDOW: &str = "main";

/// The window's least inner size at 100 % text, logical px (`minWidth`, `minHeight` in
/// `tauri.conf.json`).
pub(crate) const MIN_INNER_WIDTH: f64 = 340.0;
pub(crate) const MIN_INNER_HEIGHT: f64 = 480.0;

/// The window's inner size at 100 % text, logical px (`width`, `height` in `tauri.conf.json`).
pub(crate) const DEFAULT_INNER_WIDTH: f64 = 400.0;
pub(crate) const DEFAULT_INNER_HEIGHT: f64 = 600.0;

/// Text scales closer than this are the same: the page's ratio is rounded to hundredths.
const SAME_TEXT_SCALE: f64 = 0.005;

/// The page's text scale and Windows' differ by more than this: worth a line.
const MISMATCH: f64 = 0.02;

/// The main window as Windows placed it, physical px: its outer rectangle (with the frame and its
/// invisible resize borders) and its inner size (the page).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Placed {
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) outer_width: u32,
    pub(crate) outer_height: u32,
    pub(crate) inner_width: u32,
    pub(crate) inner_height: u32,
}

/// What to do with the window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Fit {
    /// Wholly inside the work area: left where it is.
    Fits,
    /// Moved to `(x, y)` (physical, its outer top-left), and its inner height set to
    /// `inner_height` logical px first when it is `Some`.
    Place {
        x: i32,
        y: i32,
        inner_height: Option<f64>,
    },
}

/// The inner size a work area leaves the window, logical px: its width, and its height under the
/// title bar and the frame as much of it as shows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Room {
    pub(crate) width: f64,
    pub(crate) height: f64,
}

/// The side frame (`(outer − inner) / 2`, physical) is mostly Windows' invisible resize border,
/// which also runs under the bottom edge; what is left of the vertical frame is the title bar and
/// the top edge, which show.
fn frame(w: Placed) -> (i64, i64) {
    let border = i64::from(w.outer_width.saturating_sub(w.inner_width) / 2);
    let chrome = i64::from(w.outer_height.saturating_sub(w.inner_height)) - border;
    (border, chrome)
}

/// The room `work` leaves a window framed as `w`, at `scale`.
pub(crate) fn room(work: Rect, w: Placed, scale: f64) -> Room {
    let (_, chrome) = frame(w);
    Room {
        width: f64::from(work.width) / scale,
        height: (i64::from(work.height) - chrome).max(0) as f64 / scale,
    }
}

/// The window's least and default inner sizes, logical px.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Sizes {
    pub(crate) min_width: f64,
    pub(crate) min_height: f64,
    pub(crate) width: f64,
    pub(crate) height: f64,
}

/// The window's sizes at Windows' text size `text` (1.0 = 100 %) within `room`: each the 100 % one
/// times `text`, so the page has the CSS px it has at 100 %; no larger than the room, so the window
/// fits the screen; never under the 100 % one. At 1.0, exactly `tauri.conf.json`'s.
pub(crate) fn sizes(text: f64, room: Room) -> Sizes {
    let at = |base: f64, room: f64| (base * text).min(room).floor().max(base);
    Sizes {
        min_width: at(MIN_INNER_WIDTH, room.width),
        min_height: at(MIN_INNER_HEIGHT, room.height),
        width: at(DEFAULT_INNER_WIDTH, room.width),
        height: at(DEFAULT_INNER_HEIGHT, room.height),
    }
}

/// The decision for a window placed as `w` on a monitor whose work area is `work`, at `scale`, whose
/// least inner height is `min_inner_height` logical px.
///
/// A window whose visible bottom touches the work area's is inside it (see [`frame`]).
pub(crate) fn fit(work: Rect, w: Placed, scale: f64, min_inner_height: f64) -> Fit {
    let (border, chrome) = frame(w);
    let left = i64::from(w.x) + border;
    let right = i64::from(w.x) + i64::from(w.outer_width) - border;
    let top = i64::from(w.y);
    let bottom = i64::from(w.y) + i64::from(w.outer_height) - border;
    let inside = top >= i64::from(work.y)
        && bottom <= work.bottom()
        && left >= i64::from(work.x)
        && right <= work.right();
    if inside {
        return Fit::Fits;
    }
    let room = i64::from(work.height) - chrome;
    let min_inner = (min_inner_height * scale).ceil() as i64;
    let (inner, inner_height) = if i64::from(w.inner_height) <= room {
        (i64::from(w.inner_height), None)
    } else {
        let inner = room.max(min_inner);
        (
            inner,
            Some((inner as f64 / scale).floor().max(min_inner_height)),
        )
    };
    let visible_height = inner + chrome;
    let x = (i64::from(work.x) + (i64::from(work.width) - i64::from(w.outer_width)) / 2)
        .max(i64::from(work.x) - border);
    let y =
        (i64::from(work.y) + (i64::from(work.height) - visible_height) / 2).max(i64::from(work.y));
    let clamp = |v: i64| v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32;
    Fit::Place {
        x: clamp(x),
        y: clamp(y),
        inner_height,
    }
}

/// The text scale the main window's sizes were last set for, kept as Tauri state.
#[derive(Debug)]
pub(crate) struct MainWindowText {
    state: Mutex<TextState>,
}

#[derive(Debug)]
struct TextState {
    /// 1.0 until the window is sized for a larger text size.
    applied: f64,
    /// The page's first report of this launch has come (compared with Windows' setting for the
    /// log).
    first_report_seen: bool,
}

impl Default for MainWindowText {
    fn default() -> Self {
        Self {
            state: Mutex::new(TextState {
                applied: 1.0,
                first_report_seen: false,
            }),
        }
    }
}

/// Windows' text size as a factor; 100 % when it cannot be read (said in the log).
fn windows_text_scale() -> f64 {
    match text_scale_setting() {
        Ok(percent) => TextScale::from_setting(percent),
        Err(e) => {
            tracing::debug!("main window: Windows' text size not read ({e}); sized at 100 %");
            1.0
        }
    }
}

/// The monitor the window is on (else the primary one); `None`, said in the log, when neither is
/// known.
fn monitor_of(app: &AppHandle, w: &WebviewWindow) -> Option<tauri::Monitor> {
    match w.current_monitor() {
        Ok(Some(m)) => Some(m),
        Ok(None) => match app.primary_monitor() {
            Ok(Some(m)) => Some(m),
            Ok(None) => {
                tracing::debug!("main window: no monitor known");
                None
            }
            Err(e) => {
                tracing::debug!("main window: primary monitor: {e}");
                None
            }
        },
        Err(e) => {
            tracing::debug!("main window: its monitor: {e}");
            None
        }
    }
}

/// Where the window is now; `None`, said in the log, when that cannot be read.
fn placed_of(w: &WebviewWindow) -> Option<Placed> {
    match (w.outer_position(), w.outer_size(), w.inner_size()) {
        (Ok(p), Ok(o), Ok(i)) => Some(Placed {
            x: p.x,
            y: p.y,
            outer_width: o.width,
            outer_height: o.height,
            inner_width: i.width,
            inner_height: i.height,
        }),
        (p, o, i) => {
            tracing::debug!(
                position = ?p.err().map(|e| e.to_string()),
                outer = ?o.err().map(|e| e.to_string()),
                inner = ?i.err().map(|e| e.to_string()),
                "main window: its place unknown"
            );
            None
        }
    }
}

/// The monitor's work area, physical px.
fn work_area(monitor: &tauri::Monitor) -> Rect {
    let area = monitor.work_area();
    Rect {
        x: area.position.x,
        y: area.position.y,
        width: area.size.width,
        height: area.size.height,
    }
}

/// Set the window's least size to `s`'s — and, with `resize`, its size too. Each failure is said;
/// the window keeps what it had.
fn apply_sizes(w: &WebviewWindow, s: Sizes, resize: bool) {
    if let Err(e) = w.set_min_size(Some(LogicalSize::new(s.min_width, s.min_height))) {
        tracing::warn!(
            min_width = s.min_width,
            min_height = s.min_height,
            "main window: least size not set for the text size: {e}"
        );
    }
    if resize {
        if let Err(e) = w.set_size(LogicalSize::new(s.width, s.height)) {
            tracing::warn!(
                width = s.width,
                height = s.height,
                "main window: size not set for the text size: {e}"
            );
        }
    }
}

/// Inside the work area (see [`fit`]): left where it is when it already is, else moved (and made
/// shorter first when it must). `why` is for the log.
fn place(
    w: &WebviewWindow,
    monitor: &tauri::Monitor,
    placed: Placed,
    min_inner_height: f64,
    why: &str,
) {
    let scale = monitor.scale_factor();
    let work = work_area(monitor);
    let monitor_name = monitor.name().cloned().unwrap_or_else(|| "-".to_string());
    match fit(work, placed, scale, min_inner_height) {
        Fit::Fits => tracing::debug!(
            monitor = %monitor_name,
            scale,
            work = ?work,
            window = ?placed,
            min_inner_height,
            "main window inside the work area ({why}): left where it is"
        ),
        Fit::Place { x, y, inner_height } => {
            if let Some(height) = inner_height {
                let width = f64::from(placed.inner_width) / scale;
                if let Err(e) = w.set_size(LogicalSize::new(width, height)) {
                    tracing::warn!(
                        height,
                        "main window not made shorter to fit the screen: {e}"
                    );
                }
            }
            match w.set_position(PhysicalPosition::new(x, y)) {
                Ok(()) => tracing::info!(
                    monitor = %monitor_name,
                    scale,
                    work = ?work,
                    window = ?placed,
                    x,
                    y,
                    inner_height = inner_height.unwrap_or(f64::from(placed.inner_height) / scale),
                    min_inner_height,
                    shortened = inner_height.is_some(),
                    "main window did not fit the work area ({why}): centred{}",
                    if inner_height.is_some() { ", made shorter" } else { "" }
                ),
                Err(e) => tracing::warn!(x, y, "main window not moved to fit the screen: {e}"),
            }
        }
    }
}

/// Once, at startup: the main window sized for Windows' text size and inside its monitor's work
/// area (see the module). Every step that cannot be read leaves the window as Windows made it, said
/// in the log.
pub(crate) fn fit_main_window(app: &AppHandle) {
    let Some(w) = app.get_webview_window(MAIN_WINDOW) else {
        tracing::warn!("main window not fitted to the screen: no main window");
        return;
    };
    let Some(monitor) = monitor_of(app, &w) else {
        tracing::debug!("main window not fitted to the screen: no monitor");
        return;
    };
    let Some(placed) = placed_of(&w) else {
        tracing::debug!("main window not fitted to the screen: its place unknown");
        return;
    };
    let scale = monitor.scale_factor();
    let text = windows_text_scale();
    let (placed, min_inner_height) = if text > 1.0 + SAME_TEXT_SCALE {
        let room = room(work_area(&monitor), placed, scale);
        let s = sizes(text, room);
        apply_sizes(&w, s, true);
        let now = placed_of(&w);
        tracing::info!(
            text_scale = text,
            scale,
            room_width = room.width,
            room_height = room.height,
            min_width = s.min_width,
            min_height = s.min_height,
            width = s.width,
            height = s.height,
            capped = s.min_height + 1.0 <= MIN_INNER_HEIGHT * text
                || s.height + 1.0 <= DEFAULT_INNER_HEIGHT * text,
            window = ?now,
            "main window sized for Windows' text size: its page has the CSS px of 100 % (as far as \
             the work area allows)"
        );
        (now.unwrap_or(placed), s.min_height)
    } else {
        tracing::debug!(
            text_scale = text,
            "main window: Windows' text size is 100 %: tauri.conf.json's sizes as they are"
        );
        (placed, MIN_INNER_HEIGHT)
    };
    if let Some(state) = app.try_state::<MainWindowText>() {
        afklink_core::lock(&state.state).applied = text.max(1.0);
    }
    place(&w, &monitor, placed, min_inner_height, "first show");
}

/// The main window's page: it is drawn at `ratio` (`devicePixelRatio`), at load and after each
/// change. The ratio over the window's display scale is the text size WebView2 draws at; Windows'
/// setting is read beside it, and decides (see the module). A text size other than the one the
/// window's sizes were set for sets its least size anew — the window grows to it when smaller, and
/// is brought back inside the work area if that took it out of it.
#[tauri::command]
pub(crate) fn main_window_ratio(
    window: WebviewWindow,
    text: State<'_, MainWindowText>,
    ratio: f64,
) {
    if window.label() != MAIN_WINDOW {
        tracing::debug!(
            window = window.label(),
            ratio,
            "pixel ratio report from another window; ignored"
        );
        return;
    }
    let display_scale = match window.scale_factor() {
        Ok(scale) => scale,
        Err(e) => {
            tracing::debug!(
                ratio,
                "main window: display scale unknown ({e}); ratio ignored"
            );
            return;
        }
    };
    let page = TextScale::from_page(ratio, display_scale);
    let setting = text_scale_setting();
    let windows = setting.as_ref().ok().map(|p| TextScale::from_setting(*p));
    let target = match (windows, page) {
        (Some(w), _) => w,
        (None, Some(p)) => p,
        (None, None) => {
            tracing::debug!(
                ratio,
                display_scale,
                "main window: neither Windows' text size nor the page's is known; nothing changes"
            );
            return;
        }
    };
    let differs = matches!((page, windows), (Some(p), Some(w)) if (p - w).abs() > MISMATCH);
    let was = {
        let mut st = afklink_core::lock(&text.state);
        tracing::debug!(
            ratio,
            display_scale,
            page_text_scale = page.unwrap_or(0.0),
            windows_text_size = %setting
                .as_ref()
                .map_or_else(|e| format!("unread: {e}"), |p| format!("{}%", p.unwrap_or(100))),
            differs,
            applied = st.applied,
            "main window: the page reports its pixel ratio"
        );
        // The first report of a launch, at load: nothing is moving between monitors then, so a
        // difference is real — WebView2 drawing at another text size than Windows says.
        let first = !st.first_report_seen;
        st.first_report_seen = true;
        if first && differs {
            tracing::warn!(
                page = page.unwrap_or(0.0),
                windows = windows.unwrap_or(0.0),
                ratio,
                display_scale,
                "main window: the page's text scale is not Windows' text size; sized by Windows'"
            );
        }
        if (target - st.applied).abs() < SAME_TEXT_SCALE {
            return;
        }
        std::mem::replace(&mut st.applied, target)
    };
    // No lock across the window calls below.
    let app = window.app_handle();
    let (Some(monitor), Some(placed)) = (monitor_of(app, &window), placed_of(&window)) else {
        tracing::debug!(
            was,
            target,
            "main window: Windows' text size changed, but the window's place is unknown; its \
             sizes stay"
        );
        return;
    };
    let s = sizes(
        target,
        room(work_area(&monitor), placed, monitor.scale_factor()),
    );
    apply_sizes(&window, s, false);
    tracing::info!(
        was,
        text_scale = target,
        min_width = s.min_width,
        min_height = s.min_height,
        "main window: Windows' text size changed; least size set for it (the size stays the \
         owner's)"
    );
    if target > was {
        // The least size may have grown the window past the work area.
        if let Some(now) = placed_of(&window) {
            place(
                &window,
                &monitor,
                now,
                s.min_height,
                "after the text size went up",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    /// `width`×`height` logical with a 31 px title bar and a 7 px invisible border each side, at
    /// `scale`, at `(x, y)` physical.
    fn window(x: i32, y: i32, width: f64, height: f64, scale: f64) -> Placed {
        let px = |v: f64| (v * scale).round() as u32;
        Placed {
            x,
            y,
            outer_width: px(width) + 2 * px(7.0),
            outer_height: px(height) + px(31.0) + px(7.0),
            inner_width: px(width),
            inner_height: px(height),
        }
    }

    /// The 400×600 of `tauri.conf.json`.
    fn default_window(x: i32, y: i32, scale: f64) -> Placed {
        window(x, y, DEFAULT_INNER_WIDTH, DEFAULT_INNER_HEIGHT, scale)
    }

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// Every ordinary setup is left alone: 1080p at 100 and 125 %, 1440p at 150 %, a 768p laptop at
    /// 100 %.
    #[test]
    fn a_window_that_fits_is_left_where_windows_put_it() {
        // 1920×1080, a 48 px taskbar.
        assert_eq!(
            fit(
                rect(0, 0, 1920, 1032),
                default_window(26, 26, 1.0),
                1.0,
                MIN_INNER_HEIGHT
            ),
            Fit::Fits
        );
        assert_eq!(
            fit(
                rect(0, 0, 1920, 1020),
                default_window(33, 33, 1.25),
                1.25,
                MIN_INNER_HEIGHT
            ),
            Fit::Fits
        );
        assert_eq!(
            fit(
                rect(0, 0, 2560, 1368),
                default_window(39, 39, 1.5),
                1.5,
                MIN_INNER_HEIGHT
            ),
            Fit::Fits
        );
        assert_eq!(
            fit(
                rect(0, 0, 1366, 728),
                default_window(26, 26, 1.0),
                1.0,
                MIN_INNER_HEIGHT
            ),
            Fit::Fits
        );
        // Touching the work area's bottom with the visible edge is inside it.
        let w = default_window(26, 0, 1.0);
        let bottom = w.outer_height - 7;
        assert_eq!(
            fit(rect(0, 0, 1920, bottom), w, 1.0, MIN_INNER_HEIGHT),
            Fit::Fits
        );
    }

    /// 1920×1080 at 150 %: the window fits the work area's height, but Windows put it too low —
    /// moved to the centre, its size kept.
    #[test]
    fn a_window_put_too_low_is_centred_at_its_size() {
        let work = rect(0, 0, 1920, 1008); // 1080 − a 72 px taskbar
        let w = default_window(300, 200, 1.5);
        match fit(work, w, 1.5, MIN_INNER_HEIGHT) {
            Fit::Place { x, y, inner_height } => {
                assert_eq!(inner_height, None, "its size kept");
                assert_eq!(x, (1920 - w.outer_width as i32) / 2);
                let visible = w.outer_height as i32 - 11; // the bottom border: 7 × 1.5, rounded
                assert!(y >= 0 && y + visible <= 1008, "{y} + {visible}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// 1920×1080 at 175 % (~569 logical px of work area) and 1366×768 at 125 % (~566): shorter, as
    /// tall as the work area leaves, never under 480, and centred.
    #[test]
    fn a_window_taller_than_the_screen_is_made_shorter_and_centred() {
        for (work, scale) in [(rect(0, 0, 1920, 996), 1.75), (rect(0, 0, 1366, 708), 1.25)] {
            let w = default_window(30, 30, scale);
            match fit(work, w, scale, MIN_INNER_HEIGHT) {
                Fit::Place {
                    y,
                    inner_height: Some(h),
                    ..
                } => {
                    assert!((MIN_INNER_HEIGHT..600.0).contains(&h), "{h} at {scale}");
                    let chrome = f64::from(w.outer_height - w.inner_height) - (7.0 * scale).round();
                    let visible = h * scale + chrome;
                    assert!(
                        visible <= f64::from(work.height) + 1.0,
                        "{visible} at {scale}"
                    );
                    assert!(y >= work.y, "{y} at {scale}");
                }
                other => panic!("{other:?} at {scale}"),
            }
        }
    }

    /// A work area too small even for 480 px: the minimum, at the top, the title bar reachable.
    #[test]
    fn a_tiny_screen_gets_the_minimum_at_the_top() {
        let work = rect(0, 0, 1280, 500);
        match fit(work, default_window(20, 20, 1.0), 1.0, MIN_INNER_HEIGHT) {
            Fit::Place {
                y,
                inner_height: Some(h),
                ..
            } => {
                assert!(close(h, MIN_INNER_HEIGHT), "{h}");
                assert_eq!(y, 0);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A second monitor left of the primary one (negative coordinates), the window off its edge.
    #[test]
    fn a_window_off_a_monitor_edge_is_brought_in() {
        let work = rect(-1920, 0, 1920, 1040);
        let w = default_window(-200, 26, 1.0);
        match fit(work, w, 1.0, MIN_INNER_HEIGHT) {
            Fit::Place {
                x, inner_height, ..
            } => {
                assert_eq!(inner_height, None);
                assert_eq!(x, -1920 + (1920 - w.outer_width as i32) / 2);
            }
            other => panic!("{other:?}"),
        }
    }

    // ---- Windows' text size ----

    /// At 100 % text the sizes are `tauri.conf.json`'s, whatever the room — nothing changes for the
    /// ordinary setup, not even on a screen smaller than the window (the place then shortens it).
    #[test]
    fn at_100_percent_the_sizes_are_the_configs() {
        for room in [
            Room {
                width: 1920.0,
                height: 1001.0,
            },
            Room {
                width: 1093.0,
                height: 535.0,
            },
            Room {
                width: 1024.0,
                height: 400.0,
            },
        ] {
            assert_eq!(
                sizes(1.0, room),
                Sizes {
                    min_width: 340.0,
                    min_height: 480.0,
                    width: 400.0,
                    height: 600.0,
                },
                "{room:?}"
            );
        }
    }

    /// A larger text size scales both sizes, so the page has 340×480 and 400×600 CSS px as at 100 %
    /// — where the room allows.
    #[test]
    fn a_larger_text_size_scales_the_sizes_within_the_room() {
        let big = Room {
            width: 1920.0,
            height: 1001.0,
        };
        // 125 % and 150 % on 1080p at 100 %: room for all of it.
        assert_eq!(
            sizes(1.25, big),
            Sizes {
                min_width: 425.0,
                min_height: 600.0,
                width: 500.0,
                height: 750.0,
            }
        );
        assert_eq!(
            sizes(1.5, big),
            Sizes {
                min_width: 510.0,
                min_height: 720.0,
                width: 600.0,
                height: 900.0,
            }
        );
        // The page's CSS px: the logical size over the text scale.
        let s = sizes(1.25, big);
        assert!(close(s.min_width / 1.25, 340.0) && close(s.min_height / 1.25, 480.0));
        assert!(close(s.width / 1.25, 400.0) && close(s.height / 1.25, 600.0));

        // 200 % on 1080p at 100 %: 1200 does not fit 1001 — capped, the least size too.
        let s = sizes(2.0, big);
        assert!(
            close(s.height, 1001.0) && close(s.min_height, 960.0),
            "{s:?}"
        );
        assert!(close(s.width, 800.0));

        // 1366×768 at 125 % with 125 % text: 535 px of room — the least height capped there; the
        // height no lower than the 100 % one, 600, which `fit` then shortens to the room when it
        // places the window (as it did at 100 %).
        let small = Room {
            width: 1092.8,
            height: 535.2,
        };
        let s = sizes(1.25, small);
        assert_eq!(
            s,
            Sizes {
                min_width: 425.0,
                min_height: 535.0,
                width: 500.0,
                height: 600.0,
            }
        );
        let tiny = Room {
            width: 1000.0,
            height: 450.0,
        };
        let s = sizes(1.5, tiny);
        assert!(
            close(s.min_height, 480.0) && close(s.height, 600.0),
            "{s:?}"
        );
    }

    /// The room is the work area under the title bar, in logical px.
    #[test]
    fn the_room_is_the_work_area_under_the_title_bar() {
        // 1366×768 at 125 %, a 60 px taskbar: 708 px of work area, a 39 px title bar (31 × 1.25).
        let w = default_window(30, 30, 1.25);
        let r = room(rect(0, 0, 1366, 708), w, 1.25);
        assert!(close(r.width, 1366.0 / 1.25), "{r:?}");
        assert!(close(r.height, (708.0 - 39.0) / 1.25), "{r:?}");
    }

    /// Sized for 125 % text on a screen with room, the window that then fits stays where it is; on
    /// one without, the least height capped at the room keeps it inside the work area.
    #[test]
    fn a_window_sized_for_the_text_size_still_fits_the_screen() {
        // 1920×1080 at 100 %, 125 % text: 500×750 fits.
        let work = rect(0, 0, 1920, 1032);
        let s = sizes(1.25, room(work, default_window(26, 26, 1.0), 1.0));
        let w = window(26, 26, s.width, s.height, 1.0);
        assert_eq!(fit(work, w, 1.0, s.min_height), Fit::Fits);

        // 1366×768 at 125 %, 125 % text: 750 does not fit; shortened to the room, centred, inside.
        let work = rect(0, 0, 1366, 708);
        let s = sizes(1.25, room(work, default_window(30, 30, 1.25), 1.25));
        let w = window(30, 30, s.width, DEFAULT_INNER_HEIGHT * 1.25, 1.25);
        match fit(work, w, 1.25, s.min_height) {
            Fit::Place {
                y,
                inner_height: Some(h),
                ..
            } => {
                assert!(
                    h >= MIN_INNER_HEIGHT && h <= s.min_height + 1.0,
                    "{h} {s:?}"
                );
                let chrome = 39.0;
                assert!(h * 1.25 + chrome <= 708.0 + 1.0, "{h}");
                assert!(y >= 0);
            }
            other => panic!("{other:?}"),
        }
    }
}
