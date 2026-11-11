//! Hand-run probes for the "game window only" mode: ignored tests, diagnostics rather than tests of
//! this crate, run with a person at the PC and the game running.
//!
//! - [`window_capture`]: can a medium-integrity process (the agent, and the terminal the probe runs
//!   from) capture the window of an elevated game with WGC `CreateForWindow`, and what does that
//!   capture show while the game is covered, minimized and restored?
//! - [`game_watch`] (passive): what the process tree and the game's windows do while the game is
//!   closed and started again through its launcher.
//! - [`focus`]: can this unelevated process bring the elevated game's window back to the foreground
//!   when something else has taken it? The agent restores the game's focus by itself in this mode.
//! - [`cursor_capture`]: does WGC, capturing the game's window, draw the game's cursor with its tip
//!   on the hotspot (the pixel `GetCursorInfo` reports and a click lands on) when the game does not
//!   support the display's scale? Two captures of the window, with and without the cursor, cropped
//!   around the hotspot.
//!
//! What they **never** do, because the target game (Lineage 2, `ScrydeGame.bin`, elevated) runs a
//! kernel anti-cheat (`active64.sys`): inject input of any kind (no `SendInput`, no HID report, no
//! `SetCursorPos`, no `keybd_event`), or send or post a window message to another process; open the
//! game's process for more than `PROCESS_QUERY_LIMITED_INFORMATION` (`game_watch` adds
//! `SYNCHRONIZE` only when asked to wait for exit codes, off by default); read its memory or hook
//! it; start, stop or signal any process. Through that one limited handle they read the exe path,
//! the creation time and, opening the process's token for `TOKEN_QUERY`, integrity and elevation. A
//! window's class, title, rectangle and owning pid, and a process snapshot (exe name, parent), need
//! no process handle at all. `window_capture` and `game_watch` also never touch the game's windows'
//! focus, z-order, size or state. `focus` does exactly that and nothing more: it asks the system,
//! through the ordinary window APIs its module docs list, to activate, raise or restore the game's
//! window, as a program switching to another one would; the system then sends the game its usual
//! activation messages. Its shell-hook window is a notification from the shell
//! (`RegisterShellHookWindow`), not a `SetWindowsHookEx` hook: nothing is loaded into any process.
//!
//! This file holds the pure parts the probes share (matching, rectangle maths, picture sizing,
//! parsing), unit-tested below and run by every `cargo test`; `win` holds the Win32 reads.

use serde::Serialize;

mod cursor_capture;
mod focus;
mod game_watch;
mod win;
mod window_capture;

/// A rectangle in screen pixels, `[left, top, right, bottom]`, right and bottom exclusive, as Windows
/// reports it.
type Rect = [i32; 4];

/// The longest run `window_capture` and `game_watch` accept, s.
const MAX_SECONDS: u64 = 3600;

/// A channel value below this on all three channels counts as black in a picture's statistics.
const BLACK_BELOW: u8 = 16;

fn area(r: Rect) -> i64 {
    let w = i64::from(r[2]) - i64::from(r[0]);
    let h = i64::from(r[3]) - i64::from(r[1]);
    w.max(0) * h.max(0)
}

/// The overlap of two rectangles; `None` when they do not overlap (touching edges do not).
fn intersect(a: Rect, b: Rect) -> Option<Rect> {
    let r = [
        a[0].max(b[0]),
        a[1].max(b[1]),
        a[2].min(b[2]),
        a[3].min(b[3]),
    ];
    (r[0] < r[2] && r[1] < r[3]).then_some(r)
}

/// How much of `of` the rectangle `by` covers, 0..=1 (0 for an empty `of`).
fn covered_fraction(of: Rect, by: Rect) -> f64 {
    let whole = area(of);
    if whole == 0 {
        return 0.0;
    }
    intersect(of, by).map_or(0.0, |i| area(i) as f64 / whole as f64)
}

fn rect_text(r: Option<Rect>) -> String {
    r.map_or_else(
        || "-".to_owned(),
        |r| format!("{},{},{},{}", r[0], r[1], r[2], r[3]),
    )
}

/// An environment variable's text as a case-insensitive needle: trimmed and lowercased; `None` when
/// that leaves nothing.
fn needle_of(raw: &str) -> Option<String> {
    let n = raw.trim().to_lowercase();
    (!n.is_empty()).then_some(n)
}

/// Which of a window's fields contain the needle.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
struct Matched {
    class: bool,
    exe: bool,
    title: bool,
}

impl Matched {
    fn any(self) -> bool {
        self.class || self.exe || self.title
    }

    /// By class or exe name: what identifies a game's window. A title alone may belong to anything —
    /// a terminal showing the command line, a browser tab about the game.
    fn strong(self) -> bool {
        self.class || self.exe
    }

    fn fields(self) -> String {
        [
            (self.class, "class"),
            (self.exe, "exe"),
            (self.title, "title"),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join("+")
    }
}

/// Match a lowercased needle against a window's class, its process's exe name (unknown when the
/// snapshot missed the process) and its title, each case-insensitively (titles may be Cyrillic).
fn match_window(needle: &str, class: &str, exe: Option<&str>, title: &str) -> Matched {
    let has = |text: &str| text.to_lowercase().contains(needle);
    Matched {
        class: has(class),
        exe: exe.is_some_and(has),
        title: has(title),
    }
}

/// A visible top-level window that matched, as the choice between several sees it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Candidate {
    matched: Matched,
    minimized: bool,
    cloaked: bool,
    area: i64,
}

/// Which matching window to capture: a match by class or exe name before a title-only one, a window
/// actually on screen (not minimized, not cloaked) before one that is not, then the largest; a tie goes
/// to the first, the top of the z-order (`EnumWindows` lists top first). `None` for no candidate.
fn pick_candidate(candidates: &[Candidate]) -> Option<usize> {
    let key = |c: &Candidate| (c.matched.strong(), !c.minimized && !c.cloaked, c.area);
    let mut best: Option<usize> = None;
    for (i, c) in candidates.iter().enumerate() {
        match best.and_then(|b| candidates.get(b)) {
            Some(b) if key(b) >= key(c) => {}
            _ => best = Some(i),
        }
    }
    best
}

/// A picture's size: the frame's, scaled down to at most `max_w` wide with the aspect kept (height
/// rounded, at least 1). A frame no wider than `max_w` keeps its size.
fn fit_width(w: u32, h: u32, max_w: u32) -> (u32, u32) {
    if w <= max_w || max_w == 0 {
        return (w, h);
    }
    let scaled = (u64::from(h) * u64::from(max_w) + u64::from(w) / 2) / u64::from(w);
    // `scaled <= h`, so it fits.
    (max_w, scaled.max(1) as u32)
}

/// Scale a tightly packed BGRA picture to `(ow, oh)` RGB, each output pixel the average of its
/// footprint (a box filter: a thin line survives as a faint one, which sampling one pixel would drop).
/// Alpha is ignored — every pixel is shown as if opaque — so nothing a transparent region holds is
/// hidden from whoever checks the picture for a leak. Empty when the input is shorter than `w x h`.
fn downscale_bgra_to_rgb(src: &[u8], w: u32, h: u32, ow: u32, oh: u32) -> Vec<u8> {
    let (w, h, ow, oh) = (w as usize, h as usize, ow as usize, oh as usize);
    let mut out = Vec::with_capacity(ow * oh * 3);
    if w == 0 || h == 0 || ow == 0 || oh == 0 || src.len() < w * h * 4 {
        return out;
    }
    for oy in 0..oh {
        let y0 = oy * h / oh;
        let y1 = ((oy + 1) * h / oh).max(y0 + 1).min(h);
        for ox in 0..ow {
            let x0 = ox * w / ow;
            let x1 = ((ox + 1) * w / ow).max(x0 + 1).min(w);
            let (mut b, mut g, mut r, mut n) = (0u64, 0u64, 0u64, 0u64);
            for y in y0..y1 {
                let (pixels, _) = src[(y * w + x0) * 4..(y * w + x1) * 4].as_chunks::<4>();
                for px in pixels {
                    b += u64::from(px[0]);
                    g += u64::from(px[1]);
                    r += u64::from(px[2]);
                    n += 1;
                }
            }
            // n >= 1: every footprint is at least one pixel.
            let avg = |sum: u64| ((sum + n / 2) / n.max(1)) as u8;
            out.extend_from_slice(&[avg(r), avg(g), avg(b)]);
        }
    }
    out
}

/// What a saved picture looks like in numbers, so a black or blank capture shows without opening it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
struct PictureStats {
    /// Mean luma, 0..255 (0.299 R + 0.587 G + 0.114 B).
    mean_luma: f64,
    /// Share of pixels below [`BLACK_BELOW`] on every channel.
    black_fraction: f64,
    /// Every pixel the same colour.
    uniform: bool,
}

fn picture_stats(rgb: &[u8]) -> PictureStats {
    let (pixels, _) = rgb.as_chunks::<3>();
    let first = pixels.first();
    let (mut sum, mut black, mut n, mut uniform) = (0f64, 0usize, 0usize, true);
    for px in pixels {
        let [r, g, b] = *px;
        sum += 0.299 * f64::from(r) + 0.587 * f64::from(g) + 0.114 * f64::from(b);
        if r.max(g).max(b) < BLACK_BELOW {
            black += 1;
        }
        if Some(px) != first {
            uniform = false;
        }
        n += 1;
    }
    if n == 0 {
        return PictureStats {
            mean_luma: 0.0,
            black_fraction: 0.0,
            uniform: true,
        };
    }
    PictureStats {
        mean_luma: (sum / n as f64 * 10.0).round() / 10.0,
        black_fraction: (black as f64 / n as f64 * 1000.0).round() / 1000.0,
        uniform,
    }
}

/// `AFK_PROBE_SECONDS`: unset or empty is `default`; otherwise whole seconds, 1..=[`MAX_SECONDS`].
fn parse_seconds(raw: Option<&str>, default: u64) -> Result<u64, String> {
    let Some(text) = raw.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(default);
    };
    match text.parse::<u64>() {
        Ok(s) if (1..=MAX_SECONDS).contains(&s) => Ok(s),
        Ok(s) => Err(format!(
            "AFK_PROBE_SECONDS={s} is out of range (1..={MAX_SECONDS})"
        )),
        Err(error) => Err(format!(
            "AFK_PROBE_SECONDS={text:?} is not a whole number of seconds: {error}"
        )),
    }
}

/// An on/off switch: unset, empty, `0`, `false`, `no`, `off` are off; `1`, `true`, `yes`, `on` are
/// on; anything else is an error rather than a guess.
fn parse_flag(name: &str, raw: Option<&str>) -> Result<bool, String> {
    let text = raw.map(|t| t.trim().to_ascii_lowercase());
    match text.as_deref() {
        None | Some("" | "0" | "false" | "no" | "off") => Ok(false),
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some(other) => Err(format!("{name}={other:?}: use 1 (on) or 0 (off)")),
    }
}

/// Frames per whole second: `counts[s]` is how many of `times_us` (µs since the capture started,
/// ascending) fall in `[s, s + 1)` s; at least `seconds` long, longer if a frame came later.
fn per_second_counts(times_us: &[i64], seconds: usize) -> Vec<u32> {
    let mut counts = vec![0u32; seconds];
    for &t in times_us.iter().filter(|t| **t >= 0) {
        let s = (t / 1_000_000) as usize;
        if s >= counts.len() {
            counts.resize(s + 1, 0);
        }
        counts[s] += 1;
    }
    counts
}

/// Stretches longer than `min_us` without a frame, `(from_us, to_us)`: from the capture's start (0)
/// or a frame to the next frame, and from the last frame to `end_us`.
fn frame_gaps(times_us: &[i64], end_us: i64, min_us: i64) -> Vec<(i64, i64)> {
    let mut gaps = Vec::new();
    let mut prev = 0i64;
    for &t in times_us {
        if t - prev > min_us {
            gaps.push((prev, t));
        }
        prev = prev.max(t);
    }
    if end_us - prev > min_us {
        gaps.push((prev, end_us));
    }
    gaps
}

/// `yyyymmdd-hhmmss`, for file names.
fn stamp(year: u16, month: u16, day: u16, hour: u16, minute: u16, second: u16) -> String {
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

/// At most `max` characters of `text`, the last replaced by `…` when cut (for table columns).
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// µs as ms with a µs remainder, for the JSON.
fn ms(us: i64) -> f64 {
    us as f64 / 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlap_needs_shared_area_not_a_shared_edge() {
        let game = [0, 0, 3600, 2328];
        assert_eq!(
            intersect(game, [100, 200, 900, 800]),
            Some([100, 200, 900, 800])
        );
        // The taskbar right under the game touches its bottom edge and does not cover it.
        assert_eq!(intersect(game, [0, 2328, 3600, 2400]), None);
        assert_eq!(intersect(game, [-50, -50, 10, 20]), Some([0, 0, 10, 20]));
        // A minimized window lives at -32000 and covers nothing.
        assert_eq!(intersect(game, [-32000, -32000, -31840, -31972]), None);
        assert_eq!(area([10, 10, 5, 20]), 0);
        assert_eq!(area([0, 0, 3600, 2328]), 3600 * 2328);
    }

    #[test]
    fn covered_fraction_is_the_share_of_the_target() {
        let game = [0, 0, 1000, 1000];
        let half = covered_fraction(game, [0, 0, 500, 1000]);
        assert!((half - 0.5).abs() < 1e-9, "{half}");
        let whole = covered_fraction(game, [-10, -10, 2000, 2000]);
        assert!((whole - 1.0).abs() < 1e-9, "{whole}");
        assert!(covered_fraction(game, [1000, 0, 1200, 100]).abs() < 1e-12);
        assert!(covered_fraction([5, 5, 5, 9], game).abs() < 1e-12);
    }

    #[test]
    fn matching_is_case_insensitive_on_class_exe_and_title() {
        let n = needle_of("  ScrydeGame ").unwrap();
        assert_eq!(n, "scrydegame");
        let m = match_window(
            &n,
            "ScrydeGameUnrealWWindowsViewportWindow",
            Some("ScrydeGame.bin"),
            "ТАНОР",
        );
        assert_eq!(
            m,
            Matched {
                class: true,
                exe: true,
                title: false
            }
        );
        assert!(m.strong());
        assert_eq!(m.fields(), "class+exe");
        // Cyrillic titles lowercase too.
        let t = match_window(&needle_of("танор").unwrap(), "X", None, "ТАНОР");
        assert!(t.title && !t.strong() && t.any());
        assert!(!match_window(&n, "Notepad", Some("notepad.exe"), "Untitled").any());
        assert_eq!(needle_of("   "), None);
    }

    #[test]
    fn the_pick_prefers_class_or_exe_then_on_screen_then_the_largest() {
        let strong = Matched {
            class: true,
            ..Matched::default()
        };
        let title_only = Matched {
            title: true,
            ..Matched::default()
        };
        let c = |matched, minimized, area| Candidate {
            matched,
            minimized,
            cloaked: false,
            area,
        };
        // A big terminal whose title mentions the game loses to the game's own window.
        assert_eq!(
            pick_candidate(&[c(title_only, false, 9_000_000), c(strong, false, 8_000_000)]),
            Some(1)
        );
        // A minimized game window loses to one on screen, whatever the sizes.
        assert_eq!(
            pick_candidate(&[c(strong, true, 99_000_000), c(strong, false, 100)]),
            Some(1)
        );
        // Then the largest; a tie keeps the top of the z-order.
        assert_eq!(
            pick_candidate(&[
                c(strong, false, 100),
                c(strong, false, 400),
                c(strong, false, 400)
            ]),
            Some(1)
        );
        assert_eq!(pick_candidate(&[]), None);
    }

    #[test]
    fn pictures_fit_1280_wide_with_the_aspect_kept() {
        // A 3600 x 2328 game window: 1280 x 827.7.
        assert_eq!(fit_width(3600, 2328, 1280), (1280, 828));
        assert_eq!(fit_width(3600, 2400, 1280), (1280, 853));
        assert_eq!(fit_width(1280, 720, 1280), (1280, 720));
        assert_eq!(fit_width(800, 600, 1280), (800, 600));
        // A minimized window's 1x1 frame stays 1x1; a sliver never goes to height 0.
        assert_eq!(fit_width(1, 1, 1280), (1, 1));
        assert_eq!(fit_width(100_000, 1, 1280), (1280, 1));
    }

    #[test]
    fn the_downscale_averages_each_footprint_and_ignores_alpha() {
        // 4 x 2 BGRA: left half pure blue, right half pure red; alpha 0 everywhere.
        let blue = [255u8, 0, 0, 0];
        let red = [0u8, 0, 255, 0];
        let row: Vec<u8> = [blue, blue, red, red].concat();
        let src = [row.clone(), row].concat();
        assert_eq!(
            downscale_bgra_to_rgb(&src, 4, 2, 2, 1),
            vec![0, 0, 255, 255, 0, 0]
        );
        // All four into one: the average colour.
        assert_eq!(downscale_bgra_to_rgb(&src, 4, 2, 1, 1), vec![128, 0, 128]);
        // Same size: a plain BGRA -> RGB conversion.
        assert_eq!(downscale_bgra_to_rgb(&src, 4, 2, 4, 2).len(), 4 * 2 * 3);
        // Too short an input is refused, not read past.
        assert!(downscale_bgra_to_rgb(&src[..8], 4, 2, 2, 1).is_empty());
    }

    #[test]
    fn picture_stats_flag_black_and_blank_frames() {
        let black = vec![0u8; 30];
        let s = picture_stats(&black);
        assert!(s.uniform && s.mean_luma.abs() < 1e-9);
        assert!((s.black_fraction - 1.0).abs() < 1e-9);
        let mixed = [vec![255u8; 3], vec![0u8; 3]].concat();
        let s = picture_stats(&mixed);
        assert!(!s.uniform);
        assert!((s.black_fraction - 0.5).abs() < 1e-9);
        assert!((s.mean_luma - 127.5).abs() < 0.05, "{}", s.mean_luma);
    }

    #[test]
    fn seconds_and_flags_parse_strictly() {
        assert_eq!(parse_seconds(None, 45), Ok(45));
        assert_eq!(parse_seconds(Some("  "), 45), Ok(45));
        assert_eq!(parse_seconds(Some(" 30 "), 45), Ok(30));
        assert!(parse_seconds(Some("0"), 45).is_err());
        assert!(parse_seconds(Some("3601"), 45).is_err());
        assert!(parse_seconds(Some("1.5"), 45).is_err());
        assert_eq!(parse_flag("F", None), Ok(false));
        assert_eq!(parse_flag("F", Some("1")), Ok(true));
        assert_eq!(parse_flag("F", Some(" Yes ")), Ok(true));
        assert_eq!(parse_flag("F", Some("0")), Ok(false));
        assert!(parse_flag("F", Some("2")).is_err());
    }

    #[test]
    fn frames_are_counted_per_second_and_gaps_found() {
        let t = [
            0, 400_000, 800_000, 1_000_000, 3_500_000, 3_600_000, 5_200_000,
        ];
        assert_eq!(per_second_counts(&t, 4), vec![3, 1, 0, 2, 0, 1]);
        assert_eq!(per_second_counts(&[], 3), vec![0, 0, 0]);
        // Gaps over half a second: 1.0 -> 3.5 s, 3.6 -> 5.2 s, and 5.2 s -> the end at 6 s.
        assert_eq!(
            frame_gaps(&t, 6_000_000, 500_000),
            vec![
                (1_000_000, 3_500_000),
                (3_600_000, 5_200_000),
                (5_200_000, 6_000_000)
            ]
        );
        // No frame at all: one gap, the whole run.
        assert_eq!(frame_gaps(&[], 2_000_000, 250_000), vec![(0, 2_000_000)]);
    }

    #[test]
    fn stamps_and_clips_are_shaped_for_files_and_columns() {
        assert_eq!(stamp(2026, 9, 30, 7, 5, 9), "20260930-070509");
        assert_eq!(clip("ScrydeGame.bin", 20), "ScrydeGame.bin");
        assert_eq!(
            clip("ScrydeGameUnrealWWindowsViewportWindow", 10),
            "ScrydeGam…"
        );
        assert_eq!(clip("ТАНОР", 3), "ТА…");
        assert_eq!(rect_text(Some([0, 0, 3600, 2328])), "0,0,3600,2328");
        assert_eq!(rect_text(None), "-");
    }
}
