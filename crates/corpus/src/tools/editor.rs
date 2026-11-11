//! Typing in a code editor, and an idle editor (with and without a blinking caret).
//!
//! Typing is synthesised from two renders of the same page: the finished text, and the same layout
//! with the lines still to be typed made transparent. A keystroke reveals the finished render up to
//! the right edge of the character just typed, measured in the page itself by a script, so glyph
//! positions are the browser's own (Consolas advances are fractional at 200%). The caret blinks at
//! Windows' 530 ms and stays solid while keys arrive, and the current line carries VS Code's
//! highlight border.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::edge::{measure_json, DSF};
use super::emit::Emitter;
use super::html::{self, CodeLine, EDITOR_VIEW};
use super::image::{rgb, Image};
use super::scene::{self, Ctx, Rect, JITTER_US, SOURCE_H, SOURCE_W};
use crate::format::{Scaling, Summary};
use crate::motion::{caret_visible, plan_typing, TypingParams, Vsync};
use crate::rng::Rng;
use crate::writer::WriterOptions;

/// Relative to the agent repository's root ([`Ctx::repo`]).
const TYPED_FILE: &str = "crates/capture/src/pace.rs";
const IDLE_FILE: &str = "crates/core/src/quality.rs";
/// Lines of existing code shown above the typing.
const CONTEXT_LINES: usize = 37;
const CARET: [u8; 4] = rgb(0xaeafad);
const LINE_BORDER: [u8; 4] = rgb(0x282828);
/// Left edge of code text in the editor page (gutter 48 + padding 22), CSS pixels.
const TEXT_LEFT_CSS: f64 = 70.0;

#[derive(Debug, Deserialize)]
struct LineBox {
    top: f64,
    bottom: f64,
    num_left: f64,
    rights: Vec<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypingSpec {
    pub name: String,
    pub seed: u64,
    pub seconds: f64,
    /// Median seconds between keystrokes.
    pub key_median_s: f64,
}

fn px(css: f64) -> i64 {
    (css * f64::from(DSF)).round() as i64
}

/// The editor screen with an empty text area, and the text area's physical rectangle.
fn editor_chrome(
    ctx: &mut Ctx,
    name: &str,
    file: &str,
    crumbs: &[&str],
    pos: &str,
) -> Result<(Image, Rect)> {
    let screen = ctx.edge()?.screenshot(
        &format!("{name}-screen"),
        &html::editor_screen(file, crumbs, pos),
        html::SCREEN_W,
        html::SCREEN_H,
        false,
    )?;
    Ok((screen, Rect::from_css(EDITOR_VIEW)))
}

fn draw_line_highlight(img: &mut Image, view: Rect, top: i64, bottom: i64) {
    let x0 = view.x + px(TEXT_LEFT_CSS) - 8;
    let w = view.w - (x0 - view.x);
    let b = 4;
    img.fill(x0, top, w, b, LINE_BORDER);
    img.fill(x0, bottom - b, w, b, LINE_BORDER);
}

pub fn generate_typing(ctx: &mut Ctx, spec: &TypingSpec) -> Result<Summary> {
    let src = ctx.repo_text(TYPED_FILE)?;
    let all: Vec<&str> = src.lines().collect();
    let start = all
        .iter()
        .position(|l| l.starts_with("pub fn admit("))
        .context("pace.rs no longer has `pub fn admit(`; pick another typed block")?;
    let end = all[start..]
        .iter()
        .position(|l| *l == "}")
        .map(|i| start + i)
        .context("end of admit()")?;
    let first = start.saturating_sub(CONTEXT_LINES);
    let typed: Vec<String> = all[start..=end].iter().map(|s| (*s).to_string()).collect();

    let lines = |hide: bool| -> Vec<CodeLine> {
        (first..=end)
            .map(|i| CodeLine {
                number: i + 1,
                text: all[i].to_string(),
                hidden: hide && i >= start,
                measure: (i >= start).then(|| i - start),
            })
            .collect()
    };
    let (screen, view) = editor_chrome(
        ctx,
        &spec.name,
        "pace.rs",
        &["agent", "crates", "capture", "src", "pace.rs"],
        "Ln 65, Col 1",
    )?;
    let edge = ctx.edge()?;
    let fin = edge.screenshot(
        &format!("{}-final", spec.name),
        &html::code_document(&lines(false), EDITOR_VIEW.w, 0, ""),
        EDITOR_VIEW.w,
        EDITOR_VIEW.h,
        false,
    )?;
    let empty = edge.screenshot(
        &format!("{}-empty", spec.name),
        &html::code_document(&lines(true), EDITOR_VIEW.w, 0, ""),
        EDITOR_VIEW.w,
        EDITOR_VIEW.h,
        false,
    )?;
    let dom = edge.dump_dom(
        &format!("{}-measure", spec.name),
        &html::code_document(&lines(false), EDITOR_VIEW.w, 0, html::MEASURE_CHARS_JS),
        EDITOR_VIEW.w,
        EDITOR_VIEW.h,
    )?;
    let json = measure_json(&dom)?
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">");
    let boxes: Vec<LineBox> = serde_json::from_str(&json).context("character measurements")?;
    anyhow::ensure!(
        boxes.len() == typed.len(),
        "measured {} typed lines, expected {}",
        boxes.len(),
        typed.len()
    );
    for (b, t) in boxes.iter().zip(&typed) {
        anyhow::ensure!(
            b.rights.len() == t.chars().count(),
            "line {t:?}: {} measured characters",
            b.rights.len()
        );
    }

    let params = TypingParams {
        seconds: spec.seconds,
        seed: spec.seed,
        key_median_s: spec.key_median_s,
        ..TypingParams::default()
    };
    let keys = plan_typing(&typed, &params);
    tracing::debug!(
        scenario = %spec.name,
        keystrokes = keys.len(),
        last_line = keys.last().map(|k| k.1.line),
        "typing planned"
    );

    let meta = scene::synthetic_meta(
        &spec.name,
        "Typing Rust into a dark code editor at about five characters a second, with Enter pauses, thinking pauses, \
         a few backspaces and a blinking caret. Small, localised changes. Full resolution.",
        "typing",
        spec.seed,
        serde_json::json!({ "spec": spec, "planner": params }),
        vec![format!("{TYPED_FILE} lines {}-{} (typed {}-{})", first + 1, end + 1, start + 1, end + 1)],
        (SOURCE_W, SOURCE_H),
        Scaling::Native,
        JITTER_US,
        false,
        vec![
            "Characters appear with their final syntax colour; VS Code would recolour a token as it completes.".into(),
            "The status bar's Ln/Col does not update (a few pixels per keystroke in the real editor).".into(),
        ],
    );
    let vsync = params.vsync;
    let mut rng = Rng::new(spec.seed ^ 0x7e11);
    let mut emitter = Emitter::create(
        &ctx.out_path(&spec.name),
        &meta,
        WriterOptions::default(),
        vsync,
        rng.fork(1),
    )?;

    let mut frame = screen;
    let mut last_state: Option<(usize, bool)> = None;
    let mut key_i = 0usize;
    for k in 0..vsync.count(spec.seconds) {
        let t = vsync.t_s(k);
        while key_i + 1 < keys.len() && keys[key_i + 1].0 <= t {
            key_i += 1;
        }
        let visible = caret_visible(t, keys[key_i].0, params.blink_s);
        let state = (key_i, visible);
        if last_state == Some(state) {
            continue;
        }
        last_state = Some(state);
        let caret = keys[key_i].1;

        frame.blit(&empty, 0, 0, view.w, view.h, view.x, view.y);
        for b in boxes.iter().take(caret.line) {
            let (top, bottom) = (px(b.top), px(b.bottom));
            frame.blit(&fin, 0, top, view.w, bottom - top, view.x, view.y + top);
        }
        let b = &boxes[caret.line];
        let (top, bottom) = (px(b.top), px(b.bottom));
        let x_end = if caret.col == 0 {
            px(TEXT_LEFT_CSS)
        } else {
            px(b.rights[caret.col - 1])
        };
        // The line number appears with the line; the text up to the caret.
        let reveal = x_end.max(px(b.num_left));
        frame.blit(&fin, 0, top, reveal, bottom - top, view.x, view.y + top);
        draw_line_highlight(&mut frame, view, view.y + top, view.y + bottom);
        if visible {
            frame.fill(view.x + x_end, view.y + top, 4, bottom - top, CARET);
        }
        emitter.deliver(k, &frame.px, &[])?;
    }
    emitter.finish(scene::us(spec.seconds))
}

#[derive(Debug, Clone, Serialize)]
pub struct IdleSpec {
    pub name: String,
    pub seed: u64,
    pub seconds: f64,
    /// Blink a caret in the editor (otherwise nothing changes at all).
    pub caret: bool,
}

pub fn generate_idle(ctx: &mut Ctx, spec: &IdleSpec) -> Result<Summary> {
    let src = ctx.repo_text(IDLE_FILE)?;
    let rows = (EDITOR_VIEW.h / html::CODE_LINE_H) as usize + 1;
    let lines: Vec<CodeLine> = src
        .lines()
        .skip(1419)
        .take(rows)
        .enumerate()
        .map(|(i, t)| CodeLine {
            number: 1420 + i,
            text: t.to_string(),
            hidden: false,
            measure: None,
        })
        .collect();
    let (mut frame, view) = editor_chrome(
        ctx,
        &spec.name,
        "quality.rs",
        &["agent", "crates", "core", "src", "quality.rs"],
        "Ln 1431, Col 21",
    )?;
    let page = ctx.edge()?.screenshot(
        &format!("{}-page", spec.name),
        &html::code_document(&lines, EDITOR_VIEW.w, 0, ""),
        EDITOR_VIEW.w,
        EDITOR_VIEW.h,
        false,
    )?;
    frame.blit(&page, 0, 0, view.w, view.h, view.x, view.y);
    // Caret on line 12 of the view, after 20 characters (Consolas advance 7.695 CSS px at 14 px).
    let line_top = view.y + px(11.0 * f64::from(html::CODE_LINE_H));
    let line_h = px(f64::from(html::CODE_LINE_H));
    let caret_x = view.x + px(TEXT_LEFT_CSS + 20.0 * 7.695);
    draw_line_highlight(&mut frame, view, line_top, line_top + line_h);
    let under = frame.crop(caret_x as u32, line_top as u32, 4, line_h as u32);

    let vsync = Vsync {
        hz: scene::DISPLAY_HZ,
    };
    let blink_s = TypingParams::default().blink_s;
    let meta = scene::synthetic_meta(
        &spec.name,
        &if spec.caret {
            "An idle code editor whose only change is the caret blinking every 530 ms (4x38 px). Full resolution.".to_string()
        } else {
            "An idle desktop: one frame, then nothing for the whole scenario, as WGC delivers nothing while the screen is still. Full resolution.".to_string()
        },
        "idle",
        spec.seed,
        serde_json::json!({ "spec": spec, "blink_s": blink_s }),
        vec![format!("{IDLE_FILE} lines 1420-{}", 1419 + rows)],
        (SOURCE_W, SOURCE_H),
        Scaling::Native,
        JITTER_US,
        false,
        vec![
            "The taskbar clock does not tick; a real idle minute usually has one clock change."
                .into(),
        ],
    );
    let mut rng = Rng::new(spec.seed ^ 0x1d1e);
    let mut emitter = Emitter::create(
        &ctx.out_path(&spec.name),
        &meta,
        WriterOptions::default(),
        vsync,
        rng.fork(1),
    )?;
    let mut last: Option<bool> = None;
    for k in 0..vsync.count(spec.seconds) {
        let visible = !spec.caret || caret_visible(vsync.t_s(k), 0.0, blink_s);
        if last == Some(visible) {
            continue;
        }
        last = Some(visible);
        if spec.caret {
            if visible {
                frame.fill(caret_x, line_top, 4, line_h, CARET);
            } else {
                frame.blit(&under, 0, 0, 4, line_h, caret_x, line_top);
            }
        }
        emitter.deliver(k, &frame.px, &[])?;
    }
    emitter.finish(scene::us(spec.seconds))
}
