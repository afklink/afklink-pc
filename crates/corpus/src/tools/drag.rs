//! Dragging and resizing a window over the desktop.
//!
//! The desktop (a stock Windows wallpaper, icons, the taskbar) and a File Explorer window are each
//! rendered once. Each frame composites the window at the planned rectangle with a soft shadow and
//! the pointer on its title bar (or its corner, while resizing). A resize keeps the window's four
//! corners and crops the middle, which is how Explorer's list behaves when it narrows (columns are
//! clipped, not reflowed).

use anyhow::{Context, Result};
use serde::Serialize;

use super::emit::Emitter;
use super::html;
use super::image::{rgb, Image};
use super::scene::{self, Ctx, JITTER_US, SOURCE_H, SOURCE_W};
use crate::codec::Move;
use crate::format::{Scaling, Summary};
use crate::motion::{plan_drag, DragParams, Vsync, WindowRect};
use crate::rng::Rng;
use crate::writer::WriterOptions;

/// Window size rendered (CSS px); every size the plan uses is cropped from it.
const WIN_CSS: (u32, u32) = (1300, 860);
/// Right and bottom strips kept whole when the window is resized (title buttons, status bar).
const KEEP_RIGHT: i64 = 300;
const KEEP_BOTTOM: i64 = 60;
/// Where the pointer holds the window while moving it, relative to its top-left.
const GRAB: (i64, i64) = (700, 40);

#[derive(Debug, Clone, Serialize)]
pub struct DragSpec {
    pub name: String,
    pub seed: u64,
    pub seconds: f64,
    pub resize_share: f64,
}

pub fn generate(ctx: &mut Ctx, spec: &DragSpec) -> Result<Summary> {
    let walls = scene::wallpapers();
    let wall = walls
        .iter()
        .find(|p| p.ends_with(r"ThemeA\img20.jpg"))
        .or(walls.first())
        .cloned()
        .context("a wallpaper for the desktop")?;
    let edge = ctx.edge()?;
    let desktop = edge.screenshot(
        &format!("{}-desktop", spec.name),
        &html::desktop_screen(&wall),
        html::SCREEN_W,
        html::SCREEN_H,
        false,
    )?;
    let window = edge.screenshot(
        &format!("{}-window", spec.name),
        &html::explorer_window(WIN_CSS.0, WIN_CSS.1),
        WIN_CSS.0,
        WIN_CSS.1,
        false,
    )?;
    let (win_w, win_h) = (i64::from(window.w), i64::from(window.h));
    let taskbar = i64::from(html::TASKBAR_H * super::edge::DSF);

    let params = DragParams {
        seconds: spec.seconds,
        vsync: Vsync {
            hz: scene::DISPLAY_HZ,
        },
        seed: spec.seed,
        area_w: i64::from(SOURCE_W),
        area_h: i64::from(SOURCE_H) - taskbar,
        start: WindowRect {
            x: 520,
            y: 240,
            w: 2100,
            h: 1400,
        },
        min_size: (1400, 900),
        max_size: (win_w, win_h),
        move_s: (0.35, 1.1),
        pause_s: (0.4, 1.8),
        resize_share: spec.resize_share,
        tremor_px: 2.5,
    };
    let plan = plan_drag(&params);
    let changes = plan.windows(2).filter(|w| w[0] != w[1]).count();
    tracing::debug!(scenario = %spec.name, vsyncs = plan.len(), changes, "drag planned");

    let meta = scene::synthetic_meta(
        &spec.name,
        "Dragging a File Explorer window around the desktop (and resizing it from the corner about a third of the time), \
         with pauses. Large moving regions over a photo wallpaper. Full resolution.",
        "drag",
        spec.seed,
        serde_json::json!({ "spec": spec, "planner": params }),
        vec![format!("wallpaper {}", wall.display())],
        (SOURCE_W, SOURCE_H),
        Scaling::Native,
        JITTER_US,
        false,
        vec![
            "No live-resize repaint lag: the window content is cropped, never stale or blank as a slow app's would be.".into(),
            "The shadow is an approximation drawn per frame.".into(),
        ],
    );
    let mut rng = Rng::new(spec.seed ^ 0xd4a6);
    let mut emitter = Emitter::create(
        &ctx.out_path(&spec.name),
        &meta,
        WriterOptions::default(),
        params.vsync,
        rng.fork(1),
    )?;

    let mut frame = desktop.clone();
    let mut last: Option<WindowRect> = None;
    for (k, r) in plan.iter().enumerate() {
        if last == Some(*r) {
            continue;
        }
        let resizing = last.is_some_and(|l| l.w != r.w || l.h != r.h);
        frame.blit(
            &desktop,
            0,
            0,
            i64::from(desktop.w),
            i64::from(desktop.h),
            0,
            0,
        );
        draw_shadow(&mut frame, *r);
        draw_window(&mut frame, &window, *r, win_w, win_h);
        let (px, py) = if resizing {
            (r.x + r.w - 10, r.y + r.h - 10)
        } else {
            (r.x + GRAB.0, r.y + GRAB.1)
        };
        frame.draw_pointer(px, py);
        let moves: Vec<Move> = match last {
            Some(l) if l.w == r.w && l.h == r.h => vec![Move {
                x0: r.x as u32,
                y0: r.y as u32,
                x1: (r.x + r.w) as u32,
                y1: (r.y + r.h) as u32,
                dx: (l.x - r.x) as i32,
                dy: (l.y - r.y) as i32,
            }],
            _ => Vec::new(),
        };
        emitter.deliver(k as u64, &frame.px, &moves)?;
        last = Some(*r);
    }
    emitter.finish(scene::us(spec.seconds))
}

/// The window at `r`, cropped from the full-size render around its four corners.
fn draw_window(frame: &mut Image, win: &Image, r: WindowRect, win_w: i64, win_h: i64) {
    let (kr, kb) = (KEEP_RIGHT.min(r.w), KEEP_BOTTOM.min(r.h));
    let (lw, th) = (r.w - kr, r.h - kb);
    frame.blit(win, 0, 0, lw, th, r.x, r.y);
    frame.blit(win, win_w - kr, 0, kr, th, r.x + lw, r.y);
    frame.blit(win, 0, win_h - kb, lw, kb, r.x, r.y + th);
    frame.blit(win, win_w - kr, win_h - kb, kr, kb, r.x + lw, r.y + th);
}

/// A soft drop shadow: rings of decreasing opacity, offset slightly down.
fn draw_shadow(frame: &mut Image, r: WindowRect) {
    let black = rgb(0x000000);
    let rings = 18i64;
    for i in 1..=rings {
        let a = (70.0 * (1.0 - i as f64 / (rings + 1) as f64).powi(2)) as u8;
        let (x0, y0) = (r.x - i, r.y - i + 6);
        let (w, h) = (r.w + 2 * i, r.h + 2 * i);
        frame.blend(x0, y0, w, 1, black, a);
        frame.blend(x0, y0 + h - 1, w, 1, black, a);
        frame.blend(x0, y0 + 1, 1, h - 2, black, a);
        frame.blend(x0 + w - 1, y0 + 1, 1, h - 2, black, a);
    }
}
