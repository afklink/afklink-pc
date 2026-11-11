//! Text scrolling: a real document rendered by Edge, scrolled inside real-looking chrome.
//!
//! The document is rendered once, tall, at the panel's resolution; each frame crops it at the
//! planned offset into the viewport of a screen rendered with the same browser. Offsets are whole
//! physical pixels (Chromium snaps composited scroll offsets to device pixels), so the stored
//! full-resolution frames are exactly what the screen showed, and the capturer's box filter then
//! produces the sub-pixel phases a real scroll gives the encoder at every rung.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::edge::DSF;
use super::emit::Emitter;
use super::html::{self, CodeLine, BROWSER_VIEW, EDITOR_VIEW};
use super::image::{rgb, Image};
use super::scene::{self, Ctx, Rect, JITTER_US, SOURCE_H, SOURCE_W};
use crate::codec::Move;
use crate::format::{Scaling, Summary};
use crate::motion::{plan_scroll, ScrollParams, ScrollProfile};
use crate::rng::Rng;
use crate::writer::WriterOptions;

/// What scrolls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    /// `crates/core/src/quality.rs` in a VS Code-like dark editor.
    Code,
    /// A long Markdown article (Russian, with tables, code and photos) in an Edge-like browser.
    /// The article is not part of this repository: see [`article_source`].
    Article,
}

impl std::str::FromStr for Content {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "code" => Ok(Self::Code),
            "article" => Ok(Self::Article),
            other => bail!("unknown content {other:?} (code, article)"),
        }
    }
}

/// A scroll scenario.
#[derive(Debug, Clone, Serialize)]
pub struct ScrollSpec {
    pub name: String,
    pub content: Content,
    pub profile: ScrollProfile,
    pub seconds: f64,
    pub seed: u64,
    /// Lines of the source file rendered (code only).
    pub code_lines: usize,
    /// Draw a still mouse pointer over the page (WGC captures the cursor).
    pub pointer: bool,
    /// Overrides applied to the planner defaults (`None` keeps the default).
    pub speed_px_s: Option<f64>,
    pub swipe_px: Option<(f64, f64)>,
    pub pause_s: Option<(f64, f64)>,
    pub page_instant: Option<f64>,
    pub weights: Option<[f64; 4]>,
}

impl ScrollSpec {
    #[must_use]
    pub fn new(
        name: &str,
        content: Content,
        profile: ScrollProfile,
        seconds: f64,
        seed: u64,
    ) -> Self {
        Self {
            name: name.to_string(),
            content,
            profile,
            seconds,
            seed,
            code_lines: 700,
            pointer: true,
            speed_px_s: None,
            swipe_px: None,
            pause_s: None,
            page_instant: None,
            weights: None,
        }
    }
}

/// Relative to the agent repository's root ([`Ctx::repo`]).
const CODE_FILE: &str = "crates/core/src/quality.rs";
/// The article's path in the directory this repository is checked out in (the project's working
/// tree around `agent/`, not part of this repository; elsewhere [`ARTICLE_ENV`] names the file);
/// also the label the corpus metadata records for it.
const ARTICLE_FILE: &str = "docs/control-research.md";
/// Overrides where the `article` content is read from: a path to the markdown file.
pub const ARTICLE_ENV: &str = "AFKLINK_CORPUS_ARTICLE";

/// Where the `article` content comes from, and how the corpus metadata names it.
#[derive(Debug, Clone)]
pub struct ArticleSource {
    pub path: PathBuf,
    pub label: String,
}

/// Find the article the `article` scroll scenarios render. It is not part of this repository:
///
/// 1. `AFKLINK_CORPUS_ARTICLE`, when set, wins — an explicit choice, so a file that cannot be read
///    there fails the generation instead of silently falling back;
/// 2. otherwise `<repo>/../docs/control-research.md`, i.e. a parent checkout this repository
///    lives in as `agent/`.
///
/// `None` (with a warning) when neither is available; the CLI then skips the article scenarios
/// the way it skips a video scenario whose recording is missing.
#[must_use]
pub fn article_source(repo: &Path) -> Option<ArticleSource> {
    match std::env::var_os(ARTICLE_ENV) {
        Some(v) if !v.is_empty() => {
            let path = PathBuf::from(v);
            if path.is_file() {
                tracing::debug!(env = ARTICLE_ENV, path = %path.display(), "article: from the env override");
            } else {
                tracing::warn!(env = ARTICLE_ENV, path = %path.display(), "article: the env override is not a file; generation will fail");
            }
            let label = path.display().to_string();
            return Some(ArticleSource { path, label });
        }
        Some(_) => tracing::debug!(
            env = ARTICLE_ENV,
            "article: env override set but empty; ignored"
        ),
        None => {}
    }
    let parent = repo.join("..").join(ARTICLE_FILE);
    if parent.is_file() {
        tracing::debug!(path = %parent.display(), "article: from the parent checkout's docs/");
        return Some(ArticleSource {
            path: parent,
            label: ARTICLE_FILE.to_string(),
        });
    }
    tracing::warn!(
        env = ARTICLE_ENV,
        tried = %parent.display(),
        "article not found: set {ARTICLE_ENV} to the markdown file; article scenarios cannot be \
         generated"
    );
    None
}

pub fn generate(ctx: &mut Ctx, spec: &ScrollSpec) -> Result<Summary> {
    let wallpapers = scene::wallpapers();
    let (screen, tall, view, track, track_bg, input) = match spec.content {
        Content::Code => {
            let src = ctx.repo_text(CODE_FILE)?;
            let lines: Vec<CodeLine> = src
                .lines()
                .take(spec.code_lines)
                .enumerate()
                .map(|(i, t)| CodeLine {
                    number: i + 1,
                    text: t.to_string(),
                    hidden: false,
                    measure: None,
                })
                .collect();
            let edge = ctx.edge()?;
            let screen = edge.screenshot(
                &format!("{}-screen", spec.name),
                &html::editor_screen(
                    "quality.rs",
                    &["agent", "crates", "core", "src", "quality.rs"],
                    "Ln 1, Col 1",
                ),
                html::SCREEN_W,
                html::SCREEN_H,
                false,
            )?;
            let css_h = html::code_height(lines.len());
            let tall = scene::tall_document(edge, &spec.name, EDITOR_VIEW.w, css_h, |off| {
                html::code_document(&lines, EDITOR_VIEW.w, off, "")
            })?;
            let view = Rect::from_css(EDITOR_VIEW);
            let track = Rect {
                x: view.x + view.w,
                y: view.y,
                w: 14 * i64::from(DSF),
                h: view.h,
            };
            (
                screen,
                tall,
                view,
                track,
                rgb(0x1f1f1f),
                format!("{CODE_FILE} lines 1-{}", lines.len()),
            )
        }
        Content::Article => {
            let article = article_source(&ctx.repo)
                .with_context(|| format!("no article to render: set {ARTICLE_ENV}"))?;
            let md = std::fs::read_to_string(&article.path)
                .with_context(|| format!("read article {}", article.path.display()))?;
            let images: Vec<&std::path::Path> = wallpapers.iter().map(|p| p.as_path()).collect();
            let edge = ctx.edge()?;
            let screen = edge.screenshot(
                &format!("{}-screen", spec.name),
                &html::browser_screen(
                    "Ресёрч управления — мобайл + Telegram Desktop",
                    "docs.afklink.local/control-research",
                ),
                html::SCREEN_W,
                html::SCREEN_H,
                false,
            )?;
            let dom = edge.dump_dom(
                &format!("{}-measure", spec.name),
                &html::article_document(&md, &images, BROWSER_VIEW.w, 0, html::MEASURE_HEIGHT_JS),
                BROWSER_VIEW.w,
                BROWSER_VIEW.h,
            )?;
            #[derive(serde::Deserialize)]
            struct H {
                h: f64,
            }
            let h: H = serde_json::from_str(super::edge::measure_json(&dom)?)?;
            let css_h = (h.h.ceil() as u32).max(BROWSER_VIEW.h + 1);
            tracing::debug!(css_h, "article height measured");
            let tall = scene::tall_document(edge, &spec.name, BROWSER_VIEW.w, css_h, |off| {
                html::article_document(&md, &images, BROWSER_VIEW.w, off, "")
            })?;
            let view = Rect::from_css(BROWSER_VIEW);
            let track = Rect {
                x: view.x + view.w,
                y: view.y,
                w: 15 * i64::from(DSF),
                h: view.h,
            };
            (
                screen,
                tall,
                view,
                track,
                rgb(0xf5f5f5),
                format!(
                    "{} (whole), photos from C:\\Windows\\Web\\Wallpaper",
                    article.label
                ),
            )
        }
    };

    let doc_h = i64::from(tall.h);
    let max_scroll = (doc_h - view.h).max(0);
    let mut params = ScrollParams::new(
        spec.profile,
        max_scroll as f64,
        view.h as f64,
        doc_h as f64 / track.h as f64,
    );
    params.seconds = spec.seconds;
    params.seed = spec.seed;
    if let Some(v) = spec.speed_px_s {
        params.speed_px_s = v;
    }
    if let Some(v) = spec.swipe_px {
        params.swipe_px = v;
    }
    if let Some(v) = spec.pause_s {
        params.pause_s = v;
    }
    if let Some(v) = spec.page_instant {
        params.page_instant = v;
    }
    if let Some(v) = spec.weights {
        params.weights = v;
    }
    let plan = plan_scroll(&params);
    let moving = plan.windows(2).filter(|w| w[0] != w[1]).count();
    let max_step = plan
        .windows(2)
        .map(|w| (w[1] - w[0]).abs())
        .max()
        .unwrap_or(0);
    tracing::debug!(
        scenario = %spec.name,
        doc_h,
        max_scroll,
        vsyncs = plan.len(),
        moving,
        max_step,
        "scroll planned"
    );

    let notes = vec![
        "Text rendered by headless Edge (DirectWrite, ClearType) at 200%; offsets snap to whole physical pixels as Chromium's composited scrolling does.".into(),
        "A delivery happens at a vsync only when the offset changed: a still page produces no frames.".into(),
        match spec.content {
            Content::Code => "Editor chrome is an HTML imitation of VS Code Dark Modern (no minimap).".into(),
            Content::Article => "Browser chrome is an HTML imitation of Edge; the scrollbar thumb is drawn per frame.".into(),
        },
    ];
    let mut meta = scene::synthetic_meta(
        &spec.name,
        &match spec.profile {
            ScrollProfile::Steady => format!(
                "Smooth scrolling of {} at a steady reading pace ({:.0} px/s physical) with a slow wobble.",
                describe(spec.content),
                params.speed_px_s
            ),
            ScrollProfile::Wheel => format!(
                "Mouse-wheel scrolling of {}: animated 200 px notches in bursts of 1-3, reading pauses between.",
                describe(spec.content)
            ),
            ScrollProfile::Jerky => format!(
                "Jerky scrolling of {}: phone swipes, Page Down (instant or animated), scrollbar drags and flings, with stops.",
                describe(spec.content)
            ),
        },
        "scroll",
        spec.seed,
        serde_json::json!({ "spec": spec, "planner": params }),
        vec![input],
        (SOURCE_W, SOURCE_H),
        Scaling::Native,
        JITTER_US,
        false,
        notes,
    );
    meta.description.push_str(" Full resolution.");

    let mut rng = Rng::new(spec.seed ^ 0x5c7011);
    let mut emitter = Emitter::create(
        &ctx.out_path(&spec.name),
        &meta,
        WriterOptions::default(),
        params.vsync,
        rng.fork(1),
    )?;
    let pointer = spec
        .pointer
        .then(|| (view.x + view.w * 62 / 100, view.y + view.h * 45 / 100));

    let mut frame = screen;
    let mut last: Option<i64> = None;
    for (k, &pos) in plan.iter().enumerate() {
        if last == Some(pos) {
            continue;
        }
        frame.blit(&tall, 0, pos, view.w, view.h, view.x, view.y);
        draw_thumb(
            &mut frame,
            track,
            track_bg,
            pos,
            doc_h,
            view.h,
            spec.content,
        );
        if let Some((px, py)) = pointer {
            frame.draw_pointer(px, py);
        }
        let moves: Vec<Move> = last
            .and_then(|l| {
                Move::vertical_scroll(
                    view.x as u32,
                    view.y as u32,
                    (view.x + view.w) as u32,
                    (view.y + view.h) as u32,
                    pos - l,
                )
            })
            .into_iter()
            .collect();
        emitter.deliver(k as u64, &frame.px, &moves)?;
        last = Some(pos);
    }
    emitter.finish(scene::us(spec.seconds))
}

fn describe(c: Content) -> &'static str {
    match c {
        Content::Code => "Rust source in a dark code editor",
        Content::Article => "a long Russian technical article in a light browser page",
    }
}

/// Redraw the scrollbar track and its thumb for offset `pos`.
fn draw_thumb(
    frame: &mut Image,
    track: Rect,
    bg: [u8; 4],
    pos: i64,
    doc_h: i64,
    view_h: i64,
    content: Content,
) {
    frame.fill(track.x, track.y, track.w, track.h, bg);
    let thumb_h = (track.h * view_h / doc_h.max(1)).max(40);
    let max_scroll = (doc_h - view_h).max(1);
    let y = track.y + (track.h - thumb_h) * pos / max_scroll;
    match content {
        Content::Code => {
            frame.fill(track.x, track.y, 2, track.h, rgb(0x2b2b2b));
            frame.blend(track.x + 2, y, track.w - 2, thumb_h, rgb(0x797979), 102);
        }
        Content::Article => {
            frame.fill(track.x, track.y, 2, track.h, rgb(0xe8e8e8));
            frame.fill(track.x + 8, y + 4, track.w - 14, thumb_h - 8, rgb(0xc2c2c2));
        }
    }
}
