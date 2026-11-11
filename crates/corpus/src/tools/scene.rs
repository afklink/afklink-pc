//! What every generator shares: where things are, the metadata skeleton, tall documents rendered
//! in tiles, and the rectangle arithmetic between CSS and physical pixels.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::edge::{Edge, DSF};
use super::html::{CssRect, TILE_H};
use super::image::Image;
use crate::format::{
    CodecInfo, Metadata, Origin, Scaling, SourceInfo, StoredInfo, TimingInfo, FORMAT_VERSION,
    PIXEL_FORMAT_BGRA8,
};

/// The panel this corpus models: a 3600x2400 display at 200%, 60 Hz.
pub const SOURCE_W: u32 = 3600;
pub const SOURCE_H: u32 = 2400;
pub const DISPLAY_HZ: f64 = 60.0;
/// The top rung's height; natural-content scenarios are stored at this size.
pub const TOP_RUNG_H: u32 = 1080;
/// Peak WGC delivery jitter applied to the vsync grid.
pub const JITTER_US: u32 = 700;

/// Where a generator reads from and writes to.
pub struct Ctx {
    /// The agent repository's root (for the source files rendered; the article is found by
    /// [`super::scroll::article_source`]).
    pub repo: PathBuf,
    /// Output directory for `.rcorp` files.
    pub out_dir: PathBuf,
    /// Scratch for pages and screenshots (`<out_dir>/.work`).
    pub work: PathBuf,
    edge: Option<Edge>,
}

impl Ctx {
    pub fn new(repo: PathBuf, out_dir: PathBuf) -> Result<Self> {
        let work = out_dir.join(".work");
        std::fs::create_dir_all(&work).with_context(|| format!("create {}", work.display()))?;
        Ok(Self {
            repo,
            out_dir,
            work,
            edge: None,
        })
    }

    /// Headless Edge, located on first use.
    pub fn edge(&mut self) -> Result<&Edge> {
        if self.edge.is_none() {
            self.edge = Some(Edge::locate(&self.work.join("edge"))?);
        }
        self.edge.as_ref().context("edge")
    }

    #[must_use]
    pub fn out_path(&self, scenario: &str) -> PathBuf {
        self.out_dir
            .join(format!("{scenario}.{}", crate::format::EXTENSION))
    }

    /// A file of the repository, read as UTF-8.
    pub fn repo_text(&self, rel: &str) -> Result<String> {
        let p = self.repo.join(rel);
        std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))
    }
}

/// A rectangle in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i64,
    pub y: i64,
    pub w: i64,
    pub h: i64,
}

impl Rect {
    #[must_use]
    pub fn from_css(r: CssRect) -> Self {
        let s = i64::from(DSF);
        Self {
            x: i64::from(r.x) * s,
            y: i64::from(r.y) * s,
            w: i64::from(r.w) * s,
            h: i64::from(r.h) * s,
        }
    }
}

/// Metadata with the fields every synthetic scenario shares filled in.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn synthetic_meta(
    scenario: &str,
    description: &str,
    generator: &str,
    seed: u64,
    params: serde_json::Value,
    inputs: Vec<String>,
    stored: (u32, u32),
    scaling: Scaling,
    jitter_us: u32,
    duplicates: bool,
    notes: Vec<String>,
) -> Metadata {
    Metadata {
        format_version: FORMAT_VERSION,
        scenario: scenario.to_string(),
        description: description.to_string(),
        created_utc: crate::format::now_rfc3339(),
        source: SourceInfo {
            width: SOURCE_W,
            height: SOURCE_H,
            display_hz: DISPLAY_HZ,
            scale_factor: f64::from(DSF),
        },
        stored: StoredInfo {
            width: stored.0,
            height: stored.1,
            pixel_format: PIXEL_FORMAT_BGRA8.into(),
            scaling,
        },
        origin: Origin::Synthetic {
            generator: generator.to_string(),
            seed,
            params,
            inputs,
        },
        timing: TimingInfo {
            clock: "vsync_model".into(),
            jitter_us,
            duplicates,
        },
        codec: CodecInfo {
            tile: 0,
            zstd_level: 0,
            key_interval_us: 0,
        },
        notes,
    }
}

/// Render a document taller than any window: `html(offset_css)` must shift the page up by
/// `offset_css` CSS pixels. Returns the stitched picture, `css_w * 2` by `css_h * 2`.
pub fn tall_document(
    edge: &Edge,
    name: &str,
    css_w: u32,
    css_h: u32,
    html: impl Fn(u32) -> String,
) -> Result<Image> {
    let tiles = css_h.div_ceil(TILE_H);
    let mut tall = Image::new(css_w * DSF, css_h * DSF, [0, 0, 0, 255]);
    for k in 0..tiles {
        let offset = k * TILE_H;
        let tile = edge.screenshot(
            &format!("{name}-tile{k:02}"),
            &html(offset),
            css_w,
            TILE_H,
            false,
        )?;
        tall.blit(
            &tile,
            0,
            0,
            i64::from(tile.w),
            i64::from(tile.h),
            0,
            i64::from(offset * DSF),
        );
    }
    tracing::debug!(
        name,
        tiles,
        w = tall.w,
        h = tall.h,
        "tall document stitched"
    );
    Ok(tall)
}

/// The Windows wallpapers shipped with the OS, for photos in pages and the desktop.
#[must_use]
pub fn wallpapers() -> Vec<PathBuf> {
    let root = Path::new(r"C:\Windows\Web\Wallpaper");
    let mut out = Vec::new();
    for sub in ["ThemeA", "ThemeB", "ThemeC", "ThemeD", "Windows"] {
        if let Ok(rd) = std::fs::read_dir(root.join(sub)) {
            let mut v: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("jpg")))
                .collect();
            v.sort();
            out.extend(v);
        }
    }
    if out.is_empty() {
        tracing::warn!("no Windows wallpapers found; pages will render without photos");
    }
    out
}

/// Seconds to microseconds.
#[must_use]
pub fn us(seconds: f64) -> u64 {
    (seconds * 1e6).round().max(0.0) as u64
}
