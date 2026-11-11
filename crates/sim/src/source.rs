//! What is on the screen: a stream of timestamped frames at the screen's native size.
//!
//! ## The trait, and where the corpus plugs in
//!
//! A [`FrameSource`] is nothing more than an iterator of `(time since start, frame)`, the frame in
//! BGRA at the source's native resolution and the time in virtual time. The simulator does what the
//! capture thread does with it (`crate::encode_loop::Capturer`): pace it to the rung's frame rate,
//! scale it to the rung's height, and hand it to the encode loop.
//!
//! It is modelled on Windows.Graphics.Capture, which delivers a frame only when the screen changed:
//! a source yields nothing for a still desktop, and a quiet stretch costs the simulation nothing.
//!
//! The corpus reader being built in `agent/crates/corpus` (recorded or synthesised screen frames)
//! is expected to be exactly such an iterator; once it exists, wrapping it is a one-line
//! `Box::new(reader)` passed to `crate::sim::Simulation::with_source`. Nothing here depends on it.
//!
//! ## The synthetic desktop
//!
//! [`DesktopSource`] draws something shaped like a remote desktop — a sidebar, a title bar, a page
//! of text-like glyphs, an editor line at the bottom — and changes it according to a script of
//! phases: nothing, typing, scrolling, page jumps, and a region of noise standing in for video.
//! The page is rendered once; a frame is the page's visible window copied at the scroll offset, so
//! a 1080p frame costs a few row copies rather than a redraw.

use std::time::Duration;

use afklink_core::types::Frame;
use serde::Deserialize;

use crate::rng::SimRng;

/// One captured frame: when it appeared (virtual time since the start of the pipeline), and the
/// pixels at the source's native size. `Frame::timestamp_ms` is ignored by the simulator, which
/// stamps frames the way the capture thread does.
pub type TimedFrame = (Duration, Frame);

/// Anything that yields timestamped frames in order. See the module documentation.
pub trait FrameSource: Iterator<Item = TimedFrame> {}
impl<T: Iterator<Item = TimedFrame> + ?Sized> FrameSource for T {}

/// One scripted stretch of screen activity.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Phase {
    /// Nothing changes: no frames at all.
    Idle { secs: f64 },
    /// Characters appear on the editor line, `cps` a second, with a blinking caret. The quiet
    /// stretch of a text session: small inter frames, a few hundred kbps.
    Typing { secs: f64, cps: f64 },
    /// The page scrolls continuously by `px_per_frame` on every display refresh. A few pixels is a
    /// smooth scroll OpenH264 tracks with motion vectors; a hundred or more is the sharp scroll its
    /// search window cannot follow, coded as intra — the 60-120 kB frames of a burst.
    Scroll { secs: f64, px_per_frame: u32 },
    /// The page jumps by `px` every `every_ms`: page-down, a new document, a slide change.
    Jump { secs: f64, px: u32, every_ms: f64 },
    /// A rectangle covering `fraction` of the screen is repainted with noise `fps` times a second:
    /// a video pane at its most expensive.
    Noise { secs: f64, fraction: f64, fps: f64 },
}

impl Phase {
    fn secs(&self) -> f64 {
        match self {
            Phase::Idle { secs }
            | Phase::Typing { secs, .. }
            | Phase::Scroll { secs, .. }
            | Phase::Jump { secs, .. }
            | Phase::Noise { secs, .. } => *secs,
        }
    }
}

/// How a scenario describes its content.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentSpec {
    /// One frame at time zero and nothing after: a still desktop.
    Static {
        #[serde(default = "default_width")]
        width: u32,
        #[serde(default = "default_height")]
        height: u32,
    },
    /// The scripted desktop. See [`DesktopSource`].
    Desktop {
        /// The screen's native size. 1620x1080 prices every rung exactly as a 3600x2400
        /// panel does (the ladder fits height and keeps the aspect ratio) while costing a ninth of
        /// the pixels to draw and scale.
        #[serde(default = "default_width")]
        width: u32,
        #[serde(default = "default_height")]
        height: u32,
        #[serde(default = "default_refresh")]
        refresh_hz: f64,
        /// Start the script over when it runs out, until the scenario's duration.
        #[serde(default = "default_true")]
        repeat: bool,
        phases: Vec<Phase>,
    },
    /// Frames from the corpus crate. Not wired yet: see the module documentation.
    Corpus { path: String },
}

fn default_width() -> u32 {
    1620
}
fn default_height() -> u32 {
    1080
}
fn default_refresh() -> f64 {
    60.0
}
fn default_true() -> bool {
    true
}

impl ContentSpec {
    /// Build the source this spec describes. `seed` makes the page and the noise reproducible.
    pub fn build(&self, seed: u64) -> anyhow::Result<Box<dyn FrameSource>> {
        match self {
            ContentSpec::Static { width, height } => Ok(Box::new(DesktopSource::new(
                *width,
                *height,
                60.0,
                vec![Phase::Idle { secs: 1.0 }],
                false,
                seed,
            )?)),
            ContentSpec::Desktop {
                width,
                height,
                refresh_hz,
                repeat,
                phases,
            } => Ok(Box::new(DesktopSource::new(
                *width,
                *height,
                *refresh_hz,
                phases.clone(),
                *repeat,
                seed,
            )?)),
            ContentSpec::Corpus { path } => anyhow::bail!(
                "content kind \"corpus\" ({path}) is not wired yet: the corpus reader \
                 (agent/crates/corpus) is being built separately. Any Iterator<Item = (Duration, \
                 Frame)> can be run today through Simulation::with_source."
            ),
        }
    }
}

/// Glyph cell geometry on the page: small type, as a 200%-scaled 3600x2400 panel's text is once
/// the capture has fitted it into 1080 lines.
const GLYPH_W: usize = 5;
const GLYPH_H: usize = 9;
const ADVANCE: usize = 7;
const LINE_PITCH: usize = 16;
const SIDEBAR_W: usize = 140;
const TITLE_H: usize = 40;
const EDITOR_H: usize = 60;
const PAGE_BG: u8 = 0xf4;
const INK: u8 = 0x2a;
/// How far the page extends below the viewport, in screens; scrolling wraps around it.
const PAGE_SCREENS: usize = 4;
/// Caret blink half-period, as Windows' default.
const CARET_MS: f64 = 530.0;

/// The scripted synthetic desktop. See the module documentation.
pub struct DesktopSource {
    w: usize,
    h: usize,
    refresh: f64,
    phases: Vec<Phase>,
    repeat: bool,
    /// The page, BGRA, `page_w` x `page_h`, rendered once.
    page: Vec<u8>,
    page_w: usize,
    page_h: usize,
    glyphs: Vec<[u8; GLYPH_H]>,
    current: Vec<u8>,
    rng: SimRng,
    tick: u64,
    phase_idx: usize,
    phase_start: u64,
    phase_ticks: u64,
    events_applied: u64,
    caret_on: bool,
    scroll: usize,
    typed: usize,
    first: bool,
    /// Something changed outside a phase's own schedule (a noise pane closing) and has not been
    /// delivered yet.
    dirty: bool,
    ended: bool,
}

impl std::fmt::Debug for DesktopSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesktopSource")
            .field("w", &self.w)
            .field("h", &self.h)
            .field("refresh", &self.refresh)
            .field("phases", &self.phases.len())
            .field("tick", &self.tick)
            .finish()
    }
}

impl DesktopSource {
    pub fn new(
        width: u32,
        height: u32,
        refresh_hz: f64,
        phases: Vec<Phase>,
        repeat: bool,
        seed: u64,
    ) -> anyhow::Result<Self> {
        let (w, h) = (width as usize & !1, height as usize & !1);
        anyhow::ensure!(
            w >= SIDEBAR_W + 64 && h >= TITLE_H + EDITOR_H + 64,
            "desktop content needs at least {}x{} pixels, got {width}x{height}",
            SIDEBAR_W + 64,
            TITLE_H + EDITOR_H + 64
        );
        anyhow::ensure!(
            refresh_hz.is_finite() && refresh_hz >= 1.0,
            "refresh_hz must be at least 1, got {refresh_hz}"
        );
        anyhow::ensure!(
            !phases.is_empty(),
            "desktop content needs at least one phase"
        );
        for p in &phases {
            anyhow::ensure!(
                p.secs().is_finite() && p.secs() > 0.0,
                "every phase needs a positive duration: {p:?}"
            );
        }
        let mut rng = SimRng::new(seed);
        let glyphs = make_glyphs(&mut rng);
        let page_w = w - SIDEBAR_W;
        let page_h = (h - TITLE_H - EDITOR_H) * PAGE_SCREENS;
        let page = render_page(page_w, page_h, &glyphs, &mut rng);
        let mut me = Self {
            w,
            h,
            refresh: refresh_hz,
            phases,
            repeat,
            page,
            page_w,
            page_h,
            glyphs,
            current: vec![0u8; w * h * 4],
            rng,
            tick: 0,
            phase_idx: 0,
            phase_start: 0,
            phase_ticks: 0,
            events_applied: 0,
            caret_on: false,
            scroll: 0,
            typed: 0,
            first: true,
            dirty: false,
            ended: false,
        };
        me.phase_ticks = me.ticks_of(0);
        me.draw_chrome();
        me.draw_viewport();
        tracing::debug!(
            width = w,
            height = h,
            refresh_hz,
            phases = me.phases.len(),
            repeat,
            "synthetic desktop ready"
        );
        Ok(me)
    }

    fn ticks_of(&self, idx: usize) -> u64 {
        ((self.phases[idx].secs() * self.refresh).round() as u64).max(1)
    }

    fn time_of(&self, tick: u64) -> Duration {
        Duration::from_secs_f64(tick as f64 / self.refresh)
    }

    fn fill_rect(&mut self, x0: usize, y0: usize, x1: usize, y1: usize, v: u8) {
        let (x1, y1) = (x1.min(self.w), y1.min(self.h));
        for y in y0..y1 {
            let row = &mut self.current[(y * self.w + x0) * 4..(y * self.w + x1) * 4];
            for px in row.as_chunks_mut::<4>().0 {
                *px = [v, v, v, 255];
            }
        }
    }

    fn draw_chrome(&mut self) {
        let (w, h) = (self.w, self.h);
        self.fill_rect(0, 0, SIDEBAR_W, h, 0x2b);
        // Sidebar entries: short light bars, like a file tree.
        for i in 0..(h / 28) {
            let len = 40 + (i * 37 % 70);
            self.fill_rect(14, 50 + i * 28, 14 + len, 50 + i * 28 + 8, 0x9a);
        }
        self.fill_rect(SIDEBAR_W, 0, w, TITLE_H, 0xd8);
        self.fill_rect(SIDEBAR_W + 12, 14, SIDEBAR_W + 260, 26, 0x55);
        self.fill_rect(SIDEBAR_W, h - EDITOR_H, w, h, 0xfb);
        self.fill_rect(SIDEBAR_W, h - EDITOR_H, w, h - EDITOR_H + 1, 0xb0);
    }

    fn draw_viewport(&mut self) {
        let vh = self.h - TITLE_H - EDITOR_H;
        let row_bytes = self.page_w * 4;
        for y in 0..vh {
            let src_y = (self.scroll + y) % self.page_h;
            let src = &self.page[src_y * row_bytes..(src_y + 1) * row_bytes];
            let dst_off = ((TITLE_H + y) * self.w + SIDEBAR_W) * 4;
            self.current[dst_off..dst_off + row_bytes].copy_from_slice(src);
        }
    }

    fn draw_glyph(&mut self, x: usize, y: usize, g: usize, ink: u8) {
        let bits = self.glyphs[g % self.glyphs.len()];
        for (dy, row) in bits.iter().enumerate() {
            for dx in 0..GLYPH_W {
                if row & (1 << dx) != 0 {
                    let o = ((y + dy) * self.w + x + dx) * 4;
                    self.current[o..o + 4].copy_from_slice(&[ink, ink, ink, 255]);
                }
            }
        }
    }

    fn editor_line_y(&self) -> usize {
        self.h - EDITOR_H + (EDITOR_H - GLYPH_H) / 2
    }

    fn type_char(&mut self) {
        let per_line = (self.w - SIDEBAR_W - 40) / ADVANCE;
        if self.typed >= per_line {
            self.fill_rect(SIDEBAR_W, self.h - EDITOR_H + 2, self.w, self.h, 0xfb);
            self.typed = 0;
        }
        let x = SIDEBAR_W + 16 + self.typed * ADVANCE;
        let y = self.editor_line_y();
        // One in six is a space, as in prose.
        if self.rng.below(6) != 0 {
            let g = self.rng.below(self.glyphs.len() as u64) as usize;
            self.draw_glyph(x, y, g, INK);
        }
        self.typed += 1;
    }

    fn set_caret(&mut self, on: bool) {
        let x = SIDEBAR_W + 16 + self.typed * ADVANCE;
        let y = self.editor_line_y();
        let v = if on { INK } else { 0xfb };
        self.fill_rect(x, y - 2, x + 2, y + GLYPH_H + 2, v);
        self.caret_on = on;
    }

    fn paint_noise(&mut self, fraction: f64) {
        let fraction = fraction.clamp(0.01, 1.0);
        let rw = (((self.w as f64) * fraction.sqrt()) as usize & !1).min(self.w);
        let rh = (((self.h as f64) * fraction.sqrt()) as usize & !1).min(self.h);
        // Towards the right of the page, as a video pane would sit, and always on screen.
        let x0 = self
            .w
            .saturating_sub(rw + 40)
            .max(SIDEBAR_W)
            .min(self.w - rw);
        let y0 = TITLE_H.min(self.h - rh);
        for y in y0..(y0 + rh).min(self.h) {
            let mut x = x0;
            while x < (x0 + rw).min(self.w) {
                let r = self.rng.next_u64();
                for k in 0..4 {
                    if x + k >= (x0 + rw).min(self.w) {
                        break;
                    }
                    let v = (r >> (k * 16)) as u8;
                    let o = (y * self.w + x + k) * 4;
                    self.current[o..o + 4].copy_from_slice(&[v, v ^ 0x35, v.wrapping_add(90), 255]);
                }
                x += 4;
            }
        }
    }

    /// Step one display refresh: apply whatever the current phase changes at this tick, and say
    /// whether anything on screen changed.
    fn step(&mut self, t_in: u64) -> bool {
        let t_in_secs = t_in as f64 / self.refresh;
        let phase = self.phases[self.phase_idx].clone();
        match phase {
            Phase::Idle { .. } => false,
            Phase::Typing { cps, .. } => {
                let mut changed = false;
                let due = (t_in_secs * cps.max(0.0)).floor() as u64;
                while self.events_applied < due {
                    self.events_applied += 1;
                    if self.caret_on {
                        self.set_caret(false);
                    }
                    self.type_char();
                    changed = true;
                }
                let blink_on = ((t_in_secs * 1000.0 / CARET_MS).floor() as u64).is_multiple_of(2);
                if blink_on != self.caret_on {
                    self.set_caret(blink_on);
                    changed = true;
                }
                changed
            }
            Phase::Scroll { px_per_frame, .. } => {
                if px_per_frame == 0 {
                    return false;
                }
                self.scroll = (self.scroll + px_per_frame as usize) % self.page_h;
                self.draw_viewport();
                true
            }
            Phase::Jump { px, every_ms, .. } => {
                let due = (t_in_secs * 1000.0 / every_ms.max(1.0)).floor() as u64;
                if self.events_applied < due {
                    self.events_applied = due;
                    self.scroll = (self.scroll + px as usize) % self.page_h;
                    self.draw_viewport();
                    true
                } else {
                    false
                }
            }
            Phase::Noise { fraction, fps, .. } => {
                let due = (t_in_secs * fps.max(0.0)).floor() as u64;
                if self.events_applied < due {
                    self.events_applied = due;
                    self.paint_noise(fraction);
                    true
                } else {
                    false
                }
            }
        }
    }

    fn advance_phase(&mut self) -> bool {
        let mut idx = self.phase_idx + 1;
        if idx >= self.phases.len() {
            if !self.repeat {
                return false;
            }
            idx = 0;
        }
        // Leaving a noise pane: the page comes back, which is itself a change, delivered on the
        // first tick of the next phase even if that phase is idle.
        if matches!(self.phases[self.phase_idx], Phase::Noise { .. }) {
            self.draw_viewport();
            self.dirty = true;
        }
        self.phase_start += self.phase_ticks;
        self.phase_idx = idx;
        self.phase_ticks = self.ticks_of(idx);
        self.events_applied = 0;
        tracing::trace!(
            phase = idx,
            at_s = self.time_of(self.phase_start).as_secs_f64(),
            kind = ?self.phases[idx],
            "content phase"
        );
        true
    }
}

impl Iterator for DesktopSource {
    type Item = TimedFrame;

    fn next(&mut self) -> Option<TimedFrame> {
        loop {
            if self.ended {
                return None;
            }
            while self.tick >= self.phase_start + self.phase_ticks {
                if !self.advance_phase() {
                    self.ended = true;
                    return None;
                }
            }
            // A still stretch is skipped whole rather than tick by tick.
            if !self.first
                && !self.dirty
                && matches!(self.phases[self.phase_idx], Phase::Idle { .. })
            {
                self.tick = self.phase_start + self.phase_ticks;
                continue;
            }
            let t_in = self.tick - self.phase_start;
            let changed = self.step(t_in) || self.first || self.dirty;
            self.dirty = false;
            let at = self.time_of(self.tick);
            self.tick += 1;
            if changed {
                self.first = false;
                return Some((
                    at,
                    Frame {
                        data: self.current.clone(),
                        width: self.w as u32,
                        height: self.h as u32,
                        timestamp_ms: at.as_millis() as u64,
                    },
                ));
            }
        }
    }
}

/// Ninety-six random glyphs, 5x9, each one or two strokes — a stem, a bowl, a bar — so a line of
/// them has the ink density and edge count of type rather than of noise.
fn make_glyphs(rng: &mut SimRng) -> Vec<[u8; GLYPH_H]> {
    (0..96)
        .map(|_| {
            let mut g = [0u8; GLYPH_H];
            // x-height (rows 3..8) or an ascender (rows 0..8); row 8 is the baseline.
            let top = if rng.below(3) == 0 { 0 } else { 3 };
            let strokes = 1 + rng.below(2);
            for _ in 0..strokes {
                match rng.below(3) {
                    0 => {
                        let x = rng.below(GLYPH_W as u64) as u8;
                        for row in g.iter_mut().take(GLYPH_H - 1).skip(top) {
                            *row |= 1 << x;
                        }
                    }
                    1 => {
                        // A bowl: the outline of the x-height box.
                        for (i, row) in g.iter_mut().enumerate().take(GLYPH_H - 1).skip(3) {
                            *row |= if i == 3 || i == GLYPH_H - 2 {
                                0b01110
                            } else {
                                0b10001
                            };
                        }
                    }
                    _ => {
                        let y = top + rng.below((GLYPH_H - 1 - top) as u64) as usize;
                        g[y] |= 0b01111;
                    }
                }
            }
            g
        })
        .collect()
}

/// The page: paragraphs of glyph words on a light background, the odd heading and code block, with
/// generous whitespace, then softened by a small blur standing in for the anti-aliasing and the
/// downscale a real panel's text has been through.
///
/// Calibrated with `examples/content_probe.rs` against the `wifi-0924` recording: a 1620x1080
/// keyframe of this page is in the range of the recording's 45 kB `idr_bytes`, and a slow scroll
/// costs a few hundred kbps at the quantiser floor, as the recording's quiet seconds do.
fn render_page(w: usize, h: usize, glyphs: &[[u8; GLYPH_H]], rng: &mut SimRng) -> Vec<u8> {
    let mut luma = vec![PAGE_BG; w * h];
    let put = |luma: &mut Vec<u8>, x: usize, y: usize, g: usize, ink: u8| {
        let bits = glyphs[g % glyphs.len()];
        for (dy, row) in bits.iter().enumerate() {
            for dx in 0..GLYPH_W {
                if row & (1 << dx) != 0 && x + dx < w && y + dy < h {
                    luma[(y + dy) * w + x + dx] = ink;
                }
            }
        }
    };
    let margin = 32;
    let text_w = w.saturating_sub(2 * margin).min(900);
    let mut y = 12;
    while y + LINE_PITCH < h {
        let kind = rng.below(10);
        if kind < 2 {
            // Paragraph breaks.
            y += LINE_PITCH;
            continue;
        }
        let code = kind == 2;
        if code {
            for yy in y.saturating_sub(3)..(y + LINE_PITCH - 3).min(h) {
                for xx in margin..(margin + text_w).min(w) {
                    luma[yy * w + xx] = 0xea;
                }
            }
        }
        // Ragged right: a line fills between a third and all of the text column.
        let len = text_w / 3 + rng.below((text_w * 2 / 3) as u64) as usize;
        let start = margin + if code { 28 } else { 0 };
        let end = (start + len).min(w.saturating_sub(GLYPH_W + 1));
        let ink = if kind == 3 { 0x10 } else { INK };
        let mut x = start;
        while x < end {
            let word = 2 + rng.below(7) as usize;
            for _ in 0..word {
                if x >= end {
                    break;
                }
                let g = rng.below(glyphs.len() as u64) as usize;
                put(&mut luma, x, y, g, ink);
                x += ADVANCE;
            }
            x += ADVANCE;
        }
        y += LINE_PITCH;
    }
    blur121(&mut luma, w, h);
    let mut page = vec![0u8; w * h * 4];
    for (px, v) in page.as_chunks_mut::<4>().0.iter_mut().zip(&luma) {
        *px = [*v, *v, *v, 255];
    }
    page
}

/// A separable [1 2 1]/4 blur, in place.
fn blur121(luma: &mut [u8], w: usize, h: usize) {
    let mut tmp = luma.to_vec();
    for y in 0..h {
        for x in 1..w.saturating_sub(1) {
            let o = y * w + x;
            tmp[o] = ((u16::from(luma[o - 1])
                + 2 * u16::from(luma[o])
                + u16::from(luma[o + 1])
                + 2)
                / 4) as u8;
        }
    }
    for y in 1..h.saturating_sub(1) {
        for x in 0..w {
            let o = y * w + x;
            luma[o] = ((u16::from(tmp[o - w]) + 2 * u16::from(tmp[o]) + u16::from(tmp[o + w]) + 2)
                / 4) as u8;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{ContentSpec, DesktopSource, Phase};
    use std::time::Duration;

    fn frames(src: &mut DesktopSource, until: Duration) -> Vec<Duration> {
        let mut out = Vec::new();
        for (t, f) in src.by_ref() {
            if t >= until {
                break;
            }
            assert_eq!(f.data.len(), (f.width * f.height * 4) as usize);
            out.push(t);
        }
        out
    }

    #[test]
    fn a_still_screen_yields_one_frame() {
        let mut s =
            DesktopSource::new(640, 480, 60.0, vec![Phase::Idle { secs: 5.0 }], false, 1).unwrap();
        assert_eq!(
            frames(&mut s, Duration::from_secs(10)),
            vec![Duration::ZERO]
        );
    }

    #[test]
    fn scrolling_yields_a_frame_per_refresh_and_typing_far_fewer() {
        let mut s = DesktopSource::new(
            640,
            480,
            60.0,
            vec![
                Phase::Scroll {
                    secs: 1.0,
                    px_per_frame: 8,
                },
                Phase::Typing {
                    secs: 2.0,
                    cps: 5.0,
                },
            ],
            false,
            1,
        )
        .unwrap();
        let got = frames(&mut s, Duration::from_secs(4));
        let scroll = got.iter().filter(|t| **t < Duration::from_secs(1)).count();
        let typing = got.len() - scroll;
        assert_eq!(scroll, 60);
        // Ten characters and the caret's blinks over two seconds.
        assert!((10..=16).contains(&typing), "{typing}");
    }

    #[test]
    fn the_script_repeats_and_the_content_is_a_function_of_the_seed() {
        let spec = ContentSpec::Desktop {
            width: 640,
            height: 480,
            refresh_hz: 60.0,
            repeat: true,
            phases: vec![
                Phase::Idle { secs: 0.5 },
                Phase::Noise {
                    secs: 0.5,
                    fraction: 0.2,
                    fps: 10.0,
                },
            ],
        };
        let a: Vec<_> = spec.build(3).unwrap().take(12).collect();
        let b: Vec<_> = spec.build(3).unwrap().take(12).collect();
        assert_eq!(a.len(), 12);
        for ((ta, fa), (tb, fb)) in a.iter().zip(&b) {
            assert_eq!(ta, tb);
            assert!(fa.data == fb.data);
        }
        // The first repeat's noise begins at 1.5 s.
        assert!(a.iter().any(|(t, _)| *t >= Duration::from_millis(1_500)));
    }

    #[test]
    fn the_corpus_is_refused_until_it_is_wired() {
        let spec = ContentSpec::Corpus {
            path: "x".to_string(),
        };
        assert!(spec.build(1).is_err());
    }
}
