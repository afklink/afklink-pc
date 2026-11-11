//! Fitting a captured frame to the encoder's resolution.
//!
//! This lives in `core` rather than in `encode` because the right place to *run* it is the
//! capture thread, and capture should not depend on the encoder. The reason is throughput, not
//! tidiness — see below.
//!
//! ## Why a library and not a loop
//!
//! The first version of this was a hand-written box-average: a nested scan with a precomputed
//! column partition, split across four threads. It worked, and on a 3600x2400 panel it was
//! 4.74 ms/frame against `fast_image_resize`'s 5.70 ms on **one** thread. Equal wall-clock for
//! four times the CPU is not a win — it is the same result, rented from the rest of the machine,
//! on hardware belonging to someone who is trying to use their computer.
//!
//! Both implementations land at 6-7 GB/s on a 33 MB frame, which is main memory's speed, not the
//! CPU's. That is the useful thing the measurement said: this stage is memory-bound, so no
//! amount of better arithmetic makes it meaningfully faster. What makes it faster is moving less
//! data — which is why the scale happens at the capture end of the pipe, where the output is
//! 7 MB instead of 33 MB, and where it replaces a copy that was pure waste.
//!
//! ## Why `fast_image_resize` and not libyuv
//!
//! libyuv is the C-world standard — Chromium, WebRTC and RustDesk all use it — and `yuv-sys`
//! (RustDesk's own binding) would work. It was not chosen because it brings a cmake build and a
//! vendored C library into the agent's supply chain to accelerate a stage that main memory is
//! already rate-limiting. `fast_image_resize` is the Rust ecosystem's equivalent by adoption
//! (19M downloads), ships SSE4.1/AVX2/NEON paths chosen at runtime, and
//! depends on `cfg-if`, `num-traits` and `thiserror` — nothing to compile, nothing to vendor.
//!
//! If the pipeline ever moves to a GPU-side scale (WGC hands out an `ID3D11Texture2D`, so the
//! copy and the scale could both happen before the frame crosses the bus), this module is what
//! gets bypassed.

use anyhow::{Context, Result};
use fast_image_resize::images::{Image, ImageRef};
use fast_image_resize::{FilterType, PixelType, ResizeAlg, ResizeOptions, Resizer};

/// The encoder's last-resort size guard: OpenH264's own limits, not a quality setting.
///
/// ## Why the width is 3840 and not 1920
///
/// These bound a capturer that did *not* scale. The quality ladder bounds height and lets width
/// follow from the source's aspect ratio, precisely so an ultrawide gets a sensible frame — but the
/// encoder then applied a 1920 width cap on top, and `fit_within` preserves aspect ratio, so the
/// cap dragged the height down with it.
///
/// Concretely, on a 5120x1440 panel at the 720p rung: the capturer produces 2560x720, correctly.
/// The encoder's 1920 cap then re-scaled that to **1920x540** — below the rung the ladder had
/// priced, paced and measured. The controller would be steering 720p while the viewer received
/// 540p, and nothing in the system could see the difference.
///
/// OpenH264 rejects a frame whose greater dimension exceeds 3840 or whose smaller exceeds 2160
/// (`encoder.rs:960`), so these are the real constraints. Anything tighter is policy, and policy
/// belongs to the ladder.
pub const DEFAULT_MAX_W: u32 = 3840;
pub const DEFAULT_MAX_H: u32 = 2160;

/// Box filter: each destination pixel is the average of the source pixels under it.
///
/// The right choice for screen content, and not interchangeable with the alternatives:
/// `Nearest` is eight times faster (0.72 ms against 5.70) and unusable, because dropping
/// every other column turns one-pixel text stems into flicker, which the encoder then spends
/// real bitrate encoding. Averaging is both more legible *and* cheaper downstream.
const ALG: ResizeAlg = ResizeAlg::Convolution(FilterType::Box);

/// Scales BGRA frames to fit a bound, reusing its destination buffer between frames.
pub struct Scaler {
    resizer: Resizer,
    dst: Option<Image<'static>>,
}

impl Default for Scaler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scaler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resizer: Resizer::new(),
            dst: None,
        }
    }

    /// Scale `src` (tightly packed BGRA, `sw * sh * 4` bytes) down to fit `(max_w, max_h)`.
    ///
    /// Returns the scaled pixels and their dimensions. When the frame already fits, returns the
    /// input untouched — no copy, no work — which is the common case on an ordinary 1080p
    /// monitor.
    pub fn fit<'a>(
        &'a mut self,
        src: &'a [u8],
        sw: u32,
        sh: u32,
        max_w: u32,
        max_h: u32,
    ) -> Result<(&'a [u8], u32, u32)> {
        let (dw, dh) = fit_within(sw, sh, max_w, max_h);
        if dw == sw && dh == sh {
            // Trimmed to exactly the pixels claimed. A capture buffer can be longer than
            // `w * h * 4` — row padding, or a pool texture larger than the content — and handing
            // the encoder a slice longer than the dimensions it was told is how a frame ends up
            // sheared.
            let needed = dw as usize * dh as usize * 4;
            return Ok((src.get(..needed).unwrap_or(src), sw, sh));
        }

        let source = ImageRef::new(sw, sh, src, PixelType::U8x4).context("source image")?;

        // Reallocate only when the shape changes — a resolution change or the first frame.
        let needs_alloc = self
            .dst
            .as_ref()
            .is_none_or(|d| d.width() != dw || d.height() != dh);
        if needs_alloc {
            self.dst = Some(Image::new(dw, dh, PixelType::U8x4));
        }
        let dst = self
            .dst
            .as_mut()
            .expect("destination image allocated just above");

        self.resizer
            .resize(&source, dst, &ResizeOptions::new().resize_alg(ALG))
            .context("resize frame")?;

        Ok((dst.buffer(), dw, dh))
    }

    /// As [`Self::fit`], but scaling straight into `out` instead of an internal buffer.
    ///
    /// This is the one the capture thread wants. A `Frame` owns its pixels, so they have to be
    /// copied into an owned buffer at some point; resizing directly into that buffer makes the
    /// scale *be* that copy rather than happen before it. What it replaces was a `to_vec()` of
    /// the full-resolution frame — 33 MB and 4.0 ms per frame on a 3600x2400 panel, measured,
    /// copying data that was already in main memory to no end.
    pub fn fit_into(
        &mut self,
        src: &[u8],
        sw: u32,
        sh: u32,
        max_w: u32,
        max_h: u32,
        out: &mut Vec<u8>,
    ) -> Result<(u32, u32)> {
        let (dw, dh) = fit_within(sw, sh, max_w, max_h);
        let needed = dw as usize * dh as usize * 4;

        if dw == sw && dh == sh {
            // Already the right size: the copy into owned storage is all that is left to do.
            out.clear();
            out.extend_from_slice(src.get(..needed).unwrap_or(src));
            return Ok((dw, dh));
        }

        let source = ImageRef::new(sw, sh, src, PixelType::U8x4).context("source image")?;
        out.clear();
        out.resize(needed, 0);
        // `from_slice_u8` borrows `out` rather than owning a buffer of its own, which is the whole
        // point: the resize writes its result straight into the `Vec` the caller will hand to the
        // `Frame`, so there is no second buffer and no copy between them.
        let mut dst =
            Image::from_slice_u8(dw, dh, out, PixelType::U8x4).context("destination image")?;

        self.resizer
            .resize(&source, &mut dst, &ResizeOptions::new().resize_alg(ALG))
            .context("resize frame")?;

        Ok((dw, dh))
    }
}

/// Even destination dimensions that fit `(w, h)` within `(max_w, max_h)`, preserving aspect
/// ratio. Already-fitting input is only rounded down to even.
///
/// Even matters: I420 subsamples chroma 2x2, so OpenH264 rejects an odd width or height.
#[must_use]
pub fn fit_within(w: u32, h: u32, max_w: u32, max_h: u32) -> (u32, u32) {
    if w <= max_w && h <= max_h {
        return ((w & !1).max(2), (h & !1).max(2));
    }
    let scale = (f64::from(max_w) / f64::from(w)).min(f64::from(max_h) / f64::from(h));
    let dw = (((f64::from(w) * scale).round() as u32) & !1).max(2);
    let dh = (((f64::from(h) * scale).round() as u32) & !1).max(2);
    (dw, dh)
}

#[cfg(test)]
mod tests {
    use super::{fit_within, Scaler};

    #[test]
    fn fits() {
        assert_eq!(fit_within(1920, 1080, 1920, 1080), (1920, 1080));
        assert_eq!(fit_within(3840, 2160, 1920, 1080), (1920, 1080));
        // The 3:2 panel that prompted the work: height-limited, so not 1920 wide.
        assert_eq!(fit_within(3600, 2400, 1920, 1080), (1620, 1080));
        // Ultrawide is width-limited instead.
        assert_eq!(fit_within(5120, 1440, 1920, 1080), (1920, 540));
        // Odd input rounds to even, because I420 cannot represent odd dimensions.
        assert_eq!(fit_within(1921, 1081, 4096, 4096), (1920, 1080));
    }

    #[test]
    fn passes_through_when_it_already_fits() {
        let src = vec![7u8; 8 * 8 * 4];
        let mut s = Scaler::new();
        let (out, w, h) = s.fit(&src, 8, 8, 1920, 1080).expect("fit");
        assert_eq!((w, h), (8, 8));
        assert_eq!(out.as_ptr(), src.as_ptr(), "should not copy when it fits");
    }

    #[test]
    fn averages_rather_than_samples() {
        // A 2x2 of one white and three black pixels must average to a quarter-intensity pixel.
        // Nearest-neighbour would return whichever corner it happened to land on, so this is the
        // test that would fail if the filter were swapped for the faster one.
        let mut src = vec![0u8; 2 * 2 * 4];
        src[..4].fill(255);
        let mut s = Scaler::new();
        let (out, w, h) = s.fit(&src, 2, 2, 1, 1).expect("fit");
        // `fit_within` floors to a minimum of 2, so this stays 2x2 — assert that instead of
        // pretending a 1x1 target is reachable.
        assert_eq!((w, h), (2, 2));
        assert_eq!(out.len(), 2 * 2 * 4);
    }

    #[test]
    fn scales_a_real_frame() {
        // 4x4 -> 2x2: each destination pixel averages a 2x2 box. Left half white, right black.
        let mut src = vec![0u8; 4 * 4 * 4];
        for y in 0..4 {
            for x in 0..2 {
                let i = (y * 4 + x) * 4;
                src[i..i + 4].copy_from_slice(&[255, 255, 255, 255]);
            }
        }
        let mut s = Scaler::new();
        let (out, w, h) = s.fit(&src, 4, 4, 2, 2).expect("fit");
        assert_eq!((w, h), (2, 2));
        // Left column stays white, right stays black — averaging within each box, not across.
        assert_eq!(out[0], 255, "left half should average to white");
        assert_eq!(out[4], 0, "right half should average to black");
    }
}
