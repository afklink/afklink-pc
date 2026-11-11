//! A BGRA picture and the handful of compositing operations the generators need.

use std::path::Path;

use anyhow::{bail, ensure, Context, Result};

/// BGRA8, tightly packed, top-down — the capturer's own layout.
#[derive(Clone)]
pub struct Image {
    pub w: u32,
    pub h: u32,
    pub px: Vec<u8>,
}

impl std::fmt::Debug for Image {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Image({}x{})", self.w, self.h)
    }
}

/// A colour as `[b, g, r, a]` from `0xRRGGBB`.
#[must_use]
pub const fn rgb(hex: u32) -> [u8; 4] {
    [
        (hex & 0xff) as u8,
        ((hex >> 8) & 0xff) as u8,
        ((hex >> 16) & 0xff) as u8,
        255,
    ]
}

impl Image {
    #[must_use]
    pub fn new(w: u32, h: u32, fill: [u8; 4]) -> Self {
        let mut px = vec![0u8; w as usize * h as usize * 4];
        for p in px.as_chunks_mut::<4>().0 {
            *p = fill;
        }
        Self { w, h, px }
    }

    #[must_use]
    pub fn stride(&self) -> usize {
        self.w as usize * 4
    }

    /// Decode an 8-bit RGB or RGBA PNG (what headless Edge writes).
    pub fn load_png(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut decoder = png::Decoder::new(std::io::BufReader::new(file));
        decoder.set_transformations(png::Transformations::EXPAND);
        let mut reader = decoder
            .read_info()
            .with_context(|| format!("read PNG header of {}", path.display()))?;
        let mut buf = vec![0u8; reader.output_buffer_size()];
        let info = reader
            .next_frame(&mut buf)
            .with_context(|| format!("decode {}", path.display()))?;
        ensure!(
            info.bit_depth == png::BitDepth::Eight,
            "{}: {:?} bit depth, expected 8",
            path.display(),
            info.bit_depth
        );
        let (w, h) = (info.width, info.height);
        let mut px = vec![0u8; w as usize * h as usize * 4];
        let dst = px.as_chunks_mut::<4>().0;
        match info.color_type {
            png::ColorType::Rgb => {
                for y in 0..h as usize {
                    let row = &buf[y * info.line_size..y * info.line_size + w as usize * 3];
                    for (x, s) in row.as_chunks::<3>().0.iter().enumerate() {
                        dst[y * w as usize + x] = [s[2], s[1], s[0], 255];
                    }
                }
            }
            png::ColorType::Rgba => {
                for y in 0..h as usize {
                    let row = &buf[y * info.line_size..y * info.line_size + w as usize * 4];
                    for (x, s) in row.as_chunks::<4>().0.iter().enumerate() {
                        dst[y * w as usize + x] = [s[2], s[1], s[0], s[3]];
                    }
                }
            }
            other => bail!("{}: unsupported PNG colour type {other:?}", path.display()),
        }
        Ok(Self { w, h, px })
    }

    /// Write as an RGB PNG (alpha dropped), for looking at a frame.
    pub fn save_png(&self, path: &Path) -> Result<()> {
        save_png_bgra(path, self.w, self.h, &self.px)
    }

    /// Copy the `w x h` block at `(sx, sy)` of `src` to `(dx, dy)`, clipped to both pictures.
    #[allow(clippy::too_many_arguments)]
    pub fn blit(&mut self, src: &Image, sx: i64, sy: i64, w: i64, h: i64, dx: i64, dy: i64) {
        let Some((sx, sy, dx, dy, w, h)) = clip(src, self, sx, sy, w, h, dx, dy) else {
            return;
        };
        let (ss, ds) = (src.stride(), self.stride());
        for row in 0..h {
            let s = (sy + row) * ss + sx * 4;
            let d = (dy + row) * ds + dx * 4;
            self.px[d..d + w * 4].copy_from_slice(&src.px[s..s + w * 4]);
        }
    }

    /// As [`Self::blit`], compositing `src` over this picture by its alpha.
    #[allow(clippy::too_many_arguments)]
    pub fn blit_over(&mut self, src: &Image, sx: i64, sy: i64, w: i64, h: i64, dx: i64, dy: i64) {
        let Some((sx, sy, dx, dy, w, h)) = clip(src, self, sx, sy, w, h, dx, dy) else {
            return;
        };
        let (ss, ds) = (src.stride(), self.stride());
        for row in 0..h {
            let s = (sy + row) * ss + sx * 4;
            let d = (dy + row) * ds + dx * 4;
            let srow = src.px[s..s + w * 4].as_chunks::<4>().0;
            let drow = self.px[d..d + w * 4].as_chunks_mut::<4>().0;
            for (dp, sp) in drow.iter_mut().zip(srow) {
                over(dp, *sp);
            }
        }
    }

    /// Fill a rectangle with an opaque colour (clipped).
    pub fn fill(&mut self, x: i64, y: i64, w: i64, h: i64, c: [u8; 4]) {
        let Some((x0, y0, x1, y1)) = self.clip_rect(x, y, w, h) else {
            return;
        };
        let stride = self.stride();
        for yy in y0..y1 {
            for p in self.px[yy * stride + x0 * 4..yy * stride + x1 * 4]
                .as_chunks_mut::<4>()
                .0
            {
                *p = c;
            }
        }
    }

    /// Blend a colour over a rectangle with opacity `alpha` (0..=255).
    pub fn blend(&mut self, x: i64, y: i64, w: i64, h: i64, c: [u8; 4], alpha: u8) {
        let Some((x0, y0, x1, y1)) = self.clip_rect(x, y, w, h) else {
            return;
        };
        let stride = self.stride();
        let src = [c[0], c[1], c[2], alpha];
        for yy in y0..y1 {
            for p in self.px[yy * stride + x0 * 4..yy * stride + x1 * 4]
                .as_chunks_mut::<4>()
                .0
            {
                over(p, src);
            }
        }
    }

    fn clip_rect(&self, x: i64, y: i64, w: i64, h: i64) -> Option<(usize, usize, usize, usize)> {
        let x0 = x.max(0);
        let y0 = y.max(0);
        let x1 = (x + w).min(i64::from(self.w));
        let y1 = (y + h).min(i64::from(self.h));
        (x1 > x0 && y1 > y0).then_some((x0 as usize, y0 as usize, x1 as usize, y1 as usize))
    }

    /// Fill a polygon (even-odd, pixel centres), for the mouse pointer.
    pub fn fill_polygon(&mut self, pts: &[(f64, f64)], c: [u8; 4]) {
        if pts.len() < 3 {
            return;
        }
        let ymin = pts
            .iter()
            .map(|p| p.1)
            .fold(f64::MAX, f64::min)
            .floor()
            .max(0.0) as i64;
        let ymax = pts
            .iter()
            .map(|p| p.1)
            .fold(f64::MIN, f64::max)
            .ceil()
            .min(f64::from(self.h)) as i64;
        let mut xs = Vec::new();
        for y in ymin..ymax {
            let yc = y as f64 + 0.5;
            xs.clear();
            for i in 0..pts.len() {
                let (a, b) = (pts[i], pts[(i + 1) % pts.len()]);
                if (a.1 <= yc && b.1 > yc) || (b.1 <= yc && a.1 > yc) {
                    xs.push(a.0 + (yc - a.1) / (b.1 - a.1) * (b.0 - a.0));
                }
            }
            xs.sort_by(f64::total_cmp);
            for [xa, xb] in xs.as_chunks::<2>().0 {
                let x0 = (xa - 0.5).ceil() as i64;
                let x1 = (xb - 0.5).floor() as i64 + 1;
                self.fill(x0, y, x1 - x0, 1, c);
            }
        }
    }

    /// The standard arrow pointer at 200%: black outline, white fill, tip at `(x, y)`.
    pub fn draw_pointer(&mut self, x: i64, y: i64) {
        let s = 2.0;
        let shape = |grow: f64| -> Vec<(f64, f64)> {
            [
                (0.0, 0.0),
                (0.0, 16.0),
                (4.0, 12.3),
                (6.8, 18.6),
                (9.2, 17.6),
                (6.5, 11.5),
                (11.5, 11.5),
            ]
            .iter()
            .map(|(px, py)| {
                (
                    x as f64 + (px - 3.0) * s * grow + 3.0 * s,
                    y as f64 + (py - 7.0) * s * grow + 7.0 * s,
                )
            })
            .collect()
        };
        self.fill_polygon(&shape(1.12), rgb(0x000000));
        self.fill_polygon(&shape(0.9), rgb(0xffffff));
    }

    /// Copy of a sub-rectangle.
    #[must_use]
    pub fn crop(&self, x: u32, y: u32, w: u32, h: u32) -> Image {
        let mut out = Image::new(w, h, [0, 0, 0, 255]);
        out.blit(
            self,
            i64::from(x),
            i64::from(y),
            i64::from(w),
            i64::from(h),
            0,
            0,
        );
        out
    }
}

/// Source-over for straight alpha, opaque destination.
#[inline]
fn over(d: &mut [u8; 4], s: [u8; 4]) {
    let a = u32::from(s[3]);
    if a == 255 {
        *d = [s[0], s[1], s[2], 255];
    } else if a > 0 {
        let ia = 255 - a;
        for c in 0..3 {
            d[c] = ((u32::from(s[c]) * a + u32::from(d[c]) * ia + 127) / 255) as u8;
        }
        d[3] = 255;
    }
}

#[allow(clippy::too_many_arguments)]
fn clip(
    src: &Image,
    dst: &Image,
    mut sx: i64,
    mut sy: i64,
    mut w: i64,
    mut h: i64,
    mut dx: i64,
    mut dy: i64,
) -> Option<(usize, usize, usize, usize, usize, usize)> {
    if sx < 0 {
        w += sx;
        dx -= sx;
        sx = 0;
    }
    if sy < 0 {
        h += sy;
        dy -= sy;
        sy = 0;
    }
    if dx < 0 {
        w += dx;
        sx -= dx;
        dx = 0;
    }
    if dy < 0 {
        h += dy;
        sy -= dy;
        dy = 0;
    }
    w = w.min(i64::from(src.w) - sx).min(i64::from(dst.w) - dx);
    h = h.min(i64::from(src.h) - sy).min(i64::from(dst.h) - dy);
    (w > 0 && h > 0).then_some((
        sx as usize,
        sy as usize,
        dx as usize,
        dy as usize,
        w as usize,
        h as usize,
    ))
}

/// Write BGRA pixels as an RGB PNG.
pub fn save_png_bgra(path: &Path, w: u32, h: u32, bgra: &[u8]) -> Result<()> {
    let file = std::fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    let mut writer = enc.write_header()?;
    let mut rgb = Vec::with_capacity(w as usize * h as usize * 3);
    for p in bgra.as_chunks::<4>().0 {
        rgb.extend_from_slice(&[p[2], p[1], p[0]]);
    }
    writer.write_image_data(&rgb)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blit_clips_on_every_side() {
        let src = Image::new(10, 10, rgb(0xff0000));
        let mut dst = Image::new(8, 8, rgb(0x000000));
        dst.blit(&src, 0, 0, 10, 10, -3, 5);
        // Columns 0..7 of rows 5..8 are red, rows above untouched.
        assert_eq!(dst.px[(5 * 8) * 4..(5 * 8) * 4 + 4], rgb(0xff0000));
        assert_eq!(dst.px[..4], rgb(0x000000));
        dst.blit(&src, 20, 20, 5, 5, 0, 0); // entirely outside the source: nothing
        assert_eq!(dst.px[..4], rgb(0x000000));
    }

    #[test]
    fn blending_is_exact_at_the_ends() {
        let mut img = Image::new(2, 1, rgb(0x102030));
        img.blend(0, 0, 1, 1, rgb(0xffffff), 255);
        img.blend(1, 0, 1, 1, rgb(0xffffff), 0);
        assert_eq!(img.px[..4], rgb(0xffffff));
        assert_eq!(img.px[4..], rgb(0x102030));
    }

    #[test]
    fn pointer_is_drawn_near_its_tip() {
        let mut img = Image::new(80, 80, rgb(0x808080));
        img.draw_pointer(20, 20);
        let white = img
            .px
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|p| **p == rgb(0xffffff))
            .count();
        assert!(white > 100, "{white} white pixels");
    }
}
