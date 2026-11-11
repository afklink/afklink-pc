//! Frame payloads: lossless, and shaped for screen content.
//!
//! Three kinds of frame, chosen per frame by the writer:
//!
//! * **KEY** — the whole picture, coded on its own. The four channels are decorrelated
//!   (`G, B-G, R-G, A`, the "subtract green" transform lossless WebP uses), split into planes,
//!   optionally run through the LOCO-I median predictor ([`Predictor::Med`]), and compressed with
//!   zstd. Natural pictures (video, games) shrink by about a third more with the predictor than
//!   without it; flat screen content barely cares.
//! * **INTER** — the previous picture, first rearranged by a list of rectangle [`Move`]s (a scroll
//!   is one move; a dragged window is another), then corrected by residuals in the 64x64 tiles that
//!   still differ. A scroll of a text page at full resolution costs the newly exposed strip and the
//!   scrollbar thumb, not the page; a keystroke costs one tile.
//! * **REPEAT** — a delivery that did not change the picture (a 30 fps video on a 60 Hz
//!   compositor). No payload.
//!
//! Everything is byte arithmetic modulo 256, so decoding reproduces the writer's input exactly:
//! encoding the frames a reader returns gives the same H.264 bits as encoding the originals would.
//!
//! Payload layout (both compressed kinds): `u32 raw_len` then the zstd frame of the raw bytes.
//!
//! ```text
//! KEY raw   := u8:predictor plane_G plane_(B-G) plane_(R-G) plane_A      (each w*h bytes)
//! INTER raw := u16:n_moves move*n u32:tile u32:n_dirty bitmap residual*
//! move      := u32:x0 u32:y0 u32:x1 u32:y1 i32:dx i32:dy
//! bitmap    := ceil(tiles_x*tiles_y / 8) bytes, tile t dirty = bit (t & 7) of byte t >> 3
//! residual  := for each dirty tile in raster order, 4 planes of tile_w*tile_h bytes of
//!              transformed (cur - prediction)
//! ```

use anyhow::{bail, ensure, Context, Result};

/// Intra predictor for KEY frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Predictor {
    /// Planes as they are.
    None = 0,
    /// LOCO-I / JPEG-LS median edge detector over left, up and up-left.
    Med = 1,
    /// [`Self::Med`], with each plane's residuals split into [`CTX_N`] streams by the local
    /// gradient (`|left - upleft| + |up - upleft|`), so zstd's per-block Huffman tables each see one
    /// tight distribution instead of a mixture of flat sky and foliage. zstd has no context
    /// modelling of its own; this is the cheap substitute.
    MedCtx = 2,
}

impl Predictor {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Med),
            2 => Ok(Self::MedCtx),
            other => bail!("unknown key-frame predictor {other}"),
        }
    }
}

/// Residual streams per plane for [`Predictor::MedCtx`]: eight gradient classes plus one for the
/// first row and column, which have no full neighbourhood.
pub const CTX_N: usize = 9;

#[inline]
fn gradient_ctx(a: u8, b: u8, c: u8) -> usize {
    let g = u16::from(a.abs_diff(c)) + u16::from(b.abs_diff(c));
    match g {
        0 => 0,
        1..=2 => 1,
        3..=5 => 2,
        6..=10 => 3,
        11..=20 => 4,
        21..=40 => 5,
        41..=80 => 6,
        _ => 7,
    }
}

/// Split `p`'s median residuals into per-context streams (appended to `streams`).
fn med_ctx_forward(p: &[u8], w: usize, h: usize, streams: &mut [Vec<u8>; CTX_N]) {
    for s in streams.iter_mut() {
        s.clear();
    }
    if w == 0 || h == 0 {
        return;
    }
    let edge = CTX_N - 1;
    streams[edge].push(p[0]);
    for x in 1..w {
        streams[edge].push(p[x].wrapping_sub(p[x - 1]));
    }
    for y in 1..h {
        let up = &p[(y - 1) * w..y * w];
        let row = &p[y * w..(y + 1) * w];
        streams[edge].push(row[0].wrapping_sub(up[0]));
        for x in 1..w {
            let (a, b, c) = (row[x - 1], up[x], up[x - 1]);
            streams[gradient_ctx(a, b, c)].push(row[x].wrapping_sub(med(a, b, c)));
        }
    }
}

/// Undo [`med_ctx_forward`] into `p` (`w * h` bytes), reading the streams in order.
fn med_ctx_inverse(p: &mut [u8], w: usize, h: usize, streams: &[&[u8]; CTX_N]) -> Result<()> {
    if w == 0 || h == 0 {
        return Ok(());
    }
    let mut at = [0usize; CTX_N];
    let mut take = |ctx: usize| -> Result<u8> {
        let v = *streams[ctx]
            .get(at[ctx])
            .with_context(|| format!("residual stream {ctx} ran out"))?;
        at[ctx] += 1;
        Ok(v)
    };
    let edge = CTX_N - 1;
    p[0] = take(edge)?;
    for x in 1..w {
        p[x] = take(edge)?.wrapping_add(p[x - 1]);
    }
    for y in 1..h {
        let (above, here) = p.split_at_mut(y * w);
        let up = &above[(y - 1) * w..];
        let row = &mut here[..w];
        row[0] = take(edge)?.wrapping_add(up[0]);
        for x in 1..w {
            let (a, b, c) = (row[x - 1], up[x], up[x - 1]);
            row[x] = take(gradient_ctx(a, b, c))?.wrapping_add(med(a, b, c));
        }
    }
    for (ctx, s) in streams.iter().enumerate() {
        ensure!(
            at[ctx] == s.len(),
            "residual stream {ctx} has {} unused bytes",
            s.len() - at[ctx]
        );
    }
    Ok(())
}

/// A rectangle of the new picture that is a copy of another place in the previous one.
///
/// For every `(x, y)` with `x0 <= x < x1` and `y0 <= y < y1`, the prediction is the previous
/// picture's pixel at `(x + dx, y + dy)`. Scrolling a page *down* by `d` pixels moves its content
/// up, so it is `dy = +d` over the rows whose source is still inside the viewport. All moves of one
/// frame read the previous picture as it was before any of them was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Move {
    pub x0: u32,
    pub y0: u32,
    pub x1: u32,
    pub y1: u32,
    pub dx: i32,
    pub dy: i32,
}

impl Move {
    /// Bytes one move occupies in an INTER payload.
    pub const WIRE_LEN: usize = 24;

    /// Vertical shift of a viewport `[x0, x1) x [y0, y1)` whose content moved up by `dy` pixels
    /// (`dy < 0`: down). Returns `None` when nothing of the old viewport is left on screen.
    #[must_use]
    pub fn vertical_scroll(x0: u32, y0: u32, x1: u32, y1: u32, dy: i64) -> Option<Self> {
        let height = i64::from(y1) - i64::from(y0);
        if dy == 0 || dy.abs() >= height || x1 <= x0 {
            return None;
        }
        let d = i32::try_from(dy).ok()?;
        let (dst_y0, dst_y1) = if dy > 0 {
            (i64::from(y0), i64::from(y1) - dy)
        } else {
            (i64::from(y0) - dy, i64::from(y1))
        };
        Some(Self {
            x0,
            y0: u32::try_from(dst_y0).ok()?,
            x1,
            y1: u32::try_from(dst_y1).ok()?,
            dx: 0,
            dy: d,
        })
    }

    fn validate(&self, w: u32, h: u32) -> Result<()> {
        ensure!(
            self.x0 < self.x1 && self.x1 <= w && self.y0 < self.y1 && self.y1 <= h,
            "move destination {self:?} outside a {w}x{h} frame"
        );
        let sx0 = i64::from(self.x0) + i64::from(self.dx);
        let sx1 = i64::from(self.x1) + i64::from(self.dx);
        let sy0 = i64::from(self.y0) + i64::from(self.dy);
        let sy1 = i64::from(self.y1) + i64::from(self.dy);
        ensure!(
            sx0 >= 0 && sx1 <= i64::from(w) && sy0 >= 0 && sy1 <= i64::from(h),
            "move source of {self:?} outside a {w}x{h} frame"
        );
        Ok(())
    }

    fn area(&self) -> usize {
        (self.x1 - self.x0) as usize * (self.y1 - self.y0) as usize
    }
}

/// Apply `moves` to `buf` (BGRA, `w x h`) in place, every move reading the picture as it was
/// before the first. `scratch` is reused between calls.
pub fn apply_moves(
    buf: &mut [u8],
    w: u32,
    h: u32,
    moves: &[Move],
    scratch: &mut Vec<u8>,
) -> Result<()> {
    let stride = w as usize * 4;
    ensure!(
        buf.len() == stride * h as usize,
        "frame buffer size mismatch"
    );
    for m in moves {
        m.validate(w, h)?;
    }
    match moves {
        [] => Ok(()),
        [m] => {
            // One move: a memmove per row, ordered so no source row is overwritten before it is
            // read. The common case (a scroll) and twice as fast as going through scratch.
            let row_bytes = (m.x1 - m.x0) as usize * 4;
            let rows: Box<dyn Iterator<Item = u32>> = if m.dy > 0 {
                Box::new(m.y0..m.y1)
            } else {
                Box::new((m.y0..m.y1).rev())
            };
            for y in rows {
                let sy = (i64::from(y) + i64::from(m.dy)) as usize;
                let sx = (i64::from(m.x0) + i64::from(m.dx)) as usize;
                let src = sy * stride + sx * 4;
                let dst = y as usize * stride + m.x0 as usize * 4;
                buf.copy_within(src..src + row_bytes, dst);
            }
            Ok(())
        }
        many => {
            // Several moves: gather every source first, then write every destination, so a move
            // whose source another move overwrites still reads the old picture.
            scratch.clear();
            scratch.reserve(many.iter().map(|m| m.area() * 4).sum());
            for m in many {
                let row_bytes = (m.x1 - m.x0) as usize * 4;
                let sx = (i64::from(m.x0) + i64::from(m.dx)) as usize;
                for y in m.y0..m.y1 {
                    let sy = (i64::from(y) + i64::from(m.dy)) as usize;
                    let src = sy * stride + sx * 4;
                    scratch.extend_from_slice(&buf[src..src + row_bytes]);
                }
            }
            let mut at = 0;
            for m in many {
                let row_bytes = (m.x1 - m.x0) as usize * 4;
                for y in m.y0..m.y1 {
                    let dst = y as usize * stride + m.x0 as usize * 4;
                    buf[dst..dst + row_bytes].copy_from_slice(&scratch[at..at + row_bytes]);
                    at += row_bytes;
                }
            }
            Ok(())
        }
    }
}

/// Encode a whole picture as a KEY raw payload (before zstd).
///
/// ```text
/// None, Med := u8:predictor plane*4                     (each w*h bytes)
/// MedCtx    := u8:2 (u32:len * CTX_N) * 4 stream*(4*CTX_N)  (plane-major, context-minor)
/// ```
pub fn encode_key_raw(frame: &[u8], w: u32, h: u32, predictor: Predictor, out: &mut Vec<u8>) {
    let n = w as usize * h as usize;
    let mut planes_buf = Vec::new();
    let planes: &mut [u8] = if predictor == Predictor::MedCtx {
        planes_buf.resize(4 * n, 0);
        &mut planes_buf
    } else {
        out.clear();
        out.resize(1 + 4 * n, 0);
        out[0] = predictor as u8;
        &mut out[1..]
    };
    let (p0, rest) = planes.split_at_mut(n);
    let (p1, rest) = rest.split_at_mut(n);
    let (p2, p3) = rest.split_at_mut(n);
    for (i, px) in frame.as_chunks::<4>().0.iter().take(n).enumerate() {
        let [b, g, r, a] = *px;
        p0[i] = g;
        p1[i] = b.wrapping_sub(g);
        p2[i] = r.wrapping_sub(g);
        p3[i] = a;
    }
    match predictor {
        Predictor::None => {}
        Predictor::Med => {
            for p in [p0, p1, p2, p3] {
                med_forward(p, w as usize, h as usize);
            }
        }
        Predictor::MedCtx => {
            let mut all: Vec<[Vec<u8>; CTX_N]> = Vec::with_capacity(4);
            for p in [&*p0, &*p1, &*p2, &*p3] {
                let mut streams: [Vec<u8>; CTX_N] = Default::default();
                med_ctx_forward(p, w as usize, h as usize, &mut streams);
                all.push(streams);
            }
            out.clear();
            out.reserve(1 + 4 * CTX_N * 4 + 4 * n);
            out.push(predictor as u8);
            for streams in &all {
                for s in streams {
                    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
                }
            }
            for streams in &all {
                for s in streams {
                    out.extend_from_slice(s);
                }
            }
        }
    }
}

/// Decode a KEY raw payload into `out` (BGRA). `scratch` holds the planes while the predictor is
/// undone.
pub fn decode_key_raw(
    raw: &[u8],
    w: u32,
    h: u32,
    out: &mut [u8],
    scratch: &mut Vec<u8>,
) -> Result<()> {
    let n = w as usize * h as usize;
    ensure!(!raw.is_empty(), "empty key payload");
    ensure!(out.len() == 4 * n, "output buffer size mismatch");
    let predictor = Predictor::from_u8(raw[0])?;
    let header = 1 + 4 * CTX_N * 4;
    ensure!(
        if predictor == Predictor::MedCtx {
            raw.len() == header + 4 * n
        } else {
            raw.len() == 1 + 4 * n
        },
        "key payload is {} bytes, wrong for {w}x{h} with {predictor:?}",
        raw.len(),
    );
    let planes: &[u8] = match predictor {
        Predictor::None => &raw[1..],
        Predictor::MedCtx => {
            let mut r = Cursor::new(&raw[1..header]);
            let mut lens = [[0usize; CTX_N]; 4];
            for plane in &mut lens {
                for l in plane.iter_mut() {
                    *l = r.u32()? as usize;
                }
            }
            scratch.clear();
            scratch.resize(4 * n, 0);
            let mut body = Cursor::new(&raw[header..]);
            for (pi, plane_lens) in lens.iter().enumerate() {
                let mut streams: [&[u8]; CTX_N] = [&[]; CTX_N];
                for (s, len) in streams.iter_mut().zip(plane_lens) {
                    *s = body.bytes(*len)?;
                }
                med_ctx_inverse(
                    &mut scratch[pi * n..(pi + 1) * n],
                    w as usize,
                    h as usize,
                    &streams,
                )?;
            }
            ensure!(body.remaining() == 0, "trailing bytes in a key frame");
            scratch
        }
        Predictor::Med => {
            scratch.clear();
            scratch.extend_from_slice(&raw[1..]);
            for p in scratch.chunks_exact_mut(n) {
                med_inverse(p, w as usize, h as usize);
            }
            scratch
        }
    };
    let (p0, rest) = planes.split_at(n);
    let (p1, rest) = rest.split_at(n);
    let (p2, p3) = rest.split_at(n);
    for (i, px) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let g = p0[i];
        *px = [p1[i].wrapping_add(g), g, p2[i].wrapping_add(g), p3[i]];
    }
    Ok(())
}

#[inline]
fn med(a: u8, b: u8, c: u8) -> u8 {
    let (mx, mn) = if a > b { (a, b) } else { (b, a) };
    if c >= mx {
        mn
    } else if c <= mn {
        mx
    } else {
        // mn < c < mx, so the result lies in (mn, mx) and cannot wrap.
        (i16::from(a) + i16::from(b) - i16::from(c)) as u8
    }
}

/// Replace each sample by its residual against the median prediction. Walks backwards so the
/// neighbours a sample is predicted from are still the original values.
fn med_forward(p: &mut [u8], w: usize, h: usize) {
    if w == 0 || h == 0 {
        return;
    }
    for y in (1..h).rev() {
        let (above, here) = p.split_at_mut(y * w);
        let up = &above[(y - 1) * w..];
        let row = &mut here[..w];
        for x in (1..w).rev() {
            let pred = med(row[x - 1], up[x], up[x - 1]);
            row[x] = row[x].wrapping_sub(pred);
        }
        row[0] = row[0].wrapping_sub(up[0]);
    }
    for x in (1..w).rev() {
        p[x] = p[x].wrapping_sub(p[x - 1]);
    }
}

/// Undo [`med_forward`], in raster order.
fn med_inverse(p: &mut [u8], w: usize, h: usize) {
    if w == 0 || h == 0 {
        return;
    }
    for x in 1..w {
        p[x] = p[x].wrapping_add(p[x - 1]);
    }
    for y in 1..h {
        let (above, here) = p.split_at_mut(y * w);
        let up = &above[(y - 1) * w..];
        let row = &mut here[..w];
        row[0] = row[0].wrapping_add(up[0]);
        for x in 1..w {
            let pred = med(row[x - 1], up[x], up[x - 1]);
            row[x] = row[x].wrapping_add(pred);
        }
    }
}

/// How an INTER frame came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterStats {
    pub dirty_tiles: u32,
    pub total_tiles: u32,
}

impl InterStats {
    #[must_use]
    pub fn dirty_fraction(&self) -> f64 {
        if self.total_tiles == 0 {
            0.0
        } else {
            f64::from(self.dirty_tiles) / f64::from(self.total_tiles)
        }
    }
}

/// Encode `cur` against `prev` as an INTER raw payload (before zstd).
///
/// `pred` and `scratch` are reused buffers. On return `pred` holds the moved previous picture.
#[allow(clippy::too_many_arguments)]
pub fn encode_inter_raw(
    prev: &[u8],
    cur: &[u8],
    w: u32,
    h: u32,
    tile: u32,
    moves: &[Move],
    pred: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> Result<InterStats> {
    ensure!(tile >= 8, "tile size {tile} is too small");
    ensure!(
        moves.len() <= usize::from(u16::MAX),
        "too many moves in one frame"
    );
    let stride = w as usize * 4;
    ensure!(prev.len() == stride * h as usize && cur.len() == prev.len());
    pred.clear();
    pred.extend_from_slice(prev);
    apply_moves(pred, w, h, moves, scratch)?;

    let tiles_x = w.div_ceil(tile);
    let tiles_y = h.div_ceil(tile);
    let total = tiles_x * tiles_y;

    out.clear();
    out.extend_from_slice(&(moves.len() as u16).to_le_bytes());
    for m in moves {
        for v in [m.x0, m.y0, m.x1, m.y1] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&m.dx.to_le_bytes());
        out.extend_from_slice(&m.dy.to_le_bytes());
    }
    out.extend_from_slice(&tile.to_le_bytes());
    let dirty_at = out.len();
    out.extend_from_slice(&0u32.to_le_bytes());
    let bitmap_at = out.len();
    out.resize(bitmap_at + (total as usize).div_ceil(8), 0);

    let mut dirty = 0u32;
    for ty in 0..tiles_y {
        let y0 = (ty * tile) as usize;
        let y1 = ((ty + 1) * tile).min(h) as usize;
        for tx in 0..tiles_x {
            let x0 = (tx * tile) as usize;
            let x1 = ((tx + 1) * tile).min(w) as usize;
            let differs = (y0..y1).any(|y| {
                let a = y * stride + x0 * 4;
                let b = y * stride + x1 * 4;
                cur[a..b] != pred[a..b]
            });
            if !differs {
                continue;
            }
            let t = (ty * tiles_x + tx) as usize;
            out[bitmap_at + (t >> 3)] |= 1 << (t & 7);
            dirty += 1;

            let tw = x1 - x0;
            let n = tw * (y1 - y0);
            let base = out.len();
            out.resize(base + 4 * n, 0);
            let (_, planes) = out.split_at_mut(base);
            let (q0, rest) = planes.split_at_mut(n);
            let (q1, rest) = rest.split_at_mut(n);
            let (q2, q3) = rest.split_at_mut(n);
            let mut j = 0;
            for y in y0..y1 {
                let a = y * stride + x0 * 4;
                let c = cur[a..a + tw * 4].as_chunks::<4>().0;
                let p = pred[a..a + tw * 4].as_chunks::<4>().0;
                for (cp, pp) in c.iter().zip(p) {
                    let db = cp[0].wrapping_sub(pp[0]);
                    let dg = cp[1].wrapping_sub(pp[1]);
                    let dr = cp[2].wrapping_sub(pp[2]);
                    let da = cp[3].wrapping_sub(pp[3]);
                    q0[j] = dg;
                    q1[j] = db.wrapping_sub(dg);
                    q2[j] = dr.wrapping_sub(dg);
                    q3[j] = da;
                    j += 1;
                }
            }
        }
    }
    out[dirty_at..dirty_at + 4].copy_from_slice(&dirty.to_le_bytes());
    Ok(InterStats {
        dirty_tiles: dirty,
        total_tiles: total,
    })
}

/// Apply an INTER raw payload to `state` (the previous picture, BGRA) in place.
pub fn decode_inter_raw(
    raw: &[u8],
    w: u32,
    h: u32,
    state: &mut [u8],
    scratch: &mut Vec<u8>,
) -> Result<InterStats> {
    let stride = w as usize * 4;
    ensure!(
        state.len() == stride * h as usize,
        "state buffer size mismatch"
    );
    let mut r = Cursor::new(raw);
    let n_moves = usize::from(r.u16()?);
    let mut moves = Vec::with_capacity(n_moves);
    for _ in 0..n_moves {
        moves.push(Move {
            x0: r.u32()?,
            y0: r.u32()?,
            x1: r.u32()?,
            y1: r.u32()?,
            dx: r.i32()?,
            dy: r.i32()?,
        });
    }
    apply_moves(state, w, h, &moves, scratch).context("inter frame moves")?;

    let tile = r.u32()?;
    ensure!(tile >= 8, "inter frame tile size {tile}");
    let n_dirty = r.u32()?;
    let tiles_x = w.div_ceil(tile);
    let tiles_y = h.div_ceil(tile);
    let total = tiles_x * tiles_y;
    let bitmap = r.bytes((total as usize).div_ceil(8))?;
    let mut seen = 0u32;
    for t in 0..total {
        if bitmap[(t >> 3) as usize] & (1 << (t & 7)) == 0 {
            continue;
        }
        seen += 1;
        let (tx, ty) = (t % tiles_x, t / tiles_x);
        let x0 = (tx * tile) as usize;
        let x1 = ((tx + 1) * tile).min(w) as usize;
        let y0 = (ty * tile) as usize;
        let y1 = ((ty + 1) * tile).min(h) as usize;
        let tw = x1 - x0;
        let n = tw * (y1 - y0);
        let planes = r.bytes(4 * n)?;
        let (q0, rest) = planes.split_at(n);
        let (q1, rest) = rest.split_at(n);
        let (q2, q3) = rest.split_at(n);
        let mut j = 0;
        for y in y0..y1 {
            let a = y * stride + x0 * 4;
            for px in state[a..a + tw * 4].as_chunks_mut::<4>().0 {
                let dg = q0[j];
                px[0] = px[0].wrapping_add(q1[j].wrapping_add(dg));
                px[1] = px[1].wrapping_add(dg);
                px[2] = px[2].wrapping_add(q2[j].wrapping_add(dg));
                px[3] = px[3].wrapping_add(q3[j]);
                j += 1;
            }
        }
    }
    ensure!(
        seen == n_dirty,
        "inter frame claims {n_dirty} dirty tiles, bitmap has {seen}"
    );
    ensure!(
        r.remaining() == 0,
        "{} trailing bytes in inter frame",
        r.remaining()
    );
    Ok(InterStats {
        dirty_tiles: n_dirty,
        total_tiles: total,
    })
}

/// zstd, with the raw length in front so the reader can size its buffer.
pub struct Zstd {
    compressor: zstd::bulk::Compressor<'static>,
    decompressor: zstd::bulk::Decompressor<'static>,
}

impl Zstd {
    /// `workers` > 0 spreads one frame's compression over that many threads (zstdmt).
    pub fn new(level: i32, workers: u32) -> Result<Self> {
        let mut compressor = zstd::bulk::Compressor::new(level).context("zstd compressor")?;
        if workers > 0 {
            compressor
                .set_parameter(zstd::stream::raw::CParameter::NbWorkers(workers))
                .context("zstd worker threads")?;
        }
        let decompressor = zstd::bulk::Decompressor::new().context("zstd decompressor")?;
        Ok(Self {
            compressor,
            decompressor,
        })
    }

    /// Compress `raw` into `out` as `u32 raw_len` + zstd frame.
    pub fn compress(&mut self, raw: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let len = u32::try_from(raw.len()).context("frame payload over 4 GiB")?;
        let packed = self.compressor.compress(raw).context("zstd compress")?;
        out.clear();
        out.reserve(4 + packed.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&packed);
        Ok(())
    }

    /// Inverse of [`Self::compress`]. `max_raw` guards against a corrupt length asking for an
    /// absurd allocation.
    pub fn decompress(&mut self, payload: &[u8], max_raw: usize, raw: &mut Vec<u8>) -> Result<()> {
        ensure!(
            payload.len() >= 4,
            "compressed payload shorter than its length prefix"
        );
        let len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        ensure!(
            len <= max_raw,
            "payload claims {len} raw bytes, at most {max_raw} are possible"
        );
        raw.clear();
        raw.resize(len, 0);
        let got = self
            .decompressor
            .decompress_to_buffer(&payload[4..], &mut raw[..])
            .context("zstd decompress")?;
        ensure!(got == len, "zstd produced {got} bytes, expected {len}");
        Ok(())
    }
}

/// Largest raw payload a `w x h` frame can have, for [`Zstd::decompress`].
#[must_use]
pub fn max_raw_len(w: u32, h: u32) -> usize {
    let n = w as usize * h as usize;
    // Key: 1 + 4n. Inter: moves + tile header + bitmap + at most every pixel as residual; the
    // bitmap at the smallest allowed tile (8) is n / 512 bytes.
    64 + usize::from(u16::MAX) * Move::WIRE_LEN + n / 64 + 4 * n
}

/// Bounds-checked little-endian reader over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .with_context(|| {
                format!(
                    "payload ends at {} bytes, needed {} more at offset {}",
                    self.buf.len(),
                    n,
                    self.at
                )
            })?;
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i32(&mut self) -> Result<i32> {
        let b = self.bytes(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picture(w: u32, h: u32, seed: u32) -> Vec<u8> {
        let mut v = vec![0u8; (w * h * 4) as usize];
        for (i, px) in v.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let (x, y) = (i as u32 % w, i as u32 / w);
            let t = x.wrapping_mul(7) ^ y.wrapping_mul(13) ^ seed;
            *px = [
                (t & 0xff) as u8,
                ((t >> 3) & 0xff) as u8,
                ((x + y + seed) & 0xff) as u8,
                255,
            ];
        }
        v
    }

    #[test]
    fn key_frames_round_trip_with_and_without_the_predictor() {
        let (w, h) = (37, 23);
        let f = picture(w, h, 5);
        for pred in [Predictor::None, Predictor::Med, Predictor::MedCtx] {
            let mut raw = Vec::new();
            encode_key_raw(&f, w, h, pred, &mut raw);
            let mut out = vec![0u8; f.len()];
            let mut scratch = Vec::new();
            decode_key_raw(&raw, w, h, &mut out, &mut scratch).expect("decode");
            assert_eq!(out, f, "{pred:?}");
        }
    }

    #[test]
    fn inter_frames_round_trip_with_moves() {
        let (w, h) = (100, 90);
        let prev = picture(w, h, 1);
        // Scroll the band y in [10, 80) up by 7 and change a few pixels elsewhere.
        let mut cur = prev.clone();
        let stride = (w * 4) as usize;
        for y in 10..73 {
            let src = (y + 7) * stride;
            let dst = y * stride;
            let row = prev[src..src + stride].to_vec();
            cur[dst..dst + stride].copy_from_slice(&row);
        }
        cur[5 * stride + 40] ^= 0x5a;
        cur[85 * stride + 4] = 0;
        let mv = Move::vertical_scroll(0, 10, w, 80, 7).expect("move");
        assert_eq!(mv.y0, 10);
        assert_eq!(mv.y1, 73);

        let (mut pred, mut scratch, mut raw) = (Vec::new(), Vec::new(), Vec::new());
        let stats = encode_inter_raw(
            &prev,
            &cur,
            w,
            h,
            16,
            &[mv],
            &mut pred,
            &mut scratch,
            &mut raw,
        )
        .expect("encode");
        // The move predicts the band exactly; only the two poked pixels and the exposed strip at the
        // bottom of the band are left.
        assert!(stats.dirty_tiles < stats.total_tiles / 2, "{stats:?}");
        let mut state = prev.clone();
        decode_inter_raw(&raw, w, h, &mut state, &mut scratch).expect("decode");
        assert_eq!(state, cur);
    }

    #[test]
    fn several_moves_read_the_old_picture() {
        let (w, h) = (40, 40);
        let prev = picture(w, h, 9);
        // Swap two 10x10 blocks: each move's source is the other's destination.
        let a = Move {
            x0: 0,
            y0: 0,
            x1: 10,
            y1: 10,
            dx: 20,
            dy: 20,
        };
        let b = Move {
            x0: 20,
            y0: 20,
            x1: 30,
            y1: 30,
            dx: -20,
            dy: -20,
        };
        let mut moved = prev.clone();
        let mut scratch = Vec::new();
        apply_moves(&mut moved, w, h, &[a, b], &mut scratch).expect("moves");
        let px = |buf: &[u8], x: u32, y: u32| {
            let i = ((y * w + x) * 4) as usize;
            buf[i..i + 4].to_vec()
        };
        assert_eq!(px(&moved, 3, 4), px(&prev, 23, 24));
        assert_eq!(px(&moved, 23, 24), px(&prev, 3, 4));

        let mut raw = Vec::new();
        let mut pred = Vec::new();
        encode_inter_raw(
            &prev,
            &moved,
            w,
            h,
            8,
            &[a, b],
            &mut pred,
            &mut scratch,
            &mut raw,
        )
        .expect("encode");
        let mut state = prev.clone();
        let stats = decode_inter_raw(&raw, w, h, &mut state, &mut scratch).expect("decode");
        assert_eq!(
            stats.dirty_tiles, 0,
            "the moves alone reproduce the picture"
        );
        assert_eq!(state, moved);
    }

    #[test]
    fn a_move_out_of_bounds_is_refused() {
        let mut buf = vec![0u8; 16 * 16 * 4];
        let bad = Move {
            x0: 0,
            y0: 0,
            x1: 16,
            y1: 10,
            dx: 0,
            dy: 8,
        };
        assert!(apply_moves(&mut buf, 16, 16, &[bad], &mut Vec::new()).is_err());
        assert!(Move::vertical_scroll(0, 0, 16, 16, 16).is_none());
        assert!(Move::vertical_scroll(0, 0, 16, 16, 0).is_none());
        let up = Move::vertical_scroll(0, 0, 16, 16, -3).expect("scroll up");
        assert_eq!((up.y0, up.y1, up.dy), (3, 16, -3));
    }

    #[test]
    fn corrupt_payloads_are_errors_not_panics() {
        let mut state = vec![0u8; 32 * 32 * 4];
        let mut scratch = Vec::new();
        assert!(decode_inter_raw(&[1, 0], 32, 32, &mut state, &mut scratch).is_err());
        assert!(decode_inter_raw(&[], 32, 32, &mut state, &mut scratch).is_err());
        assert!(decode_key_raw(&[0; 10], 32, 32, &mut state, &mut scratch).is_err());
        let mut z = Zstd::new(1, 0).expect("zstd");
        let mut raw = Vec::new();
        assert!(z
            .decompress(&[0xff, 0xff, 0xff, 0x7f, 1, 2], 1000, &mut raw)
            .is_err());
    }
}
