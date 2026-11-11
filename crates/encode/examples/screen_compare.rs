//! Whether `CameraVideoRealTime` (`usage_mode.rs`'s conclusion) costs anything in
//! on-screen text legibility, measured against a REAL captured screen rather than a synthetic
//! generator, at the bitrates the product's 1080p ladder actually uses.
//!
//! ## The question
//!
//! `usage_mode.rs` showed `ScreenContentRealTime` overshooting its bitrate budget 5-9x under
//! full-screen motion, and recommended `CameraVideoRealTime` with `.scene_change_detect(false)`
//! instead. But screen-content mode exists specifically for static desktops and scrolling text,
//! exactly what a real screen mostly looks like. So: on an actual screen, at 1200/2500/4000 kbps,
//! does camera mode give up any text sharpness that screen-content mode would have kept?
//!
//! This does not decide anything. It encodes, decodes, measures, and writes images so a human can
//! look at the actual pixels.
//!
//! ## How to run
//!
//! This example does not capture the screen itself; something else has to produce `source.bmp`
//! (a 24bpp Windows BMP of the primary display) in the target directory first, e.g. from
//! PowerShell:
//!
//! ```powershell
//! Add-Type -AssemblyName System.Windows.Forms,System.Drawing
//! $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
//! $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
//! $g = [System.Drawing.Graphics]::FromImage($bmp)
//! $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
//! $bmp24 = New-Object System.Drawing.Bitmap $bmp.Width, $bmp.Height, ([System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
//! [System.Drawing.Graphics]::FromImage($bmp24).DrawImage($bmp, 0, 0, $bmp.Width, $bmp.Height)
//! $bmp24.Save("<dir>\source.bmp", [System.Drawing.Imaging.ImageFormat]::Bmp)
//! ```
//!
//! Then: `cargo run --release -p afklink-encode --example screen_compare -- <dir>`. Everything
//! else (the scaled source, per-run decoded frames, side-by-side crops, `results.csv`) is written
//! into `<dir>` as BMP/CSV; convert the BMPs to PNG for viewing however is convenient.
//!
//! ## Measured, one real 2400x1600 desktop scaled to 1620x1080
//!
//! ```text
//! scenario  kbps  mode    produced_kbps  keys  mean_qp  psnr_db
//! still     1200  screen        840.0     1    29.00    42.30
//! still     1200  camera        905.7     1    30.04    42.55
//! still     2500  screen        358.6     1    21.08    42.41
//! still     2500  camera        394.6     1    21.31    42.68
//! still     4000  screen        206.2     1    19.64    42.58
//! still     4000  camera        224.2     1    19.67    42.62
//! scroll    1200  screen       1068.2     1    39.03    36.23
//! scroll    1200  camera       1126.2     1    35.77    38.99
//! scroll    2500  screen       1545.9     1    23.51    42.44
//! scroll    2500  camera       1256.3     1    22.24    42.66
//! scroll    4000  screen        986.0     1    20.01    42.58
//! scroll    4000  camera        787.6     1    19.84    42.73
//! ```
//!
//! Camera mode matched or slightly beat screen mode's PSNR in every single row, and the
//! side-by-side crops (source | screen | camera, over a text-dense region) showed no visible
//! difference in text sharpness at any bitrate in either the static or the scrolling scenario.
//!
//! Caveat: on this real, mostly-static desktop, screen-content mode did **not** IDR-storm: both
//! modes produced exactly 1 keyframe across all 90 frames. The 5-9x overshoot `usage_mode.rs`
//! measures is specific to content that moves everywhere on every frame (a panning game), which a
//! real desktop or scrolling-text session does not do; that failure mode is covered there, not
//! here.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use afklink_core::scale::Scaler;
use anyhow::{bail, Context, Result};
use openh264::decoder::Decoder;
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, Profile, QpRange,
    RateControlMode, UsageType,
};
use openh264::formats::{BgraSliceU8, YUVSource};
use openh264::{OpenH264API, Timestamp};
use openh264_sys2::{SEncoderStatistics, ENCODER_OPTION_GET_STATISTICS};

const FRAMES: u32 = 90;
const MEASURE_FROM: u32 = 30;
const SCROLL_PX_PER_FRAME: usize = 4;
const MAX_W: u32 = 1920;
const MAX_H: u32 = 1080;

/// Text-dense crop rectangle, chosen by eye against `preview_scaled.png` (the sidebar + bullet
/// list with inline code spans, at the resolution the encoders actually see). Kept in sync with
/// the report: x=592, y=85, 640x360.
const CROP: (usize, usize, usize, usize) = (592, 85, 640, 360);

// ---------------------------------------------------------------------------------------------
// Minimal 24bpp BMP read/write (no image crate available to examples of this crate).
// ---------------------------------------------------------------------------------------------

struct Bgr24 {
    w: usize,
    h: usize,
    /// Top-down BGR rows, tightly packed (no padding).
    px: Vec<u8>,
}

fn read_bmp24(path: &Path) -> Result<Bgr24> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if data.len() < 54 || &data[0..2] != b"BM" {
        bail!("{}: not a BMP", path.display());
    }
    let pixel_offset = u32::from_le_bytes(
        data[10..14]
            .try_into()
            .expect("slice literal is exactly 4 bytes"),
    ) as usize;
    let width = i32::from_le_bytes(
        data[18..22]
            .try_into()
            .expect("slice literal is exactly 4 bytes"),
    );
    let height = i32::from_le_bytes(
        data[22..26]
            .try_into()
            .expect("slice literal is exactly 4 bytes"),
    );
    let bpp = u16::from_le_bytes(
        data[28..30]
            .try_into()
            .expect("slice literal is exactly 2 bytes"),
    );
    if bpp != 24 {
        bail!("{}: expected 24bpp, got {bpp}", path.display());
    }
    let w = width.unsigned_abs() as usize;
    let h = height.unsigned_abs() as usize;
    let bottom_up = height > 0;
    let row_stride = (w * 3).div_ceil(4) * 4;
    let mut px = vec![0u8; w * h * 3];
    for row in 0..h {
        let src_row = if bottom_up { h - 1 - row } else { row };
        let src_off = pixel_offset + src_row * row_stride;
        let dst_off = row * w * 3;
        px[dst_off..dst_off + w * 3].copy_from_slice(&data[src_off..src_off + w * 3]);
    }
    Ok(Bgr24 { w, h, px })
}

/// Writes tightly-packed top-down BGR pixels as a 24bpp BMP (bottom-up on disk, per the format).
fn write_bmp24(path: &Path, w: usize, h: usize, top_down_bgr: &[u8]) -> Result<()> {
    assert_eq!(top_down_bgr.len(), w * h * 3);
    let row_stride = (w * 3).div_ceil(4) * 4;
    let pad = row_stride - w * 3;
    let pixel_offset = 54u32;
    let data_size = row_stride * h;
    let file_size = pixel_offset as usize + data_size;
    let mut out = Vec::with_capacity(file_size);
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(file_size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&pixel_offset.to_le_bytes());
    out.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER size
    out.extend_from_slice(&(w as i32).to_le_bytes());
    out.extend_from_slice(&(h as i32).to_le_bytes()); // positive => bottom-up
    out.extend_from_slice(&1u16.to_le_bytes()); // planes
    out.extend_from_slice(&24u16.to_le_bytes()); // bpp
    out.extend_from_slice(&0u32.to_le_bytes()); // no compression
    out.extend_from_slice(&(data_size as u32).to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes()); // 72 DPI
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    for row in 0..h {
        let src_row = h - 1 - row; // bottom-up on disk
        let off = src_row * w * 3;
        out.extend_from_slice(&top_down_bgr[off..off + w * 3]);
        out.extend(std::iter::repeat_n(0u8, pad));
    }
    fs::write(path, &out).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn bgr_to_bgra(bgr: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 4];
    for i in 0..w * h {
        out[i * 4] = bgr[i * 3];
        out[i * 4 + 1] = bgr[i * 3 + 1];
        out[i * 4 + 2] = bgr[i * 3 + 2];
        out[i * 4 + 3] = 255;
    }
    out
}

fn bgra_to_bgr(bgra: &[u8], w: usize, h: usize) -> Vec<u8> {
    let mut out = vec![0u8; w * h * 3];
    for i in 0..w * h {
        out[i * 3] = bgra[i * 4];
        out[i * 3 + 1] = bgra[i * 4 + 1];
        out[i * 3 + 2] = bgra[i * 4 + 2];
    }
    out
}

fn rgb_to_bgr(rgb: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; rgb.len()];
    for i in 0..rgb.len() / 3 {
        out[i * 3] = rgb[i * 3 + 2];
        out[i * 3 + 1] = rgb[i * 3 + 1];
        out[i * 3 + 2] = rgb[i * 3];
    }
    out
}

/// Shifts a top-down BGR image's rows UP by `n` pixels, wrapping around (scrolling text).
fn shift_up_bgr(src: &[u8], w: usize, h: usize, n: usize) -> Vec<u8> {
    let n = n % h;
    let mut out = vec![0u8; w * h * 3];
    for row in 0..h {
        let src_row = (row + n) % h;
        out[row * w * 3..(row + 1) * w * 3]
            .copy_from_slice(&src[src_row * w * 3..(src_row + 1) * w * 3]);
    }
    out
}

fn crop_bgr(src: &[u8], w: usize, _h: usize, x: usize, y: usize, cw: usize, ch: usize) -> Vec<u8> {
    let mut out = vec![0u8; cw * ch * 3];
    for row in 0..ch {
        let src_off = ((y + row) * w + x) * 3;
        let dst_off = row * cw * 3;
        out[dst_off..dst_off + cw * 3].copy_from_slice(&src[src_off..src_off + cw * 3]);
    }
    out
}

/// Horizontally concatenates BGR images of equal height with a 4px white gap between them.
fn hconcat_bgr(images: &[(&[u8], usize)], h: usize) -> (Vec<u8>, usize) {
    const GAP: usize = 4;
    let total_w: usize = images.iter().map(|(_, w)| *w).sum::<usize>() + GAP * (images.len() - 1);
    let mut out = vec![255u8; total_w * h * 3];
    let mut x0 = 0usize;
    for (img, w) in images {
        for row in 0..h {
            let src_off = row * w * 3;
            let dst_off = (row * total_w + x0) * 3;
            out[dst_off..dst_off + w * 3].copy_from_slice(&img[src_off..src_off + w * 3]);
        }
        x0 += w + GAP;
    }
    (out, total_w)
}

// ---------------------------------------------------------------------------------------------
// Encoder / decoder
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Mode {
    name: &'static str,
    usage: UsageType,
    scd: bool,
}

const SCREEN: Mode = Mode {
    name: "screen",
    usage: UsageType::ScreenContentRealTime,
    scd: false, // irrelevant: screen-content force-enables it
};
const CAMERA: Mode = Mode {
    name: "camera",
    usage: UsageType::CameraVideoRealTime,
    scd: false,
};

fn build_encoder(mode: Mode, kbps: u32) -> Encoder {
    let config = EncoderConfig::new()
        .profile(Profile::Baseline)
        .bitrate(BitRate::from_bps(kbps * 1000))
        .max_frame_rate(FrameRate::from_hz(30.0))
        .rate_control_mode(RateControlMode::Bitrate)
        .usage_type(mode.usage)
        .intra_frame_period(IntraFramePeriod::from_num_frames(300))
        .num_threads(4)
        .skip_frames(false)
        .qp(QpRange::new(16, 46))
        .scene_change_detect(mode.scd)
        .adaptive_quantization(false)
        .background_detection(false)
        .max_slice_len(4096)
        .debug(false);
    Encoder::with_api_config(OpenH264API::from_source(), config).expect("encoder")
}

fn frame_qp(enc: &mut Encoder) -> Option<u32> {
    let mut stats = SEncoderStatistics::default();
    let rc = unsafe {
        enc.raw_api().get_option(
            ENCODER_OPTION_GET_STATISTICS,
            std::ptr::from_mut(&mut stats).cast(),
        )
    };
    (rc == 0 && stats.uiAverageFrameQP > 0).then_some(stats.uiAverageFrameQP)
}

/// A decoded frame kept for comparison: top-down RGB8 pixels, plus its width and height.
type DecodedFrame = (Vec<u8>, usize, usize);

struct RunResult {
    produced_kbps: f64,
    keys: u32,
    mean_qp: f64,
    /// Decoded last frame. `None` if the decoder never produced the final frame.
    last_frame: Option<DecodedFrame>,
}

/// Encodes `frames` (BGRA, `w`x`h`) with `mode`/`kbps`, then decodes the produced bitstream in
/// order to recover the actual last decoded picture.
fn run(mode: Mode, kbps: u32, frames: &[Vec<u8>], w: usize, h: usize) -> Result<RunResult> {
    let mut enc = build_encoder(mode, kbps);
    let mut bitstreams: Vec<Vec<u8>> = Vec::with_capacity(frames.len());
    let (mut bytes_measured, mut frames_measured, mut keys) = (0u64, 0u64, 0u32);
    let (mut qp_sum, mut qp_n) = (0u64, 0u64);

    for (n, frame) in frames.iter().enumerate() {
        let yuv = openh264::formats::YUVBuffer::from_bgra8_source(BgraSliceU8::new(frame, (w, h)));
        let bytes = {
            let bs = enc
                .encode_at(&yuv, Timestamp::from_millis(n as u64 * 33))
                .context("encode")?;
            let ft = bs.frame_type();
            if matches!(ft, FrameType::IDR | FrameType::I) {
                keys += 1;
            }
            bs.to_vec()
        };
        if let Some(q) = frame_qp(&mut enc) {
            qp_sum += u64::from(q);
            qp_n += 1;
        }
        if n as u32 >= MEASURE_FROM {
            bytes_measured += bytes.len() as u64;
            frames_measured += 1;
        }
        bitstreams.push(bytes);
    }

    // Decode everything in order, keeping the most recent decoded picture.
    let mut dec = Decoder::new().context("decoder")?;
    let mut last: Option<DecodedFrame> = None;
    for bytes in &bitstreams {
        if let Some(yuv) = dec.decode(bytes).context("decode")? {
            let (dw, dh) = yuv.dimensions();
            let mut rgb = vec![0u8; dw * dh * 3];
            yuv.write_rgb8(&mut rgb);
            last = Some((rgb, dw, dh));
        }
    }
    for yuv in dec.flush_remaining().context("flush decoder")? {
        let (dw, dh) = yuv.dimensions();
        let mut rgb = vec![0u8; dw * dh * 3];
        yuv.write_rgb8(&mut rgb);
        last = Some((rgb, dw, dh));
    }

    Ok(RunResult {
        produced_kbps: bytes_measured as f64 * 8.0 * 30.0 / frames_measured.max(1) as f64 / 1000.0,
        keys,
        mean_qp: if qp_n > 0 {
            qp_sum as f64 / qp_n as f64
        } else {
            f64::NAN
        },
        last_frame: last,
    })
}

/// Mean PSNR across R, G, B against a reference RGB image of the same size.
fn psnr(a_rgb: &[u8], b_rgb: &[u8]) -> f64 {
    assert_eq!(a_rgb.len(), b_rgb.len());
    let mut sum_sq = 0.0f64;
    for (x, y) in a_rgb.iter().zip(b_rgb.iter()) {
        let d = f64::from(*x) - f64::from(*y);
        sum_sq += d * d;
    }
    let mse = sum_sq / a_rgb.len() as f64;
    if mse <= 0.0 {
        return f64::INFINITY;
    }
    20.0 * 255.0f64.log10() - 10.0 * mse.log10()
}

fn main() -> Result<()> {
    let dir = env::args().nth(1).context("usage: screen_compare <dir>")?;
    let dir = PathBuf::from(dir);

    let src_path = dir.join("source.bmp");
    let src = read_bmp24(&src_path)?;
    println!("captured screen: {}x{}", src.w, src.h);

    // Scale to fit 1920x1080 exactly as the production encoder does.
    let src_bgra = bgr_to_bgra(&src.px, src.w, src.h);
    let mut scaler = Scaler::new();
    let (scaled_bgra_ref, sw, sh) =
        scaler.fit(&src_bgra, src.w as u32, src.h as u32, MAX_W, MAX_H)?;
    let scaled_bgra = scaled_bgra_ref.to_vec();
    let (sw, sh) = (sw as usize, sh as usize);
    println!("scaled to: {sw}x{sh}");

    let scaled_bgr = bgra_to_bgr(&scaled_bgra, sw, sh);
    write_bmp24(&dir.join("source_scaled.bmp"), sw, sh, &scaled_bgr)?;

    if CROP.0 + CROP.2 > sw || CROP.1 + CROP.3 > sh {
        bail!(
            "crop rectangle {CROP:?} does not fit inside scaled image {sw}x{sh}; adjust CROP in screen_compare.rs"
        );
    }
    println!(
        "crop rectangle: x={} y={} w={} h={}",
        CROP.0, CROP.1, CROP.2, CROP.3
    );

    // Build the two content scenarios.
    let mut still_frames = Vec::with_capacity(FRAMES as usize);
    let mut scroll_frames = Vec::with_capacity(FRAMES as usize);
    let mut scroll_source_bgr = Vec::with_capacity(FRAMES as usize);
    for n in 0..FRAMES as usize {
        still_frames.push(scaled_bgra.clone());
        let shifted_bgr = shift_up_bgr(&scaled_bgr, sw, sh, n * SCROLL_PX_PER_FRAME);
        scroll_frames.push(bgr_to_bgra(&shifted_bgr, sw, sh));
        scroll_source_bgr.push(shifted_bgr);
    }

    let kbps_list = [1200u32, 2500, 4000];
    let modes = [SCREEN, CAMERA];

    let mut csv = String::from("scenario,kbps,mode,produced_kbps,keys,mean_qp,psnr_db\n");
    println!(
        "{:<7} {:>5} {:<7} {:>13} {:>5} {:>8} {:>9}",
        "scen", "kbps", "mode", "produced_kbps", "keys", "mean_qp", "psnr_db"
    );

    for (scenario, frames, ref_bgr) in [
        ("still", &still_frames, &scaled_bgr),
        (
            "scroll",
            &scroll_frames,
            &scroll_source_bgr[FRAMES as usize - 1],
        ),
    ] {
        for &kbps in &kbps_list {
            let mut decoded: Vec<(Mode, Option<DecodedFrame>)> = Vec::new();
            for mode in modes {
                let r = run(mode, kbps, frames, sw, sh)?;
                let psnr_db = match &r.last_frame {
                    Some((rgb, dw, dh)) if *dw == sw && *dh == sh => {
                        let ref_rgb: Vec<u8> = ref_bgr
                            .as_chunks::<3>()
                            .0
                            .iter()
                            .flat_map(|p| [p[2], p[1], p[0]])
                            .collect();
                        psnr(rgb, &ref_rgb)
                    }
                    Some((_, dw, dh)) => {
                        println!(
                            "  ! {scenario}/{kbps}/{}: decoded size {dw}x{dh} != source {sw}x{sh}",
                            mode.name
                        );
                        f64::NAN
                    }
                    None => {
                        println!(
                            "  ! {scenario}/{kbps}/{}: decoder produced NO final frame",
                            mode.name
                        );
                        f64::NAN
                    }
                };
                println!(
                    "{:<7} {:>5} {:<7} {:>13.1} {:>5} {:>8.2} {:>9.2}",
                    scenario, kbps, mode.name, r.produced_kbps, r.keys, r.mean_qp, psnr_db
                );
                csv.push_str(&format!(
                    "{scenario},{kbps},{},{:.1},{},{:.2},{:.2}\n",
                    mode.name, r.produced_kbps, r.keys, r.mean_qp, psnr_db
                ));

                if let Some((rgb, dw, dh)) = &r.last_frame {
                    let bgr = rgb_to_bgr(rgb);
                    write_bmp24(
                        &dir.join(format!("{scenario}_{kbps}_{}.bmp", mode.name)),
                        *dw,
                        *dh,
                        &bgr,
                    )?;
                }
                decoded.push((mode, r.last_frame));
            }

            // Side-by-side crop: source | screen | camera.
            let (cx, cy, cw, ch) = CROP;
            let src_crop = crop_bgr(ref_bgr, sw, sh, cx, cy, cw, ch);
            let mut parts: Vec<Vec<u8>> = vec![src_crop];
            for (_, last) in &decoded {
                match last {
                    Some((rgb, dw, dh)) if *dw == sw && *dh == sh => {
                        let bgr = rgb_to_bgr(rgb);
                        parts.push(crop_bgr(&bgr, sw, sh, cx, cy, cw, ch));
                    }
                    _ => parts.push(vec![0u8; cw * ch * 3]),
                }
            }
            let refs: Vec<(&[u8], usize)> = parts.iter().map(|p| (p.as_slice(), cw)).collect();
            let (combined, total_w) = hconcat_bgr(&refs, ch);
            write_bmp24(
                &dir.join(format!("crop_{scenario}_{kbps}.bmp")),
                total_w,
                ch,
                &combined,
            )?;
        }
    }

    fs::write(dir.join("results.csv"), &csv)?;
    println!("\nwrote results.csv and BMP outputs to {}", dir.display());
    Ok(())
}
