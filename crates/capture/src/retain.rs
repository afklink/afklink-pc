//! The game window capture's last frame, kept on the GPU for one use: the picture a still window
//! is resumed on after a background hold (`afklink_core::game::WindowCapture::retained`).
//!
//! ## Why every frame, and why on the GPU
//!
//! WGC sends a window's frame only when it changes, so the window's last update before it went
//! still is the only true picture there is. Sampling now and then can miss exactly that frame, and
//! a still window never sends it again: the viewer would resume on an older picture for good. So
//! every frame of the live capture that arrives — passed, paced out or dropped by the hold — is
//! copied, as it is, into one texture on the capture's own device ([`Retainer::keep`]): a
//! GPU-to-GPU `CopySubresourceRegion`, no CPU read-back, no allocation per frame. The texture has
//! the whole frame's size and format, and is made again only when either changes; each copy
//! writes the region it was given at the region's own place, and the region is remembered with it
//! — the only part of the texture that holds the last frame.
//!
//! The region is the frame's own client area for a frame cropped on the live path (its crop is
//! computed from the window's geometry read for that frame — exactly the part that goes out), and
//! the whole frame for every other one: held, paced out or refused. Those are retained without
//! reading the window's geometry, and a crop remembered from an earlier frame of the same size
//! would be wrong when the client area moved inside an unchanged frame (a menu or a title bar
//! removed: `SetMenu`, `SetWindowPos` with `SWP_FRAMECHANGED`) — the read after the hold would then
//! never find the new crop inside it. The whole frame holds any crop of it. That is the pattern of
//! Microsoft's own capture samples, which copy the frame's surface on the immediate context and
//! close the frame at once; WGC orders the reuse of its surface after the work queued on it.
//!
//! Cost, unmeasured so far: one GPU copy per arriving frame — the client area of a frame sent, the
//! whole frame of one held or paced out, which for a borderless game is the same and for a window
//! with a frame a few per cent more (its borders and title bar) — and one texture of the whole
//! frame's size in video memory per capture. 2560x1440 BGRA writes 14.7 MB and reads as much; at
//! 144 frames a second about 4.2 GB/s of memory traffic, which on an integrated GPU shares its
//! bandwidth with the game. What to measure on afk-pc with a game at its real rate: the pipeline
//! line's `game_retain` (the copies submitted per second and the MB they write — a count of work
//! queued on the GPU, not GPU time: `afklink_core::game::GameStatus::retain_copies`), the game's
//! own frame rate and GPU time with the agent capturing and without (PresentMon or the game's
//! counter), and the GPU engines' utilisation in Task Manager. The read-back, crop and scale
//! happen only for a resend, at most a few times per hold ([`Retainer::read`]).
//!
//! ## Threads, and the device's immediate context
//!
//! The immediate context is not thread-safe. [`Retainer::keep`] runs on the capture's own thread
//! (the crate's, inside `on_frame_arrived`); [`Retainer::read`] on the game capture's thread
//! (`game-capture`), reached through `CaptureControl::callback` — the crate's own lock on the frame
//! handler, which its thread holds for every `on_frame_arrived` — so the two never use the context
//! at once. Windows' capture also uses the device on threads of its own, outside that lock: the
//! device's multithread protection, turned on in [`Retainer::new`] before the frame pool exists,
//! serializes every context call against those. It is set through `ID3D11Multithread`, which
//! Microsoft documents on the immediate context, or — when that is missing — through
//! `ID3D10Multithread` on the device (documented for D3D10 and D3D11 devices alike). Without
//! either, [`Retainer::read`] refuses and the resend is skipped; the capture itself is
//! unaffected.
//!
//! The read-back's `Map` never blocks on the GPU while the handler's lock is held: it is asked
//! with `D3D11_MAP_FLAG_DO_NOT_WAIT` and polled every [`MAP_POLL`] up to [`MAP_DEADLINE`], after
//! the copy was flushed to the GPU. Past the deadline the read gives up ("the GPU is busy") and
//! the caller tries again later; the capture's thread waits at most that long for its next frame.

use std::time::{Duration, Instant};

use afklink_core::game::Crop;
use windows::core::{Interface, HRESULT};
use windows::Win32::Graphics::Direct3D10::ID3D10Multithread;
use windows::Win32::Graphics::Direct3D11::{
    ID3D11Device, ID3D11DeviceContext, ID3D11Multithread, ID3D11Texture2D, D3D11_BOX,
    D3D11_CPU_ACCESS_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_FLAG_DO_NOT_WAIT, D3D11_MAP_READ,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT, DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R16G16B16A16_FLOAT, DXGI_SAMPLE_DESC,
};
use windows_capture::frame::Frame as WgcFrame;

use crate::game::error_text;

/// `DXGI_ERROR_WAS_STILL_DRAWING`: a `Map` asked not to wait found the GPU still on the copy.
/// Spelled out here so the crate need not build all of `Win32_Graphics_Dxgi` for one constant.
const WAS_STILL_DRAWING: HRESULT = HRESULT(0x887A_000A_u32 as i32);

/// How long a read-back waits at most for the GPU to finish its copy, polling.
pub(crate) const MAP_DEADLINE: Duration = Duration::from_millis(200);
/// The pause between two polls of a `Map` that found the GPU still busy.
const MAP_POLL: Duration = Duration::from_millis(3);

/// The last frame of one window capture, on its device.
pub(crate) struct Retainer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    /// The interface the device's multithread protection was turned on through; `None`: neither
    /// was there, and [`Self::read`] may not use the context off the capture's thread.
    protected: Option<&'static str>,
    last: Option<Last>,
    /// Why the last frame could not be retained, said once until one is again. With no texture
    /// left (it could not be made for a new size), what [`Self::last`] reports.
    failing: Option<String>,
    hwnd: usize,
}

// SAFETY: the D3D11 device is free-threaded; the immediate context and the textures are used only
// under the crate's lock on the frame handler that owns this (see the module's «Threads»), with the
// device's multithread protection on before any use off the capture's thread.
unsafe impl Send for Retainer {}

struct Last {
    texture: ID3D11Texture2D,
    /// The retained texture's description: the whole frame's size and format.
    desc: D3D11_TEXTURE2D_DESC,
    /// The whole frame's size, and the region of it the last copy wrote — at its own place in the
    /// texture, so texture pixels are frame pixels; the rest of the texture is older.
    frame: (u32, u32),
    region: Crop,
    at: Instant,
    in_hold: bool,
}

/// What [`Retainer::last`] says of the retained frame.
pub(crate) enum LastFrame {
    /// A frame of `size` (the whole frame's) that arrived at `at`, during a hold or not, of which
    /// `region` is retained.
    Kept {
        size: (u32, u32),
        region: Crop,
        at: Instant,
        in_hold: bool,
    },
    /// No frame has arrived since the capture started.
    None,
    /// Frames arrived, but none is retained now, and why.
    Lost(String),
}

/// Why [`Retainer::read`] gave no picture.
#[derive(Debug)]
pub(crate) enum ReadError {
    /// No try can succeed on this retained frame: the crop is not inside the retained region, the
    /// frame's format is not one the read-back takes, or the context may not be used off the
    /// capture's thread at all. Only a new frame changes that, and a fresh frame ends the resend
    /// anyway.
    Unusable(String),
    /// This try failed (the GPU busy, a staging texture or a `Map` failing); a later one may not.
    Failed(String),
}

/// What one read-back took: how long the GPU was waited for, and how many `Map` polls found it
/// still busy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadBack {
    pub(crate) gpu_wait: Duration,
    pub(crate) busy_polls: u32,
}

/// Same size, format and layout: one region copy can go into it.
fn same_shape(a: &D3D11_TEXTURE2D_DESC, b: &D3D11_TEXTURE2D_DESC) -> bool {
    (a.Width, a.Height, a.Format, a.MipLevels, a.ArraySize)
        == (b.Width, b.Height, b.Format, b.MipLevels, b.ArraySize)
        && (a.SampleDesc.Count, a.SampleDesc.Quality) == (b.SampleDesc.Count, b.SampleDesc.Quality)
}

/// Bytes per pixel of the formats a WGC frame pool hands out (BGRA8, or FP16 for HDR); 4 for any
/// other, for the cost's count only.
fn bytes_per_pixel(format: DXGI_FORMAT) -> u64 {
    if format == DXGI_FORMAT_R16G16B16A16_FLOAT {
        8
    } else {
        4
    }
}

/// `inner` lies wholly inside `outer`.
fn contains(outer: Crop, inner: Crop) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && u64::from(inner.x) + u64::from(inner.w) <= u64::from(outer.x) + u64::from(outer.w)
        && u64::from(inner.y) + u64::from(inner.h) <= u64::from(outer.y) + u64::from(outer.h)
}

impl Retainer {
    /// On the capture's own thread, as its frame handler is made — before the frame pool exists,
    /// so nothing else uses the device yet: turns the device's multithread protection on, through
    /// the immediate context's `ID3D11Multithread` or else the device's `ID3D10Multithread`.
    pub(crate) fn new(device: ID3D11Device, context: ID3D11DeviceContext, hwnd: usize) -> Self {
        let hwnd_text = format!("{hwnd:#x}");
        let protected = match context.cast::<ID3D11Multithread>() {
            Ok(multithread) => {
                // SAFETY: plain calls on a live interface; the first returns the previous setting.
                let (was, now) = unsafe {
                    let was = multithread.SetMultithreadProtected(true);
                    (was, multithread.GetMultithreadProtected())
                };
                tracing::debug!(
                    hwnd = %hwnd_text,
                    interface = "ID3D11Multithread (immediate context)",
                    was_on = was.as_bool(),
                    now_on = now.as_bool(),
                    "game window capture: D3D11 multithread protection on (the retained last \
                     frame may be read back off the capture's thread)"
                );
                now.as_bool().then_some("ID3D11Multithread")
            }
            Err(e11) => match device.cast::<ID3D10Multithread>() {
                Ok(multithread) => {
                    // SAFETY: as above.
                    let (was, now) = unsafe {
                        let was = multithread.SetMultithreadProtected(true);
                        (was, multithread.GetMultithreadProtected())
                    };
                    tracing::debug!(
                        hwnd = %hwnd_text,
                        interface = "ID3D10Multithread (device)",
                        no_d3d11_interface = %error_text(&e11),
                        was_on = was.as_bool(),
                        now_on = now.as_bool(),
                        "game window capture: D3D11 multithread protection on through the \
                         device's ID3D10Multithread (the immediate context has no \
                         ID3D11Multithread)"
                    );
                    now.as_bool().then_some("ID3D10Multithread")
                }
                Err(e10) => {
                    tracing::warn!(
                        hwnd = %hwnd_text,
                        "game window capture: no multithread interface on the capture's device \
                         (context ID3D11Multithread: {}; device ID3D10Multithread: {}); a still \
                         window's last frame cannot be read back after a background hold, and \
                         the viewer waits for the window's next frame instead",
                        error_text(&e11),
                        error_text(&e10)
                    );
                    None
                }
            },
        };
        if protected.is_none() {
            tracing::debug!(
                hwnd = %hwnd_text,
                "game window capture: multithread protection is off; read-backs are refused"
            );
        }
        Self {
            device,
            context,
            protected,
            last: None,
            failing: None,
            hwnd,
        }
    }

    /// Retain `frame` as the last one: a GPU copy of `region` of it (frame pixels; the whole frame
    /// when `None` or not inside it) to the same place in the retained texture, which has the
    /// frame's size and is made again only for a new frame size or format — so frames retained
    /// whole and frames retained by their crop share it. On the capture's own thread, for every
    /// live frame. The bytes written, or `None` when it could not be retained (logged once until
    /// one is again).
    pub(crate) fn keep(
        &mut self,
        frame: &WgcFrame,
        region: Option<Crop>,
        now: Instant,
        in_hold: bool,
    ) -> Option<u64> {
        self.keep_texture(frame.as_raw_texture(), frame.desc(), region, now, in_hold)
    }

    /// [`Self::keep`] of a texture of this device described by `source`.
    fn keep_texture(
        &mut self,
        texture: &ID3D11Texture2D,
        source: &D3D11_TEXTURE2D_DESC,
        region: Option<Crop>,
        now: Instant,
        in_hold: bool,
    ) -> Option<u64> {
        let frame = (source.Width, source.Height);
        let whole = Crop {
            x: 0,
            y: 0,
            w: frame.0,
            h: frame.1,
        };
        let region = region
            .filter(|r| r.w > 0 && r.h > 0 && contains(whole, *r))
            .unwrap_or(whole);
        if region.w == 0 || region.h == 0 {
            self.fail(format!("the frame is empty ({}x{})", frame.0, frame.1));
            return None;
        }
        if source.SampleDesc.Count != 1 {
            self.fail(format!(
                "the frame is multisampled ({} samples)",
                source.SampleDesc.Count
            ));
            return None;
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: frame.0,
            Height: frame.1,
            MipLevels: 1,
            ArraySize: 1,
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: 0,
            CPUAccessFlags: 0,
            MiscFlags: 0,
            ..*source
        };
        if !self
            .last
            .as_ref()
            .is_some_and(|l| same_shape(&l.desc, &desc))
        {
            let from = self
                .last
                .take()
                .map(|l| format!("{} of {}x{}", l.region, l.frame.0, l.frame.1));
            let mut made = None;
            // SAFETY: a live description and a live out slot; no initial data.
            let result = unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut made)) };
            let made = match (result, made) {
                (Ok(()), Some(made)) => made,
                (Ok(()), None) => {
                    self.fail("CreateTexture2D returned no texture".to_string());
                    return None;
                }
                (Err(e), _) => {
                    self.fail(format!(
                        "CreateTexture2D {}x{} (format {}): {}",
                        desc.Width,
                        desc.Height,
                        desc.Format.0,
                        error_text(&e)
                    ));
                    return None;
                }
            };
            tracing::debug!(
                hwnd = %format!("{:#x}", self.hwnd),
                size = %format!("{}x{}", desc.Width, desc.Height),
                region = %region,
                whole = region == whole,
                format = desc.Format.0,
                from = ?from,
                vram_bytes = u64::from(desc.Width)
                    * u64::from(desc.Height)
                    * bytes_per_pixel(desc.Format),
                "game window capture: the texture the last frame is retained in is made, the \
                 frame's size (each frame is copied into it on the GPU: a sent frame's client \
                 area, any other frame whole)"
            );
            self.last = Some(Last {
                texture: made,
                desc,
                frame,
                region,
                at: now,
                in_hold,
            });
        }
        let last = self.last.as_mut()?;
        let src_box = D3D11_BOX {
            left: region.x,
            top: region.y,
            front: 0,
            right: region.x + region.w,
            bottom: region.y + region.h,
            back: 1,
        };
        // SAFETY: both textures are this device's, of one format and size, single-sampled; the
        // box lies inside the source (checked above) and, at its own place, inside the
        // destination. The context is used under the crate's lock on the frame handler, with
        // multithread protection against Windows' own use (the module's «Threads»).
        unsafe {
            self.context.CopySubresourceRegion(
                &last.texture,
                0,
                region.x,
                region.y,
                0,
                texture,
                0,
                Some(&src_box),
            );
        }
        last.frame = frame;
        last.region = region;
        last.at = now;
        last.in_hold = in_hold;
        if let Some(why) = self.failing.take() {
            tracing::debug!(
                hwnd = %format!("{:#x}", self.hwnd),
                after = %why,
                "game window capture: the last frame is retained again"
            );
        }
        Some(u64::from(region.w) * u64::from(region.h) * bytes_per_pixel(desc.Format))
    }

    fn fail(&mut self, why: String) {
        self.last = None;
        if self.failing.is_none() {
            tracing::warn!(
                hwnd = %format!("{:#x}", self.hwnd),
                "game window capture: the last frame cannot be retained: {why}; a still window \
                 after a background hold has no picture to resume on until this recovers"
            );
        }
        self.failing = Some(why);
    }

    /// The retained frame, as [`Self::keep`] left it.
    pub(crate) fn last(&self) -> LastFrame {
        match (&self.last, &self.failing) {
            (Some(l), _) => LastFrame::Kept {
                size: l.frame,
                region: l.region,
                at: l.at,
                in_hold: l.in_hold,
            },
            (None, Some(why)) => LastFrame::Lost(why.clone()),
            (None, None) => LastFrame::None,
        }
    }

    /// Read `crop` (frame pixels) of the retained frame back from the GPU into `out`: BGRA rows,
    /// no padding. On the game capture's thread, under the crate's lock on the frame handler; a
    /// staging texture of the crop's size, made for this one read; the GPU polled, never blocked
    /// on, for [`MAP_DEADLINE`] at most. Each failing step says its HRESULT, and whether a later
    /// try can do better ([`ReadError`]).
    pub(crate) fn read(&self, crop: Crop, out: &mut Vec<u8>) -> Result<ReadBack, ReadError> {
        use ReadError::{Failed, Unusable};
        if self.protected.is_none() {
            return Err(Unusable(
                "the device's multithread protection is off: no read-back off the capture's thread"
                    .into(),
            ));
        }
        let Some(last) = &self.last else {
            return Err(Unusable("nothing is retained".into()));
        };
        if last.desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(Unusable(format!(
                "the retained frame is not BGRA (format {})",
                last.desc.Format.0
            )));
        }
        if crop.w == 0 || crop.h == 0 || !contains(last.region, crop) {
            return Err(Unusable(format!(
                "the crop {crop} is not inside the retained region {} of the {}x{} frame (the \
                 window's client area moved within a frame of the same size since its last \
                 frame was cropped, and no frame came whole after)",
                last.region, last.frame.0, last.frame.1
            )));
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: crop.w,
            Height: crop.h,
            MipLevels: 1,
            ArraySize: 1,
            Format: last.desc.Format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut staging = None;
        // SAFETY: a live description and a live out slot; no initial data.
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut staging)) }.map_err(|e| {
            Failed(format!(
                "CreateTexture2D (staging {crop}): {}",
                error_text(&e)
            ))
        })?;
        let staging = staging
            .ok_or_else(|| Failed("CreateTexture2D (staging) returned no texture".into()))?;
        // The retained texture's pixels are the frame's.
        let region = D3D11_BOX {
            left: crop.x,
            top: crop.y,
            front: 0,
            right: crop.x + crop.w,
            bottom: crop.y + crop.h,
            back: 1,
        };
        // SAFETY: both textures are this device's; the box lies inside the retained region, so
        // inside the retained texture (checked above), and matches the staging texture's size. The context's use is guarded
        // as the module's «Threads» says. The flush hands the copy to the GPU now, so the polls
        // below see it finish rather than wait for the runtime to submit it.
        unsafe {
            self.context.CopySubresourceRegion(
                &staging,
                0,
                0,
                0,
                0,
                &last.texture,
                0,
                Some(&region),
            );
            self.context.Flush();
        }
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        let waiting = Instant::now();
        let mut busy_polls = 0u32;
        loop {
            // SAFETY: a staging texture of this device with CPU read access; `mapped` is a live
            // out slot. DO_NOT_WAIT: the call returns at once while the GPU is still on the copy.
            let result = unsafe {
                self.context.Map(
                    &staging,
                    0,
                    D3D11_MAP_READ,
                    D3D11_MAP_FLAG_DO_NOT_WAIT.0 as u32,
                    Some(&mut mapped),
                )
            };
            match result {
                Ok(()) => break,
                Err(e) if e.code() == WAS_STILL_DRAWING => {
                    busy_polls += 1;
                    let waited = waiting.elapsed();
                    if waited >= MAP_DEADLINE {
                        return Err(Failed(format!(
                            "the GPU is busy: the read-back's copy is not done after {} ms \
                             ({busy_polls} polls)",
                            waited.as_millis()
                        )));
                    }
                    std::thread::sleep(MAP_POLL);
                }
                Err(e) => return Err(Failed(format!("Map (staging {crop}): {}", error_text(&e)))),
            }
        }
        let gpu_wait = waiting.elapsed();
        let row = crop.w as usize * 4;
        let pitch = mapped.RowPitch as usize;
        let copied = if mapped.pData.is_null() || pitch < row {
            Err(Failed(format!(
                "Map gave no usable rows (pitch {pitch}, a row {row} bytes)"
            )))
        } else {
            out.clear();
            out.reserve(row * crop.h as usize);
            for y in 0..crop.h as usize {
                // SAFETY: the mapped texture holds `h` rows `pitch` apart, each at least `row`
                // bytes; it stays mapped until the `Unmap` below.
                let src = unsafe {
                    std::slice::from_raw_parts(mapped.pData.cast::<u8>().add(y * pitch), row)
                };
                out.extend_from_slice(src);
            }
            Ok(ReadBack {
                gpu_wait,
                busy_polls,
            })
        };
        // SAFETY: mapped above on this context.
        unsafe { self.context.Unmap(&staging, 0) };
        copied
    }
}

#[cfg(test)]
mod tests {
    //! On a WARP device (Windows' software rasterizer): the multithread interface is found, a
    //! region copy and the read-back keep every pixel where it was, rows unpadded, a crop outside
    //! the retained region is refused for good, and a frame retained whole gives any crop of it —
    //! the client area moved inside it included. Windows only, like the module.

    use super::*;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_WARP;
    use windows::Win32::Graphics::Direct3D11::{
        D3D11CreateDevice, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_SDK_VERSION,
        D3D11_SUBRESOURCE_DATA,
    };

    /// Pixel (x, y) of the test frame `tag`: B = x, G = y, R = tag, A = 255.
    fn pixel(x: u32, y: u32, tag: u8) -> [u8; 4] {
        [x as u8, y as u8, tag, 255]
    }

    fn warp() -> (ID3D11Device, ID3D11DeviceContext) {
        let (mut device, mut context) = (None, None);
        // SAFETY: live out slots; WARP needs no adapter or module.
        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_WARP,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .expect("a WARP device");
        (device.expect("device"), context.expect("context"))
    }

    fn frame(
        device: &ID3D11Device,
        w: u32,
        h: u32,
        tag: u8,
    ) -> (ID3D11Texture2D, D3D11_TEXTURE2D_DESC) {
        let mut data = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                data.extend_from_slice(&pixel(x, y, tag));
            }
        }
        let desc = D3D11_TEXTURE2D_DESC {
            Width: w,
            Height: h,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: 0,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let init = D3D11_SUBRESOURCE_DATA {
            pSysMem: data.as_ptr().cast(),
            SysMemPitch: w * 4,
            SysMemSlicePitch: 0,
        };
        let mut texture = None;
        // SAFETY: `init` points at `h` rows of `w * 4` bytes, alive for the call.
        unsafe { device.CreateTexture2D(&desc, Some(&init), Some(&mut texture)) }
            .expect("the test frame");
        (texture.expect("texture"), desc)
    }

    fn expect_rows(out: &[u8], crop: Crop, tag: u8) {
        assert_eq!(out.len(), (crop.w * crop.h * 4) as usize, "unpadded rows");
        for y in 0..crop.h {
            for x in 0..crop.w {
                let at = ((y * crop.w + x) * 4) as usize;
                assert_eq!(
                    &out[at..at + 4],
                    &pixel(crop.x + x, crop.y + y, tag),
                    "pixel {x},{y} of {crop}"
                );
            }
        }
    }

    /// The retained texture itself, to tell a texture made again from the same one.
    fn texture_of(r: &Retainer) -> usize {
        r.last.as_ref().expect("retained").texture.as_raw() as usize
    }

    #[test]
    fn a_retained_region_reads_back_every_pixel_in_place() {
        let (device, context) = warp();
        let mut r = Retainer::new(device.clone(), context, 0x1);
        assert!(r.protected.is_some(), "a multithread interface is found");
        // Odd widths, so the staging texture's row pitch is padded past a row.
        let (texture, desc) = frame(&device, 77, 41, 7);
        let now = Instant::now();
        let region = Crop {
            x: 5,
            y: 9,
            w: 61,
            h: 29,
        };
        assert_eq!(
            r.keep_texture(&texture, &desc, Some(region), now, false),
            Some(61 * 29 * 4)
        );
        let crop = Crop {
            x: 6,
            y: 10,
            w: 59,
            h: 27,
        };
        let mut out = Vec::new();
        r.read(crop, &mut out).expect("read back");
        expect_rows(&out, crop, 7);
        r.read(region, &mut out).expect("the whole region");
        expect_rows(&out, region, 7);
        let outside = Crop {
            x: 4,
            y: 9,
            w: 10,
            h: 10,
        };
        assert!(
            matches!(r.read(outside, &mut out), Err(ReadError::Unusable(_))),
            "outside the region"
        );

        // No crop known (a new size): the whole frame, and any crop of it reads back.
        assert_eq!(
            r.keep_texture(&texture, &desc, None, now, true),
            Some(77 * 41 * 4)
        );
        assert!(matches!(
            r.last(),
            LastFrame::Kept {
                size: (77, 41),
                in_hold: true,
                ..
            }
        ));
        r.read(outside, &mut out).expect("inside the whole frame");
        expect_rows(&out, outside, 7);

        // A region not inside the frame is taken as the whole frame.
        let past = Crop {
            x: 70,
            y: 0,
            w: 10,
            h: 10,
        };
        assert_eq!(
            r.keep_texture(&texture, &desc, Some(past), now, false),
            Some(77 * 41 * 4)
        );
    }

    /// A held frame retained by an earlier frame's crop (a handler that crops before retaining):
    /// the menu removed during the hold moves the client area up inside a frame of the same size,
    /// and the crop read after the hold is not inside the kept region — refused as unusable, so
    /// the resend gives up at once rather than retry what cannot change.
    #[test]
    fn a_crop_moved_outside_the_kept_region_is_refused_for_good() {
        let (device, context) = warp();
        let mut r = Retainer::new(device.clone(), context, 0x1);
        let (texture, desc) = frame(&device, 80, 60, 1);
        // Title bar and menu above the client area.
        let before = Crop {
            x: 4,
            y: 20,
            w: 72,
            h: 36,
        };
        assert!(r
            .keep_texture(&texture, &desc, Some(before), Instant::now(), true)
            .is_some());
        // The menu gone: the client area starts higher and is taller.
        let after = Crop {
            x: 4,
            y: 12,
            w: 72,
            h: 44,
        };
        let mut out = Vec::new();
        match r.read(after, &mut out) {
            Err(ReadError::Unusable(why)) => assert!(why.contains("not inside"), "{why}"),
            other => panic!("refused as unusable: {other:?}"),
        }
    }

    /// Frames retained whole (held, paced out, refused) and frames retained by their crop share
    /// one texture of the frame's size, never made again between them; the last whole frame gives
    /// the moved client area exactly, and a cropped frame after it narrows what is retained to its
    /// own crop, of its own pixels.
    #[test]
    fn a_frame_retained_whole_gives_a_moved_crop() {
        let (device, context) = warp();
        let mut r = Retainer::new(device.clone(), context, 0x1);
        let (sent, desc) = frame(&device, 80, 60, 1);
        let (held, _) = frame(&device, 80, 60, 2);
        let before = Crop {
            x: 4,
            y: 20,
            w: 72,
            h: 36,
        };
        let now = Instant::now();
        // A frame sent before the hold, cropped on the live path.
        assert_eq!(
            r.keep_texture(&sent, &desc, Some(before), now, false),
            Some(72 * 36 * 4)
        );
        let made = texture_of(&r);
        // A held frame, after the menu went: retained whole.
        assert_eq!(
            r.keep_texture(&held, &desc, None, now, true),
            Some(80 * 60 * 4)
        );
        assert_eq!(texture_of(&r), made, "the same texture for a whole frame");
        let after = Crop {
            x: 4,
            y: 12,
            w: 72,
            h: 44,
        };
        let mut out = Vec::new();
        r.read(after, &mut out)
            .expect("the moved crop of the whole frame");
        expect_rows(&out, after, 2);

        // A cropped frame again: the same texture, and only its crop is retained.
        let (next, _) = frame(&device, 80, 60, 3);
        assert_eq!(
            r.keep_texture(&next, &desc, Some(after), now, false),
            Some(72 * 44 * 4)
        );
        assert_eq!(texture_of(&r), made, "the same texture for a crop");
        r.read(after, &mut out).expect("its own crop");
        expect_rows(&out, after, 3);
        let whole = Crop {
            x: 0,
            y: 0,
            w: 80,
            h: 60,
        };
        assert!(
            matches!(r.read(whole, &mut out), Err(ReadError::Unusable(_))),
            "the rest of the texture is an older frame's"
        );

        // A new frame size makes the texture again (the old one kept alive here, so the new one
        // cannot take its address).
        let old = r.last.as_ref().expect("retained").texture.clone();
        let (bigger, bigger_desc) = frame(&device, 96, 60, 4);
        assert!(r
            .keep_texture(&bigger, &bigger_desc, None, now, true)
            .is_some());
        assert_ne!(texture_of(&r), made, "a new size, a new texture");
        drop(old);
    }
}
