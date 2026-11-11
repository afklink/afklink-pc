//! Natural content: a video playing in a browser page or full screen, and a game.
//!
//! Frames come from real recordings decoded by mpv (software decode, deterministic), composed at
//! the panel's full resolution the way the screen would show them, then scaled by the capturer's
//! own `Scaler` to the top rung (1620x1080) before storing. See the crate docs for why natural
//! content is stored at that size and text is not.
//!
//! Timing: a 30 fps video on a 60 Hz desktop is presented on every vsync, so WGC delivers 60 frames
//! a second of which every second one repeats the picture (an agent log shows 48-62 offered while
//! video plays); those are `REPEAT` records. A game renders a new picture every vsync.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use afklink_core::scale::Scaler;
use anyhow::{bail, ensure, Context, Result};
use serde::Serialize;

use super::emit::Emitter;
use super::html::{self, VIDEO_PLAYER};
use super::image::{rgb, Image};
use super::scene::{self, Ctx, Rect, JITTER_US, SOURCE_H, SOURCE_W, TOP_RUNG_H};
use crate::format::{Scaling, Summary};
use crate::motion::Vsync;
use crate::rng::Rng;
use crate::writer::WriterOptions;

/// Locate mpv: `$AFKLINK_CORPUS_MPV`, then `mpv.com`/`mpv.exe` on PATH, then scoop's default.
pub fn locate_mpv() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("AFKLINK_CORPUS_MPV") {
        return Ok(PathBuf::from(p));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path) {
        for exe in ["mpv.com", "mpv.exe"] {
            let p = dir.join(exe);
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        let p = PathBuf::from(home).join(r"scoop\apps\mpv-git\current\mpv.com");
        if p.is_file() {
            return Ok(p);
        }
    }
    bail!("mpv not found: install it (scoop install mpv) or set AFKLINK_CORPUS_MPV")
}

/// Raw BGRA frames streamed from an mpv decode.
pub struct MpvFrames {
    child: Child,
    stdout: ChildStdout,
    pub w: u32,
    pub h: u32,
    pub read: u64,
}

impl MpvFrames {
    /// Decode `seconds` of `file` from `start_s`, through the libavfilter chain `vf` (which must
    /// produce `w x h`), as BGRA.
    pub fn spawn(
        file: &Path,
        start_s: f64,
        seconds: f64,
        vf: &str,
        w: u32,
        h: u32,
    ) -> Result<Self> {
        ensure!(file.is_file(), "video {} not found", file.display());
        let mpv = locate_mpv()?;
        let vf = if vf.is_empty() {
            "format=bgra".to_string()
        } else {
            format!("{vf},format=bgra")
        };
        let mut cmd = Command::new(&mpv);
        cmd.args([
            "--no-config",
            "--really-quiet",
            "--audio=no",
            "--sub=no",
            "--hwdec=no",
            &format!("--start={start_s}"),
            &format!("--length={seconds}"),
            &format!("--vf={vf}"),
            "--of=rawvideo",
            "--ovc=rawvideo",
            "--o=-",
        ])
        .arg(file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("start {}", mpv.display()))?;
        let stdout = child.stdout.take().context("mpv stdout")?;
        tracing::debug!(
            mpv = %mpv.display(),
            file = %file.display(),
            start_s,
            seconds,
            vf = %vf,
            w,
            h,
            "mpv decode started"
        );
        Ok(Self {
            child,
            stdout,
            w,
            h,
            read: 0,
        })
    }

    /// The next frame into `buf`; `false` at the end of the stream.
    pub fn next_frame(&mut self, buf: &mut Vec<u8>) -> Result<bool> {
        let n = self.w as usize * self.h as usize * 4;
        buf.resize(n, 0);
        let mut at = 0;
        while at < n {
            match self.stdout.read(&mut buf[at..]) {
                Ok(0) => break,
                Ok(k) => at += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e).context("read from mpv"),
            }
        }
        if at == 0 {
            tracing::debug!(frames = self.read, "mpv stream ended");
            return Ok(false);
        }
        ensure!(at == n, "mpv ended inside a frame ({at} of {n} bytes)");
        self.read += 1;
        Ok(true)
    }
}

impl Drop for MpvFrames {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                if let Err(e) = self.child.kill() {
                    tracing::debug!("mpv already gone when stopping it: {e}");
                }
                let _ = self.child.wait();
            }
        }
    }
}

/// How the video is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layout {
    /// In a video site's player, in the browser.
    Windowed,
    /// Full screen, 16:9 letterboxed on the 3:2 panel.
    Fullscreen,
    /// A game at the panel's native resolution: a new picture every vsync.
    Game,
}

#[derive(Debug, Clone, Serialize)]
pub struct VideoSpec {
    pub name: String,
    pub layout: Layout,
    pub file: PathBuf,
    pub start_s: f64,
    pub seconds: f64,
    /// Content frame rate (video: 30; game: the display's 60).
    pub content_fps: f64,
    /// Deliver the repeated vsyncs of a slower video as REPEAT frames.
    pub duplicates: bool,
    pub seed: u64,
    /// Source frame size as decoded (checked against mpv's output size).
    pub source_w: u32,
    pub source_h: u32,
}

pub fn generate(ctx: &mut Ctx, spec: &VideoSpec) -> Result<Summary> {
    let hz = scene::DISPLAY_HZ;
    let vsync = Vsync { hz };
    let repeat = (hz / spec.content_fps).round().max(1.0) as u64;
    ensure!(
        (hz / repeat as f64 - spec.content_fps).abs() < 0.5,
        "content at {} fps does not divide the {hz} Hz display; only integer cadences are modelled",
        spec.content_fps
    );

    // The full-resolution screen and where the video sits in it.
    let (mut screen, place, vf) = match spec.layout {
        Layout::Windowed => {
            let walls = scene::wallpapers();
            let thumbs: Vec<&Path> = walls.iter().map(PathBuf::as_path).collect();
            let page = ctx.edge()?.screenshot(
                &format!("{}-page", spec.name),
                &html::video_page(&thumbs),
                html::SCREEN_W,
                html::SCREEN_H,
                false,
            )?;
            let p = Rect::from_css(VIDEO_PLAYER);
            (
                page,
                p,
                format!("fps={},scale={}:{}", spec.content_fps, p.w, p.h),
            )
        }
        Layout::Fullscreen => {
            // 16:9 of the panel width, rounded down to even: mpv's raw encoder refuses odd
            // heights (2025 produced no frames at all).
            let h = (i64::from(SOURCE_W) * 9 / 16) & !1;
            let p = Rect {
                x: 0,
                y: (i64::from(SOURCE_H) - h) / 2,
                w: i64::from(SOURCE_W),
                h,
            };
            (
                Image::new(SOURCE_W, SOURCE_H, rgb(0x000000)),
                p,
                format!("fps={},scale={}:{}", spec.content_fps, p.w, p.h),
            )
        }
        Layout::Game => {
            ensure!(
                spec.source_w == SOURCE_W && spec.source_h == SOURCE_H,
                "a game recording must be at the panel's {SOURCE_W}x{SOURCE_H}, got {}x{}",
                spec.source_w,
                spec.source_h
            );
            (
                Image::new(SOURCE_W, SOURCE_H, rgb(0x000000)),
                Rect {
                    x: 0,
                    y: 0,
                    w: i64::from(SOURCE_W),
                    h: i64::from(SOURCE_H),
                },
                if (spec.content_fps - hz).abs() < 0.5 {
                    String::new()
                } else {
                    format!("fps={}", spec.content_fps)
                },
            )
        }
    };
    let mut decoder = MpvFrames::spawn(
        &spec.file,
        spec.start_s,
        spec.seconds,
        &vf,
        place.w as u32,
        place.h as u32,
    )?;

    let (stored_w, stored_h) =
        afklink_core::scale::fit_within(SOURCE_W, SOURCE_H, u32::MAX / 2, TOP_RUNG_H);
    let description = match spec.layout {
        Layout::Windowed => format!(
            "A {:.0} fps cinematic cutscene playing in a video site's 1280x720 CSS player inside the browser \
             (about 44% of the screen), 60 Hz deliveries with every other one a repeat. Stored at {stored_w}x{stored_h}.",
            spec.content_fps
        ),
        Layout::Fullscreen => format!(
            "The same {:.0} fps cutscene full screen, 16:9 letterboxed on the 3:2 panel, 60 Hz deliveries with repeats. \
             Stored at {stored_w}x{stored_h}.",
            spec.content_fps
        ),
        Layout::Game => format!(
            "A third-person game at the panel's native 3600x2400, a new picture every vsync ({:.0} fps). \
             Stored at {stored_w}x{stored_h}.",
            spec.content_fps
        ),
    };
    let meta = scene::synthetic_meta(
        &spec.name,
        &description,
        "video",
        spec.seed,
        serde_json::json!({ "spec": spec, "mpv_vf": vf, "placement": [place.x, place.y, place.w, place.h] }),
        vec![format!(
            "{} from {:.1} s for {:.1} s",
            spec.file.display(),
            spec.start_s,
            spec.seconds
        )],
        (stored_w, stored_h),
        Scaling::Scaler { max_h: TOP_RUNG_H },
        JITTER_US,
        spec.duplicates && repeat > 1,
        vec![
            "Decoded from a lossy recording (AMD ReLive, AV1/HEVC): its own compression is part of the picture.".into(),
            "Player scaling is libswscale bicubic (mpv), standing in for the browser's GPU scaler.".into(),
            format!(
                "Stored already scaled by afklink_core::scale::Scaler to the {TOP_RUNG_H}p rung; lower rungs rescale from it (see the crate docs)."
            ),
        ],
    );
    let mut rng = Rng::new(spec.seed ^ 0x71de0);
    let mut emitter = Emitter::create(
        &ctx.out_path(&spec.name),
        &meta,
        WriterOptions::default(),
        vsync,
        rng.fork(1),
    )?;

    let mut scaler = Scaler::new();
    let mut decoded = Vec::new();
    let mut stored = Vec::new();
    let mut video = Image::new(place.w as u32, place.h as u32, rgb(0));
    let total = vsync.count(spec.seconds);
    let mut k = 0u64;
    while k < total && decoder.next_frame(&mut decoded)? {
        std::mem::swap(&mut video.px, &mut decoded);
        screen.blit(&video, 0, 0, place.w, place.h, place.x, place.y);
        let (w, h) = scaler
            .fit_into(
                &screen.px,
                SOURCE_W,
                SOURCE_H,
                u32::MAX / 2,
                TOP_RUNG_H,
                &mut stored,
            )
            .context("scale to the top rung")?;
        ensure!((w, h) == (stored_w, stored_h), "scaled to {w}x{h}");
        for r in 0..repeat {
            if k >= total {
                break;
            }
            if r == 0 || spec.duplicates {
                emitter.deliver(k, &stored, &[])?;
            }
            k += 1;
        }
    }
    if k < total {
        tracing::warn!(
            scenario = %spec.name,
            vsyncs = k,
            wanted = total,
            "the video ended before the scenario did; the rest is a still picture"
        );
    }
    emitter.finish(scene::us(spec.seconds))
}
