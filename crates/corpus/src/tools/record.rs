//! Live recorder: the primary monitor through the project's own WGC capturer, into a corpus file.
//!
//! Run only with the user's agreement — it records whatever is on the screen. It sends no input
//! and opens no window; stop it with `--seconds` or by creating the file `<out>.stop`.
//!
//! The capturer is `afklink_capture::WgcCapturer` with a target that admits every delivery (a
//! 1000 fps "rung", so the pacing gate never holds a frame back) and, by default, no scaling. Each
//! frame is timestamped when the recorder receives it from the capture thread, microseconds from
//! the first frame: the capture thread's copy sits between WGC and that instant, a near-constant
//! few milliseconds. While the screen is still WGC delivers nothing and the file keeps the gap.
//!
//! Full resolution is 35 MB a frame. The writer runs on its own thread behind a bounded queue; if it
//! falls behind (full-screen video at 60 Hz can outrun it), deliveries are dropped and counted in the
//! summary rather than blocking the capture. `--max-h 1080` stores what the top rung would see
//! instead, which keeps up with anything.

use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_core::quality::{QualityTarget, Rung};
use afklink_core::traits::Capturer;
use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::format::{
    CodecInfo, Metadata, Origin, Scaling, SourceInfo, StoredInfo, Summary, TimingInfo,
    FORMAT_VERSION, PIXEL_FORMAT_BGRA8,
};
use crate::writer::{Writer, WriterOptions};

#[derive(Debug, Clone, Serialize)]
pub struct RecordSpec {
    pub out: PathBuf,
    pub scenario: String,
    pub description: String,
    pub seconds: f64,
    /// Store frames scaled to this height by the capturer (`None`: full resolution).
    pub max_h: Option<u32>,
    pub zstd_level: i32,
    pub zstd_workers: u32,
    /// Memory the queue in front of the writer may hold before deliveries are dropped.
    pub queue_mb: u64,
    /// Display refresh, for the metadata.
    pub display_hz: f64,
    pub scale_factor: f64,
}

pub fn record(spec: &RecordSpec) -> Result<Summary> {
    let stop_file = spec.out.with_extension("stop");
    let _ = std::fs::remove_file(&stop_file);
    let target = Arc::new(QualityTarget::new(Rung {
        max_h: spec.max_h.unwrap_or(8640),
        fps: 1000,
    }));
    let (tx, rx) = mpsc::channel();
    let mut capturer = afklink_capture::WgcCapturer::new();
    capturer
        .start(tx, target.clone())
        .context("start WGC capture")?;
    tracing::info!(
        out = %spec.out.display(),
        seconds = spec.seconds,
        max_h = ?spec.max_h,
        stop_file = %stop_file.display(),
        "recording the primary monitor"
    );

    // WGC hands over the current picture as soon as capture starts.
    let first = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(f) => f,
        Err(e) => {
            capturer.stop();
            bail!("no frame from WGC within 10 s: {e}");
        }
    };
    let t0 = Instant::now();
    let (src_w, src_h) = target.source().unwrap_or((first.width, first.height));
    let scaling = if (first.width, first.height) == (src_w, src_h) {
        Scaling::Native
    } else {
        Scaling::Scaler {
            max_h: spec.max_h.unwrap_or(first.height),
        }
    };
    let meta = Metadata {
        format_version: FORMAT_VERSION,
        scenario: spec.scenario.clone(),
        description: spec.description.clone(),
        created_utc: crate::format::now_rfc3339(),
        source: SourceInfo {
            width: src_w,
            height: src_h,
            display_hz: spec.display_hz,
            scale_factor: spec.scale_factor,
        },
        stored: StoredInfo {
            width: first.width,
            height: first.height,
            pixel_format: PIXEL_FORMAT_BGRA8.into(),
            scaling,
        },
        origin: Origin::Recorded {
            tool: "afklink-corpus record (afklink_capture::WgcCapturer, cursor included)".into(),
            note: String::new(),
        },
        timing: TimingInfo {
            clock: "wgc_receipt".into(),
            jitter_us: 0,
            duplicates: true,
        },
        codec: CodecInfo {
            tile: 0,
            zstd_level: 0,
            key_interval_us: 0,
        },
        notes: vec![
            "Timestamps are when the recorder received each frame from the capture thread.".into(),
        ],
    };
    let opts = WriterOptions {
        zstd_level: spec.zstd_level,
        zstd_workers: spec.zstd_workers,
        // Live: no second trial encode per frame.
        key_trial_fraction: 2.0,
        ..WriterOptions::default()
    };
    let mut writer = Writer::create(&spec.out, &meta, opts)?;
    let frame_bytes = first.data.len() as u64;
    let depth = ((spec.queue_mb << 20) / frame_bytes.max(1)).max(2) as usize;
    let (qtx, qrx) = mpsc::sync_channel::<(u64, Vec<u8>)>(depth);
    let worker = std::thread::Builder::new()
        .name("corpus-writer".into())
        .spawn(move || -> Result<Writer> {
            while let Ok((t, data)) = qrx.recv() {
                writer.push(t, &data, &[])?;
            }
            Ok(writer)
        })
        .context("spawn writer thread")?;
    tracing::debug!(depth, frame_mb = frame_bytes >> 20, "writer queue sized");

    let mut dropped = 0u64;
    let mut delivered = 0u64;
    let mut last_t = 0u64;
    // `move`, so dropping the closure closes the queue and lets the writer thread finish.
    let send = move |t: u64, data: Vec<u8>, dropped: &mut u64| -> Result<()> {
        match qtx.try_send((t, data)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                *dropped += 1;
                if *dropped == 1 || dropped.is_multiple_of(100) {
                    tracing::warn!(
                        dropped = *dropped,
                        "the writer is behind; dropping deliveries"
                    );
                }
                Ok(())
            }
            Err(TrySendError::Disconnected(_)) => bail!("the writer thread stopped"),
        }
    };
    send(0, first.data, &mut dropped)?;
    delivered += 1;
    let deadline = Duration::from_secs_f64(spec.seconds);
    let mut last_check = Instant::now();
    let outcome: Result<()> = loop {
        if t0.elapsed() >= deadline {
            break Ok(());
        }
        if stop_file.exists() {
            tracing::info!("stop file found; ending the recording");
            break Ok(());
        }
        if last_check.elapsed() >= Duration::from_millis(500) {
            last_check = Instant::now();
            if let Err(e) = capturer.check() {
                break Err(e.context("capture ended during the recording"));
            }
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(f) => {
                let mut t = t0.elapsed().as_micros() as u64;
                if t <= last_t {
                    t = last_t + 1;
                }
                last_t = t;
                delivered += 1;
                if let Err(e) = send(t, f.data, &mut dropped) {
                    break Err(e);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                break Err(anyhow::anyhow!("capture channel closed"))
            }
        }
    };
    capturer.stop();
    drop(send);
    let duration = t0.elapsed().as_micros() as u64;
    let mut writer = worker
        .join()
        .map_err(|_| anyhow::anyhow!("writer thread panicked"))??;
    writer.note_dropped(dropped);
    let summary = writer.finish(duration.max(last_t))?;
    tracing::info!(
        delivered,
        dropped,
        stored = summary.frame_count,
        seconds = duration as f64 / 1e6,
        "recording finished"
    );
    outcome?;
    Ok(summary)
}
