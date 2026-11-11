//! `--capture-corpus`: a [`Capturer`] that plays a screen-content corpus file instead of capturing
//! the screen.
//!
//! It stands in for `afklink_capture::WgcCapturer` and behaves like it from the pipeline's side:
//!
//! * **Real time.** Each recorded delivery is handed over at its recorded timestamp (from the first
//!   frame on); an idle gap in the recording is an idle gap here — WGC delivers nothing while the
//!   screen is still, and neither does this. A frame is decoded while waiting for its instant.
//!   Inter frames decode in about a millisecond at 3600x2400, but a key frame takes 50-60 ms —
//!   three display periods — so key frames are decoded *ahead* by a second reader on a helper
//!   thread and swapped in when playback reaches them ([`Prefetch`]); otherwise every key frame
//!   (every 10 s in the shipped corpus) would arrive 35-40 ms late and take the next frame's slot.
//! * **The same pacing and scaling.** Every delivery goes through exactly what
//!   `wgc::Handler::on_frame_arrived` does with one: `note_offered`, the deadline pacer
//!   (`afklink_capture::pace::admit`, the same function) with `note_early` for a frame before its
//!   slot, `set_source` with the recorded screen's size (`metadata().source`), and a scale to the
//!   rung's height read fresh per frame (`afklink_corpus::fit_for_rung`, the capturer's own
//!   `Scaler` call). A rung change reaches the pixels on the next frame, as with WGC.
//! * **`REPEAT` records are re-deliveries.** WGC offers a frame whose picture did not change (a
//!   30 fps video on a 60 Hz desktop); so does this, with the same picture, through the same pacer.
//! * **Loops.** At the end of the recording (its full duration, a still tail included) playback
//!   starts again from the beginning, timestamps continuing.
//! * **`check()`** says the capture ended when the playback thread has stopped without being asked
//!   (an unreadable file, a consumer that went away), as the WGC capturer does for its thread.
//!
//! Logging: start (info, with the recording's facts), each loop (info, with that loop's counts),
//! each size change (debug, like the WGC capturer), a count every [`SUMMARY_EVERY`] (debug), each
//! delivery (trace).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use afklink_capture::pace::{self, Admission};
use afklink_core::quality::QualityTarget;
use afklink_core::scale::Scaler;
use afklink_core::traits::Capturer;
use afklink_core::types::Frame;
use afklink_corpus::{fit_for_rung, FrameKind, Reader};
use anyhow::{anyhow, Context, Result};

/// The longest the playback thread sleeps before looking at its stop flag.
const STOP_POLL: Duration = Duration::from_millis(20);

/// A delivery later than this behind its recorded instant counts as late.
const LATE: Duration = Duration::from_millis(4);

/// How often the running count is logged.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(10);

/// See the module documentation.
pub struct CorpusCapturer {
    path: PathBuf,
    running: Option<Running>,
    starts: u64,
}

struct Running {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<Result<Ended>>,
}

/// Why the playback thread ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// Asked to, by `stop`.
    Stopped,
    /// The frame receiver went away (the session's encode side is gone).
    ConsumerGone,
}

impl CorpusCapturer {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            running: None,
            starts: 0,
        }
    }

    /// Open the file once and describe it, so a bad path or a damaged file stops the agent at
    /// startup rather than at the first session.
    pub fn probe(path: &Path) -> Result<String> {
        let reader =
            Reader::open(path).with_context(|| format!("open corpus {}", path.display()))?;
        let meta = reader.metadata();
        let summary = reader.summary();
        anyhow::ensure!(
            summary.is_none_or(|s| s.frame_count > 0),
            "corpus {} has no frames",
            path.display()
        );
        Ok(format!(
            "scenario {} ({}), source {}x{} at {} Hz, stored {}x{} {:?}, {} frames ({} repeats) \
             over {} ms{}",
            meta.scenario,
            meta.description,
            meta.source.width,
            meta.source.height,
            meta.source.display_hz,
            meta.stored.width,
            meta.stored.height,
            meta.stored.scaling,
            summary.map_or_else(|| "?".to_string(), |s| s.frame_count.to_string()),
            summary.map_or_else(|| "?".to_string(), |s| s.repeat_frames.to_string()),
            reader
                .duration_us()
                .map_or_else(|| "?".to_string(), |d| (d / 1000).to_string()),
            if summary.is_none() {
                "; truncated file, played up to the damage"
            } else {
                ""
            }
        ))
    }
}

impl Capturer for CorpusCapturer {
    fn start(&mut self, sink: Sender<Frame>, target: Arc<QualityTarget>) -> Result<()> {
        if self.running.is_some() {
            tracing::debug!("corpus capture started while running: stopping the previous playback");
            self.stop();
        }
        let reader = Reader::open(&self.path)
            .with_context(|| format!("open corpus {}", self.path.display()))?;
        let meta = reader.metadata().clone();
        self.starts += 1;
        tracing::info!(
            path = %self.path.display(),
            scenario = %meta.scenario,
            source = %format!("{}x{}", meta.source.width, meta.source.height),
            stored = %format!("{}x{}", meta.stored.width, meta.stored.height),
            scaling = ?meta.stored.scaling,
            frames = reader.summary().map(|s| s.frame_count),
            duration_ms = reader.duration_us().map(|d| d / 1000),
            start = self.starts,
            "starting corpus playback in place of screen capture (real time, looping)"
        );
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = stop.clone();
            let path = self.path.clone();
            std::thread::Builder::new()
                .name("capture-corpus".into())
                .spawn(move || play(reader, &path, &sink, &target, &stop))
                .context("spawn the corpus playback thread")?
        };
        self.running = Some(Running { stop, thread });
        Ok(())
    }

    fn stop(&mut self) {
        let Some(running) = self.running.take() else {
            tracing::trace!("corpus capture stop: not running");
            return;
        };
        running.stop.store(true, Ordering::Release);
        match running.thread.join() {
            Ok(Ok(ended)) => tracing::debug!(?ended, "corpus playback stopped"),
            Ok(Err(e)) => tracing::debug!("corpus playback had already failed: {e:#}"),
            Err(_) => tracing::warn!("corpus playback thread panicked"),
        }
    }

    fn check(&mut self) -> Result<()> {
        match self.running.take() {
            Some(running) if running.thread.is_finished() => Err(match running.thread.join() {
                Ok(Ok(Ended::Stopped)) => anyhow!("corpus playback stopped"),
                Ok(Ok(Ended::ConsumerGone)) => anyhow!(
                    "corpus playback ended without being stopped (the frame consumer went away)"
                ),
                Ok(Err(e)) => e.context("corpus playback failed"),
                Err(_) => anyhow!("corpus playback thread panicked"),
            }),
            Some(running) => {
                self.running = Some(running);
                Ok(())
            }
            None => Err(anyhow!("corpus playback is not running")),
        }
    }
}

impl Drop for CorpusCapturer {
    /// A capturer dropped without `stop` must not leave a playback thread feeding a channel
    /// forever.
    fn drop(&mut self) {
        if self.running.is_some() {
            tracing::debug!("corpus capturer dropped while playing; stopping it");
            self.stop();
        }
    }
}

/// Counts for a loop or a summary window.
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    read: u64,
    delivered: u64,
    repeats: u64,
    early: u64,
    late: u64,
    max_late: Duration,
}

impl Counts {
    fn note_late(&mut self, late: Duration) {
        if late > LATE {
            self.late += 1;
        }
        self.max_late = self.max_late.max(late);
    }

    fn add(&mut self, f: impl Fn(&mut Counts)) {
        f(self);
    }
}

/// Sleep until `due`, looking at `stop` at least every [`STOP_POLL`]. `false` when stopped.
fn sleep_until(due: Instant, stop: &AtomicBool) -> bool {
    loop {
        if stop.load(Ordering::Acquire) {
            return false;
        }
        let now = Instant::now();
        if now >= due {
            return true;
        }
        // `thread::sleep` is a high-resolution wait on Windows: the recorded cadence survives.
        std::thread::sleep((due - now).min(STOP_POLL));
    }
}

/// Key frames decoded ahead by a second reader on a helper thread.
///
/// The playback reader and the spare trade places at every key frame: the spare, already seeked to
/// the key (its `current()` is that frame, decoded), becomes the playback reader, and the old one
/// goes to the helper to be seeked to the next key. The keys come from the file's index and are
/// used cyclically — after the last one, the first again, for the next loop. A key frame costs
/// 50-60 ms to decode at 3600x2400 and the helper has the whole stretch between two keys (10 s in
/// the shipped corpus) to do it.
struct Prefetch {
    /// `(frame index, t_us)` of every key frame, in file order.
    keys: Vec<(u64, u64)>,
    jobs: Sender<(Reader, usize)>,
    done: Receiver<Result<(Reader, usize)>>,
    /// The key the helper is preparing, or has prepared, as a position in `keys`.
    slot: usize,
}

impl Prefetch {
    /// Open the spare reader and start preparing the key after the first (the playback reader
    /// decodes the first itself).
    fn start(path: &Path, keys: Vec<(u64, u64)>) -> Result<Self> {
        anyhow::ensure!(!keys.is_empty(), "no key frames in the index");
        let spare = Reader::open(path)
            .with_context(|| format!("open a second reader on {}", path.display()))?;
        let (jobs, job_rx) = mpsc::channel::<(Reader, usize)>();
        let (done_tx, done) = mpsc::channel::<Result<(Reader, usize)>>();
        let helper_keys = keys.clone();
        std::thread::Builder::new()
            .name("capture-corpus-prefetch".into())
            .spawn(move || {
                while let Ok((mut reader, slot)) = job_rx.recv() {
                    let (index, t_us) = helper_keys[slot];
                    let started = Instant::now();
                    let landed = reader.seek(t_us).map(|f| f.map(|f| (f.index, f.t_us)));
                    let result = match landed {
                        Ok(Some((i, t))) if i == index && t == t_us => {
                            tracing::debug!(
                                slot,
                                key_t_ms = t_us / 1000,
                                took_ms = started.elapsed().as_millis() as u64,
                                "corpus key frame decoded ahead"
                            );
                            Ok((reader, slot))
                        }
                        Ok(other) => Err(anyhow!(
                            "seeking to the key frame {index} at {t_us} us landed on {other:?}"
                        )),
                        Err(e) => Err(e.context(format!("decode the key frame at {t_us} us"))),
                    };
                    if done_tx.send(result).is_err() {
                        break;
                    }
                }
                tracing::debug!("corpus key-frame prefetch helper stopped");
            })
            .context("spawn the corpus prefetch thread")?;
        let slot = 1 % keys.len();
        jobs.send((spare, slot))
            .map_err(|_| anyhow!("the corpus prefetch helper is gone"))?;
        // not-a-key-name: a count of key frames
        tracing::debug!(
            keys = keys.len(),
            first_key_t_ms = keys[slot].1 / 1000,
            "corpus key frames are decoded ahead by a second reader"
        );
        Ok(Self {
            keys,
            jobs,
            done,
            slot,
        })
    }

    /// Whether the frame with this index is the key being prepared.
    fn is_next(&self, index: u64) -> bool {
        self.keys[self.slot].0 == index
    }

    /// The reader positioned at the prepared key, waiting for the helper if it is not done yet.
    fn take_ready(&mut self) -> Result<Reader> {
        let asked = Instant::now();
        let (ready, slot) = self
            .done
            .recv()
            .map_err(|_| anyhow!("the corpus prefetch helper is gone"))??;
        let waited = asked.elapsed();
        if waited > Duration::from_millis(1) {
            tracing::debug!(
                slot,
                waited_ms = waited.as_millis() as u64,
                "waited for a key frame decoded ahead (keys closer together than its decode time)"
            );
        }
        Ok(ready)
    }

    /// Hand the reader that played up to this key to the helper, for the next key.
    fn hand_back(&mut self, old: Reader) -> Result<()> {
        self.slot = (self.slot + 1) % self.keys.len();
        self.jobs
            .send((old, self.slot))
            .map_err(|_| anyhow!("the corpus prefetch helper is gone"))
    }
}

/// The playback thread.
fn play(
    mut reader: Reader,
    path: &Path,
    sink: &Sender<Frame>,
    target: &QualityTarget,
    stop: &AtomicBool,
) -> Result<Ended> {
    let (src_w, src_h) = (
        reader.metadata().source.width,
        reader.metadata().source.height,
    );
    // One display period: the least a loop may add after its last frame, so the first frame of
    // the next loop never lands on the same instant as the last of this one.
    let period_us = (1e6 / reader.metadata().source.display_hz.max(1.0)) as u64;
    let keys: Vec<(u64, u64)> = reader.summary().map_or_else(Vec::new, |s| {
        s.key_index.iter().map(|k| (k.index, k.t_us)).collect()
    });
    let mut prefetch = if keys.is_empty() {
        tracing::debug!("no key frame index (a truncated file): key frames are decoded in line");
        None
    } else {
        match Prefetch::start(path, keys) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!(
                    "corpus key frames will not be decoded ahead ({e:#}); each will arrive late by \
                     its decode time"
                );
                None
            }
        }
    };
    // Frame timestamps count from the capture's start, as the WGC capturer's do.
    let capture_start = Instant::now();
    // The recording's clock, anchored when the first frame is decoded, so decoding it does not
    // make it late.
    let mut epoch: Option<Instant> = None;
    // The index of the frame the playback reader would return next; `None` before the first.
    let mut next_index: Option<u64> = None;
    let mut scaler = Scaler::new();
    let mut next_due: Option<Instant> = None;
    let mut offset_us: u64 = 0;
    let mut loops: u64 = 0;
    let mut last_t_us: u64 = 0;
    let mut last_scaled: Option<(u32, u32)> = None;
    let mut this_loop = Counts::default();
    let mut window = Counts::default();
    let mut window_start = Instant::now();
    loop {
        let mut swapped = false;
        if let (Some(p), Some(i)) = (prefetch.as_mut(), next_index) {
            if p.is_next(i) {
                let ready = p.take_ready()?;
                let old = std::mem::replace(&mut reader, ready);
                p.hand_back(old)?;
                swapped = true;
            }
        }
        let frame = if swapped {
            reader
                .current()
                .ok_or_else(|| anyhow!("the reader decoded ahead holds no frame"))?
        } else {
            let Some(frame) = reader
                .next_frame()
                .with_context(|| format!("read {}", path.display()))?
            else {
                anyhow::ensure!(
                    this_loop.read > 0,
                    "corpus {} has no frames to play",
                    path.display()
                );
                let duration = reader
                    .summary()
                    .map_or(last_t_us, |s| s.duration_us)
                    .max(last_t_us + period_us);
                loops += 1;
                tracing::info!(
                    loop_n = loops,
                    duration_ms = duration / 1000,
                    truncated = reader.is_truncated(),
                    read = this_loop.read,
                    delivered = this_loop.delivered,
                    repeats = this_loop.repeats,
                    early = this_loop.early,
                    late = this_loop.late,
                    max_late_ms = this_loop.max_late.as_millis() as u64,
                    "corpus playback reached the end of the recording; looping from the start"
                );
                offset_us += duration;
                this_loop = Counts::default();
                next_index = Some(0);
                // The first frame of the next loop is a key frame: decoded ahead when there is a
                // helper preparing it, read from the start otherwise.
                if !prefetch.as_ref().is_some_and(|p| p.is_next(0)) {
                    reader
                        .rewind()
                        .with_context(|| format!("rewind {}", path.display()))?;
                }
                continue;
            };
            frame
        };
        let (t_us, kind) = (frame.t_us, frame.kind);
        next_index = Some(frame.index + 1);
        last_t_us = t_us;
        this_loop.read += 1;
        window.read += 1;

        let epoch = *epoch.get_or_insert_with(|| {
            let now = Instant::now();
            now.checked_sub(Duration::from_micros(t_us)).unwrap_or(now)
        });
        let due = epoch + Duration::from_micros(offset_us + t_us);
        if !sleep_until(due, stop) {
            return Ok(Ended::Stopped);
        }
        let now = Instant::now();
        let late = now.saturating_duration_since(due);
        this_loop.note_late(late);
        window.note_late(late);

        // From here on, exactly what `wgc::Handler::on_frame_arrived` does with a delivery.
        target.note_offered();
        let interval = target.min_frame_interval();
        let (decision, due_next) = pace::admit(now, next_due, interval);
        next_due = Some(due_next);
        if decision == Admission::Early {
            target.note_early();
            this_loop.early += 1;
            window.early += 1;
            tracing::trace!(
                t_us,
                "corpus delivery before its slot; held back by the pacer"
            );
        } else {
            target.set_source(src_w, src_h);
            let max_h = target.max_h();
            let mut pixels = Vec::new();
            let (w, h) = fit_for_rung(&frame, max_h, &mut scaler, &mut pixels)
                .with_context(|| format!("scale corpus frame at {t_us} us"))?;
            if last_scaled != Some((w, h)) {
                tracing::debug!(
                    from = ?last_scaled,
                    to = %format!("{w}x{h}"),
                    max_h,
                    source = %format!("{src_w}x{src_h}"),
                    "corpus playback scales to a new size"
                );
                last_scaled = Some((w, h));
            }
            let repeat = kind == FrameKind::Repeat;
            this_loop.add(|c| {
                c.delivered += 1;
                c.repeats += u64::from(repeat);
            });
            window.add(|c| {
                c.delivered += 1;
                c.repeats += u64::from(repeat);
            });
            tracing::trace!(
                t_us,
                kind = kind.as_str(),
                w,
                h,
                late_us = late.as_micros() as u64,
                "corpus frame delivered"
            );
            let out = Frame {
                data: pixels,
                width: w,
                height: h,
                timestamp_ms: capture_start.elapsed().as_millis() as u64,
            };
            if sink.send(out).is_err() {
                tracing::debug!("frame consumer gone; stopping the corpus playback");
                return Ok(Ended::ConsumerGone);
            }
        }

        if window_start.elapsed() >= SUMMARY_EVERY {
            tracing::debug!(
                window_s = window_start.elapsed().as_secs(),
                loop_n = loops + 1,
                read = window.read,
                delivered = window.delivered,
                repeats = window.repeats,
                early = window.early,
                late = window.late,
                max_late_ms = window.max_late.as_millis() as u64,
                "corpus playback"
            );
            window = Counts::default();
            window_start = Instant::now();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;
    use afklink_core::quality::Rung;
    use afklink_corpus::format::{CodecInfo, SourceInfo, StoredInfo, TimingInfo};
    use afklink_corpus::{Metadata, Origin, Scaling, Writer, WriterOptions};
    use std::sync::mpsc::{self, Receiver};

    const W: u32 = 64;
    const H: u32 = 48;

    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "afklink-agent-corpus-{}-{nanos}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{name}.rcorp"))
    }

    /// A small `W`x`H` corpus: each frame one flat shade, `(t_us, shade)`; the same shade twice in
    /// a row is a `REPEAT` record. At this size every changed frame is stored as a key frame (the
    /// writer keeps whichever of key and inter is smaller), so these corpora exercise the key-frame
    /// swap on every frame.
    fn write_corpus(path: &Path, frames: &[(u64, u8)], duration_us: u64) {
        let pictures: Vec<(u64, Vec<u8>)> = frames
            .iter()
            .map(|(t, shade)| {
                let mut pixels = vec![*shade; (W * H * 4) as usize];
                pixels[0] = shade.wrapping_mul(7);
                (*t, pixels)
            })
            .collect();
        write_pictures(path, (W, H), &pictures, duration_us, 10_000_000);
    }

    /// Write `pictures` (`(t_us, BGRA)`) at `size`, a key frame forced at least every
    /// `key_interval_us`. The recorded source is twice the stored size.
    fn write_pictures(
        path: &Path,
        size: (u32, u32),
        pictures: &[(u64, Vec<u8>)],
        duration_us: u64,
        key_interval_us: u64,
    ) {
        let meta = Metadata {
            format_version: 1,
            scenario: "bench_test".into(),
            description: "generated by a test".into(),
            created_utc: String::new(),
            source: SourceInfo {
                width: 2 * size.0,
                height: 2 * size.1,
                display_hz: 60.0,
                scale_factor: 1.0,
            },
            stored: StoredInfo {
                width: size.0,
                height: size.1,
                pixel_format: "bgra8".into(),
                scaling: Scaling::Native,
            },
            origin: Origin::Synthetic {
                generator: "test".into(),
                seed: 0,
                params: serde_json::Value::Null,
                inputs: vec![],
            },
            timing: TimingInfo {
                clock: "vsync_model".into(),
                jitter_us: 0,
                duplicates: true,
            },
            codec: CodecInfo {
                tile: 64,
                zstd_level: 1,
                key_interval_us: 10_000_000,
            },
            notes: vec![],
        };
        let opts = WriterOptions {
            zstd_level: 1,
            key_interval_us,
            ..WriterOptions::default()
        };
        let mut w = Writer::create(path, &meta, opts).unwrap();
        for (t, pixels) in pictures {
            w.push(*t, pixels, &[]).unwrap();
        }
        w.finish(duration_us).unwrap();
    }

    fn start(path: &Path, rung: Rung) -> (CorpusCapturer, Receiver<Frame>, Arc<QualityTarget>) {
        let mut cap = CorpusCapturer::new(path.to_path_buf());
        let (tx, rx) = mpsc::channel();
        let target = Arc::new(QualityTarget::new(rung));
        cap.start(tx, target.clone()).unwrap();
        (cap, rx, target)
    }

    fn recv(rx: &Receiver<Frame>) -> Frame {
        rx.recv_timeout(Duration::from_secs(3)).unwrap()
    }

    #[test]
    fn frames_arrive_at_their_recorded_times_repeat_and_loop() {
        let path = scratch("timing");
        // 60 ms repeats 30 ms's picture; 60..200 ms is an idle gap; the recording lasts 300 ms.
        write_corpus(
            &path,
            &[(0, 10), (30_000, 20), (60_000, 20), (200_000, 30)],
            300_000,
        );
        let t0 = Instant::now();
        let (mut cap, rx, target) = start(&path, Rung { max_h: H, fps: 60 });
        let expected_ms = [0u64, 30, 60, 200, 300, 330, 360, 500];
        let shades = [10u8, 20, 20, 30, 10, 20, 20, 30];
        let mut frames = Vec::new();
        for _ in 0..expected_ms.len() {
            let f = recv(&rx);
            frames.push((t0.elapsed(), f));
        }
        assert!(cap.check().is_ok(), "still running");
        cap.stop();
        for (i, ((at, f), (want_ms, shade))) in frames
            .iter()
            .zip(expected_ms.iter().zip(shades))
            .enumerate()
        {
            let want = Duration::from_millis(*want_ms);
            assert!(
                *at + Duration::from_millis(2) >= want && *at < want + Duration::from_millis(40),
                "frame {i} at {at:?}, recorded for {want:?}"
            );
            assert_eq!(
                (f.width, f.height),
                (W, H),
                "no scaling at the stored height"
            );
            assert_eq!(f.data[4], shade, "frame {i} has the recorded picture");
        }
        // The REPEAT is a re-delivery of the same picture.
        assert_eq!(frames[1].1.data, frames[2].1.data);
        // The recorded source size is what the ladder is told.
        assert_eq!(target.source(), Some((2 * W, 2 * H)));
        let (offered, early) = target.take_capture_counts();
        assert!(offered >= 8, "{offered}");
        assert_eq!(early, 0, "30 ms apart never beats a 60 fps slot");
        assert!(cap.check().is_err(), "stopped");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn key_frames_decoded_ahead_keep_their_place_across_loops() {
        let path = scratch("keys");
        // 256x192 is twelve 64-pixel tiles; each frame changes only the first, so the writer
        // stores inter frames — except where a key is forced, at least every 50 ms: at 0, 60, 120,
        // 180 and 240 ms of a frame every 20 ms.
        let (w, h) = (256u32, 192u32);
        let pictures: Vec<(u64, Vec<u8>)> = (0..15u8)
            .map(|i| {
                let mut pixels = vec![100u8; (w * h * 4) as usize];
                for y in 0..64usize {
                    let row = y * w as usize * 4;
                    pixels[row..row + 64 * 4].fill(i + 1);
                }
                (u64::from(i) * 20_000, pixels)
            })
            .collect();
        write_pictures(&path, (w, h), &pictures, 300_000, 50_000);
        let summary = Reader::open(&path).unwrap().summary().cloned().unwrap();
        assert_eq!(
            (summary.key_frames, summary.inter_frames),
            (5, 10),
            "{summary:?}"
        );

        let t0 = Instant::now();
        let (mut cap, rx, _target) = start(&path, Rung { max_h: h, fps: 60 });
        let got: Vec<(Duration, u8)> = (0..25)
            .map(|_| {
                let f = recv(&rx);
                assert_eq!((f.width, f.height), (w, h));
                assert_eq!(
                    f.data[(w * h * 4) as usize - 1],
                    100,
                    "the background is intact"
                );
                (t0.elapsed(), f.data[0])
            })
            .collect();
        assert!(cap.check().is_ok(), "{:?}", cap.check());
        cap.stop();
        let shades: Vec<u8> = got.iter().map(|(_, s)| *s).collect();
        let want: Vec<u8> = (1..=15).chain(1..=10).collect();
        assert_eq!(shades, want, "every frame, in order, across the loop");
        for (k, (at, _)) in got.iter().enumerate() {
            let want = Duration::from_millis(20 * k as u64);
            assert!(
                *at + Duration::from_millis(2) >= want && *at < want + Duration::from_millis(40),
                "frame {k} at {at:?}, recorded for {want:?}"
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_pacer_holds_back_what_the_rung_does_not_want() {
        let path = scratch("pacing");
        // A delivery every 10 ms for 200 ms, each a new picture; a 10 fps rung wants one in ten.
        let frames: Vec<(u64, u8)> = (0..20).map(|i| (i * 10_000, i as u8 + 1)).collect();
        write_corpus(&path, &frames, 200_000);
        let (mut cap, rx, target) = start(&path, Rung { max_h: H, fps: 10 });
        std::thread::sleep(Duration::from_millis(190));
        cap.stop();
        let delivered = rx.try_iter().count() as u32;
        let (offered, early) = target.take_capture_counts();
        assert!((18..=20).contains(&offered), "{offered} offered");
        assert_eq!(
            offered,
            delivered + early,
            "every offer is delivered or held back"
        );
        assert!(
            (2..=3).contains(&delivered),
            "{delivered} delivered at 10 fps"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_rung_change_reaches_the_next_frame() {
        let path = scratch("resize");
        let frames: Vec<(u64, u8)> = (0..40).map(|i| (i * 20_000, i as u8 + 1)).collect();
        write_corpus(&path, &frames, 800_000);
        let (mut cap, rx, target) = start(&path, Rung { max_h: H, fps: 60 });
        for _ in 0..3 {
            let f = recv(&rx);
            assert_eq!((f.width, f.height), (W, H));
        }
        target.set(Rung {
            max_h: H / 2,
            fps: 60,
        });
        // At most the frame already being scaled keeps the old size.
        let sizes: Vec<(u32, u32)> = (0..4)
            .map(|_| recv(&rx))
            .map(|f| (f.width, f.height))
            .collect();
        cap.stop();
        assert_eq!(*sizes.last().unwrap(), (W / 2, H / 2), "{sizes:?}");
        let first_small = sizes.iter().position(|s| *s == (W / 2, H / 2)).unwrap();
        assert!(first_small <= 1, "{sizes:?}");
        assert!(
            sizes[first_small..].iter().all(|s| *s == (W / 2, H / 2)),
            "{sizes:?}"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn check_reports_an_ending_nobody_asked_for() {
        let path = scratch("ending");
        write_corpus(&path, &[(0, 1), (10_000, 2), (20_000, 3)], 30_000);

        // The consumer goes away: the playback ends by itself, and `check` says so.
        let (mut cap, rx, _target) = start(&path, Rung { max_h: H, fps: 60 });
        let _ = recv(&rx);
        drop(rx);
        let deadline = Instant::now() + Duration::from_secs(3);
        let err = loop {
            match cap.check() {
                Err(e) => break e,
                Ok(()) => {
                    assert!(Instant::now() < deadline, "never noticed");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        assert!(err.to_string().contains("consumer"), "{err:#}");

        // A damaged record: the second frame's payload does not match its CRC.
        let mut bytes = std::fs::read(&path).unwrap();
        let meta_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
        let first = 16 + meta_len;
        let len1 = u32::from_le_bytes(bytes[first + 9..first + 13].try_into().unwrap()) as usize;
        let second = first + 13 + len1 + 4;
        bytes[second + 13] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        let (mut cap, rx, _target) = start(&path, Rung { max_h: H, fps: 60 });
        let _ = recv(&rx);
        let deadline = Instant::now() + Duration::from_secs(3);
        let err = loop {
            match cap.check() {
                Err(e) => break e,
                Ok(()) => {
                    assert!(Instant::now() < deadline, "never noticed");
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        assert!(format!("{err:#}").contains("CRC"), "{err:#}");

        // Stop is prompt, and a stopped capture is not running.
        let (mut cap, _rx, _target) = start(&path, Rung { max_h: H, fps: 60 });
        let t = Instant::now();
        cap.stop();
        assert!(
            t.elapsed() < Duration::from_millis(200),
            "{:?}",
            t.elapsed()
        );
        assert!(cap.check().is_err());
        assert!(CorpusCapturer::probe(&path).is_ok(), "the header is intact");
        assert!(CorpusCapturer::probe(&path.with_extension("missing")).is_err());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
