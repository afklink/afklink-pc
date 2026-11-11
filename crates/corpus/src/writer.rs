//! Writing a scenario file, one captured frame at a time.

use std::fs::File;
use std::io::{BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};

use crate::codec::{self, Move, Predictor, Zstd};
use crate::format::{
    KeyEntry, Metadata, Summary, FOOTER_MAGIC, FORMAT_VERSION, MAGIC, PIXEL_FORMAT_BGRA8, TAG_END,
    TAG_INTER, TAG_KEY, TAG_REPEAT,
};

/// How a frame was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Key,
    Inter,
    Repeat,
}

impl FrameKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Inter => "inter",
            Self::Repeat => "repeat",
        }
    }
}

/// Knobs for [`Writer`]. The defaults are what the shipped corpus was written with.
#[derive(Debug, Clone)]
pub struct WriterOptions {
    /// Residual tile edge in pixels. 64 keeps the bitmap small at 3600x2400 (2166 tiles) while a
    /// keystroke still costs a single tile.
    pub tile: u32,
    pub zstd_level: i32,
    /// zstd worker threads per frame (0 = compress on the calling thread).
    pub zstd_workers: u32,
    /// A KEY is forced at least this often, so a reader can seek and a damaged region stays local.
    pub key_interval_us: u64,
    /// When an INTER leaves at least this share of tiles dirty, a KEY is also tried and the smaller
    /// kept: on a video frame the temporal residual is often larger than the picture itself.
    pub key_trial_fraction: f64,
    pub key_predictor: Predictor,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            tile: 64,
            zstd_level: 9,
            zstd_workers: 0,
            key_interval_us: 10_000_000,
            key_trial_fraction: 0.25,
            key_predictor: Predictor::Med,
        }
    }
}

/// What [`Writer::push`] did with a frame.
#[derive(Debug, Clone, Copy)]
pub struct Pushed {
    pub kind: FrameKind,
    /// Payload bytes on disk for this frame.
    pub bytes: usize,
    /// Share of tiles that needed a residual (1.0 for a key frame, 0.0 for a repeat).
    pub dirty_fraction: f64,
}

/// Streams frames into a corpus file. Call [`Writer::finish`]; a writer dropped without it leaves a
/// file the reader reports as truncated.
pub struct Writer {
    path: PathBuf,
    out: BufWriter<File>,
    width: u32,
    height: u32,
    opts: WriterOptions,
    zstd: Zstd,
    prev: Vec<u8>,
    have_prev: bool,
    last_t: Option<u64>,
    last_key_t: Option<u64>,
    offset: u64,
    summary: Summary,
    finished: bool,
    raw: Vec<u8>,
    raw_key: Vec<u8>,
    packed: Vec<u8>,
    packed_key: Vec<u8>,
    pred: Vec<u8>,
    scratch: Vec<u8>,
    key_trials: u64,
    key_trials_won: u64,
}

impl Writer {
    /// Create `path` (overwriting it) and write the header. The frame size is taken from
    /// `meta.stored`.
    pub fn create(path: &Path, meta: &Metadata, opts: WriterOptions) -> Result<Self> {
        ensure!(
            meta.stored.pixel_format == PIXEL_FORMAT_BGRA8,
            "only {PIXEL_FORMAT_BGRA8} is supported, got {}",
            meta.stored.pixel_format
        );
        let (width, height) = (meta.stored.width, meta.stored.height);
        ensure!(
            width >= 2 && height >= 2,
            "stored size {width}x{height} is degenerate"
        );
        ensure!(opts.tile >= 8, "tile {} is too small", opts.tile);
        let mut meta = meta.clone();
        meta.format_version = FORMAT_VERSION;
        meta.codec.tile = opts.tile;
        meta.codec.zstd_level = opts.zstd_level;
        meta.codec.key_interval_us = opts.key_interval_us;
        let json = serde_json::to_vec(&meta).context("serialise metadata")?;

        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create directory {}", dir.display()))?;
        }
        let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
        let mut out = BufWriter::with_capacity(1 << 20, file);
        out.write_all(MAGIC)?;
        out.write_all(&FORMAT_VERSION.to_le_bytes())?;
        out.write_all(&u32::try_from(json.len())?.to_le_bytes())?;
        out.write_all(&json)?;
        let offset = (MAGIC.len() + 8 + json.len()) as u64;

        tracing::debug!(
            path = %path.display(),
            scenario = %meta.scenario,
            width,
            height,
            tile = opts.tile,
            zstd_level = opts.zstd_level,
            zstd_workers = opts.zstd_workers,
            key_interval_ms = opts.key_interval_us / 1000,
            key_trial_fraction = opts.key_trial_fraction,
            predictor = ?opts.key_predictor,
            "corpus writer created"
        );
        Ok(Self {
            path: path.to_path_buf(),
            out,
            width,
            height,
            zstd: Zstd::new(opts.zstd_level, opts.zstd_workers)?,
            opts,
            prev: vec![0; width as usize * height as usize * 4],
            have_prev: false,
            last_t: None,
            last_key_t: None,
            offset,
            summary: Summary::default(),
            finished: false,
            raw: Vec::new(),
            raw_key: Vec::new(),
            packed: Vec::new(),
            packed_key: Vec::new(),
            pred: Vec::new(),
            scratch: Vec::new(),
            key_trials: 0,
            key_trials_won: 0,
        })
    }

    /// The frame size this writer expects.
    #[must_use]
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Record that the producer dropped `n` deliveries it could not keep up with (goes into the
    /// summary).
    pub fn note_dropped(&mut self, n: u64) {
        self.summary.dropped += n;
    }

    /// Append one delivered frame. `t_us` must increase strictly. `moves` are hints from a
    /// generator that knows how the picture moved (see [`Move`]); they only change the size on
    /// disk, never the decoded pixels.
    pub fn push(&mut self, t_us: u64, frame: &[u8], moves: &[Move]) -> Result<Pushed> {
        let expected = self.width as usize * self.height as usize * 4;
        ensure!(
            frame.len() == expected,
            "frame is {} bytes, expected {expected} for {}x{}",
            frame.len(),
            self.width,
            self.height
        );
        if let Some(last) = self.last_t {
            ensure!(
                t_us > last,
                "timestamps must increase: {t_us} after {last} in {}",
                self.path.display()
            );
        }

        let pushed = if self.have_prev && frame == self.prev.as_slice() {
            self.write_record(TAG_REPEAT, t_us, &[])?;
            self.summary.repeat_frames += 1;
            Pushed {
                kind: FrameKind::Repeat,
                bytes: 0,
                dirty_fraction: 0.0,
            }
        } else {
            let force_key = !self.have_prev
                || self
                    .last_key_t
                    .is_none_or(|k| t_us.saturating_sub(k) >= self.opts.key_interval_us);
            let (kind, dirty_fraction) = if force_key {
                self.encode_key(frame)?;
                (FrameKind::Key, 1.0)
            } else {
                let stats = codec::encode_inter_raw(
                    &self.prev,
                    frame,
                    self.width,
                    self.height,
                    self.opts.tile,
                    moves,
                    &mut self.pred,
                    &mut self.scratch,
                    &mut self.raw,
                )?;
                self.zstd.compress(&self.raw, &mut self.packed)?;
                let fraction = stats.dirty_fraction();
                if fraction >= self.opts.key_trial_fraction {
                    self.key_trials += 1;
                    let inter_len = self.packed.len();
                    self.encode_key(frame)?;
                    if self.packed_key.len() < inter_len {
                        self.key_trials_won += 1;
                        tracing::trace!(
                            t_us,
                            inter_bytes = inter_len,
                            key_bytes = self.packed_key.len(),
                            "key frame smaller than the inter residual; keeping the key"
                        );
                        (FrameKind::Key, 1.0)
                    } else {
                        (FrameKind::Inter, fraction)
                    }
                } else {
                    (FrameKind::Inter, fraction)
                }
            };

            let bytes = match kind {
                FrameKind::Key => {
                    let offset = self.offset;
                    let payload = std::mem::take(&mut self.packed_key);
                    self.write_record(TAG_KEY, t_us, &payload)?;
                    let n = payload.len();
                    self.packed_key = payload;
                    self.summary.key_frames += 1;
                    self.summary.bytes_key += n as u64;
                    self.summary.key_index.push(KeyEntry {
                        t_us,
                        offset,
                        index: self.summary.frame_count,
                    });
                    self.last_key_t = Some(t_us);
                    n
                }
                FrameKind::Inter => {
                    let payload = std::mem::take(&mut self.packed);
                    self.write_record(TAG_INTER, t_us, &payload)?;
                    let n = payload.len();
                    self.packed = payload;
                    self.summary.inter_frames += 1;
                    self.summary.bytes_inter += n as u64;
                    n
                }
                FrameKind::Repeat => 0,
            };
            self.prev.copy_from_slice(frame);
            self.have_prev = true;
            Pushed {
                kind,
                bytes,
                dirty_fraction,
            }
        };

        self.summary.frame_count += 1;
        self.summary.first_t_us.get_or_insert(t_us);
        self.summary.last_t_us = Some(t_us);
        self.last_t = Some(t_us);
        tracing::trace!(
            t_us,
            kind = pushed.kind.as_str(),
            bytes = pushed.bytes,
            dirty = pushed.dirty_fraction,
            "corpus frame written"
        );
        Ok(pushed)
    }

    fn encode_key(&mut self, frame: &[u8]) -> Result<()> {
        codec::encode_key_raw(
            frame,
            self.width,
            self.height,
            self.opts.key_predictor,
            &mut self.raw_key,
        );
        self.zstd.compress(&self.raw_key, &mut self.packed_key)
    }

    fn write_record(&mut self, tag: u8, t_us: u64, payload: &[u8]) -> Result<()> {
        let len = u32::try_from(payload.len()).context("record over 4 GiB")?;
        let mut header = [0u8; crate::format::RECORD_HEADER_LEN];
        header[0] = tag;
        header[1..9].copy_from_slice(&t_us.to_le_bytes());
        header[9..13].copy_from_slice(&len.to_le_bytes());
        let mut crc = crc32fast::Hasher::new();
        crc.update(&header);
        crc.update(payload);
        self.out.write_all(&header)?;
        self.out.write_all(payload)?;
        self.out.write_all(&crc.finalize().to_le_bytes())?;
        self.offset += (header.len() + payload.len() + 4) as u64;
        Ok(())
    }

    /// Write the end record and the footer. `duration_us` is how long the scenario lasts; it may
    /// run past the last frame (a still screen at the end is part of the scenario).
    pub fn finish(mut self, duration_us: u64) -> Result<Summary> {
        if let Some(last) = self.last_t {
            ensure!(
                duration_us >= last,
                "duration {duration_us} us ends before the last frame at {last} us"
            );
        }
        self.summary.duration_us = duration_us;
        let json = serde_json::to_vec(&self.summary).context("serialise summary")?;
        let end_at = self.offset;
        self.write_record(TAG_END, duration_us, &json)?;
        self.out.write_all(&end_at.to_le_bytes())?;
        self.out.write_all(FOOTER_MAGIC)?;
        self.out.flush()?;
        let file = self.out.get_mut();
        let len = file.stream_position().unwrap_or(0);
        file.sync_all()
            .with_context(|| format!("sync {}", self.path.display()))?;
        self.finished = true;
        tracing::debug!(
            path = %self.path.display(),
            frames = self.summary.frame_count,
            key = self.summary.key_frames,
            inter = self.summary.inter_frames,
            repeat = self.summary.repeat_frames,
            key_trials = self.key_trials,
            key_trials_won = self.key_trials_won,
            duration_ms = duration_us / 1000,
            file_bytes = len,
            "corpus writer finished"
        );
        Ok(self.summary.clone())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if !self.finished {
            // Not an error to propagate from a destructor, but never silent: the file on disk has no
            // end record and will read back as truncated.
            if let Err(e) = self.out.flush() {
                tracing::warn!(path = %self.path.display(), "flushing an unfinished corpus file failed: {e}");
            }
            tracing::warn!(
                path = %self.path.display(),
                frames = self.summary.frame_count,
                "corpus writer dropped without finish(); the file is truncated"
            );
        }
    }
}
