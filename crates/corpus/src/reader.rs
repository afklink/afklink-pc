//! Streaming a scenario file back, one frame at a time, without holding more than one picture.
//!
//! [`Reader::next_frame`] is the simulator's entry point: it returns each delivered frame with its
//! capture timestamp, borrowing the reader's single picture buffer (no 35 MB copy per frame).
//! [`Reader::into_frames`] is the same thing as an owning iterator for code that wants one.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use afklink_core::types::Frame;
use anyhow::{bail, ensure, Context, Result};

use crate::codec::{self, max_raw_len, Zstd};
use crate::format::{
    Metadata, Summary, FOOTER_MAGIC, FORMAT_VERSION, MAGIC, PIXEL_FORMAT_BGRA8, RECORD_HEADER_LEN,
    TAG_END, TAG_INTER, TAG_KEY, TAG_REPEAT,
};
use crate::writer::FrameKind;

/// Largest metadata or summary JSON the reader accepts, as a guard against a corrupt length.
const MAX_JSON: usize = 64 << 20;

/// One delivered frame, borrowing the reader's picture.
#[derive(Debug, Clone, Copy)]
pub struct FrameRef<'a> {
    /// Capture timestamp, microseconds from the scenario start.
    pub t_us: u64,
    /// Zero-based position among all frames of the file.
    pub index: u64,
    pub kind: FrameKind,
    pub width: u32,
    pub height: u32,
    /// BGRA8, `width * height * 4` bytes, top-down.
    pub data: &'a [u8],
}

impl FrameRef<'_> {
    /// WGC delivered a frame but the picture did not change.
    #[must_use]
    pub fn is_repeat(&self) -> bool {
        self.kind == FrameKind::Repeat
    }

    #[must_use]
    pub fn to_owned_frame(&self) -> CorpusFrame {
        CorpusFrame {
            t_us: self.t_us,
            index: self.index,
            kind: self.kind,
            width: self.width,
            height: self.height,
            data: self.data.to_vec(),
        }
    }

    /// The pipeline's own frame type, as the capturer would hand it to the encoder (timestamp in
    /// milliseconds, truncated).
    #[must_use]
    pub fn to_core_frame(&self) -> Frame {
        Frame {
            data: self.data.to_vec(),
            width: self.width,
            height: self.height,
            timestamp_ms: self.t_us / 1000,
        }
    }
}

/// An owned frame, from [`Frames`].
#[derive(Debug, Clone)]
pub struct CorpusFrame {
    pub t_us: u64,
    pub index: u64,
    pub kind: FrameKind,
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

impl CorpusFrame {
    #[must_use]
    pub fn into_core_frame(self) -> Frame {
        Frame {
            data: self.data,
            width: self.width,
            height: self.height,
            timestamp_ms: self.t_us / 1000,
        }
    }
}

/// Streaming reader for one scenario file.
pub struct Reader {
    path: PathBuf,
    file: BufReader<File>,
    meta: Metadata,
    summary: Option<Summary>,
    width: u32,
    height: u32,
    data_start: u64,
    state: Vec<u8>,
    have_state: bool,
    last_kind: FrameKind,
    next_index: u64,
    last_t: Option<u64>,
    done: bool,
    truncated: bool,
    zstd: Zstd,
    payload: Vec<u8>,
    raw: Vec<u8>,
    scratch: Vec<u8>,
}

impl Reader {
    /// Open a file and read its metadata, and its summary when the file was finished.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut file = BufReader::with_capacity(1 << 20, file);

        let mut magic = [0u8; 8];
        file.read_exact(&mut magic)
            .with_context(|| format!("{}: shorter than a header", path.display()))?;
        ensure!(&magic == MAGIC, "{} is not a corpus file", path.display());
        let version = read_u32(&mut file)?;
        ensure!(
            version == FORMAT_VERSION,
            "{} is format version {version}, this build reads {FORMAT_VERSION}",
            path.display()
        );
        let meta_len = read_u32(&mut file)? as usize;
        ensure!(
            meta_len <= MAX_JSON,
            "metadata length {meta_len} is corrupt"
        );
        let mut json = vec![0u8; meta_len];
        file.read_exact(&mut json)
            .with_context(|| format!("{}: metadata cut short", path.display()))?;
        let meta: Metadata = serde_json::from_slice(&json)
            .with_context(|| format!("{}: metadata is not valid", path.display()))?;
        ensure!(
            meta.stored.pixel_format == PIXEL_FORMAT_BGRA8,
            "unsupported pixel format {}",
            meta.stored.pixel_format
        );
        let (width, height) = (meta.stored.width, meta.stored.height);
        ensure!(width >= 2 && height >= 2, "stored size {width}x{height}");
        let data_start = (8 + 4 + 4 + meta_len) as u64;

        let summary = match read_footer(&mut file, file_len, data_start) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::debug!(
                    path = %path.display(),
                    "no usable end record ({e:#}); the file is truncated or still being written, \
                     streaming what is there"
                );
                None
            }
        };
        file.seek(SeekFrom::Start(data_start))?;

        tracing::debug!(
            path = %path.display(),
            scenario = %meta.scenario,
            width,
            height,
            frames = summary.as_ref().map(|s| s.frame_count),
            duration_ms = summary.as_ref().map(|s| s.duration_us / 1000),
            "corpus reader opened"
        );
        Ok(Self {
            path: path.to_path_buf(),
            file,
            meta,
            summary,
            width,
            height,
            data_start,
            state: vec![0; width as usize * height as usize * 4],
            have_state: false,
            last_kind: FrameKind::Key,
            next_index: 0,
            last_t: None,
            done: false,
            truncated: false,
            zstd: Zstd::new(1, 0)?,
            payload: Vec::new(),
            raw: Vec::new(),
            scratch: Vec::new(),
        })
    }

    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.meta
    }

    /// Counts, sizes and the scenario duration, or `None` for a truncated file.
    #[must_use]
    pub fn summary(&self) -> Option<&Summary> {
        self.summary.as_ref()
    }

    /// Scenario length: from the end record, or for a truncated file the last frame read so far.
    #[must_use]
    pub fn duration_us(&self) -> Option<u64> {
        self.summary.as_ref().map(|s| s.duration_us).or(self.last_t)
    }

    /// Stored frame size.
    #[must_use]
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// True once streaming reached the end of a file that has no end record (a recorder that died,
    /// a copy cut short). Every frame before the damage was returned.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// The next delivered frame, or `None` at the end of the scenario.
    pub fn next_frame(&mut self) -> Result<Option<FrameRef<'_>>> {
        if self.done {
            return Ok(None);
        }
        let Some((tag, t_us, payload_len)) = self.read_record()? else {
            return Ok(None);
        };
        match tag {
            TAG_END => {
                if self.summary.is_none() {
                    match serde_json::from_slice::<Summary>(&self.payload) {
                        Ok(s) => self.summary = Some(s),
                        Err(e) => {
                            tracing::warn!(path = %self.path.display(), "end record summary unreadable: {e}")
                        }
                    }
                }
                self.done = true;
                tracing::debug!(
                    path = %self.path.display(),
                    frames = self.next_index,
                    duration_ms = t_us / 1000,
                    "corpus reader reached the end record"
                );
                return Ok(None);
            }
            TAG_KEY | TAG_INTER | TAG_REPEAT => {}
            other => bail!(
                "{}: unknown record tag {other:#x} at frame {}",
                self.path.display(),
                self.next_index
            ),
        }
        if let Some(last) = self.last_t {
            ensure!(
                t_us > last,
                "{}: timestamp {t_us} after {last} at frame {}",
                self.path.display(),
                self.next_index
            );
        }
        let kind = match tag {
            TAG_KEY => {
                self.zstd.decompress(
                    &self.payload,
                    max_raw_len(self.width, self.height),
                    &mut self.raw,
                )?;
                codec::decode_key_raw(
                    &self.raw,
                    self.width,
                    self.height,
                    &mut self.state,
                    &mut self.scratch,
                )
                .with_context(|| format!("key frame {} at {t_us} us", self.next_index))?;
                FrameKind::Key
            }
            TAG_INTER => {
                ensure!(
                    self.have_state,
                    "{}: inter frame before any key frame",
                    self.path.display()
                );
                self.zstd.decompress(
                    &self.payload,
                    max_raw_len(self.width, self.height),
                    &mut self.raw,
                )?;
                codec::decode_inter_raw(
                    &self.raw,
                    self.width,
                    self.height,
                    &mut self.state,
                    &mut self.scratch,
                )
                .with_context(|| format!("inter frame {} at {t_us} us", self.next_index))?;
                FrameKind::Inter
            }
            _ => {
                ensure!(
                    self.have_state,
                    "{}: repeat frame before any key frame",
                    self.path.display()
                );
                ensure!(payload_len == 0, "repeat frame with a payload");
                FrameKind::Repeat
            }
        };
        self.have_state = true;
        self.last_kind = kind;
        self.last_t = Some(t_us);
        let index = self.next_index;
        self.next_index += 1;
        tracing::trace!(t_us, index, kind = kind.as_str(), "corpus frame read");
        Ok(Some(FrameRef {
            t_us,
            index,
            kind,
            width: self.width,
            height: self.height,
            data: &self.state,
        }))
    }

    /// The picture as of the last frame returned (or skipped by [`Self::seek`]).
    #[must_use]
    pub fn current(&self) -> Option<FrameRef<'_>> {
        let t_us = self.last_t?;
        self.have_state.then(|| FrameRef {
            t_us,
            index: self.next_index.saturating_sub(1),
            kind: self.last_kind,
            width: self.width,
            height: self.height,
            data: &self.state,
        })
    }

    /// Back to the first frame.
    pub fn rewind(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(self.data_start))?;
        self.reset_stream(0);
        Ok(())
    }

    /// Position the reader at `t_us`: afterwards [`Self::current`] is the picture on screen at that
    /// instant (the last frame at or before it) and [`Self::next_frame`] returns the first frame
    /// after it. Jumps to the nearest key frame through the index when the file has one.
    pub fn seek(&mut self, t_us: u64) -> Result<Option<FrameRef<'_>>> {
        let key = self.summary.as_ref().and_then(|s| {
            s.key_index
                .iter()
                .take_while(|k| k.t_us <= t_us)
                .last()
                .copied()
        });
        match key {
            Some(k) => {
                self.file.seek(SeekFrom::Start(k.offset))?;
                self.reset_stream(k.index);
            }
            None => self.rewind()?,
        }
        loop {
            match self.peek_t()? {
                Some(t) if t <= t_us => {
                    if self.next_frame()?.is_none() {
                        break;
                    }
                }
                _ => break,
            }
        }
        tracing::debug!(target_us = t_us, landed_us = ?self.last_t, "corpus reader seek");
        Ok(self.current())
    }

    /// Owning iterator over the remaining frames.
    #[must_use]
    pub fn into_frames(self) -> Frames {
        Frames { reader: self }
    }

    fn reset_stream(&mut self, next_index: u64) {
        self.have_state = false;
        self.last_t = None;
        self.next_index = next_index;
        self.done = false;
        self.truncated = false;
    }

    /// Timestamp of the next frame record without consuming it (`None` at the end).
    fn peek_t(&mut self) -> Result<Option<u64>> {
        if self.done {
            return Ok(None);
        }
        let at = self.file.stream_position()?;
        let mut header = [0u8; RECORD_HEADER_LEN];
        let n = read_full(&mut self.file, &mut header)?;
        self.file.seek(SeekFrom::Start(at))?;
        if n < RECORD_HEADER_LEN || header[0] == TAG_END {
            return Ok(None);
        }
        Ok(Some(u64::from_le_bytes(
            header[1..9].try_into().context("record header")?,
        )))
    }

    /// Read one record into `self.payload`, verifying its CRC. `None` (and `truncated`) if the file
    /// ends inside or right before a record, which is how an unfinished file ends.
    fn read_record(&mut self) -> Result<Option<(u8, u64, usize)>> {
        let mut header = [0u8; RECORD_HEADER_LEN];
        let n = read_full(&mut self.file, &mut header)?;
        if n < RECORD_HEADER_LEN {
            self.mark_truncated(if n == 0 {
                "the file ends without an end record"
            } else {
                "the file ends inside a record header"
            });
            return Ok(None);
        }
        let tag = header[0];
        let t_us = u64::from_le_bytes(header[1..9].try_into().context("record header")?);
        let len = u32::from_le_bytes(header[9..13].try_into().context("record header")?) as usize;
        ensure!(
            len <= max_raw_len(self.width, self.height) + 4 || (tag == TAG_END && len <= MAX_JSON),
            "{}: record of {len} bytes at frame {} is corrupt",
            self.path.display(),
            self.next_index
        );
        self.payload.clear();
        self.payload.resize(len, 0);
        let got = read_full(&mut self.file, &mut self.payload)?;
        let mut crc_bytes = [0u8; 4];
        let got_crc = read_full(&mut self.file, &mut crc_bytes)?;
        if got < len || got_crc < 4 {
            self.mark_truncated("the file ends inside a record");
            return Ok(None);
        }
        let mut crc = crc32fast::Hasher::new();
        crc.update(&header);
        crc.update(&self.payload);
        let want = u32::from_le_bytes(crc_bytes);
        ensure!(
            crc.finalize() == want,
            "{}: record CRC mismatch at frame {} (t={t_us} us): the file is corrupt",
            self.path.display(),
            self.next_index
        );
        Ok(Some((tag, t_us, len)))
    }

    fn mark_truncated(&mut self, why: &str) {
        self.done = true;
        self.truncated = true;
        tracing::warn!(
            path = %self.path.display(),
            frames_read = self.next_index,
            last_t_us = ?self.last_t,
            "corpus file truncated: {why}"
        );
    }
}

/// Owning iterator over frames: `Item = Result<CorpusFrame>`. Stops after the first error.
pub struct Frames {
    reader: Reader,
}

impl Frames {
    /// The reader, to ask about truncation or duration after iterating.
    #[must_use]
    pub fn reader(&self) -> &Reader {
        &self.reader
    }
}

impl Iterator for Frames {
    type Item = Result<CorpusFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_frame() {
            Ok(Some(f)) => Some(Ok(f.to_owned_frame())),
            Ok(None) => None,
            Err(e) => {
                self.reader.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Metadata and summary of a file without decoding any frame.
pub fn read_info(path: &Path) -> Result<(Metadata, Option<Summary>)> {
    let r = Reader::open(path)?;
    Ok((r.meta, r.summary))
}

fn read_footer(file: &mut BufReader<File>, file_len: u64, data_start: u64) -> Result<Summary> {
    ensure!(
        file_len >= data_start + (RECORD_HEADER_LEN + 4 + 16) as u64,
        "too short for an end record"
    );
    file.seek(SeekFrom::Start(file_len - 16))?;
    let mut footer = [0u8; 16];
    file.read_exact(&mut footer)?;
    ensure!(&footer[8..] == FOOTER_MAGIC, "no footer");
    let end_at = u64::from_le_bytes(footer[..8].try_into().context("footer")?);
    ensure!(
        end_at >= data_start && end_at < file_len - 16,
        "footer points outside the file"
    );
    file.seek(SeekFrom::Start(end_at))?;
    let mut header = [0u8; RECORD_HEADER_LEN];
    file.read_exact(&mut header)?;
    ensure!(
        header[0] == TAG_END,
        "footer does not point at an end record"
    );
    let len = u32::from_le_bytes(header[9..13].try_into().context("end header")?) as usize;
    ensure!(len <= MAX_JSON, "end record length {len}");
    let mut json = vec![0u8; len];
    file.read_exact(&mut json)?;
    let mut crc_bytes = [0u8; 4];
    file.read_exact(&mut crc_bytes)?;
    let mut crc = crc32fast::Hasher::new();
    crc.update(&header);
    crc.update(&json);
    ensure!(
        crc.finalize() == u32::from_le_bytes(crc_bytes),
        "end record CRC mismatch"
    );
    serde_json::from_slice(&json).context("end record summary")
}

fn read_u32(r: &mut impl Read) -> Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Read until `buf` is full or the file ends; the number of bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut at = 0;
    while at < buf.len() {
        match r.read(&mut buf[at..]) {
            Ok(0) => break,
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(at)
}
