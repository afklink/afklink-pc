//! The on-disk layout and the metadata every scenario file carries.
//!
//! ```text
//! file    := header record* end footer
//! header  := "RCORPUS\0" u32:version u32:meta_len meta_json
//! record  := u8:tag u64:t_us u32:payload_len payload u32:crc32(tag..payload)
//! end     := record with tag END, t_us = duration_us, payload = summary_json
//! footer  := u64:offset_of_end_record "RCEND\0\0\x01"
//! ```
//!
//! All integers little-endian. `t_us` is the capture timestamp of the frame in microseconds from
//! the start of the scenario. A gap between two records is a gap in WGC delivery — nothing on the
//! screen changed — and is kept as a gap: there are no filler records for a still screen.
//!
//! Frame payloads are described in [`crate::codec`]. A file whose writer died has no end record and
//! no footer; the reader streams every complete record up to the damage and reports the file as
//! truncated (see [`crate::reader::Reader::is_truncated`]).

use serde::{Deserialize, Serialize};

/// First eight bytes of every corpus file.
pub const MAGIC: &[u8; 8] = b"RCORPUS\0";
/// Last eight bytes of a completely written file, after the end record's offset.
pub const FOOTER_MAGIC: &[u8; 8] = b"RCEND\0\0\x01";
/// Bumped on any incompatible change to the layout or the codec.
pub const FORMAT_VERSION: u32 = 1;
/// The file extension the tools use and look for.
pub const EXTENSION: &str = "rcorp";

/// Record tags.
pub const TAG_KEY: u8 = 0x01;
pub const TAG_INTER: u8 = 0x02;
pub const TAG_REPEAT: u8 = 0x03;
pub const TAG_END: u8 = 0x7f;

/// Bytes in a record header: tag, timestamp, payload length.
pub const RECORD_HEADER_LEN: usize = 1 + 8 + 4;

/// Pixel format of the stored frames. Only one exists: what WGC hands the capturer and what
/// `afklink_core::types::Frame` carries — BGRA8, tightly packed, top-down.
pub const PIXEL_FORMAT_BGRA8: &str = "bgra8";

/// Everything a consumer needs to know about a scenario before reading a frame.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Metadata {
    pub format_version: u32,
    /// Short machine name, also the file stem: `text_scroll_jerky_article`.
    pub scenario: String,
    /// One or two sentences a person can read in the manifest.
    pub description: String,
    /// RFC 3339 UTC, when the file was written. Informational only: it is the one field that
    /// differs between two runs of a deterministic generator.
    pub created_utc: String,
    /// The screen this scenario represents, as the capturer would report it
    /// (`QualityTarget::set_source`). The ladder prices rungs against this, not the stored size.
    pub source: SourceInfo,
    /// What is actually in the file.
    pub stored: StoredInfo,
    /// Where the pixels came from.
    pub origin: Origin,
    /// How the timestamps were produced.
    pub timing: TimingInfo,
    /// Codec settings used when writing (the reader does not need them; they document the size).
    pub codec: CodecInfo,
    /// Free-form caveats: what is and is not realistic about this scenario.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// The physical screen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceInfo {
    pub width: u32,
    pub height: u32,
    /// Display refresh; WGC delivers at most this often.
    pub display_hz: f64,
    /// Windows display scaling (2.0 = 200%), which sets how big text and chrome are in pixels.
    pub scale_factor: f64,
}

/// The stored frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredInfo {
    pub width: u32,
    pub height: u32,
    /// Always [`PIXEL_FORMAT_BGRA8`] in this version.
    pub pixel_format: String,
    pub scaling: Scaling,
}

/// Whether the stored frames are the full-resolution screen or already scaled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scaling {
    /// Exactly the source: the simulator runs the capturer's own `Scaler` for any rung, so every
    /// rung sees bit-exactly what the live pipeline would.
    Native,
    /// Already scaled by `afklink_core::scale::Scaler::fit_into(.., u32::MAX / 2, max_h, ..)` from
    /// the full-resolution screen, i.e. exactly the frames the live capturer produces at a rung of
    /// this height. Rungs of this height are exact; lower rungs are a second box filter over this one
    /// (see the crate docs for the measured cost of that approximation).
    Scaler { max_h: u32 },
}

/// Provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Origin {
    /// Produced by a generator in this crate from real renders (headless Edge) or a real video.
    Synthetic {
        generator: String,
        seed: u64,
        /// Every parameter the generator was run with, so the file can be reproduced.
        params: serde_json::Value,
        /// External inputs (documents rendered, video files decoded) and where in them.
        #[serde(default)]
        inputs: Vec<String>,
    },
    /// Captured from the live screen by the recorder. How many deliveries it had to drop is in the
    /// summary ([`Summary::dropped`]), which is written at the end.
    Recorded {
        tool: String,
        #[serde(default)]
        note: String,
    },
}

/// How `t_us` was produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimingInfo {
    /// `vsync_model`: generated on a display-refresh grid plus jitter; `wgc_receipt`: the instant
    /// the recorder received the frame from the capture thread.
    pub clock: String,
    /// Peak delivery jitter applied to the vsync grid, microseconds (0 for recordings).
    pub jitter_us: u32,
    /// Whether a delivery can repeat the previous picture exactly (a 30 fps video presented on a
    /// 60 Hz compositor); such deliveries are stored as `REPEAT` records.
    pub duplicates: bool,
}

/// Codec parameters used by the writer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CodecInfo {
    pub tile: u32,
    pub zstd_level: i32,
    pub key_interval_us: u64,
}

/// What the end record carries: counts and sizes, and the key frame index for seeking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Summary {
    pub frame_count: u64,
    pub key_frames: u64,
    pub inter_frames: u64,
    pub repeat_frames: u64,
    /// Scenario length, microseconds. At least the last frame's timestamp; longer when the scenario
    /// ends on a still screen.
    pub duration_us: u64,
    pub first_t_us: Option<u64>,
    pub last_t_us: Option<u64>,
    /// Payload bytes by record kind (headers and CRCs excluded).
    pub bytes_key: u64,
    pub bytes_inter: u64,
    /// Every key frame, for seeking.
    pub key_index: Vec<KeyEntry>,
    /// Deliveries the producer saw but could not store (a recorder that fell behind). Non-zero
    /// means the timing is not a faithful WGC record around those instants.
    #[serde(default)]
    pub dropped: u64,
}

/// Where a key frame is.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyEntry {
    pub t_us: u64,
    /// File offset of the record's tag byte.
    pub offset: u64,
    /// Zero-based index of the frame among all frames of the file.
    pub index: u64,
}

impl Summary {
    /// Frames that changed the picture.
    #[must_use]
    pub fn unique_frames(&self) -> u64 {
        self.key_frames + self.inter_frames
    }
}

/// Current UTC time as RFC 3339 (`2026-09-24T18:57:26Z`), without a date crate.
#[must_use]
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339_from_unix(secs)
}

/// Format seconds since the Unix epoch as RFC 3339 UTC.
#[must_use]
pub fn rfc3339_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::rfc3339_from_unix;

    #[test]
    fn formats_known_instants() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        // An instant with seconds, in the corpus's era.
        assert_eq!(rfc3339_from_unix(1_790_276_246), "2026-09-24T18:57:26Z");
        assert_eq!(rfc3339_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }
}
