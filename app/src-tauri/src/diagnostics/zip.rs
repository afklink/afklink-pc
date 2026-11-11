//! The report's zip: deflated entries, written from data compressed beforehand.
//!
//! Compressing first is what lets the report's builder (`package`) know what every entry costs
//! before it decides what goes in, and drop the oldest session rather than overshoot the size limit.
//! The format is the plain one every unzip reads: a local header and the data for each entry, then
//! the central directory and its end record. No zip64 (the report is capped far below 4 GiB), no
//! encryption, no extra fields; names are ASCII (`is_file_name`), and times are UTC in the DOS
//! fields — the lines inside carry their own timestamps.

use std::io::{self, Read};

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};

/// Fixed part of a local file header, before the name.
const LOCAL_HEADER: u64 = 30;
/// Fixed part of a central directory header, before the name.
const CENTRAL_HEADER: u64 = 46;
/// The end of central directory record, without a comment.
pub(crate) const END_RECORD: u64 = 22;

/// Zip 2.0: what deflate needs to extract.
const VERSION: u16 = 20;
const DEFLATE: u16 = 8;

/// How much a compression pass reads at a time.
const CHUNK: usize = 64 * 1024;

/// One file of the archive, compressed.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub(crate) name: String,
    /// Bytes before compression.
    pub(crate) raw_len: u64,
    pub(crate) crc32: u32,
    /// Raw deflate, as the entry's data.
    pub(crate) deflated: Vec<u8>,
    /// For the DOS date and time, UTC.
    pub(crate) modified_unix_s: u64,
    /// The file's size when only its end is in the entry (`truncated` in the metadata).
    pub(crate) truncated_from: Option<u64>,
}

impl Entry {
    /// Compress everything `reader` yields, a chunk at a time: the file itself is never in memory,
    /// only what it compresses to.
    pub(crate) fn deflate_from(
        name: &str,
        mut reader: impl Read,
        modified_unix_s: u64,
    ) -> io::Result<Self> {
        let mut crc = Crc::new();
        // Counted here: `Crc::amount` is 32-bit.
        let mut raw_len = 0u64;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let chunk = buf.get(..n).unwrap_or_default();
            crc.update(chunk);
            raw_len += n as u64;
            io::Write::write_all(&mut encoder, chunk)?;
        }
        Ok(Self {
            name: name.to_string(),
            raw_len,
            crc32: crc.sum(),
            deflated: encoder.finish()?,
            modified_unix_s,
            truncated_from: None,
        })
    }

    /// [`Self::deflate_from`] over bytes already in memory (the generated files).
    pub(crate) fn deflate_bytes(name: &str, bytes: &[u8], modified_unix_s: u64) -> Self {
        // Reading a slice and writing a `Vec` cannot fail.
        Self::deflate_from(name, bytes, modified_unix_s).unwrap_or_else(|e| {
            tracing::error!(name, "diagnostics: compressing bytes in memory failed: {e}");
            Self {
                name: name.to_string(),
                raw_len: 0,
                crc32: 0,
                deflated: vec![0x03, 0x00],
                modified_unix_s,
                truncated_from: None,
            }
        })
    }

    /// What this entry adds to the archive: its data and both of its headers.
    pub(crate) fn cost(&self) -> u64 {
        cost_of(self.name.len(), self.deflated.len())
    }
}

/// What an entry named with `name_len` bytes and `deflated_len` bytes of data adds to the archive.
pub(crate) fn cost_of(name_len: usize, deflated_len: usize) -> u64 {
    LOCAL_HEADER + CENTRAL_HEADER + 2 * name_len as u64 + deflated_len as u64
}

/// The archive, entries in the order given. Refuses what the plain format cannot hold — an entry
/// of 4 GiB or more, more than 65 535 entries — which the report never comes near.
pub(crate) fn write(entries: &[Entry]) -> io::Result<Vec<u8>> {
    let too_big = |what: &str| io::Error::other(format!("zip: {what} does not fit without zip64"));
    let total: u64 = entries.iter().map(Entry::cost).sum::<u64>() + END_RECORD;
    let count = u16::try_from(entries.len()).map_err(|_| too_big("the entry count"))?;
    let mut out = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    let mut central = Vec::new();
    for e in entries {
        let offset = u32::try_from(out.len()).map_err(|_| too_big("an offset"))?;
        let packed = u32::try_from(e.deflated.len()).map_err(|_| too_big(&e.name))?;
        let raw = u32::try_from(e.raw_len).map_err(|_| too_big(&e.name))?;
        let name_len = u16::try_from(e.name.len()).map_err(|_| too_big("a name"))?;
        let (time, date) = dos_time(e.modified_unix_s);

        put32(&mut out, 0x0403_4b50);
        for v in [VERSION, 0, DEFLATE, time, date] {
            put16(&mut out, v);
        }
        for v in [e.crc32, packed, raw] {
            put32(&mut out, v);
        }
        put16(&mut out, name_len);
        put16(&mut out, 0); // no extra field
        out.extend_from_slice(e.name.as_bytes());
        out.extend_from_slice(&e.deflated);

        put32(&mut central, 0x0201_4b50);
        // Made by: zip 2.0 on MS-DOS (attributes none), the same version needed.
        for v in [VERSION, VERSION, 0, DEFLATE, time, date] {
            put16(&mut central, v);
        }
        for v in [e.crc32, packed, raw] {
            put32(&mut central, v);
        }
        put16(&mut central, name_len);
        for v in [0, 0, 0, 0] {
            // Extra field, comment, disk number, internal attributes.
            put16(&mut central, v);
        }
        put32(&mut central, 0); // external attributes
        put32(&mut central, offset);
        central.extend_from_slice(e.name.as_bytes());
    }
    let directory_at = u32::try_from(out.len()).map_err(|_| too_big("the directory offset"))?;
    let directory_len = u32::try_from(central.len()).map_err(|_| too_big("the directory"))?;
    out.extend_from_slice(&central);
    put32(&mut out, 0x0605_4b50);
    for v in [0, 0, count, count] {
        put16(&mut out, v);
    }
    put32(&mut out, directory_len);
    put32(&mut out, directory_at);
    put16(&mut out, 0); // no comment
    Ok(out)
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// `(time, date)` in the DOS fields, UTC, clamped to what they can say (1980–2107).
fn dos_time(unix_s: u64) -> (u16, u16) {
    let days = i64::try_from(unix_s / 86_400).unwrap_or(i64::MAX);
    let rem = unix_s % 86_400;
    let (y, m, d) = crate::fakerinput_setup::civil_from_days(days);
    if y < 1980 {
        return (0, (1 << 5) | 1);
    }
    if y > 2107 {
        return ((23 << 11) | (59 << 5) | 29, (127 << 9) | (12 << 5) | 31);
    }
    let time = ((rem / 3600) << 11) | (((rem % 3600) / 60) << 5) | ((rem % 60) / 2);
    let date = ((y - 1980) << 9) | (i64::from(m) << 5) | i64::from(d);
    (
        u16::try_from(time).unwrap_or(0),
        u16::try_from(date).unwrap_or(0),
    )
}

/// The archive read back, for the tests: every entry's name and inflated bytes, with each local
/// header, size and CRC checked against the central directory.
#[cfg(test)]
pub(crate) fn read_back(zip: &[u8]) -> Vec<(String, Vec<u8>)> {
    use std::io::Read as _;

    let u16_at = |at: usize| u16::from_le_bytes([zip[at], zip[at + 1]]);
    let u32_at = |at: usize| u32::from_le_bytes([zip[at], zip[at + 1], zip[at + 2], zip[at + 3]]);
    let end = zip.len() - END_RECORD as usize;
    assert_eq!(u32_at(end), 0x0605_4b50, "end record");
    let count = usize::from(u16_at(end + 10));
    let mut at = u32_at(end + 16) as usize;
    assert_eq!(
        at + u32_at(end + 12) as usize,
        end,
        "the directory ends at the end record"
    );
    let mut out = Vec::new();
    for _ in 0..count {
        assert_eq!(u32_at(at), 0x0201_4b50, "central header");
        assert_eq!(u16_at(at + 10), DEFLATE);
        let crc = u32_at(at + 16);
        let packed = u32_at(at + 20) as usize;
        let raw = u32_at(at + 24) as usize;
        let name_len = usize::from(u16_at(at + 28));
        let skip = usize::from(u16_at(at + 30)) + usize::from(u16_at(at + 32));
        let local = u32_at(at + 42) as usize;
        let name = String::from_utf8(zip[at + 46..at + 46 + name_len].to_vec()).expect("name");
        at += 46 + name_len + skip;

        assert_eq!(u32_at(local), 0x0403_4b50, "local header of {name}");
        assert_eq!(u32_at(local + 14), crc, "{name}: local CRC");
        assert_eq!(u32_at(local + 18) as usize, packed, "{name}: local size");
        assert_eq!(
            &zip[local + 30..local + 30 + name_len],
            name.as_bytes(),
            "{name}: local name"
        );
        let data = local + 30 + name_len + usize::from(u16_at(local + 28));
        let mut bytes = Vec::new();
        flate2::read::DeflateDecoder::new(&zip[data..data + packed])
            .read_to_end(&mut bytes)
            .expect("inflates");
        assert_eq!(bytes.len(), raw, "{name}: size");
        let mut check = Crc::new();
        check.update(&bytes);
        assert_eq!(check.sum(), crc, "{name}: CRC");
        out.push((name, bytes));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_reads_back_entry_for_entry() {
        let big: Vec<u8> = (0..300_000u32)
            .flat_map(|i| (i % 251).to_le_bytes())
            .collect();
        let entries = [
            Entry::deflate_bytes("report.json", br#"{"format":1}"#, 1_790_590_529),
            Entry::deflate_bytes("empty.log", b"", 0),
            Entry::deflate_from("big.bin", big.as_slice(), 1_790_590_529).expect("deflates"),
        ];
        let zip = write(&entries).expect("writes");
        let expected_len: u64 = entries.iter().map(Entry::cost).sum::<u64>() + END_RECORD;
        assert_eq!(zip.len() as u64, expected_len, "cost() is exact");
        let back = read_back(&zip);
        assert_eq!(
            back.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["report.json", "empty.log", "big.bin"]
        );
        assert_eq!(back[0].1, br#"{"format":1}"#);
        assert!(back[1].1.is_empty());
        assert_eq!(back[2].1, big);
        assert_eq!(entries[2].raw_len, big.len() as u64);
    }

    /// An unzip that is not ours reads the archive the same: Windows' `tar` (libarchive's bsdtar,
    /// in Windows since 10 1803). Skipped, saying so, where there is none.
    #[test]
    fn another_unzip_reads_it_too() {
        let text = "строка лога\n".repeat(5000);
        let entries = [
            Entry::deflate_bytes("report.json", br#"{"format":1}"#, 1_790_676_930),
            Entry::deflate_bytes("afklink-app.2026-09-29.log", text.as_bytes(), 1_790_676_930),
        ];
        let zip = write(&entries).expect("writes");
        let dir = std::env::temp_dir().join(format!("afklink-zip-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("logs.zip");
        std::fs::write(&path, &zip).expect("write");
        for (name, want) in [
            ("report.json", br#"{"format":1}"#.to_vec()),
            ("afklink-app.2026-09-29.log", text.as_bytes().to_vec()),
        ] {
            let out = std::process::Command::new("tar")
                .arg("-xOf")
                .arg(&path)
                .arg(name)
                .output();
            match out {
                Ok(out) if out.status.success() => assert_eq!(out.stdout, want, "{name}"),
                Ok(out) => unreachable!(
                    "tar refused the archive: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                Err(e) => {
                    eprintln!("no tar to check the archive with ({e}); skipped");
                    break;
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dos_times_are_utc_and_clamped() {
        // 2026-09-29T10:15:30Z.
        let (time, date) = dos_time(1_790_676_930);
        assert_eq!(date, ((2026 - 1980) << 9) | (9 << 5) | 29);
        assert_eq!(time, (10 << 11) | (15 << 5) | 15);
        assert_eq!(dos_time(0), (0, (1 << 5) | 1), "before 1980: 1980-01-01");
    }
}
