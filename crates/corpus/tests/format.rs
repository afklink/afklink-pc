//! Round trips, timestamps, truncation and corruption, seeking.

use std::path::{Path, PathBuf};

use afklink_corpus::format::{
    CodecInfo, Metadata, Origin, Scaling, SourceInfo, StoredInfo, TimingInfo, FORMAT_VERSION,
    PIXEL_FORMAT_BGRA8,
};
use afklink_corpus::{FrameKind, Move, Reader, Writer, WriterOptions};

const W: u32 = 200;
const H: u32 = 150;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("afklink-corpus-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join(name)
}

fn meta(name: &str) -> Metadata {
    Metadata {
        format_version: FORMAT_VERSION,
        scenario: name.into(),
        description: "test".into(),
        created_utc: "2026-09-24T00:00:00Z".into(),
        source: SourceInfo {
            width: W,
            height: H,
            display_hz: 60.0,
            scale_factor: 1.0,
        },
        stored: StoredInfo {
            width: W,
            height: H,
            pixel_format: PIXEL_FORMAT_BGRA8.into(),
            scaling: Scaling::Native,
        },
        origin: Origin::Synthetic {
            generator: "test".into(),
            seed: 1,
            params: serde_json::json!({}),
            inputs: vec![],
        },
        timing: TimingInfo {
            clock: "test".into(),
            jitter_us: 0,
            duplicates: true,
        },
        codec: CodecInfo {
            tile: 0,
            zstd_level: 0,
            key_interval_us: 0,
        },
        notes: vec![],
    }
}

/// A picture with text-like structure that changes with `seed`.
fn picture(seed: u32) -> Vec<u8> {
    let mut v = vec![0u8; (W * H * 4) as usize];
    for (i, px) in v.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let (x, y) = (i as u32 % W, i as u32 / W);
        let ink = (y / 3 + seed).is_multiple_of(7) && (x * 13 + y * 7 + seed) % 5 < 3;
        *px = if ink {
            [30, 30, 36, 255]
        } else {
            [250, (x ^ seed) as u8, 248, 255]
        };
    }
    v
}

/// `prev` scrolled up by `dy` rows, the exposed rows filled from `fresh`.
fn scrolled(prev: &[u8], fresh: &[u8], dy: usize) -> Vec<u8> {
    let stride = (W * 4) as usize;
    let mut out = fresh.to_vec();
    out[..(H as usize - dy) * stride].copy_from_slice(&prev[dy * stride..]);
    out
}

/// Frames of every kind, with their timestamps and the moves a generator would pass.
fn sequence() -> Vec<(u64, Vec<u8>, Vec<Move>)> {
    let mut out = Vec::new();
    let a = picture(1);
    out.push((0, a.clone(), vec![]));
    let b = scrolled(&a, &picture(2), 9);
    let mv = Move::vertical_scroll(0, 0, W, H, 9).expect("move");
    out.push((16_667, b.clone(), vec![mv]));
    out.push((33_333, b.clone(), vec![])); // repeat
    let mut c = b.clone();
    c[4000..4100].fill(7);
    out.push((50_000, c.clone(), vec![]));
    // A long still gap, then a big change.
    out.push((2_050_000, picture(3), vec![]));
    for i in 0..30u32 {
        out.push((2_100_000 + u64::from(i) * 16_667, picture(10 + i), vec![]));
    }
    out
}

fn write(path: &Path, frames: &[(u64, Vec<u8>, Vec<Move>)], opts: WriterOptions, duration: u64) {
    let mut w = Writer::create(path, &meta("t"), opts).expect("create");
    for (t, f, m) in frames {
        w.push(*t, f, m).expect("push");
    }
    w.finish(duration).expect("finish");
}

#[test]
fn every_frame_comes_back_bit_exact_with_its_timestamp() {
    let path = temp("roundtrip.rcorp");
    let frames = sequence();
    let opts = WriterOptions {
        key_interval_us: 1_000_000,
        ..WriterOptions::default()
    };
    write(&path, &frames, opts, 5_000_000);

    let mut r = Reader::open(&path).expect("open");
    let s = r.summary().cloned().expect("summary of a finished file");
    assert_eq!(s.frame_count, frames.len() as u64);
    assert_eq!(s.repeat_frames, 1);
    assert!(s.key_frames >= 2, "the 2 s gap forces a key: {s:?}");
    assert_eq!(s.duration_us, 5_000_000, "a still ending is kept");
    assert_eq!(r.metadata().scenario, "t");
    let mut kinds = Vec::new();
    let mut i = 0;
    while let Some(f) = r.next_frame().expect("frame") {
        assert_eq!(f.t_us, frames[i].0, "timestamp of frame {i}");
        assert_eq!(f.data, frames[i].1.as_slice(), "pixels of frame {i}");
        assert_eq!(f.index, i as u64);
        kinds.push(f.kind);
        i += 1;
    }
    assert_eq!(i, frames.len());
    assert!(!r.is_truncated());
    assert_eq!(kinds[0], FrameKind::Key);
    assert_eq!(
        kinds[1],
        FrameKind::Inter,
        "a scroll with its move is an inter frame"
    );
    assert_eq!(kinds[2], FrameKind::Repeat);
    assert_eq!(r.duration_us(), Some(5_000_000));
    assert!(r.next_frame().expect("after the end").is_none());
}

#[test]
fn the_owning_iterator_matches_the_lending_reader() {
    let path = temp("iter.rcorp");
    let frames = sequence();
    write(&path, &frames, WriterOptions::default(), 3_000_000);
    let owned: Vec<_> = Reader::open(&path)
        .expect("open")
        .into_frames()
        .collect::<anyhow::Result<Vec<_>>>()
        .expect("frames");
    assert_eq!(owned.len(), frames.len());
    for (o, (t, f, _)) in owned.iter().zip(&frames) {
        assert_eq!(o.t_us, *t);
        assert_eq!(&o.data, f);
    }
    let core = owned[1].clone().into_core_frame();
    assert_eq!(core.timestamp_ms, 16);
    assert_eq!((core.width, core.height), (W, H));
}

#[test]
fn timestamps_must_increase_and_sizes_must_match() {
    let path = temp("ts.rcorp");
    let mut w = Writer::create(&path, &meta("ts"), WriterOptions::default()).expect("create");
    w.push(100, &picture(1), &[]).expect("first");
    assert!(w.push(100, &picture(2), &[]).is_err(), "equal timestamp");
    assert!(w.push(50, &picture(2), &[]).is_err(), "going back");
    assert!(w.push(200, &[0u8; 16], &[]).is_err(), "wrong size");
    w.push(200, &picture(2), &[]).expect("still usable");
    assert!(w.finish(150).is_err(), "a duration before the last frame");
}

#[test]
fn an_idle_scenario_is_one_frame_and_a_long_duration() {
    let path = temp("idle.rcorp");
    write(
        &path,
        &[(0, picture(4), vec![])],
        WriterOptions::default(),
        60_000_000,
    );
    let mut r = Reader::open(&path).expect("open");
    assert_eq!(r.duration_us(), Some(60_000_000));
    assert!(r.next_frame().expect("frame").is_some());
    assert!(r.next_frame().expect("end").is_none());
    assert!(!r.is_truncated());
}

#[test]
fn a_truncated_file_streams_every_complete_frame() {
    let path = temp("full.rcorp");
    let frames = sequence();
    write(&path, &frames, WriterOptions::default(), 4_000_000);
    let bytes = std::fs::read(&path).expect("read");

    // Where each frame record ends, found by reading the finished file.
    let complete_ends: Vec<usize> = {
        let mut ends = Vec::new();
        let mut r = Reader::open(&path).expect("open");
        let meta_len = u32::from_le_bytes(bytes[12..16].try_into().expect("len")) as usize;
        let mut at = 16 + meta_len;
        while r.next_frame().expect("frame").is_some() {
            let len = u32::from_le_bytes(bytes[at + 9..at + 13].try_into().expect("len")) as usize;
            at += 13 + len + 4;
            ends.push(at);
        }
        ends
    };
    assert_eq!(complete_ends.len(), frames.len());

    for (cut, expect) in [
        (complete_ends[3], 4),            // right after a record
        (complete_ends[3] + 5, 4),        // inside the next header
        (complete_ends[5] - 3, 5),        // inside a record's CRC
        (complete_ends[5] - 40, 5),       // inside a payload
        (bytes.len() - 16, frames.len()), // footer lost, end record intact
        (bytes.len() - 20, frames.len()), // inside the end record
    ] {
        let p = temp(&format!("cut-{cut}.rcorp"));
        std::fs::write(&p, &bytes[..cut]).expect("write cut");
        let mut r = Reader::open(&p).expect("a truncated file still opens");
        assert!(
            r.summary().is_none(),
            "cut at {cut}: no summary without a footer"
        );
        let mut n = 0;
        while let Some(f) = r.next_frame().expect("complete frames read fine") {
            assert_eq!(f.data, frames[n].1.as_slice());
            n += 1;
        }
        assert_eq!(n, expect, "cut at {cut}");
        if cut == bytes.len() - 16 {
            // Only the footer is gone: the end record is still read while streaming.
            assert!(!r.is_truncated(), "cut at {cut}");
            assert_eq!(r.duration_us(), Some(4_000_000));
        } else {
            assert!(r.is_truncated(), "cut at {cut}");
            assert_eq!(r.duration_us(), Some(frames[n - 1].0), "cut at {cut}");
        }
    }
}

#[test]
fn a_writer_dropped_without_finish_leaves_a_readable_truncated_file() {
    let path = temp("dropped.rcorp");
    {
        let mut w = Writer::create(&path, &meta("d"), WriterOptions::default()).expect("create");
        w.push(0, &picture(1), &[]).expect("push");
        w.push(10_000, &picture(2), &[]).expect("push");
    }
    let mut r = Reader::open(&path).expect("open");
    assert!(r.summary().is_none());
    let mut n = 0;
    while r.next_frame().expect("frame").is_some() {
        n += 1;
    }
    assert_eq!(n, 2);
    assert!(r.is_truncated());
}

#[test]
fn a_corrupt_record_is_an_error() {
    let path = temp("corrupt.rcorp");
    let frames = sequence();
    write(&path, &frames, WriterOptions::default(), 4_000_000);
    let mut bytes = std::fs::read(&path).expect("read");
    let meta_len = u32::from_le_bytes(bytes[12..16].try_into().expect("len")) as usize;
    let first_payload = 16 + meta_len + 13;
    bytes[first_payload + 20] ^= 0xff;
    let p = temp("corrupt-flipped.rcorp");
    std::fs::write(&p, &bytes).expect("write");
    let mut r = Reader::open(&p).expect("header is fine");
    let err = r.next_frame().expect_err("CRC must catch the flipped byte");
    assert!(format!("{err:#}").contains("CRC"), "{err:#}");
}

#[test]
fn seek_lands_on_the_picture_on_screen_at_that_instant() {
    let path = temp("seek.rcorp");
    let frames = sequence();
    let opts = WriterOptions {
        key_interval_us: 100_000,
        ..WriterOptions::default()
    };
    write(&path, &frames, opts, 4_000_000);
    let mut r = Reader::open(&path).expect("open");
    for target in [0u64, 20_000, 1_000_000, 2_100_000, 2_200_000, 3_999_999] {
        let idx = frames
            .iter()
            .rposition(|f| f.0 <= target)
            .expect("a frame before");
        {
            let cur = r.seek(target).expect("seek").expect("a picture");
            assert_eq!(cur.t_us, frames[idx].0, "seek {target}");
            assert_eq!(cur.data, frames[idx].1.as_slice(), "seek {target}");
            assert_eq!(cur.index, idx as u64);
        }
        match r.next_frame().expect("next") {
            Some(n) => assert_eq!(n.t_us, frames[idx + 1].0),
            None => assert_eq!(idx, frames.len() - 1),
        }
    }
    r.rewind().expect("rewind");
    assert_eq!(r.next_frame().expect("first").expect("frame").t_us, 0);
}

#[test]
fn not_a_corpus_file_is_refused() {
    let p = temp("junk.rcorp");
    std::fs::write(&p, b"definitely not a corpus").expect("write");
    assert!(Reader::open(&p).is_err());
}
