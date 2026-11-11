//! A generator end to end, without Edge: a procedural page scrolled by the planner, stamped and
//! written. Same seed, same bytes; another seed, another file.

#![cfg(feature = "tools")]

use std::path::PathBuf;

use afklink_corpus::format::{
    CodecInfo, Metadata, Origin, Scaling, SourceInfo, StoredInfo, TimingInfo, FORMAT_VERSION,
    PIXEL_FORMAT_BGRA8,
};
use afklink_corpus::motion::{plan_scroll, ScrollParams, ScrollProfile, Vsync};
use afklink_corpus::rng::Rng;
use afklink_corpus::tools::emit::Emitter;
use afklink_corpus::tools::image::{rgb, Image};
use afklink_corpus::{Move, Reader, WriterOptions};

const W: u32 = 320;
const H: u32 = 240;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("afklink-corpus-gen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join(name)
}

fn meta(seed: u64) -> Metadata {
    Metadata {
        format_version: FORMAT_VERSION,
        scenario: "gen".into(),
        description: "procedural scroll".into(),
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
            seed,
            params: serde_json::json!({}),
            inputs: vec![],
        },
        timing: TimingInfo {
            clock: "vsync_model".into(),
            jitter_us: 700,
            duplicates: false,
        },
        codec: CodecInfo {
            tile: 0,
            zstd_level: 0,
            key_interval_us: 0,
        },
        notes: vec![],
    }
}

/// A tall page of "text lines".
fn page() -> Image {
    let mut img = Image::new(W, 4000, rgb(0xffffff));
    for line in 0..(4000 / 20) {
        let len = 40 + (line * 37) % 220;
        img.fill(
            12,
            i64::from(line * 20 + 6),
            i64::from(len),
            8,
            rgb(0x202020),
        );
    }
    img
}

fn generate(seed: u64, name: &str) -> (PathBuf, usize) {
    let tall = page();
    let mut p = ScrollParams::new(
        ScrollProfile::Jerky,
        f64::from(4000 - H),
        f64::from(H),
        10.0,
    );
    p.seed = seed;
    p.seconds = 8.0;
    let plan = plan_scroll(&p);
    let path = temp(name);
    let mut rng = Rng::new(seed);
    let mut em = Emitter::create(
        &path,
        &meta(seed),
        WriterOptions::default(),
        Vsync { hz: 60.0 },
        rng.fork(1),
    )
    .expect("emitter");
    let mut frame = Image::new(W, H, rgb(0));
    let mut last: Option<i64> = None;
    let mut delivered = 0;
    for (k, &pos) in plan.iter().enumerate() {
        if last == Some(pos) {
            continue;
        }
        frame.blit(&tall, 0, pos, i64::from(W), i64::from(H), 0, 0);
        let moves: Vec<Move> = last
            .and_then(|l| Move::vertical_scroll(0, 0, W, H, pos - l))
            .into_iter()
            .collect();
        em.deliver(k as u64, &frame.px, &moves).expect("deliver");
        last = Some(pos);
        delivered += 1;
    }
    em.finish(8_000_000).expect("finish");
    (path, delivered)
}

#[test]
fn same_seed_same_file_other_seed_other_file() {
    let (a, na) = generate(21, "a.rcorp");
    let (b, nb) = generate(21, "b.rcorp");
    let (c, _) = generate(22, "c.rcorp");
    assert_eq!(na, nb);
    assert!(na > 20, "a jerky plan moves: {na} deliveries");
    let (ba, bb, bc) = (
        std::fs::read(&a).expect("a"),
        std::fs::read(&b).expect("b"),
        std::fs::read(&c).expect("c"),
    );
    assert_eq!(ba, bb, "a generator is a pure function of its seed");
    assert_ne!(ba, bc);

    // And the idle stretches really are gaps: consecutive deliveries are at least one vsync apart,
    // and some are far more.
    let mut r = Reader::open(&a).expect("open");
    let mut last = None;
    let mut max_gap = 0;
    while let Some(f) = r.next_frame().expect("frame") {
        if let Some(l) = last {
            let gap = f.t_us - l;
            assert!(gap >= 16_667 - 1_400, "gap {gap}");
            max_gap = max_gap.max(gap);
        }
        last = Some(f.t_us);
    }
    assert!(
        max_gap > 500_000,
        "pauses between gestures are gaps: {max_gap}"
    );
}
