//! Delivering frames on the vsync grid into a writer, with progress logging.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;

use crate::codec::Move;
use crate::format::{Metadata, Summary};
use crate::motion::{Stamper, Vsync};
use crate::rng::Rng;
use crate::writer::{FrameKind, Writer, WriterOptions};

/// A writer fed at vsync indices: it stamps each delivery with jittered time and counts.
pub struct Emitter {
    writer: Writer,
    stamper: Stamper,
    scenario: String,
    started: Instant,
    last_log: Instant,
    delivered: u64,
    bytes: u64,
    kinds: [u64; 3],
}

impl Emitter {
    pub fn create(
        path: &Path,
        meta: &Metadata,
        opts: WriterOptions,
        vsync: Vsync,
        jitter_rng: Rng,
    ) -> Result<Self> {
        let writer = Writer::create(path, meta, opts)?;
        tracing::info!(scenario = %meta.scenario, path = %path.display(), "generating");
        Ok(Self {
            writer,
            stamper: Stamper::new(vsync, meta.timing.jitter_us, jitter_rng),
            scenario: meta.scenario.clone(),
            started: Instant::now(),
            last_log: Instant::now(),
            delivered: 0,
            bytes: 0,
            kinds: [0; 3],
        })
    }

    /// Deliver `frame` at vsync `k`.
    pub fn deliver(&mut self, k: u64, frame: &[u8], moves: &[Move]) -> Result<u64> {
        let t = self.stamper.stamp(k);
        let pushed = self.writer.push(t, frame, moves)?;
        self.delivered += 1;
        self.bytes += pushed.bytes as u64;
        self.kinds[match pushed.kind {
            FrameKind::Key => 0,
            FrameKind::Inter => 1,
            FrameKind::Repeat => 2,
        }] += 1;
        if self.last_log.elapsed().as_secs() >= 5 {
            self.last_log = Instant::now();
            tracing::info!(
                scenario = %self.scenario,
                delivered = self.delivered,
                at_s = t as f64 / 1e6,
                mb = self.bytes as f64 / 1e6,
                "progress"
            );
        }
        Ok(t)
    }

    pub fn finish(self, duration_us: u64) -> Result<Summary> {
        let summary = self.writer.finish(duration_us)?;
        tracing::info!(
            scenario = %self.scenario,
            frames = self.delivered,
            key = self.kinds[0],
            inter = self.kinds[1],
            repeat = self.kinds[2],
            mb = self.bytes as f64 / 1e6,
            wall_s = self.started.elapsed().as_secs_f64(),
            "generated"
        );
        Ok(summary)
    }
}
