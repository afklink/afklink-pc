//! Screen-content corpus for the offline simulator.
//!
//! The simulator runs the real encoder, controller and transport on virtual time; what it needs from
//! outside is the screen: the frames WGC would deliver and *when* it would deliver them. This crate
//! is that input: a file format, a streaming reader, generators that build realistic scenarios from
//! real renders and real video, and a live recorder for the user's own screen.
//!
//! # Reading (the simulator's side)
//!
//! ```no_run
//! use afklink_corpus::Reader;
//! # fn main() -> anyhow::Result<()> {
//! let mut r = Reader::open(std::path::Path::new("corpus/text_scroll_jerky_article.rcorp"))?;
//! let (src_w, src_h) = (r.metadata().source.width, r.metadata().source.height); // for QualityTarget::set_source
//! let duration_us = r.duration_us();                                              // the scenario may end on a still screen
//! while let Some(f) = r.next_frame()? {
//!     // f.t_us: capture time (µs from scenario start); f.data: BGRA, f.width x f.height.
//!     // Feed it to the capturer's pacing (`afklink_capture::pace::admit`) at virtual time f.t_us,
//!     // then scale it with `fit_for_rung` exactly as `wgc::Handler` does.
//! }
//! # Ok(()) }
//! ```
//!
//! [`Reader::next_frame`] borrows one internal picture (no per-frame allocation);
//! [`Reader::into_frames`] is the owning `Iterator<Item = Result<CorpusFrame>>`; [`Reader::seek`]
//! jumps through the key-frame index. A file whose writer died streams up to the damage and then
//! reports [`Reader::is_truncated`].
//!
//! # What a file holds
//!
//! One scenario per `.rcorp` file (layout in [`format`], frame coding in [`codec`]):
//!
//! * JSON metadata: scenario name and description, the **source** screen (3600x2400, 60 Hz, 200%:
//!   what the ladder prices rungs against), the **stored** size and whether it is the native screen
//!   or already the top rung, provenance (generator + seed + every parameter, or "recorded"),
//!   how timestamps were made, caveats.
//! * One record per WGC delivery: the capture timestamp in microseconds and the frame. No record
//!   while the screen is still — an idle minute is a one-minute gap, and the end record carries the
//!   scenario's full duration so a still ending is not lost. A delivery that did not change the
//!   picture (a 30 fps video on a 60 Hz desktop) is a `REPEAT` record: WGC offered it, the pacer
//!   must see it, it costs no disk.
//! * Frames are lossless BGRA: key frames are planes with a subtract-green transform and a median
//!   predictor, inter frames are moves (a scroll, a dragged window) plus residual tiles, all zstd.
//!   Decoding reproduces the writer's input bit for bit, so the H.264 the simulator gets is the H.264
//!   the original frames would give. See [`codec`] for why this shape and the sizes it reaches.
//!
//! # Stored size: native for screen content, top rung for natural content
//!
//! The live capturer scales every frame from 3600x2400 with a box filter to the rung's height
//! (`afklink_core::scale::Scaler`, called from `wgc::Handler`). For text, *which* pixels the box
//! averages decides what the encoder sees: a scroll of 22 physical pixels is 9.9 pixels at 1080p and
//! 6.6 at 720p, so each rung gets its own sub-pixel phase and its own motion-search cost, and a
//! second box filter over an already-scaled frame is a different picture. Screen-content scenarios
//! are therefore stored at native resolution — which is also cheap, because a moved-rectangle plus
//! residual codec stores a scrolled page as the exposed strip — and the simulator scales them per
//! rung with the real `Scaler`, bit-exactly.
//!
//! Natural content (video, a game) is the opposite case: nothing repeats between frames, lossless
//! 3600x2400 costs about 10 MB a frame, and 30 s of 60 fps would be tens of gigabytes. Those are
//! composed at full resolution, scaled once with the same `Scaler` to 1620x1080 and stored at that
//! size: the 1080p rungs are exact, and lower rungs rescale from it. `afklink-corpus rescale-check`
//! measures what that approximation costs (bytes and QP of direct vs. two-step scaling).
//!
//! # Scenarios and tools
//!
//! `afklink-corpus gen all` builds the default corpus into `<repo>/corpus/`, `<repo>` being this
//! agent repository's root (see [`tools::catalog`]; the article scenarios render a Markdown
//! article that is not part of this repository, found next to an `agent/` checkout or through
//! `AFKLINK_CORPUS_ARTICLE`);
//! `afklink-corpus manifest` writes its README and JSON manifest; `afklink-corpus verify` encodes
//! scenarios with the production encoder at fixed budgets or against an agent log's budget
//! trajectory; `afklink-corpus record` records the live screen (only with the user's agreement).
//!
//! # Adding a scenario
//!
//! 1. If an existing generator fits, add an entry to [`tools::catalog`] with a new name and seed
//!    (e.g. another `ScrollSpec` with different content, profile or planner overrides). Every
//!    parameter lands in the file's metadata, so the file can always be regenerated.
//! 2. For a new kind of motion, add a planner to [`motion`]: a pure function of parameters and a
//!    seed that returns one state per vsync, with a determinism test. A frame is delivered at a vsync
//!    exactly when the picture changed.
//! 3. For a new picture source, add a generator under `tools/` that renders what it needs once
//!    (headless Edge via `tools::edge`, a video via `tools::video::MpvFrames`), composes each frame
//!    at 3600x2400, and hands it to `tools::emit::Emitter::deliver(vsync, frame, moves)`. Pass
//!    [`Move`]s when you know how the picture moved: they only shrink the file.
//! 4. Decide the stored size (native for anything with text, `Scaling::Scaler { max_h: 1080 }` for
//!    natural content) and say what is not realistic in the metadata's `notes`.
//! 5. `afklink-corpus gen <name>`, then `afklink-corpus verify <file>` and `manifest`.
//!
//! # Recording during a live session (design, not implemented)
//!
//! The recorder here captures on its own. A hook inside a session would record exactly what the
//! agent captured while the network did what it did: a tap in `wgc::Handler::on_frame_arrived`
//! **before** `pace::admit` (the corpus needs every delivery, not only the admitted ones), handed the
//! full-resolution buffer and the arrival `Instant`, pushing into a bounded queue that a writer
//! thread drains; a full queue drops and counts rather than blocking capture. It would be switched
//! on per session from the config, start its clock at the session's first frame so timestamps line
//! up with the `pipeline` log lines, and write the file next to the session log. Its cost is one
//! 35 MB copy per delivery on the capture thread, which is why it must stay off by default. It is
//! not built yet because `capture` and `core::agent` are being changed by other work.

pub mod codec;
pub mod format;
pub mod motion;
pub mod reader;
pub mod rng;
pub mod writer;

#[cfg(feature = "tools")]
pub mod tools;

pub use codec::Move;
pub use format::{Metadata, Origin, Scaling, Summary};
pub use reader::{read_info, CorpusFrame, FrameRef, Frames, Reader};
pub use writer::{FrameKind, Pushed, Writer, WriterOptions};

use afklink_core::scale::Scaler;
use anyhow::Result;

/// Scale a stored frame for a rung of height `max_h`, exactly as the capture thread does
/// (`Scaler::fit_into(.., u32::MAX / 2, max_h, ..)`), into `out`. Returns the scaled size.
///
/// For a [`Scaling::Native`] file this is bit-exact at every rung. For a file stored at the top
/// rung it is exact at that height and a second box filter below it.
pub fn fit_for_rung(
    frame: &FrameRef<'_>,
    max_h: u32,
    scaler: &mut Scaler,
    out: &mut Vec<u8>,
) -> Result<(u32, u32)> {
    scaler.fit_into(
        frame.data,
        frame.width,
        frame.height,
        u32::MAX / 2,
        max_h,
        out,
    )
}
