//! The flight recorder: the last [`WINDOW`] of our crates' `debug` lines, kept in memory whatever
//! the file log's level, for a diagnostics report («Отправить логи») to carry as `recent-debug.log`.
//!
//! A release after the beta logs at `info`, and a tester may lower the level to save disk; a bad
//! session is then over before anyone could have raised it. The recorder keeps the detail anyway,
//! for a quarter of an hour, and only the owner's press of «Отправить логи» ever takes it out of the
//! process — it is never written to disk.
//!
//! # What it records
//!
//! Its own filter, [`filter`]: `warn,afklink=debug` — exactly what the file gets at `debug` — beside
//! the file's, not under it (the subscriber's layers each have their own filter, see `lib.rs`'s
//! `log_layers`). So the file gets what its level says and nothing more, and the recorder gets
//! `debug` of ours plus third-party warnings, whether the file is at `error`, `info` or `debug`. It
//! never records `trace`: the file does at `trace`, and a per-packet line has no place in memory.
//! Lines are formatted by the file's own layer (`log_file::file_layer`), so a recorded line is a
//! file line, timestamp and target included.
//!
//! `off` («Выключено», from the setting or from `RUST_LOG=off`) switches the recorder off too and
//! empties it: «Журнал не пишется» holds for memory as well. `RUST_LOG` otherwise decides only the
//! file's filter. Off is a state of the ring itself ([`FlightRecorder::set_on`]), set and checked
//! under the ring's lock, not only a filter: a line that was already past the filter on another
//! thread when `off` came is dropped, never kept after it.
//!
//! # Bounds and cost
//!
//! [`WINDOW`] by age and [`MAX_BYTES`] by size, whichever is reached first; the oldest lines go. At
//! the busiest measured minute (~530 lines a minute, ~300 bytes each) fifteen
//! minutes are ~2.4 MB, so the age bound is the one that works. A line costs one format into the
//! layer's thread-local buffer, one allocation and a short lock: ~0.8 µs in a release build
//! (`recording_costs_microseconds_a_line`, ignored by default) — at ~9 lines a second, under
//! a thousandth of a percent of a core. Nothing new is logged per frame or per packet for it.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_core::logging::LogLevel;
use tracing_subscriber::EnvFilter;

/// How far back the recorder reaches.
pub(crate) const WINDOW: Duration = Duration::from_secs(15 * 60);

/// The most it holds, in bytes of formatted lines.
pub(crate) const MAX_BYTES: usize = 16 * 1024 * 1024;

/// What the recorder lets through while it is on: the file's filter at `debug`.
pub(crate) const RECORDING: LogLevel = LogLevel::Debug;

/// The recorder's filter: [`RECORDING`]'s while `on`, nothing while off.
pub(crate) fn filter(on: bool) -> EnvFilter {
    if on {
        RECORDING.filter()
    } else {
        LogLevel::Off.filter()
    }
}

/// The ring of recent lines. Shared by the logging layer (writing) and the report (reading).
#[derive(Debug)]
pub(crate) struct FlightRecorder {
    ring: Mutex<Ring>,
    window: Duration,
    max_bytes: usize,
}

#[derive(Debug)]
struct Ring {
    /// Whether lines are kept. Off, [`FlightRecorder::record`] drops every line it is handed.
    on: bool,
    /// Oldest first; each line with the moment it was recorded.
    lines: VecDeque<(Instant, Arc<[u8]>)>,
    bytes: usize,
    /// Lines let go since the start: past the window, and for room.
    evicted_by_age: u64,
    evicted_by_size: u64,
}

/// What a [`FlightRecorder::snapshot`] holds, for the report and its log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Stats {
    pub(crate) lines: usize,
    pub(crate) bytes: usize,
    /// How long ago the oldest line kept was recorded; `None` when empty.
    pub(crate) span: Option<Duration>,
    pub(crate) evicted_by_age: u64,
    pub(crate) evicted_by_size: u64,
}

impl FlightRecorder {
    /// A recorder that is on.
    pub(crate) fn new(window: Duration, max_bytes: usize) -> Self {
        Self {
            ring: Mutex::new(Ring {
                on: true,
                lines: VecDeque::new(),
                bytes: 0,
                evicted_by_age: 0,
                evicted_by_size: 0,
            }),
            window,
            max_bytes,
        }
    }

    /// Keep `line`, recorded at `now`, and let go of whatever that puts past the bounds. A single
    /// line larger than the whole budget keeps its start. Nothing while the recorder is off.
    pub(crate) fn record(&self, now: Instant, line: &[u8]) {
        let line = line.get(..self.max_bytes).unwrap_or(line);
        let line: Arc<[u8]> = Arc::from(line);
        let mut ring = afklink_core::lock(&self.ring);
        if !ring.on {
            return;
        }
        ring.bytes = ring.bytes.saturating_add(line.len());
        ring.lines.push_back((now, line));
        ring.evict(now, self.window, self.max_bytes);
    }

    /// Everything kept at `now`, oldest first, as one text; and what it is. The lines are taken
    /// under the lock as shared pointers and joined outside it, so a thread logging meanwhile waits
    /// for pointer copies, not for megabytes of text.
    pub(crate) fn snapshot(&self, now: Instant) -> (Vec<u8>, Stats) {
        let (lines, stats) = {
            let mut ring = afklink_core::lock(&self.ring);
            ring.evict(now, self.window, self.max_bytes);
            let lines: Vec<Arc<[u8]>> = ring.lines.iter().map(|(_, l)| Arc::clone(l)).collect();
            let stats = Stats {
                lines: ring.lines.len(),
                bytes: ring.bytes,
                span: ring
                    .lines
                    .front()
                    .map(|(at, _)| now.saturating_duration_since(*at)),
                evicted_by_age: ring.evicted_by_age,
                evicted_by_size: ring.evicted_by_size,
            };
            (lines, stats)
        };
        let mut text = Vec::with_capacity(stats.bytes);
        for line in lines {
            text.extend_from_slice(&line);
        }
        (text, stats)
    }

    /// Switch the recorder on or off. Off also lets go of everything, in the same step under the
    /// ring's lock, so no line recorded before and none handed over after is kept; how many lines
    /// that dropped (0 when switching on).
    pub(crate) fn set_on(&self, on: bool) -> usize {
        let mut ring = afklink_core::lock(&self.ring);
        ring.on = on;
        if on {
            return 0;
        }
        let cleared = ring.lines.len();
        ring.lines.clear();
        ring.bytes = 0;
        cleared
    }

    /// Whether the recorder keeps lines.
    pub(crate) fn is_on(&self) -> bool {
        afklink_core::lock(&self.ring).on
    }

    /// The recorder as the logging layer's writer.
    pub(crate) fn writer(self: &Arc<Self>) -> RecorderWriter {
        RecorderWriter(Arc::clone(self))
    }
}

impl Ring {
    fn evict(&mut self, now: Instant, window: Duration, max_bytes: usize) {
        while let Some((at, line)) = self.lines.front() {
            let old = now.saturating_duration_since(*at) > window;
            let over = self.bytes > max_bytes;
            if !old && !over {
                break;
            }
            self.bytes = self.bytes.saturating_sub(line.len());
            if old {
                self.evicted_by_age += 1;
            } else {
                self.evicted_by_size += 1;
            }
            self.lines.pop_front();
        }
    }
}

/// The recorder as a `MakeWriter` for the formatting layer.
#[derive(Debug, Clone)]
pub(crate) struct RecorderWriter(Arc<FlightRecorder>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RecorderWriter {
    type Writer = LineSink<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LineSink(&self.0)
    }
}

/// One event's writer. The formatting layer hands it a whole formatted line in a single
/// `write_all` (tracing-subscriber formats into a buffer first), so each write is one line.
pub(crate) struct LineSink<'a>(&'a FlightRecorder);

impl io::Write for LineSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.record(Instant::now(), buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(recorder: &FlightRecorder, now: Instant) -> String {
        String::from_utf8(recorder.snapshot(now).0).expect("utf-8")
    }

    #[test]
    fn the_oldest_lines_go_when_the_bytes_run_out() {
        let recorder = FlightRecorder::new(WINDOW, 30);
        let t0 = Instant::now();
        for i in 0..5 {
            recorder.record(t0, format!("line {i}\n").as_bytes()); // 7 bytes each
        }
        let (bytes, stats) = recorder.snapshot(t0);
        assert_eq!(
            String::from_utf8(bytes).expect("utf-8"),
            "line 1\nline 2\nline 3\nline 4\n"
        );
        assert_eq!(
            stats,
            Stats {
                lines: 4,
                bytes: 28,
                span: Some(Duration::ZERO),
                evicted_by_age: 0,
                evicted_by_size: 1,
            }
        );
        // A line bigger than the whole budget keeps its start, alone.
        recorder.record(t0, &[b'x'; 100]);
        let (bytes, stats) = recorder.snapshot(t0);
        assert_eq!(bytes, vec![b'x'; 30]);
        assert_eq!(
            (stats.lines, stats.bytes, stats.evicted_by_size),
            (1, 30, 5)
        );
    }

    #[test]
    fn lines_older_than_the_window_go() {
        let recorder = FlightRecorder::new(Duration::from_secs(15 * 60), MAX_BYTES);
        let t0 = Instant::now();
        recorder.record(t0, b"at 0\n");
        recorder.record(t0 + Duration::from_secs(10 * 60), b"at 10 min\n");
        recorder.record(t0 + Duration::from_secs(16 * 60), b"at 16 min\n");
        let at = t0 + Duration::from_secs(16 * 60);
        assert_eq!(text(&recorder, at), "at 10 min\nat 16 min\n");
        // Nothing new is recorded, and time passes: the snapshot itself applies the window.
        let later = t0 + Duration::from_secs(26 * 60);
        let (bytes, stats) = recorder.snapshot(later);
        assert_eq!(String::from_utf8(bytes).expect("utf-8"), "at 16 min\n");
        assert_eq!(stats.evicted_by_age, 2);
        assert_eq!(stats.span, Some(Duration::from_secs(10 * 60)));
    }

    /// Off empties it, and a line handed over after that — one that was past the filter already on
    /// another thread — is dropped, not kept; on again, it records.
    #[test]
    fn off_empties_it_and_keeps_nothing_after() {
        let recorder = FlightRecorder::new(WINDOW, MAX_BYTES);
        assert!(recorder.is_on());
        let t0 = Instant::now();
        recorder.record(t0, b"a\n");
        recorder.record(t0, b"b\n");
        assert_eq!(recorder.set_on(false), 2);
        assert!(!recorder.is_on());
        recorder.record(t0, b"late\n");
        let (bytes, stats) = recorder.snapshot(t0);
        assert!(bytes.is_empty());
        assert_eq!((stats.lines, stats.bytes, stats.span), (0, 0, None));
        assert_eq!(recorder.set_on(true), 0);
        recorder.record(t0, b"c\n");
        assert_eq!(text(&recorder, t0), "c\n");
    }

    /// Off from one thread while others keep handing lines over: from the moment `set_on(false)`
    /// returns, the ring is empty and stays so.
    #[test]
    fn off_holds_against_threads_still_writing() {
        let recorder = Arc::new(FlightRecorder::new(WINDOW, MAX_BYTES));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writers: Vec<_> = (0..4)
            .map(|i| {
                let recorder = Arc::clone(&recorder);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        recorder.record(Instant::now(), format!("writer {i}\n").as_bytes());
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(20));
        recorder.set_on(false);
        for _ in 0..50 {
            assert_eq!(recorder.snapshot(Instant::now()).1.lines, 0);
            std::thread::sleep(Duration::from_millis(1));
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for writer in writers {
            writer.join().expect("writer thread");
        }
        assert_eq!(recorder.snapshot(Instant::now()).1.lines, 0);
    }

    #[test]
    fn the_filter_is_the_file_at_debug_or_nothing() {
        assert_eq!(
            filter(true).to_string(),
            LogLevel::Debug.filter().to_string()
        );
        assert_eq!(
            filter(false).max_level_hint(),
            Some(tracing_subscriber::filter::LevelFilter::OFF)
        );
    }

    /// The file, played by memory.
    #[derive(Clone, Default)]
    struct Mem(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Mem {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            afklink_core::lock(&self.0).extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Mem {
        fn text(&self) -> String {
            String::from_utf8_lossy(&afklink_core::lock(&self.0)).into_owned()
        }
    }

    /// The app's layers (`crate::log_layers`) with the file at `file_level`, the recorder on; the
    /// file's text, the recorder, and the file filter's handle.
    fn stack(
        file_level: LogLevel,
    ) -> (
        impl tracing::Subscriber + Send + Sync,
        Mem,
        Arc<FlightRecorder>,
        tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>,
    ) {
        use tracing_subscriber::layer::SubscriberExt;

        let file = Mem::default();
        let recorder = Arc::new(FlightRecorder::new(WINDOW, MAX_BYTES));
        let (file_filter, handle) = tracing_subscriber::reload::Layer::new(file_level.filter());
        let (recorder_filter, _) = tracing_subscriber::reload::Layer::new(filter(true));
        let written = file.clone();
        let subscriber = tracing_subscriber::registry().with(crate::log_layers(
            io::sink,
            move || written.clone(),
            file_filter,
            &recorder,
            recorder_filter,
        ));
        (subscriber, file, recorder, handle)
    }

    /// The recorder takes our `debug` whatever the file's level, never `trace`, never third-party
    /// chatter; the file gets exactly what its level says — and a line in both is the same line.
    #[test]
    fn the_recorder_keeps_debug_whatever_the_file_level() {
        let (subscriber, file, recorder, file_filter) = stack(LogLevel::Info);
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "afklink_core::agent", "ours at debug under info");
            tracing::trace!(target: "afklink_core::agent", "ours at trace under info");
            tracing::debug!(target: "str0m::rtp", "theirs at debug under info");
            tracing::warn!(target: "str0m::rtp", "theirs at warn");
            tracing::info!(target: "afklink_core::agent", n = 3, "ours at info");
            file_filter
                .reload(LogLevel::Error.filter())
                .expect("file filter reloads");
            tracing::debug!(target: "afklink_transport::webrtc", "ours at debug under error");
            tracing::info!(target: "afklink_app_lib", "ours at info under error");
            file_filter
                .reload(LogLevel::Trace.filter())
                .expect("file filter reloads");
            tracing::trace!(target: "afklink_core::agent", "ours at trace under trace");
            tracing::debug!(target: "str0m::ice", "theirs at debug under trace");
        });
        let file = file.text();
        let kept = String::from_utf8(recorder.snapshot(Instant::now()).0).expect("utf-8");

        for (line, in_file, in_recorder) in [
            ("ours at debug under info", false, true),
            ("ours at trace under info", false, false),
            ("theirs at debug under info", false, false),
            ("theirs at warn", true, true),
            ("ours at info", true, true),
            ("ours at debug under error", false, true),
            ("ours at info under error", false, true),
            ("ours at trace under trace", true, false),
            ("theirs at debug under trace", true, false),
        ] {
            assert_eq!(file.contains(line), in_file, "file, {line:?}:\n{file}");
            assert_eq!(
                kept.contains(line),
                in_recorder,
                "recorder, {line:?}:\n{kept}"
            );
        }

        // Formatted by the file's layer: the same line, but for the moment each was stamped.
        let after_time = |text: &str, needle: &str| {
            text.lines()
                .find(|l| l.contains(needle))
                .and_then(|l| l.split_once(' ').map(|(_, rest)| rest.to_string()))
                .expect("the line is there")
        };
        assert_eq!(
            after_time(&kept, "ours at info n=3"),
            after_time(&file, "ours at info n=3")
        );
        assert_eq!(
            after_time(&kept, "ours at info n=3"),
            " INFO afklink_core::agent: ours at info n=3"
        );
        assert!(kept.starts_with("20"), "a timestamp first: {kept}");
    }

    /// What recording costs per line with the file at `info`: every `debug` line of ours formatted
    /// once more, into memory. A measurement, not a check:
    /// `cargo test -p afklink-app --lib recording_costs -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement; run by hand with --ignored --nocapture"]
    fn recording_costs_microseconds_a_line() {
        const LINES: u32 = 200_000;
        let measure = |recording: bool| {
            use tracing_subscriber::layer::SubscriberExt;
            let recorder = Arc::new(FlightRecorder::new(WINDOW, MAX_BYTES));
            let (file_filter, _) = tracing_subscriber::reload::Layer::new(LogLevel::Info.filter());
            let (recorder_filter, _) = tracing_subscriber::reload::Layer::new(filter(recording));
            let subscriber = tracing_subscriber::registry().with(crate::log_layers(
                io::sink,
                io::sink,
                file_filter,
                &recorder,
                recorder_filter,
            ));
            tracing::subscriber::with_default(subscriber, || {
                let started = Instant::now();
                for i in 0..LINES {
                    tracing::debug!(
                        target: "afklink_core::agent",
                        session = "3fa85f64",
                        i,
                        rtt_ms = 42.5,
                        "a decision with its inputs, as long as a typical debug line of ours"
                    );
                }
                started.elapsed()
            })
        };
        let off = measure(false);
        let on = measure(true);
        let per_line_ns = on.saturating_sub(off).as_nanos() / u128::from(LINES);
        println!(
            "flight recorder: {per_line_ns} ns a line on top of a file at info \
             ({LINES} lines: {on:?} recording, {off:?} not)"
        );
    }
}
