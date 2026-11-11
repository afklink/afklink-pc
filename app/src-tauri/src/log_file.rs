//! The file log's machinery: what a line in the files looks like, the queue it waits in, the one
//! thread that writes every file, and every line that queue or a file loses — counted per file,
//! where it is lost, and said in that file. Which file a line belongs to — the system log or a
//! session's own — is `log_route`'s decision; the names on disk and how long each file is kept are
//! `log_retention`'s.
//!
//! # One queue, one writer thread, every file
//!
//! A line is formatted on the thread that logs it ([`file_layer`]), given its file there, and handed
//! to a queue ([`Queue`]) that one thread, `afklink-log-writer`, empties into the files. The queue is
//! lossy by design: a line that finds [`QUEUE_LINES`] lines already waiting is dropped rather than
//! stalling the capture, encode and network threads that emit it, because a disk that stalls must
//! not stall the picture. Those threads never touch a disk: opening a session's file, rotating the
//! system log, closing a file, removing old ones — all of it happens on the writer thread.
//!
//! Commands ([`Msg`]: open a session's file, close it, sweep old files, flush) travel in the same
//! queue as the lines, so they keep their place among them — a session's file is opened before its
//! first line and closed after its last — but are never refused: only lines count against
//! [`QUEUE_LINES`].
//!
//! # Losses
//!
//! A line is lost when the queue refuses it (full, or already closed on the way out) or when its
//! write fails (a full disk, a file another program has locked). Both are counted per file
//! ([`LostLines`]); the router's housekeeping turns new losses into a `WARN` line in that same file
//! once a second ([`report_line`]), so the line lands within about a second of the hole it describes,
//! and a session file's last line states its totals. A report goes through the same queue and can
//! be lost too: then it is counted, and the next report includes it.
//!
//! Still lost without a word, because there is nowhere left to write them: lines queued when the
//! process dies without unwinding (a crash in native code — `flush_log` covers exits and main-thread
//! panics), and lines logged after the files were closed on exit.
//!
//! # Lines the machinery writes itself
//!
//! A session file's first line (its header) and last (its footer), the system log's record of each
//! session file opened and closed, rotations, removals and loss reports are written here, not
//! through `tracing` ([`notice`]): they are in the files whatever the level (short of `off`, which
//! writes nothing), and they cannot land in the wrong file. They look like any other line — the same
//! timestamp, level and target columns — so a reader or a parser cannot tell them apart.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, TryLockError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::Level;

use crate::log_retention::{
    self, system_log_name, LocalTime, RetentionRules, SESSIONS_DIR, SYSTEM_LOG,
};

/// Lines the queue in front of the writer thread holds (tracing-appender's default, which this queue
/// replaced), named because it is the whole margin. At `debug` a session writes tens of lines a
/// second, so the disk has to stall for minutes before a line finds the queue full.
pub(crate) const QUEUE_LINES: usize = 128_000;

/// How often the router's housekeeping looks at the counters (and at the sessions' tails): the
/// most a loss report trails the hole it describes.
pub(crate) const CHECK_EVERY: Duration = Duration::from_secs(1);

/// The target the machinery's own lines carry.
pub(crate) const TARGET: &str = "afklink_app_lib::log_file";

/// A line of the file: no colour, and the target kept (`afklink_transport` against `afklink_core` is
/// the first fork in reading a failed session). One function, so the tests format lines exactly as
/// the file does.
///
/// `log_internal_errors`: an event with a field that fails to format (a `Display` returning an
/// error) is otherwise dropped without a trace; with it, the file gets a line naming the event and
/// its fields instead.
pub(crate) fn file_layer<S, W>(writer: W) -> impl tracing_subscriber::Layer<S> + Send + Sync
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'w> tracing_subscriber::fmt::MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .log_internal_errors(true)
        .with_writer(writer)
}

/// A line the machinery writes itself, in the file layer's shape: the same UTC timestamp, the level
/// padded to five, the target, the message (with its `key=value` fields already in it).
pub(crate) fn notice(level: Level, target: &str, message: &str) -> Vec<u8> {
    use std::fmt::Write as _;
    use tracing_subscriber::fmt::time::FormatTime;

    let mut line = String::with_capacity(48 + target.len() + message.len());
    let mut stamp = tracing_subscriber::fmt::format::Writer::new(&mut line);
    if tracing_subscriber::fmt::time::SystemTime
        .format_time(&mut stamp)
        .is_err()
    {
        // The file layer prints `<unknown time>` then; a line without its time is still the line.
        line.push_str("<unknown time>");
    }
    // Writing into a `String` cannot fail.
    let _ = writeln!(line, " {:>5} {target}: {message}", level.as_str());
    line.into_bytes()
}

/// Lines lost, by where.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LostCounts {
    /// Refused by the queue: full, or — on the way out — already closed.
    pub(crate) queue_full: usize,
    /// Taken off the queue by the writer thread, but the write to the file failed.
    pub(crate) write_failed: usize,
}

impl LostCounts {
    pub(crate) fn total(self) -> usize {
        self.queue_full.saturating_add(self.write_failed)
    }

    fn since(self, earlier: Self) -> Self {
        Self {
            queue_full: self.queue_full.saturating_sub(earlier.queue_full),
            write_failed: self.write_failed.saturating_sub(earlier.write_failed),
        }
    }
}

/// One file's losses: where they are counted, and how many of them are on record already.
#[derive(Debug, Clone, Default)]
pub(crate) struct LostLines {
    queue_full: Arc<AtomicUsize>,
    write_failed: Arc<WriteFailures>,
    /// What the reports so far covered. Taken with `try_lock`: the housekeeping and the exit path
    /// both report, and the exit path runs inside the panic hook, where waiting on a lock is how a
    /// crash becomes a hang.
    reported: Arc<Mutex<LostCounts>>,
}

impl LostLines {
    pub(crate) fn counts(&self) -> LostCounts {
        LostCounts {
            queue_full: self.queue_full.load(Ordering::Acquire),
            write_failed: self.write_failed.count(),
        }
    }

    /// A line the queue refused.
    fn refused(&self) {
        self.queue_full.fetch_add(1, Ordering::AcqRel);
    }
}

/// Writes to a file that failed, and the last one's error.
///
/// The error is stored before the count moves (`Release`), and the count is read with `Acquire`:
/// whoever sees a count also sees the error of that failure or a later one — never a count with
/// no error on record, which a report would print as `last_write_error="-"`.
#[derive(Debug, Default)]
struct WriteFailures {
    count: AtomicUsize,
    last: Mutex<Option<String>>,
}

impl WriteFailures {
    /// A failed write: its error on record first, then counted.
    fn note(&self, error: &io::Error) {
        *afklink_core::lock(&self.last) = Some(error.to_string());
        self.count.fetch_add(1, Ordering::Release);
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}

/// The lines `lost` lost since the last report, as a `WARN` line for the file it counts (`file`, as
/// the line names it); `None` when nothing new was lost, or another report is being made at this
/// moment.
///
/// The caller sends the line to that same file, through the same queue, so it can be lost too:
/// then it is counted, and the next report includes it.
pub(crate) fn report_line(lost: &LostLines, file: &str) -> Option<(LostCounts, Vec<u8>)> {
    let now = lost.counts();
    let new = {
        let mut reported = match lost.reported.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return None,
        };
        let new = now.since(*reported);
        if new.total() == 0 {
            return None;
        }
        *reported = now;
        new
    };
    let last_error = afklink_core::lock(&lost.write_failed.last).clone();
    let message = format!(
        "log file: lines are missing from the file in the second or so before this one: the queue \
         to the writer thread was full (the disk fell behind) or a write to the file failed \
         lost={} queue_full={} write_failed={} lost_total={} last_write_error={:?} file={file:?}",
        new.total(),
        new.queue_full,
        new.write_failed,
        now.total(),
        last_error.as_deref().unwrap_or("-"),
    );
    Some((new, notice(Level::WARN, TARGET, &message)))
}

/// Which file a queued line goes to: [`SYSTEM`], or a session's, by the number the router gave it.
pub(crate) type Dest = u64;

/// The system log.
pub(crate) const SYSTEM: Dest = 0;

/// What the queue carries to the writer thread.
pub(crate) enum Msg {
    /// A formatted line for `dest`. The only message the queue may refuse.
    Line { dest: Dest, bytes: Vec<u8> },
    /// Open a session's file; every line for its `dest` goes there until it is closed.
    Open(OpenSession),
    /// Write a session file's last line and close it; its old files may go.
    Close(CloseSession),
    /// Apply the retention rules (`log_retention::sweep`).
    Sweep,
    /// Answer once everything queued before is written.
    Flush(mpsc::SyncSender<()>),
    /// Answer once everything queued before is written, then stop.
    Shutdown(mpsc::SyncSender<()>),
}

/// A session's file to open.
pub(crate) struct OpenSession {
    pub(crate) dest: Dest,
    /// The file's name in [`SESSIONS_DIR`].
    pub(crate) name: String,
    /// Its first line.
    pub(crate) header: Vec<u8>,
    /// `session=… telegram_user_id=…`, for the system log's record of it.
    pub(crate) about: String,
    pub(crate) lost: LostLines,
}

/// A session's file to close.
pub(crate) struct CloseSession {
    pub(crate) dest: Dest,
    /// What its last line says; `None` when the log is `off`, which writes nothing more.
    pub(crate) footer: Option<Footer>,
}

/// A session file's last line, but for the counts the writer thread adds.
pub(crate) struct Footer {
    pub(crate) session_id: String,
    /// Why it closes now: `finished`, `tail_timeout`, `not_started`, or the process's end.
    pub(crate) why: &'static str,
    pub(crate) end_reason: Option<String>,
    pub(crate) open_for: Duration,
}

/// The sending end of the queue: lossy for lines, never for commands.
pub(crate) struct Queue {
    tx: mpsc::Sender<Msg>,
    /// Lines in the queue now.
    waiting: Arc<AtomicUsize>,
    limit: usize,
}

impl Queue {
    /// Queue `bytes` for `dest`, or count it lost in `lost` — `dest`'s — when [`QUEUE_LINES`] are
    /// waiting already or the writer thread is gone. Never blocks.
    pub(crate) fn line(&self, dest: Dest, bytes: &[u8], lost: &LostLines) {
        if self.waiting.fetch_add(1, Ordering::AcqRel) >= self.limit {
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            lost.refused();
            return;
        }
        let msg = Msg::Line {
            dest,
            bytes: bytes.to_vec(),
        };
        if self.tx.send(msg).is_err() {
            self.waiting.fetch_sub(1, Ordering::AcqRel);
            lost.refused();
        }
    }

    /// Queue a command. `false` only when the writer thread is gone.
    pub(crate) fn command(&self, msg: Msg) -> bool {
        self.tx.send(msg).is_ok()
    }

    /// Count `lines` more as waiting (or, negative, fewer), as a disk that fell behind leaves them:
    /// what fills the queue in a test.
    #[cfg(test)]
    pub(crate) fn pretend_waiting(&self, lines: isize) {
        if lines >= 0 {
            self.waiting
                .fetch_add(lines.unsigned_abs(), Ordering::AcqRel);
        } else {
            self.waiting
                .fetch_sub(lines.unsigned_abs(), Ordering::AcqRel);
        }
    }
}

/// Where the writer thread writes, and how it keeps the files.
pub(crate) struct WriterSettings {
    /// The logs folder.
    pub(crate) dir: PathBuf,
    pub(crate) system_max_bytes: u64,
    pub(crate) system_rotations: u32,
    pub(crate) retention: RetentionRules,
    pub(crate) queue_lines: usize,
}

/// Open the system log in `settings.dir` and start the writer thread on it.
///
/// The folder and the system log are opened here, on the caller's thread, so one that cannot be had
/// is an error the caller reports; every disk operation after that is the writer thread's.
/// `system_lost` counts the system log's losses.
pub(crate) fn start_writer(settings: WriterSettings, system_lost: LostLines) -> io::Result<Queue> {
    let system = SystemFile::open(
        &settings.dir,
        settings.system_max_bytes,
        settings.system_rotations,
        system_lost,
    )?;
    let (tx, rx) = mpsc::channel();
    let waiting = Arc::new(AtomicUsize::new(0));
    let writer = Writer {
        dir: settings.dir,
        retention: settings.retention,
        system,
        sessions: HashMap::new(),
        waiting: Arc::clone(&waiting),
    };
    std::thread::Builder::new()
        .name("afklink-log-writer".to_string())
        .spawn(move || writer.run(&rx))?;
    Ok(Queue {
        tx,
        waiting,
        limit: settings.queue_lines,
    })
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// The system log, rotated by size (`log_retention`): at `max` bytes `system.log` becomes
/// `system.1.log` and so on, the oldest going.
struct SystemFile {
    dir: PathBuf,
    /// `None` after a rotation that could not reopen the file; the next write tries again.
    file: Option<File>,
    size: u64,
    max: u64,
    rotations: u32,
    /// After a failed rotation, the size at which the next is tried: not on every line.
    retry_at: u64,
    lost: LostLines,
}

impl SystemFile {
    fn open(dir: &Path, max: u64, rotations: u32, lost: LostLines) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let file = open_append(&dir.join(SYSTEM_LOG))?;
        let size = file.metadata().map_or(0, |m| m.len());
        Ok(Self {
            dir: dir.to_path_buf(),
            file: Some(file),
            size,
            max,
            rotations: rotations.max(1),
            retry_at: 0,
            lost,
        })
    }

    /// Write one line, rotating first when it would take the file past `max`. A failure is counted
    /// as a lost line of the system log.
    fn write(&mut self, bytes: &[u8]) {
        let len = bytes.len() as u64;
        if self.size > 0 && self.size.saturating_add(len) > self.max && self.size >= self.retry_at {
            self.rotate();
        }
        self.write_raw(bytes);
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        if self.file.is_none() {
            match open_append(&self.dir.join(SYSTEM_LOG)) {
                Ok(file) => {
                    self.size = file.metadata().map_or(0, |m| m.len());
                    self.file = Some(file);
                }
                Err(e) => {
                    self.lost.write_failed.note(&e);
                    return;
                }
            }
        }
        if let Some(file) = self.file.as_mut() {
            match file.write_all(bytes) {
                Ok(()) => self.size = self.size.saturating_add(bytes.len() as u64),
                Err(e) => self.lost.write_failed.note(&e),
            }
        }
    }

    /// `system.log` → `system.1.log` → … → `system.<rotations>.log` → gone, and a fresh `system.log`
    /// whose first line says so. A rotation that fails (the file held by another program without
    /// delete sharing) leaves the file growing, says so in it, and is tried again after an eighth
    /// of `max` more.
    fn rotate(&mut self) {
        let size = self.size;
        // Closed first: the renames move the file this handle has open.
        self.file = None;
        match shift_rotations(&self.dir, self.rotations) {
            Ok(()) => {
                self.size = 0;
                self.retry_at = 0;
                let note = format!(
                    "log file: {SYSTEM_LOG} reached {size} bytes (the most is {}) and was rotated: \
                     the lines before this one are in {}, and {} is the oldest kept",
                    self.max,
                    system_log_name(1),
                    system_log_name(self.rotations)
                );
                self.write_raw(&notice(Level::INFO, TARGET, &note));
            }
            Err(e) => {
                let step = (self.max / 8).max(1);
                self.retry_at = size.saturating_add(step);
                let note = format!(
                    "log file: {SYSTEM_LOG} not rotated at {size} bytes ({e}); it keeps growing, and \
                     the rotation is tried again after {step} more bytes"
                );
                self.write_raw(&notice(Level::WARN, TARGET, &note));
            }
        }
    }
}

/// Move every rotation one up, the oldest out, and `system.log` to `system.1.log`.
fn shift_rotations(dir: &Path, rotations: u32) -> io::Result<()> {
    match std::fs::remove_file(dir.join(system_log_name(rotations))) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    for n in (1..rotations).rev() {
        match std::fs::rename(
            dir.join(system_log_name(n)),
            dir.join(system_log_name(n + 1)),
        ) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    std::fs::rename(dir.join(SYSTEM_LOG), dir.join(system_log_name(1)))
}

/// A session's file as the writer thread holds it.
struct SessionFile {
    name: String,
    /// `None` when it could not be opened: its lines go to the system log instead.
    file: Option<File>,
    /// Lines written to it (header and footer aside).
    lines: u64,
    lost: LostLines,
}

/// The writer thread: every file, and the queue's other end.
struct Writer {
    dir: PathBuf,
    retention: RetentionRules,
    system: SystemFile,
    sessions: HashMap<Dest, SessionFile>,
    waiting: Arc<AtomicUsize>,
}

impl Writer {
    fn run(mut self, rx: &mpsc::Receiver<Msg>) {
        let done = loop {
            let Ok(msg) = rx.recv() else {
                // Every sender gone without a shutdown (a test's router dropped).
                break None;
            };
            match msg {
                Msg::Line { dest, bytes } => {
                    self.waiting.fetch_sub(1, Ordering::AcqRel);
                    self.line(dest, &bytes);
                }
                Msg::Open(open) => self.open(open),
                Msg::Close(close) => {
                    self.close(close);
                    self.sweep("a session file closed");
                }
                Msg::Sweep => self.sweep("scheduled"),
                Msg::Flush(done) => {
                    // A waiter that gave up (its wait timed out) is gone; nobody is left to answer.
                    let _ = done.send(());
                }
                Msg::Shutdown(done) => break Some(done),
            }
        };
        // Every file closed before the answer: whoever waits may move or remove them. A session
        // file the router did not close (it closes them all first) closes here without a last line.
        drop(self);
        if let Some(done) = done {
            // As above: a waiter that gave up is gone.
            let _ = done.send(());
        }
    }

    fn line(&mut self, dest: Dest, bytes: &[u8]) {
        if dest != SYSTEM {
            if let Some(session) = self.sessions.get_mut(&dest) {
                if let Some(file) = session.file.as_mut() {
                    match file.write_all(bytes) {
                        Ok(()) => session.lines += 1,
                        Err(e) => session.lost.write_failed.note(&e),
                    }
                    return;
                }
                // Its file could not be opened: the system log has its lines, as it said then.
                session.lines += 1;
            }
            // A line for a file that is not open cannot come (the queue keeps the router's order);
            // were it to, the system log keeps it rather than nowhere.
        }
        self.system.write(bytes);
    }

    fn open(&mut self, open: OpenSession) {
        let dir = self.dir.join(SESSIONS_DIR);
        let opened =
            std::fs::create_dir_all(&dir).and_then(|()| open_append(&dir.join(&open.name)));
        let file = match opened {
            Ok(mut file) => {
                if let Err(e) = file.write_all(&open.header) {
                    open.lost.write_failed.note(&e);
                }
                let note = format!(
                    "session log opened: {SESSIONS_DIR}\\{} {}",
                    open.name, open.about
                );
                self.system.write(&notice(Level::INFO, TARGET, &note));
                Some(file)
            }
            Err(e) => {
                // The session's first line here instead, and why its lines follow it.
                self.system.write(&open.header);
                let note = format!(
                    "session log: {SESSIONS_DIR}\\{} not opened ({e}); the session's lines follow in \
                     the system log {}",
                    open.name, open.about
                );
                self.system.write(&notice(Level::WARN, TARGET, &note));
                None
            }
        };
        self.sessions.insert(
            open.dest,
            SessionFile {
                name: open.name,
                file,
                lines: 0,
                lost: open.lost,
            },
        );
    }

    fn close(&mut self, close: CloseSession) {
        let Some(mut session) = self.sessions.remove(&close.dest) else {
            let note = format!(
                "log file: asked to close session file #{} that is not open; nothing to close",
                close.dest
            );
            self.system.write(&notice(Level::WARN, TARGET, &note));
            return;
        };
        let Some(footer) = close.footer else {
            // The log is off: the file closes without another line.
            return;
        };
        // Final: nothing is sent to this file after its close.
        let lost = session.lost.counts();
        let level = if lost.total() > 0 {
            Level::WARN
        } else {
            Level::INFO
        };
        let fields = format!(
            "session={} why={} end_reason={} lines={} lost={} queue_full={} write_failed={} \
             open_s={}",
            footer.session_id,
            footer.why,
            footer.end_reason.as_deref().unwrap_or("-"),
            session.lines,
            lost.total(),
            lost.queue_full,
            lost.write_failed,
            footer.open_for.as_secs(),
        );
        let last = notice(level, TARGET, &format!("session log closed {fields}"));
        let mut last_written = true;
        match session.file.as_mut() {
            Some(file) => {
                if let Err(e) = file.write_all(&last) {
                    session.lost.write_failed.note(&e);
                    last_written = false;
                }
            }
            None => self.system.write(&last),
        }
        let note = format!(
            "session log closed: {SESSIONS_DIR}\\{} {fields}{}",
            session.name,
            if last_written {
                ""
            } else {
                " (and its last line, which says so, could not be written to it)"
            }
        );
        self.system.write(&notice(level, TARGET, &note));
    }

    /// The retention rules (`log_retention::sweep`), each removal and failure said in the system
    /// log; nothing said when nothing was due.
    fn sweep(&mut self, why: &str) {
        let open: Vec<String> = self
            .sessions
            .values()
            .filter(|s| s.file.is_some())
            .map(|s| s.name.clone())
            .collect();
        let today = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() / 86_400);
        let swept = log_retention::sweep(
            &self.dir,
            LocalTime::now(),
            i64::try_from(today).unwrap_or(i64::MAX),
            &open,
            &self.retention,
        );
        for removed in &swept.removed {
            let note = format!(
                "log retention: removed {} bytes={} rule={} ({why})",
                removed.name, removed.bytes, removed.why
            );
            self.system.write(&notice(Level::INFO, TARGET, &note));
        }
        for (due, error) in &swept.failed {
            let note = format!(
                "log retention: {} not removed ({error}); it was due to go bytes={} rule={} ({why})",
                due.name, due.bytes, due.why
            );
            self.system.write(&notice(Level::WARN, TARGET, &note));
        }
        for (folder, error) in &swept.unlisted {
            let note = format!(
                "log retention: {folder} not listed ({error}); nothing in it was removed ({why})"
            );
            self.system.write(&notice(Level::WARN, TARGET, &note));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Instant;

    use afklink_core::logging::LogLevel;
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    /// The file layer's output, played by memory.
    struct TestFile {
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for TestFile {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            afklink_core::lock(&self.out).extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn text(out: &Mutex<Vec<u8>>) -> String {
        String::from_utf8_lossy(&afklink_core::lock(out)).into_owned()
    }

    /// A folder of its own under the temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(what: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("afklink-log-{what}-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn settings(dir: &Path, queue_lines: usize, system_max_bytes: u64) -> WriterSettings {
        WriterSettings {
            dir: dir.to_path_buf(),
            system_max_bytes,
            system_rotations: 3,
            retention: RetentionRules::DEFAULT,
            queue_lines,
        }
    }

    /// Wait until everything queued so far is written.
    fn flush(queue: &Queue) {
        let (done, wait) = mpsc::sync_channel(1);
        assert!(queue.command(Msg::Flush(done)));
        wait.recv_timeout(Duration::from_secs(30))
            .expect("the writer thread answers");
    }

    /// Stop the writer thread, its files closed, so the test's folder can go.
    fn stop(queue: Queue) {
        let (done, wait) = mpsc::sync_channel(1);
        assert!(queue.command(Msg::Shutdown(done)));
        wait.recv_timeout(Duration::from_secs(30))
            .expect("the writer thread stops");
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// A line of the machinery's own looks like a line of the file layer's: the same timestamp
    /// shape, the level padded to five, the target.
    #[test]
    fn a_notice_is_shaped_like_a_file_line() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let file = Arc::clone(&out);
        let subscriber = tracing_subscriber::registry()
            .with(LogLevel::Debug.filter())
            .with(file_layer(move || TestFile {
                out: Arc::clone(&file),
            }));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "afklink_app_lib::log_file", "same shape x=1");
        });
        let layer = text(&out);
        let ours = String::from_utf8(notice(Level::WARN, TARGET, "same shape x=1")).expect("utf-8");
        let shape = |line: &str| -> (usize, String) {
            let (stamp, rest) = line.split_once(' ').expect("a timestamp first");
            (stamp.len(), rest.to_string())
        };
        assert_eq!(shape(&layer), shape(&ours), "{layer:?} / {ours:?}");
        assert!(ours.ends_with(" WARN afklink_app_lib::log_file: same shape x=1\n"));
        let info = String::from_utf8(notice(Level::INFO, TARGET, "m")).expect("utf-8");
        assert!(
            info.contains("Z  INFO afklink_app_lib::log_file: m\n"),
            "{info}"
        );
    }

    /// Both ways a line is lost — the queue full, the write failing — are counted for their file and
    /// said once, in that file, where the hole is; the lines around it are all there.
    #[test]
    fn lost_lines_are_counted_and_said_in_their_file() {
        let dir = TempDir::new("losses");
        let lost = LostLines::default();
        let queue = start_writer(settings(&dir.0, 2, u64::MAX), lost.clone()).expect("starts");
        queue.line(SYSTEM, b"line one\n", &lost);
        flush(&queue);
        // A queue holding its two lines, as one behind a stalled disk does: the next is refused.
        queue.waiting.fetch_add(2, Ordering::AcqRel);
        queue.line(SYSTEM, b"line lost to a full queue\n", &lost);
        queue.waiting.fetch_sub(2, Ordering::AcqRel);
        assert_eq!(
            lost.counts(),
            LostCounts {
                queue_full: 1,
                write_failed: 0
            }
        );
        // A write that fails: another handle holds the whole file locked, as a program that locks
        // what it reads would.
        let locker = File::open(dir.0.join(SYSTEM_LOG)).expect("a second handle");
        locker.lock().expect("locked");
        queue.line(SYSTEM, b"line lost to a failed write\n", &lost);
        flush(&queue);
        locker.unlock().expect("unlocked");
        assert_eq!(
            lost.counts(),
            LostCounts {
                queue_full: 1,
                write_failed: 1
            }
        );

        let (counts, line) = report_line(&lost, SYSTEM_LOG).expect("new losses");
        assert_eq!(counts, lost.counts());
        assert!(report_line(&lost, SYSTEM_LOG).is_none(), "said once");
        queue.line(SYSTEM, &line, &lost);
        queue.line(SYSTEM, b"line two\n", &lost);
        stop(queue);
        assert!(
            report_line(&lost, SYSTEM_LOG).is_none(),
            "nothing lost since"
        );

        let text = read(&dir.0.join(SYSTEM_LOG));
        let lines: Vec<&str> = text.lines().collect();
        let at = |needle: &str| {
            lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("no {needle:?} in:\n{text}"))
        };
        assert!(!text.contains("line lost"), "{text}");
        let warned = at("log file: lines are missing");
        assert_eq!(
            (at("line one"), warned, at("line two")),
            (0, 1, 2),
            "the report sits where the lines went missing:\n{text}"
        );
        let warn = lines[warned];
        assert!(
            warn.contains(" WARN afklink_app_lib::log_file: log file: lines are missing"),
            "{warn}"
        );
        for field in [
            "lost=2",
            "queue_full=1",
            "write_failed=1",
            "lost_total=2",
            "(os error 33)",
            "file=\"system.log\"",
        ] {
            assert!(warn.contains(field), "{field} is missing from: {warn}");
        }
    }

    /// Whoever sees a failed write counted also sees its error on record — a report never says
    /// `last_write_error="-"` beside a count. A thread fails write after write, each with its
    /// number; this thread reads the count and then the error as a report does, and the error is
    /// always that write's or a later one's. Holds on every interleaving; with the count moved
    /// first it fails 10 runs out of 10.
    #[test]
    fn a_counted_failure_is_seen_with_its_error() {
        const WRITES: usize = 20_000;
        let failures = Arc::new(WriteFailures::default());
        let writer = Arc::clone(&failures);
        let thread = std::thread::spawn(move || {
            for n in 1..=WRITES {
                writer.note(&io::Error::other(format!("fail {n}")));
            }
        });
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let count = failures.count();
            let last = afklink_core::lock(&failures.last).clone();
            if count > 0 {
                let numbered = last
                    .as_deref()
                    .and_then(|l| l.strip_prefix("fail "))
                    .and_then(|n| n.parse::<usize>().ok());
                match numbered {
                    Some(n) => assert!(n >= count, "count {count} seen with write {n}'s error"),
                    None => unreachable!("count {count} seen with no error on record: {last:?}"),
                }
            }
            if count == WRITES {
                break;
            }
            assert!(
                Instant::now() < until,
                "the writing thread stopped at {count}"
            );
        }
        thread.join().expect("the writing thread");
    }

    /// Past its size the system log rotates — `system.log` → `system.1.log` → … — keeping three
    /// rotations, and each new file says where the lines before it are. A long line goes whole
    /// into the file it starts.
    #[test]
    fn the_system_log_rotates_by_size_and_keeps_three() {
        let dir = TempDir::new("rotation");
        let lost = LostLines::default();
        let queue = start_writer(settings(&dir.0, QUEUE_LINES, 400), lost.clone()).expect("starts");
        for n in 0..40 {
            queue.line(
                SYSTEM,
                format!("line {n:02} {}\n", "x".repeat(40)).as_bytes(),
                &lost,
            );
        }
        stop(queue);
        let names: Vec<String> = {
            let mut names: Vec<String> = log_retention::list_files(&dir.0)
                .expect("list")
                .into_iter()
                .map(|(n, _)| n)
                .collect();
            names.sort();
            names
        };
        assert_eq!(
            names,
            ["system.1.log", "system.2.log", "system.3.log", "system.log"]
        );
        let current = read(&dir.0.join("system.log"));
        assert!(
            current.starts_with(char::is_numeric)
                && current
                    .lines()
                    .next()
                    .is_some_and(|l| l.contains("log file: system.log reached")
                        && l.contains("the lines before this one are in system.1.log")),
            "{current}"
        );
        assert!(
            current.contains("line 39 "),
            "the newest line is in system.log"
        );
        // Every file stays near its bound: a rotation happens before the line that would cross it.
        for name in &names {
            let size = std::fs::metadata(dir.0.join(name)).expect("meta").len();
            assert!(size <= 400 + 200, "{name}: {size}");
        }
        // The oldest lines went with the oldest rotation; the rest are in order.
        let all: String = ["system.3.log", "system.2.log", "system.1.log", "system.log"]
            .iter()
            .map(|n| read(&dir.0.join(n)))
            .collect();
        let numbers: Vec<u32> = all
            .lines()
            .filter_map(|l| l.strip_prefix("line "))
            .filter_map(|l| l.get(..2)?.parse().ok())
            .collect();
        assert!(numbers.windows(2).all(|w| w[1] == w[0] + 1), "{numbers:?}");
        assert_eq!(numbers.last(), Some(&39));
        assert_eq!(lost.counts().total(), 0);
    }

    /// A session file that cannot be opened: its header and lines go to the system log, after a
    /// `WARN` that says so, and its last line there too.
    #[test]
    fn a_session_file_that_cannot_be_opened_falls_back_to_the_system_log() {
        let dir = TempDir::new("fallback");
        // `sessions` is a file, so no file can be opened inside it.
        std::fs::write(dir.0.join(SESSIONS_DIR), "not a folder").expect("write");
        let system_lost = LostLines::default();
        let queue = start_writer(settings(&dir.0, QUEUE_LINES, u64::MAX), system_lost.clone())
            .expect("starts");
        let lost = LostLines::default();
        assert!(queue.command(Msg::Open(OpenSession {
            dest: 7,
            name: "2026-09-29_12-10-05_d1020ebf.log".to_string(),
            header: b"header line\n".to_vec(),
            about: "session=d1020ebf".to_string(),
            lost: lost.clone(),
        })));
        queue.line(7, b"a line of the session\n", &lost);
        assert!(queue.command(Msg::Close(CloseSession {
            dest: 7,
            footer: Some(Footer {
                session_id: "d1020ebf".to_string(),
                why: "finished",
                end_reason: Some("peer_closed".to_string()),
                open_for: Duration::from_secs(5),
            }),
        })));
        stop(queue);
        let text = read(&dir.0.join(SYSTEM_LOG));
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"header line"), "{text}");
        assert!(
            lines.get(1).is_some_and(|l| l.contains(" WARN ")
                && l.contains(
                    "session log: sessions\\2026-09-29_12-10-05_d1020ebf.log not opened"
                )
                && l.contains("the session's lines follow in the system log session=d1020ebf")),
            "{text}"
        );
        assert_eq!(lines.get(2), Some(&"a line of the session"), "{text}");
        assert!(
            lines
                .get(3)
                .is_some_and(|l| l.contains("session log closed session=d1020ebf")
                    && l.contains("why=finished")
                    && l.contains("end_reason=peer_closed")
                    && l.contains("lines=1 lost=0")),
            "{text}"
        );
        assert!(
            lines
                .get(4)
                .is_some_and(|l| l.contains("session log closed: sessions\\2026-09-29")),
            "{text}"
        );
        assert_eq!(system_lost.counts().total(), 0);
    }

    /// The file layer's lines — the transport's `ICE candidate pair in use` line whole, field for
    /// field: when that line is missing from a file, the running exe did not contain it (see the
    /// transport's `the_first_media_datagram_puts_the_candidate_pair_in_the_log`), not anything
    /// here dropping it. And an event whose field cannot be formatted leaves a line saying so
    /// instead of vanishing.
    #[test]
    fn the_file_layer_writes_every_event_it_is_given() {
        struct Unprintable;
        impl std::fmt::Display for Unprintable {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                Err(std::fmt::Error)
            }
        }

        let out = Arc::new(Mutex::new(Vec::new()));
        let file = Arc::clone(&out);
        let subscriber = tracing_subscriber::registry()
            .with(LogLevel::Debug.filter())
            .with(file_layer(move || TestFile {
                out: Arc::clone(&file),
            }));
        tracing::subscriber::with_default(subscriber, || {
            // A recorded session's values, in the shape `PeerLoop::note_selected_pair` logs.
            let source: SocketAddr = "172.18.0.1:55739".parse().expect("addr");
            let destination: SocketAddr = "198.51.100.157:12389".parse().expect("addr");
            let why = "first";
            let local_kind = "host";
            let relay_transport = "tcp";
            tracing::info!(
                target: "afklink_transport::webrtc",
                why,
                local = %source,
                local_kind,
                local_srflx = %"203.0.113.131:36558",
                remote = %destination,
                remote_kind = %"relay",
                remote_proto = %"udp",
                relay_transport,
                remote_prio = ?Some(16_786_431_u32),
                candidates_known = 12_usize,
                "ICE candidate pair in use"
            );
            tracing::info!(value = %Unprintable, "an event that cannot be formatted");
        });

        let text = text(&out);
        assert!(
            text.contains(
                " INFO afklink_transport::webrtc: ICE candidate pair in use why=\"first\" \
                 local=172.18.0.1:55739 local_kind=\"host\" local_srflx=203.0.113.131:36558 \
                 remote=198.51.100.157:12389 remote_kind=relay remote_proto=udp \
                 relay_transport=\"tcp\" remote_prio=Some(16786431) candidates_known=12\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("Unable to format the following event"),
            "{text}"
        );
    }
}
