//! msiexec's verbose log, read while it runs, for the one line that shows Windows Installer is past
//! the UAC consent — what separates «Разрешение Windows» from «Установка» / «Удаление» in the
//! dialog.
//!
//! **Which line, and why it is only written after the consent.** With `/passive` msiexec itself
//! runs nothing: «Client-side and UI is none or basic: Running entire install on the server». The
//! Windows Installer service takes the whole operation and asks for elevation at the very beginning
//! of its own processing of the package, before its execute sequence runs a single action (Robert
//! Flaming, Windows Installer team, «UAC in MSI Notes: Credential Prompt and Permissions»). The
//! service logs as it goes, so its first lines — `MSI (s) … Resetting cached policy values`, the
//! software restriction policy check, `MSI_LUA: Elevation required to install product, will prompt
//! for credentials` — are in the file **before** the prompt is answered: «the first `MSI (s)`
//! line» is no consent. Two lines are (the texts from «UAC in MSI Notes: How do I troubleshoot UAC
//! in MSI via the log?»):
//!
//! - `MSI_LUA: Elevated credential consent provided. Install will run elevated` — written the moment
//!   the prompt is answered «Да», after `MSI_LUA: Credential Request return = 0x0`. A «Нет» writes
//!   `… return = 0x800704C7` (`ERROR_CANCELLED`) instead, and msiexec ends with 1602. Only when a
//!   prompt was shown.
//! - `MSI (s) (…) […]: Doing action: InstallInitialize` — the start of the transaction, inside the
//!   execute sequence (FakerInput's package: sequence 1500, before its driver actions), which runs
//!   only once the elevation question is settled: after the consent, or when no prompt was needed
//!   (the app already elevated, `AlwaysInstallElevated`, a managed product — `MSI_LUA: Credential
//!   prompt not required …`). A declined prompt never gets there.
//!
//! Whichever comes first moves the dialog on. Both are the service's own debug lines, English on
//! every Windows language; the localized `Action start …` (German «Aktion gestartet um …») is not
//! used.
//!
//! **Format.** Text, CRLF lines, in UTF-16LE with a BOM or in the ANSI code page — both are met in
//! the wild, so the first bytes decide. The markers are ASCII, so an ANSI file is read as lossy
//! UTF-8 and its Cyrillic (a localized line, a path) cannot hide them. `/l*v!` has every line
//! flushed as it is written; without `!` the log is buffered and the consent line could land
//! seconds late.
//!
//! **Reading it live.** msiexec creates the file as it starts, and it and the service append to it;
//! such logs are tailed live all the time (CMTrace), i.e. they are opened sharing read. Each look
//! opens the file (sharing read, write and delete), reads what is new and closes it again: no handle
//! is held while msiexec works. Nothing here can touch the operation: after repeated failures the
//! watch gives up (`warn`), and the dialog shows the first two steps running together.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long msiexec may take to create its log before the watch stops waiting for it.
const LOG_APPEAR_TIMEOUT: Duration = Duration::from_secs(5);

/// Failed reads in a row (other than «not created yet») the watch rides out before giving up.
const READ_FAILURES_TOLERATED: u32 = 3;

/// The most one look reads; the rest waits for the next look.
const READ_CHUNK: u64 = 4 << 20;

/// A line of the log that means something for the dialog or for the diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogMarker {
    /// `MSI_LUA: Elevation required …, will prompt for credentials`: the UAC prompt is going up.
    PromptRequested,
    /// `MSI_LUA: Credential prompt not required …`: no prompt (the caller is already elevated).
    NoPromptNeeded,
    /// `MSI_LUA: Elevated credential consent provided …`: the prompt was answered «Да».
    ConsentProvided,
    /// `MSI (s) … Doing action: InstallInitialize`: the transaction started, past any consent.
    InstallInitialize,
}

impl LogMarker {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::PromptRequested => "MSI_LUA: elevation required, prompting",
            Self::NoPromptNeeded => "MSI_LUA: credential prompt not required",
            Self::ConsentProvided => "MSI_LUA: elevated credential consent provided",
            Self::InstallInitialize => "server: Doing action: InstallInitialize",
        }
    }

    /// Whether the line is only ever written once Windows Installer is past the consent.
    pub(super) fn past_consent(self) -> bool {
        matches!(self, Self::ConsentProvided | Self::InstallInitialize)
    }
}

/// What `line` (one log line, without its line end) means, if anything.
pub(super) fn classify(line: &str) -> Option<LogMarker> {
    if let Some((_, lua)) = line.split_once("MSI_LUA: ") {
        return if lua.starts_with("Elevated credential consent provided") {
            Some(LogMarker::ConsentProvided)
        } else if lua.starts_with("Elevation required") {
            Some(LogMarker::PromptRequested)
        } else if lua.starts_with("Credential prompt not required") {
            Some(LogMarker::NoPromptNeeded)
        } else {
            None
        };
    }
    // The service's line only (`MSI (c)` is msiexec itself), and exactly this action.
    if line.starts_with("MSI (s)") {
        if let Some((_, action)) = line.split_once("Doing action: ") {
            if action.trim_end() == "InstallInitialize" {
                return Some(LogMarker::InstallInitialize);
            }
        }
    }
    None
}

/// The log's text encoding, told by its first bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogEncoding {
    /// UTF-16LE, with or without a BOM.
    Utf16Le,
    /// The ANSI code page (or UTF-8): read as lossy UTF-8.
    Narrow,
}

/// Turns the log's bytes, as they arrive in pieces, into whole lines.
#[derive(Debug, Default)]
pub(super) struct LineReader {
    encoding: Option<LogEncoding>,
    /// Bytes of a line not finished yet (or, before the encoding is known, the first byte).
    pending: Vec<u8>,
}

impl LineReader {
    /// The encoding, once two bytes have been seen.
    pub(super) fn encoding(&self) -> Option<LogEncoding> {
        self.encoding
    }

    /// Take the next bytes of the log; every line they complete goes to `on_line`, without its
    /// line end. A line cut between two reads waits for its end.
    pub(super) fn feed(&mut self, bytes: &[u8], on_line: &mut dyn FnMut(&str)) {
        self.pending.extend_from_slice(bytes);
        self.lines(false, on_line);
    }

    /// msiexec is done: whatever is left is the last line, even without a line end.
    pub(super) fn finish(&mut self, on_line: &mut dyn FnMut(&str)) {
        self.lines(true, on_line);
        self.pending.clear();
    }

    fn lines(&mut self, all: bool, on_line: &mut dyn FnMut(&str)) {
        let Some(encoding) = self.detect() else {
            return;
        };
        let consumed = match encoding {
            LogEncoding::Utf16Le => {
                let units: Vec<u16> = self
                    .pending
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&pair| u16::from_le_bytes(pair))
                    .collect();
                let end = if all {
                    Some(units.len())
                } else {
                    units
                        .iter()
                        .rposition(|&u| u == u16::from(b'\n'))
                        .map(|last| last + 1)
                };
                end.map_or(0, |end| {
                    String::from_utf16_lossy(&units[..end])
                        .lines()
                        .for_each(&mut *on_line);
                    end * 2
                })
            }
            LogEncoding::Narrow => {
                let end = if all {
                    Some(self.pending.len())
                } else {
                    self.pending
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map(|last| last + 1)
                };
                end.map_or(0, |end| {
                    String::from_utf8_lossy(&self.pending[..end])
                        .lines()
                        .for_each(&mut *on_line);
                    end
                })
            }
        };
        self.pending.drain(..consumed.min(self.pending.len()));
    }

    /// The encoding from the first two bytes, dropping a BOM; `None` until there are two.
    fn detect(&mut self) -> Option<LogEncoding> {
        if self.encoding.is_none() {
            let (encoding, bom) = match self.pending.as_slice() {
                [0xFF, 0xFE, ..] => (LogEncoding::Utf16Le, 2),
                // `=\0=\0=\0 Verbose logging started`: UTF-16LE without a BOM.
                [first, 0, ..] if *first != 0 => (LogEncoding::Utf16Le, 0),
                [0xEF, 0xBB, 0xBF, ..] => (LogEncoding::Narrow, 3),
                [_, _, ..] => (LogEncoding::Narrow, 0),
                _ => return None,
            };
            self.pending.drain(..bom);
            self.encoding = Some(encoding);
        }
        self.encoding
    }
}

/// What the watch has to tell the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WatchEvent {
    /// A line only written past the consent: Windows Installer is at work.
    PastConsent(LogMarker),
    /// The log cannot be read: consent and work cannot be told apart from here on.
    Blind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchState {
    Watching,
    PastConsent(LogMarker),
    Blind,
}

/// Follows one msiexec run's log from its start.
#[derive(Debug)]
pub(super) struct LogWatch {
    path: PathBuf,
    started: Instant,
    offset: u64,
    reader: LineReader,
    failures: u32,
    state: WatchState,
    waiting_logged: bool,
}

impl LogWatch {
    pub(super) fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            started: Instant::now(),
            offset: 0,
            reader: LineReader::default(),
            failures: 0,
            state: WatchState::Watching,
            waiting_logged: false,
        }
    }

    /// Still looking: neither the line past the consent seen nor given up on the log.
    pub(super) fn watching(&self) -> bool {
        self.state == WatchState::Watching
    }

    /// One look at what msiexec has written since the last. `Some` when the dialog should move;
    /// after that, and after giving up, it only returns `None`.
    pub(super) fn poll(&mut self) -> Option<WatchEvent> {
        if self.state != WatchState::Watching {
            return None;
        }
        let (bytes, len) = match read_from(&self.path, self.offset) {
            Ok(read) => read,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return self.not_there_yet();
            }
            Err(e) => return self.read_failed(&e),
        };
        self.failures = 0;
        if len < self.offset {
            tracing::warn!(
                log = %self.path.display(),
                len,
                offset = self.offset,
                "FakerInput: the Windows Installer log got shorter while it ran; reading it from the \
                 start"
            );
            self.offset = 0;
            self.reader = LineReader::default();
            return None;
        }
        self.offset += bytes.len() as u64;
        let found = self.scan(&bytes, false)?;
        self.state = WatchState::PastConsent(found);
        Some(WatchEvent::PastConsent(found))
    }

    /// msiexec has exited (`succeeded`: 0 or 3010). If the line was not seen while it ran, read the
    /// finished log for it — whether it is there at all is what tells a declined prompt from a
    /// marker that needs checking.
    pub(super) fn finish(mut self, succeeded: bool) {
        match self.state {
            WatchState::PastConsent(_) | WatchState::Blind => return,
            WatchState::Watching => {}
        }
        let found = match read_from(&self.path, self.offset) {
            Ok((bytes, _)) => {
                let found = self.scan(&bytes, true);
                found.map(|marker| marker.name())
            }
            Err(e) => {
                tracing::warn!(
                    log = %self.path.display(),
                    "FakerInput: the finished Windows Installer log not read ({e}); whether it has \
                     the line past the consent is unknown"
                );
                return;
            }
        };
        match (found, succeeded) {
            (Some(marker), _) => tracing::debug!(
                marker,
                "FakerInput: the line past the consent is in the log, but appeared only after \
                 msiexec exited"
            ),
            (None, false) => tracing::debug!(
                "FakerInput: no line past the consent in the finished log: Windows Installer \
                 stopped before it (a declined prompt, or an earlier refusal)"
            ),
            (None, true) => tracing::warn!(
                log = %self.path.display(),
                "FakerInput: msiexec succeeded, yet its log has no line past the consent; the \
                 dialog could not tell permission from work — the marker needs checking"
            ),
        }
    }

    /// Feed `bytes`, logging each meaningful line at `debug`; the first line past the consent.
    fn scan(&mut self, bytes: &[u8], last: bool) -> Option<LogMarker> {
        let had_encoding = self.reader.encoding();
        let after_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut found = None;
        let mut on_line = |line: &str| {
            if found.is_some() {
                return;
            }
            if let Some(marker) = classify(line) {
                tracing::debug!(
                    marker = marker.name(),
                    after_ms,
                    past_consent = marker.past_consent(),
                    "FakerInput: Windows Installer log line"
                );
                if marker.past_consent() {
                    found = Some(marker);
                }
            }
        };
        self.reader.feed(bytes, &mut on_line);
        if last {
            self.reader.finish(&mut on_line);
        }
        if had_encoding.is_none() {
            if let Some(encoding) = self.reader.encoding() {
                tracing::debug!(
                    ?encoding,
                    log = %self.path.display(),
                    "FakerInput: Windows Installer log encoding"
                );
            }
        }
        found
    }

    fn not_there_yet(&mut self) -> Option<WatchEvent> {
        if self.started.elapsed() < LOG_APPEAR_TIMEOUT {
            if !self.waiting_logged {
                tracing::debug!(
                    log = %self.path.display(),
                    "FakerInput: the Windows Installer log is not there yet; waiting for msiexec to \
                     create it"
                );
                self.waiting_logged = true;
            }
            return None;
        }
        tracing::warn!(
            log = %self.path.display(),
            timeout_s = LOG_APPEAR_TIMEOUT.as_secs(),
            "FakerInput: msiexec has not created its log; permission and work are shown together"
        );
        self.state = WatchState::Blind;
        Some(WatchEvent::Blind)
    }

    /// A read that failed (not «not created yet»): `warn` each time — at most
    /// [`READ_FAILURES_TOLERATED`] in a row, then the watch gives up.
    fn read_failed(&mut self, error: &io::Error) -> Option<WatchEvent> {
        self.failures += 1;
        if self.failures < READ_FAILURES_TOLERATED {
            tracing::warn!(
                log = %self.path.display(),
                failures = self.failures,
                "FakerInput: the Windows Installer log not read ({error}); trying again"
            );
            return None;
        }
        tracing::warn!(
            log = %self.path.display(),
            failures = self.failures,
            "FakerInput: the Windows Installer log cannot be read ({error}); permission and work are \
             shown together"
        );
        self.state = WatchState::Blind;
        Some(WatchEvent::Blind)
    }
}

/// The bytes of `path` from `offset` on (at most [`READ_CHUNK`]), and the file's length. Opened
/// sharing read, write and delete — Rust's default — and closed before returning.
fn read_from(path: &Path, offset: u64) -> io::Result<(Vec<u8>, u64)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len <= offset {
        return Ok((Vec::new(), len));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    file.take(READ_CHUNK).read_to_end(&mut bytes)?;
    Ok((bytes, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A verbose log of `msiexec /i … /passive /l*v!` from a non-elevated caller, as the service
    /// writes it: before the prompt is answered, then after «Да». (The lines around the markers are
    /// the usual ones; the Russian line is how a localized Windows prints the action start.)
    const BEFORE_CONSENT: &[&str] = &[
        "=== Verbose logging started: 28.09.2026  14:12:03  Build type: SHIP UNICODE 5.00.10011.00  \
         Calling process: C:\\WINDOWS\\system32\\msiexec.exe ===",
        "MSI (c) (1C:2C) [14:12:03:120]: Resetting cached policy values",
        "MSI (c) (1C:2C) [14:12:03:121]: Client-side and UI is none or basic: Running entire install \
         on the server.",
        "MSI (c) (1C:2C) [14:12:03:122]: Grabbed execution mutex.",
        "MSI (s) (58:A0) [14:12:03:140]: Resetting cached policy values",
        "MSI (s) (58:A0) [14:12:03:141]: Machine policy value 'Debug' is 0",
        "MSI (s) (58:A0) [14:12:03:190]: SOFTWARE RESTRICTION POLICY: Verifying package --> \
         'C:\\Users\\Иван\\AppData\\Local\\Temp\\AFKLink-FakerInput-1\\FakerInput_Setup_0.1.1_x64.msi' \
         against software restriction policy",
        "MSI (s) (58:A0) [14:12:03:220]: Product {17AA3E01-1012-4BF7-B908-1C499909B259} is not \
         managed.",
        "MSI (s) (58:A0) [14:12:03:221]: MSI_LUA: Elevation required to install product, will prompt \
         for credentials",
    ];
    const AFTER_CONSENT: &[&str] = &[
        "MSI (s) (58:A0) [14:12:07:512]: MSI_LUA: Credential Request return = 0x0",
        "MSI (s) (58:A0) [14:12:07:512]: MSI_LUA: Elevated credential consent provided. Install will \
         run elevated",
        "MSI (s) (58:A0) [14:12:07:530]: Product installation will be elevated because user provided \
         elevated credentials and product is being installed per-machine.",
        "MSI (s) (58:A0) [14:12:07:601]: Doing action: INSTALL",
        "Действие 14:12:07: INSTALL.",
        "MSI (s) (58:A0) [14:12:08:010]: Doing action: InstallInitialize",
        "Действие 14:12:08: InstallInitialize.",
    ];

    fn crlf(lines: &[&str]) -> String {
        lines.iter().map(|l| format!("{l}\r\n")).collect()
    }

    fn utf16le(text: &str, bom: bool) -> Vec<u8> {
        let mut bytes = if bom { vec![0xFF, 0xFE] } else { Vec::new() };
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        bytes
    }

    /// Russian text in Windows-1251, as an ANSI log on a Russian Windows would hold it.
    fn cp1251(text: &str) -> Vec<u8> {
        text.chars()
            .map(|c| match c {
                'А'..='я' => (u32::from(c) - 0x0410 + 0xC0) as u8,
                c if c.is_ascii() => c as u8,
                _ => b'?',
            })
            .collect()
    }

    fn markers(bytes: &[u8]) -> Vec<LogMarker> {
        let mut reader = LineReader::default();
        let mut found = Vec::new();
        reader.feed(bytes, &mut |line| found.extend(classify(line)));
        found
    }

    #[test]
    fn only_the_consent_and_the_transaction_count_as_past_the_consent() {
        let mut before = Vec::new();
        for line in BEFORE_CONSENT {
            before.extend(classify(line));
        }
        // The service's lines before the answer — the prompt request included — are not consent.
        assert_eq!(before, vec![LogMarker::PromptRequested]);
        assert!(!LogMarker::PromptRequested.past_consent());

        let after: Vec<LogMarker> = AFTER_CONSENT.iter().filter_map(|l| classify(l)).collect();
        assert_eq!(
            after,
            vec![LogMarker::ConsentProvided, LogMarker::InstallInitialize]
        );
        assert!(after.iter().all(|m| m.past_consent()));

        // No prompt at all (the caller already elevated): noted, but only the transaction moves on.
        let admin =
            "MSI (s) (58:A0) [14:12:03:221]: MSI_LUA: Credential prompt not required, user is \
                     an admin";
        assert_eq!(classify(admin), Some(LogMarker::NoPromptNeeded));
        assert!(!LogMarker::NoPromptNeeded.past_consent());

        // A declined prompt: nothing past the consent.
        let declined = "MSI (s) (58:A0) [14:12:09:004]: MSI_LUA: Credential Request return = \
                        0x800704C7";
        assert_eq!(classify(declined), None);

        // Not msiexec's own lines, not another action, not the localized action start.
        for line in [
            "MSI (c) (1C:2C) [14:12:03:300]: Doing action: InstallInitialize",
            "MSI (s) (58:A0) [14:12:08:010]: Doing action: InstallInitializeCustom",
            "MSI (s) (58:A0) [14:12:08:010]: Doing action: InstallFiles",
            "Action start 14:12:08: InstallInitialize.",
            "Действие 14:12:08: InstallInitialize.",
        ] {
            assert_eq!(classify(line), None, "{line}");
        }
    }

    #[test]
    fn both_encodings_are_read_line_by_line() {
        let text = crlf(BEFORE_CONSENT) + &crlf(AFTER_CONSENT);
        let want = vec![
            LogMarker::PromptRequested,
            LogMarker::ConsentProvided,
            LogMarker::InstallInitialize,
        ];
        assert_eq!(markers(&utf16le(&text, true)), want, "UTF-16LE with a BOM");
        assert_eq!(
            markers(&utf16le(&text, false)),
            want,
            "UTF-16LE without a BOM"
        );
        assert_eq!(markers(&cp1251(&text)), want, "ANSI (Windows-1251)");
        assert_eq!(markers(text.as_bytes()), want, "UTF-8");

        let mut reader = LineReader::default();
        reader.feed(&utf16le("=== x\r\n", true), &mut |_| {});
        assert_eq!(reader.encoding(), Some(LogEncoding::Utf16Le));
        let mut reader = LineReader::default();
        reader.feed(&cp1251("=== x\r\n"), &mut |_| {});
        assert_eq!(reader.encoding(), Some(LogEncoding::Narrow));
    }

    #[test]
    fn a_line_cut_between_reads_is_read_whole() {
        let consent = crlf(&AFTER_CONSENT[1..2]);
        for bytes in [utf16le(&consent, true), cp1251(&consent)] {
            // Every split, odd ones through a UTF-16 code unit included.
            for cut in 1..bytes.len() {
                let mut reader = LineReader::default();
                let mut lines = Vec::new();
                reader.feed(&bytes[..cut], &mut |l| lines.push(l.to_owned()));
                reader.feed(&bytes[cut..], &mut |l| lines.push(l.to_owned()));
                assert_eq!(lines.len(), 1, "cut at {cut}");
                assert_eq!(classify(&lines[0]), Some(LogMarker::ConsentProvided));
            }
        }
        // The last line without a line end waits for `finish`.
        let mut reader = LineReader::default();
        let mut lines = Vec::new();
        reader.feed(AFTER_CONSENT[5].as_bytes(), &mut |l| {
            lines.push(l.to_owned())
        });
        assert!(lines.is_empty());
        reader.finish(&mut |l| lines.push(l.to_owned()));
        assert_eq!(lines, vec![AFTER_CONSENT[5].to_owned()]);
    }

    /// A fresh file under the temp folder, removed when dropped.
    struct TempLog(PathBuf);

    impl TempLog {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "afklink-app-msi-log-{}-{}.log",
                std::process::id(),
                uuid::Uuid::new_v4()
            )))
        }

        fn append(&self, bytes: &[u8]) {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.0)
                .unwrap();
            file.write_all(bytes).unwrap();
        }
    }

    impl Drop for TempLog {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn the_watch_moves_on_only_once_the_consent_line_is_written() {
        type Encode = fn(&str) -> Vec<u8>;
        let encodings: [(&str, Encode); 2] =
            [("utf-16le", |t| utf16le(t, false)), ("ansi", cp1251)];
        for (name, encode) in encodings {
            let log = TempLog::new();
            let mut watch = LogWatch::new(&log.0);
            // msiexec has not created the file yet.
            assert_eq!(watch.poll(), None, "{name}");
            // The BOM first, as msiexec writes it, then the service up to the prompt.
            if name == "utf-16le" {
                log.append(&[0xFF, 0xFE]);
            }
            log.append(&encode(&crlf(BEFORE_CONSENT)));
            assert_eq!(watch.poll(), None, "{name}");
            // Half of the consent line: not yet.
            let consent = encode(&crlf(&AFTER_CONSENT[..2]));
            let half = consent.len() / 2 + 1;
            log.append(&consent[..half]);
            assert_eq!(watch.poll(), None, "{name}");
            assert!(watch.watching(), "{name}");
            log.append(&consent[half..]);
            assert_eq!(
                watch.poll(),
                Some(WatchEvent::PastConsent(LogMarker::ConsentProvided)),
                "{name}"
            );
            // Said once.
            assert!(!watch.watching(), "{name}");
            log.append(&encode(&crlf(&AFTER_CONSENT[2..])));
            assert_eq!(watch.poll(), None, "{name}");
            watch.finish(true);
        }
    }

    #[test]
    fn without_a_prompt_the_transaction_moves_the_watch() {
        let log = TempLog::new();
        let mut watch = LogWatch::new(&log.0);
        let admin = [
            "MSI (s) (58:A0) [14:12:03:221]: MSI_LUA: Credential prompt not required, user is an admin",
            "MSI (s) (58:A0) [14:12:03:601]: Doing action: INSTALL",
            "MSI (s) (58:A0) [14:12:04:010]: Doing action: InstallInitialize",
        ];
        log.append(&utf16le(&crlf(&admin), true));
        assert_eq!(
            watch.poll(),
            Some(WatchEvent::PastConsent(LogMarker::InstallInitialize))
        );
    }

    #[test]
    fn a_log_that_never_appears_is_given_up_on() {
        let log = TempLog::new();
        let mut watch = LogWatch::new(&log.0);
        watch.started = Instant::now() - LOG_APPEAR_TIMEOUT - Duration::from_millis(1);
        assert_eq!(watch.poll(), Some(WatchEvent::Blind));
        // Given up: nothing more, even once the file is there.
        log.append(&utf16le(&crlf(AFTER_CONSENT), true));
        assert_eq!(watch.poll(), None);
        watch.finish(true);
    }

    #[test]
    fn repeated_read_failures_are_given_up_on() {
        // A directory where the file should be: opening it fails, and not with «not found».
        let dir = std::env::temp_dir().join(format!(
            "afklink-app-msi-log-dir-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut watch = LogWatch::new(&dir);
        let events: Vec<Option<WatchEvent>> = (0..READ_FAILURES_TOLERATED + 1)
            .map(|_| watch.poll())
            .collect();
        std::fs::remove_dir(&dir).unwrap();
        let blind_at = events.iter().position(Option::is_some);
        assert_eq!(
            blind_at,
            Some(READ_FAILURES_TOLERATED as usize - 1),
            "{events:?}"
        );
        assert_eq!(
            events[READ_FAILURES_TOLERATED as usize - 1],
            Some(WatchEvent::Blind)
        );
        assert_eq!(events[READ_FAILURES_TOLERATED as usize], None);
    }
}
