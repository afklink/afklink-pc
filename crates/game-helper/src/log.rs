//! `helper.log` (the helper's lines) and `setup.log` (the elevated setup's), in UTC, one line per
//! decision. The desktop app mirrors new lines of both into its own log
//! (`afklink_app_lib::game_helper`), so a session's file has what the helper decided during it.
//!
//! Each file has one writer: the setup never writes `helper.log`, because a setup that installs over
//! a running helper would append and rotate it while that helper still does — two processes renaming
//! the same file lose lines.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The helper's log in the directory it writes to.
pub const LOG_FILE: &str = "helper.log";
/// The previous helper log, kept once: rotation renames `helper.log` to this.
pub const LOG_OLD_FILE: &str = "helper.1.log";
/// The setup's log, in the install directory only (the setup runs elevated).
pub const SETUP_LOG_FILE: &str = "setup.log";
/// The previous setup log, kept once.
pub const SETUP_LOG_OLD_FILE: &str = "setup.1.log";
/// Each log is rotated at about this size. A line comes per decision, not per tick, so this holds
/// weeks of sessions (and many more setups).
pub const LOG_MAX_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "ERROR" => Some(Self::Error),
            "WARN" => Some(Self::Warn),
            "INFO" => Some(Self::Info),
            "DEBUG" => Some(Self::Debug),
            _ => None,
        }
    }
}

/// Where the helper's decisions go: [`HelperLog`], or a list in tests.
pub trait Log {
    fn line(&mut self, level: Level, message: &str);
}

/// Appends to one log file in one directory, rotating it at [`LOG_MAX_BYTES`]. Opened for each line
/// and closed again: lines are rare, and no handle keeps the file from the setup that removes it.
pub struct HelperLog {
    path: PathBuf,
    old: PathBuf,
    who: &'static str,
    max_bytes: u64,
    /// The last write that failed, for the state file — the log cannot report its own failures.
    failed: Option<String>,
}

impl HelperLog {
    /// The helper's `helper.log` in `dir`; its lines say `helper:`.
    pub fn new(dir: &Path) -> Self {
        Self::with_limit(dir, LOG_FILE, LOG_OLD_FILE, "helper", LOG_MAX_BYTES)
    }

    /// The setup's `setup.log` in `dir`; its lines say `setup:`.
    pub fn setup(dir: &Path) -> Self {
        Self::with_limit(
            dir,
            SETUP_LOG_FILE,
            SETUP_LOG_OLD_FILE,
            "setup",
            LOG_MAX_BYTES,
        )
    }

    /// `file` and `old`: the log and its rotated copy; `who`: the line's source.
    pub fn with_limit(
        dir: &Path,
        file: &str,
        old: &str,
        who: &'static str,
        max_bytes: u64,
    ) -> Self {
        Self {
            path: dir.join(file),
            old: dir.join(old),
            who,
            max_bytes,
            failed: None,
        }
    }

    pub fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    fn write(&mut self, line: &str) -> std::io::Result<()> {
        let size = std::fs::metadata(&self.path).map_or(0, |m| m.len());
        if size > 0 && size + line.len() as u64 > self.max_bytes {
            std::fs::rename(&self.path, &self.old)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())
    }
}

impl Log for HelperLog {
    fn line(&mut self, level: Level, message: &str) {
        let line = format_line(SystemTime::now(), level, self.who, message);
        match self.write(&line) {
            Ok(()) => self.failed = None,
            Err(e) => self.failed = Some(format!("{}: {e}", self.path.display())),
        }
    }
}

/// `2026-10-02T10:11:12.345Z INFO helper: message`, one line whatever the message holds.
pub fn format_line(at: SystemTime, level: Level, who: &str, message: &str) -> String {
    let message = message.replace(['\r', '\n'], " | ");
    format!("{} {} {who}: {message}\n", utc_stamp(at), level.as_str())
}

/// A line of `helper.log` or `setup.log`, split: its stamp, its level and the rest (`helper: …`).
pub fn parse_line(line: &str) -> Option<(&str, Level, &str)> {
    let (stamp, rest) = line.split_once(' ')?;
    let (level, rest) = rest.split_once(' ')?;
    if stamp.len() != STAMP_LEN || !stamp.ends_with('Z') {
        return None;
    }
    Some((stamp, Level::parse(level)?, rest.trim_end()))
}

const STAMP_LEN: usize = "2026-10-02T10:11:12.345Z".len();

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`. Sorts as text in time order, which the app's mirror relies on.
pub fn utc_stamp(at: SystemTime) -> String {
    let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// Unix ms of `at`.
pub fn unix_ms(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn stamps_are_utc_and_sort_as_text() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        // An instant with every field non-zero, milliseconds included.
        let at = UNIX_EPOCH + Duration::from_millis(1_790_935_872_345);
        assert_eq!(utc_stamp(at), "2026-10-02T10:11:12.345Z");
        // A leap day.
        let leap = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(utc_stamp(leap), "2024-02-29T00:00:00.000Z");
        assert!(utc_stamp(leap) < utc_stamp(at));
    }

    #[test]
    fn a_line_is_one_line_and_parses_back() {
        let at = UNIX_EPOCH + Duration::from_millis(1_790_935_872_345);
        let line = format_line(at, Level::Warn, "helper", "two\nlines\r\n");
        assert_eq!(
            line,
            "2026-10-02T10:11:12.345Z WARN helper: two | lines |  | \n"
        );
        let (stamp, level, rest) = parse_line(&line).unwrap();
        assert_eq!(stamp, "2026-10-02T10:11:12.345Z");
        assert_eq!(level, Level::Warn);
        assert_eq!(rest, "helper: two | lines |  |");
        assert_eq!(parse_line("garbage"), None);
        assert_eq!(parse_line("2026-10-02T10:11:12.345Z LOUD x"), None);
    }

    #[test]
    fn the_log_rotates_once_and_keeps_one_old_file() {
        let dir = std::env::temp_dir().join(format!(
            "afklink-helper-log-{}-{}",
            std::process::id(),
            unix_ms(SystemTime::now())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut log = HelperLog::with_limit(&dir, LOG_FILE, LOG_OLD_FILE, "helper", 200);
        for i in 0..10 {
            log.line(
                Level::Info,
                &format!("line {i} with some padding to fill it"),
            );
        }
        assert!(log.failed().is_none());
        let current = std::fs::read_to_string(dir.join(LOG_FILE)).unwrap();
        let old = std::fs::read_to_string(dir.join(LOG_OLD_FILE)).unwrap();
        assert!(current.len() <= 200 && old.len() <= 200, "{current}\n{old}");
        assert!(current.contains("line 9"));
        assert!(!current.contains("line 0") && !old.contains("line 0"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The setup writes its own file: never the helper's, which a running helper may be rotating.
    #[test]
    fn the_setup_and_the_helper_write_different_files() {
        let dir = std::env::temp_dir().join(format!(
            "afklink-setup-log-{}-{}",
            std::process::id(),
            unix_ms(SystemTime::now())
        ));
        std::fs::create_dir_all(&dir).unwrap();
        HelperLog::setup(&dir).line(Level::Info, "started elevated");
        HelperLog::new(&dir).line(Level::Info, "started");
        let setup = std::fs::read_to_string(dir.join(SETUP_LOG_FILE)).unwrap();
        let helper = std::fs::read_to_string(dir.join(LOG_FILE)).unwrap();
        assert!(
            setup.contains(" INFO setup: started elevated") && !setup.contains("helper:"),
            "{setup}"
        );
        assert!(
            helper.contains(" INFO helper: started") && !helper.contains("setup:"),
            "{helper}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
