//! The log files on disk: their names, and how long each is kept.
//!
//! `%APPDATA%\AFKLink\logs\`:
//!
//! - `system.log` — the system log: the app's life outside sessions (startup, config, settings,
//!   the tray, signaling, pairing, updates, the driver, autostart, exit), and the system events that
//!   happen during one. Rotated by size, not by day: at [`SYSTEM_MAX_BYTES`] it becomes
//!   `system.1.log`, `system.1.log` becomes `system.2.log`, and so on; the oldest,
//!   `system.<SYSTEM_ROTATIONS>.log`, goes. So at most `(1 + SYSTEM_ROTATIONS) × 8 MiB` = 32 MiB.
//! - `sessions\<local date>_<local time>_<first 8 of the session id>.log` — one file per session
//!   ([`session_file_name`]), e.g. `sessions\2026-09-29_12-10-05_d1020ebf.log`: the local time the
//!   session was requested, so the files sort by when they happened and the owner finds «the one
//!   at ten past twelve» by its name. Kept [`SESSION_MAX_AGE_DAYS`] days, at most
//!   [`SESSION_MAX_FILES`] files and [`SESSION_MAX_BYTES`] together, the oldest going first
//!   ([`sessions_to_remove`]); a session's own file is never removed while it is open.
//! - `afklink-app.<UTC date>.log` — the daily files of older builds (and
//!   `remoter-app.<UTC date>.log`, under the app's former name). Not written now; removed once
//!   their day is more than [`LEGACY_MAX_AGE_DAYS`] days back ([`legacy_to_remove`]), the daily
//!   appender's own limit.
//! - `afklink-watchdog.<UTC date>.log` (the update's watchdog, another process with its own
//!   appender) and `msiexec-fakerinput-*.log` (Windows Installer, pruned by `fakerinput_setup`):
//!   never touched here.
//!
//! Anything else in the folder — `identity.json` if someone copies it there, a file of the owner's —
//! is not ours by name and is left alone. [`sweep`] applies the rules on disk; the log writer runs
//! it when the log opens, after each session's file closes, and once an hour.

use std::io;
use std::path::Path;

/// The system log's name.
pub(crate) const SYSTEM_LOG: &str = "system.log";

/// The size at which `system.log` is rotated. At a quiet PC's rate (a few kilobytes a day outside
/// sessions) that is months; with the system events of busy days, weeks.
pub(crate) const SYSTEM_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Rotated system logs kept beside the current one: `system.1.log` (the newest) to `system.3.log`.
pub(crate) const SYSTEM_ROTATIONS: u32 = 3;

/// The folder of the session files, inside the logs folder.
pub(crate) const SESSIONS_DIR: &str = "sessions";

/// How long a session's file is kept, from when the session was requested: a week covers «it broke
/// on Saturday» reported on Monday.
pub(crate) const SESSION_MAX_AGE_DAYS: i64 = 7;

/// The most session files kept, whatever their age: a hundred short sessions in a week of testing.
pub(crate) const SESSION_MAX_FILES: usize = 100;

/// The most the session files may weigh together. An hour at `debug` is ~5 MB (measured: 5.6 MB
/// for a day's sessions); a session at `trace` can be hundreds, and then it pushes the older ones
/// out.
pub(crate) const SESSION_MAX_BYTES: u64 = 200 * 1024 * 1024;

/// How many days back the old daily files (`afklink-app.<date>.log`) are kept — the daily
/// appender's own seven.
pub(crate) const LEGACY_MAX_AGE_DAYS: i64 = 7;

/// The old daily files' prefixes: this product's, and the name before the rename.
const LEGACY_PREFIXES: [&str; 2] = ["afklink-app.", "remoter-app."];

/// What [`sweep`] applies. [`RetentionRules::DEFAULT`] in the app; smaller in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetentionRules {
    pub(crate) session_max_age_days: i64,
    pub(crate) session_max_files: usize,
    pub(crate) session_max_bytes: u64,
    pub(crate) legacy_max_age_days: i64,
}

impl RetentionRules {
    pub(crate) const DEFAULT: Self = Self {
        session_max_age_days: SESSION_MAX_AGE_DAYS,
        session_max_files: SESSION_MAX_FILES,
        session_max_bytes: SESSION_MAX_BYTES,
        legacy_max_age_days: LEGACY_MAX_AGE_DAYS,
    };
}

/// The name of the system log's rotation `n`: `system.log` for 0, `system.<n>.log` after.
pub(crate) fn system_log_name(n: u32) -> String {
    if n == 0 {
        SYSTEM_LOG.to_string()
    } else {
        format!("system.{n}.log")
    }
}

/// Which rotation of the system log `name` is (0 for `system.log`), for `0..=SYSTEM_ROTATIONS`;
/// `None` for any other name.
pub(crate) fn system_log_index(name: &str) -> Option<u32> {
    (0..=SYSTEM_ROTATIONS).find(|&n| system_log_name(n) == name)
}

/// A wall-clock time in the PC's time zone, to the second: what a session file is named after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct LocalTime {
    pub(crate) year: i32,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: u32,
    pub(crate) minute: u32,
    pub(crate) second: u32,
}

impl LocalTime {
    pub(crate) const fn new(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// Now, as the PC's clock and time zone say (`GetLocalTime`).
    #[cfg(windows)]
    pub(crate) fn now() -> Self {
        // SAFETY: GetLocalTime takes no input and only fills the structure it returns.
        let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
        Self::new(
            i32::from(t.wYear),
            u32::from(t.wMonth),
            u32::from(t.wDay),
            u32::from(t.wHour),
            u32::from(t.wMinute),
            u32::from(t.wSecond),
        )
    }

    /// Now, in UTC: off Windows there is no time zone to ask (the app runs on Windows only).
    #[cfg(not(windows))]
    pub(crate) fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let (y, m, d) = crate::fakerinput_setup::civil_from_days((secs / 86_400) as i64);
        let rem = secs % 86_400;
        Self::new(
            y as i32,
            m,
            d,
            (rem / 3600) as u32,
            ((rem % 3600) / 60) as u32,
            (rem % 60) as u32,
        )
    }

    /// Seconds since 1970-01-01 00:00 of the same wall clock, as if it were UTC: comparable with
    /// another local time, which is all an age needs.
    pub(crate) fn civil_seconds(self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    /// `YYYY-MM-DD HH:MM:SS`, for a header.
    pub(crate) fn display(self) -> String {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// Days from 1970-01-01 to `year-month-day` (proleptic Gregorian), negative before it. Howard
/// Hinnant's `days_from_civil`, the inverse of `fakerinput_setup::civil_from_days`.
pub(crate) fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The first eight characters of a session id that may go into a file name: letters, digits and
/// `-` (a UUID's first group); `session` when there are none.
pub(crate) fn short_id(session_id: &str) -> String {
    let short: String = session_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(8)
        .collect();
    if short.is_empty() {
        "session".to_string()
    } else {
        short
    }
}

/// `<YYYY-MM-DD>_<HH-MM-SS>_<short id>.log`: the session file's name (inside [`SESSIONS_DIR`]).
pub(crate) fn session_file_name(requested: LocalTime, session_id: &str) -> String {
    format!(
        "{:04}-{:02}-{:02}_{:02}-{:02}-{:02}_{}.log",
        requested.year,
        requested.month,
        requested.day,
        requested.hour,
        requested.minute,
        requested.second,
        short_id(session_id)
    )
}

/// The time in a session file's name, or `None` when the name is not one of ours.
pub(crate) fn session_file_time(name: &str) -> Option<LocalTime> {
    let stem = name.strip_suffix(".log")?;
    let (date, rest) = (stem.get(..10)?, stem.get(10..)?);
    let (time, id) = (rest.strip_prefix('_')?.get(..8)?, rest.get(10..)?);
    if rest.get(9..10)? != "_"
        || id.is_empty()
        || id.len() > 8
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    let digits = |s: &str, seps: &[usize], sep: u8| {
        s.bytes().enumerate().all(|(i, b)| {
            if seps.contains(&i) {
                b == sep
            } else {
                b.is_ascii_digit()
            }
        })
    };
    if date.len() != 10 || !digits(date, &[4, 7], b'-') || !digits(time, &[2, 5], b'-') {
        return None;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    let t = LocalTime::new(
        date.get(..4)?.parse().ok()?,
        num(date.get(5..7)?)?,
        num(date.get(8..10)?)?,
        num(time.get(..2)?)?,
        num(time.get(3..5)?)?,
        num(time.get(6..8)?)?,
    );
    let valid = (1..=12).contains(&t.month)
        && (1..=31).contains(&t.day)
        && t.hour < 24
        && t.minute < 60
        && t.second < 61;
    valid.then_some(t)
}

/// The day (since 1970, UTC) of an old daily file — `afklink-app.<YYYY-MM-DD>.log` or
/// `remoter-app.<YYYY-MM-DD>.log` — or `None` for any other name.
pub(crate) fn legacy_day(name: &str) -> Option<i64> {
    let date = LEGACY_PREFIXES
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix)?.strip_suffix(".log"))?;
    let shape_ok = date.len() == 10
        && date.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            _ => b.is_ascii_digit(),
        });
    if !shape_ok {
        return None;
    }
    let (y, m, d) = (
        date.get(..4)?.parse().ok()?,
        date.get(5..7)?.parse().ok()?,
        date.get(8..10)?.parse().ok()?,
    );
    ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| days_from_civil(y, m, d))
}

/// A file to remove, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Removal {
    /// Relative to the logs folder: `sessions\<name>` or the old daily file's name.
    pub(crate) name: String,
    pub(crate) bytes: u64,
    pub(crate) why: &'static str,
}

/// Which session files to remove, oldest first: past the age, then past the count, then past the
/// bytes. `files` are the names and sizes in [`SESSIONS_DIR`] (names not of ours are left alone and
/// not counted); `open` the files being written now, which are never removed — they still count,
/// so the older ones make room for them.
pub(crate) fn sessions_to_remove(
    files: &[(String, u64)],
    now: LocalTime,
    open: &[String],
    rules: &RetentionRules,
) -> Vec<Removal> {
    let mut ours: Vec<(LocalTime, &str, u64)> = files
        .iter()
        .filter_map(|(name, bytes)| Some((session_file_time(name)?, name.as_str(), *bytes)))
        .collect();
    ours.sort();
    let is_open = |name: &str| open.iter().any(|o| o == name);
    let cutoff = now.civil_seconds() - rules.session_max_age_days * 86_400;
    let mut removals = Vec::new();
    let mut kept = Vec::new();
    for (at, name, bytes) in ours {
        if at.civil_seconds() < cutoff && !is_open(name) {
            removals.push(Removal {
                name: format!("{SESSIONS_DIR}\\{name}"),
                bytes,
                why: "older_than_max_age",
            });
        } else {
            kept.push((name, bytes));
        }
    }
    let mut count = kept.len();
    let mut total: u64 = kept.iter().map(|(_, b)| b).sum();
    for (name, bytes) in kept {
        if count <= rules.session_max_files && total <= rules.session_max_bytes {
            break;
        }
        if is_open(name) {
            continue;
        }
        let why = if count > rules.session_max_files {
            "over_max_files"
        } else {
            "over_max_bytes"
        };
        removals.push(Removal {
            name: format!("{SESSIONS_DIR}\\{name}"),
            bytes,
            why,
        });
        count -= 1;
        total = total.saturating_sub(bytes);
    }
    removals
}

/// Which old daily files among `files` (names and sizes in the logs folder) to remove: those whose
/// day is more than `legacy_max_age_days` before `today` (UTC days since 1970).
pub(crate) fn legacy_to_remove(
    files: &[(String, u64)],
    today: i64,
    rules: &RetentionRules,
) -> Vec<Removal> {
    let mut removals: Vec<Removal> = files
        .iter()
        .filter(|(name, _)| legacy_day(name).is_some_and(|d| d < today - rules.legacy_max_age_days))
        .map(|(name, bytes)| Removal {
            name: name.clone(),
            bytes: *bytes,
            why: "old_daily_file",
        })
        .collect();
    removals.sort_by(|a, b| a.name.cmp(&b.name));
    removals
}

/// What a [`sweep`] did.
#[derive(Debug, Default)]
pub(crate) struct Swept {
    pub(crate) removed: Vec<Removal>,
    /// Files it meant to remove and could not, with why.
    pub(crate) failed: Vec<(Removal, String)>,
    /// Folders it could not list, with why (a missing `sessions` folder is not one: nothing to do).
    pub(crate) unlisted: Vec<(String, String)>,
}

/// Apply the rules to the logs folder `dir`: the session files, and the old daily files. `open`
/// names the session files being written (never removed); `now` is the local time, `today_utc` the
/// UTC day since 1970.
pub(crate) fn sweep(
    dir: &Path,
    now: LocalTime,
    today_utc: i64,
    open: &[String],
    rules: &RetentionRules,
) -> Swept {
    let mut swept = Swept::default();
    let sessions = dir.join(SESSIONS_DIR);
    match list_files(&sessions) {
        Ok(files) => {
            for removal in sessions_to_remove(&files, now, open, rules) {
                let path = dir.join(&removal.name);
                remove(&path, removal, &mut swept);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => swept
            .unlisted
            .push((format!("{SESSIONS_DIR}\\"), e.to_string())),
    }
    match list_files(dir) {
        Ok(files) => {
            for removal in legacy_to_remove(&files, today_utc, rules) {
                let path = dir.join(&removal.name);
                remove(&path, removal, &mut swept);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => swept.unlisted.push((".".to_string(), e.to_string())),
    }
    swept
}

fn remove(path: &Path, removal: Removal, swept: &mut Swept) {
    match std::fs::remove_file(path) {
        Ok(()) => swept.removed.push(removal),
        // Gone already (the owner, another sweep): nothing to remove, nothing to say.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => swept.failed.push((removal, e.to_string())),
    }
}

/// The plain files in `dir`, with their sizes. An entry that cannot be read is skipped.
pub(crate) fn list_files(dir: &Path) -> io::Result<Vec<(String, u64)>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() {
            files.push((entry.file_name().to_string_lossy().into_owned(), meta.len()));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: LocalTime = LocalTime::new(2026, 9, 29, 12, 10, 5);

    #[test]
    fn a_session_file_is_named_by_its_local_start_and_its_id() {
        let id = "d1020ebf-00d8-4048-a861-f51293d9135e";
        let name = session_file_name(NOW, id);
        assert_eq!(name, "2026-09-29_12-10-05_d1020ebf.log");
        assert_eq!(session_file_time(&name), Some(NOW));
        assert!(afklink_protocol::diagnostics::is_file_name(&format!(
            "{SESSIONS_DIR}/{name}"
        )));
        // An id that is not a UUID still makes a name of ours.
        assert_eq!(session_file_name(NOW, "s1"), "2026-09-29_12-10-05_s1.log");
        assert_eq!(
            session_file_name(NOW, "../..\\x"),
            "2026-09-29_12-10-05_x.log"
        );
        assert_eq!(
            session_file_name(NOW, "///"),
            "2026-09-29_12-10-05_session.log"
        );
        for other in [
            "system.log",
            "2026-09-29_12-10-05_.log",
            "2026-09-29_12-10-05_d1020ebf0.log",
            "2026-09-29_12-10-05_d1020ebf.txt",
            "2026-13-29_12-10-05_d1020ebf.log",
            "2026-09-29 12-10-05_d1020ebf.log",
            "2026-09-29_12:10:05_d1020ebf.log",
            "afklink-app.2026-09-29.log",
        ] {
            assert_eq!(session_file_time(other), None, "{other}");
        }
        // The names sort as the times do.
        let earlier = session_file_name(LocalTime::new(2026, 9, 29, 9, 59, 59), "ffffffff");
        assert!(earlier < name);
    }

    #[test]
    fn days_from_civil_is_the_inverse_of_civil_from_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2026, 9, 29), 20_725);
        for day in [-1000_i64, -1, 0, 59, 60, 11_016, 20_725, 36_525] {
            let (y, m, d) = crate::fakerinput_setup::civil_from_days(day);
            assert_eq!(days_from_civil(y as i32, m, d), day, "{y}-{m}-{d}");
        }
    }

    #[test]
    fn the_system_log_rotations_are_named_by_number() {
        assert_eq!(system_log_name(0), "system.log");
        assert_eq!(system_log_name(3), "system.3.log");
        assert_eq!(system_log_index("system.log"), Some(0));
        assert_eq!(system_log_index("system.2.log"), Some(2));
        assert_eq!(
            system_log_index("system.4.log"),
            None,
            "past the rotations kept"
        );
        assert_eq!(system_log_index("system.0.log"), None);
        assert_eq!(system_log_index("system.log.1"), None);
    }

    fn file(t: LocalTime, id: &str, bytes: u64) -> (String, u64) {
        (session_file_name(t, id), bytes)
    }

    fn names(removals: &[Removal]) -> Vec<(&str, &str)> {
        removals.iter().map(|r| (r.name.as_str(), r.why)).collect()
    }

    /// Past the age first; then the oldest go while there are too many, then while they weigh too
    /// much. An open file is never removed but still counts.
    #[test]
    fn sessions_go_by_age_then_count_then_bytes_oldest_first() {
        let rules = RetentionRules {
            session_max_age_days: 7,
            session_max_files: 3,
            session_max_bytes: 100,
            legacy_max_age_days: 7,
        };
        let files = vec![
            file(LocalTime::new(2026, 9, 22, 12, 10, 4), "aaaaaaaa", 1), // 7 days and 1 s: out
            file(LocalTime::new(2026, 9, 22, 12, 10, 5), "bbbbbbbb", 1), // exactly 7 days: kept
            file(LocalTime::new(2026, 9, 25, 8, 0, 0), "cccccccc", 10),
            file(LocalTime::new(2026, 9, 26, 8, 0, 0), "dddddddd", 10),
            file(LocalTime::new(2026, 9, 28, 8, 0, 0), "eeeeeeee", 10),
            ("notes.txt".to_string(), 1_000_000),
        ];
        let removals = sessions_to_remove(&files, NOW, &[], &rules);
        assert_eq!(
            names(&removals),
            [
                (
                    "sessions\\2026-09-22_12-10-04_aaaaaaaa.log",
                    "older_than_max_age"
                ),
                ("sessions\\2026-09-22_12-10-05_bbbbbbbb.log", "over_max_files"),
            ],
            "four left after the age, three allowed: the oldest of them goes; notes.txt is not ours"
        );

        // By bytes: 60 + 50 > 100, so the oldest goes — but not the open one, which still counts.
        let files = vec![
            file(LocalTime::new(2026, 9, 28, 8, 0, 0), "open0000", 60),
            file(LocalTime::new(2026, 9, 28, 9, 0, 0), "ffffffff", 30),
            file(LocalTime::new(2026, 9, 29, 9, 0, 0), "gggggggg", 20),
        ];
        let open = vec![session_file_name(
            LocalTime::new(2026, 9, 28, 8, 0, 0),
            "open0000",
        )];
        let removals = sessions_to_remove(&files, NOW, &open, &rules);
        assert_eq!(
            names(&removals),
            [(
                "sessions\\2026-09-28_09-00-00_ffffffff.log",
                "over_max_bytes"
            )]
        );
    }

    #[test]
    fn old_daily_files_go_after_seven_days_by_their_date() {
        let today = days_from_civil(2026, 9, 29);
        let files: Vec<(String, u64)> = [
            "afklink-app.2026-09-29.log",
            "afklink-app.2026-09-22.log", // seven days back: kept
            "afklink-app.2026-09-21.log", // eight: out
            "remoter-app.2026-09-01.log",
            "afklink-watchdog.2026-09-01.log",
            "afklink-app.2026-9-1.log",
            "afklink-app.log",
            "system.log",
        ]
        .iter()
        .map(|n| ((*n).to_string(), 5))
        .collect();
        let removals = legacy_to_remove(&files, today, &RetentionRules::DEFAULT);
        assert_eq!(
            names(&removals),
            [
                ("afklink-app.2026-09-21.log", "old_daily_file"),
                ("remoter-app.2026-09-01.log", "old_daily_file"),
            ]
        );
    }

    /// On disk: what the rules name goes, everything else — the open file, a file not of ours, the
    /// watchdog's and the installer's logs — stays; a folder without `sessions\` is no error.
    #[test]
    fn a_sweep_removes_only_what_the_rules_name() {
        let dir = std::env::temp_dir().join(format!("afklink-retention-{}", uuid::Uuid::new_v4()));
        let sessions = dir.join(SESSIONS_DIR);
        std::fs::create_dir_all(&dir).expect("dir");
        let today = days_from_civil(2026, 9, 29);

        // No sessions folder yet.
        let swept = sweep(&dir, NOW, today, &[], &RetentionRules::DEFAULT);
        assert!(swept.removed.is_empty() && swept.failed.is_empty() && swept.unlisted.is_empty());

        std::fs::create_dir_all(&sessions).expect("sessions dir");
        let old = session_file_name(LocalTime::new(2026, 9, 1, 8, 0, 0), "old00000");
        let open_old = session_file_name(LocalTime::new(2026, 9, 1, 9, 0, 0), "open0000");
        let fresh = session_file_name(LocalTime::new(2026, 9, 29, 8, 0, 0), "fresh000");
        for name in [&old, &open_old, &fresh, &"mine.txt".to_string()] {
            std::fs::write(sessions.join(name), "x\n").expect("write");
        }
        for name in [
            "afklink-app.2026-09-01.log",
            "afklink-app.2026-09-28.log",
            "afklink-watchdog.2026-09-01.log",
            "msiexec-fakerinput-install-20260901-120000Z.log",
            "identity.json",
            "system.log",
        ] {
            std::fs::write(dir.join(name), "x\n").expect("write");
        }
        let swept = sweep(
            &dir,
            NOW,
            today,
            std::slice::from_ref(&open_old),
            &RetentionRules::DEFAULT,
        );
        let mut removed: Vec<&str> = swept.removed.iter().map(|r| r.name.as_str()).collect();
        removed.sort_unstable();
        assert_eq!(
            removed,
            [
                "afklink-app.2026-09-01.log",
                "sessions\\2026-09-01_08-00-00_old00000.log"
            ]
        );
        assert!(swept.failed.is_empty(), "{:?}", swept.failed);
        let mut left: Vec<String> = list_files(&sessions)
            .expect("list")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        left.sort();
        assert_eq!(left, [open_old.clone(), fresh, "mine.txt".to_string()]);
        for name in [
            "afklink-app.2026-09-28.log",
            "afklink-watchdog.2026-09-01.log",
            "msiexec-fakerinput-install-20260901-120000Z.log",
            "identity.json",
            "system.log",
        ] {
            assert!(dir.join(name).exists(), "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
