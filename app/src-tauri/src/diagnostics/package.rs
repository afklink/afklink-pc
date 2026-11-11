//! What a report carries, and how it stays under the size limit.
//!
//! # Contents
//!
//! - `report.json`: how this zip was made: what was left out and why, which session files went in
//!   and which session each is of (`session_files`), the flight recorder's figures, the log level,
//!   the sessions named. The server keeps only the metadata it validated, so what only this zip
//!   needs to say is said here.
//! - `build.json`, `system.json`: made by the caller (`diagnostics`).
//! - `config.json`: the file on disk, only the fields in [`CONFIG_FIELDS`] (none is a secret, and a
//!   field a later build adds is not sent until it is listed there).
//! - `recent-debug.log`: the flight recorder's text, when it holds any.
//! - From the logs folder ([`select`], `log_retention` for the names), in this order:
//!   1. the system log, `system.log`, then its rotations `system.1.log` … `system.3.log`;
//!   2. the update watchdog's logs (`afklink-watchdog.<UTC date>.log`, kept a week), newest first,
//!      and the newest [`INSTALLER_LOGS`] Windows Installer logs of the driver;
//!   3. the newest session's file, `sessions/<local time>_<id>.log`, or, for a report sent from a
//!      journal entry, that session's file ([`select`]'s `first`);
//!   4. an old daily file (`afklink-app.<UTC date>.log`) written in the last day: what a build
//!      before the per-session files logged just before the update;
//!   5. the [`SESSION_FILES`]` − 1` sessions before the newest, newest first.
//!
//! Nothing else is ever read from disk: the logs folder only by those exact name shapes,
//! `config.json` by the path the app loaded it from. `identity.json`, the device's private key, is
//! neither, and cannot be picked up by accident (tested with one in both folders).
//!
//! # The cap
//!
//! The zip stays under the cap it is given ([`Inputs::cap`]): [`CAP`] (24 MiB; the server takes 25)
//! from a PC bound to someone, [`UNBOUND_CAP`] from one bound to nobody (`diagnostics::manual_cap`;
//! after a `413` at the full cap it is packed once more at the small one), [`AUTO_CAP`] for the
//! automatic report. Files go in in the order above and the sessions come last, so they are what
//! gives way, oldest first. How each part is cut: [`build`]. Log files are read a chunk at a time
//! into the compressor; only compressed data is held.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use afklink_protocol::diagnostics::{limits, DiagnosticFile};
use serde_json::{json, Map, Value};

use super::zip::{self, Entry};
use crate::log_retention::{
    legacy_day, session_file_time, system_log_index, LocalTime, SESSIONS_DIR,
};

/// The most the zip may weigh: under the server's 25 MiB (`limits::AGENT_BODY_BYTES`) with room
/// to spare.
pub(crate) const CAP: u64 = 24 * 1024 * 1024;

/// The most a manual report's zip may weigh from a PC bound to nobody: under the server's 2 MiB for
/// such a PC (backend `UNBOUND_AGENT_BODY_BYTES`, `server/src/diagnostics/limits.ts`; 413 above it)
/// with room to spare, as [`CAP`] is under its 25. `diagnostics::manual_cap` chooses it.
pub(crate) const UNBOUND_CAP: u64 = 2 * 1024 * 1024 - 128 * 1024;

/// Of the cap, the share the flight recorder's text (`recent-debug.log`) may take at most: past it,
/// only its newest end. With [`CAP`] it is never reached (16 MiB of lines compress far below 6 MiB);
/// with [`UNBOUND_CAP`] it leaves the rest to the log files.
const RECENT_DEBUG_SHARE: u64 = 4;

/// Session files a report carries: the newest, and the four before it.
pub(crate) const SESSION_FILES: usize = 5;

/// An old daily file (`afklink-app.<date>.log`) goes in when it was written this recently: the
/// last day of a build from before the per-session files, the day it was updated.
const LEGACY_WITHIN_S: u64 = 24 * 3600;

/// Windows Installer logs of the driver a report carries, the newest.
pub(crate) const INSTALLER_LOGS: usize = 3;

/// The most of one log file ever read: past it, only its end. Keeps a day logged at `trace` (up to
/// gigabytes) from taking seconds per hundred megabytes to compress.
const MAX_RAW_READ: u64 = 128 * 1024 * 1024;

/// Room kept for `report.json`, written last.
const REPORT_RESERVE: u64 = 64 * 1024;

/// Less room than this left for a file's end, and the file is left out instead.
const MIN_TAIL: u64 = 64 * 1024;

/// Tries at cutting a file to fit.
const CUT_TRIES: u32 = 4;

/// How much of a session file is read for the session id in its first line.
const HEADER_READ: u64 = 4096;

/// config.json's fields a report carries. Anything else in the file is left out, and named in
/// `report.json`. The game's settings too, so a report says whether «Только игра» or the game
/// helper was on: a switch that is off is not in the file at all, as config.json writes it —
/// absent is off. The paths in them go with the account's folder masked ([`CONFIG_PATHS`]).
pub(crate) const CONFIG_FIELDS: [&str; 15] = [
    "device_id",
    "server_url",
    "name",
    "bot_username",
    "miniapp_short_name",
    "lang",
    "autostart",
    "log_level",
    "auto_update",
    "game_only",
    "game_only_for_guests",
    "game",
    "game_helper",
    "game_launch_exe",
    "game_launch_learned",
];

/// config.json's fields of [`CONFIG_FIELDS`] that hold a path on this PC — the game's window exe
/// and its launch exe — as `field` or `field.inner`: the folder named after the Windows account in
/// them is masked ([`mask_user_folder`]), as `system.json` names no user either; where the game
/// lies stays, for what the paths are needed for.
const CONFIG_PATHS: [&str; 3] = ["game.exe_path", "game_launch_exe", "game_launch_learned"];

/// A config.json larger than this is not read (hand-edited beyond recognition): the app's config in
/// memory goes instead.
const CONFIG_MAX_BYTES: u64 = 1024 * 1024;

/// Which of the logs folder's files a log is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogKind {
    /// `system.log` and its rotations `system.<n>.log`.
    System,
    /// `afklink-watchdog.<YYYY-MM-DD>.log`.
    Watchdog,
    /// `msiexec-fakerinput-<operation>-<YYYYMMDD-HHMMSSZ>.log`.
    Installer,
    /// `sessions/<YYYY-MM-DD>_<HH-MM-SS>_<id>.log`.
    Session,
    /// `afklink-app.<YYYY-MM-DD>.log`, the daily file of a build before the per-session files.
    LegacyApp,
}

impl LogKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Watchdog => "watchdog",
            Self::Installer => "installer",
            Self::Session => "session",
            Self::LegacyApp => "legacy_app",
        }
    }
}

/// How much of the room a file that does not fit whole may keep of its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    /// None: whole, or left out.
    No,
    /// At most half the room the log files have: `system.log`.
    HalfTheRoom,
    /// Whatever is left: the newest session's file.
    TheRest,
}

/// A log file a report may carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidate {
    /// Its name in the zip, and its path under the logs folder with `/` between the parts:
    /// `system.log`, `sessions/2026-09-29_12-10-05_d1020ebf.log`.
    pub(crate) name: String,
    pub(crate) kind: LogKind,
    cut: Cut,
    /// When it does not fit, the files after it of its kind are left out unread: the older
    /// rotations of the system log, the older sessions.
    older_follow: bool,
}

/// The logs folder as [`select`] sees it.
#[derive(Debug, Default)]
pub(crate) struct Listing {
    /// Its files: the name, and when each was last written (Unix seconds) when that could be read.
    pub(crate) files: Vec<(String, Option<u64>)>,
    /// The names of the files in its `sessions` folder.
    pub(crate) sessions: Vec<String>,
}

/// The log files in `listing` a report carries, in the order they are packed (the module docs):
/// what is dropped first when the room runs out is last. `now_s` is the PC's clock, Unix seconds.
///
/// By exact name shape only (`log_retention`, `fakerinput_setup::msi_log_stamp`): the system log
/// and its rotations; every watchdog log; the newest [`INSTALLER_LOGS`] installer logs whatever
/// their age (a driver problem goes back to its installation); the newest [`SESSION_FILES`]
/// sessions' files; an old daily file written in the last day. Anything else — `identity.json`
/// included, the old `remoter-app.*` logs, a file someone put there — is not a log of ours.
///
/// `first`: the session the report is about («Отправить логи» on a journal entry). Its file, found
/// by the id's first eight characters in its name, takes the newest's place — whole, or its end —
/// and the newest others follow, [`SESSION_FILES`] in all. Not found (its log was not written, or
/// is gone), the usual order, said at `debug`.
pub(crate) fn select(listing: &Listing, now_s: u64, first: Option<&str>) -> Vec<Candidate> {
    let candidate = |name: String, kind, cut, older_follow| Candidate {
        name,
        kind,
        cut,
        older_follow,
    };
    let mut system: Vec<(u32, &str)> = listing
        .files
        .iter()
        .filter_map(|(name, _)| Some((system_log_index(name)?, name.as_str())))
        .collect();
    system.sort_unstable();
    let mut watchdog: Vec<(String, &str)> = listing
        .files
        .iter()
        .filter_map(|(name, _)| Some((dated(name, "afklink-watchdog.")?, name.as_str())))
        .collect();
    watchdog.sort_unstable_by(|a, b| b.cmp(a));
    let mut installers: Vec<(&str, &str)> = listing
        .files
        .iter()
        .filter_map(|(name, _)| {
            Some((crate::fakerinput_setup::msi_log_stamp(name)?, name.as_str()))
        })
        .collect();
    // Newest first by the time in the name; the name breaks a tie within one second.
    installers.sort_unstable_by(|a, b| b.cmp(a));
    let today = i64::try_from(now_s / 86_400).unwrap_or(i64::MAX);
    let mut legacy: Vec<&str> = listing
        .files
        .iter()
        .filter(|(name, modified)| {
            name.starts_with("afklink-app.")
                && legacy_day(name).is_some_and(|day| match modified {
                    // A clock set back puts the write in the future: that is recent too.
                    Some(at) => now_s.saturating_sub(*at) <= LEGACY_WITHIN_S,
                    None => day >= today - 1,
                })
        })
        .map(|(name, _)| name.as_str())
        .collect();
    legacy.sort_unstable_by(|a, b| b.cmp(a));
    let mut sessions: Vec<(LocalTime, &str)> = listing
        .sessions
        .iter()
        .filter_map(|name| Some((session_file_time(name)?, name.as_str())))
        .collect();
    sessions.sort_unstable_by(|a, b| b.cmp(a));
    if let Some(id) = first {
        let suffix = format!("_{}.log", crate::log_retention::short_id(id));
        match sessions
            .iter()
            .position(|(_, name)| name.ends_with(&suffix))
        {
            Some(index) => {
                let chosen = sessions.remove(index);
                tracing::debug!(
                    file = chosen.1,
                    was_at = index,
                    "diagnostics: the session asked for goes first among the sessions"
                );
                sessions.insert(0, chosen);
            }
            None => tracing::debug!(
                session = id,
                "diagnostics: no log file for the session asked for (not written, or gone); the \
                 newest sessions go in as usual"
            ),
        }
    }
    sessions.truncate(SESSION_FILES);

    let mut chosen = Vec::new();
    for (index, name) in system {
        let cut = if index == 0 {
            Cut::HalfTheRoom
        } else {
            Cut::No
        };
        chosen.push(candidate(name.to_string(), LogKind::System, cut, true));
    }
    for (_, name) in watchdog {
        chosen.push(candidate(
            name.to_string(),
            LogKind::Watchdog,
            Cut::No,
            false,
        ));
    }
    for (_, name) in installers.into_iter().take(INSTALLER_LOGS) {
        chosen.push(candidate(
            name.to_string(),
            LogKind::Installer,
            Cut::No,
            false,
        ));
    }
    let session = |name: &str, cut| {
        candidate(
            format!("{SESSIONS_DIR}/{name}"),
            LogKind::Session,
            cut,
            true,
        )
    };
    let mut sessions = sessions.into_iter();
    if let Some((_, newest)) = sessions.next() {
        chosen.push(session(newest, Cut::TheRest));
    }
    for name in legacy {
        chosen.push(candidate(
            name.to_string(),
            LogKind::LegacyApp,
            Cut::No,
            false,
        ));
    }
    for (_, name) in sessions {
        chosen.push(session(name, Cut::No));
    }
    chosen
}

/// The `YYYY-MM-DD` of `<prefix><YYYY-MM-DD>.log`, or `None` for any other name.
fn dated(name: &str, prefix: &str) -> Option<String> {
    let date = name.strip_prefix(prefix)?.strip_suffix(".log")?;
    let shape_ok = date.len() == 10
        && date.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            _ => b.is_ascii_digit(),
        });
    shape_ok.then(|| date.to_string())
}

/// `YYYY-MM-DD` of a day counted from 1970-01-01.
pub(crate) fn date_of_day(day: i64) -> String {
    let (y, m, d) = crate::fakerinput_setup::civil_from_days(day);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `YYYY-MM-DDTHH:MM:SSZ` of a Unix time.
pub(crate) fn utc_timestamp(unix_s: u64) -> String {
    let day = i64::try_from(unix_s / 86_400).unwrap_or(i64::MAX);
    let rem = unix_s % 86_400;
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        date_of_day(day),
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Where config.json comes from.
#[derive(Debug, Clone)]
pub(crate) struct ConfigSource {
    /// The file the app loaded; `None` when it has none.
    pub(crate) path: Option<PathBuf>,
    /// The app's config in memory, when the file cannot be read.
    pub(crate) in_memory: Value,
}

/// Everything a report is packed from, gathered by the caller.
#[derive(Debug)]
pub(crate) struct Inputs {
    /// `%APPDATA%\AFKLink\logs`; `None` when it cannot be had.
    pub(crate) logs_dir: Option<PathBuf>,
    pub(crate) config: ConfigSource,
    /// Made by the caller, in the order they go in: `build.json`, `system.json`.
    pub(crate) generated: Vec<(String, Vec<u8>)>,
    /// The flight recorder's text; `None` or empty when it holds nothing.
    pub(crate) recent_debug: Option<Vec<u8>>,
    /// The PC's clock, Unix ms: the report's time, and what an old daily file has to be newer than.
    pub(crate) now_unix_ms: u64,
    pub(crate) cap: u64,
    /// More for `report.json`, merged in at its top level (the recorder, the log level, sessions).
    pub(crate) about: Map<String, Value>,
    /// The session the report is about, whose file goes first ([`select`]); `None` for a report
    /// from Settings.
    pub(crate) first_session: Option<String>,
}

/// A file left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dropped {
    pub(crate) name: String,
    pub(crate) bytes: u64,
    pub(crate) why: &'static str,
}

/// The packed report.
#[derive(Debug)]
pub(crate) struct Package {
    pub(crate) zip: Vec<u8>,
    /// What is in it, in order, for the metadata.
    pub(crate) files: Vec<DiagnosticFile>,
    pub(crate) dropped: Vec<Dropped>,
    /// Log files that could not be read (locked, gone), with why.
    pub(crate) unreadable: Vec<(String, String)>,
    /// Bytes of all entries before compression.
    pub(crate) raw_bytes: u64,
}

/// Pack the report. Every decision is logged at `debug`, the result at `info`; a file that cannot
/// be read is left out and named, never the end of the report.
///
/// The generated entries and the flight recorder always go in, the recorder cut to its newest end
/// at a quarter of the cap ([`RECENT_DEBUG_SHARE`]; never reached at [`CAP`]). The log files go in
/// in [`select`]'s order, each compressed before it is counted. A session's file that does not fit
/// is left out with every older one. The newest session's file, alone too big (a session at
/// `trace`), keeps its end instead (`truncated`), cut where a line starts; so does `system.log`, in
/// at most half the room. A system log rotation that does not fit is left out with the older ones.
/// The system log is bounded (`log_retention`: 8 MiB a file) and the other logs are small, so at
/// [`CAP`] everything but the sessions always goes in.
pub(crate) fn build(inputs: Inputs) -> io::Result<Package> {
    let started = Instant::now();
    let now_s = inputs.now_unix_ms / 1000;
    let mut entries: Vec<Entry> = Vec::new();

    for (name, bytes) in &inputs.generated {
        entries.push(Entry::deflate_bytes(name, bytes, now_s));
    }
    let (config, config_about) = config_json(&inputs.config);
    entries.push(Entry::deflate_bytes("config.json", &config, now_s));
    match inputs.recent_debug.as_deref() {
        Some(text) if !text.is_empty() => {
            let limit = inputs.cap / RECENT_DEBUG_SHARE;
            entries.push(deflate_bytes_end("recent-debug.log", text, limit, now_s));
        }
        _ => tracing::debug!("diagnostics: no recent-debug.log, the flight recorder holds nothing"),
    }
    let fixed: u64 = entries.iter().map(Entry::cost).sum();
    let mut budget = inputs
        .cap
        .saturating_sub(zip::END_RECORD + REPORT_RESERVE + fixed);
    tracing::debug!(
        entries = entries.len(),
        fixed_bytes = fixed,
        budget,
        cap = inputs.cap,
        "diagnostics: the generated entries and the flight recorder are in; room left for logs"
    );

    let mut dropped = Vec::new();
    let mut unreadable = Vec::new();
    let mut session_files = Vec::new();
    let candidates = match &inputs.logs_dir {
        Some(dir) => list_logs(dir, now_s, inputs.first_session.as_deref()),
        None => {
            tracing::debug!("diagnostics: no logs folder; the report carries no log files");
            Vec::new()
        }
    };
    // The room the log files had at the start: what `system.log` may keep at most half of.
    let room = budget;
    // Kinds whose next files are left out unread: one of them did not fit (an older rotation, an
    // older session).
    let mut left_out: Vec<LogKind> = Vec::new();
    for c in candidates {
        let Some(dir) = inputs.logs_dir.as_deref() else {
            break;
        };
        let path = c
            .name
            .split('/')
            .fold(dir.to_path_buf(), |p, part| p.join(part));
        let session_id = (c.kind == LogKind::Session)
            .then(|| session_id_in(&path))
            .flatten();
        let mut session_file = |packed: &str| {
            if c.kind == LogKind::Session {
                session_files.push(json!({
                    "name": c.name,
                    "session_id": session_id,
                    "packed": packed,
                }));
            }
        };
        if c.older_follow && left_out.contains(&c.kind) {
            let bytes = std::fs::metadata(&path).map_or(0, |m| m.len());
            tracing::debug!(
                file = %c.name,
                kind = c.kind.as_str(),
                bytes,
                "diagnostics: left out, older than a file of its kind that did not fit"
            );
            session_file("left_out");
            dropped.push(Dropped {
                name: c.name,
                bytes,
                why: "older_than_a_file_that_did_not_fit",
            });
            continue;
        }
        // Past the metadata's limit on files (never, with the files this chooses: 26 at most).
        if entries.len() + 1 >= limits::FILES {
            let bytes = std::fs::metadata(&path).map_or(0, |m| m.len());
            tracing::warn!(
                file = %c.name,
                files = entries.len() + 1,
                limit = limits::FILES,
                "diagnostics: left out, the report holds as many files as the server takes"
            );
            session_file("left_out");
            dropped.push(Dropped {
                name: c.name,
                bytes,
                why: "too_many_files",
            });
            continue;
        }
        let cut_to = match c.cut {
            Cut::No => None,
            Cut::HalfTheRoom => Some(budget.min(room / 2)),
            Cut::TheRest => Some(budget),
        };
        match pack_file(&path, &c.name, budget, cut_to) {
            Ok(Packed::In(entry)) => {
                tracing::debug!(
                    file = %c.name,
                    kind = c.kind.as_str(),
                    raw = entry.raw_len,
                    compressed = entry.deflated.len(),
                    truncated_from = ?entry.truncated_from,
                    budget_before = budget,
                    session = session_id.as_deref().unwrap_or("-"),
                    "diagnostics: log file in"
                );
                session_file(if entry.truncated_from.is_some() {
                    "end"
                } else {
                    "whole"
                });
                budget = budget.saturating_sub(entry.cost());
                entries.push(entry);
            }
            Ok(Packed::TooBig { bytes }) => {
                tracing::debug!(
                    file = %c.name,
                    kind = c.kind.as_str(),
                    bytes,
                    budget,
                    older_follow = c.older_follow,
                    "diagnostics: log file does not fit; left out{}",
                    if c.older_follow {
                        ", with the older files of its kind"
                    } else {
                        ""
                    }
                );
                session_file("left_out");
                dropped.push(Dropped {
                    name: c.name,
                    bytes,
                    why: "no_room",
                });
                if c.older_follow {
                    left_out.push(c.kind);
                }
            }
            Err(e) => {
                tracing::warn!(file = %c.name, "diagnostics: log file not read: {e}");
                session_file("unreadable");
                unreadable.push((c.name, e.to_string()));
            }
        }
    }

    let files: Vec<DiagnosticFile> = entries.iter().map(file_of).collect();
    let report = report_json(
        &inputs,
        &entries,
        &dropped,
        &unreadable,
        config_about,
        session_files,
        now_s,
    );
    let report = serde_json::to_vec_pretty(&report).unwrap_or_else(|e| {
        tracing::warn!("diagnostics: report.json not serialized: {e}");
        b"{}".to_vec()
    });
    entries.insert(0, Entry::deflate_bytes("report.json", &report, now_s));
    let mut all_files = vec![file_of(&entries[0])];
    all_files.extend(files);
    let zip = zip::write(&entries)?;
    let raw_bytes = entries.iter().map(|e| e.raw_len).sum();
    tracing::info!(
        files = entries.len(),
        zip_bytes = zip.len(),
        raw_bytes,
        dropped = dropped.len(),
        truncated = entries
            .iter()
            .filter(|e| e.truncated_from.is_some())
            .count(),
        unreadable = unreadable.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "diagnostics: report packed"
    );
    Ok(Package {
        zip,
        files: all_files,
        dropped,
        unreadable,
        raw_bytes,
    })
}

/// Where the system log stood when this process started, before its first line: where the previous
/// process stopped writing. An automatic report after a crash ends its tail there ([`build_tail`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogStart {
    /// `system.log`'s length then.
    pub(crate) len: u64,
    /// Its last bytes then (at most [`LogStart::PRINT`]): found again at the same place in the file
    /// that holds them now — `system.log`, or a rotation, when this run's lines rotated it.
    pub(crate) last: Vec<u8>,
}

impl LogStart {
    /// How many of the last bytes are kept to find the place again.
    pub(crate) const PRINT: u64 = 64;

    /// `path`'s length and last bytes now; a file that is not there is an empty one.
    pub(crate) fn read(path: &Path) -> io::Result<Self> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self {
                    len: 0,
                    last: Vec::new(),
                })
            }
            Err(e) => return Err(e),
        };
        let len = file.metadata()?.len();
        let last = read_range(&mut file, len.saturating_sub(Self::PRINT), len)?;
        Ok(Self { len, last })
    }

    /// Whether `file` holds this start's last bytes right before [`Self::len`].
    fn found_in(&self, file: &mut File, file_len: u64) -> io::Result<bool> {
        if file_len < self.len {
            return Ok(false);
        }
        let from = self.len.saturating_sub(self.last.len() as u64);
        Ok(read_range(file, from, self.len)? == self.last)
    }
}

/// Bytes `from..to` of `file`, in memory (an automatic report's pieces are a few MiB at most).
fn read_range(file: &mut File, from: u64, to: u64) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(from))?;
    let mut out = Vec::new();
    Read::by_ref(file)
        .take(to.saturating_sub(from))
        .read_to_end(&mut out)?;
    Ok(out)
}

/// An automatic report's zip as sent: the server refuses past it (`agentAutoBodyBytes`).
pub(crate) const AUTO_CAP: u64 = limits::AGENT_AUTO_BODY_BYTES;

/// The most of the system log an automatic report reads, before compression: «the last minutes».
pub(crate) const AUTO_SYSTEM_RAW: u64 = 3 * 1024 * 1024;

/// The most of the failed session's file it reads.
pub(crate) const AUTO_SESSION_RAW: u64 = 2 * 1024 * 1024;

/// After a crash, the most of this run's first lines it reads (after where the last run stopped).
pub(crate) const AUTO_THIS_RUN_RAW: u64 = 256 * 1024;

/// How far back before the event an automatic report's lines go — «последние минуты»: older lines
/// are left out whatever room is left. After a crash, back from the previous run's last line.
pub(crate) const AUTO_LOOKBACK_MS: u64 = 30 * 60_000;

/// What marks a line that names a key (`afklink_input::KEY_NAMES_TARGET` as the log writes a
/// target): left out of an automatic report (the privacy policy: «нажатых клавиш там нет»).
const KEY_LINE_MARK: &str = " afklink_input::key_names:";

/// Tries at shrinking the tails until the zip fits [`AUTO_CAP`].
const TAIL_TRIES: u32 = 8;

/// A tail given less than this to keep is left out instead.
const MIN_PIECE_RAW: u64 = 1024;

/// Room kept beside the measured `report.json`: it grows a little between tries.
const TAIL_SLACK: u64 = 1024;

/// What an automatic report («автоотчёт») is packed from, gathered by the caller
/// (`diagnostics::auto`).
#[derive(Debug)]
pub(crate) struct TailInputs {
    /// `%APPDATA%\AFKLink\logs`; `None` when it cannot be had.
    pub(crate) logs_dir: Option<PathBuf>,
    pub(crate) config: ConfigSource,
    /// Made by the caller: `build.json`.
    pub(crate) generated: Vec<(String, Vec<u8>)>,
    /// More for `report.json` (the trigger, the merged and skipped triggers, the log level).
    pub(crate) about: Map<String, Value>,
    pub(crate) now_unix_ms: u64,
    /// When the report's first trigger happened, Unix ms: lines from [`AUTO_LOOKBACK_MS`] before it
    /// go in, none older.
    pub(crate) event_unix_ms: u64,
    /// The zip's limit: [`AUTO_CAP`].
    pub(crate) cap: u64,
    /// The system log's tail, before compression, at most ([`AUTO_SYSTEM_RAW`]).
    pub(crate) system_raw: u64,
    /// The session whose file's tail goes in (`session_failed`), found by its id.
    pub(crate) session: Option<String>,
    pub(crate) session_raw: u64,
    /// After a crash: where the previous process stopped writing. The system log's tail ends there,
    /// and this run's first lines (at most `this_run_raw`) follow as their own entry.
    pub(crate) previous_end: Option<LogStart>,
    pub(crate) this_run_raw: u64,
}

/// Which part of a file a piece of an automatic report is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The last bytes before `to`, from a line's start.
    Tail { to: u64 },
    /// The first bytes from `from` (a line's start), up to `end` at most.
    Head { from: u64, end: u64 },
}

/// One log piece of an automatic report.
#[derive(Debug, Clone)]
struct Piece {
    /// Its name in the zip.
    name: String,
    /// The file it is read from, under the logs folder, `/` between the parts.
    source: String,
    part: Part,
    /// What it may keep before compression, shrunk until the zip fits.
    raw: u64,
    /// Lines written before this (Unix ms) are left out.
    since_ms: u64,
    /// For `report.json`: what this piece is.
    what: &'static str,
}

/// What became of a piece's lines ([`filter_lines`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LineStats {
    /// Lines kept (with the lines without a time that follow them).
    pub(crate) kept: u64,
    /// Left out: written before the piece's time bound.
    pub(crate) too_old: u64,
    /// Left out: dated after the time of packing (and its slack) — a clock that was set back.
    pub(crate) too_new: u64,
    /// Left out: they name a key ([`KEY_LINE_MARK`], [`names_a_key`]).
    pub(crate) key_lines: u64,
    /// Left out: no time of their own and no line with one above them in the piece.
    pub(crate) orphans: u64,
    /// Lines whose account folder was masked.
    pub(crate) masked: u64,
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` at the start of a log line, as Unix ms; `None` for a line
/// without one (a continuation of the line above).
pub(crate) fn line_time_ms(line: &[u8]) -> Option<u64> {
    let digits = |from: usize, len: usize| -> Option<i64> {
        let part = line.get(from..from + len)?;
        part.iter().try_fold(0i64, |n, b| {
            b.is_ascii_digit().then(|| n * 10 + i64::from(b - b'0'))
        })
    };
    let at = |i: usize, want: u8| line.get(i) == Some(&want);
    if !(at(4, b'-') && at(7, b'-') && at(10, b'T') && at(13, b':') && at(16, b':')) {
        return None;
    }
    let (y, mo, d) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (h, mi, s) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let mut ms = 0i64;
    let mut i = 19;
    if at(i, b'.') {
        i += 1;
        let mut scale = 100;
        while let Some(b) = line.get(i).filter(|b| b.is_ascii_digit()) {
            ms += i64::from(b - b'0') * scale;
            scale /= 10;
            i += 1;
        }
    }
    if !at(i, b'Z') {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    let total = ((days * 24 + h) * 60 + mi) * 60 + s;
    u64::try_from(total * 1000 + ms).ok()
}

/// Days since 1970-01-01 of a civil date (the inverse of `civil_from_days`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The account folder in every path of `line` masked — `C:\Users\Ivan\…`, `C:\\Users\\Ivan\\…` (a
/// path in a `Debug` field), `C:/Users/Ivan/…` — as `<user>`, up to the next slash, quote or the
/// line's end (a name with a space is masked whole); and whether anything was.
pub(crate) fn mask_users_in_line(line: &str) -> (String, bool) {
    let lower = line.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let is_sep = |b: u8| b == b'\\' || b == b'/';
    let mut out = String::with_capacity(line.len());
    let mut from = 0;
    let mut masked = false;
    let mut search = 0;
    while let Some(found) = lower[search..].find("users") {
        let at = search + found;
        search = at + "users".len();
        let before_ok = at > 0 && is_sep(bytes[at - 1]);
        let after = at + "users".len();
        if !before_ok || !bytes.get(after).is_some_and(|b| is_sep(*b)) {
            continue;
        }
        let mut start = after;
        while bytes.get(start).is_some_and(|b| is_sep(*b)) {
            start += 1;
        }
        let end = bytes[start..]
            .iter()
            .position(|b| is_sep(*b) || matches!(b, b'"' | b'\'' | b'\n' | b'\r'))
            .map_or(bytes.len(), |n| start + n);
        if end > start && &line[start..end] != "<user>" {
            out.push_str(&line[from..start]);
            out.push_str("<user>");
            from = end;
            masked = true;
        }
        search = end.max(search);
    }
    out.push_str(&line[from..]);
    (out, masked)
}

/// Whether a word is shaped like a key's name as the viewer sends it (`KeyboardEvent.code`):
/// `KeyA`, `Digit1`, `Numpad7`, `F4`, `ArrowUp`, `AltLeft`, `Escape`, `Enter`, `Space`, `Tab`,
/// `PageUp`, `Semicolon`, `IntlBackslash`, `MediaPlayPause`, `AudioVolumeUp` and the rest of the
/// list. Whole words, case as written — `Alt`, `Key`, `Keyboard`, `F`, `enter` or `space` in lower
/// case are not; a capitalised prose word that is also a key's name (`End`, `Sleep`) is taken for
/// one, which only drops a harmless line.
fn is_key_code_word(word: &str) -> bool {
    let rest = |prefix: &str| word.strip_prefix(prefix);
    let all = |s: &str, f: fn(u8) -> bool| !s.is_empty() && s.bytes().all(f);
    if let Some(r) = rest("Key") {
        return r.len() == 1 && r.bytes().all(|b| b.is_ascii_uppercase());
    }
    if let Some(r) = rest("Digit") {
        return r.len() == 1 && all(r, |b| b.is_ascii_digit());
    }
    if let Some(r) = rest("Numpad") {
        return all(r, |b| b.is_ascii_alphanumeric());
    }
    if let Some(r) = rest("Arrow") {
        return matches!(r, "Up" | "Down" | "Left" | "Right");
    }
    if let Some(r) = rest("F") {
        return (1..=2).contains(&r.len()) && all(r, |b| b.is_ascii_digit());
    }
    if ["Meta", "Alt", "Control", "Shift", "OS"]
        .iter()
        .any(|m| matches!(word.strip_prefix(m), Some("Left" | "Right")))
    {
        return true;
    }
    if let Some(r) = rest("Intl") {
        return all(r, |b| b.is_ascii_alphanumeric());
    }
    if let Some(r) = rest("Lang") {
        return r.len() == 1 && all(r, |b| b.is_ascii_digit());
    }
    // The media, volume, browser and launch keys by their exact names: a bare prefix
    // (`MediaFoundation`) is not one.
    if let Some(r) = rest("Media") {
        return matches!(
            r,
            "PlayPause" | "Stop" | "TrackNext" | "TrackPrevious" | "Select"
        );
    }
    if let Some(r) = rest("AudioVolume") {
        return matches!(r, "Mute" | "Down" | "Up");
    }
    if let Some(r) = rest("Browser") {
        return matches!(
            r,
            "Back" | "Forward" | "Refresh" | "Stop" | "Search" | "Favorites" | "Home"
        );
    }
    if let Some(r) = rest("Launch") {
        return matches!(r, "App1" | "App2" | "Mail" | "MediaPlayer");
    }
    matches!(
        word,
        "Escape"
            | "Backspace"
            | "Enter"
            | "Space"
            | "Tab"
            | "Delete"
            | "Insert"
            | "Home"
            | "End"
            | "PageUp"
            | "PageDown"
            | "CapsLock"
            | "NumLock"
            | "ScrollLock"
            | "PrintScreen"
            | "Pause"
            | "ContextMenu"
            | "Semicolon"
            | "Quote"
            | "Comma"
            | "Period"
            | "Slash"
            | "Backslash"
            | "Backquote"
            | "Minus"
            | "Equal"
            | "BracketLeft"
            | "BracketRight"
            | "Power"
            | "Sleep"
            | "WakeUp"
            | "Fn"
            | "FnLock"
            | "Eject"
            | "Help"
            | "Convert"
            | "NonConvert"
            | "KanaMode"
    )
}

/// Whether a log line names a key by its content — the second line of defence behind the target
/// ([`KEY_LINE_MARK`]): a word shaped like a key's code ([`is_key_code_word`]), or a `combo=`,
/// `hotkey=` or `vk=` field.
pub(crate) fn names_a_key(line: &str) -> bool {
    let field = |name: &str| {
        line.match_indices(name).any(|(at, _)| {
            line[..at]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric())
        })
    };
    if field("combo=") || field("hotkey=") || field("vk=") {
        return true;
    }
    line.split(|c: char| !c.is_ascii_alphanumeric())
        .any(is_key_code_word)
}

/// How far after the time it was packed a line may be dated: a clock set back makes old lines look
/// newer than now, and they are left out.
pub(crate) const FUTURE_SLACK_MS: u64 = 60_000;

/// A piece's lines as an automatic report carries them: only those written from `since_ms` to
/// `until_ms` (a line without a time of its own goes with the line above it), none that names a
/// key — by its target or its content ([`names_a_key`]) — every account folder masked.
pub(crate) fn filter_lines(text: &[u8], since_ms: u64, until_ms: u64) -> (Vec<u8>, LineStats) {
    let mut out = Vec::with_capacity(text.len());
    let mut stats = LineStats::default();
    let mut keep = false;
    let mut seen_head = false;
    for line in text.split_inclusive(|b| *b == b'\n') {
        let names_key = |line: &[u8]| {
            line.windows(KEY_LINE_MARK.len())
                .any(|w| w == KEY_LINE_MARK.as_bytes())
                || names_a_key(&String::from_utf8_lossy(line))
        };
        match line_time_ms(line) {
            Some(at) => {
                seen_head = true;
                keep = if at < since_ms {
                    stats.too_old += 1;
                    false
                } else if at > until_ms {
                    stats.too_new += 1;
                    false
                } else if names_key(line) {
                    stats.key_lines += 1;
                    false
                } else {
                    true
                };
            }
            None if !seen_head => {
                stats.orphans += 1;
                continue;
            }
            // A continuation of a kept line that names a key goes on its own.
            None if keep && names_key(line) => {
                stats.key_lines += 1;
                continue;
            }
            None => {}
        }
        if keep {
            let text = String::from_utf8_lossy(line);
            let (text, masked) = mask_users_in_line(&text);
            stats.kept += 1;
            stats.masked += u64::from(masked);
            out.extend_from_slice(text.as_bytes());
        }
    }
    (out, stats)
}

/// The time of the last line with one in `file` before byte `end` (read back at most 64 KiB).
fn last_line_time(file: &mut File, end: u64) -> io::Result<Option<u64>> {
    let tail = read_range(file, end.saturating_sub(64 * 1024), end)?;
    Ok(tail.split(|b| *b == b'\n').rev().find_map(line_time_ms))
}

/// The pieces of the logs an automatic report carries, from the files as they are now, and notes
/// on the choice for `report.json`. By exact name only: `system.log` and its rotations, and the one
/// session file whose header names `inputs.session`.
fn tail_pieces(dir: &Path, inputs: &TailInputs) -> (Vec<Piece>, Map<String, Value>) {
    use crate::log_retention::{system_log_name, SYSTEM_ROTATIONS};
    let mut notes = Map::new();
    let mut pieces = Vec::new();
    let len_of = |name: &str| std::fs::metadata(dir.join(name)).ok().map(|m| m.len());
    let anchored = inputs.previous_end.as_ref().and_then(|start| {
        let found = (0..=SYSTEM_ROTATIONS).find_map(|n| {
            let name = system_log_name(n);
            let mut file = File::open(dir.join(&name)).ok()?;
            let len = file.metadata().ok()?.len();
            match start.found_in(&mut file, len) {
                Ok(true) => Some((n, len)),
                Ok(false) => None,
                Err(e) => {
                    tracing::debug!(file = %name, "diagnostics: auto: a system log not read for the crash's place: {e}");
                    None
                }
            }
        });
        tracing::debug!(
            previous_len = start.len,
            found_in = ?found.map(|(n, _)| system_log_name(n)),
            "diagnostics: auto: where the previous run stopped writing, looked for in the system logs"
        );
        if found.is_none() {
            notes.insert("crash_place".into(), json!("not_found"));
        }
        found.map(|found| (start.len, found))
    });
    // «The last minutes»: from the event back, at most this far, whatever room is left.
    let event_since = inputs
        .event_unix_ms
        .min(inputs.now_unix_ms)
        .saturating_sub(AUTO_LOOKBACK_MS);
    match anchored {
        Some((end, (n, len))) => {
            let source = system_log_name(n);
            // Back from the previous run's last line (a crash's time is when it was last seen).
            let last = File::open(dir.join(&source))
                .and_then(|mut file| last_line_time(&mut file, end))
                .unwrap_or_else(|e| {
                    tracing::debug!(file = %source, "diagnostics: auto: the previous run's last line not read: {e}");
                    None
                });
            let since = last.map_or(event_since, |at| at.saturating_sub(AUTO_LOOKBACK_MS));
            tracing::debug!(
                last_line_ms = ?last,
                since_ms = since,
                "diagnostics: auto: a crash's lines go back from the previous run's last line"
            );
            notes.insert(
                "crash_place".into(),
                json!({ "file": source, "offset": end, "last_line_ms": last }),
            );
            pieces.push(Piece {
                name: "system.previous-run.log".into(),
                source: source.clone(),
                part: Part::Tail { to: end },
                raw: inputs.system_raw,
                since_ms: since,
                what: "previous_run_end",
            });
            if end < inputs.system_raw && n < SYSTEM_ROTATIONS {
                let older = system_log_name(n + 1);
                if let Some(older_len) = len_of(&older) {
                    pieces.push(Piece {
                        name: "system.previous-run.older.log".into(),
                        source: older,
                        part: Part::Tail { to: older_len },
                        raw: inputs.system_raw - end,
                        since_ms: since,
                        what: "previous_run_older",
                    });
                }
            }
            // This run's first lines: after the place in its file — or, when this run's first
            // line rotated it (nothing after the place), from the start of the newer file.
            let this_run = if len > end || n == 0 {
                Some((source, end, len))
            } else {
                let newer = system_log_name(n - 1);
                len_of(&newer).map(|newer_len| (newer, 0, newer_len))
            };
            if let Some((source, from, end)) = this_run {
                pieces.push(Piece {
                    name: "system.this-run.log".into(),
                    source,
                    part: Part::Head { from, end },
                    raw: inputs.this_run_raw,
                    since_ms: since,
                    what: "this_run_start",
                });
            }
        }
        None => {
            let current = system_log_name(0);
            let len = len_of(&current).unwrap_or(0);
            if len > 0 {
                pieces.push(Piece {
                    name: current.clone(),
                    source: current,
                    part: Part::Tail { to: len },
                    raw: inputs.system_raw,
                    since_ms: event_since,
                    what: "tail",
                });
            }
            // Just rotated: the rest of the tail is in the newest rotation.
            if len < inputs.system_raw {
                let older = system_log_name(1);
                if let Some(older_len) = len_of(&older) {
                    pieces.push(Piece {
                        name: older.clone(),
                        source: older,
                        part: Part::Tail { to: older_len },
                        raw: inputs.system_raw - len,
                        since_ms: event_since,
                        what: "older_tail",
                    });
                }
            }
        }
    }
    if let Some(id) = inputs.session.as_deref() {
        match session_file_of(dir, id) {
            Some((name, len)) => pieces.push(Piece {
                name: format!("{SESSIONS_DIR}/{name}"),
                source: format!("{SESSIONS_DIR}/{name}"),
                part: Part::Tail { to: len },
                raw: inputs.session_raw,
                since_ms: event_since,
                what: "session_tail",
            }),
            None => {
                tracing::debug!(
                    session = id,
                    "diagnostics: auto: no log file of the failed session (not written, gone, or its \
                     header names another); none goes in"
                );
                notes.insert("session_file".into(), json!("not_found"));
            }
        }
    }
    (pieces, notes)
}

/// The file in the sessions folder whose name ends in `id`'s short form and whose header names `id`
/// exactly — the newest of them — and its length.
fn session_file_of(dir: &Path, id: &str) -> Option<(String, u64)> {
    let suffix = format!("_{}.log", crate::log_retention::short_id(id));
    let sessions = dir.join(SESSIONS_DIR);
    let mut found: Vec<(LocalTime, String, u64)> = list_dir(&sessions, "the sessions folder")
        .into_iter()
        .filter(|(name, _)| name.ends_with(&suffix))
        .filter_map(|(name, meta)| Some((session_file_time(&name)?, name, meta.len())))
        .filter(|(_, name, _)| session_id_in(&sessions.join(name)).as_deref() == Some(id))
        .collect();
    found.sort_unstable_by(|a, b| b.cmp(a));
    found.into_iter().next().map(|(_, name, len)| (name, len))
}

/// One piece read as planned, its lines filtered ([`filter_lines`]) and compressed; `Ok(None)` when
/// nothing of it is left.
fn pack_piece(dir: &Path, piece: &Piece, until_ms: u64) -> io::Result<Option<(Entry, LineStats)>> {
    let path = piece
        .source
        .split('/')
        .fold(dir.to_path_buf(), |p, part| p.join(part));
    let mut file = File::open(&path)?;
    let meta = file.metadata()?;
    let file_len = meta.len();
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or_else(now_unix_s, |d| d.as_secs());
    let raw = match piece.part {
        Part::Tail { to } => {
            let to = to.min(file_len);
            let from = to.saturating_sub(piece.raw);
            let mut bytes = read_range(&mut file, from, to)?;
            if from > 0 {
                // From the first whole line: the rest of the one the cut fell in goes.
                let cut = bytes
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |n| n + 1);
                bytes.drain(..cut);
            }
            bytes
        }
        Part::Head { from, end } => {
            let to = end.min(file_len).min(from.saturating_add(piece.raw));
            read_range(&mut file, from, to)?
        }
    };
    let read = raw.len();
    let (text, stats) = filter_lines(&raw, piece.since_ms, until_ms);
    tracing::debug!(
        file = %piece.name,
        read,
        kept_bytes = text.len(),
        kept = stats.kept,
        too_old = stats.too_old,
        too_new = stats.too_new,
        key_lines = stats.key_lines,
        orphans = stats.orphans,
        masked = stats.masked,
        since_ms = piece.since_ms,
        "diagnostics: auto: a piece's lines filtered (time bound, key lines, account folder)"
    );
    if text.is_empty() {
        return Ok(None);
    }
    let mut entry = Entry::deflate_bytes(&piece.name, &text, modified);
    // Any part of a file but the whole of it is said so (`truncated` in the metadata).
    if entry.raw_len < file_len {
        entry.truncated_from = Some(file_len);
    }
    Ok(Some((entry, stats)))
}

/// Pack an automatic report: `build.json`, `config.json` (the same list and masking as a report the
/// owner sends), the system log's tail — after a crash, the tail where the previous run stopped
/// and this run's first lines — the failed session's file's tail, and `report.json`. Nothing else:
/// no flight recorder, no `system.json`, no other session, no installer or watchdog log.
///
/// The tails shrink until the zip fits `inputs.cap` (at most [`TAIL_TRIES`] tries); a zip that
/// still does not fit is an error, never a bigger zip.
pub(crate) fn build_tail(inputs: TailInputs) -> io::Result<Package> {
    let started = Instant::now();
    let now_s = inputs.now_unix_ms / 1000;
    let mut fixed: Vec<Entry> = inputs
        .generated
        .iter()
        .map(|(name, bytes)| Entry::deflate_bytes(name, bytes, now_s))
        .collect();
    let (config, config_about) = config_json(&inputs.config);
    fixed.push(Entry::deflate_bytes("config.json", &config, now_s));
    let fixed_cost: u64 = fixed.iter().map(Entry::cost).sum();
    let (mut pieces, notes) = match inputs.logs_dir.as_deref() {
        Some(dir) => tail_pieces(dir, &inputs),
        None => {
            tracing::debug!("diagnostics: auto: no logs folder; the report carries no log");
            (Vec::new(), Map::new())
        }
    };
    tracing::debug!(
        pieces = ?pieces.iter().map(|p| (p.name.as_str(), p.what, p.raw)).collect::<Vec<_>>(),
        fixed_bytes = fixed_cost,
        cap = inputs.cap,
        "diagnostics: auto: what the report reads, and how much of each before compression"
    );
    for attempt in 1..=TAIL_TRIES {
        let mut logs: Vec<(Entry, &Piece, LineStats)> = Vec::new();
        let mut dropped = Vec::new();
        let mut unreadable = Vec::new();
        for piece in &pieces {
            if piece.raw < MIN_PIECE_RAW {
                dropped.push(Dropped {
                    name: piece.name.clone(),
                    bytes: 0,
                    why: "no_room",
                });
                continue;
            }
            let Some(dir) = inputs.logs_dir.as_deref() else {
                break;
            };
            match pack_piece(
                dir,
                piece,
                inputs.now_unix_ms.saturating_add(FUTURE_SLACK_MS),
            ) {
                Ok(Some((entry, stats))) => logs.push((entry, piece, stats)),
                Ok(None) => {
                    tracing::debug!(file = %piece.name, "diagnostics: auto: nothing of a piece is left, left out")
                }
                Err(e) => {
                    tracing::warn!(file = %piece.name, "diagnostics: auto: a log not read: {e}");
                    unreadable.push((piece.name.clone(), e.to_string()));
                }
            }
        }
        let logs_cost: u64 = logs.iter().map(|(e, _, _)| e.cost()).sum();
        let report = tail_report_json(
            &inputs,
            &fixed,
            &logs,
            &dropped,
            &unreadable,
            &config_about,
            &notes,
            attempt,
        );
        let report = serde_json::to_vec_pretty(&report).unwrap_or_else(|e| {
            tracing::warn!("diagnostics: auto: report.json not serialized: {e}");
            b"{}".to_vec()
        });
        let report = Entry::deflate_bytes("report.json", &report, now_s);
        let total = zip::END_RECORD + report.cost() + fixed_cost + logs_cost;
        tracing::debug!(
            attempt,
            total,
            cap = inputs.cap,
            logs_compressed = logs_cost,
            logs_raw = logs.iter().map(|(e, _, _)| e.raw_len).sum::<u64>(),
            per_file = ?logs.iter().map(|(e, _, _)| (e.name.as_str(), e.raw_len, e.deflated.len())).collect::<Vec<_>>(),
            "diagnostics: auto: packed once; the zip's size against its cap"
        );
        if total <= inputs.cap {
            let mut entries = vec![report];
            entries.extend(fixed);
            entries.extend(logs.into_iter().map(|(e, _, _)| e));
            let zip = zip::write(&entries)?;
            if zip.len() as u64 > inputs.cap {
                return Err(io::Error::other(format!(
                    "the automatic report came to {} bytes, over its cap of {}",
                    zip.len(),
                    inputs.cap
                )));
            }
            let raw_bytes = entries.iter().map(|e| e.raw_len).sum();
            tracing::info!(
                files = entries.len(),
                zip_bytes = zip.len(),
                raw_bytes,
                attempts = attempt,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "diagnostics: auto: report packed"
            );
            return Ok(Package {
                files: entries.iter().map(file_of).collect(),
                zip,
                dropped,
                unreadable,
                raw_bytes,
            });
        }
        // Too big: every tail shrinks by what the compression seen says fits, with a margin —
        // halved again on the later tries, so this ends.
        let room = inputs
            .cap
            .saturating_sub(zip::END_RECORD + report.cost() + fixed_cost + TAIL_SLACK);
        if logs_cost == 0 {
            break;
        }
        let mut factor = (room as f64 / logs_cost as f64) * 0.9;
        if attempt >= TAIL_TRIES / 2 {
            factor *= 0.5;
        }
        let factor = factor.clamp(0.0, 0.95);
        for piece in &mut pieces {
            piece.raw = (piece.raw as f64 * factor) as u64;
        }
        tracing::debug!(
            attempt,
            factor,
            room,
            "diagnostics: auto: over the cap; every tail shrinks and the report is packed again"
        );
    }
    Err(io::Error::other(format!(
        "the automatic report does not fit {} bytes after {TAIL_TRIES} tries",
        inputs.cap
    )))
}

/// `report.json` of an automatic report.
#[allow(clippy::too_many_arguments)]
fn tail_report_json(
    inputs: &TailInputs,
    fixed: &[Entry],
    logs: &[(Entry, &Piece, LineStats)],
    dropped: &[Dropped],
    unreadable: &[(String, String)],
    config: &Value,
    notes: &Map<String, Value>,
    attempt: u32,
) -> Value {
    let mut report = Map::new();
    report.insert("format".into(), json!(1));
    report.insert("kind".into(), json!("auto"));
    report.insert(
        "packed_at".into(),
        json!(utc_timestamp(inputs.now_unix_ms / 1000)),
    );
    report.insert("cap_bytes".into(), json!(inputs.cap));
    report.insert("tries".into(), json!(attempt));
    let mut files: Vec<Value> = fixed
        .iter()
        .map(|e| json!({ "name": e.name, "bytes": e.raw_len, "compressed": e.deflated.len() }))
        .collect();
    files.extend(logs.iter().map(|(e, piece, stats)| {
        json!({
            "name": e.name,
            "bytes": e.raw_len,
            "compressed": e.deflated.len(),
            "source": piece.source,
            "part": piece.what,
            "file_bytes": e.truncated_from,
            "since": utc_timestamp(piece.since_ms / 1000),
            "lines": {
                "kept": stats.kept,
                "too_old": stats.too_old,
                "too_new": stats.too_new,
                "naming_keys": stats.key_lines,
                "orphans": stats.orphans,
                "user_folder_masked": stats.masked,
            },
        })
    }));
    report.insert("lookback_s".into(), json!(AUTO_LOOKBACK_MS / 1000));
    report.insert("files".into(), Value::Array(files));
    report.insert(
        "left_out".into(),
        dropped
            .iter()
            .map(|d| json!({ "name": d.name, "why": d.why }))
            .collect(),
    );
    report.insert(
        "unreadable".into(),
        unreadable
            .iter()
            .map(|(name, error)| json!({ "name": name, "error": error }))
            .collect(),
    );
    report.insert("config".into(), config.clone());
    for (key, value) in notes.iter().chain(inputs.about.iter()) {
        report.insert(key.clone(), value.clone());
    }
    Value::Object(report)
}

fn file_of(entry: &Entry) -> DiagnosticFile {
    DiagnosticFile {
        name: entry.name.clone(),
        bytes: entry.raw_len,
        truncated: entry.truncated_from.map(|_| true),
    }
}

/// The logs folder's files a report carries ([`select`]), in the order they are packed.
fn list_logs(dir: &Path, now_s: u64, first: Option<&str>) -> Vec<Candidate> {
    let listing = Listing {
        files: list_dir(dir, "the logs folder")
            .into_iter()
            .map(|(name, meta)| {
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs());
                (name, modified)
            })
            .collect(),
        sessions: list_dir(&dir.join(SESSIONS_DIR), "the sessions folder")
            .into_iter()
            .map(|(name, _)| name)
            .collect(),
    };
    let chosen = select(&listing, now_s, first);
    tracing::debug!(
        in_folder = listing.files.len(),
        session_files = listing.sessions.len(),
        chosen = chosen.len(),
        names = ?chosen.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        "diagnostics: log files for the report, in the order they are packed"
    );
    chosen
}

/// The plain files in `dir` (`what`, for the log) with their metadata; none when it cannot be
/// listed, which is said at `debug` (no `sessions` folder is ordinary before the first session).
fn list_dir(dir: &Path, what: &str) -> Vec<(String, std::fs::Metadata)> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(dir = %dir.display(), "diagnostics: {what} not listed: {e}");
            return Vec::new();
        }
    };
    let mut files = Vec::new();
    for entry in entries {
        match entry.and_then(|entry| Ok((entry.file_name(), entry.metadata()?))) {
            Ok((name, meta)) if meta.is_file() => {
                files.push((name.to_string_lossy().into_owned(), meta));
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("diagnostics: an entry of {what} not read: {e}"),
        }
    }
    files
}

/// The session id a session file's first line (its header, `log_route`) names, or `None` when the
/// file cannot be read or its first line is not a header.
fn session_id_in(path: &Path) -> Option<String> {
    let mut first = Vec::new();
    let read = File::open(path)
        .and_then(|file| BufReader::new(file.take(HEADER_READ)).read_until(b'\n', &mut first));
    if let Err(e) = read {
        tracing::debug!(file = %path.display(), "diagnostics: a session file's header not read: {e}");
        return None;
    }
    let line = String::from_utf8_lossy(&first);
    let id = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("session="))
        .filter(|_| line.contains("session log opened"))
        .map(|id| id.trim_matches('"').to_string());
    if id.is_none() {
        tracing::debug!(file = %path.display(), "diagnostics: a session file without a header");
    }
    id
}

enum Packed {
    In(Entry),
    TooBig { bytes: u64 },
}

/// One log file compressed, if it fits `budget`; else, with `cut_to`, its end cut to fit that.
fn pack_file(path: &Path, name: &str, budget: u64, cut_to: Option<u64>) -> io::Result<Packed> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    // The size now: a log still being written grows, and the entry is what was there at the start.
    let len = meta.len();
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or_else(now_unix_s, |d| d.as_secs());
    let start = len.saturating_sub(MAX_RAW_READ);
    if start > 0 {
        tracing::debug!(
            file = name,
            bytes = len,
            read = MAX_RAW_READ,
            "diagnostics: a log file this large is read from its end only"
        );
    }
    let entry = deflate_range(&mut file, name, start, len, modified)?;
    if entry.cost() <= budget {
        return Ok(Packed::In(entry));
    }
    let Some(limit) = cut_to.filter(|&limit| limit >= MIN_TAIL) else {
        return Ok(Packed::TooBig { bytes: len });
    };
    // Keep as much of the end as the compression seen so far says fits, with a margin; again
    // smaller if that was too much.
    let mut entry = entry;
    for attempt in 1..=CUT_TRIES {
        let ratio = limit as f64 / entry.cost().max(1) as f64;
        let keep = ((entry.raw_len as f64) * ratio * 0.9) as u64;
        let from = len.saturating_sub(keep);
        entry = deflate_range(&mut file, name, from, len, modified)?;
        tracing::debug!(
            file = name,
            attempt,
            kept_raw = entry.raw_len,
            cost = entry.cost(),
            limit,
            budget,
            "diagnostics: a log file is cut to its end to fit"
        );
        if entry.cost() <= limit {
            return Ok(Packed::In(entry));
        }
    }
    Ok(Packed::TooBig { bytes: len })
}

/// `bytes` compressed into an entry of at most `limit` (its cost in the archive): whole if it fits,
/// else its newest end, from the start of a whole line, marked truncated. A text that will not
/// compress to the limit after [`CUT_TRIES`] cuts goes in empty, marked truncated, and said at `warn`.
fn deflate_bytes_end(name: &str, bytes: &[u8], limit: u64, now_s: u64) -> Entry {
    let mut entry = Entry::deflate_bytes(name, bytes, now_s);
    if entry.cost() <= limit {
        return entry;
    }
    let len = bytes.len();
    for attempt in 1..=CUT_TRIES {
        let ratio = limit as f64 / entry.cost().max(1) as f64;
        let keep = ((entry.raw_len as f64) * ratio * 0.9) as usize;
        let cut = len.saturating_sub(keep);
        // From the line after the cut: the one it fell in is left out whole.
        let from = bytes
            .get(cut..)
            .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
            .map_or(len, |at| cut + at + 1);
        entry = Entry::deflate_bytes(name, bytes.get(from..).unwrap_or_default(), now_s);
        entry.truncated_from = Some(len as u64);
        tracing::debug!(
            file = name,
            attempt,
            bytes = len,
            kept_raw = entry.raw_len,
            cost = entry.cost(),
            limit,
            "diagnostics: in-memory text cut to its newest end to fit"
        );
        if entry.cost() <= limit {
            return entry;
        }
    }
    tracing::warn!(
        file = name,
        bytes = len,
        limit,
        "diagnostics: in-memory text does not compress to its limit; it goes in empty"
    );
    let mut empty = Entry::deflate_bytes(name, b"", now_s);
    empty.truncated_from = Some(len as u64);
    empty
}

/// Bytes `from..to` of `file` compressed into an entry — from the start of the first whole line when
/// `from` is inside the file, and then marked truncated.
fn deflate_range(
    file: &mut File,
    name: &str,
    from: u64,
    to: u64,
    modified: u64,
) -> io::Result<Entry> {
    file.seek(SeekFrom::Start(from))?;
    let mut reader = BufReader::new(Read::by_ref(file).take(to.saturating_sub(from)));
    if from > 0 {
        // The rest of the line the cut fell in; a line longer than this is cut where it ends up.
        let mut partial = Vec::new();
        Read::by_ref(&mut reader)
            .take(64 * 1024)
            .read_until(b'\n', &mut partial)?;
    }
    let mut entry = Entry::deflate_from(name, reader, modified)?;
    if from > 0 {
        entry.truncated_from = Some(to);
    }
    Ok(entry)
}

fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// config.json as a report carries it: the file's fields in [`CONFIG_FIELDS`], and what was left
/// out and where the values came from, for `report.json`.
fn config_json(source: &ConfigSource) -> (Vec<u8>, Value) {
    let from_file = source.path.as_deref().map(|path| {
        let meta = std::fs::metadata(path)?;
        if meta.len() > CONFIG_MAX_BYTES {
            return Err(io::Error::other(format!("{} bytes", meta.len())));
        }
        let text = std::fs::read(path)?;
        serde_json::from_slice::<Value>(&text).map_err(io::Error::other)
    });
    let (value, origin) = match from_file {
        Some(Ok(value)) => (value, "file".to_string()),
        Some(Err(e)) => {
            tracing::warn!(
                "diagnostics: config.json not read ({e}); the app's config in memory goes instead"
            );
            (source.in_memory.clone(), format!("memory ({e})"))
        }
        None => {
            tracing::debug!(
                "diagnostics: the app has no config.json path; its config in memory goes"
            );
            (source.in_memory.clone(), "memory".to_string())
        }
    };
    let (mut kept, left_out) = whitelist_config(&value);
    if !left_out.is_empty() {
        tracing::debug!(fields = ?left_out, "diagnostics: config.json fields not in the report's list, left out");
    }
    let masked = mask_config_paths(&mut kept);
    tracing::debug!(
        fields = ?masked,
        "diagnostics: config.json's game paths with the account's folder masked (none: no path \
         under Users)"
    );
    let bytes = serde_json::to_vec_pretty(&kept).unwrap_or_default();
    (
        bytes,
        json!({
            "source": origin,
            "fields_left_out": left_out,
            "user_folder_masked": masked,
        }),
    )
}

/// The account's folder masked in `config`'s fields of [`CONFIG_PATHS`] that are strings; the ones
/// it was masked in.
pub(crate) fn mask_config_paths(config: &mut Value) -> Vec<String> {
    let mut masked = Vec::new();
    for field in CONFIG_PATHS {
        let mut at = Some(&mut *config);
        for key in field.split('.') {
            at = at.and_then(|value| value.get_mut(key));
        }
        if let Some(Value::String(path)) = at {
            let (text, changed) = mask_user_folder(path);
            if changed {
                *path = text;
                masked.push(field.to_string());
            }
        }
    }
    masked
}

/// `path` with the folder after each `Users` masked as `<user>` — `C:\Users\Ivan\Games\x.exe` →
/// `C:\Users\<user>\Games\x.exe` — either slash, any case; and whether anything was.
pub(crate) fn mask_user_folder(path: &str) -> (String, bool) {
    const USERS: &str = "\\users\\";
    // The same bytes as `path` at the same places: ASCII lowered, `/` read as `\`.
    let search = path.to_ascii_lowercase().replace('/', "\\");
    let mut out = String::with_capacity(path.len());
    let mut from = 0;
    let mut masked = false;
    while let Some(found) = search[from..].find(USERS) {
        let start = from + found + USERS.len();
        let end = search[start..]
            .find('\\')
            .map_or(path.len(), |len| start + len);
        out.push_str(&path[from..start]);
        if end > start {
            out.push_str("<user>");
            masked = true;
        }
        from = end;
    }
    out.push_str(&path[from..]);
    (out, masked)
}

/// `config`'s fields in [`CONFIG_FIELDS`], and the names of the others. Not an object: nothing kept,
/// and `"<not an object>"` named.
pub(crate) fn whitelist_config(config: &Value) -> (Value, Vec<String>) {
    let Some(object) = config.as_object() else {
        return (json!({}), vec!["<not an object>".to_string()]);
    };
    let mut kept = Map::new();
    let mut left_out = Vec::new();
    for (key, value) in object {
        if CONFIG_FIELDS.contains(&key.as_str()) {
            kept.insert(key.clone(), value.clone());
        } else {
            left_out.push(key.clone());
        }
    }
    (Value::Object(kept), left_out)
}

/// `report.json`: how this zip was made. `session_files`: each session file considered, newest
/// first as packed, with the session its header names and whether it went in whole, as its end,
/// or not at all.
fn report_json(
    inputs: &Inputs,
    entries: &[Entry],
    dropped: &[Dropped],
    unreadable: &[(String, String)],
    config: Value,
    session_files: Vec<Value>,
    now_s: u64,
) -> Value {
    let mut report = Map::new();
    report.insert("format".into(), json!(1));
    report.insert("packed_at".into(), json!(utc_timestamp(now_s)));
    report.insert("cap_bytes".into(), json!(inputs.cap));
    report.insert(
        "files".into(),
        entries
            .iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "bytes": e.raw_len,
                    "compressed": e.deflated.len(),
                    "truncated_from": e.truncated_from,
                })
            })
            .collect(),
    );
    report.insert(
        "left_out".into(),
        dropped
            .iter()
            .map(|d| json!({ "name": d.name, "bytes": d.bytes, "why": d.why }))
            .collect(),
    );
    report.insert(
        "unreadable".into(),
        unreadable
            .iter()
            .map(|(name, error)| json!({ "name": name, "error": error }))
            .collect(),
    );
    report.insert("session_files".into(), Value::Array(session_files));
    report.insert("config".into(), config);
    for (key, value) in &inputs.about {
        report.insert(key.clone(), value.clone());
    }
    Value::Object(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_retention::SYSTEM_LOG;
    use afklink_protocol::diagnostics::is_file_name;

    /// The day of `NOW_MS`, in days since 1970.
    const TODAY: i64 = 20_725;
    /// 2026-09-29T10:15:30Z.
    const NOW_MS: u64 = 1_790_676_930_000;

    #[test]
    fn today_is_the_day_the_constants_say() {
        assert_eq!(date_of_day(TODAY), "2026-09-29");
        assert_eq!(utc_timestamp(NOW_MS / 1000), "2026-09-29T10:15:30Z");
        assert_eq!(i64::try_from(NOW_MS / 1000 / 86_400).expect("fits"), TODAY);
    }

    /// The Unix second `hours` before [`NOW_MS`].
    fn hours_ago(hours: u64) -> Option<u64> {
        Some(NOW_MS / 1000 - hours * 3600)
    }

    /// Only our logs, by name, in the order they are packed: the system log and its rotations, the
    /// watchdog's and the newest three installer logs, the newest session, an old daily file of the
    /// last day, then the four sessions before the newest.
    #[test]
    fn only_our_logs_are_chosen_in_packing_order() {
        let files: Vec<(String, Option<u64>)> = [
            ("system.2.log", hours_ago(300)),
            ("system.log", hours_ago(0)),
            ("system.1.log", hours_ago(100)),
            ("system.4.log", hours_ago(400)), // past the rotations kept: not ours
            ("system.log.bak", hours_ago(1)),
            ("afklink-app.2026-09-29.log", hours_ago(2)), // the day's old daily file: in
            ("afklink-app.2026-09-28.log", hours_ago(23)), // written 23 hours ago: in
            ("afklink-app.2026-09-27.log", hours_ago(30)), // 30 hours ago: out
            ("afklink-app.2026-09-30.log", None),         // no time known: by its date, in
            ("afklink-watchdog.2026-09-20.log", hours_ago(200)),
            ("afklink-watchdog.2026-09-28.log", hours_ago(30)),
            ("msiexec-fakerinput-install-20260901-120000Z.log", None),
            ("msiexec-fakerinput-uninstall-20260928-134804Z.log", None),
            ("msiexec-fakerinput-install-20260928-134843Z.log", None),
            ("msiexec-fakerinput-install-20260928-124950Z.log", None),
            ("identity.json", None),
            ("identity.json.bak-49c5a67f", None),
            ("config.json", None),
            ("remoter-app.2026-09-29.log", hours_ago(1)),
            ("afklink-app.log", None),
            ("afklink-app.2026-09-29.log.bak", None),
            ("notes.txt", None),
        ]
        .iter()
        .map(|(n, t)| ((*n).to_string(), *t))
        .collect();
        let sessions: Vec<String> = [
            "2026-09-29_12-10-05_d1020ebf.log",
            "2026-09-28_16-49-17_d466bdd9.log",
            "2026-09-28_16-59-38_d59808dd.log",
            "2026-09-29_01-15-00_cc1a93cd.log",
            "2026-09-27_10-00-00_aaaaaaaa.log",
            "2026-09-20_10-00-00_bbbbbbbb.log", // the sixth newest: out
            "identity.json",
            "notes.log",
        ]
        .iter()
        .map(|n| (*n).to_string())
        .collect();
        let listing = Listing { files, sessions };
        let chosen = select(&listing, NOW_MS / 1000, None);
        let got: Vec<(&str, LogKind)> = chosen.iter().map(|c| (c.name.as_str(), c.kind)).collect();
        assert_eq!(
            got,
            [
                ("system.log", LogKind::System),
                ("system.1.log", LogKind::System),
                ("system.2.log", LogKind::System),
                ("afklink-watchdog.2026-09-28.log", LogKind::Watchdog),
                ("afklink-watchdog.2026-09-20.log", LogKind::Watchdog),
                (
                    "msiexec-fakerinput-install-20260928-134843Z.log",
                    LogKind::Installer
                ),
                (
                    "msiexec-fakerinput-uninstall-20260928-134804Z.log",
                    LogKind::Installer
                ),
                (
                    "msiexec-fakerinput-install-20260928-124950Z.log",
                    LogKind::Installer
                ),
                (
                    "sessions/2026-09-29_12-10-05_d1020ebf.log",
                    LogKind::Session
                ),
                ("afklink-app.2026-09-30.log", LogKind::LegacyApp),
                ("afklink-app.2026-09-29.log", LogKind::LegacyApp),
                ("afklink-app.2026-09-28.log", LogKind::LegacyApp),
                (
                    "sessions/2026-09-29_01-15-00_cc1a93cd.log",
                    LogKind::Session
                ),
                (
                    "sessions/2026-09-28_16-59-38_d59808dd.log",
                    LogKind::Session
                ),
                (
                    "sessions/2026-09-28_16-49-17_d466bdd9.log",
                    LogKind::Session
                ),
                (
                    "sessions/2026-09-27_10-00-00_aaaaaaaa.log",
                    LogKind::Session
                ),
            ]
        );
        assert!(chosen.iter().all(|c| is_file_name(&c.name)));
        let cuts: Vec<(&str, Cut)> = chosen
            .iter()
            .filter(|c| c.cut != Cut::No)
            .map(|c| (c.name.as_str(), c.cut))
            .collect();
        assert_eq!(
            cuts,
            [
                ("system.log", Cut::HalfTheRoom),
                ("sessions/2026-09-29_12-10-05_d1020ebf.log", Cut::TheRest),
            ],
            "only the current system log and the newest session keep their end"
        );

        // «Отправить логи» on a journal entry: that session first — even the sixth newest, which
        // would otherwise stay out — keeping its end if it must, then the four newest others.
        let chosen = select(
            &listing,
            NOW_MS / 1000,
            Some("bbbbbbbb-1111-4222-8333-444444444444"),
        );
        let sessions: Vec<(&str, Cut)> = chosen
            .iter()
            .filter(|c| c.kind == LogKind::Session)
            .map(|c| (c.name.as_str(), c.cut))
            .collect();
        assert_eq!(
            sessions,
            [
                ("sessions/2026-09-20_10-00-00_bbbbbbbb.log", Cut::TheRest),
                ("sessions/2026-09-29_12-10-05_d1020ebf.log", Cut::No),
                ("sessions/2026-09-29_01-15-00_cc1a93cd.log", Cut::No),
                ("sessions/2026-09-28_16-59-38_d59808dd.log", Cut::No),
                ("sessions/2026-09-28_16-49-17_d466bdd9.log", Cut::No),
            ]
        );
        // A session without a file: the usual order.
        let usual = select(
            &listing,
            NOW_MS / 1000,
            Some("ffffffff-0000-4000-8000-000000000000"),
        );
        assert_eq!(usual, select(&listing, NOW_MS / 1000, None));
    }

    #[test]
    fn config_keeps_the_listed_fields_only() {
        let config = json!({
            "device_id": "843eda6a-0000-4000-8000-000000000000",
            "server_url": "wss://api.afklink.app/ws/agent",
            "name": "Test-PC",
            "lang": "ru",
            "autostart": true,
            "log_level": "debug",
            "auto_update": true,
            "api_token": "must not leave",
            "secret_key": "must not leave either",
        });
        let (kept, left_out) = whitelist_config(&config);
        let text = kept.to_string();
        assert!(!text.contains("must not leave"), "{text}");
        assert_eq!(kept["name"], "Test-PC");
        assert_eq!(kept["log_level"], "debug");
        let mut left_out = left_out;
        left_out.sort();
        assert_eq!(left_out, ["api_token", "secret_key"]);
        assert_eq!(whitelist_config(&json!([1])).0, json!({}));
    }

    /// The game's settings go in (so a report says whether the game helper was on), the
    /// account's folder masked in their paths; where the game lies stays.
    #[test]
    fn the_game_settings_go_in_with_the_accounts_folder_masked() {
        let config = json!({
            "device_id": "d",
            "game_only": true,
            "game_only_for_guests": true,
            "game_helper": true,
            "game": {
                "exe_path": r"C:\Users\Иван Петров\Games\Scryde\ScrydeGame.bin",
                "window_class": "ScrydeGameUnrealWWindowsViewportWindow",
                "display_name": "ScrydeGame.bin",
            },
            "game_launch_exe": r"D:\Games\Scryde\ScrydeGame.exe",
            "game_launch_learned": "c:/USERS/ivan/AppData/Local/Scryde/Launcher.exe",
            "input_not_reaching": true,
        });
        let (mut kept, left_out) = whitelist_config(&config);
        assert_eq!(left_out, ["input_not_reaching"]);
        assert_eq!(
            mask_config_paths(&mut kept),
            ["game.exe_path", "game_launch_learned"]
        );
        assert_eq!(
            kept["game"]["exe_path"],
            r"C:\Users\<user>\Games\Scryde\ScrydeGame.bin"
        );
        assert_eq!(
            kept["game"]["window_class"],
            "ScrydeGameUnrealWWindowsViewportWindow"
        );
        assert_eq!(kept["game_launch_exe"], r"D:\Games\Scryde\ScrydeGame.exe");
        assert_eq!(
            kept["game_launch_learned"],
            "c:/USERS/<user>/AppData/Local/Scryde/Launcher.exe"
        );
        assert_eq!(
            (kept["game_only"].clone(), kept["game_helper"].clone()),
            (json!(true), json!(true))
        );
        assert!(!kept.to_string().contains("Иван"), "{kept}");
        // Every one, and nothing else.
        assert_eq!(
            mask_user_folder(r"\\?\C:\Users\a\x;C:\Users\b"),
            (r"\\?\C:\Users\<user>\x;C:\Users\<user>".to_string(), true)
        );
        assert_eq!(
            mask_user_folder(r"D:\Games\users.exe"),
            (r"D:\Games\users.exe".to_string(), false)
        );
        // A config with no game: nothing to mask, nothing added.
        let (mut plain, _) = whitelist_config(&json!({ "device_id": "d" }));
        assert!(mask_config_paths(&mut plain).is_empty());
        assert_eq!(plain, json!({ "device_id": "d" }));
    }

    /// A data folder as the app has it — `identity.json` in it, and copies of it in the logs folder
    /// for good measure — packed: every entry read back, no identity file among them, and the secret
    /// in none of their bytes.
    #[test]
    fn identity_json_never_goes_in() {
        // A marker, not a key: built at run time, so the source holds nothing key-shaped.
        let secret = ["FAKE", "IDENTITY", "SECRET", "MARKER"].join("-").repeat(2);
        let secret = secret.as_str();
        let dir = TempDir::new("identity");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        let identity = format!(r#"{{"secret_key":"{secret}"}}"#);
        let sessions = logs.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).expect("sessions dir");
        for path in [
            dir.0.join("identity.json"),
            dir.0.join("identity.json.bak-49c5a67f"),
            logs.join("identity.json"),
            logs.join("identity.json.log"),
            logs.join("afklink-app.identity.log"),
            logs.join("system.identity.log"),
            sessions.join("identity.json"),
            sessions.join("2026-09-29_12-10-05_identity.json"),
        ] {
            std::fs::write(&path, &identity).expect("write");
        }
        std::fs::write(logs.join(SYSTEM_LOG), "a line\n").expect("write");
        std::fs::write(
            sessions.join("2026-09-29_12-10-05_d1020ebf.log"),
            "a session's line\n",
        )
        .expect("write");
        let config = dir.0.join("config.json");
        std::fs::write(
            &config,
            r#"{"device_id":"d","server_url":"wss://x/ws/agent","name":"PC","identity":"x"}"#,
        )
        .expect("write");

        let package = build(inputs(Some(logs), Some(config), CAP)).expect("packs");
        let back = zip::read_back(&package.zip);
        let names: Vec<&str> = back.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "report.json",
                "build.json",
                "system.json",
                "config.json",
                "recent-debug.log",
                "system.log",
                "sessions/2026-09-29_12-10-05_d1020ebf.log",
            ]
        );
        for (name, bytes) in &back {
            assert!(!name.contains("identity"), "{name}");
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains(secret), "{name} carries the secret");
        }
        // The metadata's list is the zip's, size for size.
        let listed: Vec<(&str, u64)> = package
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.bytes))
            .collect();
        let actual: Vec<(&str, u64)> = back
            .iter()
            .map(|(n, b)| (n.as_str(), b.len() as u64))
            .collect();
        assert_eq!(listed, actual);
        // config.json: the unknown `identity` field left out, and said so.
        let config = &back[3].1;
        let config: Value = serde_json::from_slice(config).expect("json");
        assert_eq!(config.get("identity"), None);
        let report: Value = serde_json::from_slice(&back[0].1).expect("json");
        assert_eq!(report["config"]["fields_left_out"], json!(["identity"]));
        assert_eq!(report["config"]["source"], "file");
    }

    /// Text that barely compresses: every line carries a pseudo-random hex tail.
    fn noisy(lines: usize, seed: u64) -> String {
        let mut x = seed;
        let mut out = String::new();
        for i in 0..lines {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            out.push_str(&format!("line {i} {:016x}{:016x}\n", x, x.rotate_left(17)));
        }
        out
    }

    /// A session file's first line, as `log_route` writes it.
    fn header(id: &str) -> String {
        format!(
            "2026-09-29T09:10:05.000001Z  INFO afklink_app_lib::log_file: session log opened \
             session={id} telegram_user_id=5000000001 build=\"0.1.0\" log_level=\"debug\"\n"
        )
    }

    const NEWEST: &str = "2026-09-29_12-10-05_d1020ebf.log";
    const MIDDLE: &str = "2026-09-29_11-00-00_d466bdd9.log";
    const OLDEST: &str = "2026-09-29_10-00-00_d59808dd.log";
    const NEWEST_ID: &str = "d1020ebf-00d8-4048-a861-f51293d9135e";

    /// A logs folder with a small system log, a watchdog log and three sessions of `lines` lines
    /// each, newest to oldest.
    fn logs_with_sessions(dir: &TempDir, lines: [usize; 3]) -> PathBuf {
        let logs = dir.0.join("logs");
        let sessions = logs.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).expect("sessions dir");
        std::fs::write(logs.join(SYSTEM_LOG), noisy(100, 9)).expect("write");
        std::fs::write(logs.join("afklink-watchdog.2026-09-28.log"), "w\n").expect("write");
        for ((name, lines), seed) in [NEWEST, MIDDLE, OLDEST].iter().zip(lines).zip(1..) {
            let first = if *name == NEWEST {
                header(NEWEST_ID)
            } else {
                String::new()
            };
            std::fs::write(sessions.join(name), first + &noisy(lines, seed)).expect("write");
        }
        logs
    }

    fn left_out(package: &Package) -> Vec<(&str, &str)> {
        package
            .dropped
            .iter()
            .map(|d| (d.name.as_str(), d.why))
            .collect()
    }

    /// Too much for the cap, the sessions give way: an older session that does not fit is left out
    /// with every older one — the oldest go first — while the newest goes in whole, and the system
    /// log and the small logs all go in.
    #[test]
    fn the_oldest_sessions_go_first() {
        let dir = TempDir::new("cap-oldest");
        let logs = logs_with_sessions(&dir, [100, 20_000, 100]);
        let cap = 400 * 1024;
        let package = build(inputs(Some(logs), None, cap)).expect("packs");
        assert!(package.zip.len() as u64 <= cap, "{}", package.zip.len());
        let back = zip::read_back(&package.zip);
        let names: Vec<&str> = back.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "report.json",
                "build.json",
                "system.json",
                "config.json",
                "recent-debug.log",
                "system.log",
                "afklink-watchdog.2026-09-28.log",
                "sessions/2026-09-29_12-10-05_d1020ebf.log",
            ]
        );
        assert!(package.files.iter().all(|f| f.truncated.is_none()));
        assert_eq!(
            left_out(&package),
            [
                ("sessions/2026-09-29_11-00-00_d466bdd9.log", "no_room"),
                (
                    "sessions/2026-09-29_10-00-00_d59808dd.log",
                    "older_than_a_file_that_did_not_fit"
                ),
            ]
        );
    }

    /// A PC bound to nobody (`diagnostics::manual_cap`): with logs far over 2 MiB and a full flight
    /// recorder, the report stays under [`UNBOUND_CAP`], the oldest sessions are what is left out,
    /// the newest session and the recorder keep their ends, and the summaries all go in. The same
    /// folder under [`CAP`] goes in whole, as before.
    #[test]
    fn a_report_from_a_pc_bound_to_nobody_fits_the_small_cap_newest_first() {
        let dir = TempDir::new("cap-unbound");
        let logs = logs_with_sessions(&dir, [60_000, 60_000, 60_000]);
        let recorder = noisy(200_000, 77);
        let mut small = inputs(Some(logs.clone()), None, UNBOUND_CAP);
        small.recent_debug = Some(recorder.clone().into_bytes());
        let package = build(small).expect("packs");
        assert!(
            package.zip.len() as u64 <= UNBOUND_CAP,
            "{}",
            package.zip.len()
        );
        let back = zip::read_back(&package.zip);
        let text_of = |name: &str| {
            back.iter()
                .find(|(n, _)| n == name)
                .map(|(_, b)| String::from_utf8(b.clone()).expect("utf-8"))
        };
        for summary in [
            "report.json",
            "build.json",
            "system.json",
            "config.json",
            SYSTEM_LOG,
        ] {
            assert!(text_of(summary).is_some(), "{summary} is in");
        }
        let recent = text_of("recent-debug.log").expect("the recorder is in");
        assert!(recent.starts_with("line "), "cut where a line starts");
        assert!(recent.contains("line 199999 "), "its newest end is kept");
        assert!(!recent.contains("line 0 "), "its oldest part is cut");
        let newest = format!("{SESSIONS_DIR}/{NEWEST}");
        let session = text_of(&newest).expect("the newest session is in");
        assert!(session.contains("line 59999 "), "the newest lines are kept");
        let truncated: Vec<&str> = package
            .files
            .iter()
            .filter(|f| f.truncated == Some(true))
            .map(|f| f.name.as_str())
            .collect();
        assert!(truncated.contains(&"recent-debug.log"), "{truncated:?}");
        let out: Vec<&str> = package.dropped.iter().map(|d| d.name.as_str()).collect();
        assert!(
            out.contains(&format!("{SESSIONS_DIR}/{OLDEST}").as_str()),
            "the oldest session is left out: {out:?}"
        );
        assert!(!out.contains(&newest.as_str()), "{out:?}");

        // A PC with people on it: the same folder, the full cap — everything whole.
        let mut full = inputs(Some(logs), None, CAP);
        full.recent_debug = Some(recorder.into_bytes());
        let package = build(full).expect("packs");
        assert!(package.files.iter().all(|f| f.truncated.is_none()));
        assert!(package.dropped.is_empty(), "{:?}", package.dropped);
        assert!(package.zip.len() as u64 > UNBOUND_CAP);
    }

    /// The recorder's text, cut to its limit: whole when it fits, else its end from a whole line.
    #[test]
    fn in_memory_text_keeps_its_newest_end_within_its_limit() {
        let text = noisy(50_000, 3);
        let whole = deflate_bytes_end("recent-debug.log", text.as_bytes(), u64::MAX, 0);
        assert_eq!(whole.truncated_from, None);
        assert_eq!(whole.raw_len, text.len() as u64);
        let limit = 64 * 1024;
        let cut = deflate_bytes_end("recent-debug.log", text.as_bytes(), limit, 0);
        assert!(cut.cost() <= limit, "{}", cut.cost());
        assert_eq!(cut.truncated_from, Some(text.len() as u64));
        assert!(cut.raw_len > 0 && cut.raw_len < text.len() as u64);
        let back = zip::read_back(&zip::write(&[cut]).expect("zip"));
        let kept = String::from_utf8(back[0].1.clone()).expect("utf-8");
        assert!(kept.starts_with("line ") && text.ends_with(&kept));
        // Nothing fits: empty, still marked cut.
        let none = deflate_bytes_end("recent-debug.log", text.as_bytes(), 1, 0);
        assert_eq!(
            (none.raw_len, none.truncated_from),
            (0, Some(text.len() as u64))
        );
    }

    /// The newest session alone too big for what is left: the older sessions are left out, and the
    /// newest keeps its end, cut where a line starts — the trim comes after the drops. `report.json`
    /// says which session files went in, how, and which session each is of.
    #[test]
    fn then_the_newest_session_keeps_its_end() {
        let dir = TempDir::new("cap-newest");
        let logs = logs_with_sessions(&dir, [20_000, 20_000, 100]);
        let cap = 400 * 1024;
        let package = build(inputs(Some(logs), None, cap)).expect("packs");
        assert!(package.zip.len() as u64 <= cap, "{}", package.zip.len());
        let back = zip::read_back(&package.zip);
        let newest = format!("{SESSIONS_DIR}/{NEWEST}");
        let text = back
            .iter()
            .find(|(n, _)| *n == newest)
            .map(|(_, b)| String::from_utf8(b.clone()).expect("utf-8"))
            .expect("the newest session is in");
        assert!(text.starts_with("line "), "cut where a line starts");
        assert!(!text.contains("line 0 "), "the start is cut");
        assert!(text.contains("line 19999 "), "the end is kept");
        let truncated: Vec<&str> = package
            .files
            .iter()
            .filter(|f| f.truncated == Some(true))
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(truncated, [newest.as_str()]);
        assert!(back.iter().any(|(n, _)| n == SYSTEM_LOG));
        assert_eq!(
            left_out(&package),
            [
                ("sessions/2026-09-29_11-00-00_d466bdd9.log", "no_room"),
                (
                    "sessions/2026-09-29_10-00-00_d59808dd.log",
                    "older_than_a_file_that_did_not_fit"
                ),
            ]
        );
        let report: Value = serde_json::from_slice(&back[0].1).expect("json");
        assert_eq!(
            report["session_files"],
            json!([
                { "name": newest, "session_id": NEWEST_ID, "packed": "end" },
                { "name": format!("{SESSIONS_DIR}/{MIDDLE}"), "session_id": null, "packed": "left_out" },
                { "name": format!("{SESSIONS_DIR}/{OLDEST}"), "session_id": null, "packed": "left_out" },
            ])
        );
        assert_eq!(report["left_out"].as_array().map(Vec::len), Some(2));
    }

    /// A report fits the cap with room: every chosen file whole, nothing left out — the system log
    /// with its rotations, the watchdog's and the installer's logs, the sessions, and an old daily
    /// file of the last day.
    #[test]
    fn a_small_report_carries_everything_whole() {
        let dir = TempDir::new("small");
        let logs = dir.0.join("logs");
        let sessions = logs.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).expect("sessions dir");
        for name in [
            "system.log",
            "system.1.log",
            "afklink-watchdog.2026-09-28.log",
            "msiexec-fakerinput-install-20260928-124950Z.log",
        ] {
            std::fs::write(logs.join(name), format!("{name}\n").repeat(1000)).expect("write");
        }
        for name in [NEWEST, MIDDLE] {
            std::fs::write(sessions.join(name), format!("{name}\n").repeat(1000)).expect("write");
        }
        let package = build(inputs(Some(logs), None, CAP)).expect("packs");
        assert!(package.dropped.is_empty());
        assert!(package.unreadable.is_empty());
        assert_eq!(package.files.len(), 11);
        assert!(package.files.iter().all(|f| f.truncated.is_none()));
        let back = zip::read_back(&package.zip);
        let log = &back
            .iter()
            .find(|(n, _)| n == "afklink-watchdog.2026-09-28.log")
            .expect("in")
            .1;
        assert_eq!(log.len(), "afklink-watchdog.2026-09-28.log\n".len() * 1000);
        // config.json from memory when there is no file.
        let report: Value = serde_json::from_slice(&back[0].1).expect("json");
        assert_eq!(report["config"]["source"], "memory");
        assert_eq!(report["sessions"], json!(["s"]));
        assert_eq!(
            report["session_files"].as_array().map(|files| files
                .iter()
                .map(|f| f["packed"].clone())
                .collect::<Vec<_>>()),
            Some(vec![json!("whole"), json!("whole")])
        );
    }

    // ---------- The automatic report's tails ----------

    const FAILED_ID: &str = "d1020ebf-00d8-4048-a861-f51293d9135e";

    /// 30 s before [`NOW_MS`], the event's time in these tests.
    const RECENT: &str = "2026-09-29T10:15:00.000000Z";

    /// `text`'s lines, each as the log writes one at [`RECENT`].
    fn stamped(text: &str) -> String {
        text.lines()
            .map(|line| format!("{RECENT} DEBUG afklink_core::agent: {line}\n"))
            .collect()
    }

    fn tail_inputs(logs_dir: Option<PathBuf>, config: Option<PathBuf>) -> TailInputs {
        let mut about = Map::new();
        about.insert("auto".into(), json!({ "trigger": "stall" }));
        TailInputs {
            logs_dir,
            config: ConfigSource {
                path: config,
                in_memory: json!({ "device_id": "d", "name": "PC" }),
            },
            generated: vec![("build.json".into(), br#"{"version":"0.7.2"}"#.to_vec())],
            about,
            now_unix_ms: NOW_MS,
            event_unix_ms: NOW_MS,
            cap: AUTO_CAP,
            system_raw: AUTO_SYSTEM_RAW,
            session: None,
            session_raw: AUTO_SESSION_RAW,
            previous_end: None,
            this_run_raw: AUTO_THIS_RUN_RAW,
        }
    }

    fn names(package: &Package) -> Vec<String> {
        zip::read_back(&package.zip)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    fn entry_text(package: &Package, name: &str) -> String {
        zip::read_back(&package.zip)
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, bytes)| String::from_utf8(bytes).expect("utf-8"))
            .unwrap_or_else(|| unreachable!("{name} is not in the zip"))
    }

    /// Ten megabytes of log that barely compresses, and a big session file: the zip still comes in
    /// under 200 000 bytes, the tails cut where lines start, their ends kept.
    #[test]
    fn an_automatic_report_fits_its_cap_whatever_the_logs_weigh() {
        let dir = TempDir::new("auto-cap");
        let logs = dir.0.join("logs");
        let sessions = logs.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).expect("sessions dir");
        let system = stamped(&noisy(150_000, 3));
        assert!(system.len() > 10 * 1024 * 1024, "{}", system.len());
        std::fs::write(logs.join(SYSTEM_LOG), &system).expect("write");
        std::fs::write(logs.join("system.1.log"), stamped(&noisy(1000, 4))).expect("write");
        std::fs::write(
            sessions.join(NEWEST),
            header(FAILED_ID) + &stamped(&noisy(40_000, 5)),
        )
        .expect("write");
        let mut inputs = tail_inputs(Some(logs), None);
        inputs.session = Some(FAILED_ID.into());
        let package = build_tail(inputs).expect("packs");
        assert!(
            package.zip.len() as u64 <= AUTO_CAP,
            "{} bytes",
            package.zip.len()
        );
        assert_eq!(
            names(&package),
            [
                "report.json",
                "build.json",
                "config.json",
                "system.log",
                &format!("{SESSIONS_DIR}/{NEWEST}")
            ]
        );
        let tail = entry_text(&package, SYSTEM_LOG);
        assert!(tail.starts_with(RECENT), "cut where a line starts");
        assert!(tail.contains("line 149999 "), "its end kept");
        assert!(!tail.contains("line 0 "), "only the tail");
        let session = entry_text(&package, &format!("{SESSIONS_DIR}/{NEWEST}"));
        assert!(session.contains("line 39999 "));
        assert!(package
            .files
            .iter()
            .skip(3)
            .all(|f| f.truncated == Some(true)));
        let report: Value =
            serde_json::from_str(&entry_text(&package, "report.json")).expect("json");
        assert_eq!(report["kind"], "auto");
        assert!(report["tries"].as_u64().is_some_and(|n| n > 1), "it shrank");
        assert_eq!(report["auto"]["trigger"], "stall");
    }

    /// Only the system log's tail, the failed session's file, the config's whitelist and the
    /// generated entries: not `identity.json` (in the data folder, the logs folder and the sessions
    /// folder), not a file planted beside the logs, not the flight recorder, the watchdog's or the
    /// installer's logs, another session's file, or one whose name looks like the session's but whose
    /// header names another.
    #[test]
    fn an_automatic_report_carries_nothing_else() {
        // A marker, not a key: built at run time, so the source holds nothing key-shaped.
        let secret = ["FAKE", "IDENTITY", "SECRET", "MARKER"].join("-").repeat(2);
        let secret = secret.as_str();
        let dir = TempDir::new("auto-only");
        let logs = dir.0.join("logs");
        let sessions = logs.join(SESSIONS_DIR);
        std::fs::create_dir_all(&sessions).expect("sessions dir");
        let identity = format!(r#"{{"secret_key":"{secret}"}}"#);
        for path in [
            dir.0.join("identity.json"),
            logs.join("identity.json"),
            logs.join("system.identity.log"),
            sessions.join("identity.json"),
            logs.join("planted.log"),
            logs.join("recent-debug.log"),
            logs.join("system.json"),
            logs.join("afklink-watchdog.2026-09-28.log"),
            logs.join("msiexec-fakerinput-install-20260928-124950Z.log"),
            logs.join("afklink-app.2026-09-29.log"),
        ] {
            std::fs::write(&path, &identity).expect("write");
        }
        // The system log: a plain line, paths with the account's folder, a line naming keys.
        let system = stamped("a line\nconfig: C:\\Users\\Иван\\AppData\\Roaming\\AFKLink\\config.json")
            + &format!(
                "{RECENT} DEBUG afklink_input::key_names: keys: presses cells=F1×2 sheet=KeyQ\n\
                 {RECENT}  INFO afklink_app_lib::log_file: session log opened file=\"C:\\\\Users\\\\Иван\\\\x.log\"\n"
            );
        std::fs::write(logs.join(SYSTEM_LOG), system).expect("write");
        // The failed session, another, and one with the same short id whose header is another's.
        std::fs::write(
            sessions.join(NEWEST),
            header(FAILED_ID) + &stamped("its line"),
        )
        .expect("write");
        std::fs::write(
            sessions.join(MIDDLE),
            header("d466bdd9-0000-4000-8000-000000000000") + &stamped("other"),
        )
        .expect("write");
        std::fs::write(
            sessions.join("2026-09-29_09-00-00_d1020ebf.log"),
            header("d1020ebf-ffff-4048-a861-f51293d9135e") + &stamped("not it"),
        )
        .expect("write");
        let config = dir.0.join("config.json");
        std::fs::write(
            &config,
            r#"{"device_id":"d","name":"PC","identity":"x","game_launch_exe":"C:\\Users\\Иван\\g.exe"}"#,
        )
        .expect("write");
        let mut inputs = tail_inputs(Some(logs), Some(config));
        inputs.session = Some(FAILED_ID.into());
        let package = build_tail(inputs).expect("packs");
        assert_eq!(
            names(&package),
            [
                "report.json",
                "build.json",
                "config.json",
                "system.log",
                &format!("{SESSIONS_DIR}/{NEWEST}")
            ]
        );
        for (name, bytes) in zip::read_back(&package.zip) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains(secret), "{name} carries the secret");
            assert!(!text.contains("Иван"), "{name} names the account");
            assert!(
                !text.contains("not it") && !text.contains("other\n"),
                "{name}"
            );
            assert!(
                !text.contains("F1×2") && !text.contains("KeyQ"),
                "{name} names keys"
            );
        }
        let tail = entry_text(&package, SYSTEM_LOG);
        assert!(tail.contains(r"config: C:\Users\<user>\AppData\Roaming\AFKLink\config.json"));
        assert!(
            tail.contains(r#"file="C:\\Users\\<user>\\x.log""#),
            "{tail}"
        );
        assert!(entry_text(&package, &format!("{SESSIONS_DIR}/{NEWEST}")).contains("its line"));
        let config: Value =
            serde_json::from_str(&entry_text(&package, "config.json")).expect("json");
        assert_eq!(config.get("identity"), None);
        assert_eq!(config["game_launch_exe"], r"C:\Users\<user>\g.exe");
    }

    /// After a crash the system log's tail ends exactly where the previous run stopped writing, and
    /// this run's first lines follow as their own entry — also when this run's lines rotated the
    /// file since, and the place is in `system.1.log`.
    #[test]
    fn a_crash_report_ends_where_the_previous_run_stopped() {
        // Not rotated; rotated by this run's later lines; rotated by this run's very first line.
        for rotation in ["none", "later", "first_write"] {
            let dir = TempDir::new("auto-crash");
            let logs = dir.0.join("logs");
            std::fs::create_dir_all(&logs).expect("logs dir");
            // The previous run: two hours before its last lines one that is too old to go.
            let previous = "2026-09-29T07:00:00.000000Z DEBUG afklink_core::agent: long before\n"
                .to_string()
                + &stamped(
                    &(0..500)
                        .map(|i| format!("previous run line {i}\n"))
                        .collect::<String>(),
                );
            std::fs::write(logs.join(SYSTEM_LOG), &previous).expect("write");
            let start = LogStart::read(&logs.join(SYSTEM_LOG)).expect("reads");
            assert_eq!(start.len, previous.len() as u64);
            let this_run = stamped(
                &(0..200)
                    .map(|i| format!("this run line {i}\n"))
                    .collect::<String>(),
            );
            match rotation {
                "first_write" => {
                    std::fs::rename(logs.join(SYSTEM_LOG), logs.join("system.1.log"))
                        .expect("rotate");
                    std::fs::write(logs.join(SYSTEM_LOG), &this_run).expect("write");
                }
                _ => {
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(logs.join(SYSTEM_LOG))
                        .expect("open");
                    std::io::Write::write_all(&mut file, this_run.as_bytes()).expect("append");
                    drop(file);
                    if rotation == "later" {
                        std::fs::rename(logs.join(SYSTEM_LOG), logs.join("system.1.log"))
                            .expect("rotate");
                        std::fs::write(logs.join(SYSTEM_LOG), stamped("after the rotation"))
                            .expect("write");
                    }
                }
            }
            let mut inputs = tail_inputs(Some(logs), None);
            inputs.previous_end = Some(start);
            // The crash's time is the previous run's last sign of life, long before now.
            inputs.event_unix_ms = NOW_MS - 3 * 3_600_000;
            let package = build_tail(inputs).expect("packs");
            let before = entry_text(&package, "system.previous-run.log");
            assert!(before.ends_with("previous run line 499\n"), "{rotation}");
            assert!(before.contains("previous run line 0\n"), "{rotation}");
            assert!(!before.contains("this run"), "{rotation}");
            assert!(
                !before.contains("long before"),
                "{rotation}: older than 30 min"
            );
            let after = entry_text(&package, "system.this-run.log");
            assert!(after.contains("this run line 0\n"), "{rotation}");
            assert!(after.contains("this run line 199\n"), "{rotation}");
            assert!(!after.contains("previous run"), "{rotation}");
            let report: Value =
                serde_json::from_str(&entry_text(&package, "report.json")).expect("json");
            assert_eq!(
                report["crash_place"]["file"],
                if rotation == "none" {
                    SYSTEM_LOG
                } else {
                    "system.1.log"
                },
            );
        }
    }

    /// «The last minutes»: a line older than 30 min before the event is left out, and the lines
    /// without a time of their own go with the line above them.
    #[test]
    fn only_the_last_half_hour_goes() {
        let dir = TempDir::new("auto-time");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        let log = "2026-09-29T08:15:30.000000Z  INFO a: two hours before\n\
                   a continuation of it\n\
                   2026-09-29T09:45:29.999000Z  INFO a: 30 min and a moment before\n\
                   2026-09-29T09:45:30.000000Z  INFO a: 30 min before\n\
                   its continuation\n\
                   2026-09-29T10:15:29.000000Z  INFO a: a second before\n";
        std::fs::write(logs.join(SYSTEM_LOG), log).expect("write");
        let package = build_tail(tail_inputs(Some(logs), None)).expect("packs");
        assert_eq!(
            entry_text(&package, SYSTEM_LOG),
            "2026-09-29T09:45:30.000000Z  INFO a: 30 min before\n\
             its continuation\n\
             2026-09-29T10:15:29.000000Z  INFO a: a second before\n"
        );
        let report: Value =
            serde_json::from_str(&entry_text(&package, "report.json")).expect("json");
        assert_eq!(report["files"][2]["name"], SYSTEM_LOG);
        assert_eq!(report["files"][2]["lines"]["too_old"], 2);
        assert_eq!(report["lookback_s"], 1800);
        assert_eq!(AUTO_LOOKBACK_MS, 30 * 60_000);
        // Nothing recent: the tail is left out, not sent old.
        let dir = TempDir::new("auto-time-old");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(
            logs.join(SYSTEM_LOG),
            "2026-09-29T08:15:30.000000Z  INFO a: old\n",
        )
        .expect("write");
        let package = build_tail(tail_inputs(Some(logs), None)).expect("packs");
        assert_eq!(
            names(&package),
            ["report.json", "build.json", "config.json"]
        );
    }

    #[test]
    fn log_times_and_account_folders_are_read_from_lines() {
        assert_eq!(
            line_time_ms(b"2026-09-29T10:15:30.123456Z DEBUG x: y"),
            Some(NOW_MS + 123)
        );
        assert_eq!(line_time_ms(b"2026-09-29T10:15:30Z x"), Some(NOW_MS));
        assert_eq!(days_from_civil(2026, 9, 29), TODAY);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        for bad in [
            &b"continuation"[..],
            &b"2026-13-29T10:15:30Z"[..],
            &b"2026-09-29 10:15:30Z"[..],
            &b""[..],
        ] {
            assert_eq!(line_time_ms(bad), None, "{}", String::from_utf8_lossy(bad));
        }
        for (line, want) in [
            (
                r"config: C:\Users\Иван\a.json",
                r"config: C:\Users\<user>\a.json",
            ),
            (r"dir=c:/users/john smith/logs", r"dir=c:/users/<user>/logs"),
            (
                r#"file="C:\\Users\\Ivan\\x.log""#,
                r#"file="C:\\Users\\<user>\\x.log""#,
            ),
            (r"home=C:\Users\Ivan", r"home=C:\Users\<user>"),
            (
                r"two C:\Users\a\x D:\Users\b\y",
                r"two C:\Users\<user>\x D:\Users\<user>\y",
            ),
            (
                r"all users here, \users without a folder",
                r"all users here, \users without a folder",
            ),
        ] {
            assert_eq!(mask_users_in_line(line).0, want, "{line}");
        }
        assert_eq!(
            KEY_LINE_MARK,
            format!(" {}:", afklink_input::KEY_NAMES_TARGET),
            "the mark is the input crate's target as the log writes it"
        );
    }

    /// The second line of defence: a line naming a key by its content goes, whatever its target;
    /// the agent's ordinary lines stay.
    #[test]
    fn lines_naming_keys_by_their_content_are_recognised() {
        let t = "2026-09-29T10:15:00.000000Z DEBUG afklink_core::agent:";
        for key_line in [
            format!("{t} keys: presses cells=KeyW×12 ShiftLeft+KeyA sheet=-"),
            format!("{t} input: k code=Digit7 down=true"),
            format!("{t} unmapped key code: not injected code=NumpadEnter src=cell"),
            format!("{t} game input: Alt+F4 passes key=F4 src=untagged"),
            format!("{t} held: ArrowUp ControlRight"),
            format!("{t} keys: Escape then Backspace"),
            format!("{t} keys: OSLeft"),
            format!("{t} game input: combo blocked combo=ctrl_alt_del"),
            format!("{t} keyboard layout switch hotkey=AltShift from=en to=ru"),
            format!("{t} sendinput vk=0x41"),
            format!("{t} keys: presses sheet=Enter Space Tab×3"),
            format!("{t} keys: PageDown, then CapsLock and NumLock"),
            format!("{t} cells=Semicolon Quote BracketLeft Backquote Minus Equal"),
            format!("{t} unmapped key code: not injected code=IntlBackslash"),
            format!("{t} unmapped key code: not injected code=Lang1"),
            format!("{t} keys: MediaPlayPause AudioVolumeMute BrowserBack LaunchMail"),
            format!("{t} keys: PrintScreen ContextMenu Delete Insert Home End"),
        ] {
            assert!(names_a_key(&key_line), "{key_line}");
        }
        for plain in [
            format!("{t} game input: the game's window has the front: held_keys=0 held_mods=0"),
            format!("{t} keyboard layout switch: the language hotkey instead"),
            format!("{t} keys: presses cells=- sheet=- other=3"),
            format!("{t} Alt and Shift alone, the escape key in lower case, Control"),
            format!("{t} combos=2 keys=4 vk_count=1 hvk=2"),
            format!("{t} encoder: Keyframe sent key=true F=1 F100=2 0xF1 FF"),
            format!("{t} session 3fa85f64-5717-4562-b3fc-2c963f66afa6 key frames=2"),
            format!("{t} KeyboardLayout 00000409, Digits, Numpad, Arrow, Key"),
            format!("{t} capture: MediaFoundation absent; Language=ru International Intl Lang"),
            format!("{t} press enter, the space bar, a tab; spacebar, endpoint, home=x"),
            format!("{t} Browser AudioVolume Launcher Media LaunchSomething MediaPlayer"),
            format!("{t} Tabs Ending Homes Spaces Enterprise Pauses"),
        ] {
            assert!(!names_a_key(&plain), "{plain}");
        }
        // In a tail: counted as key lines, and a kept line's continuation that names one goes too.
        let text =
            format!("{t} kept\nits continuation\nwith KeyQ in it\n{t} cells=KeyE\n{t} also kept\n");
        let (out, stats) = filter_lines(text.as_bytes(), 0, u64::MAX);
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            format!("{t} kept\nits continuation\n{t} also kept\n")
        );
        assert_eq!(stats.key_lines, 2);
    }

    /// A clock set back makes old lines look newer than the time of packing: past a minute after it
    /// they are left out.
    #[test]
    fn lines_dated_after_packing_are_left_out() {
        let text = "2026-09-29T10:15:00.000000Z  INFO a: before packing\n\
                    2026-09-29T10:16:30.000000Z  INFO a: within the slack\n\
                    2026-09-29T10:16:30.001000Z  INFO a: after it\n\
                    a continuation of it\n";
        // Packed at NOW (10:15:30): until 10:16:30.
        let (out, stats) = filter_lines(text.as_bytes(), 0, NOW_MS + FUTURE_SLACK_MS);
        assert_eq!(
            String::from_utf8(out).expect("utf-8"),
            "2026-09-29T10:15:00.000000Z  INFO a: before packing\n\
             2026-09-29T10:16:30.000000Z  INFO a: within the slack\n"
        );
        assert_eq!(stats.too_new, 1);
        // Through `build_tail`: the same, from its time of packing.
        let dir = TempDir::new("auto-future");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(logs.join(SYSTEM_LOG), text).expect("write");
        let package = build_tail(tail_inputs(Some(logs), None)).expect("packs");
        assert!(!entry_text(&package, SYSTEM_LOG).contains("after it"));
    }

    /// The place not found (the file replaced): the plain tail goes, and `report.json` says so.
    #[test]
    fn a_crash_report_without_its_place_carries_the_plain_tail() {
        let dir = TempDir::new("auto-crash-lost");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(logs.join(SYSTEM_LOG), stamped("short")).expect("write");
        let mut inputs = tail_inputs(Some(logs), None);
        inputs.previous_end = Some(LogStart {
            len: 10_000,
            last: b"gone".to_vec(),
        });
        let package = build_tail(inputs).expect("packs");
        assert!(names(&package).contains(&SYSTEM_LOG.to_string()));
        let report: Value =
            serde_json::from_str(&entry_text(&package, "report.json")).expect("json");
        assert_eq!(report["crash_place"], "not_found");
    }

    /// Just rotated: the tail goes on into `system.1.log`.
    #[test]
    fn a_tail_just_after_a_rotation_goes_on_into_the_last_file() {
        let dir = TempDir::new("auto-rotated");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(logs.join(SYSTEM_LOG), stamped("new file")).expect("write");
        std::fs::write(logs.join("system.1.log"), stamped("older file")).expect("write");
        std::fs::write(logs.join("system.2.log"), stamped("much older")).expect("write");
        let package = build_tail(tail_inputs(Some(logs), None)).expect("packs");
        assert_eq!(
            names(&package),
            [
                "report.json",
                "build.json",
                "config.json",
                "system.log",
                "system.1.log"
            ]
        );
    }

    /// A cap the fixed entries alone pass: an error, never a bigger zip.
    #[test]
    fn an_automatic_report_that_cannot_fit_is_refused() {
        let dir = TempDir::new("auto-nofit");
        let logs = dir.0.join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(logs.join(SYSTEM_LOG), stamped(&noisy(1000, 1))).expect("write");
        let mut inputs = tail_inputs(Some(logs), None);
        inputs.cap = 300;
        assert!(build_tail(inputs).is_err());
    }

    fn inputs(logs_dir: Option<PathBuf>, config: Option<PathBuf>, cap: u64) -> Inputs {
        let mut about = Map::new();
        about.insert("sessions".into(), json!(["s"]));
        Inputs {
            logs_dir,
            config: ConfigSource {
                path: config,
                in_memory: json!({ "device_id": "d", "name": "PC" }),
            },
            generated: vec![
                ("build.json".into(), br#"{"version":"0.1.0"}"#.to_vec()),
                ("system.json".into(), br#"{"cpu":{"logical":8}}"#.to_vec()),
            ],
            recent_debug: Some(
                b"2026-09-29T10:15:29.912345Z DEBUG afklink_core::agent: x\n".to_vec(),
            ),
            now_unix_ms: NOW_MS,
            cap,
            about,
            first_session: None,
        }
    }

    /// A folder of its own under the temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(what: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "afklink-diagnostics-{what}-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
