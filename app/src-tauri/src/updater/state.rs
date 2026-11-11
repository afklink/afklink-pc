//! What the updater remembers across processes: `%LOCALAPPDATA%\AFKLink\updates\state.json` (the
//! update in flight and each version's failures), `health.json` (what the new version reports to
//! the watchdog) and `check.json` (the last successful check, for the Settings section).
//!
//! # Who writes what
//!
//! - `state.json`, `attempt`: the old version writes it just before swapping the exe; the watchdog
//!   clears it when it is done (success or rollback); a start of the app that finds it with no
//!   watchdog alive settles it ([`resolve_startup`]).
//! - `state.json`, `failures`: the watchdog adds one on rollback; the app that was put back settles
//!   an unverified one ([`UpdateState::settle`]); the owner's «Повторить» forgets one.
//! - `health.json`: the new version only — healthy on its first connection to the server, quit when
//!   it exits cleanly. The watchdog only reads it.
//! - `check.json`: the updater's loop only, after each check that got an answer ([`LastCheck`]). A
//!   file of its own rather than a field of `state.json`: the loop checks while the watchdog of the
//!   update that started it may still be writing `state.json`, and two writers of one file would
//!   lose one's change.
//!
//! Never two writers at once: the old version writes before the watchdog starts, the watchdog writes
//! once at its end and only then starts the app it restores, and the app does not apply another
//! update while an attempt is in flight. Every write goes to a temporary file first and is renamed
//! over the old one, so a reader sees the old file or the new, never half of one.
//!
//! # Failures and retries ([`UpdateState::retry`])
//!
//! A rollback is a strike against that version. One strike: retried a day later. Two: skipped until
//! a newer version is published (the record is per version), or until the owner presses «Повторить».
//! A strike for «no health in time» is unverified — the network may have been down, not the version
//! — and the version put back decides: if it reaches the server within two minutes the strike stands;
//! if it cannot either, the strike is taken back and the update retried an hour later.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use semver::Version;
use serde::{Deserialize, Serialize};

pub(crate) const STATE_FILE: &str = "state.json";
pub(crate) const HEALTH_FILE: &str = "health.json";
pub(crate) const CHECK_FILE: &str = "check.json";

/// Strikes after which a version is skipped until a newer one (or the owner's «Повторить»).
pub(crate) const MAX_STRIKES: u32 = 2;
/// The wait after a strike.
pub(crate) const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(24 * 3600);
/// The wait after an inconclusive rollback (the PC could not reach the server with either version).
pub(crate) const RETRY_AFTER_INCONCLUSIVE: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UpdateState {
    /// The update in flight: the exe has been (or is about to be) swapped, and the new version has
    /// not yet proved itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) attempt: Option<Attempt>,
    /// Failed versions, by version.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) failures: BTreeMap<String, Failure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Attempt {
    pub(crate) from: String,
    pub(crate) to: String,
    /// The exe swapped in place — the one autostart and the owner start.
    pub(crate) exe: PathBuf,
    /// The copy of the old exe the watchdog runs from and a rollback restores.
    pub(crate) backup: PathBuf,
    /// SHA-256 (upper hex) of the backup and of the new exe.
    pub(crate) backup_sha256: String,
    pub(crate) new_sha256: String,
    pub(crate) started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Failure {
    pub(crate) strikes: u32,
    pub(crate) last_at_ms: u64,
    /// The last rollback's reason (`RollbackReason::as_str`), for the log.
    pub(crate) reason: String,
    /// The last strike waits for the restored version's verdict ([`UpdateState::settle`]).
    #[serde(default)]
    pub(crate) unverified: bool,
}

/// What the new version reports to the watchdog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Health {
    pub(crate) version: String,
    pub(crate) pid: u32,
    /// When it first connected to the server (with its window thread answering).
    #[serde(default)]
    pub(crate) healthy_at_ms: Option<u64>,
    /// Its last heartbeat during the probation: rewritten every few seconds while its window thread
    /// answers. The watchdog goes by whether it changes, not by the clock.
    #[serde(default)]
    pub(crate) beat_at_ms: Option<u64>,
    /// When it exited cleanly (the owner's «Выход», Windows shutting down): not a crash.
    #[serde(default)]
    pub(crate) quit_at_ms: Option<u64>,
}

impl Health {
    /// Whether this report is from `pid` running `version`.
    pub(crate) fn is_from(&self, version: &str, pid: u32) -> bool {
        self.version == version && self.pid == pid
    }
}

/// The last check that got an answer from the server. The Settings section shows
/// «Последняя версия · проверено в 16:50» from it at the next start, before that run's own first
/// check — without it a fresh start would show nothing at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LastCheck {
    /// When the answer came, Unix ms.
    pub(crate) at_ms: u64,
    /// The version that asked.
    pub(crate) version: String,
    /// The version the manifest named, newer or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) latest: Option<String>,
    /// Nothing newer than `version` was offered.
    pub(crate) up_to_date: bool,
}

impl LastCheck {
    /// Whether it still tells `me` that it is up to date: it was `me`'s own check, and it found
    /// nothing newer. Another version's answer says nothing about this one.
    pub(crate) fn says_up_to_date(&self, me: &str) -> bool {
        self.version == me && self.up_to_date
    }
}

/// Whether to try a version now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Retry {
    Now,
    /// Not before this time (Unix ms).
    At(u64),
    /// Skipped: [`MAX_STRIKES`] reached.
    Never,
}

/// What a verdict on an unverified strike did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Settled {
    /// This version reached the server: the network was fine, the strike stands.
    Confirmed { strikes: u32 },
    /// This version could not reach the server either: the strike is taken back.
    Inconclusive { strikes: u32 },
}

impl UpdateState {
    pub(crate) fn retry(&self, version: &str, now_ms: u64) -> Retry {
        let Some(f) = self.failures.get(version) else {
            return Retry::Now;
        };
        if f.strikes >= MAX_STRIKES {
            return Retry::Never;
        }
        let wait = if f.strikes == 0 {
            RETRY_AFTER_INCONCLUSIVE
        } else {
            RETRY_AFTER_FAILURE
        };
        let at = f.last_at_ms.saturating_add(wait.as_millis() as u64);
        if now_ms >= at {
            Retry::Now
        } else {
            Retry::At(at)
        }
    }

    /// A strike against `version`; returns the strikes now.
    pub(crate) fn record_failure(
        &mut self,
        version: &str,
        reason: &str,
        unverified: bool,
        now_ms: u64,
    ) -> u32 {
        let f = self
            .failures
            .entry(version.to_string())
            .or_insert_with(|| Failure {
                strikes: 0,
                last_at_ms: now_ms,
                reason: String::new(),
                unverified: false,
            });
        f.strikes += 1;
        f.last_at_ms = now_ms;
        f.reason = reason.to_string();
        f.unverified = unverified;
        f.strikes
    }

    /// The restored version's verdict on an unverified strike against `version`: `reachable` —
    /// whether it reached the server within the verification window. `None` when there is nothing
    /// to settle.
    pub(crate) fn settle(
        &mut self,
        version: &str,
        reachable: bool,
        now_ms: u64,
    ) -> Option<Settled> {
        let f = self.failures.get_mut(version)?;
        if !f.unverified {
            return None;
        }
        f.unverified = false;
        if reachable {
            return Some(Settled::Confirmed { strikes: f.strikes });
        }
        f.strikes = f.strikes.saturating_sub(1);
        f.last_at_ms = now_ms;
        Some(Settled::Inconclusive { strikes: f.strikes })
    }

    /// The update to `version` proved itself: no attempt in flight, no record against it.
    pub(crate) fn succeed(&mut self, version: &str) {
        self.attempt = None;
        self.failures.remove(version);
    }

    /// The owner's «Повторить» on a version that failed: its record goes.
    pub(crate) fn forget(&mut self, version: &str) -> Option<Failure> {
        self.failures.remove(version)
    }

    /// Records of versions not newer than `current` (or not versions at all) are of no use: removed.
    pub(crate) fn prune(&mut self, current: &Version) -> Vec<String> {
        let stale: Vec<String> = self
            .failures
            .keys()
            .filter(|v| Version::parse(v).map_or(true, |v| v <= *current))
            .cloned()
            .collect();
        for v in &stale {
            self.failures.remove(v);
        }
        stale
    }
}

/// What a start of the app does about an attempt it finds in `state.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartupResolution {
    /// No attempt; or one a live watchdog is handling for another process.
    Nothing,
    /// This is the new version and has not proved itself yet: report health on the first connection.
    /// `need_watchdog`: none is alive — start one to supervise this process.
    OnProbation { need_watchdog: bool },
    /// This is the new version and it proved itself before (the watchdog did not get to record it:
    /// a reboot during the probation): record the success.
    Confirmed,
    /// This is the old version, and the attempt was neither finished nor rolled back by a watchdog:
    /// record it as a failure and clear it.
    Interrupted,
    /// A version that is neither end of the attempt: clear it.
    Stale,
}

/// `me`: this build's version; `health`: `health.json` as read; `watchdog_alive`: whether a
/// watchdog holds its lock; `rolled_back`: this start is the watchdog's restore.
pub(crate) fn resolve_startup(
    attempt: Option<&Attempt>,
    me: &str,
    health: Option<&Health>,
    watchdog_alive: bool,
    rolled_back: bool,
) -> StartupResolution {
    let Some(a) = attempt else {
        return StartupResolution::Nothing;
    };
    if a.to == me {
        if watchdog_alive {
            return StartupResolution::OnProbation {
                need_watchdog: false,
            };
        }
        let proved = health.is_some_and(|h| h.version == me && h.healthy_at_ms.is_some());
        return if proved {
            StartupResolution::Confirmed
        } else {
            StartupResolution::OnProbation {
                need_watchdog: true,
            }
        };
    }
    if watchdog_alive {
        // The watchdog owns the attempt; this process is some other start (the owner's double-click
        // while it works), which single-instance deals with.
        return StartupResolution::Nothing;
    }
    if a.from == me && !rolled_back {
        return StartupResolution::Interrupted;
    }
    StartupResolution::Stale
}

/// Read `state.json` in `dir`. A missing file is an empty state; an unreadable one is an error the
/// caller logs before starting from an empty state (a broken file must not block updates forever).
pub(crate) fn load_state(dir: &Path) -> Result<UpdateState, String> {
    load_json(&dir.join(STATE_FILE)).map(Option::unwrap_or_default)
}

pub(crate) fn save_state(dir: &Path, state: &UpdateState) -> Result<(), String> {
    save_json(&dir.join(STATE_FILE), state)
}

pub(crate) fn load_health(dir: &Path) -> Result<Option<Health>, String> {
    load_json(&dir.join(HEALTH_FILE))
}

pub(crate) fn save_health(dir: &Path, health: &Health) -> Result<(), String> {
    save_json(&dir.join(HEALTH_FILE), health)
}

/// Read `check.json` in `dir`: `None` when there is none yet.
pub(crate) fn load_check(dir: &Path) -> Result<Option<LastCheck>, String> {
    load_json(&dir.join(CHECK_FILE))
}

pub(crate) fn save_check(dir: &Path, check: &LastCheck) -> Result<(), String> {
    save_json(&dir.join(CHECK_FILE), check)
}

/// Remove `health.json` (a new attempt starts with none). `Ok(false)`: there was none.
pub(crate) fn clear_health(dir: &Path) -> Result<bool, String> {
    let path = dir.join(HEALTH_FILE);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Write to a fresh temporary name beside `path`, then rename it over `path`.
fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|e| format!("serialize: {e}"))?;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no folder", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        // The temporary file is ours and useless now.
        let _ = std::fs::remove_file(&tmp);
        format!("rename {} to {}: {e}", tmp.display(), path.display())
    })
}

/// Now, as Unix milliseconds.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: u64 = 3_600_000;
    const T0: u64 = 1_790_000_000_000;

    fn attempt() -> Attempt {
        Attempt {
            from: "0.1.0".into(),
            to: "0.1.1".into(),
            exe: PathBuf::from(r"C:\AFKLink.exe"),
            backup: PathBuf::from(r"C:\updates\previous\AFKLink-0.1.0.exe"),
            backup_sha256: "AA".into(),
            new_sha256: "BB".into(),
            started_at_ms: T0,
        }
    }

    fn healthy(version: &str) -> Health {
        Health {
            version: version.into(),
            pid: 7,
            healthy_at_ms: Some(T0),
            beat_at_ms: Some(T0),
            quit_at_ms: None,
        }
    }

    #[test]
    fn one_strike_waits_a_day_two_skip_the_version() {
        let mut s = UpdateState::default();
        assert_eq!(s.retry("0.1.1", T0), Retry::Now);

        assert_eq!(s.record_failure("0.1.1", "exited", false, T0), 1);
        assert_eq!(s.retry("0.1.1", T0 + HOUR), Retry::At(T0 + 24 * HOUR));
        assert_eq!(s.retry("0.1.1", T0 + 24 * HOUR), Retry::Now);
        // Another version is not affected.
        assert_eq!(s.retry("0.1.2", T0), Retry::Now);

        assert_eq!(
            s.record_failure("0.1.1", "no_health", false, T0 + 25 * HOUR),
            2
        );
        assert_eq!(s.retry("0.1.1", T0 + 1000 * HOUR), Retry::Never);
        // The owner's «Повторить»: the record goes, and it is tried now.
        assert!(s.forget("0.1.1").is_some());
        assert_eq!(s.retry("0.1.1", T0 + 26 * HOUR), Retry::Now);
    }

    #[test]
    fn an_unverified_strike_stands_if_the_old_version_reaches_the_server() {
        let mut s = UpdateState::default();
        s.record_failure("0.1.1", "no_health", true, T0);
        assert_eq!(
            s.settle("0.1.1", true, T0 + 60_000),
            Some(Settled::Confirmed { strikes: 1 })
        );
        assert_eq!(s.retry("0.1.1", T0 + HOUR), Retry::At(T0 + 24 * HOUR));
        // Settled once: nothing more to settle.
        assert_eq!(s.settle("0.1.1", false, T0 + 120_000), None);
    }

    #[test]
    fn a_rollback_while_offline_is_not_counted_and_retried_within_the_hour() {
        let mut s = UpdateState::default();
        s.record_failure("0.1.1", "no_health", true, T0);
        let later = T0 + 120_000;
        assert_eq!(
            s.settle("0.1.1", false, later),
            Some(Settled::Inconclusive { strikes: 0 })
        );
        assert_eq!(s.retry("0.1.1", later), Retry::At(later + HOUR));
        assert_eq!(s.retry("0.1.1", later + HOUR), Retry::Now);
        // Offline twice is never a skip: each is taken back.
        s.record_failure("0.1.1", "no_health", true, later + HOUR);
        s.settle("0.1.1", false, later + 2 * HOUR);
        assert_ne!(s.retry("0.1.1", later + 2 * HOUR), Retry::Never);
        // A crash is verified at once and counts.
        s.record_failure("0.1.1", "exited", false, later + 3 * HOUR);
        assert_eq!(s.settle("0.1.1", false, later + 3 * HOUR), None);
        assert_eq!(s.failures["0.1.1"].strikes, 1);
    }

    #[test]
    fn success_clears_the_attempt_and_the_record_and_old_records_are_pruned() {
        let mut s = UpdateState {
            attempt: Some(attempt()),
            ..Default::default()
        };
        s.record_failure("0.1.1", "exited", false, T0);
        s.record_failure("0.1.3", "exited", false, T0);
        s.succeed("0.1.1");
        assert_eq!(s.attempt, None);
        assert!(!s.failures.contains_key("0.1.1"));

        s.record_failure("0.0.9", "exited", false, T0);
        s.failures.insert(
            "junk".into(),
            Failure {
                strikes: 1,
                last_at_ms: T0,
                reason: "x".into(),
                unverified: false,
            },
        );
        let mut pruned = s.prune(&Version::parse("0.1.1").unwrap());
        pruned.sort();
        assert_eq!(pruned, ["0.0.9", "junk"]);
        assert_eq!(s.failures.keys().collect::<Vec<_>>(), ["0.1.3"]);
    }

    #[test]
    fn a_start_settles_what_it_finds() {
        use StartupResolution::*;
        let a = attempt();
        assert_eq!(resolve_startup(None, "0.1.1", None, false, false), Nothing);
        // The new version, started by (or under) a live watchdog.
        assert_eq!(
            resolve_startup(Some(&a), "0.1.1", None, true, false),
            OnProbation {
                need_watchdog: false
            }
        );
        // The new version after a reboot in the middle: no watchdog, no health — start one.
        assert_eq!(
            resolve_startup(Some(&a), "0.1.1", None, false, false),
            OnProbation {
                need_watchdog: true
            }
        );
        // …but it had proved itself before the reboot.
        assert_eq!(
            resolve_startup(Some(&a), "0.1.1", Some(&healthy("0.1.1")), false, false),
            Confirmed
        );
        // Health of another version proves nothing.
        assert_eq!(
            resolve_startup(Some(&a), "0.1.1", Some(&healthy("0.1.0")), false, false),
            OnProbation {
                need_watchdog: true
            }
        );
        // The old version, with no watchdog to explain it.
        assert_eq!(
            resolve_startup(Some(&a), "0.1.0", None, false, false),
            Interrupted
        );
        // The old version the watchdog put back (it clears the attempt; one left is stale).
        assert_eq!(resolve_startup(Some(&a), "0.1.0", None, false, true), Stale);
        // The old version started while the watchdog works: its business.
        assert_eq!(
            resolve_startup(Some(&a), "0.1.0", None, true, false),
            Nothing
        );
        assert_eq!(
            resolve_startup(Some(&a), "0.2.0", None, false, false),
            Stale
        );
    }

    #[test]
    fn files_round_trip_and_a_broken_one_is_an_error() {
        let dir =
            std::env::temp_dir().join(format!("afklink-update-state-{}", uuid::Uuid::new_v4()));
        assert_eq!(load_state(&dir).unwrap(), UpdateState::default());
        assert_eq!(load_health(&dir).unwrap(), None);

        let mut s = UpdateState {
            attempt: Some(attempt()),
            ..Default::default()
        };
        s.record_failure("0.1.1", "no_health", true, T0);
        save_state(&dir, &s).unwrap();
        assert_eq!(load_state(&dir).unwrap(), s);
        save_state(&dir, &UpdateState::default()).unwrap();
        assert_eq!(load_state(&dir).unwrap(), UpdateState::default());
        // Only the file itself is left: no temporary names.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);

        save_health(&dir, &healthy("0.1.1")).unwrap();
        let h = load_health(&dir).unwrap().unwrap();
        assert!(h.is_from("0.1.1", 7) && !h.is_from("0.1.1", 8) && !h.is_from("0.1.0", 7));
        assert!(clear_health(&dir).unwrap());
        assert!(!clear_health(&dir).unwrap());

        std::fs::write(dir.join(STATE_FILE), "{ not json").unwrap();
        assert!(load_state(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_last_check_is_kept_and_speaks_only_for_the_version_that_made_it() {
        let dir =
            std::env::temp_dir().join(format!("afklink-update-check-{}", uuid::Uuid::new_v4()));
        assert_eq!(load_check(&dir).unwrap(), None);
        let last = LastCheck {
            at_ms: T0,
            version: "0.1.1".into(),
            latest: Some("0.1.1".into()),
            up_to_date: true,
        };
        save_check(&dir, &last).unwrap();
        assert_eq!(load_check(&dir).unwrap(), Some(last.clone()));
        // A file of its own: state.json is the watchdog's too, and stays untouched.
        assert!(!dir.join(STATE_FILE).exists());

        assert!(last.says_up_to_date("0.1.1"));
        // After an update the old version's answer is not this one's.
        assert!(!last.says_up_to_date("0.1.2"));
        let found_newer = LastCheck {
            latest: Some("0.1.2".into()),
            up_to_date: false,
            ..last
        };
        assert!(!found_newer.says_up_to_date("0.1.1"));

        std::fs::write(dir.join(CHECK_FILE), "{ not json").unwrap();
        assert!(load_check(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
