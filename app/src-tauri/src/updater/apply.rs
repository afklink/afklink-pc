//! Putting a verified update in place of the running exe, and putting the old one back.
//!
//! [`apply`] runs in the old version, on a blocking thread:
//!
//! 1. A backup of the running exe: `updates\previous\AFKLink-<old>.exe`, hash-checked. Older backups
//!    go — one previous version is kept. The watchdog runs from this copy, and a rollback restores it.
//! 2. The download staged as a [`StagedFile`] (`CREATE_NEW`, reopened read-only with
//!    `FILE_SHARE_READ`, hashed again through that handle and held while it is copied).
//! 3. `state.json` gets the attempt.
//! 4. A last look that nobody connected meanwhile, then `self_replace`: the running exe is renamed
//!    aside (Windows allows renaming a running image, not overwriting it) and the staged copy takes
//!    its name. The file at the exe's path is then hashed: it must be the update.
//! 5. The watchdog is started from the backup and must answer «ready» on its stdout within
//!    [`WATCHDOG_ACK_TIMEOUT`]; then this process exits and the watchdog takes it from there.
//!
//! Anything failing from step 4 on puts the old exe back from the backup ([`restore_exe`]) before the
//! error returns — the exe's path is never left without a working AFKLink — and this process keeps
//! running as the old version.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use semver::Version;

use super::launch::{self, WatchTarget, WatchdogArgs};
use super::policy::Defer;
use super::state::{self, Attempt};
use crate::staged_file::{sha256_of_file, StagedFile};

/// The watchdog's time to start and answer «ready».
pub(crate) const WATCHDOG_ACK_TIMEOUT: Duration = Duration::from_secs(20);
/// What the watchdog prints on its stdout once it has taken over.
pub(crate) const WATCHDOG_READY: &str = "ready";
/// How long restoring an exe keeps retrying while Windows (or an antivirus scan) still holds the
/// file of a process that just ended.
pub(crate) const RESTORE_DEADLINE: Duration = Duration::from_secs(30);

const STAGING_PREFIX: &str = "staging-";
pub(crate) const PREVIOUS_DIR: &str = "previous";

/// The updater's folders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dirs {
    /// `%LOCALAPPDATA%\AFKLink\updates`: `state.json`, `health.json`, staging folders.
    pub(crate) updates: PathBuf,
}

impl Dirs {
    /// `%LOCALAPPDATA%\AFKLink\updates`, created if missing. `%LOCALAPPDATA%` rather than the
    /// roaming `%APPDATA%`: executables are not something to roam.
    pub(crate) fn locate() -> Result<Self, String> {
        let base = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "LOCALAPPDATA is not set".to_string())?;
        let updates = base.join(afklink_core::paths::DIR_NAME).join("updates");
        std::fs::create_dir_all(&updates)
            .map_err(|e| format!("create {}: {e}", updates.display()))?;
        Ok(Self { updates })
    }

    pub(crate) fn previous(&self) -> PathBuf {
        self.updates.join(PREVIOUS_DIR)
    }
}

/// The backup's name for a version.
pub(crate) fn backup_name(version: &Version) -> String {
    format!("AFKLink-{version}.exe")
}

/// What [`apply`] needs.
pub(crate) struct Plan<'a> {
    pub(crate) from: &'a Version,
    pub(crate) to: &'a Version,
    /// The downloaded exe, signature and manifest checks passed.
    pub(crate) bytes: &'a [u8],
    /// Its SHA-256, upper hex.
    pub(crate) sha256: &'a str,
    /// The running exe.
    pub(crate) exe: PathBuf,
    pub(crate) dirs: &'a Dirs,
    /// The main window is hidden: the new version starts hidden too.
    pub(crate) hidden: bool,
    pub(crate) timeout: Duration,
}

/// How [`apply`] ended.
#[derive(Debug)]
pub(crate) enum Applied {
    /// The watchdog has taken over: exit now.
    HandedOver { watchdog_pid: u32 },
    /// The last look before the swap found something in the way — someone connecting, a pairing,
    /// the PC paused — said by `defer`, for the window: nothing was changed, try again later.
    Refused { defer: Defer, why: String },
    /// Nothing is changed on disk (or it was put back): keep running. `before_swap`: the exe was
    /// never touched — a condition changed, or preparing failed — so it is not the update's failure.
    Aborted { reason: String, before_swap: bool },
}

/// Apply the update ([module docs](self)). `still_clear` is asked just before the exe is swapped:
/// `Err((defer, why))` stops everything (someone connected meanwhile, the PC paused) with
/// [`Applied::Refused`].
pub(crate) fn apply(
    plan: &Plan<'_>,
    still_clear: &dyn Fn() -> Result<(), (Defer, String)>,
) -> Applied {
    let abort = |reason: String| Applied::Aborted {
        reason,
        before_swap: true,
    };

    // 1. The backup.
    let old_sha256 = match sha256_of_file(&plan.exe) {
        Ok((hash, len)) => {
            tracing::debug!(exe = %plan.exe.display(), sha256 = %hash, bytes = len, "update: running exe hashed");
            hash
        }
        Err(e) => {
            return abort(format!(
                "the running exe {} not read: {e}",
                plan.exe.display()
            ))
        }
    };
    let backup = match write_backup(plan.dirs, plan.from, &plan.exe, &old_sha256) {
        Ok(path) => path,
        Err(e) => return abort(e),
    };

    // 2. The staged update.
    let staged = match StagedFile::stage_in(
        &plan.dirs.updates,
        STAGING_PREFIX,
        &backup_name(plan.to),
        plan.bytes,
        plan.sha256,
        "update",
        "refusing to install it",
    ) {
        Ok(staged) => staged,
        Err(e) => return abort(e),
    };

    // 3. The attempt, on record before anything changes.
    let attempt = Attempt {
        from: plan.from.to_string(),
        to: plan.to.to_string(),
        exe: plan.exe.clone(),
        backup: backup.clone(),
        backup_sha256: old_sha256.clone(),
        new_sha256: plan.sha256.to_ascii_uppercase(),
        started_at_ms: state::now_ms(),
    };
    if let Err(e) = record_attempt(plan.dirs, attempt) {
        return abort(e);
    }
    let unrecord = |why: &str| {
        // The attempt is over before it began: nothing for a watchdog or a later start to settle.
        if let Err(e) = update_state(plan.dirs, |s| s.attempt = None) {
            tracing::warn!("update: attempt not cleared from state.json after {why}: {e}");
        }
    };

    // 4. The swap.
    if let Err((defer, why)) = still_clear() {
        unrecord("a last-moment refusal");
        return Applied::Refused { defer, why };
    }
    tracing::info!(
        exe = %plan.exe.display(),
        from = %plan.from,
        to = %plan.to,
        staged = %staged.path().display(),
        "update: swapping the exe (self-replace)"
    );
    let swapped = self_replace::self_replace(staged.path());
    drop(staged);
    if let Err(e) = swapped {
        let reason = format!("self-replace failed: {e}");
        tracing::error!(exe = %plan.exe.display(), "update: {reason}; checking the exe is intact");
        let restored = ensure_exe(&plan.exe, &backup, &old_sha256);
        unrecord("a failed swap");
        return Applied::Aborted {
            reason: format!("{reason}; {restored}"),
            before_swap: false,
        };
    }
    match sha256_of_file(&plan.exe) {
        Ok((hash, _)) if hash.eq_ignore_ascii_case(plan.sha256) => {
            tracing::info!(exe = %plan.exe.display(), sha256 = %hash, "update: the exe is now {}", plan.to);
        }
        other => {
            let seen = match other {
                Ok((hash, len)) => format!("SHA-256 {hash}, {len} bytes"),
                Err(e) => format!("not readable: {e}"),
            };
            tracing::error!(exe = %plan.exe.display(), %seen, "update: the swapped exe is not the update; putting the old one back");
            let restored = restore_logged(&backup, &plan.exe, &old_sha256);
            unrecord("a wrong swap");
            return Applied::Aborted {
                reason: format!("the swapped exe is not the update ({seen}); {restored}"),
                before_swap: false,
            };
        }
    }

    // 5. The watchdog.
    let args = WatchdogArgs {
        expect: plan.to.clone(),
        from: plan.from.clone(),
        exe: plan.exe.clone(),
        target: WatchTarget::Launch {
            parent: std::process::id(),
        },
        timeout: plan.timeout,
        hidden: plan.hidden,
    };
    match start_watchdog(&backup, &args, &plan.dirs.updates) {
        Ok(pid) => Applied::HandedOver { watchdog_pid: pid },
        Err(e) => {
            tracing::error!(
                "update: the watchdog did not take over ({e}); putting the old exe back"
            );
            let restored = restore_logged(&backup, &plan.exe, &old_sha256);
            unrecord("a watchdog that did not start");
            Applied::Aborted {
                reason: format!("watchdog: {e}; {restored}"),
                before_swap: false,
            }
        }
    }
}

/// Copy the running exe to `previous\AFKLink-<version>.exe` (via a temporary name, hash-checked),
/// after removing every other file there. Returns the backup's path.
fn write_backup(
    dirs: &Dirs,
    version: &Version,
    exe: &Path,
    sha256: &str,
) -> Result<PathBuf, String> {
    let dir = dirs.previous();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let name = backup_name(version);
    let path = dir.join(&name);
    prune_previous(&dir, &name);
    if let Ok((hash, _)) = sha256_of_file(&path) {
        if hash.eq_ignore_ascii_case(sha256) {
            tracing::debug!(backup = %path.display(), "update: backup of this exe already in place");
            return Ok(path);
        }
    }
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        std::fs::copy(exe, &tmp)
            .map_err(|e| format!("copy {} to {}: {e}", exe.display(), tmp.display()))?;
        let (hash, len) =
            sha256_of_file(&tmp).map_err(|e| format!("read back {}: {e}", tmp.display()))?;
        if !hash.eq_ignore_ascii_case(sha256) {
            return Err(format!(
                "the backup reads back as SHA-256 {hash} ({len} bytes), the exe is {sha256}"
            ));
        }
        std::fs::rename(&tmp, &path)
            .map_err(|e| format!("rename {} to {}: {e}", tmp.display(), path.display()))
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("backup not written: {e}"));
    }
    tracing::info!(backup = %path.display(), sha256, "update: backup of the running exe written");
    Ok(path)
}

/// Remove everything in `previous\` but `keep`: one previous version is kept. A file in use (a
/// watchdog still running from it) stays, at `debug`.
fn prune_previous(dir: &Path, keep: &str) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), "update: old backups not listed: {e}");
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == keep || !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => tracing::info!(file = %name, "update: older backup removed"),
            Err(e) => {
                tracing::debug!(file = %name, "update: older backup not removed (in use?): {e}")
            }
        }
    }
}

fn record_attempt(dirs: &Dirs, attempt: Attempt) -> Result<(), String> {
    if let Err(e) = state::clear_health(&dirs.updates) {
        return Err(format!("stale health.json not removed: {e}"));
    }
    tracing::debug!(?attempt, "update: attempt recorded in state.json");
    update_state(dirs, |s| s.attempt = Some(attempt))
}

/// Read, change and write `state.json`. An unreadable file is started over (it must not block
/// updates forever), with a warning.
pub(crate) fn update_state(
    dirs: &Dirs,
    change: impl FnOnce(&mut state::UpdateState),
) -> Result<(), String> {
    let mut s = state::load_state(&dirs.updates).unwrap_or_else(|e| {
        tracing::warn!("update: {e}; starting state.json over");
        state::UpdateState::default()
    });
    change(&mut s);
    state::save_state(&dirs.updates, &s)
}

/// After a failed `self_replace`: make sure the exe's path holds the old exe — it may have been
/// renamed aside and not replaced. Says what it found and did.
fn ensure_exe(exe: &Path, backup: &Path, sha256: &str) -> String {
    match sha256_of_file(exe) {
        Ok((hash, _)) if hash.eq_ignore_ascii_case(sha256) => "the exe is intact".to_string(),
        seen => {
            tracing::warn!(exe = %exe.display(), ?seen, "update: the exe's path does not hold the old exe after the failed swap");
            restore_logged(backup, exe, sha256)
        }
    }
}

fn restore_logged(backup: &Path, exe: &Path, sha256: &str) -> String {
    match restore_exe(backup, exe, sha256, RESTORE_DEADLINE, |from, to| {
        std::fs::rename(from, to)
    }) {
        Ok(()) => {
            tracing::info!(exe = %exe.display(), backup = %backup.display(), "update: the old exe is back in place");
            "the old exe is back in place".to_string()
        }
        Err(e) => {
            tracing::error!(exe = %exe.display(), backup = %backup.display(), "update: the old exe could NOT be put back: {e}");
            format!("the old exe could not be put back: {e}")
        }
    }
}

/// Put `backup` at `target`: copied beside `target` under a temporary name, hash-checked against
/// `sha256`, then renamed over it. While the rename is refused (the file of a process that just ended
/// is still held), it retries until `deadline`; halfway there it first moves `target` aside
/// (`.<name>.failed-<uuid>.old`, removed when possible — Windows lets a file in use be renamed, not
/// replaced). `rename` is `std::fs::rename` outside tests.
pub(crate) fn restore_exe(
    backup: &Path,
    target: &Path,
    sha256: &str,
    deadline: Duration,
    rename: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), String> {
    let dir = target
        .parent()
        .ok_or_else(|| format!("{} has no folder", target.display()))?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.restore-{}.tmp", uuid::Uuid::new_v4()));
    std::fs::copy(backup, &tmp)
        .map_err(|e| format!("copy {} to {}: {e}", backup.display(), tmp.display()))?;
    let cleanup = |why: String| {
        let _ = std::fs::remove_file(&tmp);
        why
    };
    match sha256_of_file(&tmp) {
        Ok((hash, _)) if hash.eq_ignore_ascii_case(sha256) => {}
        Ok((hash, len)) => {
            return Err(cleanup(format!(
                "the backup {} is SHA-256 {hash} ({len} bytes), expected {sha256}",
                backup.display()
            )))
        }
        Err(e) => return Err(cleanup(format!("read back {}: {e}", tmp.display()))),
    }

    let started = Instant::now();
    let mut aside: Option<PathBuf> = None;
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match rename(&tmp, target) {
            Ok(()) => break,
            Err(e) if started.elapsed() >= deadline => {
                return Err(cleanup(format!(
                    "rename over {} refused for {} s ({attempts} attempts): {e}",
                    target.display(),
                    deadline.as_secs()
                )));
            }
            Err(e) => {
                tracing::debug!(attempts, target = %target.display(), "restore: rename refused: {e}");
                if aside.is_none() && started.elapsed() >= deadline / 2 && target.exists() {
                    let moved = dir.join(format!(".{name}.failed-{}.old", uuid::Uuid::new_v4()));
                    match rename(target, &moved) {
                        Ok(()) => {
                            tracing::info!(target = %target.display(), aside = %moved.display(), "restore: the file in the way moved aside");
                            aside = Some(moved);
                        }
                        Err(e) => {
                            tracing::debug!("restore: the file in the way not moved aside: {e}")
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    if let Some(moved) = aside {
        if let Err(e) = std::fs::remove_file(&moved) {
            tracing::info!(file = %moved.display(), "restore: the replaced file stays until it is free ({e}); a later start removes it");
        }
    }
    match sha256_of_file(target) {
        Ok((hash, _)) if hash.eq_ignore_ascii_case(sha256) => Ok(()),
        Ok((hash, len)) => Err(format!(
            "{} reads back as SHA-256 {hash} ({len} bytes)",
            target.display()
        )),
        Err(e) => Err(format!("read back {}: {e}", target.display())),
    }
}

/// Leftovers of a restore beside `exe` (`.<name>.failed-*.old`, `.<name>.restore-*.tmp`): removed
/// at startup where not in use any more.
pub(crate) fn remove_restore_leftovers(exe: &Path) {
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) else {
        return;
    };
    let name = name.to_string_lossy();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let ours = file.strip_prefix(&format!(".{name}.")).is_some_and(|rest| {
            (rest.starts_with("failed-") && rest.ends_with(".old"))
                || (rest.starts_with("restore-") && rest.ends_with(".tmp"))
        });
        if !ours {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => tracing::info!(file = %file, "update: leftover of a restore removed"),
            Err(e) => {
                tracing::debug!(file = %file, "update: leftover of a restore not removed yet: {e}")
            }
        }
    }
}

/// Staging folders a crashed apply left in `updates\`: removed at startup.
pub(crate) fn remove_stale_staging(dirs: &Dirs) {
    let Ok(entries) = std::fs::read_dir(&dirs.updates) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(STAGING_PREFIX) || !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => tracing::info!(dir = %name, "update: stale staging folder removed"),
            Err(e) => tracing::warn!(dir = %name, "update: stale staging folder not removed: {e}"),
        }
    }
}

/// Start the watchdog from `exe` with `args` and wait for its «ready». Returns its process id. On
/// failure the watchdog, if it started, is ended.
pub(crate) fn start_watchdog(exe: &Path, args: &WatchdogArgs, cwd: &Path) -> Result<u32, String> {
    let mut command = Command::new(exe);
    command
        .args(launch::watchdog_args(args))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        command.creation_flags(CREATE_NO_WINDOW.0 | CREATE_NEW_PROCESS_GROUP.0);
    }
    tracing::info!(watchdog = %exe.display(), args = ?launch::watchdog_args(args), "update: starting the watchdog");
    let mut child = command
        .spawn()
        .map_err(|e| format!("start {}: {e}", exe.display()))?;
    let pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err("no stdout from the watchdog".to_string());
    };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let read = std::io::BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send(read.map(|_| line));
    });
    match rx.recv_timeout(WATCHDOG_ACK_TIMEOUT) {
        Ok(Ok(line)) if line.trim() == WATCHDOG_READY => {
            tracing::info!(pid, "update: the watchdog is ready");
            Ok(pid)
        }
        other => {
            let seen = match other {
                Ok(Ok(line)) => format!("it said {:?}", line.trim()),
                Ok(Err(e)) => format!("its stdout failed: {e}"),
                Err(_) => format!("no answer in {} s", WATCHDOG_ACK_TIMEOUT.as_secs()),
            };
            let status = match child.try_wait() {
                Ok(Some(status)) => format!("exited with {status}"),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    "ended by us".to_string()
                }
                Err(e) => format!("state unknown: {e}"),
            };
            Err(format!(
                "the watchdog (pid {pid}) is not ready: {seen}; {status}"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::staged_file::sha256_of;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "afklink-apply-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_restore_puts_the_backup_in_place_and_checks_it() {
        let dir = scratch("restore");
        let backup = dir.join("backup.exe");
        let target = dir.join("AFKLink.exe");
        std::fs::write(&backup, b"old version").unwrap();
        std::fs::write(&target, b"broken new version").unwrap();
        let sha = sha256_of(b"old version");

        restore_exe(&backup, &target, &sha, Duration::from_secs(5), |a, b| {
            std::fs::rename(a, b)
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"old version");
        // Only the two files: no temporaries left.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        // The exe's path may be empty too (a swap that renamed it aside and failed).
        std::fs::remove_file(&target).unwrap();
        restore_exe(&backup, &target, &sha, Duration::from_secs(5), |a, b| {
            std::fs::rename(a, b)
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"old version");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_backup_that_is_not_the_old_exe_is_never_put_in_place() {
        let dir = scratch("wrong-backup");
        let backup = dir.join("backup.exe");
        let target = dir.join("AFKLink.exe");
        std::fs::write(&backup, b"tampered").unwrap();
        std::fs::write(&target, b"current").unwrap();
        let err = restore_exe(
            &backup,
            &target,
            &sha256_of(b"old version"),
            Duration::from_secs(1),
            |a, b| std::fs::rename(a, b),
        )
        .unwrap_err();
        assert!(err.contains("expected"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"current");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_held_target_is_retried_then_moved_aside() {
        use std::cell::Cell;
        let dir = scratch("held");
        let backup = dir.join("backup.exe");
        let target = dir.join("AFKLink.exe");
        std::fs::write(&backup, b"old").unwrap();
        std::fs::write(&target, b"new, still held").unwrap();
        let sha = sha256_of(b"old");
        // The rename over the target is refused until the target has been moved aside, as for the
        // image of a process that has not quite let go.
        let moved = Cell::new(false);
        let rename = |from: &Path, to: &Path| {
            if to == target && !moved.get() {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            if from == target {
                moved.set(true);
            }
            std::fs::rename(from, to)
        };
        restore_exe(&backup, &target, &sha, Duration::from_secs(5), rename).unwrap();
        assert!(moved.get());
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        // The moved-aside file was removed (nothing held it really).
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);

        // Refused for good: an error in time, the target untouched, no temporary left.
        let never =
            |_: &Path, _: &Path| Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(restore_exe(&backup, &target, &sha, Duration::from_millis(600), never).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_backup_is_kept_and_leftovers_are_cleaned() {
        let root = scratch("backup");
        let dirs = Dirs {
            updates: root.join("updates"),
        };
        std::fs::create_dir_all(dirs.previous()).unwrap();
        std::fs::write(dirs.previous().join("AFKLink-0.0.9.exe"), b"older").unwrap();
        let exe = root.join("AFKLink.exe");
        std::fs::write(&exe, b"running 0.1.0").unwrap();
        let sha = sha256_of(b"running 0.1.0");
        let v = Version::parse("0.1.0").unwrap();

        let path = write_backup(&dirs, &v, &exe, &sha).unwrap();
        assert_eq!(path, dirs.previous().join("AFKLink-0.1.0.exe"));
        assert_eq!(std::fs::read(&path).unwrap(), b"running 0.1.0");
        let names: Vec<_> = std::fs::read_dir(dirs.previous())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["AFKLink-0.1.0.exe"]);
        // Again: already there, kept.
        assert_eq!(write_backup(&dirs, &v, &exe, &sha).unwrap(), path);
        // An exe that changed under it (hash mismatch) is refused.
        assert!(write_backup(&dirs, &v, &exe, &sha256_of(b"other")).is_err());

        std::fs::create_dir_all(dirs.updates.join("staging-abc")).unwrap();
        std::fs::write(dirs.updates.join("staging-abc").join("x.exe"), b"x").unwrap();
        remove_stale_staging(&dirs);
        assert!(!dirs.updates.join("staging-abc").exists());

        std::fs::write(root.join(".AFKLink.exe.failed-1.old"), b"x").unwrap();
        std::fs::write(root.join(".AFKLink.exe.restore-1.tmp"), b"x").unwrap();
        std::fs::write(root.join(".Other.exe.failed-1.old"), b"x").unwrap();
        remove_restore_leftovers(&exe);
        assert!(!root.join(".AFKLink.exe.failed-1.old").exists());
        assert!(!root.join(".AFKLink.exe.restore-1.tmp").exists());
        assert!(root.join(".Other.exe.failed-1.old").exists(), "not ours");
        let _ = std::fs::remove_dir_all(&root);
    }
}
