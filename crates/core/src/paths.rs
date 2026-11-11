//! Config/identity storage location: `%APPDATA%\AFKLink\`, unless the process was told otherwise.
//!
//! Everything the agent keeps on disk — `config.json`, `identity.json`, the desktop app's logs —
//! lives under [`afklink_dir`]. The CLI's `--data-dir` moves all of it at once with
//! [`set_dir_override`], which is what makes a bench run a *different device*: its own identity, its
//! own device id, nothing shared with the owner's install. The desktop app never sets it.
//!
//! Before the product was renamed the directory was `%APPDATA%\Remoter`. [`migrate_legacy_dir`]
//! carries an install across once, at startup, before anything reads config or identity: the same
//! `identity.json` is the same device to the backend, so the owner's bindings survive the rename.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};

/// The data directory's name under `%APPDATA%`.
pub const DIR_NAME: &str = "AFKLink";

/// The data directory's name before the rename to AFKLink. Read only to migrate it
/// ([`migrate_legacy_dir`]) and to keep a bench run from using it ([`legacy_default_dir`]).
pub const LEGACY_DIR_NAME: &str = "Remoter";

/// What a migration by copy carries across besides `logs/`: the device itself. Anything else in
/// the legacy directory moves only with a rename.
const CARRIED_FILES: [&str; 2] = ["config.json", "identity.json"];

/// The desktop app's log directory inside the data directory.
const LOGS_DIR: &str = "logs";

/// Where [`afklink_dir`] points instead of `%APPDATA%\AFKLink`, once set.
static OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Put everything [`afklink_dir`] hands out under `dir`, for the rest of the process.
///
/// Call before anything reads config or identity: a config loaded earlier came from the default
/// place. Setting the same directory again is a no-op; a different one is refused, because two
/// halves of one run with two identities is exactly what this exists to prevent.
pub fn set_dir_override(dir: PathBuf) -> Result<()> {
    if let Some(existing) = OVERRIDE.get() {
        if *existing == dir {
            tracing::debug!(dir = %dir.display(), "data directory override set again, unchanged");
            return Ok(());
        }
        bail!(
            "the data directory is already {}; refusing to move it to {}",
            existing.display(),
            dir.display()
        );
    }
    let shown = dir.display().to_string();
    if let Err(lost) = OVERRIDE.set(dir) {
        bail!(
            "the data directory was set concurrently; {} was not applied",
            lost.display()
        );
    }
    tracing::debug!(dir = %shown, "data directory overridden for this process");
    Ok(())
}

/// The override in force, if any.
pub fn dir_override() -> Option<&'static Path> {
    OVERRIDE.get().map(PathBuf::as_path)
}

/// `%APPDATA%`, or `.` when `APPDATA` is unset (non-Windows dev).
fn appdata_base() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Config and identity then live wherever the process was started — a second device
            // identity, as far as the backend is concerned.
            tracing::warn!("APPDATA is not set; using the current directory for AFKLink's files");
            PathBuf::from(".")
        })
}

/// `%APPDATA%\AFKLink` — where the desktop app and an ordinary CLI run keep their files — whatever
/// the override says, and without creating it. Falls back to `.\AFKLink` when `APPDATA` is unset
/// (non-Windows dev).
pub fn default_dir() -> PathBuf {
    appdata_base().join(DIR_NAME)
}

/// `%APPDATA%\Remoter`, the data directory of a build from before the rename — the owner's device
/// until [`migrate_legacy_dir`] has moved it, and a copy of it after a migration by copy.
pub fn legacy_default_dir() -> PathBuf {
    appdata_base().join(LEGACY_DIR_NAME)
}

/// Returns the data directory, creating it if needed: the override when one is set, else
/// [`default_dir`].
pub fn afklink_dir() -> Result<PathBuf> {
    let dir = match OVERRIDE.get() {
        Some(dir) => dir.clone(),
        None => default_dir(),
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create config dir {}", dir.display()))?;
    Ok(dir)
}

/// What [`migrate_legacy_dir`] found and did.
///
/// Returned rather than logged: the migration runs before the log exists, because the config it
/// may move decides how the log is built. Call [`Migration::log`] once the subscriber is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Migration {
    /// A `--data-dir` override is in force: the owner's directories are not this run's to move.
    Overridden { dir: PathBuf },
    /// No legacy directory: a fresh install, or one migrated and cleaned up already.
    NothingToMigrate { dir: PathBuf, legacy: PathBuf },
    /// The new directory is already in use. A legacy one beside it (`legacy_left`) is left alone.
    AlreadyMigrated {
        dir: PathBuf,
        legacy: PathBuf,
        legacy_left: bool,
    },
    /// The legacy directory was renamed to the new name: everything in it moved at once.
    /// `entries` are its top-level names, for the log.
    Renamed {
        from: PathBuf,
        to: PathBuf,
        entries: Vec<String>,
    },
    /// The rename failed (typically a file inside is held open by a running older build), so
    /// `config.json`, `identity.json` and the log files were copied instead. The legacy directory
    /// is left as it was; `skipped` are log files that could not be copied, with why.
    Copied {
        from: PathBuf,
        to: PathBuf,
        rename_error: String,
        copied: Vec<String>,
        skipped: Vec<String>,
    },
    /// Neither worked. This run keeps using the legacy directory (`fallback`: it was made the
    /// override) so it is still the same device; the next start tries again.
    Failed {
        from: PathBuf,
        to: PathBuf,
        error: String,
        fallback: bool,
    },
}

impl Migration {
    /// Say what happened, at the level it deserves. File names only: `identity.json` holds the
    /// device's private key, and nothing here ever reads a file's contents.
    pub fn log(&self) {
        match self {
            Self::Overridden { dir } => tracing::debug!(
                dir = %dir.display(),
                "data directory migration skipped: --data-dir is in force"
            ),
            Self::NothingToMigrate { dir, legacy } => tracing::debug!(
                dir = %dir.display(),
                legacy = %legacy.display(),
                "no legacy data directory to migrate"
            ),
            Self::AlreadyMigrated {
                dir,
                legacy,
                legacy_left,
            } => tracing::debug!(
                dir = %dir.display(),
                legacy = %legacy.display(),
                legacy_left,
                "data directory already in use; nothing migrated{}",
                if *legacy_left {
                    " (the legacy directory beside it is left alone: delete it by hand once this install works)"
                } else {
                    ""
                }
            ),
            Self::Renamed { from, to, entries } => tracing::info!(
                from = %from.display(),
                to = %to.display(),
                entries = %entries.join(", "),
                "data directory migrated from the pre-AFKLink name: renamed"
            ),
            Self::Copied {
                from,
                to,
                rename_error,
                copied,
                skipped,
            } => {
                tracing::info!(
                    from = %from.display(),
                    to = %to.display(),
                    copied = %copied.join(", "),
                    skipped = skipped.len(),
                    "data directory migrated from the pre-AFKLink name: copied, because renaming \
                     failed ({rename_error}); the legacy directory is left in place — stop any older \
                     build still running from it, since it is the same device"
                );
                for s in skipped {
                    tracing::warn!(from = %from.display(), "data directory migration: {s}");
                }
            }
            Self::Failed {
                from,
                to,
                error,
                fallback,
            } => tracing::warn!(
                from = %from.display(),
                to = %to.display(),
                fallback,
                "data directory not migrated ({error}); {}",
                if *fallback {
                    "this run uses the legacy directory, and the next start tries again"
                } else {
                    "the legacy directory could not be kept in use either: this run starts from the \
                     new, empty directory as a new device"
                }
            ),
        }
    }
}

/// Carry a pre-rename install (`%APPDATA%\Remoter`) over to `%APPDATA%\AFKLink`, once.
///
/// Call at startup, before anything reads config or identity, and log the result once the log
/// exists. Does nothing under a `--data-dir` override, when there is no legacy directory, or when
/// the new directory is already in use (an empty one is taken as unused). Otherwise renames the
/// directory; if that fails, copies `config.json`, `identity.json` and `logs/` through a staging
/// directory, so a half-finished copy is never mistaken for an install. If that fails too, the
/// legacy directory becomes this run's data directory: the same device, the migration retried next
/// start.
pub fn migrate_legacy_dir() -> Migration {
    if let Some(dir) = dir_override() {
        return Migration::Overridden {
            dir: dir.to_path_buf(),
        };
    }
    let outcome = migrate_between(&legacy_default_dir(), &default_dir(), |from, to| {
        std::fs::rename(from, to)
    });
    if let Migration::Failed {
        from,
        to,
        error,
        fallback: _,
    } = outcome
    {
        let fallback = set_dir_override(from.clone()).is_ok();
        return Migration::Failed {
            from,
            to,
            error,
            fallback,
        };
    }
    outcome
}

/// [`migrate_legacy_dir`] between two given directories, with the rename injectable (tests).
fn migrate_between(
    legacy: &Path,
    new: &Path,
    rename: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Migration {
    if !legacy.is_dir() {
        return Migration::NothingToMigrate {
            dir: new.to_path_buf(),
            legacy: legacy.to_path_buf(),
        };
    }
    if new.exists() {
        // An empty directory is one something created before the migration ran (nothing in this
        // codebase does); it holds no device, so it gives way to the legacy one.
        let empty = std::fs::read_dir(new).is_ok_and(|mut entries| entries.next().is_none());
        if !empty || std::fs::remove_dir(new).is_err() {
            return Migration::AlreadyMigrated {
                dir: new.to_path_buf(),
                legacy: legacy.to_path_buf(),
                legacy_left: true,
            };
        }
    }
    let entries = top_level_names(legacy);
    match rename(legacy, new) {
        Ok(()) => Migration::Renamed {
            from: legacy.to_path_buf(),
            to: new.to_path_buf(),
            entries,
        },
        Err(e) => copy_across(legacy, new, e.to_string(), &rename),
    }
}

/// The names directly inside `dir`, sorted; a directory gets a trailing `/` and its file count.
fn top_level_names(dir: &Path) -> Vec<String> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = read
        .filter_map(Result::ok)
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_dir() {
                let files = std::fs::read_dir(entry.path()).map_or(0, Iterator::count);
                format!("{name}/ ({files} entries)")
            } else {
                name
            }
        })
        .collect();
    names.sort();
    names
}

/// The fallback when the legacy directory cannot be renamed: copy the device and its logs into a
/// staging directory beside `new`, then rename that into place.
fn copy_across(
    legacy: &Path,
    new: &Path,
    rename_error: String,
    rename: &impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Migration {
    let failed = |error: String| Migration::Failed {
        from: legacy.to_path_buf(),
        to: new.to_path_buf(),
        error: format!("rename failed ({rename_error}), then {error}"),
        fallback: false,
    };
    let mut staging_name = new
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    staging_name.push(".migrating");
    let staging = new.with_file_name(staging_name);

    // A staging directory left by a start that died half-way: never an install, always redone.
    if staging.exists() {
        if let Err(e) = std::fs::remove_dir_all(&staging) {
            return failed(format!(
                "a stale {} could not be removed: {e}",
                staging.display()
            ));
        }
    }
    if let Err(e) = std::fs::create_dir_all(&staging) {
        return failed(format!("{} could not be created: {e}", staging.display()));
    }
    let abandon = |error: String| {
        // Best effort: a staging directory left behind is removed by the next attempt.
        let _ = std::fs::remove_dir_all(&staging);
        failed(error)
    };

    let mut copied = Vec::new();
    let mut skipped = Vec::new();
    for name in CARRIED_FILES {
        let src = legacy.join(name);
        if !src.is_file() {
            continue;
        }
        if let Err(e) = std::fs::copy(&src, staging.join(name)) {
            // Without these the new directory would be a different device: stop, keep the old one.
            return abandon(format!("{name} could not be copied: {e}"));
        }
        copied.push(name.to_string());
    }

    let logs = legacy.join(LOGS_DIR);
    if logs.is_dir() {
        let target = staging.join(LOGS_DIR);
        if let Err(e) = std::fs::create_dir_all(&target) {
            skipped.push(format!("{LOGS_DIR}/ not created: {e}"));
        } else {
            match std::fs::read_dir(&logs) {
                Ok(read) => {
                    let mut n = 0usize;
                    for entry in read {
                        let entry = match entry {
                            Ok(entry) => entry,
                            Err(e) => {
                                skipped.push(format!("{LOGS_DIR}/: an entry not read: {e}"));
                                continue;
                            }
                        };
                        let path = entry.path();
                        if !path.is_file() {
                            continue;
                        }
                        let name = entry.file_name();
                        match std::fs::copy(&path, target.join(&name)) {
                            Ok(_) => n += 1,
                            Err(e) => skipped.push(format!(
                                "{LOGS_DIR}/{} not copied: {e}",
                                name.to_string_lossy()
                            )),
                        }
                    }
                    copied.push(format!("{LOGS_DIR}/ ({n} files)"));
                }
                Err(e) => skipped.push(format!("{LOGS_DIR}/ not read: {e}")),
            }
        }
    }

    if let Err(e) = rename(&staging, new) {
        return abandon(format!("the copy could not be moved into place: {e}"));
    }
    Migration::Copied {
        from: legacy.to_path_buf(),
        to: new.to_path_buf(),
        rename_error,
        copied,
        skipped,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    /// A fresh `%APPDATA%` stand-in for one test.
    fn scratch(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "afklink-paths-{}-{nanos}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A pre-rename install: config, identity, two log files.
    fn legacy_install(base: &Path) -> PathBuf {
        let legacy = base.join(LEGACY_DIR_NAME);
        std::fs::create_dir_all(legacy.join(LOGS_DIR)).unwrap();
        std::fs::write(legacy.join("config.json"), "{\"device_id\":\"d\"}").unwrap();
        std::fs::write(legacy.join("identity.json"), "{\"secret\":\"k\"}").unwrap();
        std::fs::write(
            legacy.join(LOGS_DIR).join("remoter-app.2026-09-26.log"),
            "a",
        )
        .unwrap();
        std::fs::write(
            legacy.join(LOGS_DIR).join("remoter-app.2026-09-27.log"),
            "b",
        )
        .unwrap();
        legacy
    }

    fn rename_ok(from: &Path, to: &Path) -> std::io::Result<()> {
        std::fs::rename(from, to)
    }

    #[test]
    fn a_legacy_install_is_renamed_whole() {
        let base = scratch("rename");
        let legacy = legacy_install(&base);
        let new = base.join(DIR_NAME);

        let m = migrate_between(&legacy, &new, rename_ok);
        let Migration::Renamed { entries, .. } = &m else {
            unreachable!("expected a rename, got {m:?}");
        };
        assert_eq!(
            entries,
            &["config.json", "identity.json", "logs/ (2 entries)"]
        );
        assert!(!legacy.exists());
        assert_eq!(
            std::fs::read_to_string(new.join("identity.json")).unwrap(),
            "{\"secret\":\"k\"}"
        );
        assert!(new
            .join(LOGS_DIR)
            .join("remoter-app.2026-09-27.log")
            .is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn nothing_without_a_legacy_directory() {
        let base = scratch("fresh");
        let new = base.join(DIR_NAME);
        let m = migrate_between(&base.join(LEGACY_DIR_NAME), &new, rename_ok);
        assert!(matches!(m, Migration::NothingToMigrate { .. }), "{m:?}");
        assert!(
            !new.exists(),
            "a fresh install is created by its first use, not here"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_install_in_use_is_never_overwritten() {
        let base = scratch("both");
        let legacy = legacy_install(&base);
        let new = base.join(DIR_NAME);
        std::fs::create_dir_all(&new).unwrap();
        std::fs::write(new.join("config.json"), "{\"device_id\":\"new\"}").unwrap();

        let m = migrate_between(&legacy, &new, rename_ok);
        assert!(
            matches!(
                m,
                Migration::AlreadyMigrated {
                    legacy_left: true,
                    ..
                }
            ),
            "{m:?}"
        );
        assert_eq!(
            std::fs::read_to_string(new.join("config.json")).unwrap(),
            "{\"device_id\":\"new\"}"
        );
        assert!(
            legacy.join("identity.json").is_file(),
            "the legacy one is left alone"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_empty_new_directory_gives_way() {
        let base = scratch("empty");
        let legacy = legacy_install(&base);
        let new = base.join(DIR_NAME);
        std::fs::create_dir_all(&new).unwrap();

        let m = migrate_between(&legacy, &new, rename_ok);
        assert!(matches!(m, Migration::Renamed { .. }), "{m:?}");
        assert!(new.join("identity.json").is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_failed_rename_falls_back_to_a_copy_and_leaves_the_legacy_directory() {
        let base = scratch("copy");
        let legacy = legacy_install(&base);
        std::fs::write(legacy.join("unrelated.txt"), "x").unwrap();
        let new = base.join(DIR_NAME);
        let legacy_for_rename = legacy.clone();
        let rename = move |from: &Path, to: &Path| {
            if from == legacy_for_rename {
                Err(std::io::Error::other("held open"))
            } else {
                std::fs::rename(from, to)
            }
        };

        let m = migrate_between(&legacy, &new, rename);
        let Migration::Copied {
            copied,
            skipped,
            rename_error,
            ..
        } = &m
        else {
            unreachable!("expected a copy, got {m:?}");
        };
        assert_eq!(rename_error, "held open");
        assert_eq!(copied, &["config.json", "identity.json", "logs/ (2 files)"]);
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(
            std::fs::read_to_string(new.join("identity.json")).unwrap(),
            "{\"secret\":\"k\"}"
        );
        assert!(new
            .join(LOGS_DIR)
            .join("remoter-app.2026-09-26.log")
            .is_file());
        assert!(
            !new.join("unrelated.txt").exists(),
            "only the device and its logs"
        );
        assert!(legacy.join("identity.json").is_file());
        assert!(!base.join(format!("{DIR_NAME}.migrating")).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn when_nothing_works_the_new_directory_is_not_left_half_made() {
        let base = scratch("fail");
        let legacy = legacy_install(&base);
        let new = base.join(DIR_NAME);
        let rename =
            |_: &Path, _: &Path| -> std::io::Result<()> { Err(std::io::Error::other("denied")) };

        let m = migrate_between(&legacy, &new, rename);
        let Migration::Failed { error, .. } = &m else {
            unreachable!("expected a failure, got {m:?}");
        };
        assert!(error.contains("denied"), "{error}");
        assert!(!new.exists());
        assert!(!base.join(format!("{DIR_NAME}.migrating")).exists());
        assert!(legacy.join("identity.json").is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_stale_staging_directory_is_redone() {
        let base = scratch("stale");
        let legacy = legacy_install(&base);
        let new = base.join(DIR_NAME);
        let staging = base.join(format!("{DIR_NAME}.migrating"));
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("identity.json"), "half").unwrap();
        let legacy_for_rename = legacy.clone();
        let rename = move |from: &Path, to: &Path| {
            if from == legacy_for_rename {
                Err(std::io::Error::other("held open"))
            } else {
                std::fs::rename(from, to)
            }
        };

        let m = migrate_between(&legacy, &new, rename);
        assert!(matches!(m, Migration::Copied { .. }), "{m:?}");
        assert_eq!(
            std::fs::read_to_string(new.join("identity.json")).unwrap(),
            "{\"secret\":\"k\"}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
