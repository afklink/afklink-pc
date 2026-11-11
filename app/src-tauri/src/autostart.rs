//! Launch at Windows sign-in: the HKCU `Run` value «AFKLink», kept in step with
//! `config.autostart`, written here on `winreg` rather than by `tauri-plugin-autostart`.
//!
//! What the plugin (2.5.1, over `auto-launch` 0.5) got wrong, for a portable exe above all: it
//! wrote `current_exe()` unquoted with a trailing space, so Explorer had to guess where a path with
//! spaces ends; `is_enabled()` checked that the value exists, never where it points, so a moved exe
//! left the checkbox on and the entry dead; and its startup reconcile switched the entry back on
//! after the owner had switched it off in Task Manager.
//!
//! # The rules
//!
//! `config.autostart` is the source of truth, and the registry follows it ([`decide`]):
//!
//! - **On, at every start:** the value must be `"<this exe's full path>" --autostart`: quoted, and
//!   one flag ([`AUTOSTART_FLAG`]) that only says Windows started it. Anything else (no value,
//!   another exe's path, the plugin's unquoted form, a form without the flag, an unreadable one) is
//!   rewritten, with the old and the new command at `info`.
//! - **Off:** there is no value. One found at start is removed.
//! - **Switched off in Task Manager** (or Settings → Apps → Startup): the owner's choice, and it
//!   wins over config.json. `config.autostart` becomes false, the value and its record are removed,
//!   and nothing here switches it back on; the checkbox does. Removing rather than leaving a
//!   disabled entry keeps "off" meaning one thing: an entry re-enabled in Task Manager would
//!   otherwise be removed at our next start as a value config.json does not want.
//! - **The owner ticks the checkbox** ([`set`]): the value is written and Task Manager's record for
//!   it, disabled or not, is removed. Unticking removes both.
//!
//! Several copies of the exe (a development build and a portable one) share one config.json, so
//! with autostart on every start rewrites the value to its own path: the entry points at whichever
//! copy was started last, the one the owner uses.
//!
//! Task Manager's on/off record lives under [`APPROVED_KEY`]; its format is on [`ApprovalRecord`].

#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the registry side is Windows-only; the rules are tested everywhere"
    )
)]

use std::path::Path;

use afklink_core::AgentControl;

/// The value's name, in `Run` and in `StartupApproved\Run`: `productName`, as the plugin named it,
/// so the entry a plugin-era build wrote is the one found and rewritten.
const VALUE_NAME: &str = "AFKLink";

/// `HKCU\...\Run`: what Explorer starts at sign-in.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// Task Manager's on/off record for each `Run` entry ([`ApprovalRecord`]).
const APPROVED_KEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

/// The flag the entry starts the app with (`crate::updater::AUTOSTART_ARG`, which the app's command
/// line reads): the launch was Windows', at sign-in, not a person's (`agent_started.autostart`,
/// `afklink_core::agent_events`). It changes nothing else: an autostarted launch opens the window
/// like a manual one.
const AUTOSTART_FLAG: &str = crate::updater::AUTOSTART_ARG;

/// The command line the entry must hold: the exe's full path in double quotes, then
/// [`AUTOSTART_FLAG`]. A path cannot contain `"` on Windows; one that does, or one that is not
/// Unicode (the value is a string), is refused rather than written half-right.
fn run_command(exe: &Path) -> Result<String, String> {
    let Some(path) = exe.to_str() else {
        return Err(format!(
            "the exe path is not valid Unicode: {}",
            exe.display()
        ));
    };
    if path.is_empty() {
        return Err("the exe path is empty".to_string());
    }
    if path.contains('"') {
        return Err(format!("the exe path contains a double quote: {path}"));
    }
    Ok(format!("\"{path}\" {AUTOSTART_FLAG}"))
}

/// Whether a stored command is the one this exe would write. Case is ignored, as Windows ignores it
/// in paths; nothing else is — the plugin's unquoted form with its trailing space is different.
fn same_command(stored: &str, expected: &str) -> bool {
    stored == expected || stored.to_lowercase() == expected.to_lowercase()
}

/// Our `Run` value, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunEntry {
    Absent,
    Command(String),
    /// There, but not readable as a string; the reason, for the log.
    Unreadable(String),
}

impl RunEntry {
    fn command(&self) -> Option<String> {
        match self {
            Self::Command(c) => Some(c.clone()),
            Self::Absent | Self::Unreadable(_) => None,
        }
    }
}

/// Task Manager's record for our entry, as stored under [`APPROVED_KEY`]: one `REG_BINARY` value
/// per `Run` entry, under the same name, written by Task Manager and by Settings when the owner
/// flips the entry's switch; an entry nobody has flipped has no record and runs. It is 12 bytes: a
/// little-endian `u32` of flags, then a `FILETIME` of when the entry was switched off (zero while
/// on). The low bit of the flags is the switch: `02 00 00 00` (also seen: `06`) enabled,
/// `03 00 00 00` (also `07`) disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalRecord {
    /// `REG_BINARY`, the only type Task Manager writes.
    binary: bool,
    bytes: Vec<u8>,
}

impl ApprovalRecord {
    /// The bytes as hex, for the log.
    fn hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What Task Manager's record says about our entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approval {
    /// No record: nobody has flipped the switch, and the entry runs.
    NoRecord,
    Enabled,
    /// Switched off in Task Manager or Settings: Explorer skips the entry at sign-in.
    Disabled,
    /// A record this build cannot read; treated as not disabled.
    Unreadable,
}

impl Approval {
    fn as_str(self) -> &'static str {
        match self {
            Self::NoRecord => "no record",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Unreadable => "unreadable",
        }
    }
}

/// Read Task Manager's record ([`ApprovalRecord`]): the low bit of the first little-endian `u32` is
/// the switch, and nothing else is read. `auto-launch` read the timestamp instead (eight zero bytes
/// = enabled), which calls a disabled record with a zero time enabled. A record that is not binary,
/// or shorter than four bytes, is unreadable: it counts as not disabled, with a warning, since an
/// owner's choice that cannot be read is not invented.
fn parse_approval(record: Option<&ApprovalRecord>) -> Approval {
    let Some(record) = record else {
        return Approval::NoRecord;
    };
    if !record.binary {
        return Approval::Unreadable;
    }
    let Some(flags) = record
        .bytes
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
    else {
        return Approval::Unreadable;
    };
    if u32::from_le_bytes(flags) & 1 == 1 {
        Approval::Disabled
    } else {
        Approval::Enabled
    }
}

/// What a start does about the entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupAction {
    /// Nothing to change.
    Keep { why: &'static str },
    /// Write this exe's command. `clear_record`: a «disabled» record left under a missing entry is
    /// removed too, or the new entry would be born switched off.
    Write {
        old: Option<String>,
        clear_record: bool,
        why: &'static str,
    },
    /// config.json has autostart off: remove the value and its record.
    Remove { old: Option<String> },
    /// The owner switched the entry off in Task Manager: config.json follows (autostart off), and
    /// the value and its record go.
    AdoptDisabled { old: Option<String> },
}

/// The startup decision, from config.json's `want`, the `Run` value, Task Manager's record and the
/// command this exe would write (module docs, «The rules»).
///
/// A «disabled» record counts as the owner's choice only while the entry exists: Task Manager lists
/// only entries that are in `Run`, so a record under a missing entry is a leftover (the plugin
/// removed values and left records), not something the owner could have switched just now.
fn decide(want: bool, entry: &RunEntry, approval: Approval, expected: &str) -> StartupAction {
    if !want {
        return match entry {
            RunEntry::Absent => StartupAction::Keep {
                why: "autostart is off and there is no entry",
            },
            RunEntry::Command(_) | RunEntry::Unreadable(_) => StartupAction::Remove {
                old: entry.command(),
            },
        };
    }
    match (entry, approval) {
        (RunEntry::Command(_) | RunEntry::Unreadable(_), Approval::Disabled) => {
            StartupAction::AdoptDisabled {
                old: entry.command(),
            }
        }
        (RunEntry::Absent, Approval::Disabled) => StartupAction::Write {
            old: None,
            clear_record: true,
            why: "no entry, and a stale «disabled» record under its name",
        },
        (RunEntry::Absent, _) => StartupAction::Write {
            old: None,
            clear_record: false,
            why: "no entry",
        },
        (RunEntry::Command(stored), _) if same_command(stored, expected) => StartupAction::Keep {
            why: "the entry starts this exe",
        },
        (RunEntry::Command(stored), _) => StartupAction::Write {
            old: Some(stored.clone()),
            clear_record: false,
            why: "the entry starts another exe, or is not this build's form (quoted, --autostart)",
        },
        (RunEntry::Unreadable(_), _) => StartupAction::Write {
            old: None,
            clear_record: false,
            why: "the entry is not readable",
        },
    }
}

/// Startup: remove the pre-rename entry, then bring «AFKLink» in line with config.json. Failures
/// only warn: a wrong startup entry must not stop the agent, and the checkbox can fix it once the
/// window is up.
pub(crate) fn reconcile_at_startup(control: &AgentControl) {
    let want = afklink_core::lock(&control.config).autostart;
    #[cfg(windows)]
    {
        legacy::remove(want);
        reconcile(control, want);
    }
    #[cfg(not(windows))]
    tracing::debug!(want, "autostart: Windows only; nothing to reconcile");
}

/// The Settings checkbox: write the entry (and remove Task Manager's record for it, the owner having
/// asked explicitly) or remove both. Saving the choice is the caller's.
pub(crate) fn set(enabled: bool) -> Result<(), String> {
    #[cfg(windows)]
    {
        if enabled {
            enable()
        } else {
            disable()
        }
    }
    #[cfg(not(windows))]
    {
        tracing::debug!(enabled, "autostart: Windows only");
        Err("autostart is available on Windows only".to_string())
    }
}

/// This exe's command, or why there is none.
#[cfg(windows)]
fn this_exe_command() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("this exe's path is unknown: {e}"))?;
    run_command(&exe)
}

#[cfg(windows)]
fn enable() -> Result<(), String> {
    let command = this_exe_command()?;
    registry::write_entry(&command)
        .map_err(|e| format!("HKCU\\{RUN_KEY} «{VALUE_NAME}» not written: {e}"))?;
    clear_record("the owner switched autostart on");
    tracing::info!(%command, "autostart on: entry written");
    Ok(())
}

#[cfg(windows)]
fn disable() -> Result<(), String> {
    match registry::remove_entry() {
        Ok(Some(old)) => tracing::info!(old = %old, "autostart off: entry removed"),
        Ok(None) => tracing::info!("autostart off: there was no entry to remove"),
        Err(e) => return Err(format!("HKCU\\{RUN_KEY} «{VALUE_NAME}» not removed: {e}")),
    }
    clear_record("the owner switched autostart off");
    Ok(())
}

/// Remove Task Manager's record for our entry, saying what it held. A failure warns: with the entry
/// written and a «disabled» record left, Windows would still skip it at sign-in.
#[cfg(windows)]
fn clear_record(why: &'static str) {
    match registry::remove_record() {
        Ok(Some(record)) => tracing::info!(
            why,
            was = parse_approval(Some(&record)).as_str(),
            bytes = %record.hex(),
            "Task Manager's startup record for «{VALUE_NAME}» removed"
        ),
        Ok(None) => tracing::debug!(why, "no Task Manager startup record for «{VALUE_NAME}»"),
        Err(e) => tracing::warn!(
            why,
            "Task Manager's startup record for «{VALUE_NAME}» not removed ({e}); if it says \
             disabled, Windows skips the entry at sign-in"
        ),
    }
}

/// The startup reconcile on Windows ([`decide`], then act on it).
#[cfg(windows)]
fn reconcile(control: &AgentControl, want: bool) {
    let expected = match this_exe_command() {
        Ok(command) => command,
        Err(e) => {
            tracing::warn!(want, "autostart entry not checked: {e}");
            return;
        }
    };
    let entry = registry::read_entry();
    if let RunEntry::Unreadable(e) = &entry {
        tracing::warn!("autostart entry «{VALUE_NAME}» not read: {e}");
    }
    let record = registry::read_record().unwrap_or_else(|e| {
        tracing::warn!(
            "Task Manager's startup record for «{VALUE_NAME}» not read ({e}); counted as not \
             disabled"
        );
        None
    });
    let approval = parse_approval(record.as_ref());
    if approval == Approval::Unreadable {
        tracing::warn!(
            bytes = record
                .as_ref()
                .map_or_else(String::new, ApprovalRecord::hex),
            binary = record.as_ref().is_some_and(|r| r.binary),
            "Task Manager's startup record for «{VALUE_NAME}» is not one this build can read; \
             counted as not disabled"
        );
    }
    let action = decide(want, &entry, approval, &expected);
    tracing::debug!(
        want,
        entry = ?entry,
        approval = approval.as_str(),
        record = record.as_ref().map_or_else(|| "-".to_string(), ApprovalRecord::hex),
        %expected,
        ?action,
        "autostart: startup check"
    );

    match action {
        StartupAction::Keep { why } => tracing::debug!(why, "autostart entry left as it is"),
        StartupAction::Write {
            old,
            clear_record: clear,
            why,
        } => {
            match registry::write_entry(&expected) {
                Ok(()) => tracing::info!(
                    old = old.as_deref().unwrap_or("-"),
                    new = %expected,
                    why,
                    "autostart entry rewritten to start this exe"
                ),
                Err(e) => tracing::warn!(
                    old = old.as_deref().unwrap_or("-"),
                    new = %expected,
                    why,
                    "autostart entry not rewritten: {e}; sign-in may start another exe or nothing"
                ),
            }
            if clear {
                clear_record("a stale «disabled» record under a missing entry");
            }
        }
        StartupAction::Remove { old } => {
            match registry::remove_entry() {
                Ok(Some(removed)) => tracing::info!(
                    old = %removed,
                    "autostart entry removed: config.json has autostart off"
                ),
                Ok(None) => {
                    tracing::debug!("autostart entry already gone when it was to be removed")
                }
                Err(e) => tracing::warn!(
                    old = old.as_deref().unwrap_or("-"),
                    "autostart entry not removed ({e}); sign-in may still start AFKLink"
                ),
            }
            clear_record("config.json has autostart off");
        }
        StartupAction::AdoptDisabled { old } => {
            let saved = {
                let mut cfg = afklink_core::lock(&control.config);
                cfg.autostart = false;
                cfg.save()
            };
            match saved {
                Ok(()) => {
                    tracing::info!(
                        old = old.as_deref().unwrap_or("-"),
                        "autostart was switched off in Task Manager: config.json follows \
                         (autostart=false, the checkbox clears); the entry and its record are \
                         removed and not switched back on"
                    );
                    // The owner's change, made in Task Manager: `pc_setting_changed`
                    // (`afklink_core::agent_events`).
                    afklink_core::agent_events::setting_changed(
                        afklink_protocol::metrics::PcSettingKey::Autostart,
                        afklink_protocol::metrics::PcSettingValue::Flag(false),
                    );
                    match registry::remove_entry() {
                        Ok(Some(removed)) => {
                            tracing::debug!(old = %removed, "autostart entry removed");
                        }
                        Ok(None) => tracing::debug!("autostart entry already gone"),
                        Err(e) => {
                            tracing::warn!("autostart entry not removed ({e}); it stays disabled");
                        }
                    }
                    clear_record("switched off in Task Manager");
                }
                // The entry stays as it is — disabled, so sign-in skips it — and the next start
                // finds the same record and tries again. Removing it now, with config.json still
                // saying on, would let that start write it back.
                Err(e) => tracing::warn!(
                    old = old.as_deref().unwrap_or("-"),
                    "autostart was switched off in Task Manager, but config.json was not saved \
                     ({e:#}); off for this run, the entry is left disabled and the next start \
                     tries again"
                ),
            }
        }
    }
}

/// The registry side: `Run` and `StartupApproved\Run` under HKCU, value [`VALUE_NAME`].
#[cfg(windows)]
mod registry {
    use std::io::ErrorKind;

    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    use super::{ApprovalRecord, RunEntry, APPROVED_KEY, RUN_KEY, VALUE_NAME};

    fn hkcu() -> RegKey {
        RegKey::predef(HKEY_CURRENT_USER)
    }

    pub(super) fn read_entry() -> RunEntry {
        let run = match hkcu().open_subkey_with_flags(RUN_KEY, KEY_READ) {
            Ok(key) => key,
            Err(e) if e.kind() == ErrorKind::NotFound => return RunEntry::Absent,
            Err(e) => return RunEntry::Unreadable(format!("HKCU\\{RUN_KEY} not opened: {e}")),
        };
        match run.get_value::<String, _>(VALUE_NAME) {
            Ok(command) => RunEntry::Command(command),
            Err(e) if e.kind() == ErrorKind::NotFound => RunEntry::Absent,
            Err(e) => RunEntry::Unreadable(e.to_string()),
        }
    }

    /// Created if missing (it never is on a working Windows).
    pub(super) fn write_entry(command: &str) -> std::io::Result<()> {
        let (run, _) = hkcu().create_subkey_with_flags(RUN_KEY, KEY_SET_VALUE)?;
        run.set_value(VALUE_NAME, &command)
    }

    /// The command removed (or why it could not be read, for the log), `None` when there was none.
    pub(super) fn remove_entry() -> std::io::Result<Option<String>> {
        let run = match hkcu().open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => key,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let old = match run.get_value::<String, _>(VALUE_NAME) {
            Ok(command) => command,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            // Still ours by its name, and still removed; the log says what it was not.
            Err(e) => format!("<not readable: {e}>"),
        };
        match run.delete_value(VALUE_NAME) {
            Ok(()) => Ok(Some(old)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(super) fn read_record() -> std::io::Result<Option<ApprovalRecord>> {
        let approved = match hkcu().open_subkey_with_flags(APPROVED_KEY, KEY_READ) {
            Ok(key) => key,
            // Nobody has flipped a switch in Task Manager on this account yet.
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        match approved.get_raw_value(VALUE_NAME) {
            Ok(value) => Ok(Some(ApprovalRecord {
                binary: value.vtype == RegType::REG_BINARY,
                bytes: value.bytes,
            })),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The record removed, `None` when there was none.
    pub(super) fn remove_record() -> std::io::Result<Option<ApprovalRecord>> {
        let old = read_record()?;
        if old.is_none() {
            return Ok(None);
        }
        let approved = hkcu().open_subkey_with_flags(APPROVED_KEY, KEY_SET_VALUE)?;
        match approved.delete_value(VALUE_NAME) {
            Ok(()) => Ok(old),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// The sign-in entry a build from before the rename to AFKLink wrote.
///
/// `tauri-plugin-autostart` named its HKCU `...\Run` value after `productName`, which was
/// «Remoter», and pointed it at that build's exe. Only «AFKLink» is managed now, so the old value
/// would keep starting the old build at sign-in beside this one — and after a data directory
/// migrated by copy that is the same device, and the two take the backend connection from each
/// other. Removed at startup when it points at a pre-rename exe; a «Remoter» value that points
/// anywhere else is somebody else's and is left alone.
#[cfg(windows)]
mod legacy {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    use super::{APPROVED_KEY, RUN_KEY};

    /// The value name: the old `productName`.
    const LEGACY_VALUE: &str = "Remoter";
    /// The executables a pre-rename entry points at: the `cargo tauri build --no-bundle` binary,
    /// and the one a bundled install names after `productName`.
    const LEGACY_EXES: [&str; 2] = ["remoter-app.exe", "remoter.exe"];

    /// Whether a `Run` value's command line starts one of [`LEGACY_EXES`]. The plugin writes the
    /// path unquoted followed by a space and the arguments, so the exe is matched as a path
    /// component anywhere in the line rather than parsed out of it.
    pub(super) fn points_at_legacy_exe(command: &str) -> bool {
        let line = command.to_ascii_lowercase();
        LEGACY_EXES.iter().any(|exe| {
            line.match_indices(exe).any(|(at, _)| {
                let before = line[..at].chars().next_back();
                let after = line[at + exe.len()..].chars().next();
                matches!(before, None | Some('\\' | '/' | '"'))
                    && matches!(after, None | Some(' ' | '"'))
            })
        })
    }

    /// Remove the pre-rename entry if it is ours. `autostart` is config.json's choice, for the
    /// log only: the reconcile that follows writes the «AFKLink» entry when it is on.
    pub(super) fn remove(autostart: bool) {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let run = match hkcu.open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_SET_VALUE) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(
                    "legacy autostart entry not checked: HKCU\\{RUN_KEY} not opened: {e}"
                );
                return;
            }
        };
        let command: String = match run.get_value(LEGACY_VALUE) {
            Ok(command) => command,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!("no legacy autostart entry «{LEGACY_VALUE}»");
                return;
            }
            Err(e) => {
                tracing::warn!("legacy autostart entry «{LEGACY_VALUE}» not read: {e}");
                return;
            }
        };
        if !points_at_legacy_exe(&command) {
            tracing::debug!(
                command = %command.trim(),
                "autostart entry «{LEGACY_VALUE}» points at something else; left alone"
            );
            return;
        }
        if let Err(e) = run.delete_value(LEGACY_VALUE) {
            tracing::warn!(
                command = %command.trim(),
                "legacy autostart entry «{LEGACY_VALUE}» not removed: {e}; the old build may still \
                 start at sign-in"
            );
            return;
        }
        // Task Manager's record of the removed value: harmless if left, tidier if not.
        match hkcu.open_subkey_with_flags(APPROVED_KEY, KEY_SET_VALUE) {
            Ok(approved) => match approved.delete_value(LEGACY_VALUE) {
                Ok(()) => tracing::debug!("legacy StartupApproved record removed"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::debug!("no legacy StartupApproved record");
                }
                Err(e) => tracing::debug!("legacy StartupApproved record not removed: {e}"),
            },
            Err(e) => tracing::debug!("StartupApproved key not opened: {e}"),
        }
        tracing::info!(
            command = %command.trim(),
            autostart,
            "legacy autostart entry «{LEGACY_VALUE}» removed; the «AFKLink» entry follows \
             config.json"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const EXE: &str = r"C:\Users\Иван Петров\Downloads\AFKLink-0.1.0-3a3bc46-portable.exe";

    fn expected() -> String {
        run_command(&PathBuf::from(EXE)).unwrap()
    }

    fn record(bytes: &[u8]) -> ApprovalRecord {
        ApprovalRecord {
            binary: true,
            bytes: bytes.to_vec(),
        }
    }

    /// Task Manager's «disabled» with the time it was switched off.
    const DISABLED: [u8; 12] = [
        0x03, 0x00, 0x00, 0x00, 0x5a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0xdb, 0x01,
    ];
    const ENABLED: [u8; 12] = [0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    #[test]
    fn the_command_is_the_quoted_path_and_the_autostart_flag() {
        assert_eq!(expected(), format!("\"{EXE}\" --autostart"));
        assert_eq!(
            run_command(Path::new(r"C:\Program Files\AFKLink\afklink-app.exe")).unwrap(),
            r#""C:\Program Files\AFKLink\afklink-app.exe" --autostart"#
        );
        // What the app's command line reads it as.
        assert_eq!(AUTOSTART_FLAG, "--autostart");
        assert!(run_command(Path::new("C:\\a\"b.exe")).is_err());
        assert!(run_command(Path::new("")).is_err());
    }

    #[test]
    fn task_managers_record_is_read_by_its_low_bit() {
        assert_eq!(parse_approval(None), Approval::NoRecord);
        assert_eq!(parse_approval(Some(&record(&ENABLED))), Approval::Enabled);
        assert_eq!(parse_approval(Some(&record(&DISABLED))), Approval::Disabled);
        // The other pair seen in the wild.
        assert_eq!(
            parse_approval(Some(&record(&[0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))),
            Approval::Enabled
        );
        assert_eq!(
            parse_approval(Some(&record(&[0x07, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]))),
            Approval::Disabled
        );
        // Disabled with a zero time: `auto-launch` read the zero time as enabled.
        assert_eq!(
            parse_approval(Some(&record(&[0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))),
            Approval::Disabled
        );
        // The four flag bytes are all that is needed.
        assert_eq!(
            parse_approval(Some(&record(&[0x03, 0, 0, 0]))),
            Approval::Disabled
        );
        assert_eq!(
            parse_approval(Some(&record(&[0x03, 0, 0]))),
            Approval::Unreadable
        );
        assert_eq!(parse_approval(Some(&record(&[]))), Approval::Unreadable);
        let not_binary = ApprovalRecord {
            binary: false,
            bytes: DISABLED.to_vec(),
        };
        assert_eq!(parse_approval(Some(&not_binary)), Approval::Unreadable);
    }

    #[test]
    fn on_and_already_right_is_left_alone() {
        let entry = RunEntry::Command(expected());
        for approval in [Approval::NoRecord, Approval::Enabled, Approval::Unreadable] {
            assert!(
                matches!(
                    decide(true, &entry, approval, &expected()),
                    StartupAction::Keep { .. }
                ),
                "{approval:?}"
            );
        }
        // Case differs, the path does not.
        let upper = RunEntry::Command(expected().to_uppercase());
        assert!(matches!(
            decide(true, &upper, Approval::NoRecord, &expected()),
            StartupAction::Keep { .. }
        ));
    }

    #[test]
    fn on_and_pointing_elsewhere_is_rewritten() {
        for stored in [
            // The plugin's form: unquoted, trailing space.
            format!("{EXE} "),
            // Moved.
            r#""C:\Users\Иван Петров\Desktop\AFKLink-0.1.0-3a3bc46-portable.exe""#.to_string(),
            // Renamed.
            r#""C:\Users\Иван Петров\Downloads\afklink.exe""#.to_string(),
            // With an argument.
            format!("{} --minimized", expected()),
            // An earlier build's form: this exe, quoted, without the flag.
            format!("\"{EXE}\""),
        ] {
            assert_eq!(
                decide(
                    true,
                    &RunEntry::Command(stored.clone()),
                    Approval::Enabled,
                    &expected()
                ),
                StartupAction::Write {
                    old: Some(stored.clone()),
                    clear_record: false,
                    why: "the entry starts another exe, or is not this build's form (quoted, \
                          --autostart)",
                },
                "{stored}"
            );
        }
        assert!(matches!(
            decide(
                true,
                &RunEntry::Unreadable("wrong type".into()),
                Approval::NoRecord,
                &expected()
            ),
            StartupAction::Write {
                old: None,
                clear_record: false,
                ..
            }
        ));
    }

    #[test]
    fn on_and_missing_is_written_and_a_leftover_disabled_record_cleared() {
        assert!(matches!(
            decide(true, &RunEntry::Absent, Approval::NoRecord, &expected()),
            StartupAction::Write {
                old: None,
                clear_record: false,
                ..
            }
        ));
        assert!(matches!(
            decide(true, &RunEntry::Absent, Approval::Disabled, &expected()),
            StartupAction::Write {
                old: None,
                clear_record: true,
                ..
            }
        ));
    }

    #[test]
    fn switched_off_in_task_manager_is_the_owners_choice_and_is_not_undone() {
        // Wherever the entry points: the owner switched off what Task Manager showed.
        for stored in [
            expected(),
            format!("{EXE} "),
            r#""D:\old\afklink-app.exe""#.to_string(),
        ] {
            assert_eq!(
                decide(
                    true,
                    &RunEntry::Command(stored.clone()),
                    Approval::Disabled,
                    &expected()
                ),
                StartupAction::AdoptDisabled { old: Some(stored) }
            );
        }
        // Nothing is ever written back over the owner's «disabled».
        for entry in [
            RunEntry::Command(expected()),
            RunEntry::Unreadable("x".into()),
        ] {
            assert!(!matches!(
                decide(true, &entry, Approval::Disabled, &expected()),
                StartupAction::Write { .. } | StartupAction::Keep { .. }
            ));
        }
    }

    #[test]
    fn off_means_no_entry() {
        assert!(matches!(
            decide(false, &RunEntry::Absent, Approval::NoRecord, &expected()),
            StartupAction::Keep { .. }
        ));
        for approval in [Approval::NoRecord, Approval::Enabled, Approval::Disabled] {
            assert_eq!(
                decide(false, &RunEntry::Command(expected()), approval, &expected()),
                StartupAction::Remove {
                    old: Some(expected())
                },
                "{approval:?}"
            );
        }
        assert_eq!(
            decide(
                false,
                &RunEntry::Unreadable("x".into()),
                Approval::NoRecord,
                &expected()
            ),
            StartupAction::Remove { old: None }
        );
    }
}

#[cfg(all(test, windows))]
mod legacy_tests {
    use super::legacy::points_at_legacy_exe;

    #[test]
    fn the_entries_a_pre_rename_build_wrote_are_recognised() {
        // As the plugin writes it: the path unquoted, a space, no arguments.
        assert!(points_at_legacy_exe(
            r"C:\Users\user\Documents\remoter\agent\target\release\remoter-app.exe "
        ));
        assert!(points_at_legacy_exe(
            r"C:\Program Files\Remoter\Remoter.exe --minimized"
        ));
        assert!(points_at_legacy_exe(r#""C:\Apps\remoter-app.exe""#));
    }

    #[test]
    fn anything_else_named_remoter_is_left_alone() {
        assert!(!points_at_legacy_exe(
            r"C:\Tools\RemoterPro\remoter-pro.exe"
        ));
        assert!(!points_at_legacy_exe(r"C:\Tools\not-remoter.exe "));
        assert!(!points_at_legacy_exe(
            r"C:\Users\user\Documents\remoter\agent\target\release\afklink-app.exe "
        ));
        assert!(!points_at_legacy_exe(""));
    }
}
