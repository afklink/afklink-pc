//! Windows toasts under AFKLink's own name: at every start the app registers the AppUserModelID
//! (AUMID) its toasts go out under with Windows' notification platform, before the first toast.
//!
//! # Whose name a toast goes out under
//!
//! `tauri-plugin-notification` 2.4 (`desktop.rs`, `imp::Notification::show`) decides by where the
//! exe is ([`toast_sender`]): when the exe's directory ends in `\target\debug` or `\target\release`
//! it sets no app id, and notify-rust falls back to PowerShell's AUMID ([`POWERSHELL_AUMID`]) — the
//! toast says «Windows PowerShell», a development leftover kept as it is; anywhere else it sets
//! `tauri.conf.json`'s `identifier`, `com.afklink.agent`. The portable exe is the second case.
//! Which case this run is goes to the log at `debug` ([`register_at_startup`]).
//!
//! # The registration
//!
//! An installer would have registered that AUMID; the portable exe has none, and Windows may not
//! show a toast from an AUMID it does not know. Microsoft's way for an unpackaged app that is not C#
//! or C++ («Send a local toast notification from other types of unpackaged apps», step 1) is a key
//! `Software\Classes\AppUserModelId\<AUMID>` holding:
//!
//! - `DisplayName`, `REG_EXPAND_SZ`: the name on the toast and in Settings → Notifications —
//!   `productName`, «AFKLink». Written.
//! - `IconUri`, `REG_EXPAND_SZ`: an absolute path to the icon — the app icon's 256×256 PNG, embedded
//!   in the exe and put at `%APPDATA%\AFKLink\icons\notification.png` ([`ensure_icon`]). Written.
//! - `IconBackgroundColor`, `REG_SZ`, `AARRGGBB`: the plate behind the icon. Not written: the page
//!   lists it with a placeholder and does not say it is needed, the Windows App SDK's own
//!   registration of unpackaged apps (`RegisterAssets`, `AppNotificationUtility.cpp`) does not write
//!   it, and our icon draws its own dark rounded plate — a colour would only fill its corners.
//! - `CustomActivator`, `REG_SZ`: the CLSID of a COM class Windows starts when a toast is clicked
//!   (step 2, `INotificationActivationCallback`). Not written: these toasts carry no action for the
//!   app, so there is nothing to activate, and a CLSID with no COM server behind it is worse than
//!   none.
//!
//! The page puts the key under `HKEY_LOCAL_MACHINE`, which takes an administrator; it is written
//! under `HKEY_CURRENT_USER` — the per-user half of the same `Software\Classes` view, which is also
//! where the Windows App SDK registers unpackaged apps. The value types follow the page.
//!
//! Only what differs is written ([`plan`]), and every failure warns and the start carries on: a
//! toast that shows without our name or icon, or not at all, must not cost the owner the agent.
//! Nothing removes the key; the portable exe has no uninstaller (README, «Portable-сборка»).

#![cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the registry side is Windows-only; the rules are tested everywhere"
    )
)]

use std::path::{Path, PathBuf};

/// The icon Windows draws on our toasts: the app icon at 256×256 (9 KB), large enough for every
/// place the notification platform draws it at any display scale; Windows scales it down.
static ICON_PNG: &[u8] = include_bytes!("../icons/256x256.png");

/// The icon's directory inside the data directory (`%APPDATA%\AFKLink`), and its file name.
const ICON_DIR: &str = "icons";
const ICON_FILE: &str = "notification.png";

/// The key's parent under `HKEY_CURRENT_USER`.
const AUMID_ROOT: &str = r"Software\Classes\AppUserModelId";

/// The two values written.
const DISPLAY_NAME: &str = "DisplayName";
const ICON_URI: &str = "IconUri";

/// What notify-rust sends as when no app id is set: `tauri-winrt-notification`'s
/// `Toast::POWERSHELL_APP_ID`, for the log.
const POWERSHELL_AUMID: &str =
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

/// The longest AUMID the notification platform takes whole: longer ones break scheduled toasts
/// (Microsoft's page, «AUMID restrictions»).
const AUMID_MAX_LEN: usize = 129;

/// Whose name the notification plugin sends toasts under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToastSender {
    /// The exe is in `…\target\<build_dir>` (`debug` or `release`): the plugin sets no app id, and
    /// the toast comes from PowerShell.
    PowerShell { build_dir: &'static str },
    /// Anywhere else: the configured `identifier`.
    Identifier,
}

/// The plugin's rule (`tauri-plugin-notification` 2.4, `desktop.rs`), repeated so the log can say
/// which way it went: the exe's directory, as displayed, ends in `\target\debug` or
/// `\target\release` — case-sensitive, as the plugin compares. `exe` is what the plugin looks at,
/// `tauri::utils::platform::current_exe()` (canonical, so `\\?\C:\…` on Windows).
pub(crate) fn toast_sender(exe: &Path) -> ToastSender {
    let sep = std::path::MAIN_SEPARATOR;
    // An exe path always has a parent; the plugin would panic without one, and this says
    // «identifier» for it, as its string test would.
    let dir = exe
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    for build_dir in ["debug", "release"] {
        if dir.ends_with(&format!("{sep}target{sep}{build_dir}")) {
            return ToastSender::PowerShell { build_dir };
        }
    }
    ToastSender::Identifier
}

/// Refuse an AUMID that cannot name the key: empty, with a backslash (it would open a subkey), or
/// longer than [`AUMID_MAX_LEN`]. Tauri checks `identifier` too; this is what the key needs.
fn check_aumid(aumid: &str) -> Result<(), String> {
    if aumid.is_empty() {
        return Err("the identifier is empty".to_string());
    }
    if aumid.contains('\\') {
        return Err(format!("the identifier contains a backslash: {aumid}"));
    }
    let len = aumid.chars().count();
    if len > AUMID_MAX_LEN {
        return Err(format!(
            "the identifier is {len} characters long, more than {AUMID_MAX_LEN}: {aumid}"
        ));
    }
    Ok(())
}

/// A registry string value, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stored {
    Absent,
    /// `REG_EXPAND_SZ` when `expand`, else `REG_SZ`.
    Text {
        text: String,
        expand: bool,
    },
    /// Another type, or not readable: why, for the log.
    Other(String),
}

impl Stored {
    /// For the log: `-`, `"AFKLink" (REG_EXPAND_SZ)`, or `<why>`.
    fn describe(&self) -> String {
        match self {
            Self::Absent => "-".to_string(),
            Self::Text { text, expand } => {
                let kind = if *expand { "REG_EXPAND_SZ" } else { "REG_SZ" };
                format!("{text:?} ({kind})")
            }
            Self::Other(why) => format!("<{why}>"),
        }
    }

    /// Exactly `text`, as `REG_EXPAND_SZ` — the type Microsoft's page gives both values.
    fn is(&self, text: &str) -> bool {
        matches!(self, Self::Text { text: t, expand: true } if t == text)
    }
}

/// The key's two values as they are now. Both [`Stored::Absent`] when there is no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Current {
    pub(crate) display_name: Stored,
    pub(crate) icon_uri: Stored,
}

/// What they should be. `icon_uri` is `None` when the icon is not on disk: `IconUri` is then left
/// as it is — a toast without our icon still has our name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wanted {
    pub(crate) display_name: String,
    pub(crate) icon_uri: Option<String>,
}

/// One value to (re)write as `REG_EXPAND_SZ`, and what it held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Write {
    pub(crate) name: &'static str,
    pub(crate) old: Stored,
    pub(crate) new: String,
}

/// The values to write: each one whose text differs, whose type is not `REG_EXPAND_SZ`, or that is
/// missing or unreadable. Empty when the registration is already right.
pub(crate) fn plan(current: &Current, wanted: &Wanted) -> Vec<Write> {
    let mut writes = Vec::new();
    if !current.display_name.is(&wanted.display_name) {
        writes.push(Write {
            name: DISPLAY_NAME,
            old: current.display_name.clone(),
            new: wanted.display_name.clone(),
        });
    }
    if let Some(icon_uri) = &wanted.icon_uri {
        if !current.icon_uri.is(icon_uri) {
            writes.push(Write {
                name: ICON_URI,
                old: current.icon_uri.clone(),
                new: icon_uri.clone(),
            });
        }
    }
    writes
}

/// Why the icon file has to be written, or `None` when it already holds `embedded`.
fn icon_write_reason(on_disk: &std::io::Result<Vec<u8>>, embedded: &[u8]) -> Option<String> {
    match on_disk {
        Ok(bytes) if bytes.as_slice() == embedded => None,
        Ok(bytes) => Some(format!(
            "differs ({} bytes on disk, {} in this build)",
            bytes.len(),
            embedded.len()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("missing".to_string()),
        Err(e) => Some(format!("not readable ({e})")),
    }
}

/// What [`ensure_icon`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IconOutcome {
    /// The file already held these bytes.
    Kept,
    /// Written; why.
    Written { why: String },
}

/// Put `bytes` at `<dir>\notification.png`, creating `dir`, unless the file already holds exactly
/// them. Returns the file's path.
pub(crate) fn ensure_icon(dir: &Path, bytes: &[u8]) -> Result<(PathBuf, IconOutcome), String> {
    let path = dir.join(ICON_FILE);
    let Some(why) = icon_write_reason(&std::fs::read(&path), bytes) else {
        return Ok((path, IconOutcome::Kept));
    };
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    std::fs::write(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok((path, IconOutcome::Written { why }))
}

/// At every start, before the first toast: say whose name toasts go out under, and register `aumid`
/// (`tauri.conf.json`'s `identifier`) with `product_name` as its display name. Never fails the
/// start; every failure is a warning.
pub(crate) fn register_at_startup(aumid: &str, product_name: Option<&str>) {
    #[cfg(windows)]
    {
        log_sender(aumid);
        let display_name = product_name.unwrap_or_else(|| {
            tracing::warn!(
                aumid,
                "tauri.conf.json has no productName; toasts are registered under the identifier"
            );
            aumid
        });
        register(aumid, display_name);
    }
    #[cfg(not(windows))]
    tracing::debug!(
        aumid,
        ?product_name,
        "toast registration: Windows only; nothing to do"
    );
}

/// The `debug` line saying which way the plugin's rule goes for this exe, and why.
#[cfg(windows)]
fn log_sender(aumid: &str) {
    let exe = match tauri::utils::platform::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            tracing::warn!(
                "toasts will not be shown: tauri-plugin-notification needs this exe's path, and it \
                 is unknown ({e})"
            );
            return;
        }
    };
    match toast_sender(&exe) {
        ToastSender::PowerShell { build_dir } => tracing::debug!(
            exe = %exe.display(),
            sender = POWERSHELL_AUMID,
            "toasts go out as Windows PowerShell: the exe is in target\\{build_dir}, where \
             tauri-plugin-notification sets no app id (a development build); {aumid} is registered \
             all the same, for copies of the exe elsewhere"
        ),
        ToastSender::Identifier => tracing::debug!(
            exe = %exe.display(),
            sender = aumid,
            "toasts go out as {aumid}: the exe is not in target\\debug or target\\release"
        ),
    }
}

/// The icon on disk, then the key ([`plan`], then write what differs).
#[cfg(windows)]
fn register(aumid: &str, display_name: &str) {
    if let Err(e) = check_aumid(aumid) {
        tracing::warn!("toast registration skipped: {e}; toasts may not be shown");
        return;
    }
    let key = format!(r"{AUMID_ROOT}\{aumid}");
    let wanted = Wanted {
        display_name: display_name.to_string(),
        icon_uri: place_icon(),
    };
    let current = registry::read(&key).unwrap_or_else(|e| {
        // not-a-key-name: a registry key path
        tracing::warn!(
            key = %format!(r"HKCU\{key}"),
            "toast registration not read ({e}); writing it whole"
        );
        Current {
            display_name: Stored::Absent,
            icon_uri: Stored::Absent,
        }
    });
    let writes = plan(&current, &wanted);
    // not-a-key-name: a registry key path
    tracing::debug!(
        key = %format!(r"HKCU\{key}"),
        display_name = %current.display_name.describe(),
        icon_uri = %current.icon_uri.describe(),
        wanted_display_name = %wanted.display_name,
        wanted_icon_uri = wanted.icon_uri.as_deref().unwrap_or("- (left as it is)"),
        writes = writes.len(),
        "toast registration: checked"
    );
    if wanted.icon_uri.is_none() {
        tracing::warn!(
            icon_uri = %current.icon_uri.describe(),
            "toast registration: IconUri left as it is, the icon is not in place; toasts may show \
             without AFKLink's icon"
        );
    }
    if writes.is_empty() {
        tracing::debug!(
            aumid,
            "toast registration: already registered (DisplayName, IconUri); nothing written"
        );
        return;
    }
    let reg = match registry::open_for_write(&key) {
        Ok(reg) => reg,
        Err(e) => {
            // not-a-key-name: a registry key path
            tracing::warn!(
                key = %format!(r"HKCU\{key}"),
                "toast registration not written: key not opened ({e}); toasts may show without \
                 AFKLink's name or icon, or not at all"
            );
            return;
        }
    };
    for w in &writes {
        match registry::set_expand_sz(&reg, w.name, &w.new) {
            // not-a-key-name: a registry key path
            Ok(()) => tracing::info!(
                key = %format!(r"HKCU\{key}"),
                value = w.name,
                old = %w.old.describe(),
                new = %w.new,
                "toast registration written"
            ),
            // not-a-key-name: a registry key path
            Err(e) => tracing::warn!(
                key = %format!(r"HKCU\{key}"),
                value = w.name,
                old = %w.old.describe(),
                new = %w.new,
                "toast registration not written ({e}); toasts may show without AFKLink's name or \
                 icon, or not at all"
            ),
        }
    }
}

/// `%APPDATA%\AFKLink\icons\notification.png` in place; its path for `IconUri`, or `None` (warned)
/// when it is not there or cannot be a registry string.
#[cfg(windows)]
fn place_icon() -> Option<String> {
    let dir = match afklink_core::paths::afklink_dir() {
        Ok(dir) => dir.join(ICON_DIR),
        Err(e) => {
            tracing::warn!("toast icon not placed: data directory unavailable ({e:#})");
            return None;
        }
    };
    let path = match ensure_icon(&dir, ICON_PNG) {
        Ok((path, IconOutcome::Kept)) => {
            tracing::debug!(path = %path.display(), "toast icon already in place");
            path
        }
        Ok((path, IconOutcome::Written { why })) => {
            tracing::info!(
                path = %path.display(),
                why,
                bytes = ICON_PNG.len(),
                "toast icon written"
            );
            path
        }
        Err(e) => {
            tracing::warn!("toast icon not written: {e}");
            return None;
        }
    };
    match path.to_str() {
        Some(p) => Some(p.to_string()),
        None => {
            tracing::warn!(
                path = %path.display(),
                "toast icon path is not valid Unicode; IconUri not set to it"
            );
            None
        }
    }
}

/// The key under `HKEY_CURRENT_USER`.
#[cfg(windows)]
mod registry {
    use std::io::ErrorKind;

    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::types::{FromRegValue, ToRegValue};
    use winreg::RegKey;

    use super::{Current, Stored, DISPLAY_NAME, ICON_URI};

    /// Both values; both absent when there is no key.
    pub(super) fn read(key: &str) -> std::io::Result<Current> {
        let reg = match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(key, KEY_READ) {
            Ok(reg) => reg,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(Current {
                    display_name: Stored::Absent,
                    icon_uri: Stored::Absent,
                })
            }
            Err(e) => return Err(e),
        };
        Ok(Current {
            display_name: value(&reg, DISPLAY_NAME),
            icon_uri: value(&reg, ICON_URI),
        })
    }

    fn value(reg: &RegKey, name: &str) -> Stored {
        match reg.get_raw_value(name) {
            Ok(raw) => {
                let expand = match raw.vtype {
                    RegType::REG_EXPAND_SZ => true,
                    RegType::REG_SZ => false,
                    ref other => return Stored::Other(format!("type {other:?}")),
                };
                match String::from_reg_value(&raw) {
                    Ok(text) => Stored::Text { text, expand },
                    Err(e) => Stored::Other(format!("not readable: {e}")),
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Stored::Absent,
            Err(e) => Stored::Other(format!("not readable: {e}")),
        }
    }

    /// The key, created if missing, open for writing values.
    pub(super) fn open_for_write(key: &str) -> std::io::Result<RegKey> {
        let (reg, _) =
            RegKey::predef(HKEY_CURRENT_USER).create_subkey_with_flags(key, KEY_SET_VALUE)?;
        Ok(reg)
    }

    /// `name` = `text` as `REG_EXPAND_SZ` (UTF-16, NUL-terminated, as winreg encodes a string).
    pub(super) fn set_expand_sz(reg: &RegKey, name: &str, text: &str) -> std::io::Result<()> {
        let mut raw = text.to_reg_value();
        raw.vtype = RegType::REG_EXPAND_SZ;
        reg.set_raw_value(name, &raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUMID: &str = "com.afklink.agent";
    const ICON: &str = r"C:\Users\Иван Петров\AppData\Roaming\AFKLink\icons\notification.png";

    fn expand(text: &str) -> Stored {
        Stored::Text {
            text: text.to_string(),
            expand: true,
        }
    }

    fn wanted() -> Wanted {
        Wanted {
            display_name: "AFKLink".to_string(),
            icon_uri: Some(ICON.to_string()),
        }
    }

    #[test]
    fn nothing_is_written_when_both_values_are_right() {
        let current = Current {
            display_name: expand("AFKLink"),
            icon_uri: expand(ICON),
        };
        assert_eq!(plan(&current, &wanted()), vec![]);
    }

    #[test]
    fn a_missing_key_gets_both_values() {
        let current = Current {
            display_name: Stored::Absent,
            icon_uri: Stored::Absent,
        };
        assert_eq!(
            plan(&current, &wanted()),
            vec![
                Write {
                    name: "DisplayName",
                    old: Stored::Absent,
                    new: "AFKLink".to_string(),
                },
                Write {
                    name: "IconUri",
                    old: Stored::Absent,
                    new: ICON.to_string(),
                },
            ]
        );
    }

    #[test]
    fn only_the_value_that_differs_is_rewritten() {
        // The profile folder was renamed, so %APPDATA% and the icon's path with it.
        let old_icon = expand(r"C:\Users\old\AppData\Roaming\AFKLink\icons\notification.png");
        let current = Current {
            display_name: expand("AFKLink"),
            icon_uri: old_icon.clone(),
        };
        assert_eq!(
            plan(&current, &wanted()),
            vec![Write {
                name: "IconUri",
                old: old_icon,
                new: ICON.to_string(),
            }]
        );
        // A renamed product.
        let current = Current {
            display_name: expand("Remoter"),
            icon_uri: expand(ICON),
        };
        let writes = plan(&current, &wanted());
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].name, "DisplayName");
        assert_eq!(writes[0].old, expand("Remoter"));
    }

    #[test]
    fn the_right_text_under_the_wrong_type_is_rewritten() {
        // REG_SZ where Microsoft's page says REG_EXPAND_SZ; a DWORD a hand edit left.
        let sz = Stored::Text {
            text: "AFKLink".to_string(),
            expand: false,
        };
        let current = Current {
            display_name: sz.clone(),
            icon_uri: Stored::Other("type REG_DWORD".to_string()),
        };
        let writes = plan(&current, &wanted());
        assert_eq!(
            writes.iter().map(|w| w.name).collect::<Vec<_>>(),
            ["DisplayName", "IconUri"]
        );
        assert_eq!(writes[0].old, sz);
    }

    #[test]
    fn display_name_and_path_compare_exactly() {
        let current = Current {
            display_name: expand("afklink"),
            icon_uri: expand(&ICON.to_uppercase()),
        };
        assert_eq!(plan(&current, &wanted()).len(), 2);
    }

    #[test]
    fn without_an_icon_on_disk_icon_uri_is_left_alone() {
        let old_icon = expand(r"D:\elsewhere\icon.png");
        let current = Current {
            display_name: expand("AFKLink"),
            icon_uri: old_icon,
        };
        let no_icon = Wanted {
            icon_uri: None,
            ..wanted()
        };
        assert_eq!(plan(&current, &no_icon), vec![]);
        let current = Current {
            display_name: Stored::Absent,
            icon_uri: Stored::Absent,
        };
        let writes = plan(&current, &no_icon);
        assert_eq!(
            writes.iter().map(|w| w.name).collect::<Vec<_>>(),
            ["DisplayName"]
        );
    }

    #[test]
    fn the_log_says_what_a_value_held() {
        assert_eq!(Stored::Absent.describe(), "-");
        assert_eq!(expand("AFKLink").describe(), r#""AFKLink" (REG_EXPAND_SZ)"#);
        assert_eq!(
            Stored::Text {
                text: "AFKLink".to_string(),
                expand: false
            }
            .describe(),
            r#""AFKLink" (REG_SZ)"#
        );
        assert_eq!(
            Stored::Other("type REG_DWORD".to_string()).describe(),
            "<type REG_DWORD>"
        );
    }

    #[test]
    fn the_aumid_must_name_one_key() {
        assert_eq!(check_aumid(AUMID), Ok(()));
        assert!(check_aumid("").is_err());
        assert!(check_aumid(r"com.afklink\agent").is_err());
        assert_eq!(check_aumid(&"a".repeat(AUMID_MAX_LEN)), Ok(()));
        assert!(check_aumid(&"a".repeat(AUMID_MAX_LEN + 1)).is_err());
    }

    #[test]
    fn the_embedded_icon_is_a_256_px_png() {
        assert_eq!(&ICON_PNG[..8], b"\x89PNG\r\n\x1a\n");
        // IHDR: width and height, big-endian, right after the chunk's length and type.
        assert_eq!(&ICON_PNG[12..16], b"IHDR");
        assert_eq!(ICON_PNG[16..20], 256u32.to_be_bytes());
        assert_eq!(ICON_PNG[20..24], 256u32.to_be_bytes());
    }

    #[test]
    fn the_icon_is_written_when_missing_or_different_and_kept_otherwise() {
        let root = std::env::temp_dir().join(format!(
            "afklink-toast-icon-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let dir = root.join("icons");
        let bytes = b"png bytes".as_slice();

        let (path, outcome) = ensure_icon(&dir, bytes).unwrap();
        assert_eq!(path, dir.join("notification.png"));
        assert_eq!(
            outcome,
            IconOutcome::Written {
                why: "missing".to_string()
            }
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        assert_eq!(ensure_icon(&dir, bytes).unwrap().1, IconOutcome::Kept);

        std::fs::write(&path, b"older icon").unwrap();
        let (_, outcome) = ensure_icon(&dir, bytes).unwrap();
        assert_eq!(
            outcome,
            IconOutcome::Written {
                why: "differs (10 bytes on disk, 9 in this build)".to_string()
            }
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unreadable_icon_is_rewritten() {
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let why = icon_write_reason(&Err(denied), b"x").unwrap();
        assert!(why.starts_with("not readable"), "{why}");
        assert_eq!(icon_write_reason(&Ok(b"x".to_vec()), b"x"), None);
    }

    #[cfg(windows)]
    #[test]
    fn toasts_come_from_powershell_only_in_target_debug_and_release() {
        // What the plugin sees: `current_exe()` canonicalised, so with the `\\?\` prefix.
        for (exe, build_dir) in [
            (
                r"\\?\C:\Users\user\Documents\remoter\agent\target\release\afklink-app.exe",
                "release",
            ),
            (r"C:\work\agent\target\debug\afklink-app.exe", "debug"),
        ] {
            assert_eq!(
                toast_sender(Path::new(exe)),
                ToastSender::PowerShell { build_dir },
                "{exe}"
            );
        }
        for exe in [
            // `bun run portable`'s copy, and where the owner puts it.
            r"\\?\C:\Users\user\Documents\remoter\agent\dist\AFKLink-0.1.0-bcc4345-portable.exe",
            r"\\?\C:\Users\Иван Петров\Downloads\AFKLink-0.1.0-bcc4345-portable.exe",
            // Not exactly `\target\release` at the end.
            r"C:\work\agent\target\release\deps\afklink-app.exe",
            r"C:\work\agent\target\x86_64-pc-windows-msvc\release\afklink-app.exe",
            r"C:\work\mytarget\release\afklink-app.exe",
            // The plugin compares case-sensitively.
            r"C:\work\agent\Target\Release\afklink-app.exe",
        ] {
            assert_eq!(
                toast_sender(Path::new(exe)),
                ToastSender::Identifier,
                "{exe}"
            );
        }
    }
}
