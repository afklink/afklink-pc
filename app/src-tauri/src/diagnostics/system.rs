//! `system.json`: the PC as far as a remote-desktop problem needs it — Windows and its build, the
//! regional format and display language, the displays with their sizes and scale, the CPU, the
//! memory, the virtual driver, the WebView2 Runtime. Nothing personal beyond what the log already
//! holds: no user or machine name, no paths, no network addresses.
//!
//! Each probe that fails leaves `null` and a line in `errors` (and a `warn`), never the report.

use serde_json::{json, Value};

/// A display as Tauri sees it, gathered on the command's task (`diagnostics::send_logs`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Display {
    /// Windows' device name, `\\.\DISPLAY1`.
    pub(crate) name: Option<String>,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) scale: f64,
    pub(crate) primary: bool,
}

/// Windows as a report names it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WindowsVersion {
    /// `ProductName`, e.g. «Windows 10 Pro» — which Windows 11 still says, see [`Self::label`].
    pub(crate) product: Option<String>,
    /// `DisplayVersion`, e.g. «24H2».
    pub(crate) display_version: Option<String>,
    /// `CurrentBuild`, e.g. «26100».
    pub(crate) build: Option<String>,
    /// `UBR`, the update revision: 26100.**6584**.
    pub(crate) revision: Option<u32>,
    pub(crate) edition: Option<String>,
}

/// The first build of Windows 11: the registry's `ProductName` says «Windows 10» on both.
const WINDOWS_11_BUILD: u32 = 22_000;

impl WindowsVersion {
    /// «Windows 11 Pro 24H2 (26100)» — the metadata's `os`. `None` without a product name.
    pub(crate) fn label(&self) -> Option<String> {
        let product = self.product.as_deref()?.trim();
        let build: Option<u32> = self.build.as_deref().and_then(|b| b.trim().parse().ok());
        let product = match (product.strip_prefix("Windows 10"), build) {
            (Some(rest), Some(b)) if b >= WINDOWS_11_BUILD => format!("Windows 11{rest}"),
            _ => product.to_string(),
        };
        let mut label = product;
        if let Some(v) = self.display_version.as_deref().map(str::trim) {
            if !v.is_empty() {
                label.push(' ');
                label.push_str(v);
            }
        }
        if let Some(b) = build {
            label.push_str(&format!(" ({b})"));
        }
        Some(
            label
                .chars()
                .take(afklink_protocol::diagnostics::limits::OS_CHARS)
                .collect(),
        )
    }
}

/// What the caller already knows, for `system.json`.
#[derive(Debug, Clone)]
pub(crate) struct Known {
    pub(crate) displays: Result<Vec<Display>, String>,
    /// The window's language (`ru`/`en`).
    pub(crate) app_language: String,
    pub(crate) app_uptime_s: u64,
}

/// `system.json`, and the `os` label for the metadata. Blocking (registry, a driver probe): run it
/// off the UI thread.
pub(crate) fn collect(known: Known) -> (Value, Option<String>) {
    let mut errors: Vec<String> = Vec::new();
    let mut note = |what: &str, e: String| {
        tracing::warn!(what, "diagnostics: system.json: {e}");
        errors.push(format!("{what}: {e}"));
    };

    let windows = platform::windows_version().unwrap_or_else(|e| {
        note("windows", e);
        WindowsVersion::default()
    });
    let os = windows.label();
    let user_locale = platform::user_locale()
        .map_err(|e| note("user_locale", e))
        .ok();
    let ui_language = platform::ui_language()
        .map_err(|e| note("ui_language", e))
        .ok();
    let memory = platform::memory().map_err(|e| note("memory", e)).ok();
    let cpu_name = platform::cpu_name().map_err(|e| note("cpu", e)).ok();
    let logical = std::thread::available_parallelism()
        .map(|n| n.get())
        .map_err(|e| note("cpu_count", e.to_string()))
        .ok();
    let webview2 = match crate::webview_runtime::probe() {
        crate::webview_runtime::Runtime::Present { version } => Some(version),
        crate::webview_runtime::Runtime::Missing { detail } => {
            note("webview2", detail);
            None
        }
    };
    let displays = match known.displays {
        Ok(displays) => Some(
            displays
                .iter()
                .map(|d| {
                    json!({
                        "name": d.name,
                        "width": d.width,
                        "height": d.height,
                        "x": d.x,
                        "y": d.y,
                        "scale": d.scale,
                        "primary": d.primary,
                    })
                })
                .collect::<Vec<_>>(),
        ),
        Err(e) => {
            note("displays", e);
            None
        }
    };
    let driver = crate::fakerinput_setup::driver_for_report();

    let value = json!({
        "windows": {
            "label": os,
            "product": windows.product,
            "edition": windows.edition,
            "display_version": windows.display_version,
            "build": windows.build,
            "revision": windows.revision,
        },
        "locale": {
            "format": user_locale,
            "display_language": ui_language,
            "app_language": known.app_language,
        },
        "displays": displays,
        "cpu": { "logical": logical, "name": cpu_name },
        "memory": memory.map(|(total, available)| json!({
            "total_mb": total / (1024 * 1024),
            "available_mb": available / (1024 * 1024),
        })),
        "driver": driver,
        "webview2": webview2,
        "app_uptime_s": known.app_uptime_s,
        "errors": errors,
    });
    tracing::debug!(
        os = os.as_deref().unwrap_or("-"),
        displays = value["displays"].as_array().map_or(0, Vec::len),
        logical_cpus = logical.unwrap_or(0),
        driver = %value["driver"]["state"],
        errors = value["errors"].as_array().map_or(0, Vec::len),
        "diagnostics: system.json collected"
    );
    (value, os)
}

/// The metadata's `os` alone, from the registry (no `system.json`): what an automatic report names.
/// Blocking (the registry): run it off the UI thread.
pub(crate) fn os_label() -> Option<String> {
    match platform::windows_version() {
        Ok(windows) => windows.label(),
        Err(e) => {
            tracing::debug!("diagnostics: the Windows version not read for the report: {e}");
            None
        }
    }
}

#[cfg(windows)]
mod platform {
    use windows::Win32::Globalization::{
        GetUserDefaultLocaleName, GetUserDefaultUILanguage, LCIDToLocaleName,
    };
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    use super::WindowsVersion;

    /// `LOCALE_NAME_MAX_LENGTH`.
    const LOCALE_NAME_MAX: usize = 85;

    pub(super) fn windows_version() -> Result<WindowsVersion, String> {
        let key = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .map_err(|e| format!("CurrentVersion key: {e}"))?;
        let text = |name: &str| key.get_value::<String, _>(name).ok();
        Ok(WindowsVersion {
            product: text("ProductName"),
            display_version: text("DisplayVersion"),
            build: text("CurrentBuild"),
            revision: key.get_value::<u32, _>("UBR").ok(),
            edition: text("EditionID"),
        })
    }

    pub(super) fn cpu_name() -> Result<String, String> {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            .and_then(|k| k.get_value::<String, _>("ProcessorNameString"))
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("ProcessorNameString: {e}"))
    }

    fn from_wide(buf: &[u16], len: i32) -> Result<String, String> {
        // The length counts the terminating NUL; 0 is failure.
        let len = usize::try_from(len).unwrap_or(0);
        match buf.get(..len.saturating_sub(1)) {
            Some(name) if len > 0 => Ok(String::from_utf16_lossy(name)),
            _ => Err(format!("failed: {}", windows::core::Error::from_thread())),
        }
    }

    /// The regional format, `ru-RU`.
    pub(super) fn user_locale() -> Result<String, String> {
        let mut buf = [0u16; LOCALE_NAME_MAX];
        // SAFETY: a buffer of LOCALE_NAME_MAX_LENGTH, which the call is told the length of.
        let len = unsafe { GetUserDefaultLocaleName(&mut buf) };
        from_wide(&buf, len).map_err(|e| format!("GetUserDefaultLocaleName {e}"))
    }

    /// Windows' display language, `en-US`.
    pub(super) fn ui_language() -> Result<String, String> {
        // SAFETY: no arguments.
        let langid = unsafe { GetUserDefaultUILanguage() };
        let mut buf = [0u16; LOCALE_NAME_MAX];
        // SAFETY: a buffer of LOCALE_NAME_MAX_LENGTH, which the call is told the length of.
        let len = unsafe { LCIDToLocaleName(u32::from(langid), Some(&mut buf), 0) };
        from_wide(&buf, len).map_err(|e| format!("LCIDToLocaleName({langid:#06x}) {e}"))
    }

    /// (total, available) physical memory, bytes.
    pub(super) fn memory() -> Result<(u64, u64), String> {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        // SAFETY: a MEMORYSTATUSEX with its dwLength set, as the call requires.
        unsafe { GlobalMemoryStatusEx(&mut status) }
            .map_err(|e| format!("GlobalMemoryStatusEx: {e}"))?;
        Ok((status.ullTotalPhys, status.ullAvailPhys))
    }
}

#[cfg(not(windows))]
mod platform {
    use super::WindowsVersion;

    const NONE: &str = "not on this platform";

    pub(super) fn windows_version() -> Result<WindowsVersion, String> {
        Err(NONE.into())
    }
    pub(super) fn cpu_name() -> Result<String, String> {
        Err(NONE.into())
    }
    pub(super) fn user_locale() -> Result<String, String> {
        Err(NONE.into())
    }
    pub(super) fn ui_language() -> Result<String, String> {
        Err(NONE.into())
    }
    pub(super) fn memory() -> Result<(u64, u64), String> {
        Err(NONE.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(product: &str, display: &str, build: &str) -> WindowsVersion {
        WindowsVersion {
            product: Some(product.into()),
            display_version: Some(display.into()),
            build: Some(build.into()),
            revision: Some(6584),
            edition: Some("Professional".into()),
        }
    }

    #[test]
    fn the_label_says_windows_11_where_the_registry_says_10() {
        assert_eq!(
            version("Windows 10 Pro", "24H2", "26100")
                .label()
                .as_deref(),
            Some("Windows 11 Pro 24H2 (26100)")
        );
        assert_eq!(
            version("Windows 10 Home", "22H2", "19045")
                .label()
                .as_deref(),
            Some("Windows 10 Home 22H2 (19045)")
        );
        assert_eq!(WindowsVersion::default().label(), None);
    }

    /// On the machine running the tests: every probe answers, and nothing in it names the user.
    #[cfg(windows)]
    #[test]
    fn this_pc_is_described() {
        let (value, os) = collect(Known {
            displays: Ok(vec![Display {
                name: Some(r"\\.\DISPLAY1".into()),
                width: 2560,
                height: 1440,
                x: 0,
                y: 0,
                scale: 1.25,
                primary: true,
            }]),
            app_language: "ru".into(),
            app_uptime_s: 12,
        });
        assert!(os.is_some_and(|os| os.starts_with("Windows")));
        assert!(value["locale"]["format"].is_string(), "{value}");
        assert!(value["locale"]["display_language"].is_string(), "{value}");
        assert!(
            value["memory"]["total_mb"]
                .as_u64()
                .is_some_and(|mb| mb > 0),
            "{value}"
        );
        assert!(
            value["cpu"]["logical"].as_u64().is_some_and(|n| n > 0),
            "{value}"
        );
        assert_eq!(value["displays"][0]["scale"], 1.25);
        let text = value.to_string();
        if let Ok(user) = std::env::var("USERNAME") {
            assert!(
                !text.contains(&user),
                "the user name is in system.json: {text}"
            );
        }
        if let Ok(pc) = std::env::var("COMPUTERNAME") {
            assert!(
                !text.contains(&pc),
                "the computer name is in system.json: {text}"
            );
        }
    }
}
