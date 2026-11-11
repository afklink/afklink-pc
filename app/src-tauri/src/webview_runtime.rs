//! The Microsoft Edge WebView2 Runtime, which draws every window of this app — checked before Tauri
//! starts.
//!
//! Windows 11 ships the runtime, and Edge's updater installs it on Windows 10; an old Windows 10 that
//! never got it (or had it removed) is where a portable exe lands without one. Tauri then cannot
//! create a window, and the release build — a GUI binary with no console — would end with nothing on
//! screen at all. So the runtime is looked for first, the way WebView2's own loader finds it
//! (`GetAvailableCoreWebView2BrowserVersionString`, through `tauri::webview_version`), and without one
//! the owner gets a plain Windows message box that says what is missing and opens the download page.
//!
//! The loader answers with a version when it finds a runtime (or a non-stable Edge channel it may
//! use), with an empty string or `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)` when it finds none. Any
//! error counts as missing, as Tauri itself counts it (`webview_runtime_installed` in
//! `tauri-runtime-wry` is `webview_version().is_ok()`): the same loader creates the environment, so
//! a loader that cannot answer cannot create a window either. The error is in the log.
//!
//! A machine without the runtime cannot be reproduced on the development PC (it has one, and it
//! cannot be removed from Windows 11), so the decision and the text are tested, and
//! [`SIMULATE_VAR`] makes the probe answer «missing» for a live check of the whole way out — the
//! message box, the start failure beacon (`crate::start_failure`), the exit code.

use afklink_i18n::{Locale, NativeText};

/// Microsoft's WebView2 page, with the Evergreen installer.
pub(crate) const DOWNLOAD_URL: &str = "https://developer.microsoft.com/microsoft-edge/webview2/";

/// The exit code when the runtime is missing.
pub(crate) const EXIT_NO_RUNTIME: i32 = 3;

/// `AFKLINK_SIMULATE_NO_WEBVIEW2=1` (or `true`, `yes`): the probe answers «missing» whatever is
/// installed, with [`SIMULATED_ERROR`] as the loader's error, and the loader is not asked. For a live
/// check on a PC that has the runtime; read at every probe and warned about in the log.
pub(crate) const SIMULATE_VAR: &str = "AFKLINK_SIMULATE_NO_WEBVIEW2";

/// The loader's error a simulated probe reports: its own «file not found», HRESULT included, so the
/// beacon's `detail_code` is exercised too.
pub(crate) const SIMULATED_ERROR: &str = "simulated (AFKLINK_SIMULATE_NO_WEBVIEW2): The system \
                                          cannot find the file specified. (0x80070002)";

/// Whether [`SIMULATE_VAR`]'s value turns the simulation on: `1`, `true` or `yes`, in any case, with
/// spaces around forgiven. Unset, empty, `0` or anything else: the real loader is asked.
pub(crate) fn simulate_requested(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        let v = v.trim();
        v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
    })
}

/// The HRESULT in the loader's error text, when it has one: the last `0x` followed by exactly eight
/// hex digits standing as a word of its own — how `windows::core::Error` ends its message
/// («The system cannot find the file specified. (0x80070002)»). `None` for a text without one (the
/// empty-version answer has none).
pub(crate) fn loader_hresult(detail: &str) -> Option<u32> {
    let bytes = detail.as_bytes();
    let mut found = None;
    for (at, _) in detail.match_indices(['x', 'X']) {
        let (Some(start), Some(end)) = (at.checked_sub(1), at.checked_add(9)) else {
            continue;
        };
        let word_before = start
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        let word_after = bytes
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        let Some(hex) = detail.get(at + 1..end) else {
            continue;
        };
        if bytes.get(start) == Some(&b'0')
            && !word_before
            && !word_after
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            found = u32::from_str_radix(hex, 16).ok().or(found);
        }
    }
    found
}

/// What the loader found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Runtime {
    Present { version: String },
    Missing { detail: String },
}

/// The decision, from the loader's answer (`Ok(version)` or the error's text).
pub(crate) fn assess(probe: Result<String, String>) -> Runtime {
    match probe {
        Ok(version) if !version.trim().is_empty() => Runtime::Present {
            version: version.trim().to_string(),
        },
        Ok(_) => Runtime::Missing {
            detail: "the WebView2 loader found no runtime (empty version)".to_string(),
        },
        Err(e) => Runtime::Missing {
            detail: format!("the WebView2 loader found no usable runtime: {e}"),
        },
    }
}

/// Ask the WebView2 loader — or, with [`SIMULATE_VAR`] on, answer «missing» without asking it.
pub(crate) fn probe() -> Runtime {
    let simulate = std::env::var(SIMULATE_VAR);
    if simulate_requested(simulate.as_deref().ok()) {
        tracing::warn!(
            var = SIMULATE_VAR,
            value = simulate.as_deref().unwrap_or("-"),
            "WebView2 Runtime reported missing on purpose: the loader is not asked (a live check \
             of the way out; unset the variable to start normally)"
        );
        return assess(Err(SIMULATED_ERROR.to_string()));
    }
    match &simulate {
        Ok(value) => tracing::debug!(
            var = SIMULATE_VAR,
            %value,
            "not a yes (1, true or yes): the WebView2 loader is asked"
        ),
        Err(std::env::VarError::NotUnicode(value)) => tracing::debug!(
            var = SIMULATE_VAR,
            value = ?value,
            "not Unicode, so not a yes: the WebView2 loader is asked"
        ),
        Err(std::env::VarError::NotPresent) => {}
    }
    assess(tauri::webview_version().map_err(|e| e.to_string()))
}

/// The message box's text: what is missing, and that OK opens the page (the address shown too, for
/// anyone who would rather type it).
pub(crate) fn missing_text(locale: Locale) -> String {
    format!(
        "{}\n\n{}\n{DOWNLOAD_URL}",
        NativeText::StartupWebViewMissing.t(locale),
        NativeText::StartupWebViewDownload.t(locale)
    )
}

/// Tell the owner in a message box (OK / Cancel); on OK, open the download page in the default
/// browser. Blocks until the box is closed.
#[cfg(windows)]
pub(crate) fn tell_owner(locale: Locale) {
    use windows::core::{w, HSTRING};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, IDOK, MB_ICONERROR, MB_OKCANCEL, MB_SETFOREGROUND, SW_SHOWNORMAL,
    };

    let text = HSTRING::from(missing_text(locale));
    // SAFETY: both strings are NUL-terminated and outlive the call; no owner window.
    let answer = unsafe {
        MessageBoxW(
            None,
            &text,
            w!("AFKLink"),
            MB_OKCANCEL | MB_ICONERROR | MB_SETFOREGROUND,
        )
    };
    if answer != IDOK {
        if answer.0 == 0 {
            tracing::warn!(
                "the WebView2 message box could not be shown: {}",
                std::io::Error::last_os_error()
            );
        } else {
            tracing::info!(
                answer = answer.0,
                "the owner closed the WebView2 message box without opening the page"
            );
        }
        return;
    }
    let url = HSTRING::from(DOWNLOAD_URL);
    // SAFETY: NUL-terminated strings that outlive the call; `open` on a URL hands it to the default
    // browser.
    let result = unsafe { ShellExecuteW(None, w!("open"), &url, None, None, SW_SHOWNORMAL) };
    // ShellExecuteW's documented contract: a value above 32 is success, anything else an error code.
    let code = result.0 as isize;
    if code > 32 {
        tracing::info!(
            url = DOWNLOAD_URL,
            "WebView2 download page opened for the owner"
        );
    } else {
        // not-a-key-name: a ShellExecute result code
        tracing::warn!(
            url = DOWNLOAD_URL,
            code,
            "the WebView2 download page could not be opened"
        );
    }
}

#[cfg(not(windows))]
pub(crate) fn tell_owner(locale: Locale) {
    tracing::error!("{}", missing_text(locale));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_means_present_anything_else_missing() {
        assert_eq!(
            assess(Ok("129.0.2792.65".into())),
            Runtime::Present {
                version: "129.0.2792.65".into()
            }
        );
        // A non-stable Edge channel the loader would use.
        assert!(matches!(
            assess(Ok("131.0.2903.5 beta".into())),
            Runtime::Present { .. }
        ));
        // The loader's «no runtime»: an empty version, or the file-not-found error.
        assert!(matches!(assess(Ok(String::new())), Runtime::Missing { .. }));
        assert!(matches!(assess(Ok("  ".into())), Runtime::Missing { .. }));
        let Runtime::Missing { detail } = assess(Err(
            "The system cannot find the file specified. (0x80070002)".into(),
        )) else {
            unreachable!("an error is never a runtime");
        };
        assert!(detail.contains("0x80070002"), "{detail}");
    }

    #[test]
    fn the_simulation_is_on_only_for_a_yes() {
        for on in ["1", "true", "TRUE", "Yes", " 1 ", "\ttrue\n"] {
            assert!(simulate_requested(Some(on)), "{on:?}");
        }
        for off in ["", "0", "false", "no", "2", "y", "on", "1x"] {
            assert!(!simulate_requested(Some(off)), "{off:?}");
        }
        assert!(!simulate_requested(None));
    }

    /// A simulated probe is the loader's «file not found» as `assess` words it: missing, with the
    /// HRESULT the beacon sends and the variable named, so the log says it was on purpose.
    #[test]
    fn a_simulated_probe_is_missing_with_the_loaders_code() {
        let Runtime::Missing { detail } = assess(Err(SIMULATED_ERROR.to_string())) else {
            unreachable!("a simulated probe is never a runtime");
        };
        assert!(detail.contains(SIMULATE_VAR), "{detail}");
        assert!(
            detail.contains("The system cannot find the file specified."),
            "{detail}"
        );
        assert_eq!(loader_hresult(&detail), Some(0x8007_0002));
    }

    #[test]
    fn the_hresult_is_read_from_the_loaders_error() {
        assert_eq!(
            loader_hresult(
                "the WebView2 loader found no usable runtime: The system cannot find the file \
                 specified. (0x80070002)"
            ),
            Some(0x8007_0002)
        );
        // Upper- or lowercase, `0X` too, at the very end or the very start.
        assert_eq!(
            loader_hresult("Class not registered (0x80040154)"),
            Some(0x8004_0154)
        );
        assert_eq!(loader_hresult("0X8007000E"), Some(0x8007_000E));
        assert_eq!(
            loader_hresult("0x8007000e: out of memory"),
            Some(0x8007_000E)
        );
        // The last one counts: the code `windows::core::Error` appends.
        assert_eq!(
            loader_hresult("at 0x00000001 failed with 0x80004005"),
            Some(0x8000_4005)
        );
        for none in [
            "the WebView2 loader found no runtime (empty version)",
            "",
            "0x",
            "0x8007000",          // seven digits
            "0x800700021",        // nine
            "10x80070002",        // part of a longer word
            "0x8007000g",         // not hex
            "code 0x80070002abc", // part of a longer word
            "WebView2 error",
        ] {
            assert_eq!(loader_hresult(none), None, "{none:?}");
        }
    }

    #[test]
    fn the_message_names_the_runtime_and_the_page_in_both_languages() {
        let ru = missing_text(Locale::Ru);
        assert!(ru.starts_with("Для работы AFKLink нужен Microsoft Edge WebView2 Runtime."));
        assert!(ru.contains("«ОК»"), "{ru}");
        let en = missing_text(Locale::En);
        assert!(en.contains("Microsoft Edge WebView2 Runtime"), "{en}");
        for text in [ru, en] {
            assert!(text.ends_with(DOWNLOAD_URL), "{text}");
        }
    }
}
