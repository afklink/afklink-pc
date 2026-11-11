//! Windows Installer: is FakerInput registered, and running `msiexec` in its passive mode.
//!
//! Only reads through the MSI API (`MsiQueryProductStateW`, `MsiEnumRelatedProductsW`,
//! `MsiGetProductInfoW`); every change goes through `msiexec.exe` from the system directory, with
//! `/passive` — Windows Installer's own progress bar and Windows' own UAC prompt, no wizard —
//! never silent, never elevated by us.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use windows::core::{HSTRING, PWSTR};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    MsiEnumRelatedProductsW, MsiGetProductInfoW, MsiQueryProductStateW,
    INSTALLPROPERTY_VERSIONSTRING, INSTALLSTATE,
};

use super::msi_log::{LogWatch, WatchEvent};
use super::pinned::{PACKAGE_VERSION, PRODUCT_CODE, UPGRADE_CODE};
use super::{is_product_code, MsiOperation, MsiTarget, RegisteredProduct};

/// How often a running msiexec is looked at: has it exited, what has its log said.
const MSI_WATCH_INTERVAL: Duration = Duration::from_millis(200);

const ERROR_SUCCESS: u32 = 0;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_NO_MORE_ITEMS: u32 = 259;

/// `MsiQueryProductStateW`'s answer, named for the log.
fn install_state_name(state: INSTALLSTATE) -> &'static str {
    match state.0 {
        5 => "default (installed)",
        1 => "advertised",
        2 => "absent (installed for another user)",
        -1 => "unknown (not installed)",
        -2 => "invalid argument",
        -6 => "bad configuration",
        _ => "other",
    }
}

/// Installed, or advertised: either way Windows Installer holds the product and `/x` removes it.
fn is_registered(state: INSTALLSTATE) -> bool {
    matches!(state.0, 5 | 1)
}

fn product_state(code: &str) -> INSTALLSTATE {
    // SAFETY: a valid NUL-terminated wide string that outlives the call.
    unsafe { MsiQueryProductStateW(&HSTRING::from(code)) }
}

/// The product's `VersionString`, or `None` (logged) when Windows Installer does not give it.
fn product_version(code: &str) -> Option<String> {
    let product = HSTRING::from(code);
    let mut buffer = vec![0u16; 64];
    for _ in 0..2 {
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` is writable for `len` wide chars; the strings outlive the call.
        let rc = unsafe {
            MsiGetProductInfoW(
                &product,
                INSTALLPROPERTY_VERSIONSTRING,
                Some(PWSTR(buffer.as_mut_ptr())),
                Some(&mut len as *mut u32),
            )
        };
        match rc {
            ERROR_SUCCESS => {
                let len = (len as usize).min(buffer.len());
                return Some(String::from_utf16_lossy(&buffer[..len]));
            }
            // `len` is now the length without the terminator.
            ERROR_MORE_DATA => buffer = vec![0u16; len as usize + 1],
            other => {
                tracing::warn!(
                    product = code,
                    error = other,
                    "FakerInput: Windows Installer did not report the product's version"
                );
                return None;
            }
        }
    }
    tracing::warn!(
        product = code,
        "FakerInput: the product's version kept growing between two reads; not reported"
    );
    None
}

/// Every product Windows Installer has registered under FakerInput's UpgradeCode — whatever its
/// version, whoever installed it.
fn related_products() -> Vec<String> {
    let upgrade = HSTRING::from(UPGRADE_CODE);
    let mut codes = Vec::new();
    // A product code is 38 characters; the index only walks a handful of products.
    for index in 0..64u32 {
        let mut buffer = [0u16; 39];
        // SAFETY: `buffer` holds 39 wide chars, the documented size; the string outlives the call.
        let rc =
            unsafe { MsiEnumRelatedProductsW(&upgrade, None, index, PWSTR(buffer.as_mut_ptr())) };
        match rc {
            ERROR_SUCCESS => {
                let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
                codes.push(String::from_utf16_lossy(&buffer[..len]));
            }
            ERROR_NO_MORE_ITEMS => break,
            other => {
                tracing::warn!(
                    upgrade_code = UPGRADE_CODE,
                    index,
                    error = other,
                    "FakerInput: enumerating related Windows Installer products failed; \
                     other versions may be missed"
                );
                break;
            }
        }
    }
    codes
}

/// The FakerInput product Windows Installer holds, if any: the pinned ProductCode first, else any
/// other version found by the UpgradeCode. Read-only.
pub(super) fn registered_product() -> Option<RegisteredProduct> {
    let ours = product_state(PRODUCT_CODE);
    tracing::debug!(
        product = PRODUCT_CODE,
        state = ours.0,
        meaning = install_state_name(ours),
        "FakerInput: Windows Installer product state"
    );
    let mut found: Vec<RegisteredProduct> = Vec::new();
    if is_registered(ours) {
        found.push(RegisteredProduct {
            code: PRODUCT_CODE.to_owned(),
            version: product_version(PRODUCT_CODE),
        });
    }
    let related = related_products();
    tracing::debug!(
        upgrade_code = UPGRADE_CODE,
        related = ?related,
        "FakerInput: products registered under the UpgradeCode"
    );
    for code in related {
        if code.eq_ignore_ascii_case(PRODUCT_CODE) {
            continue;
        }
        if !is_product_code(&code) {
            // not-a-key-name: an installer product code
            tracing::warn!(
                product = %code,
                "FakerInput: Windows Installer returned a malformed related product code; ignored"
            );
            continue;
        }
        let state = product_state(&code);
        if !is_registered(state) {
            // not-a-key-name: an installer product code
            tracing::debug!(
                product = %code,
                state = state.0,
                meaning = install_state_name(state),
                "FakerInput: related product listed but not installed here; ignored"
            );
            continue;
        }
        let version = product_version(&code);
        if version.as_deref() == Some(PACKAGE_VERSION) {
            // not-a-key-name: an installer product code
            tracing::debug!(
                product = %code,
                version = PACKAGE_VERSION,
                "FakerInput: the embedded version is registered under another ProductCode"
            );
        } else {
            // Not ours: installed by hand or by another program (DS4Windows ships FakerInput).
            // not-a-key-name: an installer product code
            tracing::info!(
                product = %code,
                version = version.as_deref().unwrap_or("?"),
                embedded = PACKAGE_VERSION,
                "FakerInput: another FakerInput version is registered with Windows Installer"
            );
        }
        found.push(RegisteredProduct { code, version });
    }
    if found.len() > 1 {
        tracing::warn!(
            products = ?found,
            "FakerInput: several FakerInput products are registered; operations act on the first"
        );
    }
    found.into_iter().next()
}

/// `%SystemRoot%\System32\msiexec.exe`, from the OS rather than `PATH`.
fn msiexec_path() -> Result<PathBuf, String> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buffer = [0u16; 32768];
    // SAFETY: valid writable buffer; this only resolves the OS-owned executable directory.
    let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err(format!(
            "GetSystemDirectoryW failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..len])).join("msiexec.exe"))
}

/// `"<path>"`, the form msiexec documents for paths. A path cannot contain a double quote on
/// Windows; one that does is refused rather than escaped.
fn quoted(path: &Path) -> Result<OsString, String> {
    if path.to_string_lossy().contains('"') {
        return Err(format!("path contains a double quote: {}", path.display()));
    }
    let mut out = OsString::from("\"");
    out.push(path.as_os_str());
    out.push("\"");
    Ok(out)
}

/// msiexec's command line: `/i "<package>"` or `/x {ProductCode}`, then `/passive /norestart` and,
/// when there is a log, `/l*v! "<log>"`. `target` and `log` come already quoted.
///
/// - `/passive` is `/qb!-` with `REBOOTPROMPT=S` (Microsoft, «Standard Installer Command-Line
///   Options»): basic UI — Windows Installer's small progress bar, no wizard, no licence page, no
///   «Are you sure you want to uninstall?», no Cancel button, no error boxes (the reason goes to the
///   log, the dialog says «Не удалось»). Our own dialog is the explanation and the confirmation.
///   The licence is MIT: its text ships beside the package (`resources/fakerinput/LICENSE`), and
///   MIT asks for no acceptance, so nothing is lost with the wizard's «I accept».
/// - The UAC prompt stays, so never `/quiet` or `/qn`. Windows Installer skips the prompt only for
///   a **silent** install (`MSI_LUA: Installation UI level is silent, no credential elevation is
///   possible`), and a per-machine package then fails (1625, or «Error 1730» on removal); with
///   basic UI it asks as with the wizard (Aaron Stebner, «Some useful things I have learned about
///   Windows Installer and UAC»; other exceptions: a managed product, an already elevated caller,
///   an approved package, `AlwaysInstallElevated`). FakerInput's package is per-machine
///   (`ALLUSERS=1`, no «elevation not required» bit in its Word Count) and this app runs
///   unelevated, so the owner gets Windows' ordinary consent prompt every time.
/// - `/norestart`: Windows never restarts by itself; 3010 says a restart is needed.
/// - `/l*v!`: everything, verbose, **flushed line by line** — the dialog reads this log while it
///   is written (`msi_log`), and without `!` the consent line could sit in a buffer.
fn msiexec_args(operation: MsiOperation, target: OsString, log: Option<OsString>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        operation.switch().into(),
        target,
        "/passive".into(),
        "/norestart".into(),
    ];
    if let Some(log) = log {
        args.push("/l*v!".into());
        args.push(log);
    }
    args
}

/// Run msiexec (`/passive`, see [`msiexec_args`]) and wait for it, watching its log while it runs:
/// `on_watch` hears when the log shows Windows Installer past the UAC consent, or that the log
/// cannot tell. Returns msiexec's exit code.
///
/// What the exit code can say about the prompt (read by `msi_exit`): «Нет» — 1602
/// (`ERROR_INSTALL_USEREXIT`; the log has `MSI_LUA: Credential Request return = 0x800704C7`); an
/// elevation refused by policy instead of by a click (UAC set to deny elevation requests
/// automatically, or Windows Installer restricted) — 1625 (`ERROR_INSTALL_PACKAGE_REJECTED`); 1223
/// (`ERROR_CANCELLED`) is what the credential request itself returns and is read the same way
/// should it ever surface. `/passive` has no Cancel button, so nothing else is a cancellation.
pub(super) fn run_msiexec(
    operation: MsiOperation,
    target: MsiTarget<'_>,
    log: Option<&Path>,
    on_watch: &mut dyn FnMut(WatchEvent),
) -> Result<i32, String> {
    use std::os::windows::process::CommandExt;

    let exe = msiexec_path()?;
    let target = match target {
        MsiTarget::Package(path) => quoted(path)?,
        MsiTarget::Product(code) => {
            if !is_product_code(code) {
                return Err(format!("not a product code: {code:?}"));
            }
            OsString::from(code)
        }
    };
    let args = msiexec_args(operation, target, log.map(quoted).transpose()?);
    let line = args
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    tracing::info!(
        exe = %exe.display(),
        args = %line,
        "FakerInput: starting Windows Installer (passive: its progress bar and the UAC prompt)"
    );
    let mut command = std::process::Command::new(&exe);
    for arg in &args {
        // Raw, so msiexec gets exactly the line logged above: quoting decided here, not re-escaped.
        command.raw_arg(arg);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("msiexec could not start ({}): {e}", exe.display()))?;
    tracing::debug!(
        pid = child.id(),
        watching = log.is_some(),
        "FakerInput: msiexec started"
    );
    let mut watch = log.map(LogWatch::new);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "FakerInput: msiexec's state not read ({e}); waiting for it to exit without \
                     watching its log"
                );
                // Unless the log has already shown the consent, the steps cannot move on from here.
                if watch.take().is_some_and(|w| w.watching()) {
                    on_watch(WatchEvent::Blind);
                }
                break child
                    .wait()
                    .map_err(|e| format!("msiexec could not be waited for: {e}"))?;
            }
        }
        if let Some(event) = watch.as_mut().and_then(LogWatch::poll) {
            on_watch(event);
        }
        std::thread::sleep(MSI_WATCH_INTERVAL);
    };
    let code = status
        .code()
        .ok_or_else(|| "msiexec exited without an exit code".to_owned())?;
    if let Some(watch) = watch {
        watch.finish(matches!(code, 0 | 3010));
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::super::package::StagedPackage;
    use super::*;
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MsiCloseHandle, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiRecordGetStringW,
        MsiViewExecute, MsiViewFetch, MSIDBOPEN_READONLY, MSIHANDLE,
    };

    /// Closes an MSI handle when dropped.
    struct Handle(MSIHANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: a handle this test opened and closes exactly once.
            let rc = unsafe { MsiCloseHandle(self.0) };
            assert_eq!(rc, ERROR_SUCCESS, "MsiCloseHandle");
        }
    }

    /// One value from the package's `Property` table.
    fn property(db: &Handle, name: &str) -> String {
        let query = HSTRING::from(format!(
            "SELECT `Value` FROM `Property` WHERE `Property` = '{name}'"
        ));
        let mut view = MSIHANDLE::default();
        // SAFETY: live database handle, NUL-terminated query, valid out pointer.
        let rc = unsafe { MsiDatabaseOpenViewW(db.0, &query, &mut view) };
        assert_eq!(rc, ERROR_SUCCESS, "MsiDatabaseOpenViewW({name})");
        let view = Handle(view);
        // SAFETY: live view handle; no parameter record.
        let rc = unsafe { MsiViewExecute(view.0, MSIHANDLE::default()) };
        assert_eq!(rc, ERROR_SUCCESS, "MsiViewExecute({name})");
        let mut record = MSIHANDLE::default();
        // SAFETY: live, executed view handle; valid out pointer.
        let rc = unsafe { MsiViewFetch(view.0, &mut record) };
        assert_eq!(rc, ERROR_SUCCESS, "no {name} in the Property table");
        let record = Handle(record);
        let mut buffer = vec![0u16; 256];
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` is writable for `len` wide chars.
        let rc = unsafe {
            MsiRecordGetStringW(
                record.0,
                1,
                Some(PWSTR(buffer.as_mut_ptr())),
                Some(&mut len as *mut u32),
            )
        };
        assert_eq!(rc, ERROR_SUCCESS, "MsiRecordGetStringW({name})");
        String::from_utf16_lossy(&buffer[..len as usize])
    }

    /// The guard against «replaced the file, forgot the codes»: the package really embedded in the
    /// app, unpacked the way an install unpacks it, is opened with the MSI API — read-only, as
    /// msiexec opens it, **while our read-only `FILE_SHARE_READ` handle is still held** (so the
    /// share mode that keeps the copy immutable does not lock msiexec out either) — and its
    /// identity must be the pinned one.
    #[test]
    fn the_embedded_package_has_the_pinned_identity_and_opens_while_held() {
        let staged = StagedPackage::unpack().unwrap();
        let path = HSTRING::from(staged.path());
        let mut db = MSIHANDLE::default();
        // SAFETY: NUL-terminated path, read-only persist mode, valid out pointer.
        let rc = unsafe { MsiOpenDatabaseW(&path, MSIDBOPEN_READONLY, &mut db) };
        assert_eq!(
            rc,
            ERROR_SUCCESS,
            "MsiOpenDatabaseW on the held package: {}",
            std::io::Error::from_raw_os_error(rc as i32)
        );
        let db = Handle(db);
        assert_eq!(property(&db, "ProductCode"), PRODUCT_CODE);
        assert_eq!(property(&db, "UpgradeCode"), UPGRADE_CODE);
        assert_eq!(property(&db, "ProductVersion"), PACKAGE_VERSION);
        drop(db);
        drop(staged);
    }

    #[test]
    fn product_state_names_cover_what_msi_answers() {
        assert!(is_registered(INSTALLSTATE(5)));
        assert!(is_registered(INSTALLSTATE(1)));
        assert!(!is_registered(INSTALLSTATE(-1)));
        assert!(!is_registered(INSTALLSTATE(2)));
        assert_eq!(
            install_state_name(INSTALLSTATE(-1)),
            "unknown (not installed)"
        );
    }

    #[test]
    fn msiexec_runs_passive_never_silent_and_flushes_its_log() {
        let package = quoted(Path::new(r"C:\Temp\AFKLink-FakerInput-1\x.msi")).unwrap();
        let log = quoted(Path::new(r"C:\Users\u\AppData\Roaming\AFKLink\logs\m.log")).unwrap();
        let install = msiexec_args(MsiOperation::Install, package.clone(), Some(log.clone()));
        assert_eq!(
            install,
            [
                "/i",
                r#""C:\Temp\AFKLink-FakerInput-1\x.msi""#,
                "/passive",
                "/norestart",
                "/l*v!",
                r#""C:\Users\u\AppData\Roaming\AFKLink\logs\m.log""#,
            ]
            .map(OsString::from)
        );
        let uninstall = msiexec_args(MsiOperation::Uninstall, PRODUCT_CODE.into(), Some(log));
        assert_eq!(
            uninstall[..4],
            ["/x", PRODUCT_CODE, "/passive", "/norestart"].map(OsString::from)
        );
        // Without a log folder: no `/l`, still passive.
        let no_log = msiexec_args(MsiOperation::Install, package, None);
        assert_eq!(no_log.len(), 4);

        for args in [&install, &uninstall, &no_log] {
            let args: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().to_ascii_lowercase())
                .collect();
            assert!(args.iter().any(|a| a == "/passive"), "{args:?}");
            // No silent mode in any spelling: it would skip the UAC prompt and fail.
            assert!(
                !args.iter().any(|a| a == "/quiet" || a.starts_with("/q")),
                "{args:?}"
            );
        }
    }

    #[test]
    fn paths_are_quoted_for_msiexec() {
        assert_eq!(
            quoted(Path::new(r"C:\Users\Иван Петров\AppData\Local\Temp\x.msi")).unwrap(),
            OsString::from(r#""C:\Users\Иван Петров\AppData\Local\Temp\x.msi""#)
        );
        assert!(quoted(Path::new("C:\\a\"b.msi")).is_err());
    }
}
