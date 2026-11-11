//! Owner-only, visible maintenance of the FakerInput driver. No viewer protocol reaches these
//! commands: they run only from the owner's main window, after a separate consent, one at a time.
//!
//! The official installer is embedded in the app ([`package`]), so nothing is downloaded and no
//! script runs. Install is `msiexec /i` on a verified unpacked copy, removal `msiexec /x
//! {ProductCode}`, both `/passive` — Windows Installer's progress bar and Windows' own UAC prompt,
//! no wizard: the app's dialog is the explanation and the confirmation ([`windows_installer`]).
//!
//! While an operation runs, the dialog's three steps follow what really happens ([`progress`]):
//! msiexec's log shows when the UAC prompt has been answered ([`msi_log`]), msiexec's exit and the
//! device poll show the rest.
//!
//! What the section shows ([`DriverState`]) comes from two read-only facts: is the FakerInput
//! device present (`afklink_input::fakerinput_available`), and does Windows Installer hold a
//! FakerInput product — the pinned ProductCode, or any version under its UpgradeCode.

use afklink_input::InputBackendHandle;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{Emitter, State, WebviewWindow};

#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "msiexec's log is watched on Windows only")
)]
mod msi_log;
mod package;
#[cfg_attr(
    not(windows),
    allow(
        dead_code,
        reason = "the codes are used by the Windows Installer queries only"
    )
)]
mod pinned;
mod progress;
#[cfg(windows)]
mod windows_installer;

use pinned::PACKAGE_VERSION;
use progress::{MaintenanceReport, Phase, Progress, ProgressDto, PROGRESS_EVENT};

/// The embedded package is the x64 build of FakerInput.
const INSTALL_SUPPORTED: bool = cfg!(all(windows, target_arch = "x86_64"));

/// How long a finished install or removal waits for the device to appear or go.
///
/// msiexec returns once the package has created the root device and Windows has bound the driver to
/// it (Windows' «Установить программное обеспечение для данного устройства?» comes while msiexec
/// runs), so the device is usually there at the first look. What can lag is PnP starting its six HID
/// collections — on a first install Windows also sets up its own keyboard, mouse and vendor-defined
/// drivers for them, a few seconds on a slow PC. ~3 s leaves no margin for that; 10 s does,
/// and costs nothing when the device is there at once.
const DEVICE_WAIT: Duration = Duration::from_secs(10);
const DEVICE_POLL_INTERVAL: Duration = Duration::from_millis(300);
/// Looks within [`DEVICE_WAIT`]: one at once, then one per [`DEVICE_POLL_INTERVAL`] — 34, the last
/// at ~9.9 s.
const DEVICE_POLL_ATTEMPTS: u32 =
    (DEVICE_WAIT.as_millis() / DEVICE_POLL_INTERVAL.as_millis()) as u32 + 1;

static MAINTENANCE_RUNNING: AtomicBool = AtomicBool::new(false);

/// One driver operation at a time — and no self-update while one runs, nor one while an update is
/// being applied: the updater takes this guard too (`updater`), so a running msiexec is never cut
/// off by the app restarting under it.
pub(crate) struct MaintenanceGuard;

impl MaintenanceGuard {
    pub(crate) fn acquire() -> Result<Self, String> {
        MAINTENANCE_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| "FakerInput maintenance is already running".to_owned())
    }
}

impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        MAINTENANCE_RUNNING.store(false, Ordering::Release);
    }
}

/// Whether a driver operation (or an update being applied) holds [`MaintenanceGuard`] right now.
pub(crate) fn maintenance_running() -> bool {
    MAINTENANCE_RUNNING.load(Ordering::Acquire)
}

/// The driver as the section shows it, from (product registered, device present).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverState {
    /// Neither: «Установить».
    NotInstalled,
    /// Both: «Удалить» — `msiexec /x` of the product actually found, whatever its version.
    Installed,
    /// The device without a product: installed some other way. Status only; there is nothing to
    /// remove it with.
    InstalledExternal,
    /// The product without the device (removed, or disabled in Device Manager): «Переустановить».
    /// The package creates the device only when `NOT Installed`, so neither a repair nor a second
    /// `/i` brings it back — only `/x`, then `/i`.
    Broken,
}

impl DriverState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "not_installed",
            Self::Installed => "installed",
            Self::InstalledExternal => "installed_external",
            Self::Broken => "broken",
        }
    }
}

fn driver_state(product_registered: bool, device_present: bool) -> DriverState {
    match (product_registered, device_present) {
        (false, false) => DriverState::NotInstalled,
        (true, true) => DriverState::Installed,
        (false, true) => DriverState::InstalledExternal,
        (true, false) => DriverState::Broken,
    }
}

/// A FakerInput product Windows Installer holds: what `msiexec /x` removes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegisteredProduct {
    code: String,
    /// `VersionString`, when Windows Installer reports it.
    version: Option<String>,
}

#[derive(Serialize)]
pub struct DriverStatus {
    state: DriverState,
    install_supported: bool,
    /// For the dialog's hints, which name the buttons of Windows' own windows.
    windows_language: WindowsLanguage,
}

/// The language Windows draws its own windows in — the UAC prompt, «Безопасность Windows» — so the
/// driver dialog can name their buttons as they are labelled («Да» or «Yes»). The window's table of
/// those words is `WINDOWS_WORDS` in `DriverMaintenance.tsx`; for [`Self::Other`] its hints name
/// no button.
///
/// Windows' display language (`GetUserDefaultUILanguage`), not the app's: the app's is the owner's
/// choice, and «Автоматически» follows the regional format (`GetUserDefaultLocaleName`,
/// `afklink_i18n`) — which on an English Windows set to Russian formats is Russian while every
/// prompt says «Yes».
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsLanguage {
    Ru,
    En,
    /// A language whose button names the app has not checked.
    Other,
}

impl WindowsLanguage {
    /// From a LANGID: its primary language (the low 10 bits), whatever the region — `en-GB`
    /// prompts say «Yes» as `en-US` ones do.
    fn from_langid(langid: u16) -> Self {
        const PRIMARY_MASK: u16 = 0x3ff;
        const LANG_ENGLISH: u16 = 0x09;
        const LANG_RUSSIAN: u16 = 0x19;
        match langid & PRIMARY_MASK {
            LANG_RUSSIAN => Self::Ru,
            LANG_ENGLISH => Self::En,
            _ => Self::Other,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Ru => "ru",
            Self::En => "en",
            Self::Other => "other",
        }
    }
}

/// Windows' display language, read on every status request (a sign-out is all it takes to change
/// it); each read at `debug` with the LANGID it came from.
#[cfg(windows)]
fn windows_language() -> WindowsLanguage {
    // SAFETY: no arguments; returns the calling user's UI language as a LANGID.
    let langid = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
    let language = WindowsLanguage::from_langid(langid);
    tracing::debug!(
        langid = %format_args!("{langid:#06x}"),
        language = language.as_str(),
        "Windows display language, for the driver dialog's button names"
    );
    language
}

#[cfg(not(windows))]
fn windows_language() -> WindowsLanguage {
    let language = WindowsLanguage::Other;
    tracing::debug!(
        language = language.as_str(),
        "no Windows display language on this platform; the driver dialog names no button"
    );
    language
}

/// How an operation ended, for the dialog's last line. Inside the operation a failure is an `Err`,
/// with the reason in the log; the command's answer turns one that happened after the operation
/// started into [`Self::Failed`] (`progress::Progress::report`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceOutcome {
    Done,
    RestartRequired,
    /// The UAC prompt declined (1602), or the elevation refused by policy (1625).
    Cancelled,
    /// Another Windows installation is in progress (1618).
    InstallerBusy,
    /// Windows Installer finished the install, but the device did not appear within
    /// [`DEVICE_WAIT`]: the dialog stops at its last step («Запуск») instead of «Готово», says
    /// «Драйвер не запустился — переустанови» (`app.fakerInputNotStarted`), and the section
    /// shows the driver not working, with «Переустановить».
    DeviceMissing,
    /// Started, then failed; the reason is in the log. Only in the command's answer.
    Failed,
}

/// One msiexec run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MsiOperation {
    Install,
    Uninstall,
}

impl MsiOperation {
    fn switch(self) -> &'static str {
        match self {
            Self::Install => "/i",
            Self::Uninstall => "/x",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Uninstall => "uninstall",
        }
    }
}

/// What msiexec acts on: the unpacked package for `/i`, a registered ProductCode for `/x`.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "msiexec runs on Windows only")
)]
enum MsiTarget<'a> {
    Package(&'a Path),
    Product(&'a str),
}

/// msiexec's exit code, read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MsiExit {
    Success,
    /// 3010: done, but Windows must restart to finish.
    RestartRequired,
    /// 1602 (`ERROR_INSTALL_USEREXIT`): the owner answered «Нет» to the UAC prompt — `/passive`
    /// has no Cancel button, so nothing else cancels. 1223 (`ERROR_CANCELLED`, the credential
    /// request's own 0x800704C7) means the same, should msiexec ever pass it on.
    Cancelled,
    /// 1625 (`ERROR_INSTALL_PACKAGE_REJECTED`, «forbidden by system policy»): policy, not a click,
    /// refused — UAC set to deny elevation requests automatically, or Windows Installer restricted.
    /// Nothing changed; the dialog says «Отменено» as for a declined prompt, the log says which.
    RefusedByPolicy,
    /// 1605, for `/x` only: the product is not installed — nothing left to remove.
    NotInstalled,
    /// 1618: another installation is in progress.
    InstallerBusy,
    Failed,
}

impl MsiExit {
    fn meaning(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::RestartRequired => "success, Windows must restart to finish",
            Self::Cancelled => "cancelled: the UAC prompt was declined",
            Self::RefusedByPolicy => {
                "refused by system policy (elevation denied without a prompt, or Windows Installer \
                 restricted); nothing changed"
            }
            Self::NotInstalled => "the product is not installed; nothing to remove",
            Self::InstallerBusy => "another Windows installation is in progress",
            Self::Failed => "failed",
        }
    }
}

fn msi_exit(operation: MsiOperation, code: i32) -> MsiExit {
    match code {
        0 => MsiExit::Success,
        3010 => MsiExit::RestartRequired,
        1602 | 1223 => MsiExit::Cancelled,
        1625 => MsiExit::RefusedByPolicy,
        1605 if operation == MsiOperation::Uninstall => MsiExit::NotInstalled,
        1618 => MsiExit::InstallerBusy,
        _ => MsiExit::Failed,
    }
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` in hex digits: the only shape handed to `msiexec /x`.
fn is_product_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    bytes.len() == 38
        && bytes[0] == b'{'
        && bytes[37] == b'}'
        && bytes[1..37].iter().enumerate().all(|(i, &c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

fn owner_window(label: &str) -> Result<(), String> {
    if label != "main" {
        return Err("Driver maintenance is only available in the owner's main window".into());
    }
    Ok(())
}

fn owner_consent(consent: bool) -> Result<(), String> {
    if !consent {
        return Err("Separate owner consent is required for driver maintenance".into());
    }
    Ok(())
}

/// Driver maintenance does not require stopping sessions: the backend is chosen per session and
/// switched live, so an install opens the device for running sessions and a removal closes it for
/// them first (they continue on SendInput). All that is gated is the owner's main window, their
/// separate consent, and the one-at-a-time guard.
fn authorize(window: &WebviewWindow, consent: bool) -> Result<MaintenanceGuard, String> {
    owner_window(window.label())?;
    owner_consent(consent)?;
    MaintenanceGuard::acquire()
}

/// Whether a status request should also reopen the device for live sessions.
///
/// Only the owner's explicit «Проверить» asks for it. The same command serves the section's mount
/// and the re-read after every operation, and those must stay read-only: a reopen there would undo
/// the close a removal made — e.g. one that needs a restart to finish, while the driver is still
/// half there and a session is live. An absent flag therefore means read-only.
fn recheck_requested(recheck: Option<bool>) -> bool {
    recheck == Some(true)
}

/// The last state read, so a change is logged once at `info` — and what the main view's driver row
/// shows ([`last_read`]).
static LAST_STATE: Mutex<Option<DriverState>> = Mutex::new(None);

/// The last status request failed before it could read the driver (its task did not run): the main
/// view's row says «Не удалось проверить драйвер» until a read works.
static STATUS_FAILED: AtomicBool = AtomicBool::new(false);

/// What the main view's «Управление в играх» row knows of the driver (`home::driver_row`): read
/// by any status request — the window asks when its main view shows, and after every operation — so
/// the window's once-a-second status never probes the device or Windows Installer itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverRead {
    /// Not read yet this run: «Проверка драйвера…».
    NotYet,
    /// The last request failed before reading.
    Failed,
    Read(DriverState),
}

pub(crate) fn last_read() -> DriverRead {
    if STATUS_FAILED.load(Ordering::Acquire) {
        return DriverRead::Failed;
    }
    match *afklink_core::lock(&LAST_STATE) {
        Some(state) => DriverRead::Read(state),
        None => DriverRead::NotYet,
    }
}

/// Install and reinstall run here (the embedded package is x64): the main view shows the driver's
/// row only where they do.
pub(crate) const fn install_supported() -> bool {
    INSTALL_SUPPORTED
}

fn note_state(state: DriverState, context: &'static str) {
    let mut last = afklink_core::lock(&LAST_STATE);
    if *last != Some(state) {
        tracing::info!(
            from = last.map_or("-", DriverState::as_str),
            to = state.as_str(),
            context,
            "FakerInput driver state changed"
        );
        *last = Some(state);
    }
}

/// Whether the FakerInput device is present — a read-only probe that sends no input. A probe that
/// fails counts as absent, with a warning: a broken device must leave the repair path open.
fn device_present() -> bool {
    match afklink_input::fakerinput_available() {
        Ok(present) => present,
        Err(error) => {
            tracing::warn!(%error, "FakerInput device probe failed; counted as absent");
            false
        }
    }
}

#[cfg(windows)]
use windows_installer::registered_product;

#[cfg(not(windows))]
fn registered_product() -> Option<RegisteredProduct> {
    tracing::debug!("FakerInput: no Windows Installer on this platform");
    None
}

/// Read both facts and derive the state. `context` says who asked, for the log.
fn read_driver(context: &'static str) -> (DriverState, Option<RegisteredProduct>) {
    let device = device_present();
    let product = registered_product();
    let state = driver_state(product.is_some(), device);
    // not-a-key-name: an installer product code
    tracing::debug!(
        context,
        device,
        product = product.as_ref().map_or("-", |p| p.code.as_str()),
        version = product
            .as_ref()
            .and_then(|p| p.version.as_deref())
            .unwrap_or("-"),
        state = state.as_str(),
        "FakerInput driver read (no input sent)"
    );
    note_state(state, context);
    (state, product)
}

/// The driver as a diagnostics report's `system.json` has it: the state the section would show,
/// whether the device opened, whether Windows Installer holds the product and its version. The same
/// read-only probe as the section's status (no input sent), logged the same way.
pub(crate) fn driver_for_report() -> serde_json::Value {
    let (state, product) = read_driver("report");
    serde_json::json!({
        "state": state.as_str(),
        "device_present": matches!(state, DriverState::Installed | DriverState::InstalledExternal),
        "product_registered": product.is_some(),
        "product_version": product.and_then(|p| p.version),
        "maintenance_running": maintenance_running(),
    })
}

/// How a bounded wait for the device ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceWait {
    /// The device's presence became what was wanted at look `attempt`; `failed` earlier looks were
    /// probes that failed (a collection still starting reads as an incomplete installation).
    Settled { attempt: u32, failed: u32 },
    /// Every look said otherwise; `failed` of them were failed probes, the last with `last_error`.
    TimedOut {
        failed: u32,
        last_error: Option<String>,
    },
}

/// Look up to `attempts` times, calling `sleep` between looks, until `probe` says the device's
/// presence is `want`. A failed probe counts as «not yet». Each look at `trace` — one per 300 ms is a
/// tick, not a decision; how the wait ended the caller logs.
fn poll_device<E: std::fmt::Display>(
    want: bool,
    attempts: u32,
    mut probe: impl FnMut() -> Result<bool, E>,
    mut sleep: impl FnMut(),
) -> DeviceWait {
    let mut failed = 0;
    let mut last_error = None;
    for attempt in 1..=attempts {
        match probe() {
            Ok(present) if present == want => return DeviceWait::Settled { attempt, failed },
            Ok(present) => {
                tracing::trace!(attempt, present, want, "FakerInput device poll: not yet");
            }
            Err(error) => {
                failed += 1;
                // `#`: anyhow's whole chain.
                let error = format!("{error:#}");
                tracing::trace!(attempt, %error, want, "FakerInput device poll: probe failed");
                last_error = Some(error);
            }
        }
        if attempt < attempts {
            sleep();
        }
    }
    DeviceWait::TimedOut { failed, last_error }
}

/// Poll the device for up to [`DEVICE_WAIT`] until its presence is `want`. Settling is logged at
/// `info` with the look and the time it took; giving up at `debug` with what the looks saw — the
/// caller warns with what it means.
fn wait_for_device(want: bool, why: &'static str) -> bool {
    let started = Instant::now();
    let wait = poll_device(
        want,
        DEVICE_POLL_ATTEMPTS,
        afklink_input::fakerinput_available,
        || std::thread::sleep(DEVICE_POLL_INTERVAL),
    );
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match wait {
        DeviceWait::Settled { attempt, failed } => {
            tracing::info!(
                why,
                present = want,
                attempt,
                failed_probes = failed,
                elapsed_ms,
                "FakerInput device poll: settled"
            );
            true
        }
        DeviceWait::TimedOut { failed, last_error } => {
            tracing::debug!(
                why,
                want,
                attempts = DEVICE_POLL_ATTEMPTS,
                failed_probes = failed,
                last_error = last_error.as_deref().unwrap_or("-"),
                elapsed_ms,
                "FakerInput device poll: gave up"
            );
            false
        }
    }
}

/// The start of every msiexec log's name; the rest is `<operation>-<UTC time>.log`.
const MSI_LOG_PREFIX: &str = "msiexec-fakerinput-";

/// msiexec logs kept in the logs folder, the one about to be written included. They are not the
/// app's daily files, so the appender's «7 days» does not reach them; each run's verbose log is
/// a few hundred kilobytes, and the last ten operations are more than any diagnosis goes back.
const MSI_LOGS_KEPT: usize = 10;

/// `%APPDATA%\AFKLink\logs\msiexec-fakerinput-<operation>-<UTC time>.log`, beside the app's own
/// log. `None`, with a warning, when that folder cannot be had: the operation still runs, without
/// msiexec's verbose log. Older msiexec logs past [`MSI_LOGS_KEPT`] are removed first.
fn msi_log_path(operation: MsiOperation) -> Option<PathBuf> {
    let dir = match crate::logs_dir() {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(
                "FakerInput: no folder for the Windows Installer log ({e}); running without it"
            );
            return None;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            dir = %dir.display(),
            "FakerInput: Windows Installer log folder not created ({e}); running without the log"
        );
        return None;
    }
    prune_msi_logs(&dir);
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Some(dir.join(format!(
        "{MSI_LOG_PREFIX}{}-{}.log",
        operation.name(),
        utc_stamp(secs)
    )))
}

/// Remove the msiexec logs in `dir` beyond the newest `MSI_LOGS_KEPT - 1`, making room for the one
/// about to be written. Each removal at `debug`, each failure at `warn`; a failure never stops the
/// operation.
fn prune_msi_logs(dir: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(
                dir = %dir.display(),
                "FakerInput: old Windows Installer logs not checked ({e})"
            );
            return;
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) if entry.file_type().is_ok_and(|t| t.is_file()) => {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                dir = %dir.display(),
                "FakerInput: an entry of the logs folder not read ({e})"
            ),
        }
    }
    let stale = msi_logs_to_prune(names, MSI_LOGS_KEPT.saturating_sub(1));
    tracing::debug!(
        stale = stale.len(),
        kept = MSI_LOGS_KEPT,
        "FakerInput: Windows Installer logs past the newest {MSI_LOGS_KEPT} to remove"
    );
    for name in stale {
        let path = dir.join(&name);
        match std::fs::remove_file(&path) {
            Ok(()) => {
                tracing::debug!(file = %name, "FakerInput: old Windows Installer log removed")
            }
            Err(e) => tracing::warn!(
                file = %path.display(),
                "FakerInput: old Windows Installer log not removed ({e})"
            ),
        }
    }
}

/// Which of `names` to remove so that the newest `keep` msiexec logs stay: only names of our shape
/// (`msiexec-fakerinput-<operation>-YYYYMMDD-HHMMSSZ.log`), ordered by the UTC time in them, not by
/// the operation that happens to come first alphabetically. Anything else in the folder — the
/// app's own daily logs, a file someone put there — is never touched.
fn msi_logs_to_prune(names: Vec<String>, keep: usize) -> Vec<String> {
    let mut ours: Vec<(String, String)> = names
        .into_iter()
        .filter_map(|name| Some((msi_log_stamp(&name)?.to_owned(), name)))
        .collect();
    // Newest first; the name breaks a tie within one second (a reinstall's two runs).
    ours.sort_by(|a, b| b.cmp(a));
    ours.into_iter().skip(keep).map(|(_, name)| name).collect()
}

/// The `YYYYMMDD-HHMMSSZ` in a msiexec log's name, or `None` when the name is not one of ours. Also
/// how a diagnostics report picks the newest of them (`diagnostics::package`).
pub(crate) fn msi_log_stamp(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(MSI_LOG_PREFIX)?.strip_suffix(".log")?;
    // `<operation>-` before the stamp, and the stamp itself is 16 characters.
    let at = rest.len().checked_sub(16)?;
    let (operation, stamp) = (rest.get(..at)?, rest.get(at..)?);
    let shape_ok = stamp.bytes().enumerate().all(|(i, b)| match i {
        8 => b == b'-',
        15 => b == b'Z',
        _ => b.is_ascii_digit(),
    });
    let operation_ok = operation
        .strip_suffix('-')
        .is_some_and(|op| !op.is_empty() && op.bytes().all(|b| b.is_ascii_lowercase()));
    (shape_ok && operation_ok).then_some(stamp)
}

/// `YYYYMMDD-HHMMSSZ`, UTC like the app log's file date.
fn utc_stamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to (year, month, day). Shared with the
/// diagnostics report's dates (`diagnostics`).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Run msiexec (passive, waited for) and read its exit code; the code, its meaning and the verbose
/// log's path go to the log. While it runs, its log moves `progress` from the consent on to the
/// work — or, when the log cannot tell, shows the two together.
#[cfg(windows)]
fn msiexec(
    operation: MsiOperation,
    target: MsiTarget<'_>,
    progress: &mut Progress,
) -> Result<(i32, MsiExit), String> {
    let log = msi_log_path(operation);
    if log.is_none() {
        tracing::debug!(
            operation = operation.name(),
            "FakerInput: no Windows Installer log to watch; permission and work are shown together"
        );
        progress.enter(Phase::Unobserved(operation));
    }
    let mut on_watch = |event: msi_log::WatchEvent| match event {
        msi_log::WatchEvent::PastConsent(_) => progress.enter(Phase::Working(operation)),
        msi_log::WatchEvent::Blind => progress.enter(Phase::Unobserved(operation)),
    };
    let code = windows_installer::run_msiexec(operation, target, log.as_deref(), &mut on_watch)?;
    let exit = msi_exit(operation, code);
    let log = log.map_or_else(|| "-".to_owned(), |p| p.display().to_string());
    if exit == MsiExit::Failed {
        // not-a-key-name: an installer exit code
        tracing::warn!(
            operation = operation.name(),
            code,
            meaning = exit.meaning(),
            %log,
            "FakerInput: Windows Installer exited"
        );
    } else {
        // not-a-key-name: an installer exit code
        tracing::info!(
            operation = operation.name(),
            code,
            meaning = exit.meaning(),
            %log,
            "FakerInput: Windows Installer exited"
        );
    }
    Ok((code, exit))
}

#[cfg(not(windows))]
fn msiexec(
    operation: MsiOperation,
    _target: MsiTarget<'_>,
    _progress: &mut Progress,
) -> Result<(i32, MsiExit), String> {
    Err(format!("msiexec {} requires Windows", operation.name()))
}

/// `msiexec /i` on the embedded package, then open the device for live sessions. How it ended goes
/// to the server as `driver_install_finished` ([`install_finished`]).
fn install_package(
    handle: &InputBackendHandle,
    progress: &mut Progress,
) -> Result<MaintenanceOutcome, String> {
    use afklink_protocol::metrics::DriverInstallOutcome as Out;
    let started = std::time::Instant::now();
    progress.enter(Phase::Consent(MsiOperation::Install));
    let staged = match package::StagedPackage::unpack() {
        Ok(staged) => staged,
        Err(e) => {
            install_finished(started, Out::Failed, "unpack", None);
            return Err(e);
        }
    };
    let result = msiexec(
        MsiOperation::Install,
        MsiTarget::Package(staged.path()),
        progress,
    );
    // msiexec has exited (or never started): the copy goes either way, before the result is read.
    drop(staged);
    let (code, exit) = match result {
        Ok(ran) => ran,
        Err(e) => {
            install_finished(started, Out::Failed, "msiexec_start", None);
            return Err(e);
        }
    };
    let code_n = Some(i64::from(code));
    match exit {
        MsiExit::Success => {
            progress.enter(Phase::Device(MsiOperation::Install));
            // Wait for PnP here, the dialog on «Запуск»: «Готово» only once the device is
            // really there, and the status read next sees it rather than a product without one.
            if !wait_for_device(true, "after install") {
                tracing::warn!(
                    wait_s = DEVICE_WAIT.as_secs(),
                    "FakerInput: installed, but the device did not appear in time; the dialog stops \
                     at «Запуск» (device_missing) and the section will show the driver not \
                     working"
                );
                install_finished(started, Out::Failed, "device", code_n);
                return Ok(MaintenanceOutcome::DeviceMissing);
            }
            // Live sessions: open the device now and switch them to HID — a single look, since it
            // has just been seen. A no-op without a live session (the next one's probe opens it).
            handle.refresh_driver(false);
            install_finished(started, Out::Ok, "done", code_n);
            Ok(MaintenanceOutcome::Done)
        }
        MsiExit::RestartRequired => {
            // The device may be there already: one look for live sessions, no wait.
            tracing::debug!("FakerInput: install needs a restart; one look for the device");
            handle.refresh_driver(false);
            install_finished(started, Out::Ok, "restart_required", code_n);
            Ok(MaintenanceOutcome::RestartRequired)
        }
        MsiExit::Cancelled => {
            install_finished(started, Out::Cancelled, "uac", code_n);
            Ok(MaintenanceOutcome::Cancelled)
        }
        // Policy, not a click: elevation refused without a prompt. Counted as a failure.
        MsiExit::RefusedByPolicy => {
            install_finished(started, Out::Failed, "uac_policy", code_n);
            Ok(MaintenanceOutcome::Cancelled)
        }
        MsiExit::InstallerBusy => {
            install_finished(started, Out::Failed, "installer_busy", code_n);
            Ok(MaintenanceOutcome::InstallerBusy)
        }
        MsiExit::NotInstalled | MsiExit::Failed => {
            install_finished(started, Out::Failed, "msiexec", code_n);
            Err(format!(
                "FakerInput installation failed (msiexec exit {code}); see the Windows Installer log"
            ))
        }
    }
}

/// The driver's installer ended (`driver_install_finished`, `afklink_core::agent_events`): how, at
/// which step, `msiexec`'s exit code, and how long since the owner's «Установить» — the UAC prompt's
/// wait included. Logged by the queue as it is recorded.
fn install_finished(
    started: std::time::Instant,
    outcome: afklink_protocol::metrics::DriverInstallOutcome,
    step: &str,
    code: Option<i64>,
) {
    let ms = u64::try_from(started.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .min(afklink_protocol::metrics::SESSION_MS_MAX);
    // not-a-key-name: an installer exit code
    tracing::debug!(
        outcome = outcome.as_str(),
        step,
        code = ?code,
        ms,
        "FakerInput: install ended; recorded for the server"
    );
    afklink_core::agent_events::record(
        afklink_protocol::metrics::AgentEventKind::DriverInstallFinished {
            outcome,
            step: step.to_string(),
            code,
            ms,
        },
    );
}

/// A removal that did not happen leaves the driver in place: reopen the device for live sessions
/// (single look), so they do not stay on SendInput until «Проверить».
fn reopen_after_abandoned_removal(handle: &InputBackendHandle, why: &'static str) {
    tracing::debug!(
        why,
        "FakerInput: removal did not happen; reopening the device for live sessions"
    );
    handle.refresh_driver(false);
}

/// `msiexec /x` of `product`, after closing the device for live sessions; then wait for the device
/// to go.
fn remove_product(
    handle: &InputBackendHandle,
    product: &RegisteredProduct,
    progress: &mut Progress,
) -> Result<MaintenanceOutcome, String> {
    // not-a-key-name: an installer product code
    tracing::info!(
        product = %product.code,
        version = product.version.as_deref().unwrap_or("?"),
        "FakerInput: removing the registered product"
    );
    progress.enter(Phase::Consent(MsiOperation::Uninstall));
    // Close our device handle first (releasing held input on both paths): an open handle can make
    // Windows demand a reboot to remove the driver. Live sessions continue on SendInput.
    handle.release_device_for_maintenance();
    let result = msiexec(
        MsiOperation::Uninstall,
        MsiTarget::Product(&product.code),
        progress,
    );
    match result {
        Ok((_, MsiExit::Success | MsiExit::NotInstalled)) => {
            progress.enter(Phase::Device(MsiOperation::Uninstall));
            if wait_for_device(false, "after removal") {
                Ok(MaintenanceOutcome::Done)
            } else {
                // not-a-key-name: an installer product code
                tracing::warn!(
                    product = %product.code,
                    wait_s = DEVICE_WAIT.as_secs(),
                    "FakerInput: removed, but the device is still present; Windows needs a restart \
                     to finish"
                );
                Ok(MaintenanceOutcome::RestartRequired)
            }
        }
        // Being removed: the device stays closed.
        Ok((_, MsiExit::RestartRequired)) => Ok(MaintenanceOutcome::RestartRequired),
        // The prompt declined, or the elevation refused by policy: nothing removed.
        Ok((_, exit @ (MsiExit::Cancelled | MsiExit::RefusedByPolicy))) => {
            reopen_after_abandoned_removal(handle, exit.meaning());
            Ok(MaintenanceOutcome::Cancelled)
        }
        Ok((_, MsiExit::InstallerBusy)) => {
            reopen_after_abandoned_removal(handle, "another installation in progress");
            Ok(MaintenanceOutcome::InstallerBusy)
        }
        Ok((code, MsiExit::Failed)) => {
            reopen_after_abandoned_removal(handle, "msiexec failed");
            Err(format!(
                "FakerInput removal failed (msiexec exit {code}); see the Windows Installer log"
            ))
        }
        Err(e) => {
            reopen_after_abandoned_removal(handle, "msiexec did not run");
            Err(e)
        }
    }
}

/// The owner's three operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Maintenance {
    Install,
    Remove,
    Reinstall,
}

impl Maintenance {
    fn name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Remove => "remove",
            Self::Reinstall => "reinstall",
        }
    }
}

/// Re-read the driver, check the operation still fits it, and run it, reporting each phase to
/// `progress`. Blocking.
fn maintain(
    handle: &InputBackendHandle,
    op: Maintenance,
    progress: &mut Progress,
) -> Result<MaintenanceOutcome, String> {
    let (state, product) = read_driver(op.name());
    match (op, product) {
        (Maintenance::Install, _) if state != DriverState::NotInstalled => Err(format!(
            "install refused: the driver is {} now (install needs neither device nor product)",
            state.as_str()
        )),
        (Maintenance::Install, _) => install_package(handle, progress),
        (Maintenance::Remove, Some(product)) => remove_product(handle, &product, progress),
        (Maintenance::Reinstall, Some(product)) => {
            match remove_product(handle, &product, progress)? {
                MaintenanceOutcome::Done => {
                    tracing::info!(
                        "FakerInput reinstall: removed; installing the embedded package"
                    );
                    install_package(handle, progress)
                }
                other => {
                    tracing::info!(
                        outcome = ?other,
                        "FakerInput reinstall: stopped after the removal"
                    );
                    Ok(other)
                }
            }
        }
        (Maintenance::Remove | Maintenance::Reinstall, None) => Err(format!(
            "{} refused: Windows Installer holds no FakerInput product (driver {})",
            op.name(),
            state.as_str()
        )),
    }
}

/// Delivers each phase change to the window that asked for the operation. A failed delivery is
/// logged (the first at `warn`, the rest at `debug`) and changes nothing else: the command's answer
/// still carries the final steps.
fn progress_sink(window: WebviewWindow) -> impl FnMut(&ProgressDto) + Send + 'static {
    let mut failed = false;
    move |dto: &ProgressDto| {
        if let Err(e) = window.emit_to(window.label(), PROGRESS_EVENT, dto) {
            if failed {
                tracing::debug!(steps = ?dto.steps, "FakerInput: progress not sent to the window ({e})");
            } else {
                tracing::warn!(
                    steps = ?dto.steps,
                    "FakerInput: progress not sent to the window ({e}); its dialog will jump to the \
                     result"
                );
                failed = true;
            }
        }
    }
}

async fn run_maintenance(
    window: WebviewWindow,
    backend: State<'_, InputBackendHandle>,
    consent: bool,
    op: Maintenance,
) -> Result<MaintenanceReport, String> {
    let result = async {
        let guard = authorize(&window, consent)?;
        if op != Maintenance::Remove && !INSTALL_SUPPORTED {
            return Err("The embedded FakerInput installer is for Windows x64 only".into());
        }
        tracing::info!(
            operation = op.name(),
            embedded = PACKAGE_VERSION,
            "owner consented to FakerInput maintenance; starting"
        );
        let handle = (*backend).clone();
        let sink = progress_sink(window.clone());
        tauri::async_runtime::spawn_blocking(move || {
            let _guard = guard;
            let mut progress = Progress::new(op, sink);
            let outcome = maintain(&handle, op, &mut progress);
            // The state it left, on record whether or not the window reads it again.
            read_driver("after operation");
            progress.report(outcome)
        })
        .await
        .map_err(|e| format!("FakerInput {} task failed: {e}", op.name()))?
    }
    .await;
    match &result {
        Ok(report) => tracing::info!(
            operation = op.name(),
            outcome = ?report.outcome,
            steps = ?report.steps,
            "FakerInput maintenance finished"
        ),
        Err(e) => {
            tracing::warn!(
                operation = op.name(),
                error = %e,
                "FakerInput maintenance refused before it started, or its task did not run"
            )
        }
    }
    result
}

#[tauri::command]
pub async fn get_fakerinput_status(
    window: WebviewWindow,
    backend: State<'_, InputBackendHandle>,
    recheck: Option<bool>,
) -> Result<DriverStatus, String> {
    let result = async {
        owner_window(window.label())?;
        let recheck = recheck_requested(recheck);
        let handle = (*backend).clone();
        let state = tauri::async_runtime::spawn_blocking(move || {
            if recheck {
                // «Проверить»: if the driver is present and a session is live but on SendInput
                // (e.g. after a removal that needed a restart), open it now — single attempt, no
                // wait. A no-op otherwise.
                tracing::debug!("owner asked to recheck the driver for live sessions");
                handle.refresh_driver(false);
            }
            read_driver(if recheck { "check" } else { "status" }).0
        })
        .await
        .map_err(|e| {
            if !STATUS_FAILED.swap(true, Ordering::AcqRel) {
                tracing::debug!(
                    "FakerInput status: the main view's row now says it could not check"
                );
            }
            format!("FakerInput status task failed: {e}")
        })?;
        if STATUS_FAILED.swap(false, Ordering::AcqRel) {
            tracing::debug!("FakerInput status: read again; the main view's row shows the state");
        }
        Ok(DriverStatus {
            state,
            install_supported: INSTALL_SUPPORTED,
            windows_language: windows_language(),
        })
    }
    .await;
    result.inspect_err(|e| tracing::warn!(error = %e, "FakerInput status unavailable"))
}

/// «Установить»: the embedded package, `msiexec /i`. Phases go to the window as
/// [`PROGRESS_EVENT`]; the answer is the outcome with the final steps, or an `Err` when the
/// operation was refused before it started.
#[tauri::command]
pub async fn install_fakerinput(
    window: WebviewWindow,
    backend: State<'_, InputBackendHandle>,
    consent: bool,
) -> Result<MaintenanceReport, String> {
    run_maintenance(window, backend, consent, Maintenance::Install).await
}

/// «Удалить»: `msiexec /x` of the product Windows Installer holds.
#[tauri::command]
pub async fn uninstall_fakerinput(
    window: WebviewWindow,
    backend: State<'_, InputBackendHandle>,
    consent: bool,
) -> Result<MaintenanceReport, String> {
    run_maintenance(window, backend, consent, Maintenance::Remove).await
}

/// «Переустановить» (product without device): `msiexec /x`, then `/i` — two UAC prompts.
#[tauri::command]
pub async fn reinstall_fakerinput(
    window: WebviewWindow,
    backend: State<'_, InputBackendHandle>,
    consent: bool,
) -> Result<MaintenanceReport, String> {
    run_maintenance(window, backend, consent, Maintenance::Reinstall).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The installer's end goes to the server: outcome, step, `msiexec`'s code, how long.
    #[test]
    fn an_install_that_ends_is_a_driver_install_finished() {
        use afklink_protocol::metrics::{AgentEventKind, DriverInstallOutcome};
        let queue = crate::test_event_queue();
        let started = std::time::Instant::now() - std::time::Duration::from_millis(41_250);
        install_finished(started, DriverInstallOutcome::Failed, "msiexec", Some(1603));
        let ours: Vec<_> = queue
            .waiting()
            .into_iter()
            .filter(|e| matches!(e.event, AgentEventKind::DriverInstallFinished { .. }))
            .collect();
        assert_eq!(ours.len(), 1, "{ours:?}");
        let wire =
            serde_json::to_value(afklink_protocol::AgentToServer::AgentEvent(ours[0].clone()))
                .expect("serialises");
        assert_eq!(wire["kind"], "driver_install_finished");
        assert_eq!(wire["outcome"], "failed");
        assert_eq!(wire["step"], "msiexec");
        assert_eq!(wire["code"], 1603);
        let ms = wire["ms"].as_u64().expect("ms");
        assert!((41_250..60_000).contains(&ms), "{ms}");
    }

    #[test]
    fn maintenance_requires_main_window_and_separate_consent() {
        assert!(owner_window("main").is_ok());
        assert!(owner_window("pair-request").is_err());
        // Consent is required; sessions are not (the backend switches live).
        assert!(owner_consent(false).is_err());
        assert!(owner_consent(true).is_ok());
    }

    #[test]
    fn only_an_explicit_recheck_reopens_the_device() {
        // The mount and the re-read after an operation send no flag (or `false`): read-only, so a
        // device closed for a removal is not reopened behind the owner's back.
        assert!(!recheck_requested(None));
        assert!(!recheck_requested(Some(false)));
        // «Проверить» sends `true`.
        assert!(recheck_requested(Some(true)));
    }

    #[test]
    fn msiexec_exit_codes_do_not_confuse_cancel_failure_and_success() {
        use MsiExit::*;
        use MsiOperation::*;
        for op in [Install, Uninstall] {
            assert_eq!(msi_exit(op, 0), Success);
            assert_eq!(msi_exit(op, 3010), RestartRequired);
            // The UAC prompt answered «Нет»; ERROR_CANCELLED, the credential request's own code.
            assert_eq!(msi_exit(op, 1602), Cancelled);
            assert_eq!(msi_exit(op, 1223), Cancelled);
            // Elevation refused by policy rather than by a click.
            assert_eq!(msi_exit(op, 1625), RefusedByPolicy);
            assert_eq!(msi_exit(op, 1618), InstallerBusy);
            assert_eq!(msi_exit(op, 1603), Failed);
            // Bad command line, log not writable: failures, never a cancellation.
            assert_eq!(msi_exit(op, 1639), Failed);
            assert_eq!(msi_exit(op, 1622), Failed);
            assert_eq!(msi_exit(op, 1), Failed);
            assert_eq!(msi_exit(op, -1), Failed);
        }
        // «Not installed» means nothing is left to remove — only for `/x`.
        assert_eq!(msi_exit(Uninstall, 1605), NotInstalled);
        assert_eq!(msi_exit(Install, 1605), Failed);
    }

    #[test]
    fn the_state_follows_product_and_device() {
        assert_eq!(driver_state(false, false), DriverState::NotInstalled);
        assert_eq!(driver_state(true, true), DriverState::Installed);
        assert_eq!(driver_state(false, true), DriverState::InstalledExternal);
        assert_eq!(driver_state(true, false), DriverState::Broken);
        // The names the window switches on.
        for (state, name) in [
            (DriverState::NotInstalled, "not_installed"),
            (DriverState::Installed, "installed"),
            (DriverState::InstalledExternal, "installed_external"),
            (DriverState::Broken, "broken"),
        ] {
            assert_eq!(state.as_str(), name);
            assert_eq!(
                serde_json::to_value(state).unwrap(),
                serde_json::Value::from(name)
            );
        }
    }

    #[test]
    fn outcomes_serialize_as_the_window_expects() {
        for (outcome, name) in [
            (MaintenanceOutcome::Done, "done"),
            (MaintenanceOutcome::RestartRequired, "restart_required"),
            (MaintenanceOutcome::Cancelled, "cancelled"),
            (MaintenanceOutcome::InstallerBusy, "installer_busy"),
            (MaintenanceOutcome::DeviceMissing, "device_missing"),
            (MaintenanceOutcome::Failed, "failed"),
        ] {
            assert_eq!(
                serde_json::to_value(outcome).unwrap(),
                serde_json::Value::from(name)
            );
        }
    }

    #[test]
    fn the_windows_language_is_the_primary_language_of_the_langid() {
        use WindowsLanguage::{En, Other, Ru};
        for (langid, want) in [
            // ru-RU, and Russian in another region (ru-MD).
            (0x0419, Ru),
            (0x0819, Ru),
            // en-US, en-GB: the same «Yes» and «Install».
            (0x0409, En),
            (0x0809, En),
            // Ukrainian, German, Kazakh, Chinese (Simplified): no button names.
            (0x0422, Other),
            (0x0407, Other),
            (0x043f, Other),
            (0x0804, Other),
            // LANG_NEUTRAL, should the call ever return it.
            (0x0000, Other),
        ] {
            assert_eq!(WindowsLanguage::from_langid(langid), want, "{langid:#06x}");
        }
        // The names the window switches on.
        for (language, name) in [(Ru, "ru"), (En, "en"), (Other, "other")] {
            assert_eq!(language.as_str(), name);
            assert_eq!(
                serde_json::to_value(language).unwrap(),
                serde_json::Value::from(name)
            );
        }
    }

    #[test]
    fn the_status_carries_the_windows_language() {
        let status = DriverStatus {
            state: DriverState::NotInstalled,
            install_supported: true,
            windows_language: WindowsLanguage::En,
        };
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            serde_json::json!({
                "state": "not_installed",
                "install_supported": true,
                "windows_language": "en",
            })
        );
    }

    #[test]
    fn the_device_wait_is_ten_seconds_of_looks_300_ms_apart() {
        assert_eq!(DEVICE_POLL_ATTEMPTS, 34);
        // The last look falls inside the budget, one more would not.
        let span = DEVICE_POLL_INTERVAL * (DEVICE_POLL_ATTEMPTS - 1);
        assert!(span <= DEVICE_WAIT, "{span:?}");
        assert!(span + DEVICE_POLL_INTERVAL > DEVICE_WAIT, "{span:?}");
    }

    /// `poll_device` over a scripted sequence of probe answers; returns how it ended and how many
    /// times it slept.
    fn poll(want: bool, attempts: u32, answers: &[Result<bool, &str>]) -> (DeviceWait, usize) {
        let mut answers = answers.iter().cloned();
        let mut slept = 0;
        let wait = poll_device(
            want,
            attempts,
            || answers.next().unwrap_or(Ok(!want)),
            || slept += 1,
        );
        (wait, slept)
    }

    #[test]
    fn the_device_poll_says_at_which_look_it_settled() {
        // After an install: there at once — no sleep at all.
        assert_eq!(
            poll(true, 34, &[Ok(true)]),
            (
                DeviceWait::Settled {
                    attempt: 1,
                    failed: 0
                },
                0
            )
        );
        // Two looks too early, one while PnP had started only some collections (the probe calls
        // that an incomplete installation), then there.
        assert_eq!(
            poll(
                true,
                34,
                &[Ok(false), Ok(false), Err("incomplete"), Ok(true)]
            ),
            (
                DeviceWait::Settled {
                    attempt: 4,
                    failed: 1
                },
                3
            )
        );
        // After a removal: gone at the second look.
        assert_eq!(
            poll(false, 34, &[Ok(true), Ok(false)]),
            (
                DeviceWait::Settled {
                    attempt: 2,
                    failed: 0
                },
                1
            )
        );
    }

    #[test]
    fn a_device_that_never_comes_times_out_after_every_look() {
        // Never there: every look made, no sleep after the last, the last failure kept.
        assert_eq!(
            poll(true, 5, &[Err("first"), Ok(false), Err("last")]),
            (
                DeviceWait::TimedOut {
                    failed: 2,
                    last_error: Some("last".into())
                },
                4
            )
        );
        // Removal: still present at every look (Windows needs a restart).
        assert_eq!(
            poll(false, 34, &[]),
            (
                DeviceWait::TimedOut {
                    failed: 0,
                    last_error: None
                },
                33
            )
        );
    }

    #[test]
    fn only_well_formed_product_codes_reach_msiexec() {
        assert!(is_product_code(pinned::PRODUCT_CODE));
        assert!(is_product_code(pinned::UPGRADE_CODE));
        assert!(is_product_code("{17aa3e01-1012-4bf7-b908-1c499909b259}"));
        assert!(!is_product_code("17AA3E01-1012-4BF7-B908-1C499909B259"));
        assert!(!is_product_code("{17AA3E01-1012-4BF7-B908-1C499909B25}"));
        assert!(!is_product_code(
            "{17AA3E01-1012-4BF7-B908-1C499909B259} /qn"
        ));
        assert!(!is_product_code("{17AA3E01+1012-4BF7-B908-1C499909B259}"));
        assert!(!is_product_code("{17AA3E01-1012-4BF7-B908-1C499909B2G9}"));
        assert!(!is_product_code(""));
    }

    #[test]
    fn only_the_newest_msiexec_logs_are_kept_and_nothing_else_is_touched() {
        let log = |op: &str, stamp: &str| format!("{MSI_LOG_PREFIX}{op}-{stamp}.log");
        let mut names: Vec<String> = (1..=12)
            .map(|day| {
                // Alternate operations: «install» sorts before «uninstall» by name, not by time.
                let op = if day % 2 == 0 { "install" } else { "uninstall" };
                log(op, &format!("202609{day:02}-120000Z"))
            })
            .collect();
        // Not ours, or not our shape: never removed, never counted.
        let foreign = [
            "afklink-app.2026-09-01.log",
            "remoter-app.2026-08-01.log",
            "msiexec-fakerinput-install.log",
            "msiexec-fakerinput--20260901-120000Z.log",
            "msiexec-fakerinput-install-2026-09-01-1200Z.log",
            "msiexec-other-install-20260901-120000Z.log",
        ];
        names.extend(foreign.iter().map(|s| (*s).to_string()));

        let stale = msi_logs_to_prune(names.clone(), MSI_LOGS_KEPT - 1);
        // Twelve of ours, nine kept (the tenth is about to be written): the three oldest go.
        assert_eq!(
            stale,
            vec![
                log("uninstall", "20260903-120000Z"),
                log("install", "20260902-120000Z"),
                log("uninstall", "20260901-120000Z"),
            ]
        );
        for f in foreign {
            assert!(!stale.iter().any(|s| s == f), "{f}");
        }
        // Few enough: nothing to remove.
        assert!(msi_logs_to_prune(names[..5].to_vec(), MSI_LOGS_KEPT - 1).is_empty());
        // Two runs in one second (a reinstall): the name breaks the tie, deterministically.
        let same_second = vec![
            log("install", "20260928-201507Z"),
            log("uninstall", "20260928-201507Z"),
        ];
        assert_eq!(
            msi_logs_to_prune(same_second, 1),
            vec![log("install", "20260928-201507Z")]
        );
    }

    #[test]
    fn msi_log_names_carry_utc_time() {
        assert_eq!(utc_stamp(0), "19700101-000000Z");
        // 2026-09-28T20:15:07Z.
        assert_eq!(utc_stamp(1_790_626_507), "20260928-201507Z");
        // A leap day.
        assert_eq!(utc_stamp(951_782_400), "20000229-000000Z");
    }
}
