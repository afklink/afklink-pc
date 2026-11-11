//! Windows discovery and transport. The two vendor collections are matched by the VID/PID
//! `HidD_GetAttributes` reports and the parsed HID usages ([`super::classify`]) — never by the
//! interface path, which for this root-enumerated device carries no VID/PID — and never a
//! keyboard/mouse collection or an input hook. Also the button watch's reads of the mouse
//! ([`button_probe`]).

use std::cell::{Cell, UnsafeCell};
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::Mutex;

use afklink_core::sync::lock;
use anyhow::{ensure, Context, Result};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::*;
use windows::Win32::Devices::HumanInterfaceDevice::*;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS,
    ERROR_OPERATION_ABORTED, GENERIC_READ, GENERIC_WRITE, HANDLE, HWND, POINT,
};
use windows::Win32::Foundation::{ERROR_IO_INCOMPLETE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_CONTROL_FLAGS,
    DESKTOP_READOBJECTS, UOI_NAME,
};
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::Threading::{CreateEventW, GetCurrentProcessId, ResetEvent};
use windows::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VIRTUAL_KEY, VK_LBUTTON, VK_MBUTTON, VK_RBUTTON,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetCursorPos, GetForegroundWindow, GetGUIThreadInfo, GetSystemMetrics,
    GetWindowThreadProcessId, IsChild, WindowFromPoint, GUITHREADINFO, SM_CXSCREEN, SM_CYSCREEN,
};

use super::button_watch::ButtonProbe;
use super::{classify, is_fakerinput, Collection, Driver, Report, Target, TargetEval};

struct OwnedHandle(HANDLE);

// Windows kernel handles can be used by different threads. State's mutex serializes
// all device writes; this owner is moved, never closed while another call uses it.
unsafe impl Send for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this owns one live kernel handle, never a borrowed/pseudo handle.
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            tracing::warn!(%error, "closing FakerInput Windows handle failed");
        }
    }
}

struct DeviceList(HDEVINFO);
impl Drop for DeviceList {
    fn drop(&mut self) {
        // SAFETY: the list was returned by SetupDiGetClassDevsW and is owned here.
        if let Err(error) = unsafe { SetupDiDestroyDeviceInfoList(self.0) } {
            tracing::warn!(%error, "closing FakerInput device enumeration failed");
        }
    }
}

pub(crate) struct Device {
    control: OwnedHandle,
    write_event: OwnedHandle,
}

impl Device {
    /// Find FakerInput's two vendor collections ([`survey`]) and open them for writing. Read-only
    /// otherwise: descriptors and the API feature are read; not even a neutral input report is
    /// written. One aggregated line per probe at `debug` ([`note_probe`]).
    pub(crate) fn open() -> Result<Option<Self>> {
        let mut survey = survey()?;
        let mut last_error = survey.last_error.take();
        let mut control = None;
        let mut method = None;
        for found in &survey.collections {
            let slot = match found.kind {
                Collection::Control => &mut control,
                Collection::Api => &mut method,
                Collection::Incompatible => {
                    let error = anyhow::anyhow!(
                        "unexpected FakerInput output report length {} (collection {:04x}:{:04x})",
                        found.output_len,
                        found.usage_page,
                        found.usage
                    );
                    tracing::warn!(%error, "inspecting FakerInput HID collection failed");
                    last_error = Some(error);
                    continue;
                }
                // Keyboard, mouse, consumer control: Windows owns them; nothing to open.
                Collection::Other | Collection::Foreign => continue,
            };
            if slot.is_some() {
                tracing::debug!(
                    collection = found.kind.name(),
                    path = %found.path(),
                    "a second FakerInput vendor collection of this kind; the first one found is used"
                );
                continue;
            }
            // A vendor collection we will actually write to: reopen with write access (and
            // overlapped I/O for the bounded writes). Only these two collections are ever opened for
            // writing.
            // SAFETY: the path is NUL-terminated and lives in `survey` until this call returns.
            match unsafe {
                CreateFileW(
                    PCWSTR(found.path.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    None,
                )
            } {
                Ok(handle) => *slot = Some(OwnedHandle(handle)),
                Err(error) => {
                    tracing::warn!(
                        %error,
                        collection = found.kind.name(),
                        path = %found.path(),
                        "opening FakerInput vendor collection for writing failed"
                    );
                    last_error = Some(anyhow::Error::from(error));
                }
            }
        }
        let (has_control, has_api) = (control.is_some(), method.is_some());
        let result = match (control, method) {
            (Some(control), Some(method)) => Self::ready(control, &method).map(Some),
            (None, None) => match last_error {
                Some(error) => Err(error),
                None => Ok(None),
            },
            // Also what a poll sees for a moment while PnP is still starting the collections.
            _ => Err(anyhow::anyhow!(
                "FakerInput installation is incomplete: missing control or API collection"
            )),
        };
        note_probe(&survey, has_control, has_api, &result);
        result
    }

    /// Both vendor collections are open: check the API version (feature report 0x42 of the API
    /// collection) and make the event the bounded writes wait on. Sends nothing.
    fn ready(control: OwnedHandle, method: &OwnedHandle) -> Result<Self> {
        let mut feature = [0u8; 65];
        feature[0] = 0x42;
        // SAFETY: feature is a live 65-byte output buffer; method owns a HID handle.
        ensure!(
            unsafe { HidD_GetFeature(method.0, feature.as_mut_ptr().cast(), feature.len() as u32) },
            "FakerInput API feature query failed: {}",
            windows::core::Error::from_thread()
        );
        // UINT32 follows BYTE with C alignment in the upstream API struct.
        let version = u32::from_le_bytes([feature[4], feature[5], feature[6], feature[7]]);
        ensure!(version == 1, "unsupported FakerInput API version {version}");
        // The probe's own line says `ready`, which means this version; per look, so `trace`.
        tracing::trace!(
            api_version = version,
            "FakerInput control collection ready (no input sent)"
        );
        // SAFETY: unnamed, owned manual-reset event for serialized overlapped writes.
        let write_event = OwnedHandle(unsafe { CreateEventW(None, true, false, PCWSTR::null()) }?);
        Ok(Self {
            control,
            write_event,
        })
    }
}

/// One of FakerInput's collections, as a probe found it.
pub(crate) struct Found {
    /// The interface path, NUL-terminated: what the vendor collections are reopened by.
    path: Vec<u16>,
    pub(crate) usage_page: u16,
    pub(crate) usage: u16,
    pub(crate) output_len: u16,
    pub(crate) kind: Collection,
}

impl Found {
    /// The path without its terminator, for the log and the read-only probe test.
    pub(crate) fn path(&self) -> String {
        wide_text(&self.path)
    }
}

/// What one pass over the present HID interfaces saw.
#[derive(Default)]
pub(crate) struct Survey {
    /// Present HID interfaces looked at.
    pub(crate) interfaces: u32,
    /// Interfaces SetupAPI gave no path for.
    pub(crate) pathless: u32,
    /// Interfaces a zero-access open refused. It happens (a security key Windows guards, a device
    /// going away); whose they were is unknown, so they are counted, never blamed.
    pub(crate) unopened: u32,
    /// Interfaces opened, but whose HID attributes could not be read.
    pub(crate) unreadable: u32,
    /// Interfaces with FakerInput's VID/PID (their descriptors included, readable or not).
    pub(crate) ours: u32,
    /// FakerInput's collections whose descriptor was read, in enumeration order.
    pub(crate) collections: Vec<Found>,
    /// The last failure that concerns us — a path SetupAPI would not give, a FakerInput descriptor
    /// that could not be read: what the probe answers when it finds nothing usable.
    last_error: Option<anyhow::Error>,
}

/// Look at every present HID interface, as the official client does: open it with no access and
/// read its attributes; for FakerInput's VID/PID, also its top-level caps ([`classify`]). Nothing
/// is opened for writing here and nothing is sent.
///
/// Every interface, because FakerInput is root-enumerated: its collections' paths read
/// `\\?\hid#system&colNN#…` and carry no VID/PID, so a path filter finds none of them. A zero-access
/// handle is enough for the attribute and descriptor queries (the standard HID enumeration trick)
/// and never contends with Windows' exclusive hold on keyboards and mice — FakerInput's or anyone's.
pub(crate) fn survey() -> Result<Survey> {
    // SAFETY: no pointers or handles required for the class GUID query.
    let guid = unsafe { HidD_GetHidGuid() };
    // SAFETY: guid is live; remaining pointer/window arguments are null.
    let list = DeviceList(unsafe {
        SetupDiGetClassDevsW(
            Some(&guid),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    }?);
    let mut survey = Survey::default();
    for index in 0.. {
        let mut interface = SP_DEVICE_INTERFACE_DATA {
            cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: all pointers refer to live correctly-sized values.
        if let Err(error) =
            unsafe { SetupDiEnumDeviceInterfaces(list.0, None, &guid, index, &mut interface) }
        {
            if error.code() == ERROR_NO_MORE_ITEMS.to_hresult() {
                break;
            }
            return Err(error).context("enumerating HID interfaces");
        }
        survey.interfaces += 1;
        let path = match interface_path(&list, &interface) {
            Ok(path) => path,
            Err(error) => {
                tracing::warn!(%error, index, "reading an HID interface path failed; skipped");
                survey.pathless += 1;
                survey.last_error = Some(error);
                continue;
            }
        };
        // SAFETY: the path is NUL-terminated and outlives this synchronous call.
        let query = match unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        } {
            Ok(handle) => OwnedHandle(handle),
            Err(error) => {
                tracing::trace!(%error, path = %wide_text(&path), "HID interface not opened for its attributes; skipped");
                survey.unopened += 1;
                continue;
            }
        };
        let attributes = match attributes(&query) {
            Ok(attributes) => attributes,
            Err(error) => {
                tracing::trace!(%error, path = %wide_text(&path), "HID interface attributes unreadable; skipped");
                survey.unreadable += 1;
                continue;
            }
        };
        let (vendor_id, product_id) = (attributes.VendorID, attributes.ProductID);
        if !is_fakerinput(vendor_id, product_id) {
            tracing::trace!(
                vid = format_args!("{vendor_id:04x}"),
                pid = format_args!("{product_id:04x}"),
                "HID interface of another device"
            );
            continue;
        }
        survey.ours += 1;
        let caps = match caps(&query) {
            Ok(caps) => caps,
            Err(error) => {
                tracing::warn!(%error, path = %wide_text(&path), "reading a FakerInput collection's descriptor failed");
                survey.last_error = Some(error);
                continue;
            }
        };
        let found = Found {
            path,
            usage_page: caps.UsagePage,
            usage: caps.Usage,
            output_len: caps.OutputReportByteLength,
            kind: classify(
                vendor_id,
                product_id,
                caps.UsagePage,
                caps.Usage,
                caps.OutputReportByteLength,
            ),
        };
        tracing::trace!(
            collection = found.kind.name(),
            usage = format_args!("{:04x}:{:04x}", found.usage_page, found.usage),
            output_len = found.output_len,
            path = %found.path(),
            "FakerInput HID collection"
        );
        survey.collections.push(found);
    }
    Ok(survey)
}

/// The interface's device path, NUL-terminated.
fn interface_path(list: &DeviceList, interface: &SP_DEVICE_INTERFACE_DATA) -> Result<Vec<u16>> {
    let mut required = 0;
    // SAFETY: this is the documented size query; no output detail buffer yet.
    if let Err(error) = unsafe {
        SetupDiGetDeviceInterfaceDetailW(list.0, interface, None, 0, Some(&mut required), None)
    } {
        if error.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() {
            return Err(error).context("querying HID interface path size");
        }
    }
    ensure!(
        required as usize >= size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>(),
        "invalid HID interface path size {required}"
    );
    // usize storage supplies alignment for the Windows structure (including x86/x64 cbSize).
    let mut storage = vec![0usize; (required as usize).div_ceil(size_of::<usize>())];
    let detail = storage
        .as_mut_ptr()
        .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
    // SAFETY: storage is aligned and has at least required bytes; all pointers live.
    unsafe {
        (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
    }
    // SAFETY: as above; `required` is the size SetupAPI asked for.
    unsafe {
        SetupDiGetDeviceInterfaceDetailW(list.0, interface, Some(detail), required, None, None)
    }
    .context("reading HID interface path")?;
    // SAFETY: SetupDiGetDeviceInterfaceDetailW wrote a NUL-terminated DevicePath inside `storage`,
    // which lives until the copy is made.
    let mut path = unsafe { PCWSTR((*detail).DevicePath.as_ptr()).as_wide() }.to_vec();
    path.push(0);
    Ok(path)
}

/// A NUL-terminated (or not) UTF-16 path as text, for the log.
fn wide_text(wide: &[u16]) -> String {
    String::from_utf16_lossy(wide.strip_suffix(&[0]).unwrap_or(wide))
}

/// The collection's HID attributes (VID/PID); works on a zero-access handle.
fn attributes(handle: &OwnedHandle) -> Result<HIDD_ATTRIBUTES> {
    let mut attributes = HIDD_ATTRIBUTES {
        Size: size_of::<HIDD_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    // SAFETY: handle is valid and attributes is a live output structure.
    ensure!(
        unsafe { HidD_GetAttributes(handle.0, &mut attributes) },
        "reading HID attributes: {}",
        windows::core::Error::from_thread()
    );
    Ok(attributes)
}

/// The collection's top-level caps from its parsed descriptor; works on a zero-access handle.
fn caps(handle: &OwnedHandle) -> Result<HIDP_CAPS> {
    let mut preparsed = PHIDP_PREPARSED_DATA::default();
    // SAFETY: preparsed is an output owned by HID until freed below.
    ensure!(
        unsafe { HidD_GetPreparsedData(handle.0, &mut preparsed) },
        "reading FakerInput HID descriptor: {}",
        windows::core::Error::from_thread()
    );
    let mut caps = HIDP_CAPS::default();
    // SAFETY: preparsed came from HID and remains valid through GetCaps.
    let status = unsafe { HidP_GetCaps(preparsed, &mut caps) };
    if !unsafe { HidD_FreePreparsedData(preparsed) } {
        tracing::warn!("freeing FakerInput parsed HID descriptor failed");
    }
    ensure!(
        status.is_ok(),
        "parsing FakerInput HID capabilities: {status:?}"
    );
    Ok(caps)
}

/// The last probe's summary, so a probe that saw the same as the one before — the 300 ms polls
/// while an install or a removal settles, a session's probe after the section's — goes to `trace`
/// instead of repeating at `debug`.
static LAST_PROBE: Mutex<String> = Mutex::new(String::new());

/// One aggregated line per probe: how many HID interfaces were looked at, how many are FakerInput's,
/// which of its collections were found (usage page:usage/what it is to us), which vendor collections
/// were opened, and what the probe answers (`ready`: API v1 confirmed; `absent`; `error`: the caller
/// logs why). At `debug` when it differs from the previous probe's, else at `trace`.
fn note_probe(survey: &Survey, control: bool, api: bool, result: &Result<Option<Device>>) {
    let outcome = match result {
        Ok(Some(_)) => "ready",
        Ok(None) => "absent",
        Err(_) => "error",
    };
    let collections = if survey.collections.is_empty() {
        "-".to_owned()
    } else {
        survey
            .collections
            .iter()
            .map(|f| format!("{:04x}:{:04x}/{}", f.usage_page, f.usage, f.kind.name()))
            .collect::<Vec<_>>()
            .join(",")
    };
    let summary = format!(
        "interfaces={} unopened={} unreadable={} pathless={} ours={} collections={collections} \
         control={control} api={api} outcome={outcome}",
        survey.interfaces, survey.unopened, survey.unreadable, survey.pathless, survey.ours
    );
    let mut last = lock(&LAST_PROBE);
    if *last == summary {
        tracing::trace!(%summary, "FakerInput probe: as the last one");
        return;
    }
    tracing::debug!(
        interfaces = survey.interfaces,
        unopened = survey.unopened,
        unreadable = survey.unreadable,
        pathless = survey.pathless,
        ours = survey.ours,
        %collections,
        control,
        api,
        outcome,
        "FakerInput probe (no input sent)"
    );
    *last = summary;
}

impl Driver for Device {
    fn write(&mut self, report: &Report) -> Result<()> {
        let mut written = 0;
        // SAFETY: this owned event is used by only one write at a time under the state mutex.
        unsafe { ResetEvent(self.write_event.0) }?;
        let mut overlapped = OVERLAPPED {
            hEvent: self.write_event.0,
            ..Default::default()
        };
        // SAFETY: the buffer and OVERLAPPED stay live until completion, including cancellation.
        if let Err(error) =
            unsafe { WriteFile(self.control.0, Some(report), None, Some(&mut overlapped)) }
        {
            if error.code() != ERROR_IO_PENDING.to_hresult() {
                return Err(error).context("submitting FakerInput HID report");
            }
        }
        // The normal driver completes promptly. Bound a queued report so cleanup can cancel it.
        if let Err(error) =
            unsafe { GetOverlappedResultEx(self.control.0, &overlapped, &mut written, 250, false) }
        {
            // Cancellation is asynchronous: always drain completion before the stack buffer dies.
            if let Err(cancel) = unsafe { CancelIoEx(self.control.0, Some(&overlapped)) } {
                if cancel.code() != ERROR_NOT_FOUND.to_hresult() {
                    tracing::warn!(%cancel, "cancelling FakerInput write failed");
                }
            }
            if let Err(completion) =
                unsafe { GetOverlappedResult(self.control.0, &overlapped, &mut written, true) }
            {
                if completion.code() != ERROR_OPERATION_ABORTED.to_hresult() {
                    tracing::warn!(%completion, "draining cancelled FakerInput write failed");
                }
            }
            return Err(error).context("completing FakerInput HID report (250ms deadline)");
        }
        // Upstream Queue.c completes the write with 63 bytes (65 minus its wrapper).
        // Windows HID versions may return 65. A successful WriteFile is its client's contract.
        ensure!(
            matches!(written, 63 | 65),
            "FakerInput wrote an unexpected report length {written}"
        );
        Ok(())
    }
}

/// The fenced writer of direct HID access (`super::direct`). One owned request can outlive a timeout or cancellation request.
pub(crate) struct FencedDevice {
    io: Option<Box<FencedIo>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NeutralReport {
    Keyboard,
    Mouse,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FencedRequest {
    Other,
    Neutral {
        kind: NeutralReport,
        deadline: Instant,
    },
}

impl FencedRequest {
    fn deadline(self) -> Option<Instant> {
        match self {
            Self::Other => None,
            Self::Neutral { deadline, .. } => Some(deadline),
        }
    }

    fn confirm(self, result: Result<u32>, now: Instant) -> Result<()> {
        let written = result?;
        ensure!(matches!(written, 63 | 65), "unexpected HID report length");
        ensure!(
            self.deadline().is_none_or(|deadline| now < deadline),
            "HID cleanup report completed after deadline"
        );
        Ok(())
    }

    /// Returns true only if the requested cleanup report itself has already completed.
    fn resolve_previous(
        self,
        previous: Self,
        poll: impl FnOnce() -> Option<Result<u32>>,
    ) -> Result<bool> {
        if self != previous && self.deadline().is_some() && self.deadline() == previous.deadline() {
            // Leave the other report's proof to its own retry in this cleanup operation.
            anyhow::bail!("other neutral report awaiting confirmation");
        }
        let result = poll().context("previous HID write still pending")?;
        let confirmed = previous.confirm(result, Instant::now());
        tracing::debug!(target: afklink_core::EMBED_LOG_TARGET, success = confirmed.is_ok(), "timed-out HID write has reached completion");
        if self == previous && self.deadline().is_some() {
            return confirmed.map(|()| true);
        }
        // Drain an older cleanup or input report without crediting it to this request.
        Ok(false)
    }
}

struct FencedIo {
    device: Device,
    report: UnsafeCell<Report>,
    overlapped: UnsafeCell<OVERLAPPED>,
    pending: Cell<Option<FencedRequest>>,
}

impl FencedDevice {
    pub(crate) fn open() -> Result<Option<Self>> {
        Device::open().map(|device| device.map(Self::wrap))
    }

    fn wrap(device: Device) -> Self {
        Self {
            io: Some(Box::new(FencedIo {
                device,
                report: UnsafeCell::new([0; 65]),
                overlapped: UnsafeCell::new(OVERLAPPED::default()),
                pending: Cell::new(None),
            })),
        }
    }

    pub(crate) fn write(
        &self,
        report: &Report,
        local_stop: Option<&AtomicBool>,
        generation: Option<(&AtomicU64, u64)>,
        authority: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) -> Result<()> {
        self.write_report(
            report,
            local_stop,
            generation,
            authority,
            FencedRequest::Other,
        )
    }

    pub(crate) fn neutral(&self, kind: NeutralReport, deadline: Instant) -> Result<()> {
        let report = match kind {
            NeutralReport::Keyboard => super::keyboard(0, &Default::default()),
            NeutralReport::Mouse => super::mouse(0, 0, 0, 0, 0),
        };
        self.write_report(
            &report,
            None,
            None,
            None,
            FencedRequest::Neutral { kind, deadline },
        )
    }

    fn write_report(
        &self,
        report: &Report,
        local_stop: Option<&AtomicBool>,
        generation: Option<(&AtomicU64, u64)>,
        authority: Option<&(dyn Fn() -> bool + Send + Sync)>,
        request: FencedRequest,
    ) -> Result<()> {
        let io = self.io.as_deref().context("HID device unavailable")?;
        if let Some(previous) = io.pending.get() {
            if request.resolve_previous(previous, || io.wait(0))? {
                return Ok(());
            }
        }
        // SAFETY: the event is owned exclusively by this writer and there is no pending write.
        unsafe { ResetEvent(io.device.write_event.0) }.context("reset HID write event")?;
        // SAFETY: no outstanding operation can access these buffers. The Box keeps both addresses
        // stable, and they are never read/replaced in Rust while Windows may still use them.
        unsafe {
            io.report.get().write(*report);
            io.overlapped.get().write(OVERLAPPED {
                hEvent: io.device.write_event.0,
                ..Default::default()
            });
        }
        let deadline = request.deadline();
        ensure!(
            deadline.is_none_or(|at| Instant::now() < at),
            "HID cleanup report deadline"
        );
        // This is the final admission point before WriteFile. Neutral reports carry no stop
        // dependency. Windows can still complete an operation admitted before the stop.
        ensure!(
            local_stop.is_none_or(|stop| !stop.load(Ordering::Acquire)),
            "HID report refused after local stop"
        );
        if generation.is_some_and(|(signal, expected)| signal.load(Ordering::Acquire) != expected)
            || authority.is_some_and(|permits| !permits())
        {
            tracing::trace!(target: afklink_core::EMBED_LOG_TARGET, "HID positive report refused at final authority gate");
            return Err(super::direct::HidInputPaused.into());
        }
        io.pending.set(Some(request));
        // SAFETY: the buffer, OVERLAPPED, event and file handle stay live until a checked
        // completion. WriteFile reads the report and writes OVERLAPPED through its raw pointer.
        let started = unsafe {
            WriteFile(
                io.device.control.0,
                Some(&*io.report.get()),
                None,
                Some(io.overlapped.get()),
            )
        };
        let completed = match started {
            Ok(()) => io.result(),
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {
                let wait_ms = deadline.map_or(250, |at| {
                    at.saturating_duration_since(Instant::now())
                        .as_millis()
                        .min(250) as u32
                });
                io.wait(wait_ms)
            }
            Err(error) => {
                io.pending.set(None);
                return Err(error).context("submit HID report");
            }
        };
        let Some(result) = completed else {
            // SAFETY: this request and its handles are still live. Cancellation is a request,
            // never a completion. All later checks use a zero-duration wait.
            if let Err(error) =
                unsafe { CancelIoEx(io.device.control.0, Some(io.overlapped.get())) }
            {
                if error.code() != ERROR_NOT_FOUND.to_hresult() {
                    tracing::warn!(target: afklink_core::EMBED_LOG_TARGET, "HID cancellation request failed");
                }
            }
            tracing::warn!(target: afklink_core::EMBED_LOG_TARGET, "HID write timed out; fencing further writes until completion");
            anyhow::bail!("HID write completion deadline");
        };
        request.confirm(result, Instant::now())
    }
}

impl FencedIo {
    fn wait(&self, milliseconds: u32) -> Option<Result<u32>> {
        // SAFETY: this is the manual-reset event assigned to the only outstanding write.
        if unsafe { WaitForSingleObject(self.device.write_event.0, milliseconds) } != WAIT_OBJECT_0
        {
            return None;
        }
        self.result()
    }

    /// After the event is signaled (or WriteFile reported synchronous completion), retrieve the
    /// final status without blocking. Even an unexpected pending result leaves the request owned.
    fn result(&self) -> Option<Result<u32>> {
        let mut written = 0;
        // SAFETY: stable address in the request, its own live handle, and a local u32 for the result.
        let result = unsafe {
            GetOverlappedResult(
                self.device.control.0,
                self.overlapped.get(),
                &mut written,
                false,
            )
        };
        if result
            .as_ref()
            .is_err_and(|error| error.code() == ERROR_IO_INCOMPLETE.to_hresult())
        {
            return None;
        }
        self.pending.set(None);
        Some(result.map(|()| written).context("complete HID report"))
    }
}

impl Drop for FencedDevice {
    fn drop(&mut self) {
        if let Some(io) = self.io.take() {
            if io.pending.get().is_some() && io.wait(0).is_none() {
                tracing::error!(target: afklink_core::EMBED_LOG_TARGET, "retaining unresolved HID request until process exit");
                // The direct writer owns one device and one request. Preserve the allocation and both
                // handles, even if a faulty driver never completes the cancellation. Closing or
                // reusing them here would let Windows access freed memory.
                std::mem::forget(io);
            }
        }
    }
}

pub(crate) fn screen_size() -> (i32, i32) {
    // SAFETY: these functions simply read primary display dimensions.
    unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) }
}

/// Where the cursor is, in the calling thread's DPI awareness (the same view as [`screen_size`]);
/// it fails while another desktop has the input.
pub(crate) fn cursor_pos() -> Result<(i32, i32), String> {
    let mut point = POINT::default();
    // SAFETY: `point` is a live POINT we own.
    unsafe { GetCursorPos(&mut point) }
        .map(|()| (point.x, point.y))
        .map_err(|error| format!("GetCursorPos: {error}"))
}

/// What Windows says of the mouse around a button change, for the button watch's line
/// (`super::button_watch`): the three mouse buttons as its async key state has them — the physical
/// buttons, the driver's and the PC's own mouse alike — and with `detail` who has the mouse: the
/// capture of the thread that owns the game's window `game` (`GetGUIThreadInfo`), the window under the
/// cursor (`WindowFromPoint`) and the foreground window.
///
/// Reads only. `GetAsyncKeyState` of the three mouse buttons, never a key: it answers 0 where Windows
/// does not let this process read it (another desktop), and the read clears the button's "pressed
/// since the last read" bit, which only a program polling that bit could miss — the "held" bit a
/// camera turn reads is not touched. Windows are described by handle and class; an exe is read only
/// for a window that is not the game's process (opened for limited information), the game's process
/// never.
pub(crate) fn button_probe(game: usize, detail: bool) -> ButtonProbe {
    let down = |vk: VIRTUAL_KEY| {
        // SAFETY: plain call.
        let state = unsafe { GetAsyncKeyState(i32::from(vk.0)) };
        // The high bit: down now.
        state < 0
    };
    let mut windows = 0u8;
    for (vk, bit) in [(VK_LBUTTON, 1), (VK_RBUTTON, 2), (VK_MBUTTON, 4)] {
        if down(vk) {
            windows |= bit;
        }
    }
    if !detail {
        return ButtonProbe {
            windows,
            ..ButtonProbe::default()
        };
    }
    let game_window = HWND(game as *mut c_void);
    let mut game_pid = 0u32;
    // SAFETY: plain call with a live output; a gone window answers 0.
    let thread = unsafe { GetWindowThreadProcessId(game_window, Some(&mut game_pid)) };
    let capture = if thread == 0 {
        "unknown (the game's window is gone)".to_owned()
    } else {
        let mut info = GUITHREADINFO {
            cbSize: size_of::<GUITHREADINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: a live GUITHREADINFO with its size set, as the API requires.
        match unsafe { GetGUIThreadInfo(thread, &mut info) } {
            Ok(()) => describe_window(info.hwndCapture, game_window, game_pid),
            Err(error) => format!("unreadable (GetGUIThreadInfo: {error})"),
        }
    };
    let under = match cursor_pos() {
        Ok((x, y)) => {
            // SAFETY: plain call.
            let window = unsafe { WindowFromPoint(POINT { x, y }) };
            describe_window(window, game_window, game_pid)
        }
        Err(error) => format!("unreadable ({error})"),
    };
    // SAFETY: plain call.
    let foreground = unsafe { GetForegroundWindow() };
    ButtonProbe {
        windows,
        capture: Some(capture),
        under: Some(under),
        foreground: Some(describe_window(foreground, game_window, game_pid)),
    }
}

/// A window for the button watch's line: its handle, its class, and whose it is — the game's window,
/// a window in it, the game's process, or another exe.
fn describe_window(window: HWND, game: HWND, game_pid: u32) -> String {
    if window.0.is_null() {
        return "none".to_owned();
    }
    let class = crate::cursor_shape::class_of(window);
    // SAFETY: plain call; a stale handle answers false.
    let inside = unsafe { IsChild(game, window) }.as_bool();
    let whose = if window == game {
        "the game's window".to_owned()
    } else if inside {
        "in the game's window".to_owned()
    } else {
        let mut pid = 0u32;
        // SAFETY: plain call with a live output; a gone window answers 0.
        unsafe { GetWindowThreadProcessId(window, Some(&mut pid)) };
        if pid != 0 && pid == game_pid {
            "the game's process".to_owned()
        } else {
            crate::cursor_shape::exe_of(window)
        }
    };
    format!("{:#x} {class} ({whose})", window.0 as usize)
}

fn allowed() -> TargetEval {
    TargetEval {
        target: Target::Allowed,
        reason: "default desktop of the active console session",
    }
}

fn blocked(reason: &'static str) -> TargetEval {
    TargetEval {
        target: Target::Blocked,
        reason,
    }
}

fn unknown(reason: &'static str) -> TargetEval {
    TargetEval {
        target: Target::Unknown,
        reason,
    }
}

/// Evaluate where HID input may go. Fails closed to [`Target::Blocked`] for anything Windows keeps
/// for itself (a non-Default desktop it will not let us open, or another session); a rare internal
/// query failure is [`Target::Unknown`] so input is kept but routed through SendInput. It does not
/// look at the foreground window at all — see [`Target`]. These are desktop metadata queries, never
/// reads of local keyboard input.
pub(crate) fn evaluate_target() -> TargetEval {
    let mut session = 0;
    // SAFETY: a current PID and a live u32 output pointer.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }.is_err() {
        return unknown("own session id unavailable");
    }
    if session != unsafe { WTSGetActiveConsoleSessionId() } {
        return blocked("not the active console session");
    }
    // SAFETY: request only desktop metadata; never switch desktops or obtain injection rights.
    let desktop =
        match unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) } {
            Ok(desktop) => desktop,
            // The secure desktop (a UAC prompt, the lock screen) is not openable from here.
            Err(_) => return blocked("input desktop inaccessible (secure desktop?)"),
        };
    let mut name = [0u16; 256];
    // SAFETY: name is a live array of the indicated byte size.
    let query = unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            size_of::<[u16; 256]>() as u32,
            None,
        )
    };
    if let Err(error) = unsafe { CloseDesktop(desktop) } {
        tracing::warn!(%error, "closing input desktop metadata handle failed");
    }
    if query.is_err() {
        return blocked("input desktop name unavailable");
    }
    let length = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    if !String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("Default") {
        return blocked("input on a non-default desktop");
    }
    allowed()
}

#[cfg(test)]
mod fenced_io_tests {
    use super::*;

    fn test_device() -> FencedDevice {
        // Use private nonsignaled events, no actual HID handle or input action.
        let event = || {
            // SAFETY: unnamed manual-reset event, initially nonsignaled.
            OwnedHandle(
                unsafe { CreateEventW(None, true, false, PCWSTR::null()) }.expect("test event"),
            )
        };
        FencedDevice::wrap(Device {
            control: event(),
            write_event: event(),
        })
    }

    #[test]
    fn hid_pending_request_fences_writes_without_waiting_for_completion() {
        let direct = test_device();
        let io = direct.io.as_deref().expect("test request storage");
        io.pending.set(Some(FencedRequest::Other));
        let error = direct
            .write(&[77; 65], None, None, None)
            .expect_err("pending request must fence a new write");
        assert_eq!(error.to_string(), "previous HID write still pending");
        assert!(io.pending.get().is_some());
        // SAFETY: this test never handed either buffer to Windows.
        assert_eq!(unsafe { *io.report.get() }, [0; 65]);
        // No request was submitted in the test, so both event handles can be closed.
        io.pending.set(None);
    }

    #[test]
    fn hid_stopped_positive_report_is_refused_and_neutral_can_submit() {
        let direct = test_device();
        let stop = AtomicBool::new(true);
        let error = direct
            .write(&[77; 65], Some(&stop), None, None)
            .expect_err("positive report refused");
        assert_eq!(error.to_string(), "HID report refused after local stop");
        let io = direct.io.as_deref().unwrap();
        assert!(io.pending.get().is_none());

        let error = direct
            .neutral(NeutralReport::Keyboard, Instant::now())
            .expect_err("expired cleanup report refused");
        assert_eq!(error.to_string(), "HID cleanup report deadline");

        let error = direct
            .write(&[0; 65], None, None, None)
            .expect_err("the test handle is an event and cannot accept a write");
        assert_eq!(error.to_string(), "submit HID report");
    }

    #[test]
    fn hid_old_input_generation_is_a_known_unsent_report() {
        let direct = test_device();
        let generation = AtomicU64::new(1);
        let error = direct
            .write(&[77; 65], None, Some((&generation, 0)), None)
            .expect_err("old generation must not enter WriteFile");
        assert!(error.is::<super::super::direct::HidInputPaused>());
        assert!(direct.io.as_deref().unwrap().pending.get().is_none());
    }

    #[test]
    fn hid_expired_authority_cannot_submit_even_with_current_generation() {
        let direct = test_device();
        let generation = AtomicU64::new(2);
        let error = direct
            .write(&[77; 65], None, Some((&generation, 2)), Some(&|| false))
            .expect_err("expired authority must not enter WriteFile");
        assert!(error.is::<super::super::direct::HidInputPaused>());
        assert!(direct.io.as_deref().unwrap().pending.get().is_none());
    }

    #[test]
    fn hid_late_completion_credits_only_the_same_neutral_report_and_deadline() {
        let now = Instant::now();
        let deadline = now + std::time::Duration::from_secs(2);
        let keyboard = FencedRequest::Neutral {
            kind: NeutralReport::Keyboard,
            deadline,
        };
        let mouse = FencedRequest::Neutral {
            kind: NeutralReport::Mouse,
            deadline,
        };
        assert!(keyboard
            .resolve_previous(keyboard, || Some(Ok(65)))
            .unwrap());
        assert!(mouse.resolve_previous(mouse, || Some(Ok(63))).unwrap());
        assert!(mouse
            .resolve_previous(keyboard, || panic!("keyboard owns its pending proof"))
            .is_err());
        assert!(keyboard
            .resolve_previous(mouse, || panic!("mouse owns its pending proof"))
            .is_err());
        assert!(!keyboard
            .resolve_previous(FencedRequest::Other, || Some(Ok(65)))
            .unwrap());
        let older = FencedRequest::Neutral {
            kind: NeutralReport::Keyboard,
            deadline: now,
        };
        assert!(!keyboard.resolve_previous(older, || Some(Ok(65))).unwrap());
        assert!(keyboard
            .resolve_previous(keyboard, || Some(Ok(62)))
            .is_err());
        assert!(keyboard
            .resolve_previous(keyboard, || Some(Err(anyhow::anyhow!("canceled"))))
            .is_err());
        assert!(keyboard.resolve_previous(keyboard, || None).is_err());
        assert!(keyboard.confirm(Ok(65), deadline).is_err());
    }
}
