//! A step-by-step WGC start of the game's window, for the log alone: which step fails when
//! `windows-capture` could not start a capture of it and no `CreateForWindow` error was recorded.
//!
//! ## Why
//!
//! A restart of a window capture that was stopped can fail with `Graphics capture error: Windows
//! API error: … (0x800703EE)` (`ERROR_FILE_INVALID`) in `start_free_threaded`, on every later
//! start, after `CreateForWindow` succeeds.
//! Inside the crate that one error can come from a dozen calls (the support checks, the item's
//! size, the frame pool, the session, its properties, the two event handlers, `StartCapture`), and
//! its text names none of them. So on the first failure of a kind ([`super::game`]'s backend keeps
//! which kinds it probed), the same steps are made here one by one, and one warning says which
//! failed and with what — or that all of them succeeded here, which is an observation, not a cause:
//! the probe differs from the crate's start (below), and any of the differences, or only the time
//! between the two, may be what made it succeed.
//!
//! ## The steps, in `windows-capture` 2.0.1's order
//!
//! `capture.rs` `start_free_threaded`, then `graphics_capture_api.rs` `GraphicsCaptureApi::new`
//! and `start_capture`:
//!
//! 0. `RoInitialize(MTA)` for this thread first (balanced at the end; already initialised is fine),
//!    as the crate's own capture thread does and the hand-run probe
//!    (`probe/window_capture.rs`) does: the result is in the line;
//! 1. `D3D11CreateDevice` — the crate's own `d3d11::create_d3d_device` (hardware, BGRA support);
//! 2. `CreateForWindow` (`IGraphicsCaptureItemInterop`), as [`super::game`] makes the item;
//! 3. WGC supported: `UniversalApiContract` 8 and `GraphicsCaptureSession::IsSupported`;
//! 4. whether this Windows has each optional session property (`ApiInformation`), as
//!    `session_options` asks before a start and the crate asks again;
//! 5. `CreateDirect3D11DeviceFromDXGIDevice` — the crate's `d3d11::create_direct3d_device`;
//! 6. `GraphicsCaptureItem::Size`;
//! 7. the frame pool: BGRA8, one buffer, the item's size — **`CreateFreeThreaded`** where the crate
//!    calls `Create`: the crate runs its own thread with a dispatcher queue, which `Create`'s
//!    `FrameArrived` is raised on; this thread has none;
//! 8. `CreateCaptureSession`;
//! 9. the item's `Closed` and the pool's `FrameArrived` handlers (no-ops here);
//! 10. each optional property that is present, set as the agent sets it (`session_options`);
//! 11. `StartCapture`.
//!
//! Not made: the crate's title-bar height (its error would read `Window error:`) and its
//! dispatcher queue. So the probe differs from the crate's start in the pool (`CreateFreeThreaded`
//! here, `Create` on the crate's dispatcher-queue thread there), the thread (the game capture's own
//! here, the crate's new one there) and the time (a few milliseconds after the crate's attempt). Whatever was made is closed again at once, in the crate's own order (the
//! pool's handler and the pool, the session, the item's handler); a close that fails is in the same
//! line. A probe that starts the capture holds it for no frame: it is closed right after.
//!
//! ## Threads
//!
//! Runs on the thread that called the backend's start: the game capture's own thread
//! (`game-capture`, `afklink_core::game::Director::start_live`) — never the Tauri main thread, never
//! an async runtime. That thread is put in the MTA for the probe (`RoInitialize`, balanced when the
//! probe ends, after everything it made is closed and dropped). Every call is a synchronous WinRT
//! or D3D11 call; none waits on another thread, and no lock is held. It costs what one capture start costs (expected tens of milliseconds; the line
//! says `took_ms`), once per failure kind.

use std::time::Instant;

use windows::core::{IInspectable, HSTRING};
use windows::Foundation::Metadata::ApiInformation;
use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{
    Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
use windows_capture::d3d11::{create_d3d_device, create_direct3d_device};

use crate::game::{error_text, hwnd_of};
use crate::session_options::{presence, Presence, SessionOption};

/// The step that failed and its error.
struct Failed {
    step: String,
    error: String,
}

fn failed(step: impl Into<String>, error: impl Into<String>) -> Failed {
    Failed {
        step: step.into(),
        error: error.into(),
    }
}

/// What the probe made, to be closed again whatever happened.
#[derive(Default)]
struct Made {
    item: Option<GraphicsCaptureItem>,
    pool: Option<Direct3D11CaptureFramePool>,
    session: Option<GraphicsCaptureSession>,
    closed_token: Option<i64>,
    arrived_token: Option<i64>,
}

impl Made {
    /// Close everything, in `windows-capture`'s order (`GraphicsCaptureApi::cleanup`); what failed
    /// to close.
    fn close(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        let mut note = |what: &str, result: windows::core::Result<()>| {
            if let Err(e) = result {
                failures.push(format!("{what}: {}", error_text(&e)));
            }
        };
        if let Some(pool) = self.pool.take() {
            if let Some(token) = self.arrived_token.take() {
                note("RemoveFrameArrived", pool.RemoveFrameArrived(token));
            }
            note("Direct3D11CaptureFramePool::Close", pool.Close());
        }
        if let Some(session) = self.session.take() {
            note("GraphicsCaptureSession::Close", session.Close());
        }
        if let Some(item) = self.item.take() {
            if let Some(token) = self.closed_token.take() {
                note("RemoveClosed", item.RemoveClosed(token));
            }
        }
        failures
    }
}

/// `RoInitialize(MTA)` for the probing thread, balanced when dropped — after every WinRT object
/// the probe made (as `probe/window_capture.rs`'s guard). Already initialised (`S_FALSE`) counts as
/// a success and is balanced too; a thread in another apartment (`RPC_E_CHANGED_MODE`) is not.
struct RoGuard(bool);

impl RoGuard {
    /// The guard, and what `RoInitialize` answered, for the probe's line.
    fn init() -> (Self, String) {
        // SAFETY: plain call; balanced in `drop` when it succeeded.
        let result = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        match result {
            Ok(()) => (Self(true), "ok (or already initialised)".to_string()),
            Err(e) => (Self(false), error_text(&e)),
        }
    }
}

impl Drop for RoGuard {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances this thread's successful `RoInitialize`.
            unsafe { RoUninitialize() };
        }
    }
}

/// The steps; each one that succeeded is pushed to `ok`.
fn run(hwnd: usize, made: &mut Made, ok: &mut Vec<String>) -> Result<(), Failed> {
    let (device, _context) =
        create_d3d_device().map_err(|e| failed("D3D11CreateDevice", e.to_string()))?;
    ok.push("D3D11CreateDevice".into());

    let item = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
        // SAFETY: a window handle is any value; a stale one fails with an error.
        .and_then(|interop| unsafe { interop.CreateForWindow::<GraphicsCaptureItem>(hwnd_of(hwnd)) })
        .map_err(|e| failed("CreateForWindow", error_text(&e)))?;
    made.item = Some(item.clone());
    ok.push("CreateForWindow".into());

    let contract = ApiInformation::IsApiContractPresentByMajor(
        &HSTRING::from("Windows.Foundation.UniversalApiContract"),
        8,
    )
    .map_err(|e| {
        failed(
            "IsApiContractPresent(UniversalApiContract 8)",
            error_text(&e),
        )
    })?;
    let supported = GraphicsCaptureSession::IsSupported()
        .map_err(|e| failed("GraphicsCaptureSession::IsSupported", error_text(&e)))?;
    if !(contract && supported) {
        return Err(failed(
            "WGC supported",
            format!("UniversalApiContract 8: {contract}, IsSupported: {supported}"),
        ));
    }
    ok.push("IsSupported".into());

    let mut set = Vec::new();
    for option in SessionOption::ALL {
        match presence(option) {
            Presence::Present => set.push(option),
            Presence::Absent => {}
            Presence::Unknown(e) => {
                return Err(failed(
                    format!("IsPropertyPresent({})", option.property()),
                    e,
                ))
            }
        }
    }
    ok.push(format!(
        "IsPropertyPresent (present: {})",
        set.iter()
            .map(|o| o.property())
            .collect::<Vec<_>>()
            .join(", ")
    ));

    let d3d = create_direct3d_device(&device)
        .map_err(|e| failed("CreateDirect3D11DeviceFromDXGIDevice", e.to_string()))?;
    ok.push("CreateDirect3D11DeviceFromDXGIDevice".into());

    let size = item
        .Size()
        .map_err(|e| failed("GraphicsCaptureItem::Size", error_text(&e)))?;
    ok.push(format!("Size ({}x{})", size.Width, size.Height));

    let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(
        &d3d,
        DirectXPixelFormat::B8G8R8A8UIntNormalized,
        1,
        size,
    )
    .map_err(|e| {
        failed(
            "Direct3D11CaptureFramePool::CreateFreeThreaded",
            error_text(&e),
        )
    })?;
    made.pool = Some(pool.clone());
    ok.push("CreateFreeThreaded".into());

    let session = pool
        .CreateCaptureSession(&item)
        .map_err(|e| failed("CreateCaptureSession", error_text(&e)))?;
    made.session = Some(session.clone());
    ok.push("CreateCaptureSession".into());

    let closed = item
        .Closed(&TypedEventHandler::<GraphicsCaptureItem, IInspectable>::new(|_, _| Ok(())))
        .map_err(|e| failed("GraphicsCaptureItem::Closed", error_text(&e)))?;
    made.closed_token = Some(closed);
    ok.push("Closed".into());
    let arrived = pool
        .FrameArrived(
            &TypedEventHandler::<Direct3D11CaptureFramePool, IInspectable>::new(|_, _| Ok(())),
        )
        .map_err(|e| failed("Direct3D11CaptureFramePool::FrameArrived", error_text(&e)))?;
    made.arrived_token = Some(arrived);
    ok.push("FrameArrived".into());

    for option in set {
        let value = option.value();
        let result = match option {
            SessionOption::Cursor => session.SetIsCursorCaptureEnabled(value),
            SessionOption::NoBorder => session.SetIsBorderRequired(value),
            SessionOption::NoSecondaryWindows => session.SetIncludeSecondaryWindows(value),
        };
        let step = format!("{} = {value}", option.property());
        result.map_err(|e| failed(step.clone(), error_text(&e)))?;
        ok.push(step);
    }

    session
        .StartCapture()
        .map_err(|e| failed("StartCapture", error_text(&e)))?;
    ok.push("StartCapture".into());
    Ok(())
}

/// Make the steps for `hwnd` one by one, close what was made, and log one warning: the step that
/// failed and its error, or that every step succeeded where the crate's start failed with
/// `crate_error` (also the failure kind the caller probes once).
pub(crate) fn probe(hwnd: usize, generation: u64, crate_error: &str) {
    let began = Instant::now();
    // Declared first, so dropped last: after `made` and everything `run` made.
    let (_ro, ro_init) = RoGuard::init();
    let mut made = Made::default();
    let mut ok = Vec::new();
    let outcome = run(hwnd, &mut made, &mut ok);
    let close_failures = made.close();
    let took_ms = began.elapsed().as_millis() as u64;
    let closed = if close_failures.is_empty() {
        "all".to_string()
    } else {
        close_failures.join("; ")
    };
    let steps_ok = ok.join(", ");
    match outcome {
        Err(Failed { step, error }) => tracing::warn!(
            hwnd = %format!("{hwnd:#x}"),
            generation,
            crate_error,
            ro_init = %ro_init,
            failed_step = %step,
            error = %error,
            steps_ok = %steps_ok,
            closed = %closed,
            took_ms,
            "game capture: WGC start probe: the step-by-step start of the same window fails at \
             {step}: {error}"
        ),
        Ok(()) => tracing::warn!(
            hwnd = %format!("{hwnd:#x}"),
            generation,
            crate_error,
            ro_init = %ro_init,
            steps_ok = %steps_ok,
            closed = %closed,
            took_ms,
            differences = "pool CreateFreeThreaded here vs Create on the crate's dispatcher-queue \
                           thread; this thread (game-capture) vs the crate's new one; a few ms \
                           later than the crate's attempt",
            "game capture: WGC start probe: the step-by-step start of the same window succeeded \
             here (StartCapture included) where windows-capture's start failed just before; an \
             observation, not a cause: any of the differences, or the time between the two, may \
             account for it"
        ),
    }
}
