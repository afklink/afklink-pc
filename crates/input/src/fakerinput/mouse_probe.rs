//! A hand-run diagnostic, not a test of this crate: how the foreground application (a game, or
//! Notepad as the baseline) reacts to each way the agent can move the cursor — the facts agent-side
//! cursor sync is designed on.
//!
//! It drives the real code paths, six methods: `setcursorpos`; `sendinput_abs` and `sendinput_rel`
//! as `imp` builds them ([`crate::imp::absolute_input`], [`crate::imp::relative_input`]); `hid_rel`
//! and `hid_abs`, FakerInput's relative (report 3, [`State::relative`]) and absolute mouse (report 4,
//! [`State::absolute`], mapped by [`super::absolute_wire`]); and `exact_rel`, the cursor-sync
//! planner's exact relative move (`crate::cursor_sync`) through report 3 — each 150 px move should
//! land within a pixel of 150 px at any display scale, "Enhance pointer precision" included (the
//! learned gain is in the JSON's `cursor.exact_rel_gain`).
//!
//! **It moves the real cursor.** Moves only: no button, wheel or key (clicks and drags are
//! `click_probe`'s, in Notepad only). Every point stays at least [`MARGIN`] px inside the primary
//! monitor, the run takes about fifteen seconds ([`RUN_BUDGET`] at most), and the cursor is put back.
//! Run it by hand, with the target focused and no AFKLink session live, from an **unelevated**
//! terminal — the agent runs unelevated, and what such a process can do to an elevated game is the
//! point:
//!
//! ```text
//! $env:AFK_PROBE_TARGET = 'notepad'   # a substring of the foreground window's exe name
//! cargo test -p afklink-input --release mouse_probe -- --ignored --nocapture
//! ```
//!
//! Stdout and the JSON (`agent\target\mouse-probe-<target>-<yyyymmdd-hhmmss>.json`,
//! `AFK_PROBE_OUT` overrides) are its log: every failed, refused or ignored call is in them.
//!
//! One run: DPI awareness (physical pixels throughout), screen, mouse and driver settings; then up
//! to two minutes for the target to take the foreground, a three-second countdown, an anchor near
//! the cursor, and each method's three moves (right, down, back up-left), the cursor sampled every
//! ~1 ms for half a second after each and a raw-input sink counting what a raw-input game would see.
//! Relative moves go in ten steps 16 ms apart.
//!
//! **Refusals are findings, not failures.** Over an elevated window Windows may refuse an
//! unelevated `SetCursorPos` or `SendInput` (UIPI): the refusal and `GetLastError` (cleared first)
//! are recorded, the rest of that method is skipped, and the run goes on. The cursor returns to the
//! anchor by `SetCursorPos` or, refused, FakerInput's absolute report. The run stops only when the
//! foreground leaves the target, the budget runs out, a HID write fails, the cursor position is
//! unknown, or a point would be too close to an edge.

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_core::sync::lock;
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_NO_MORE_FILES, HANDLE, HINSTANCE, HWND, LPARAM,
    LRESULT, POINT, RECT, WIN32_ERROR, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    ClientToScreen, EnumDisplayMonitors, GetMonitorInfoW, MonitorFromPoint, MonitorFromWindow, HDC,
    HMONITOR, MONITORINFO, MONITOR_DEFAULTTONEAREST, MONITOR_DEFAULTTOPRIMARY,
};
use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod, TIMERR_NOERROR};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
    TokenIntegrityLevel, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::HiDpi::{
    GetAwarenessFromDpiAwarenessContext, GetDpiForMonitor, GetDpiForSystem,
    GetThreadDpiAwarenessContext, SetProcessDpiAwarenessContext, SetThreadDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, DPI_AWARENESS_PER_MONITOR_AWARE, MDT_EFFECTIVE_DPI,
    MDT_RAW_DPI, MONITOR_DPI_TYPE,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{SendInput, INPUT};
use windows::Win32::UI::Input::{
    GetRawInputData, RegisterRawInputDevices, HRAWINPUT, MOUSE_MOVE_ABSOLUTE,
    MOUSE_VIRTUAL_DESKTOP, RAWINPUT, RAWINPUTDEVICE, RAWINPUTHEADER, RIDEV_INPUTSINK, RIDEV_REMOVE,
    RID_INPUT, RIM_TYPEMOUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClassNameW, GetClientRect,
    GetClipCursor, GetCursorInfo, GetCursorPos, GetForegroundWindow, GetGUIThreadInfo, GetMessageW,
    GetSystemMetrics, GetWindowLongW, GetWindowRect, GetWindowTextW, GetWindowThreadProcessId,
    PostThreadMessageW, RegisterClassW, SetCursorPos, SystemParametersInfoW, UnregisterClassW,
    CURSORINFO, CURSOR_SHOWING, CURSOR_SUPPRESSED, GUITHREADINFO, GWL_EXSTYLE, GWL_STYLE,
    HWND_MESSAGE, MONITORINFOF_PRIMARY, MSG, SM_CMONITORS, SM_CXSCREEN, SM_CXVIRTUALSCREEN,
    SM_CYSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN, SPI_GETMOUSE,
    SPI_GETMOUSESPEED, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_INPUT, WM_QUIT, WNDCLASSW,
};

use super::{absolute_wire, platform, State};
use crate::cursor_sync::system::SystemCursor;
use crate::cursor_sync::{CursorSync, Plan, RelEvent, RelPath};
use crate::RelCarry;

/// Every point the probe aims at stays at least this far inside the primary monitor's edges.
const MARGIN: i32 = 400;
/// One move's length on each axis, px.
const STEP: i32 = 150;
/// The three moves of every method: right, down, then back up-left to where the method started. For
/// the absolute methods and `SetCursorPos` they are target points relative to the anchor sequence
/// (anchor + (150, 0), anchor + (150, 150), anchor); for the relative ones, counts.
const MOVES: [(i32, i32); 3] = [(STEP, 0), (0, STEP), (-STEP, -STEP)];
/// The pause after the cursor is put back at the anchor, before each method.
const RESET_SETTLE: Duration = Duration::from_millis(300);
/// How long the cursor is watched after a move's last injection.
const WINDOW: Duration = Duration::from_millis(500);
/// The sampling period.
const TICK: Duration = Duration::from_millis(1);
/// Samples kept whatever they show, ms after a move's first injection started.
const MARKS_MS: [u64; 4] = [1, 20, 100, 500];
/// A relative move goes out as this many equal steps (150 counts: ten of 15)…
const REL_CHUNKS: i32 = 10;
/// …one every this long. The Mini App coalesces relative motion to one `r` per animation frame
/// (`miniapp/src/input.ts`, `scheduleFlush`), and the agent turns each `r` into exactly one
/// `SendInput` call or one HID report (split only past ±32767): a 60 Hz viewer's stream.
const REL_CHUNK_GAP: Duration = Duration::from_millis(16);
/// How long the probe waits for the target to take the foreground.
const WAIT_FOR_TARGET: Duration = Duration::from_secs(120);
const WAIT_PRINT_EVERY: Duration = Duration::from_secs(5);
/// The countdown between the target taking the foreground and the first move, s.
const COUNTDOWN_S: u64 = 3;
/// The whole run, from the first move (after the countdown) to the last sample, may not take longer.
/// Six methods of about 2.3 s each.
const RUN_BUDGET: Duration = Duration::from_secs(20);
/// Raw-input read failures kept in the notes; the rest are only counted.
const RAW_ERRORS_KEPT: usize = 20;

pub(super) type Pt = [i32; 2];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    SetCursorPos,
    SendInputAbs,
    HidAbs,
    SendInputRel,
    HidRel,
    /// The cursor-sync planner's exact relative move, through report 3: steps in px, not counts.
    ExactRel,
}

const METHODS: [Method; 6] = [
    Method::SetCursorPos,
    Method::SendInputAbs,
    Method::HidAbs,
    Method::SendInputRel,
    Method::HidRel,
    Method::ExactRel,
];

impl Method {
    fn name(self) -> &'static str {
        match self {
            Self::SetCursorPos => "setcursorpos",
            Self::SendInputAbs => "sendinput_abs",
            Self::HidAbs => "hid_abs",
            Self::SendInputRel => "sendinput_rel",
            Self::HidRel => "hid_rel",
            Self::ExactRel => "exact_rel",
        }
    }

    /// What one injection of this method calls, for the record.
    fn call(self) -> &'static str {
        match self {
            Self::SetCursorPos => "SetCursorPos",
            Self::SendInputAbs => "SendInput(imp::absolute_input)",
            Self::HidAbs => "HID report 4 (State::absolute)",
            Self::SendInputRel => "SendInput(imp::relative_input)",
            Self::HidRel => "HID report 3 (State::relative)",
            Self::ExactRel => "HID report 3 (cursor_sync exact, State::movement)",
        }
    }

    fn relative(self) -> bool {
        matches!(self, Self::SendInputRel | Self::HidRel | Self::ExactRel)
    }

    fn hid(self) -> bool {
        matches!(self, Self::HidAbs | Self::HidRel | Self::ExactRel)
    }

    /// Its steps are pixels the cursor should travel, not counts.
    fn in_pixels(self) -> bool {
        matches!(self, Self::ExactRel)
    }
}

/// What one look at the cursor saw. Samples are kept only when this changes (or at a mark).
#[derive(Serialize, Clone, Default, PartialEq, Debug)]
struct Observed {
    /// `GetCursorPos`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pos: Option<Pt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pos_error: Option<String>,
    /// `GetCursorInfo`: its flags (`CURSOR_SHOWING` 1, `CURSOR_SUPPRESSED` 2), the shape's handle,
    /// and its own position.
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor_flags: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    showing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shape: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_pos: Option<Pt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    info_error: Option<String>,
    /// `GetClipCursor`, `[left, top, right, bottom]` (the whole virtual screen when nothing clips).
    #[serde(skip_serializing_if = "Option::is_none")]
    clip: Option<[i32; 4]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clip_error: Option<String>,
    /// `GetForegroundWindow` (0: none).
    foreground: usize,
    /// `GetGUIThreadInfo(0).hwndCapture`: the foreground thread's mouse capture (0: none).
    #[serde(skip_serializing_if = "Option::is_none")]
    capture: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gui_error: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct Sample {
    method: &'static str,
    #[serde(rename = "move")]
    mv: usize,
    /// µs since the move's first injection started; negative for the look taken just before it.
    t_us: i64,
    /// `before`, `+1ms`, `+20ms`, `+100ms`, `+500ms`, `final` (a sample may carry several).
    #[serde(skip_serializing_if = "Option::is_none")]
    mark: Option<String>,
    #[serde(flatten)]
    seen: Observed,
}

/// One injection call and what it answered.
#[derive(Serialize, Clone, Debug)]
struct Call {
    /// µs since the move's first injection started.
    t_us: i64,
    call: &'static str,
    /// The point (absolute methods, `SetCursorPos`) or the step in counts (relative ones).
    arg: Pt,
    /// What went on the wire: `SendInput`'s `dx, dy` (0..65535 absolute, pixels relative) or the
    /// absolute HID report's 0..32767. None where the call does not expose it.
    #[serde(skip_serializing_if = "Option::is_none")]
    wire: Option<Pt>,
    ok: bool,
    result: String,
    /// `SetCursorPos` and `SendInput`: `GetLastError` read right after the call, cleared to 0 just
    /// before it (0 on a failure: the call set no error).
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<u32>,
    duration_us: u64,
}

/// What a `SetCursorPos` or `SendInput` call answered: its own result (for `SetCursorPos`, as
/// windows-rs reports it — which reads `GetLastError` itself), and `GetLastError` read by us right
/// after the call, cleared just before it, so a failure that sets no error reads 0 instead of
/// whatever an earlier call left there.
#[derive(Serialize, Clone, Debug)]
pub(super) struct Answer {
    pub(super) ok: bool,
    pub(super) result: String,
    pub(super) last_error: u32,
}

/// How the cursor was put on a point (the anchor, or back where it was): `SetCursorPos`, else —
/// when that is refused, as over an elevated window — FakerInput's absolute report.
#[derive(Serialize, Clone, Debug)]
struct Placement {
    to: Pt,
    /// `setcursorpos`, `hid_abs` (report 4 written after `SetCursorPos` was refused) or `none`.
    way: &'static str,
    set_cursor_pos: Answer,
    /// The HID fallback, when it was tried: `written`, `no FakerInput device`, or the write's error.
    #[serde(skip_serializing_if = "Option::is_none")]
    hid_abs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hid_wire: Option<Pt>,
    /// The HID write failed: the run stops (as on any HID failure).
    #[serde(skip)]
    hid_failed: bool,
}

impl Placement {
    fn describe(&self) -> String {
        match self.way {
            "setcursorpos" => "SetCursorPos".to_owned(),
            way => format!(
                "{way} (SetCursorPos refused: {}, GetLastError {}; HID: {})",
                self.set_cursor_pos.result,
                self.set_cursor_pos.last_error,
                self.hid_abs.as_deref().unwrap_or("not tried")
            ),
        }
    }
}

/// Why a move or a reset stopped short.
#[derive(Debug, PartialEq)]
enum Stop {
    /// The run ends: the foreground left the target, the budget ran out, a HID write failed, the
    /// cursor position is unknown, or a point would be too close to an edge.
    Abort(String),
    /// Windows refused (or failed) this method's `SetCursorPos` / `SendInput`: the rest of the method
    /// is skipped and the run goes on with the next one.
    Refused(String),
}

#[derive(Serialize, Debug)]
struct MoveRecord {
    method: &'static str,
    #[serde(rename = "move")]
    mv: usize,
    /// The move's first injection started, and its last sample was taken: µs since the run began
    /// (just before the anchor is chosen, right after the countdown and the sink's start).
    run_start_us: i64,
    run_end_us: i64,
    /// `GetCursorPos` just before the first injection.
    start: Option<Pt>,
    /// Absolute methods and `SetCursorPos`: the point aimed at.
    target: Option<Pt>,
    /// Relative methods: the counts sent (`exact_rel`: none — its steps are pixels, and each call's
    /// `wire` holds the counts the planner turned them into).
    counts: Option<Pt>,
    /// Where the cursor should end: the target, or the start plus the counts (`exact_rel`: plus the
    /// pixels).
    expected: Option<Pt>,
    calls: Vec<Call>,
    /// The last injection started and returned, µs since the first one started.
    last_call_start_us: i64,
    last_call_end_us: i64,
    #[serde(skip)]
    samples: std::ops::Range<usize>,
}

/// What a raw-input reader heard during a stretch of the run.
#[derive(Serialize, Clone, Default, Debug, PartialEq)]
struct RawSummary {
    events: usize,
    relative_events: usize,
    /// Summed `lLastX`/`lLastY` of the relative events.
    sum_x: i64,
    sum_y: i64,
    /// Events with `MOUSE_MOVE_ABSOLUTE`, and the last one's `lLastX`/`lLastY` (0..65535).
    absolute_events: usize,
    last_absolute: Option<Pt>,
    /// Any event with `MOUSE_VIRTUAL_DESKTOP`.
    virtual_desktop: bool,
    /// Events carrying a button transition (the probe presses none: these are someone else's).
    button_events: usize,
    /// `hDevice` of the events (`0x0`: injected by `SendInput`).
    devices: Vec<String>,
}

#[derive(Serialize, Debug)]
struct MoveSummary {
    method: &'static str,
    #[serde(rename = "move")]
    mv: usize,
    start: Option<Pt>,
    expected: Option<Pt>,
    /// The position at the last sample, taken [`WINDOW`] after the last injection.
    #[serde(rename = "final")]
    final_pos: Option<Pt>,
    final_at_ms: Option<f64>,
    /// Final minus expected.
    error: Option<Pt>,
    /// Final minus start, against expected minus start.
    displacement: Option<Pt>,
    intended: Option<Pt>,
    /// Displacement / intended per axis (None where nothing was intended on that axis).
    gain_x: Option<f64>,
    gain_y: Option<f64>,
    /// The first sample after the injection began whose position differs from the start.
    first_change_ms: Option<f64>,
    /// When the position took its final value for good (the first sample of the last run of
    /// samples at it). None: it never moved.
    settle_ms: Option<f64>,
    /// Position changes from the last injection's start on; one is the injection's own effect.
    changes_after_last_injection: usize,
    /// Two or more of those: the cursor moved again after the injection took effect — the sign
    /// of an application warping the cursor itself.
    moved_again: bool,
    /// The final position is nearer the start than the expected point.
    returned_toward_start: bool,
    showing_final: Option<bool>,
    hidden_seen: bool,
    /// Distinct cursor shape handles seen after the injection began.
    shapes_seen: usize,
    clip_final: Option<[i32; 4]>,
    capture_final: Option<usize>,
    injection_ok: bool,
    /// Every call was accepted, yet the position never changed: an injection Windows took and
    /// the cursor did not follow.
    no_movement: bool,
    injection_us: u64,
    /// None when the raw-input sink did not run.
    raw: Option<RawSummary>,
}

#[derive(Serialize, Debug)]
struct ResetRecord {
    run_start_us: i64,
    run_end_us: i64,
    /// How the cursor was put on the anchor (or that it could not be).
    placement: Placement,
    /// Where the cursor was at the end of the settle, and how far that is from the anchor.
    pos_after: Option<Pt>,
    off_anchor: Option<Pt>,
    /// Position changes seen during the settle (the first look is compared with the anchor).
    position_changes: usize,
    raw: Option<RawSummary>,
}

#[derive(Serialize, Debug)]
struct MethodRecord {
    method: &'static str,
    /// `ok` (with `nothing moved` / `N of 3 moves did not move` when calls were accepted but the
    /// cursor did not follow), `refused(<call and error>)`, `skipped(<why>)`, `aborted` (the run
    /// stopped here), or `not run` (after an abort).
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<ResetRecord>,
    moves: Vec<MoveRecord>,
}

#[derive(Serialize, Clone, Debug)]
struct Abort {
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,
    #[serde(rename = "move", skip_serializing_if = "Option::is_none")]
    mv: Option<usize>,
}

/// One raw-input mouse event, as the sink heard it.
#[derive(Clone, Copy, Debug)]
pub(super) struct RawEvent {
    pub(super) at: Instant,
    pub(super) flags: u16,
    pub(super) x: i32,
    pub(super) y: i32,
    /// `usButtonFlags`: `RI_MOUSE_LEFT_BUTTON_DOWN` 1, `…_UP` 2, and so on.
    pub(super) buttons: u16,
    pub(super) device: usize,
    pub(super) extra: u32,
    /// The `WM_INPUT` message's `pt`: where the cursor was when Windows posted the event — for a
    /// button, where the click landed.
    pub(super) pt: Pt,
}

#[derive(Serialize, Debug)]
struct RawEventOut {
    /// µs since the run began (negative: before it, while the sink was starting).
    t_us: i64,
    flags: u16,
    x: i32,
    y: i32,
    #[serde(skip_serializing_if = "is_zero_u16")]
    buttons: u16,
    device: String,
    #[serde(skip_serializing_if = "is_zero_u32")]
    extra: u32,
    pt: Pt,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

#[test]
#[ignore = "moves the real cursor (moves only); run by hand with the owner, see the module docs"]
fn mouse_probe() -> Result<()> {
    let target = match std::env::var("AFK_PROBE_TARGET") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_lowercase(),
        Ok(_) | Err(std::env::VarError::NotPresent) => bail!(
            "AFK_PROBE_TARGET is not set: set it to a substring of the target's exe name, e.g. \
             $env:AFK_PROBE_TARGET = 'l2' (or 'notepad'), then run again"
        ),
        Err(error) => bail!("AFK_PROBE_TARGET is unreadable: {error}"),
    };
    let out = output_path(&target)?;
    // This crate's own debug lines (the driver probe, a refused SendInput) go to stdout with ours.
    let _log = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("afklink_input=debug"))
            .with_ansi(false)
            .with_writer(std::io::stdout)
            .finish(),
    );
    println!("mouse_probe: target \"{target}\", output {}", out.display());
    let mut probe = Probe::new(target, out);
    let outcome = probe.run();
    probe.finish(outcome)
}

/// Where the JSON goes: `AFK_PROBE_OUT`, else `agent\target\mouse-probe-<target>-<local time>.json`.
fn output_path(target: &str) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AFK_PROBE_OUT").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    // SAFETY: returns a value; no pointers.
    let now = unsafe { GetLocalTime() };
    let stamp = format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond
    );
    let name: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("the crate directory has no workspace two levels above it")?;
    Ok(workspace
        .join("target")
        .join(format!("mouse-probe-{name}-{stamp}.json")))
}

/// Everything one run records, in the order the JSON lays it out.
struct Probe {
    target: String,
    out: PathBuf,
    started_local: String,
    environment: Value,
    driver: Value,
    raw_input: Value,
    foreground: Value,
    anchor: Value,
    cursor: Value,
    aborted: Option<Abort>,
    /// Every error or oddity that did not stop the run, as it was printed.
    notes: Vec<String>,
    summary: Vec<MoveSummary>,
    methods: Vec<MethodRecord>,
    samples: Vec<Sample>,
    raw_events: Vec<RawEventOut>,
}

/// Print a line and keep it for the JSON's `notes`.
fn note(notes: &mut Vec<String>, line: String) {
    println!("mouse_probe: {line}");
    notes.push(line);
}

impl Probe {
    fn new(target: String, out: PathBuf) -> Self {
        Self {
            target,
            out,
            started_local: local_time(),
            environment: Value::Null,
            driver: Value::Null,
            raw_input: Value::Null,
            foreground: Value::Null,
            anchor: Value::Null,
            cursor: Value::Null,
            aborted: None,
            notes: Vec::new(),
            summary: Vec::new(),
            methods: Vec::new(),
            samples: Vec::new(),
            raw_events: Vec::new(),
        }
    }

    fn run(&mut self) -> Result<()> {
        // First of all, before anything reads a coordinate: physical pixels from here on.
        self.environment = environment(&mut self.notes);

        let mut hid = match platform::Device::open() {
            Ok(Some(device)) => {
                self.driver =
                    json!({ "available": true, "outcome": "opened: API v1, nothing sent" });
                Some(State::new(device))
            }
            Ok(None) => {
                self.driver = json!({ "available": false, "outcome": "not installed" });
                None
            }
            Err(error) => {
                self.driver = json!({ "available": false, "error": format!("{error:#}") });
                None
            }
        };
        let desktop = platform::evaluate_target();
        self.driver["hid_target"] =
            json!({ "target": format!("{:?}", desktop.target), "reason": desktop.reason });
        println!(
            "mouse_probe: FakerInput {}; HID target {:?} ({})",
            if hid.is_some() {
                "open"
            } else {
                "unavailable: hid_abs and hid_rel are skipped"
            },
            desktop.target,
            desktop.reason
        );

        // The target in the foreground, then the countdown.
        let (hwnd, pid, exe) = wait_for_target(&self.target)?;
        let process = process_facts(pid);
        println!(
            "mouse_probe: found {} (pid {pid}, window {hwnd:#x}); process {process}",
            exe.label()
        );
        if process["elevated"] == json!(true)
            && self.environment["process"]["elevated"] != json!(true)
        {
            note(
                &mut self.notes,
                "the target runs elevated and this probe does not (as the agent does not): Windows \
                 may refuse SetCursorPos and SendInput over it (UIPI); a refused method is recorded \
                 and skipped, and the cursor is placed by the HID absolute report instead"
                    .to_owned(),
            );
        }
        for left in (1..=COUNTDOWN_S).rev() {
            println!("mouse_probe: starting in {left} s — hands off the mouse");
            std::thread::sleep(Duration::from_secs(1));
        }
        let now_hwnd = foreground();
        let now_pid = window_pid(now_hwnd);
        let (exe, process) = if now_pid == pid {
            (exe, process)
        } else {
            let now_exe = process_exe(now_pid);
            if !now_exe.matches(&self.target) {
                bail!(
                    "the target lost the foreground during the countdown (now {} pid {now_pid}); \
                     nothing was moved",
                    now_exe.label()
                );
            }
            note(
                &mut self.notes,
                format!(
                    "during the countdown the foreground moved to another process of the target \
                     exe: pid {now_pid}"
                ),
            );
            (now_exe, process_facts(now_pid))
        };
        let before = cursor_pos().map_err(|e| anyhow!("reading the cursor before the run: {e}"))?;
        self.foreground = window_info(now_hwnd, now_pid, &exe, process);
        self.cursor = json!({ "before": before });

        // The anchor. Nothing moves it there yet: the first method's reset does, with the fallback.
        let primary = primary_monitor(&mut self.notes);
        let Some((anchor, clamped)) = anchor_for(before, primary) else {
            bail!(
                "the primary monitor {:?} is too small to keep every target {MARGIN} px from its \
                 edges; nothing was moved",
                rect(primary)
            );
        };
        self.anchor = json!({ "point": anchor, "clamped_from": clamped.then_some(before) });
        if clamped {
            println!(
                "mouse_probe: anchor {anchor:?} (the cursor at {before:?} is too near an edge)"
            );
        } else {
            println!("mouse_probe: anchor {anchor:?} (the cursor's own position)");
        }

        // The planner says the settings it works with (display scale, EPP, speed) at `debug`, on
        // stdout with this crate's other lines.
        let mut sync = CursorSync::new();
        sync.begin_session(&mut SystemCursor, Instant::now());

        // From here on the cursor moves: `Run`'s drop puts it back however the run ends.
        let mut run = Run {
            epoch: Instant::now(),
            deadline: Instant::now() + RUN_BUDGET,
            target: self.target.clone(),
            target_pid: now_pid,
            target_windows: BTreeSet::from([now_hwnd]),
            primary,
            anchor,
            hid: hid.take(),
            rel_carry: Mutex::new(RelCarry::default()),
            sync,
            samples: Vec::new(),
            notes: std::mem::take(&mut self.notes),
            restore: Some(before),
            timer: false,
        };
        let mut sink = match RawSink::start() {
            Ok(sink) => {
                self.raw_input = json!({ "running": true, "registration": "RIDEV_INPUTSINK, usage page 1, usage 2, message-only window" });
                Some(sink)
            }
            Err(error) => {
                note(
                    &mut run.notes,
                    format!("raw-input sink not running: {error}"),
                );
                self.raw_input = json!({ "running": false, "error": error });
                None
            }
        };
        // SAFETY: plain call; balanced by `timeEndPeriod` below or in `Run`'s drop.
        let period = unsafe { timeBeginPeriod(1) };
        run.timer = period == TIMERR_NOERROR;
        self.environment["timer_period_1ms"] = json!(if run.timer {
            "ok".to_owned()
        } else {
            format!("timeBeginPeriod(1) returned {period}")
        });
        if !run.timer {
            note(
                &mut run.notes,
                format!("timeBeginPeriod(1) returned {period}: samples may come coarser than 1 ms"),
            );
        }

        // The run — and its budget — starts here, with the first reset.
        let epoch = Instant::now();
        run.epoch = epoch;
        run.deadline = epoch + RUN_BUDGET;
        let (methods, aborted) = run.run_methods();
        let run_end = Instant::now();

        // The cursor back where it was (SetCursorPos, else HID), then the timer, device and sink.
        run.restore = None;
        let restore = place_cursor(before, run.hid.as_mut(), primary);
        std::thread::sleep(Duration::from_millis(50));
        let end = cursor_pos();
        println!(
            "mouse_probe: cursor put back to {before:?} by {}; now at {end:?}",
            restore.describe()
        );
        // The planner's last aggregate line, and what it learned.
        run.sync.end_session(Instant::now());
        let exact_rel_gain = run.sync.gain_summary();
        println!("mouse_probe: exact_rel's planner: gain {exact_rel_gain}");
        self.cursor = json!({
            "before": before,
            "restore": restore,
            "end": end.as_ref().ok(),
            "end_error": end.as_ref().err(),
            "back_where_it_was": end.as_ref().is_ok_and(|p| *p == before),
            "off_by": end.as_ref().ok().map(|p| [p[0] - before[0], p[1] - before[1]]),
            "run_ms": run_end.saturating_duration_since(epoch).as_secs_f64() * 1000.0,
            "exact_rel_gain": exact_rel_gain,
        });
        if end.as_ref().ok() != Some(&before) {
            note(
                &mut run.notes,
                format!(
                    "the cursor ended at {end:?}, not where it started ({before:?}); put back by {}",
                    restore.describe()
                ),
            );
        }
        if run.timer {
            run.timer = false;
            // SAFETY: balances the `timeBeginPeriod(1)` above.
            let ended = unsafe { timeEndPeriod(1) };
            if ended != TIMERR_NOERROR {
                note(&mut run.notes, format!("timeEndPeriod(1) returned {ended}"));
            }
        }
        if let Some(state) = run.hid.as_mut() {
            // Nothing is held (the probe never presses); this only confirms the device is clean.
            if let Err(error) = state.release() {
                note(
                    &mut run.notes,
                    format!("FakerInput neutral cleanup failed: {error:#}"),
                );
            }
        }

        let raw = sink.take().map(|sink| {
            let (events, errors) = sink.stop();
            for error in errors {
                note(&mut run.notes, format!("raw input: {error}"));
            }
            events
        });

        // Per-move summaries, with what the raw-input reader heard in each stretch.
        let mut summary = Vec::new();
        let mut methods = methods;
        let mut attributed = 0;
        for method in &mut methods {
            if let (Some(reset), Some(events)) = (method.reset.as_mut(), raw.as_ref()) {
                let s = raw_summary(events, epoch, reset.run_start_us, reset.run_end_us);
                attributed += s.events;
                reset.raw = Some(s);
            }
            let mut still = 0;
            for record in &method.moves {
                let mut s = summarize(record, &run.samples[record.samples.clone()]);
                if let Some(events) = raw.as_ref() {
                    let r = raw_summary(events, epoch, record.run_start_us, record.run_end_us);
                    attributed += r.events;
                    s.raw = Some(r);
                }
                still += usize::from(s.no_movement);
                summary.push(s);
            }
            // Accepted is not the same as done: say so when the cursor did not follow.
            if method.status == "ok" && still > 0 {
                method.status = if still == method.moves.len() {
                    "ok (nothing moved)".to_owned()
                } else {
                    format!("ok ({still} of {} moves did not move)", method.moves.len())
                };
            }
        }
        if let Some(events) = raw.as_ref() {
            let outside = events.len().saturating_sub(attributed);
            self.raw_input["events_total"] = json!(events.len());
            self.raw_input["events_outside_moves_and_resets"] = json!(outside);
            self.raw_events = events
                .iter()
                .map(|e| RawEventOut {
                    t_us: us_between(epoch, e.at),
                    flags: e.flags,
                    x: e.x,
                    y: e.y,
                    buttons: e.buttons,
                    device: format!("{:#x}", e.device),
                    extra: e.extra,
                    pt: e.pt,
                })
                .collect();
        }

        self.summary = summary;
        self.methods = methods;
        self.samples = std::mem::take(&mut run.samples);
        self.notes = std::mem::take(&mut run.notes);
        if let Some(abort) = aborted {
            let reason = abort.reason.clone();
            self.aborted = Some(abort);
            bail!("aborted: {reason}");
        }
        Ok(())
    }

    /// Print the table, write the JSON, and answer with the run's outcome (or the write's failure).
    fn finish(self, outcome: Result<()>) -> Result<()> {
        print_table(&self.methods, &self.summary);
        let record = json!({
            "probe": "afklink-input fakerinput::mouse_probe",
            "format": 1,
            "started_local": self.started_local,
            "target": self.target,
            "outcome": match &outcome {
                Ok(()) => "complete".to_owned(),
                Err(error) => format!("{error:#}"),
            },
            "config": config(),
            "environment": self.environment,
            "driver": self.driver,
            "raw_input": self.raw_input,
            "foreground": self.foreground,
            "anchor": self.anchor,
            "cursor": self.cursor,
            "aborted": self.aborted,
            "notes": self.notes,
            "summary": self.summary,
            "methods": self.methods,
            "samples": self.samples,
            "raw_events": self.raw_events,
        });
        let written = serde_json::to_string_pretty(&record)
            .context("serializing the probe record")
            .and_then(|text| {
                if let Some(dir) = self.out.parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
                std::fs::write(&self.out, text)
                    .with_context(|| format!("writing {}", self.out.display()))
            });
        match &written {
            Ok(()) => println!("mouse_probe: written {}", self.out.display()),
            Err(error) => println!("mouse_probe: the JSON was not written: {error:#}"),
        }
        match (outcome, written) {
            (Err(error), _) => Err(error),
            (Ok(()), written) => written,
        }
    }
}

/// The part of the run that moves the cursor. Its drop is the net under the normal path: however the
/// run ends — an early error, a panic — it puts the cursor back (`SetCursorPos`, else HID) and ends
/// the 1 ms timer period, unless the normal path (an abort included) already did and recorded both.
struct Run {
    epoch: Instant,
    deadline: Instant,
    target: String,
    target_pid: u32,
    /// Foreground windows already known to be the target's.
    target_windows: BTreeSet<usize>,
    primary: RECT,
    anchor: Pt,
    hid: Option<State<platform::Device>>,
    /// `SendInput`'s sub-pixel remainder for relative moves, kept as the injector keeps it.
    rel_carry: Mutex<RelCarry>,
    /// The production cursor-sync planner `exact_rel` moves through, on this PC's real cursor and
    /// settings; one for the method's three moves, as a session keeps one.
    sync: CursorSync,
    samples: Vec<Sample>,
    notes: Vec<String>,
    /// Where the drop puts the cursor back; `None` once the normal path has.
    restore: Option<Pt>,
    /// `timeBeginPeriod(1)` is in force and the drop must end it.
    timer: bool,
}

impl Drop for Run {
    fn drop(&mut self) {
        if let Some(p) = self.restore.take() {
            let placed = place_cursor(p, self.hid.as_mut(), self.primary);
            println!(
                "mouse_probe: cursor put back to {p:?} on the way out by {}",
                placed.describe()
            );
        }
        if self.timer {
            self.timer = false;
            // SAFETY: balances the run's `timeBeginPeriod(1)`.
            let ended = unsafe { timeEndPeriod(1) };
            if ended != TIMERR_NOERROR {
                println!("mouse_probe: timeEndPeriod(1) returned {ended}");
            }
        }
    }
}

impl Run {
    fn run_methods(&mut self) -> (Vec<MethodRecord>, Option<Abort>) {
        let mut methods = Vec::new();
        let mut aborted = None;
        for method in METHODS {
            let mut record = MethodRecord {
                method: method.name(),
                status: "ok".to_owned(),
                reset: None,
                moves: Vec::new(),
            };
            if aborted.is_some() {
                record.status = "not run".to_owned();
                methods.push(record);
                continue;
            }
            if method.hid() && self.hid.is_none() {
                record.status = "skipped(no FakerInput driver)".to_owned();
                println!("mouse_probe: {} skipped: no driver", method.name());
                methods.push(record);
                continue;
            }
            println!("mouse_probe: {}", method.name());
            let (reset, stop) = self.reset();
            record.reset = Some(reset);
            if let Some(stop) = stop {
                // A reset only ever aborts: a refused SetCursorPos falls back to HID there.
                record.status = "aborted".to_owned();
                aborted = Some(self.abort(stop, method, None));
                methods.push(record);
                continue;
            }
            let mut offset = [0, 0];
            for (index, delta) in MOVES.into_iter().enumerate() {
                let mv = index + 1;
                offset = [offset[0] + delta.0, offset[1] + delta.1];
                let target = [self.anchor[0] + offset[0], self.anchor[1] + offset[1]];
                let (moved, stop) = self.run_move(method, mv, target, delta);
                record.moves.push(moved);
                match stop {
                    None => {}
                    Some(Stop::Refused(why)) => {
                        note(
                            &mut self.notes,
                            format!(
                                "{} refused at move {mv}: {why}; the rest of it is skipped",
                                method.name()
                            ),
                        );
                        record.status = format!("refused({why})");
                        break;
                    }
                    Some(stop @ Stop::Abort(_)) => {
                        record.status = "aborted".to_owned();
                        aborted = Some(self.abort(stop, method, Some(mv)));
                        break;
                    }
                }
            }
            methods.push(record);
        }
        (methods, aborted)
    }

    fn abort(&mut self, stop: Stop, method: Method, mv: Option<usize>) -> Abort {
        let reason = match stop {
            Stop::Abort(reason) | Stop::Refused(reason) => reason,
        };
        note(
            &mut self.notes,
            format!("ABORTED during {} move {mv:?}: {reason}", method.name()),
        );
        Abort {
            reason,
            method: Some(method.name()),
            mv,
        }
    }

    /// Put the cursor on the anchor (`SetCursorPos`, else the HID absolute report) and let it
    /// settle, watching the foreground. If neither way works, the run goes on from wherever the
    /// cursor is — as long as that is inside the margin.
    fn reset(&mut self) -> (ResetRecord, Option<Stop>) {
        let started = Instant::now();
        let placement = place_cursor(self.anchor, self.hid.as_mut(), self.primary);
        if placement.way != "setcursorpos" {
            note(
                &mut self.notes,
                format!(
                    "putting the cursor on the anchor {:?}: {}",
                    self.anchor,
                    placement.describe()
                ),
            );
        }
        let mut stop = placement.hid_failed.then(|| {
            Stop::Abort(format!(
                "the HID absolute report failed while putting the cursor on the anchor: {}",
                placement.hid_abs.as_deref().unwrap_or("?")
            ))
        });
        let mut record = ResetRecord {
            run_start_us: us_between(self.epoch, started),
            run_end_us: 0,
            placement,
            pos_after: None,
            off_anchor: None,
            position_changes: 0,
            raw: None,
        };
        let mut last = Some(self.anchor);
        while stop.is_none() && started.elapsed() < RESET_SETTLE {
            std::thread::sleep(
                Duration::from_millis(10).min(RESET_SETTLE.saturating_sub(started.elapsed())),
            );
            let seen = observe();
            if seen.pos != last {
                record.position_changes += 1;
                last = seen.pos;
            }
            stop = self.check(&seen, Instant::now()).map(Stop::Abort);
        }
        record.pos_after = last;
        record.off_anchor = last.map(|p| [p[0] - self.anchor[0], p[1] - self.anchor[1]]);
        record.run_end_us = us_between(self.epoch, Instant::now());
        if stop.is_none() {
            if let Some(p) = last.filter(|p| *p != self.anchor) {
                note(
                    &mut self.notes,
                    format!(
                        "after the reset the cursor is at {p:?}, not on the anchor {:?}",
                        self.anchor
                    ),
                );
                if !inside_margin(p, self.primary) {
                    stop = Some(Stop::Abort(format!(
                        "the cursor is at {p:?}, closer than {MARGIN} px to the primary \
                         monitor's edge {:?}, and could not be put on the anchor",
                        rect(self.primary)
                    )));
                }
            }
        }
        (record, stop)
    }

    /// One move: the look before, the injection (one call, or the paced relative steps) and ~1 ms
    /// looks until [`WINDOW`] after the last call. Returns the record and, if the run must stop,
    /// why.
    fn run_move(
        &mut self,
        method: Method,
        mv: usize,
        target: Pt,
        delta: (i32, i32),
    ) -> (MoveRecord, Option<Stop>) {
        let first = self.samples.len();
        let before_at = Instant::now();
        let before = observe();
        let t0 = Instant::now();
        let start = before.pos;
        self.samples.push(Sample {
            method: method.name(),
            mv,
            t_us: us_between(t0, before_at),
            mark: Some("before".to_owned()),
            seen: before.clone(),
        });
        let (plan, record_target, counts, expected) = if method.relative() {
            let plan: Vec<(Duration, Pt)> = rel_chunks(delta)
                .into_iter()
                .zip(0u32..)
                .map(|(step, i)| (REL_CHUNK_GAP * i, step))
                .collect();
            let expected = start.map(|s| [s[0] + delta.0, s[1] + delta.1]);
            let counts = (!method.in_pixels()).then_some([delta.0, delta.1]);
            (plan, None, counts, expected)
        } else {
            (
                vec![(Duration::ZERO, target)],
                Some(target),
                None,
                Some(target),
            )
        };
        let mut record = MoveRecord {
            method: method.name(),
            mv,
            run_start_us: us_between(self.epoch, t0),
            run_end_us: 0,
            start,
            target: record_target,
            counts,
            expected,
            calls: Vec::new(),
            last_call_start_us: 0,
            last_call_end_us: 0,
            samples: first..first,
        };
        let stop = match start {
            None => Some(Stop::Abort(format!(
                "the cursor position is unknown before the move: {:?}",
                before.pos_error
            ))),
            Some(_) => self.drive(method, mv, t0, &plan, &mut record, before),
        };
        record.run_end_us = us_between(self.epoch, Instant::now());
        record.samples = first..self.samples.len();
        (record, stop)
    }

    fn drive(
        &mut self,
        method: Method,
        mv: usize,
        t0: Instant,
        plan: &[(Duration, Pt)],
        record: &mut MoveRecord,
        before: Observed,
    ) -> Option<Stop> {
        let mut next = 0;
        let mut end: Option<Instant> = None;
        let mut last_seen = before;
        let mut latest_pos = last_seen.pos;
        let mut mark = 0;
        let mut tick: u32 = 0;
        loop {
            // The injections due now.
            while next < plan.len() && Instant::now() >= t0 + plan[next].0 {
                let (_, arg) = plan[next];
                if let Some(why) = self.refuse(method, arg, &plan[next..], latest_pos) {
                    return Some(Stop::Abort(why));
                }
                let started = Instant::now();
                let mut call = self.inject(method, arg);
                call.t_us = us_between(t0, started);
                record.last_call_start_us = call.t_us;
                record.last_call_end_us = us_between(t0, Instant::now());
                let failed = (!call.ok).then(|| {
                    let why = format!(
                        "{}: {}{}",
                        call.call,
                        call.result,
                        call.last_error
                            .map_or(String::new(), |e| format!(", GetLastError {e}"))
                    );
                    // A HID write that fails stops the run; Windows refusing SetCursorPos or
                    // SendInput (UIPI over an elevated window) is a finding: the method is skipped.
                    if method.hid() {
                        Stop::Abort(why)
                    } else {
                        Stop::Refused(why)
                    }
                });
                record.calls.push(call);
                if failed.is_some() {
                    return failed;
                }
                next += 1;
                if next == plan.len() {
                    end = Some(Instant::now() + WINDOW);
                }
            }

            let now = Instant::now();
            let seen = observe();
            latest_pos = seen.pos.or(latest_pos);
            let mut marks = Vec::new();
            while mark < MARKS_MS.len() && now >= t0 + Duration::from_millis(MARKS_MS[mark]) {
                marks.push(format!("+{}ms", MARKS_MS[mark]));
                mark += 1;
            }
            let done = end.is_some_and(|e| now >= e);
            if done {
                marks.push("final".to_owned());
            }
            if seen != last_seen || !marks.is_empty() {
                self.samples.push(Sample {
                    method: method.name(),
                    mv,
                    t_us: us_between(t0, now),
                    mark: (!marks.is_empty()).then(|| marks.join(",")),
                    seen: seen.clone(),
                });
            }
            if let Some(why) = self.check(&seen, now) {
                return Some(Stop::Abort(why));
            }
            if done {
                return None;
            }
            last_seen = seen;

            // Sleep to the next tick; a late wake-up skips the ticks it missed rather than racing
            // through them. Never past the next injection.
            tick += 1;
            let now = Instant::now();
            let mut due = t0 + TICK * tick;
            if due <= now {
                tick =
                    (now.saturating_duration_since(t0).as_micros() / TICK.as_micros()) as u32 + 1;
                due = t0 + TICK * tick;
            }
            if let Some((at, _)) = plan.get(next) {
                due = due.min(t0 + *at);
            }
            std::thread::sleep(due.saturating_duration_since(Instant::now()));
        }
    }

    /// Why an injection must not go out: its point, or where the rest of a relative move would take
    /// the cursor from where it is now, is closer than [`MARGIN`] to the primary monitor's edge.
    fn refuse(
        &self,
        method: Method,
        arg: Pt,
        rest: &[(Duration, Pt)],
        latest: Option<Pt>,
    ) -> Option<String> {
        let aim = if method.relative() {
            let Some(p) = latest else {
                return Some("the cursor position is unknown before a relative step".to_owned());
            };
            let (x, y) = rest
                .iter()
                .fold((0, 0), |(x, y), (_, s)| (x + s[0], y + s[1]));
            [p[0] + x, p[1] + y]
        } else {
            arg
        };
        (!inside_margin(aim, self.primary)).then(|| {
            format!(
                "refused: {aim:?} is closer than {MARGIN} px to the primary monitor's edge {:?}",
                rect(self.primary)
            )
        })
    }

    /// One injection. `t_us` is filled in by the caller.
    fn inject(&mut self, method: Method, arg: Pt) -> Call {
        let begun = Instant::now();
        let from = |answer: Answer, wire: Option<Pt>| {
            (answer.ok, answer.result, wire, Some(answer.last_error))
        };
        let (ok, result, wire, last_error) = match method {
            Method::SetCursorPos => from(set_cursor(arg), None),
            Method::SendInputAbs => {
                let (fx, fy) = fraction(arg, self.primary);
                let input = crate::imp::absolute_input(fx, fy);
                // SAFETY: `absolute_input` builds a mouse event; this reads back its own fields.
                let wire = unsafe { [input.Anonymous.mi.dx, input.Anonymous.mi.dy] };
                from(send_input(input), Some(wire))
            }
            Method::HidAbs => {
                let (w, h) = platform::screen_size();
                let [px, py] = [arg[0] - self.primary.left, arg[1] - self.primary.top];
                let wire = hid_wire(arg, self.primary);
                match self.hid.as_mut() {
                    Some(state) => match state.absolute(px, py, w, h) {
                        Ok(()) => (true, "written".to_owned(), Some(wire), None),
                        Err(error) => (false, format!("{error:#}"), Some(wire), None),
                    },
                    None => (false, "no FakerInput device".to_owned(), Some(wire), None),
                }
            }
            Method::ExactRel => self.exact_step(arg),
            Method::SendInputRel => {
                let (fx, fy) = step_fraction(arg);
                match crate::imp::relative_input(fx, fy, &self.rel_carry) {
                    Some(input) => {
                        // SAFETY: `relative_input` builds a mouse event; this reads back its own fields.
                        let wire = unsafe { [input.Anonymous.mi.dx, input.Anonymous.mi.dy] };
                        from(send_input(input), Some(wire))
                    }
                    None => (
                        false,
                        "relative_input made no event (under a pixel, or no screen size)"
                            .to_owned(),
                        None,
                        None,
                    ),
                }
            }
            Method::HidRel => {
                let (fx, fy) = step_fraction(arg);
                let (w, h) = platform::screen_size();
                match self.hid.as_mut() {
                    Some(state) => match state.relative(fx, fy, w, h) {
                        Ok(()) => (true, "written".to_owned(), None, None),
                        Err(error) => (false, format!("{error:#}"), None, None),
                    },
                    None => (false, "no FakerInput device".to_owned(), None, None),
                }
            }
        };
        Call {
            t_us: 0,
            call: method.call(),
            arg,
            wire,
            ok,
            result,
            last_error,
            duration_us: begun.elapsed().as_micros() as u64,
        }
    }

    /// One step of `exact_rel`: `step` px as an `r` without a target, planned by the production
    /// cursor-sync planner on this PC's cursor, sent as it says through report 3. What it answers:
    /// ok, the call's text, and the counts sent as the wire.
    fn exact_step(&mut self, step: Pt) -> (bool, String, Option<Pt>, Option<u32>) {
        let (fx, fy) = step_fraction(step);
        let event = RelEvent {
            dx: fx,
            dy: fy,
            x: None,
            y: None,
            s: None,
        };
        let plan = self.sync.plan(
            event,
            false,
            RelPath::Hid,
            &mut SystemCursor,
            Instant::now(),
        );
        let Some(state) = self.hid.as_mut() else {
            return (false, "no FakerInput device".to_owned(), None, None);
        };
        match plan {
            Plan::Relative { cx, cy } => match state.movement(cx, cy) {
                Ok(()) => (true, "written (exact)".to_owned(), Some([cx, cy]), None),
                Err(error) => {
                    self.sync.failed("the probe's HID report failed");
                    (false, format!("{error:#}"), Some([cx, cy]), None)
                }
            },
            Plan::Nothing => (
                true,
                "nothing to send (under a count so far)".to_owned(),
                Some([0, 0]),
                None,
            ),
            Plan::Camera => {
                // The planner saw no visible cursor on the captured screen: the camera's counts,
                // as the agent would send them. The record says so; the summary will show it.
                let (w, h) = platform::screen_size();
                match state.relative(fx, fy, w, h) {
                    Ok(()) => (
                        true,
                        "camera: the planner saw no visible cursor on the screen".to_owned(),
                        None,
                        None,
                    ),
                    Err(error) => (false, format!("{error:#}"), None, None),
                }
            }
            Plan::Absolute { px, py, .. } => (
                false,
                format!("the planner asked for an absolute move to {px},{py} without a target"),
                None,
                None,
            ),
        }
    }

    /// Stop the run if its time is up, the cursor position is unknown, or the foreground went to a
    /// process that is not the target (no foreground at all, a moment of a focus change, is let
    /// pass: the samples show it).
    fn check(&mut self, seen: &Observed, now: Instant) -> Option<String> {
        if now >= self.deadline {
            return Some(format!(
                "the run passed its {} s budget",
                RUN_BUDGET.as_secs()
            ));
        }
        if seen.pos.is_none() {
            return Some(format!(
                "the cursor position is unknown: {}",
                seen.pos_error.as_deref().unwrap_or("?")
            ));
        }
        let hwnd = seen.foreground;
        if hwnd == 0 || self.target_windows.contains(&hwnd) {
            return None;
        }
        let pid = window_pid(hwnd);
        if pid == self.target_pid {
            self.target_windows.insert(hwnd);
            note(
                &mut self.notes,
                format!("the foreground moved to another window of the target process: {hwnd:#x}"),
            );
            return None;
        }
        let exe = process_exe(pid);
        if exe.matches(&self.target) {
            self.target_windows.insert(hwnd);
            note(
                &mut self.notes,
                format!(
                    "the foreground moved to another process of the target exe: {} pid {pid}",
                    exe.label()
                ),
            );
            return None;
        }
        Some(format!(
            "the foreground changed to {} (pid {pid}, window {hwnd:#x})",
            exe.label()
        ))
    }
}

/// A relative move's counts as fractions of the primary screen — how an `r` carries them — scaled
/// by the size both relative paths scale by, so their carry turns them back into these counts.
fn step_fraction(step: Pt) -> (f64, f64) {
    let (w, h) = platform::screen_size();
    (
        f64::from(step[0]) / f64::from(w.max(1)),
        f64::from(step[1]) / f64::from(h.max(1)),
    )
}

/// A relative move as [`REL_CHUNKS`] equal steps; a remainder goes with the last.
fn rel_chunks(delta: (i32, i32)) -> Vec<Pt> {
    let (sx, sy) = (delta.0 / REL_CHUNKS, delta.1 / REL_CHUNKS);
    let mut steps = vec![[sx, sy]; REL_CHUNKS as usize];
    if let Some(last) = steps.last_mut() {
        last[0] += delta.0 - sx * REL_CHUNKS;
        last[1] += delta.1 - sy * REL_CHUNKS;
    }
    steps
}

/// What FakerInput's absolute report carries for a screen point: the production mapping
/// ([`absolute_wire`], the pixel's centre), the point taken relative to the primary monitor.
fn hid_wire(p: Pt, primary: RECT) -> Pt {
    let (w, h) = platform::screen_size();
    let (x, y) = absolute_wire(p[0] - primary.left, p[1] - primary.top, w, h);
    [i32::from(x), i32::from(y)]
}

/// A point as fractions of the primary monitor — what the viewer's `m` carries (the agent maps it
/// onto the primary monitor; its origin is the virtual screen's).
fn fraction(p: Pt, primary: RECT) -> (f64, f64) {
    let (w, h) = platform::screen_size();
    (
        f64::from(p[0] - primary.left) / f64::from(w.max(1)),
        f64::from(p[1] - primary.top) / f64::from(h.max(1)),
    )
}

/// Clear the thread's last error, so what a call leaves there is its own.
fn clear_last_error() {
    // SAFETY: plain call.
    unsafe { SetLastError(WIN32_ERROR(0)) };
}

/// The thread's last error, read right after the call it reports on.
fn last_error() -> u32 {
    // SAFETY: plain call.
    unsafe { GetLastError() }.0
}

/// `SetCursorPos`, with its answer as windows-rs gives it and `GetLastError` read right after
/// (windows-rs reads it too on a failure, and nothing runs in between that could change it).
pub(super) fn set_cursor(p: Pt) -> Answer {
    clear_last_error();
    // SAFETY: plain call.
    let set = unsafe { SetCursorPos(p[0], p[1]) };
    let last_error = last_error();
    Answer {
        ok: set.is_ok(),
        result: result_text(&set),
        last_error,
    }
}

fn send_input(input: INPUT) -> Answer {
    clear_last_error();
    // SAFETY: one live mouse INPUT and its size, as `SendInput` asks; it copies them synchronously.
    let sent = unsafe { SendInput(&[input], size_of::<INPUT>() as i32) };
    let last_error = last_error();
    let ok = sent == 1;
    let result = if ok {
        "sent 1/1".to_owned()
    } else {
        format!(
            "SendInput sent {sent}/1: {}",
            std::io::Error::from_raw_os_error(last_error as i32)
        )
    };
    Answer {
        ok,
        result,
        last_error,
    }
}

/// Put the cursor on `to`: `SetCursorPos`, else — when Windows refuses it, as it may for an
/// unelevated process over an elevated window — FakerInput's absolute report (report 4, the same
/// mapping as `hid_abs`), which goes in as a device's input. Says which way worked, if either.
fn place_cursor(to: Pt, hid: Option<&mut State<platform::Device>>, primary: RECT) -> Placement {
    let mut placement = Placement {
        to,
        way: "setcursorpos",
        set_cursor_pos: set_cursor(to),
        hid_abs: None,
        hid_wire: None,
        hid_failed: false,
    };
    if placement.set_cursor_pos.ok {
        return placement;
    }
    placement.way = "none";
    match hid {
        None => placement.hid_abs = Some("no FakerInput device".to_owned()),
        Some(state) => {
            let (w, h) = platform::screen_size();
            placement.hid_wire = Some(hid_wire(to, primary));
            match state.absolute(to[0] - primary.left, to[1] - primary.top, w, h) {
                Ok(()) => {
                    placement.way = "hid_abs";
                    placement.hid_abs = Some("written".to_owned());
                }
                Err(error) => {
                    placement.hid_failed = true;
                    placement.hid_abs = Some(format!("{error:#}"));
                }
            }
        }
    }
    placement
}

/// The anchor: the cursor, moved (if it must be) far enough inside the primary monitor that every
/// target — the anchor and [`STEP`] right of and below it — stays [`MARGIN`] px from each edge; and
/// whether it had to move. `None` when the monitor is too small for that.
fn anchor_for(cursor: Pt, primary: RECT) -> Option<(Pt, bool)> {
    let (x_lo, x_hi) = (primary.left + MARGIN, primary.right - 1 - MARGIN - STEP);
    let (y_lo, y_hi) = (primary.top + MARGIN, primary.bottom - 1 - MARGIN - STEP);
    if x_lo > x_hi || y_lo > y_hi {
        return None;
    }
    let anchor = [cursor[0].clamp(x_lo, x_hi), cursor[1].clamp(y_lo, y_hi)];
    Some((anchor, anchor != cursor))
}

/// At least [`MARGIN`] px from every edge of the monitor (its right and bottom are exclusive).
fn inside_margin(p: Pt, monitor: RECT) -> bool {
    p[0] >= monitor.left + MARGIN
        && p[0] <= monitor.right - 1 - MARGIN
        && p[1] >= monitor.top + MARGIN
        && p[1] <= monitor.bottom - 1 - MARGIN
}

/// One look at the cursor: position, shape and visibility, clip, foreground, capture.
fn observe() -> Observed {
    let mut seen = Observed::default();
    match cursor_pos() {
        Ok(p) => seen.pos = Some(p),
        Err(error) => seen.pos_error = Some(error),
    }
    match cursor_info() {
        Ok(info) => {
            seen.cursor_flags = Some(info.flags.0);
            seen.showing = Some(info.flags.0 & CURSOR_SHOWING.0 != 0);
            seen.suppressed = Some(info.flags.0 & CURSOR_SUPPRESSED.0 != 0);
            seen.shape = Some(info.hCursor.0 as usize);
            seen.info_pos = Some([info.ptScreenPos.x, info.ptScreenPos.y]);
        }
        Err(error) => seen.info_error = Some(error),
    }
    let mut clip = RECT::default();
    // SAFETY: `clip` is a live RECT we own.
    match unsafe { GetClipCursor(&mut clip) } {
        Ok(()) => seen.clip = Some(rect(clip)),
        Err(error) => seen.clip_error = Some(error.to_string()),
    }
    seen.foreground = foreground();
    let mut gui = GUITHREADINFO {
        cbSize: size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `gui` is a live GUITHREADINFO with `cbSize` set; thread 0 is the foreground thread.
    match unsafe { GetGUIThreadInfo(0, &mut gui) } {
        Ok(()) => seen.capture = Some(gui.hwndCapture.0 as usize),
        Err(error) => seen.gui_error = Some(error.to_string()),
    }
    seen
}

pub(super) fn cursor_pos() -> std::result::Result<Pt, String> {
    let mut p = POINT::default();
    // SAFETY: `p` is a live POINT we own.
    match unsafe { GetCursorPos(&mut p) } {
        Ok(()) => Ok([p.x, p.y]),
        Err(error) => Err(error.to_string()),
    }
}

fn cursor_info() -> std::result::Result<CURSORINFO, String> {
    let mut info = CURSORINFO {
        cbSize: size_of::<CURSORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a live CURSORINFO with `cbSize` set, as the API requires.
    match unsafe { GetCursorInfo(&mut info) } {
        Ok(()) => Ok(info),
        Err(error) => Err(error.to_string()),
    }
}

pub(super) fn foreground() -> usize {
    // SAFETY: plain call.
    unsafe { GetForegroundWindow() }.0 as usize
}

/// The process owning a window; 0 when the window is gone.
pub(super) fn window_pid(hwnd: usize) -> u32 {
    let mut pid = 0;
    // SAFETY: any window handle may be asked about; a stale one answers 0.
    let thread = unsafe { GetWindowThreadProcessId(HWND(hwnd as *mut c_void), Some(&mut pid)) };
    if thread == 0 {
        0
    } else {
        pid
    }
}

pub(super) fn rect(r: RECT) -> [i32; 4] {
    [r.left, r.top, r.right, r.bottom]
}

fn result_text(result: &windows::core::Result<()>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => error.to_string(),
    }
}

/// µs from `from` to `at`, negative when `at` came first.
pub(super) fn us_between(from: Instant, at: Instant) -> i64 {
    if at >= from {
        at.duration_since(from).as_micros() as i64
    } else {
        -(from.duration_since(at).as_micros() as i64)
    }
}

fn ms(us: i64) -> f64 {
    us as f64 / 1000.0
}

pub(super) fn local_time() -> String {
    // SAFETY: returns a value; no pointers.
    let t = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    )
}

fn sub(a: Option<Pt>, b: Option<Pt>) -> Option<Pt> {
    Some([a?[0] - b?[0], a?[1] - b?[1]])
}

fn distance2(a: Pt, b: Pt) -> i64 {
    let (dx, dy) = (i64::from(a[0] - b[0]), i64::from(a[1] - b[1]));
    dx * dx + dy * dy
}

/// One move's numbers, from its record and its samples (the `before` look first).
fn summarize(record: &MoveRecord, samples: &[Sample]) -> MoveSummary {
    let last = samples.last();
    let final_pos = last.and_then(|s| s.seen.pos);
    let start = record.start;
    let after = || samples.iter().filter(|s| s.t_us >= 0);
    let first_change_ms = after()
        .find(|s| s.seen.pos.is_some() && s.seen.pos != start)
        .map(|s| ms(s.t_us));
    let settle_ms = final_pos.and_then(|f| {
        let i = samples.iter().rposition(|s| s.seen.pos != Some(f))?;
        samples.get(i + 1).map(|s| ms(s.t_us))
    });
    let changes = samples
        .windows(2)
        .filter(|w| w[1].t_us >= record.last_call_start_us && w[1].seen.pos != w[0].seen.pos)
        .count();
    let displacement = sub(final_pos, start);
    let intended = sub(record.expected, start);
    let gain = |axis: usize| {
        let (d, i) = (displacement?[axis], intended?[axis]);
        (i != 0).then(|| f64::from(d) / f64::from(i))
    };
    let injection_ok = !record.calls.is_empty() && record.calls.iter().all(|c| c.ok);
    let returned_toward_start = match (final_pos, start, record.expected) {
        (Some(f), Some(s), Some(e)) if s != e => distance2(f, s) < distance2(f, e),
        _ => false,
    };
    MoveSummary {
        method: record.method,
        mv: record.mv,
        start,
        expected: record.expected,
        final_pos,
        final_at_ms: last.map(|s| ms(s.t_us)),
        error: sub(final_pos, record.expected),
        displacement,
        intended,
        gain_x: gain(0),
        gain_y: gain(1),
        first_change_ms,
        settle_ms,
        changes_after_last_injection: changes,
        moved_again: changes >= 2,
        returned_toward_start,
        showing_final: last.and_then(|s| s.seen.showing),
        hidden_seen: after().any(|s| s.seen.showing == Some(false)),
        shapes_seen: after()
            .filter_map(|s| s.seen.shape)
            .collect::<BTreeSet<_>>()
            .len(),
        clip_final: last.and_then(|s| s.seen.clip),
        capture_final: last.and_then(|s| s.seen.capture),
        injection_ok,
        no_movement: injection_ok && first_change_ms.is_none(),
        injection_us: record.calls.iter().map(|c| c.duration_us).sum(),
        raw: None,
    }
}

/// What the raw-input sink heard from `from_us` to `to_us` (µs since the run began).
fn raw_summary(events: &[RawEvent], epoch: Instant, from_us: i64, to_us: i64) -> RawSummary {
    let mut s = RawSummary::default();
    let mut devices = BTreeSet::new();
    for e in events {
        let t = us_between(epoch, e.at);
        if t < from_us || t > to_us {
            continue;
        }
        s.events += 1;
        if e.flags & MOUSE_MOVE_ABSOLUTE.0 != 0 {
            s.absolute_events += 1;
            s.last_absolute = Some([e.x, e.y]);
        } else {
            s.relative_events += 1;
            s.sum_x += i64::from(e.x);
            s.sum_y += i64::from(e.y);
        }
        s.virtual_desktop |= e.flags & MOUSE_VIRTUAL_DESKTOP.0 != 0;
        if e.buttons != 0 {
            s.button_events += 1;
        }
        devices.insert(e.device);
    }
    s.devices = devices.into_iter().map(|d| format!("{d:#x}")).collect();
    s
}

/// One line of the table: ten fixed columns, the raw-input column, then the method's status (last:
/// a refusal's text is long).
fn table_row(cells: [&str; 10], raw: &str, status: &str) -> String {
    format!(
        "{:<13} {:>2} {:>11} {:>11} {:>9} {:>11} {:>7} {:>7} {:>4} {:>6} {raw:<40} {status}",
        cells[0],
        cells[1],
        cells[2],
        cells[3],
        cells[4],
        cells[5],
        cells[6],
        cells[7],
        cells[8],
        cells[9]
    )
}

/// The table: a row per move, in method order, each with its method's status; a method with no
/// move (skipped, not run, stopped at its reset) gets one row of dashes.
fn print_table(methods: &[MethodRecord], summary: &[MoveSummary]) {
    println!();
    println!(
        "{}",
        table_row(
            [
                "method", "mv", "expected", "final", "error", "gain x/y", "first", "settle",
                "warp", "shown"
            ],
            "raw (events: rel Σx,Σy | abs last | devices)",
            "status"
        )
    );
    for method in methods {
        let rows: Vec<&MoveSummary> = summary
            .iter()
            .filter(|s| s.method == method.method)
            .collect();
        if rows.is_empty() {
            let mut cells = ["-"; 10];
            cells[0] = method.method;
            println!("{}", table_row(cells, "-", &method.status));
        }
        for s in rows {
            print_row(s, &method.status);
        }
    }
    println!(
        "(first/settle: ms after the move's first injection; warp: moved again after the \
         injection took effect; shown yes*: hidden at some point)"
    );
    println!();
}

fn print_row(s: &MoveSummary, status: &str) {
    let pt = |p: Option<Pt>| p.map_or("-".to_owned(), |p| format!("{},{}", p[0], p[1]));
    let num = |v: Option<f64>, digits: usize| v.map_or("-".to_owned(), |v| format!("{v:.digits$}"));
    let yes = |b: bool| if b { "yes" } else { "no" };
    let shown = match (s.showing_final, s.hidden_seen) {
        (Some(true), false) => "yes",
        (Some(true), true) => "yes*",
        (Some(false), _) => "no",
        (None, _) => "-",
    };
    let raw = s.raw.as_ref().map_or("-".to_owned(), |r| {
        format!(
            "{}: {} {},{} | {} {} | {}{}",
            r.events,
            r.relative_events,
            r.sum_x,
            r.sum_y,
            r.absolute_events,
            pt(r.last_absolute),
            r.devices.join(" "),
            if r.virtual_desktop { " vdesk" } else { "" }
        )
    });
    let mv = s.mv.to_string();
    let gain = format!("{}/{}", num(s.gain_x, 2), num(s.gain_y, 2));
    let cells = [
        s.method.to_owned(),
        mv,
        pt(s.expected),
        pt(s.final_pos),
        pt(s.error),
        gain,
        num(s.first_change_ms, 1),
        num(s.settle_ms, 1),
        yes(s.moved_again).to_owned(),
        shown.to_owned(),
    ];
    let status = if s.injection_ok {
        status.to_owned()
    } else {
        // The move whose call was refused (or failed).
        format!("{status} [this move's call failed]")
    };
    println!(
        "{}",
        table_row(cells.each_ref().map(String::as_str), &raw, &status)
    );
}

/// The run's fixed parameters and what the summary's fields mean, for whoever reads the JSON.
fn config() -> Value {
    json!({
        "methods": METHODS.map(Method::name),
        "moves": MOVES,
        "margin_px": MARGIN,
        "reset_settle_ms": RESET_SETTLE.as_millis() as u64,
        "window_after_last_injection_ms": WINDOW.as_millis() as u64,
        "tick_ms": TICK.as_millis() as u64,
        "marks_ms": MARKS_MS,
        "relative_steps": REL_CHUNKS,
        "relative_step_gap_ms": REL_CHUNK_GAP.as_millis() as u64,
        "relative_pacing": "each relative move goes out as 10 steps of 15 counts (exact_rel: of \
            15 px), one every 16 ms: the Mini App sends one coalesced `r` per animation frame and \
            the agent makes each one SendInput call (imp::relative_input, with its sub-pixel carry) \
            or one HID report (State::relative; exact_rel: the counts cursor_sync plans, \
            State::movement)",
        "absolute_mapping": "SendInput: the target pixel as a fraction of SM_CXSCREEN x \
            SM_CYSCREEN (the primary monitor), as `m` carries it, imp::absolute_input \
            (round(f x 65535), MOUSEEVENTF_ABSOLUTE, no MOUSEEVENTF_VIRTUALDESK); HID report 4: \
            State::absolute, the agent's point move: the pixel's centre, \
            round((px + 0.5) x 32768 / width), buttons and wheel 0",
        "exact_rel": "the production cursor-sync planner (crate::cursor_sync) on this PC's cursor \
            and settings: each 15 px step an `r` without a target; a visible cursor moves by \
            exactly the step (display scale and acceleration taken out, closed on GetCursorPos); \
            its learned gain is cursor.exact_rel_gain",
        "run_budget_s": RUN_BUDGET.as_secs(),
        "samples_kept": "a sample is kept when anything it saw changed, and at the marks",
        "refusals": "a refused or failed SetCursorPos / SendInput is recorded on its move (the \
            call's answer, and GetLastError cleared before the call and read right after it) and \
            the rest of that method is skipped; the cursor is put on the anchor before each method, \
            and back at the end, by SetCursorPos or, when that is refused, by HID report 4 \
            (`placement.way`); the run stops only when the foreground leaves the target, the budget \
            runs out, a HID write fails, the cursor position is unknown, or a point would be closer \
            than the margin to an edge",
        "summary_fields": {
            "no_movement": "every call was accepted, yet the position never changed",
            "first_change_ms": "the first sample after the injection began whose position differs from the start",
            "settle_ms": "when the position took its final value for good",
            "changes_after_last_injection": "position changes from the last injection's start on (one is its own effect)",
            "moved_again": "two or more of those: the cursor moved again after the injection took effect",
            "gain_x/gain_y": "(final - start) / (expected - start) per axis",
            "raw": "raw-input mouse events heard during the move: relative sums, absolute events (0..65535), hDevice (0x0 = SendInput)",
        },
    })
}

/// DPI awareness (first: every coordinate after it is in physical pixels), the screens, the mouse
/// settings, this process's integrity, and AFKLink processes that could move the cursor meanwhile.
fn environment(notes: &mut Vec<String>) -> Value {
    // What this test process sees before it is made DPI-aware — what a DPI-unaware agent would.
    let awareness_before = thread_awareness();
    let unaware = json!({
        "awareness": awareness_before,
        "screen": [metric(SM_CXSCREEN), metric(SM_CYSCREEN)],
        "cursor_pos": cursor_pos().ok(),
        "cursor_info_pos": cursor_info().ok().map(|i| [i.ptScreenPos.x, i.ptScreenPos.y]),
    });
    // SAFETY: plain call with a predefined context.
    let set = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    println!(
        "mouse_probe: SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2): {}",
        result_text(&set)
    );
    let mut thread_set = Value::Null;
    if thread_awareness().0 != DPI_AWARENESS_PER_MONITOR_AWARE.0 {
        // The test thread did not follow the process default: set it for this thread too.
        // SAFETY: plain call with a predefined context.
        let previous =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        let text = if previous.0.is_null() {
            format!("failed: {}", std::io::Error::last_os_error())
        } else {
            "ok".to_owned()
        };
        note(
            notes,
            format!(
                "the test thread was not per-monitor aware; SetThreadDpiAwarenessContext: {text}"
            ),
        );
        thread_set = json!(text);
    }
    let awareness = thread_awareness();
    if awareness.0 != DPI_AWARENESS_PER_MONITOR_AWARE.0 {
        note(
            notes,
            format!(
                "not per-monitor DPI aware ({}): coordinates may be scaled",
                awareness.1
            ),
        );
    }

    let mut speed = 0i32;
    // SAFETY: SPI_GETMOUSESPEED writes one int into `speed`.
    let speed_read = unsafe {
        SystemParametersInfoW(
            SPI_GETMOUSESPEED,
            0,
            Some((&mut speed as *mut i32).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    let mut mouse = [0i32; 3];
    // SAFETY: SPI_GETMOUSE writes three ints into `mouse`.
    let mouse_read = unsafe {
        SystemParametersInfoW(
            SPI_GETMOUSE,
            0,
            Some(mouse.as_mut_ptr().cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    for (what, read) in [
        ("SPI_GETMOUSESPEED", &speed_read),
        ("SPI_GETMOUSE", &mouse_read),
    ] {
        if let Err(error) = read {
            note(notes, format!("{what} failed: {error}"));
        }
    }

    // SAFETY: plain call.
    let own_pid = unsafe { GetCurrentProcessId() };
    let afklink = match processes() {
        Ok(list) => {
            let ours: Vec<Value> = list
                .into_iter()
                .filter(|(pid, name)| {
                    // Not this probe itself, nor any test binary of this crate
                    // (`afklink_input-<hash>.exe`): only an agent could move the cursor meanwhile.
                    let name = name.to_lowercase();
                    *pid != own_pid
                        && name.starts_with("afklink")
                        && !name.starts_with("afklink_input")
                })
                .map(|(pid, name)| json!({ "pid": pid, "exe": name }))
                .collect();
            if !ours.is_empty() {
                note(
                    notes,
                    format!(
                        "AFKLink is running ({}): a live session could move the cursor during the \
                         probe",
                        Value::Array(ours.clone())
                    ),
                );
            }
            json!(ours)
        }
        Err(error) => {
            note(notes, format!("listing processes failed: {error}"));
            json!({ "error": error })
        }
    };

    // SAFETY: plain call.
    let system_dpi = unsafe { GetDpiForSystem() };
    let mut env = json!({
        "dpi_unaware_view": unaware,
        "set_process_dpi_awareness_context": result_text(&set),
        "set_thread_dpi_awareness_context": thread_set,
        "awareness": awareness,
        "screen": [metric(SM_CXSCREEN), metric(SM_CYSCREEN)],
        "virtual_screen": [metric(SM_XVIRTUALSCREEN), metric(SM_YVIRTUALSCREEN), metric(SM_CXVIRTUALSCREEN), metric(SM_CYVIRTUALSCREEN)],
        "monitor_count": metric(SM_CMONITORS),
        "monitors": monitors(notes),
        "system_dpi": system_dpi,
        "mouse_speed": speed_read.is_ok().then_some(speed),
        "mouse_thresholds_and_acceleration": mouse_read.is_ok().then_some(mouse),
        "enhance_pointer_precision": mouse_read.is_ok().then_some(mouse[2] != 0),
        "process": { "pid": own_pid },
        "afklink_processes": afklink,
    });
    // SAFETY: the pseudo handle of this process; it needs no closing.
    let own = token_facts(unsafe { GetCurrentProcess() });
    if let (Value::Object(process), Value::Object(facts)) = (&mut env["process"], own) {
        process.extend(facts);
    }
    println!(
        "mouse_probe: screen {}x{} at {} dpi, pointer speed {:?}, enhance pointer precision {:?}, this process {}",
        env["screen"][0], env["screen"][1], system_dpi, env["mouse_speed"], env["enhance_pointer_precision"], env["process"]
    );
    env
}

/// The calling thread's DPI awareness: the value (-1 invalid, 0 unaware, 1 system, 2 per monitor)
/// and its name.
fn thread_awareness() -> (i32, &'static str) {
    // SAFETY: plain calls; the context is the thread's own.
    let value = unsafe { GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()) }.0;
    let name = match value {
        0 => "unaware",
        1 => "system aware",
        2 => "per-monitor aware",
        _ => "invalid",
    };
    (value, name)
}

fn metric(index: windows::Win32::UI::WindowsAndMessaging::SYSTEM_METRICS_INDEX) -> i32 {
    // SAFETY: plain metric query.
    unsafe { GetSystemMetrics(index) }
}

/// The primary monitor's rectangle; the screen size from the origin if it cannot be read.
pub(super) fn primary_monitor(notes: &mut Vec<String>) -> RECT {
    // SAFETY: plain call.
    let monitor = unsafe { MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY) };
    match monitor_info(monitor) {
        Ok(info) => info.rcMonitor,
        Err(error) => {
            note(
                notes,
                format!("the primary monitor's rectangle is unreadable ({error}); using the screen size"),
            );
            RECT {
                left: 0,
                top: 0,
                right: metric(SM_CXSCREEN),
                bottom: metric(SM_CYSCREEN),
            }
        }
    }
}

fn monitor_info(monitor: HMONITOR) -> std::result::Result<MONITORINFO, String> {
    let mut info = MONITORINFO {
        cbSize: size_of::<MONITORINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: `info` is a live MONITORINFO with `cbSize` set.
    if unsafe { GetMonitorInfoW(monitor, &mut info) }.as_bool() {
        Ok(info)
    } else {
        Err(format!(
            "GetMonitorInfoW failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

unsafe extern "system" fn collect_monitor(
    monitor: HMONITOR,
    _: HDC,
    _: *mut RECT,
    data: LPARAM,
) -> BOOL {
    // SAFETY: `data` is the `&mut Vec<HMONITOR>` `monitors` passed, alive for the enumeration.
    let list = unsafe { &mut *(data.0 as *mut Vec<HMONITOR>) };
    list.push(monitor);
    BOOL(1)
}

fn monitors(notes: &mut Vec<String>) -> Value {
    let mut list: Vec<HMONITOR> = Vec::new();
    // SAFETY: the callback only pushes into `list`, which outlives this synchronous call.
    let enumerated = unsafe {
        EnumDisplayMonitors(
            None,
            None,
            Some(collect_monitor),
            LPARAM(&mut list as *mut Vec<HMONITOR> as isize),
        )
    };
    if !enumerated.as_bool() {
        note(
            notes,
            format!(
                "EnumDisplayMonitors failed: {}",
                std::io::Error::last_os_error()
            ),
        );
    }
    let dpi = |monitor: HMONITOR, kind: MONITOR_DPI_TYPE| {
        let (mut x, mut y) = (0, 0);
        // SAFETY: two live u32 outputs.
        match unsafe { GetDpiForMonitor(monitor, kind, &mut x, &mut y) } {
            Ok(()) => json!([x, y]),
            Err(error) => json!({ "error": error.to_string() }),
        }
    };
    list.into_iter()
        .map(|monitor| match monitor_info(monitor) {
            Ok(info) => json!({
                "rect": rect(info.rcMonitor),
                "work": rect(info.rcWork),
                "primary": info.dwFlags & MONITORINFOF_PRIMARY != 0,
                "dpi_effective": dpi(monitor, MDT_EFFECTIVE_DPI),
                "dpi_raw": dpi(monitor, MDT_RAW_DPI),
            }),
            Err(error) => json!({ "error": error }),
        })
        .collect()
}

/// A process's exe: the full path when the process opens for a limited query, else only the file
/// name from a process snapshot (a protected or anti-cheat-guarded game may refuse the open).
#[derive(Clone, Debug, Serialize)]
pub(super) struct Exe {
    path: Option<String>,
    pub(super) name: Option<String>,
    source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
}

impl Exe {
    fn matches(&self, target: &str) -> bool {
        self.name
            .as_deref()
            .is_some_and(|name| name.to_lowercase().contains(target))
    }

    pub(super) fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| "<unknown exe>".to_owned())
    }
}

/// A handle this module opened and closes.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: this owns one live kernel handle, never a pseudo handle.
        if let Err(error) = unsafe { CloseHandle(self.0) } {
            println!("mouse_probe: CloseHandle failed: {error}");
        }
    }
}

pub(super) fn process_exe(pid: u32) -> Exe {
    // SAFETY: plain call; the handle is owned below.
    let open_error = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            let handle = Owned(handle);
            let mut buffer = [0u16; 1024];
            let mut len = buffer.len() as u32;
            // SAFETY: `buffer` is live and `len` holds its length in characters.
            match unsafe {
                QueryFullProcessImageNameW(
                    handle.0,
                    PROCESS_NAME_WIN32,
                    PWSTR(buffer.as_mut_ptr()),
                    &mut len,
                )
            } {
                Ok(()) => {
                    let path = String::from_utf16_lossy(&buffer[..len as usize]);
                    let name = path.rsplit(['\\', '/']).next().map(str::to_owned);
                    return Exe {
                        path: Some(path),
                        name,
                        source: "QueryFullProcessImageNameW",
                        error: None,
                    };
                }
                Err(error) => Some(format!("QueryFullProcessImageNameW: {error}")),
            }
        }
        Err(error) => Some(format!("OpenProcess: {error}")),
    };
    let (name, snapshot_error) = match processes() {
        Ok(list) => (
            list.into_iter()
                .find(|(p, _)| *p == pid)
                .map(|(_, name)| name),
            None,
        ),
        Err(error) => (None, Some(error)),
    };
    let error = [open_error, snapshot_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join("; ");
    Exe {
        path: None,
        name,
        source: "process snapshot",
        error: (!error.is_empty()).then_some(error),
    }
}

/// Every process's id and exe file name, from a snapshot (no process is opened).
fn processes() -> std::result::Result<Vec<(u32, String)>, String> {
    // SAFETY: plain call; the handle is owned below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot: {e}"))?;
    let snapshot = Owned(snapshot);
    // SAFETY: a plain-data struct; all zeroes is a valid value, `dwSize` is set next.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut list = Vec::new();
    // SAFETY: `entry` is live with `dwSize` set.
    let mut step = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while step.is_ok() {
        list.push((entry.th32ProcessID, wide_text(&entry.szExeFile)));
        // SAFETY: as above.
        step = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    match step {
        // The walk ends with ERROR_NO_MORE_FILES; anything else cut it short.
        Err(error) if error.code() != ERROR_NO_MORE_FILES.to_hresult() => {
            Err(format!("walking the process snapshot: {error}"))
        }
        _ => Ok(list),
    }
}

/// A NUL-terminated UTF-16 buffer as text.
fn wide_text(wide: &[u16]) -> String {
    let len = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..len])
}

/// Elevation and integrity of a process, or why they could not be read.
pub(super) fn process_facts(pid: u32) -> Value {
    // SAFETY: plain call; the handle is owned below.
    match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => {
            let handle = Owned(handle);
            token_facts(handle.0)
        }
        Err(error) => json!({ "error": format!("OpenProcess: {error}") }),
    }
}

fn token_facts(process: HANDLE) -> Value {
    let mut token = HANDLE::default();
    // SAFETY: `token` receives a handle owned below.
    if let Err(error) = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } {
        return json!({ "error": format!("OpenProcessToken: {error}") });
    }
    let token = Owned(token);
    let mut facts = Map::new();
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `elevation` is a live TOKEN_ELEVATION of the size given.
    match unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    } {
        Ok(()) => facts.insert("elevated".into(), json!(elevation.TokenIsElevated != 0)),
        Err(error) => facts.insert("elevation_error".into(), json!(error.to_string())),
    };
    match integrity(token.0) {
        Ok(rid) => {
            facts.insert("integrity".into(), json!(integrity_name(rid)));
            facts.insert("integrity_rid".into(), json!(format!("{rid:#06x}")));
        }
        Err(error) => {
            facts.insert("integrity_error".into(), json!(error));
        }
    }
    Value::Object(facts)
}

/// The token's mandatory-label RID (0x2000 medium, 0x3000 high, …).
fn integrity(token: HANDLE) -> std::result::Result<u32, String> {
    let mut len = 0u32;
    // The size query fails by design (ERROR_INSUFFICIENT_BUFFER) and says how much to allocate; only
    // a failure that says nothing is one.
    // SAFETY: a size query: no buffer, a live length output.
    if let Err(error) =
        unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut len) }
    {
        if len == 0 {
            return Err(format!(
                "GetTokenInformation(TokenIntegrityLevel) size: {error}"
            ));
        }
    }
    let mut buffer = vec![0u64; (len as usize).div_ceil(size_of::<u64>()).max(1)];
    // SAFETY: `buffer` is live, aligned for the label and at least `len` bytes.
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .map_err(|e| format!("GetTokenInformation(TokenIntegrityLevel): {e}"))?;
    // SAFETY: the call above wrote a TOKEN_MANDATORY_LABEL (and its SID) into `buffer`.
    let sid = unsafe { &*buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() }
        .Label
        .Sid;
    // SAFETY: `sid` points into `buffer`, still alive; these read its header.
    let count = unsafe { GetSidSubAuthorityCount(sid) };
    if count.is_null() {
        return Err("the integrity SID is unreadable".to_owned());
    }
    // SAFETY: non-null, into `buffer`.
    let count = unsafe { *count };
    if count == 0 {
        return Err("the integrity SID has no sub-authority".to_owned());
    }
    // SAFETY: the last sub-authority of the SID in `buffer`.
    let rid = unsafe { GetSidSubAuthority(sid, u32::from(count - 1)) };
    if rid.is_null() {
        return Err("the integrity SID's RID is unreadable".to_owned());
    }
    // SAFETY: non-null, into `buffer`.
    Ok(unsafe { *rid })
}

fn integrity_name(rid: u32) -> &'static str {
    match rid {
        0x0000..=0x0fff => "untrusted",
        0x1000..=0x1fff => "low",
        0x2000..=0x20ff => "medium",
        0x2100..=0x2fff => "medium plus",
        0x3000..=0x3fff => "high",
        0x4000..=0x4fff => "system",
        _ => "protected",
    }
}

/// Wait (up to [`WAIT_FOR_TARGET`]) for a foreground window whose process's exe name contains
/// `target`; its window, pid and exe.
fn wait_for_target(target: &str) -> Result<(usize, u32, Exe)> {
    println!(
        "mouse_probe: waiting up to {} s for a foreground window whose exe name contains \"{target}\" \
         — focus it now. Switching away during the run aborts it.",
        WAIT_FOR_TARGET.as_secs()
    );
    let begun = Instant::now();
    let mut printed = begun;
    let mut cached: Option<(u32, Exe)> = None;
    loop {
        let hwnd = foreground();
        let pid = window_pid(hwnd);
        let exe = match &cached {
            Some((p, exe)) if *p == pid => exe.clone(),
            _ => {
                let exe = process_exe(pid);
                cached = Some((pid, exe.clone()));
                exe
            }
        };
        if hwnd != 0 && exe.matches(target) {
            return Ok((hwnd, pid, exe));
        }
        if begun.elapsed() >= WAIT_FOR_TARGET {
            bail!(
                "no foreground window of \"{target}\" within {} s (the last one: {} pid {pid}); \
                 nothing was moved",
                WAIT_FOR_TARGET.as_secs(),
                exe.label()
            );
        }
        if printed.elapsed() >= WAIT_PRINT_EVERY {
            printed = Instant::now();
            println!(
                "mouse_probe: still waiting ({} s left); in the foreground: {} (pid {pid}{})",
                WAIT_FOR_TARGET.saturating_sub(begun.elapsed()).as_secs(),
                exe.label(),
                exe.error
                    .as_deref()
                    .map_or(String::new(), |e| format!("; {e}"))
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The target window: title, class, process, rectangles in screen pixels, whether it covers its
/// monitor, its styles.
fn window_info(hwnd: usize, pid: u32, exe: &Exe, process: Value) -> Value {
    let h = HWND(hwnd as *mut c_void);
    let mut title = [0u16; 512];
    // SAFETY: a live buffer; the call writes at most its length.
    let n = unsafe { GetWindowTextW(h, &mut title) };
    let mut class = [0u16; 256];
    // SAFETY: as above.
    let c = unsafe { GetClassNameW(h, &mut class) };
    // SAFETY: plain call.
    let thread = unsafe { GetWindowThreadProcessId(h, None) };
    let mut window = RECT::default();
    // SAFETY: a live RECT.
    let window_read = unsafe { GetWindowRect(h, &mut window) };
    let mut client = RECT::default();
    // SAFETY: a live RECT.
    let client_read = unsafe { GetClientRect(h, &mut client) };
    let client_screen = client_read.as_ref().ok().and_then(|_| {
        let mut top_left = POINT {
            x: client.left,
            y: client.top,
        };
        let mut bottom_right = POINT {
            x: client.right,
            y: client.bottom,
        };
        // SAFETY: live POINTs.
        let ok = unsafe { ClientToScreen(h, &mut top_left).as_bool() }
            && unsafe { ClientToScreen(h, &mut bottom_right).as_bool() };
        ok.then_some(RECT {
            left: top_left.x,
            top: top_left.y,
            right: bottom_right.x,
            bottom: bottom_right.y,
        })
    });
    // SAFETY: plain call.
    let monitor = monitor_info(unsafe { MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST) });
    let covers = |r: RECT, m: RECT| {
        r.left <= m.left && r.top <= m.top && r.right >= m.right && r.bottom >= m.bottom
    };
    // SAFETY: plain calls; 0 is a possible answer and is recorded as such.
    let (style, ex_style) =
        unsafe { (GetWindowLongW(h, GWL_STYLE), GetWindowLongW(h, GWL_EXSTYLE)) };
    json!({
        "hwnd": format!("{hwnd:#x}"),
        "title": String::from_utf16_lossy(&title[..n.max(0) as usize]),
        "class": String::from_utf16_lossy(&class[..c.max(0) as usize]),
        "pid": pid,
        "thread": thread,
        "exe": exe,
        "process": process,
        "window_rect": window_read.as_ref().ok().map(|_| rect(window)),
        "window_rect_error": window_read.as_ref().err().map(ToString::to_string),
        "client_rect_screen": client_screen.map(rect),
        "client_rect_error": client_read.as_ref().err().map(ToString::to_string),
        "monitor": monitor.as_ref().ok().map(|m| rect(m.rcMonitor)),
        "monitor_error": monitor.as_ref().err(),
        "window_covers_monitor": monitor.as_ref().ok().filter(|_| window_read.is_ok()).map(|m| covers(window, m.rcMonitor)),
        "client_covers_monitor": monitor.as_ref().ok().zip(client_screen).map(|(m, c)| covers(c, m.rcMonitor)),
        "style": format!("{:#010x}", style as u32),
        "ex_style": format!("{:#010x}", ex_style as u32),
    })
}

/// A raw-input sink for the mouse: a message-only window on its own thread, registered for Generic
/// Desktop / Mouse with `RIDEV_INPUTSINK` so it hears every mouse event whoever has the focus — what
/// a game reading raw input would see of each method, in the order Windows processed them.
pub(super) struct RawSink {
    thread_id: u32,
    handle: Option<std::thread::JoinHandle<Vec<String>>>,
    events: Arc<Mutex<Vec<RawEvent>>>,
}

impl RawSink {
    /// Start the sink, or say why it could not start (the probe goes on without it).
    pub(super) fn start() -> std::result::Result<Self, String> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel();
        let sink_events = Arc::clone(&events);
        let handle = std::thread::Builder::new()
            .name("mouse-probe-raw-input".into())
            .spawn(move || raw_input_thread(&sink_events, &ready_tx))
            .map_err(|e| format!("the raw-input thread did not start: {e}"))?;
        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(thread_id)) => Ok(Self {
                thread_id,
                handle: Some(handle),
                events,
            }),
            Ok(Err(error)) => {
                // The thread has cleaned up and is returning.
                let more = match handle.join() {
                    Ok(errors) => errors,
                    Err(_) => vec!["the raw-input thread panicked".to_owned()],
                };
                Err([vec![error], more].concat().join("; "))
            }
            // It may be stuck in a call: leave it (detached) rather than wait on it.
            Err(error) => Err(format!(
                "the raw-input thread did not report ready: {error}"
            )),
        }
    }

    /// Stop the thread (it unregisters and destroys its window) and hand over what it heard, with
    /// any error from reading or stopping.
    pub(super) fn stop(mut self) -> (Vec<RawEvent>, Vec<String>) {
        let errors = self.shutdown();
        let events = std::mem::take(&mut *lock(&self.events));
        (events, errors)
    }

    fn shutdown(&mut self) -> Vec<String> {
        let Some(handle) = self.handle.take() else {
            return Vec::new();
        };
        // SAFETY: a plain thread message to the sink's thread, which has a queue (it has a window).
        if let Err(error) =
            unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) }
        {
            // Joining would wait for a quit that never comes: leave the thread to the process's end.
            return vec![format!(
                "stopping the raw-input thread failed ({error}); it runs until the test exits"
            )];
        }
        match handle.join() {
            Ok(errors) => errors,
            Err(_) => vec!["the raw-input thread panicked".to_owned()],
        }
    }
}

impl Drop for RawSink {
    fn drop(&mut self) {
        for error in self.shutdown() {
            println!("mouse_probe: raw input: {error}");
        }
    }
}

unsafe extern "system" fn raw_window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // SAFETY: forwarding the window's own message; for WM_INPUT this is the cleanup Windows asks for.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

/// The sink's thread: window, registration, message loop, cleanup. Tells `ready` its thread id once
/// it listens (or why it cannot), and returns the errors it met.
fn raw_input_thread(
    events: &Mutex<Vec<RawEvent>>,
    ready: &mpsc::Sender<std::result::Result<u32, String>>,
) -> Vec<String> {
    let mut errors = Vec::new();
    // If the probe stopped waiting, the error it reports says so; nothing more to tell it.
    let tell = |answer: std::result::Result<u32, String>, errors: &mut Vec<String>| {
        if ready.send(answer).is_err() {
            errors.push("the probe stopped waiting for the raw-input thread".to_owned());
        }
    };
    // SAFETY: plain call.
    let thread_id = unsafe { GetCurrentThreadId() };
    let class: Vec<u16> = "AfkLinkMouseProbeRawInput\0".encode_utf16().collect();
    // SAFETY: the null name asks for this executable's module.
    let instance = match unsafe { GetModuleHandleW(PCWSTR::null()) } {
        Ok(module) => HINSTANCE(module.0),
        Err(error) => {
            tell(Err(format!("GetModuleHandleW: {error}")), &mut errors);
            return errors;
        }
    };
    let window_class = WNDCLASSW {
        lpfnWndProc: Some(raw_window_proc),
        hInstance: instance,
        lpszClassName: PCWSTR(class.as_ptr()),
        ..Default::default()
    };
    // SAFETY: `window_class` and the name it points to are live for the call.
    if unsafe { RegisterClassW(&window_class) } == 0 {
        let error = std::io::Error::last_os_error();
        tell(Err(format!("RegisterClassW: {error}")), &mut errors);
        return errors;
    }
    // SAFETY: the class was registered above; a message-only window (parent HWND_MESSAGE).
    let hwnd = match unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class.as_ptr()),
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance),
            None,
        )
    } {
        Ok(hwnd) => hwnd,
        Err(error) => {
            unregister_class(&class, instance, &mut errors);
            tell(Err(format!("CreateWindowExW: {error}")), &mut errors);
            return errors;
        }
    };
    let device = RAWINPUTDEVICE {
        usUsagePage: 1,
        usUsage: 2,
        dwFlags: RIDEV_INPUTSINK,
        hwndTarget: hwnd,
    };
    // SAFETY: one live RAWINPUTDEVICE and its size.
    if let Err(error) =
        unsafe { RegisterRawInputDevices(&[device], size_of::<RAWINPUTDEVICE>() as u32) }
    {
        destroy_window(hwnd, &class, instance, &mut errors);
        tell(
            Err(format!("RegisterRawInputDevices: {error}")),
            &mut errors,
        );
        return errors;
    }
    tell(Ok(thread_id), &mut errors);

    let mut read_errors = 0usize;
    let mut message = MSG::default();
    loop {
        // SAFETY: `message` is a live MSG; any window of this thread.
        let got = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if got.0 == 0 {
            break; // WM_QUIT
        }
        if got.0 == -1 {
            errors.push(format!(
                "GetMessageW failed: {}",
                std::io::Error::last_os_error()
            ));
            break;
        }
        if message.message == WM_INPUT {
            let pt = [message.pt.x, message.pt.y];
            match read_raw_mouse(message.lParam, Instant::now(), pt) {
                Ok(Some(event)) => lock(events).push(event),
                Ok(None) => {}
                Err(error) => {
                    read_errors += 1;
                    if read_errors <= RAW_ERRORS_KEPT {
                        errors.push(error);
                    }
                }
            }
        }
        // SAFETY: a message this thread retrieved; for WM_INPUT, DefWindowProc cleans up after it.
        unsafe { DispatchMessageW(&message) };
    }
    if read_errors > RAW_ERRORS_KEPT {
        errors.push(format!(
            "{} more raw-input read failures",
            read_errors - RAW_ERRORS_KEPT
        ));
    }

    let remove = RAWINPUTDEVICE {
        usUsagePage: 1,
        usUsage: 2,
        dwFlags: RIDEV_REMOVE,
        hwndTarget: HWND::default(),
    };
    // SAFETY: one live RAWINPUTDEVICE and its size.
    if let Err(error) =
        unsafe { RegisterRawInputDevices(&[remove], size_of::<RAWINPUTDEVICE>() as u32) }
    {
        errors.push(format!("unregistering raw input failed: {error}"));
    }
    destroy_window(hwnd, &class, instance, &mut errors);
    errors
}

fn destroy_window(hwnd: HWND, class: &[u16], instance: HINSTANCE, errors: &mut Vec<String>) {
    // SAFETY: this thread's own window.
    if let Err(error) = unsafe { DestroyWindow(hwnd) } {
        errors.push(format!("DestroyWindow: {error}"));
    }
    unregister_class(class, instance, errors);
}

fn unregister_class(class: &[u16], instance: HINSTANCE, errors: &mut Vec<String>) {
    // SAFETY: the NUL-terminated name registered by this thread.
    if let Err(error) = unsafe { UnregisterClassW(PCWSTR(class.as_ptr()), Some(instance)) } {
        errors.push(format!("UnregisterClassW: {error}"));
    }
}

/// One WM_INPUT's mouse event (`pt`: the message's cursor position); `None` for another device type.
fn read_raw_mouse(
    lparam: LPARAM,
    at: Instant,
    pt: Pt,
) -> std::result::Result<Option<RawEvent>, String> {
    let mut raw = RAWINPUT::default();
    let mut size = size_of::<RAWINPUT>() as u32;
    // SAFETY: `raw` is a live RAWINPUT of `size` bytes (a mouse's fits); the handle is WM_INPUT's.
    let copied = unsafe {
        GetRawInputData(
            HRAWINPUT(lparam.0 as *mut c_void),
            RID_INPUT,
            Some((&mut raw as *mut RAWINPUT).cast()),
            &mut size,
            size_of::<RAWINPUTHEADER>() as u32,
        )
    };
    if copied == u32::MAX {
        return Err(format!(
            "GetRawInputData failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if raw.header.dwType != RIM_TYPEMOUSE.0 {
        return Ok(None);
    }
    // SAFETY: a mouse event (the header says so), so the union holds a RAWMOUSE.
    let mouse = unsafe { raw.data.mouse };
    Ok(Some(RawEvent {
        at,
        flags: mouse.usFlags.0,
        x: mouse.lLastX,
        y: mouse.lLastY,
        // SAFETY: the button fields of the RAWMOUSE read above.
        buttons: unsafe { mouse.Anonymous.Anonymous.usButtonFlags },
        device: raw.header.hDevice.0 as usize,
        extra: mouse.ulExtraInformation,
        pt,
    }))
}

// The pure parts, checked without moving anything.

fn test_sample(t_us: i64, pos: Pt) -> Sample {
    Sample {
        method: "sendinput_abs",
        mv: 1,
        t_us,
        mark: None,
        seen: Observed {
            pos: Some(pos),
            showing: Some(true),
            ..Default::default()
        },
    }
}

fn test_record(start: Pt, expected: Pt) -> MoveRecord {
    MoveRecord {
        method: "sendinput_abs",
        mv: 1,
        run_start_us: 0,
        run_end_us: 0,
        start: Some(start),
        target: Some(expected),
        counts: None,
        expected: Some(expected),
        calls: Vec::new(),
        last_call_start_us: 0,
        last_call_end_us: 10,
        samples: 0..0,
    }
}

#[test]
fn the_anchor_keeps_every_target_off_the_edges() -> Result<()> {
    let primary = RECT {
        left: 0,
        top: 0,
        right: 3600,
        bottom: 2400,
    };
    for cursor in [
        [0, 0],
        [3599, 2399],
        [1800, 1200],
        [-500, 5000],
        [3300, 100],
    ] {
        let (anchor, moved) =
            anchor_for(cursor, primary).ok_or_else(|| anyhow!("no anchor for {cursor:?}"))?;
        assert_eq!(moved, anchor != cursor);
        let mut offset = [0, 0];
        assert!(inside_margin(anchor, primary), "{anchor:?}");
        for (dx, dy) in MOVES {
            offset = [offset[0] + dx, offset[1] + dy];
            let target = [anchor[0] + offset[0], anchor[1] + offset[1]];
            assert!(inside_margin(target, primary), "{cursor:?} -> {target:?}");
        }
        assert_eq!(offset, [0, 0], "the moves end where they began");
    }
    assert_eq!(
        anchor_for([1800, 1200], primary),
        Some(([1800, 1200], false))
    );
    let small = RECT {
        left: 0,
        top: 0,
        right: 900,
        bottom: 900,
    };
    assert_eq!(anchor_for([450, 450], small), None);
    Ok(())
}

#[test]
fn relative_moves_go_as_frame_sized_steps_that_add_up() {
    for (dx, dy) in MOVES.into_iter().chain([(7, -13)]) {
        let steps = rel_chunks((dx, dy));
        assert_eq!(steps.len(), REL_CHUNKS as usize);
        let sum = steps.iter().fold([0, 0], |a, s| [a[0] + s[0], a[1] + s[1]]);
        assert_eq!(sum, [dx, dy]);
    }
    assert_eq!(rel_chunks((150, 0))[0], [15, 0]);
}

/// The probe aims the absolute report as the agent does: at the pixel's centre on this PC's primary
/// monitor (the probe's 2188 → 19915 → 2187 was the old, edge-aimed mapping).
#[test]
fn the_probe_aims_the_absolute_report_as_the_agent_does() {
    assert!(Method::ExactRel.relative() && Method::ExactRel.hid() && Method::ExactRel.in_pixels());
    assert!(!Method::HidRel.in_pixels());
    let (w, h) = platform::screen_size();
    if w <= 0 || h <= 0 {
        // No display in this session: nothing to aim at.
        return;
    }
    let primary = RECT {
        left: 0,
        top: 0,
        right: w,
        bottom: h,
    };
    for p in [[0, 0], [w / 3, h / 2], [w - 1, h - 1]] {
        let (x, y) = absolute_wire(p[0], p[1], w, h);
        assert_eq!(hid_wire(p, primary), [i32::from(x), i32::from(y)]);
        assert_eq!(i64::from(x) * i64::from(w) / 32768, i64::from(p[0]));
        assert_eq!(i64::from(y) * i64::from(h) / 32768, i64::from(p[1]));
    }
}

#[test]
fn a_summary_tells_a_clean_move_from_a_warp_back() {
    // A clean move: one change, at 2 ms, to the target.
    let record = test_record([1000, 1000], [1150, 1000]);
    let clean = [
        test_sample(-20, [1000, 1000]),
        test_sample(2_000, [1150, 1000]),
        test_sample(500_000, [1150, 1000]),
    ];
    let s = summarize(&record, &clean);
    assert_eq!(s.final_pos, Some([1150, 1000]));
    assert_eq!(s.error, Some([0, 0]));
    assert_eq!(s.gain_x, Some(1.0));
    assert_eq!(s.gain_y, None);
    assert_eq!(s.first_change_ms, Some(2.0));
    assert_eq!(s.settle_ms, Some(2.0));
    assert_eq!(s.changes_after_last_injection, 1);
    assert!(!s.moved_again && !s.returned_toward_start && !s.hidden_seen);

    // The application puts the cursor back 30 ms later.
    let warped = [
        test_sample(-20, [1000, 1000]),
        test_sample(2_000, [1150, 1000]),
        test_sample(30_000, [1000, 1000]),
        test_sample(500_000, [1000, 1000]),
    ];
    let s = summarize(&record, &warped);
    assert_eq!(s.first_change_ms, Some(2.0));
    assert_eq!(s.settle_ms, Some(30.0));
    assert_eq!(s.gain_x, Some(0.0));
    assert!(s.moved_again && s.returned_toward_start);

    // Nothing moved at all.
    let still = [
        test_sample(-20, [1000, 1000]),
        test_sample(500_000, [1000, 1000]),
    ];
    let s = summarize(&record, &still);
    assert_eq!((s.first_change_ms, s.settle_ms), (None, None));
    assert_eq!(s.changes_after_last_injection, 0);
    assert!(!s.no_movement, "no call was made, so none was accepted");

    // The call was accepted (SendInput answered 1) and still nothing moved.
    let mut accepted = test_record([1000, 1000], [1150, 1000]);
    accepted.calls.push(Call {
        t_us: 0,
        call: Method::SendInputAbs.call(),
        arg: [1150, 1000],
        wire: Some([2730, 2730]),
        ok: true,
        result: "sent 1/1".to_owned(),
        last_error: Some(0),
        duration_us: 5,
    });
    let s = summarize(&accepted, &still);
    assert!(s.injection_ok && s.no_movement);
    assert!(!summarize(&accepted, &clean).no_movement);
}
