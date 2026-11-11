//! Focus: can this unelevated process bring the elevated game's window back to the foreground when
//! something else has taken it? In the "game window only" mode the agent restores the game's focus
//! by itself. The expectation is that the system refuses a background medium-integrity process and
//! flashes the game's taskbar button instead; this probe tries the ordinary window APIs one by one,
//! each from the same starting point, and records what each did: the game in front, the game raised
//! without the focus, its taskbar button flashing, or nothing.
//!
//! ## Run it
//!
//! From `agent\`, in an **unelevated** terminal (the agent runs unelevated; an elevated probe refuses
//! to run, since it would pass checks the agent does not), with the game running and Notepad open:
//!
//! ```text
//! cargo test -p afklink-capture --release --lib focus_probe -- --ignored --nocapture
//! ```
//!
//! - `AFK_PROBE_WINDOW_CLASS`: the game window's class, compared whole and case-insensitively;
//!   default `ScrydeGameUnrealWWindowsViewportWindow` (Lineage 2 on Scryde, `ScrydeGame.bin`).
//! - `AFK_PROBE_OUT`: where the JSON goes (default `agent\target\focus-probe-<yyyymmdd-hhmmss>.json`,
//!   local time).
//!
//! ## What the person at the PC does
//!
//! Follow the terminal. (1) Click Notepad so that it is in front of the game. Any window will do
//! except the game's own, this terminal and the programs that started the probe — Explorer and the
//! desktop too, when the terminal was started from them: a process started by the window in front
//! may pass the focus rules, which the agent never is, so the probe waits until such a window is not
//! in front. (2) Hands off the mouse and keyboard: after 2 s with that window in front the probe tries
//! one method and prints what happened. (3) Whenever a method brought the game to the front (or
//! raised it above Notepad), click Notepad again; the probe waits up to 30 s for that, 2 s more, then
//! tries the next. Before (b) the user may minimize the game instead of covering it: (b) then also
//! tests restoring it. The whole run takes about a minute.
//!
//! ## What it does
//!
//! 1. Per-monitor DPI awareness, the OS build, this process's integrity and elevation, its parent
//!    chain (toolhelp, checked against creation times so that a reused pid is not taken for a parent)
//!    and console window, and the foreground rules' settings: `SPI_GETFOREGROUNDLOCKTIMEOUT` (for how
//!    long after the user's last input the system refuses a background process the foreground;
//!    200 000 ms by default, 0 = never) and `SPI_GETFOREGROUNDFLASHCOUNT` (how often the taskbar
//!    button flashes instead). That is method (e): `LockSetForegroundWindow` and
//!    `AllowSetForegroundWindow` are for a process to call about itself, so the probe only records the
//!    setting.
//! 2. A hidden window of its own (a tool window that never activates), registered with
//!    `RegisterShellHookWindow` — a notification from the shell, not a `SetWindowsHookEx` hook, and
//!    nothing is loaded into any process. The shell then tells it about every activation
//!    (`HSHELL_WINDOWACTIVATED`, `HSHELL_RUDEAPPACTIVATED`) and every taskbar flash (`HSHELL_FLASH`,
//!    which is what a refused `SetForegroundWindow` turns into): the only way to see a flash from
//!    outside. Its messages are pumped every 10 ms, and the foreground window is read at the same
//!    rate; every change is logged.
//! 3. The game's window: the visible top-level window of that class (the largest one on screen if
//!    several; it waits up to 60 s for one), and its process's path, integrity and elevation through
//!    one `PROCESS_QUERY_LIMITED_INFORMATION` handle, closed at once.
//! 4. The methods, in order, each once, each from the same state — another window in front for 2 s
//!    and above the game in the z-order, or the game minimized:
//!    - (a) `SetForegroundWindow(game)`;
//!    - (b) `ShowWindow(game, SW_RESTORE)` if the game is minimized, then `SetForegroundWindow(game)`;
//!    - (c) `AttachThreadInput` of this thread to the thread of the window in front (Notepad's, never
//!      the game's), `SetForegroundWindow(game)`, `BringWindowToTop(game)`, then detach;
//!    - (d) `SwitchToThisWindow(game, TRUE)`.
//!
//!    Every call's return value and `GetLastError` (cleared before the call) are recorded. 300 ms
//!    after the first call the probe records the foreground window, whether that is the game, and
//!    whether the game now lies above the window in front (raised without the focus); again at 1 s;
//!    the flashes and activations of that second go with the method. The session's idle time
//!    (`GetLastInputInfo`, a read) at those moments says whether the user touched the mouse or
//!    keyboard meanwhile — a click on the game would read as the call's success, so the verdict
//!    flags it.
//! 5. A verdict per method, and which methods brought the game to the front.
//!
//! ## What it never does
//!
//! It never injects input — no `SendInput`, no HID report, no `keybd_event`; the Alt-key trick that
//! unlocks `SetForegroundWindow` is out of scope — and never sends or posts a message to the game.
//! The calls of (a)–(d) are the point of the probe: they ask the system to activate, raise or restore
//! the game's window, and the system then sends the game its usual activation messages, as when the
//! user clicks it. `AttachThreadInput` joins only the thread of the window in front, for a few
//! milliseconds. The game's process is opened once, for `PROCESS_QUERY_LIMITED_INFORMATION`. Window
//! titles are recorded for the game's windows only; for the user's other windows only the exe name
//! and the class.
//!
//! ## What to look at
//!
//! `summary.verdict` (also printed): per method, whether the game came to the front at +300 ms (or by
//! +1 s), was raised without the focus, or had its taskbar button flash; then the lock setting. A
//! lock that had expired (the user idle for longer than the timeout, or a timeout of 0) lets any
//! process take the foreground, so a success then says nothing about a PC with the default; each
//! method's verdict says so when it happened. `methods` has each call's result and `GetLastError`,
//! the states before, at +300 ms and at +1 s, and the shell messages; `events` is the whole timeline,
//! `shell` every shell message (those about other windows than the game's that are neither flashes
//! nor activations only up to a cap).

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{
    GetLastError, SetLastError, HINSTANCE, HWND, LPARAM, LRESULT, WIN32_ERROR, WPARAM,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Threading::{
    AttachThreadInput, GetCurrentProcessId, GetCurrentThreadId,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, CreateWindowExW, DefWindowProcW, DeregisterShellHookWindow, DestroyWindow,
    DispatchMessageW, IsIconic, PeekMessageW, RegisterClassW, RegisterShellHookWindow,
    RegisterWindowMessageW, SetForegroundWindow, ShowWindow, SwitchToThisWindow,
    SystemParametersInfoW, UnregisterClassW, HSHELL_ACCESSIBILITYSTATE, HSHELL_ACTIVATESHELLWINDOW,
    HSHELL_APPCOMMAND, HSHELL_ENDTASK, HSHELL_GETMINRECT, HSHELL_HIGHBIT, HSHELL_LANGUAGE,
    HSHELL_MONITORCHANGED, HSHELL_REDRAW, HSHELL_SYSMENU, HSHELL_TASKMAN, HSHELL_WINDOWACTIVATED,
    HSHELL_WINDOWCREATED, HSHELL_WINDOWDESTROYED, HSHELL_WINDOWREPLACED, HSHELL_WINDOWREPLACING,
    MSG, PM_REMOVE, SPI_GETFOREGROUNDFLASHCOUNT, SPI_GETFOREGROUNDLOCKTIMEOUT, SW_RESTORE,
    SYSTEM_PARAMETERS_INFO_ACTION, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS, WNDCLASSW,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_POPUP,
};

use super::win::{
    env_text, error_text, foreground, hwnd_of, local_time, make_dpi_aware, note, now_filetime,
    open_limited, os_version, output_path, own_process, process_facts, process_times, snapshot,
    top_level_windows, window_alive, window_facts, window_visible, write_json, ExeNames, WinFacts,
};
use super::{area, clip, covered_fraction, pick_candidate, Candidate, Matched};

const WHO: &str = "focus_probe";
const DEFAULT_CLASS: &str = "ScrydeGameUnrealWWindowsViewportWindow";
/// How long the probe waits for the game's window to exist.
const WAIT_FOR_WINDOW: Duration = Duration::from_secs(60);
/// How long it waits for another window in front of the game before the first method…
const FIRST_WAIT: Duration = Duration::from_secs(60);
/// …and before each next one.
const NEXT_WAIT: Duration = Duration::from_secs(30);
/// How long that window must have stayed in front, hands off, before a method runs.
const SETTLE: Duration = Duration::from_secs(2);
/// When a method's result is read, after its first call.
const AFTER: Duration = Duration::from_millis(300);
/// When it is read again: a late switch, a late flash.
const LATE: Duration = Duration::from_secs(1);
/// How often the shell messages are pumped and the foreground window read.
const PUMP: Duration = Duration::from_millis(10);
const PRINT_EVERY: Duration = Duration::from_secs(5);
/// Shell messages about other windows than the game's that are neither flashes nor activations
/// (mostly title redraws), kept word for word; the rest are counted.
const QUIET_KEPT: usize = 2000;
/// Errors of the same kind printed word for word; the rest are counted.
const ERRORS_PRINTED: usize = 5;
/// Windows' default `ForegroundLockTimeout`, ms.
const DEFAULT_LOCK_TIMEOUT_MS: u32 = 200_000;
/// The hidden shell-hook window's class.
const HOOK_CLASS: PCWSTR = w!("AFKLinkFocusProbe");

/// `HSHELL_WINDOWACTIVATED` with the high bit: an activation while a full-screen app runs.
const HSHELL_RUDEAPPACTIVATED: u32 = HSHELL_WINDOWACTIVATED | HSHELL_HIGHBIT;
/// `HSHELL_REDRAW` with the high bit: a taskbar button flashes.
const HSHELL_FLASH: u32 = HSHELL_REDRAW | HSHELL_HIGHBIT;

#[test]
#[ignore = "brings the game's window to the front while the owner covers it with Notepad; run by hand, see the module docs"]
fn focus_probe() -> Result<()> {
    let class = env_text("AFK_PROBE_WINDOW_CLASS")?
        .map(|c| c.trim().to_owned())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| DEFAULT_CLASS.to_owned());
    let out = output_path("focus-probe")?;
    println!("{WHO}: window class \"{class}\"; output {}", out.display());
    let mut probe = Probe::new(class, out);
    let outcome = probe.run();
    probe.finish(outcome)
}

/// A shell hook code's name (the `wParam` of the `SHELLHOOK` message).
fn shell_code_name(code: u32) -> &'static str {
    match code {
        HSHELL_WINDOWCREATED => "WINDOWCREATED",
        HSHELL_WINDOWDESTROYED => "WINDOWDESTROYED",
        HSHELL_ACTIVATESHELLWINDOW => "ACTIVATESHELLWINDOW",
        HSHELL_WINDOWACTIVATED => "WINDOWACTIVATED",
        HSHELL_GETMINRECT => "GETMINRECT",
        HSHELL_REDRAW => "REDRAW",
        HSHELL_TASKMAN => "TASKMAN",
        HSHELL_LANGUAGE => "LANGUAGE",
        HSHELL_SYSMENU => "SYSMENU",
        HSHELL_ENDTASK => "ENDTASK",
        HSHELL_ACCESSIBILITYSTATE => "ACCESSIBILITYSTATE",
        HSHELL_APPCOMMAND => "APPCOMMAND",
        HSHELL_WINDOWREPLACED => "WINDOWREPLACED",
        HSHELL_WINDOWREPLACING => "WINDOWREPLACING",
        HSHELL_MONITORCHANGED => "MONITORCHANGED",
        HSHELL_RUDEAPPACTIVATED => "RUDEAPPACTIVATED",
        HSHELL_FLASH => "FLASH",
        _ => "other",
    }
}

/// Whether the message's `lParam` is a window handle for this code; for the others it is a pointer
/// or a number and is never read as a window.
fn shell_names_window(code: u32) -> bool {
    matches!(
        code,
        HSHELL_WINDOWCREATED
            | HSHELL_WINDOWDESTROYED
            | HSHELL_WINDOWACTIVATED
            | HSHELL_REDRAW
            | HSHELL_ENDTASK
            | HSHELL_WINDOWREPLACED
            | HSHELL_WINDOWREPLACING
            | HSHELL_MONITORCHANGED
            | HSHELL_RUDEAPPACTIVATED
            | HSHELL_FLASH
    )
}

/// A flash or an activation: what says what a method did.
fn shell_loud(code: u32) -> bool {
    matches!(
        code,
        HSHELL_FLASH | HSHELL_WINDOWACTIVATED | HSHELL_RUDEAPPACTIVATED
    )
}

/// Whether a window's class is the one asked for: whole, case-insensitively.
fn class_is(class: &str, wanted: &str) -> bool {
    class.to_lowercase() == wanted.to_lowercase()
}

/// Whether window `a` lies above window `b` in a top-first z-order (`EnumWindows`' order); `None`
/// when either is not in it.
fn above(order: &[usize], a: usize, b: usize) -> Option<bool> {
    let ia = order.iter().position(|h| *h == a)?;
    let ib = order.iter().position(|h| *h == b)?;
    Some(ia < ib)
}

/// Why the stage is not set for a method yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NotReady {
    /// No window is in front (a switch in progress, the lock screen).
    NoForeground,
    /// The game — or another window of its process — is in front.
    GameInFront,
    /// This terminal, or a window of a process that started the probe, is in front.
    OursInFront,
    /// The game lies above the window in front: raised without the focus by the last method.
    GameAbove,
}

impl NotReady {
    fn text(self) -> &'static str {
        match self {
            Self::NoForeground => "no window is in front",
            Self::GameInFront => "the game is in front",
            Self::OursInFront => "this terminal, or a program that started the probe, is in front",
            Self::GameAbove => "the game lies above the window in front (raised without the focus)",
        }
    }

    fn ask(self) -> &'static str {
        match self {
            Self::NoForeground | Self::GameInFront => {
                "click Notepad so that it covers the game, then hands off"
            }
            Self::OursInFront => "click Notepad instead (not this terminal), then hands off",
            Self::GameAbove => "click Notepad again, then hands off",
        }
    }
}

/// Whether a method may start: another window than the game's and than ours in front, and either
/// above the game in the z-order or the game minimized. An unknown z-order (`None`: either window
/// missing from the list, or one topmost and the other not) does not hold it back.
fn not_ready(
    fg: usize,
    fg_is_game: bool,
    fg_is_ours: bool,
    game_minimized: bool,
    game_above_fg: Option<bool>,
) -> Option<NotReady> {
    if fg == 0 {
        Some(NotReady::NoForeground)
    } else if fg_is_game {
        Some(NotReady::GameInFront)
    } else if fg_is_ours {
        Some(NotReady::OursInFront)
    } else if !game_minimized && game_above_fg == Some(true) {
        Some(NotReady::GameAbove)
    } else {
        None
    }
}

/// What one method did, by the reads after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    /// The game was the foreground window 300 ms after the first call.
    InFront,
    /// Not at 300 ms, but by 1 s.
    InFrontLate,
    /// Not the foreground, but above the window in front in the z-order.
    RaisedWithoutFocus,
    /// Neither; its taskbar button flashed.
    Flashed,
    /// None of that.
    Nothing,
}

impl Outcome {
    fn in_front(self) -> bool {
        matches!(self, Self::InFront | Self::InFrontLate)
    }

    fn text(self) -> &'static str {
        match self {
            Self::InFront => "the game came to the FRONT (the foreground window at +300 ms)",
            Self::InFrontLate => "the game came to the FRONT, late (not at +300 ms, by +1 s)",
            Self::RaisedWithoutFocus => {
                "the game was raised above the window in front WITHOUT the focus"
            }
            Self::Flashed => "REFUSED: not in front, not raised; its taskbar button flashed",
            Self::Nothing => "NOTHING seen: not in front, not raised, no flash",
        }
    }
}

fn outcome(front_after: bool, front_late: bool, raised: bool, flashed: bool) -> Outcome {
    if front_after {
        Outcome::InFront
    } else if front_late {
        Outcome::InFrontLate
    } else if raised {
        Outcome::RaisedWithoutFocus
    } else if flashed {
        Outcome::Flashed
    } else {
        Outcome::Nothing
    }
}

/// ms since the last input, from two `GetTickCount` values (it wraps every 49.7 days).
fn idle_since(now_tick: u32, last_input_tick: u32) -> u32 {
    now_tick.wrapping_sub(last_input_tick)
}

/// Whether the foreground lock had expired: the user idle for at least the timeout, or no lock at
/// all (0). Then the system lets any process take the foreground.
fn lock_expired(idle_ms: u32, timeout_ms: u32) -> bool {
    timeout_ms == 0 || idle_ms >= timeout_ms
}

/// Whether there was keyboard or mouse input after a moment `since_ms` ago, by the session's idle
/// time (`None`: unread, taken as no).
fn input_after(idle_ms: Option<u32>, since_ms: f64) -> bool {
    idle_ms.is_some_and(|idle| f64::from(idle) < since_ms)
}

/// The processes that started `own`, nearest first: each parent from `parent_of` (a snapshot's parent
/// pid), kept only while it was created before its child — a parent pid whose process has exited may
/// name a newer, unrelated process. The walk stops at an unknown parent or creation time, at pid 0,
/// and at a loop.
fn ancestors(
    own: u32,
    mut parent_of: impl FnMut(u32) -> Option<u32>,
    mut created: impl FnMut(u32) -> Option<u64>,
) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut seen = HashSet::from([own]);
    let mut child = own;
    while let Some(parent) = parent_of(child) {
        if parent == 0 || !seen.insert(parent) {
            break;
        }
        match (created(parent), created(child)) {
            (Some(p), Some(c)) if p <= c => chain.push(parent),
            _ => break,
        }
        child = parent;
    }
    chain
}

/// A Win32 error code with its (localized) text; 0 is just `0`.
fn win32_text(code: u32) -> String {
    if code == 0 {
        return "0".to_owned();
    }
    let text = std::io::Error::from_raw_os_error(code as i32).to_string();
    format!("{code} ({code:#x}) {text}")
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// The methods, in the order they are tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    A,
    B,
    C,
    D,
}

impl Method {
    const ALL: [Self; 4] = [Self::A, Self::B, Self::C, Self::D];

    fn id(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::C => "c",
            Self::D => "d",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::A => "SetForegroundWindow",
            Self::B => "ShowWindow(SW_RESTORE) if minimized, then SetForegroundWindow",
            Self::C => {
                "AttachThreadInput to the window in front, SetForegroundWindow, BringWindowToTop, \
                 detach"
            }
            Self::D => "SwitchToThisWindow(game, TRUE)",
        }
    }
}

/// A call's value, and the thread's last error read right after it.
struct Traced<T> {
    value: T,
    last_error: u32,
}

/// Run one API call with the thread's last error cleared before it and read right after it.
fn traced<T>(call: impl FnOnce() -> T) -> Traced<T> {
    // SAFETY: sets this thread's last-error value; no pointers.
    unsafe { SetLastError(WIN32_ERROR(0)) };
    let value = call();
    // SAFETY: reads this thread's last-error value.
    let last_error = unsafe { GetLastError() }.0;
    Traced { value, last_error }
}

/// One API call a method made, or skipped.
struct Call {
    api: String,
    t_ms: f64,
    /// What it returned (`null` for a call that returns nothing, or was skipped).
    returned: Value,
    last_error: u32,
    remark: Option<String>,
    skipped: Option<String>,
}

impl Call {
    fn done(
        api: impl Into<String>,
        t_ms: f64,
        returned: Value,
        last_error: u32,
        remark: Option<String>,
    ) -> Self {
        Self {
            api: api.into(),
            t_ms,
            returned,
            last_error,
            remark,
            skipped: None,
        }
    }

    fn skipped(api: impl Into<String>, t_ms: f64, why: impl Into<String>) -> Self {
        Self {
            api: api.into(),
            t_ms,
            returned: Value::Null,
            last_error: 0,
            remark: None,
            skipped: Some(why.into()),
        }
    }

    fn text(&self) -> String {
        if let Some(why) = &self.skipped {
            return format!("{} skipped ({why})", self.api);
        }
        let returned = match &self.returned {
            Value::Null => "(no value)".to_owned(),
            other => other.to_string(),
        };
        format!(
            "{} → {returned}, last error {}{}",
            self.api,
            win32_text(self.last_error),
            self.remark
                .as_ref()
                .map_or_else(String::new, |r| format!(" [{r}]"))
        )
    }

    fn to_json(&self) -> Value {
        json!({
            "api": self.api,
            "t_ms": self.t_ms,
            "returned": self.returned,
            "last_error": self.last_error,
            "last_error_text": win32_text(self.last_error),
            "remark": self.remark,
            "skipped": self.skipped,
        })
    }
}

/// The foreground window and the game's place relative to it, at one moment.
#[derive(Clone, Debug)]
struct State {
    t_ms: f64,
    fg: usize,
    fg_label: Value,
    fg_text: String,
    fg_is_game: bool,
    fg_is_ours: bool,
    game_alive: bool,
    game_minimized: bool,
    /// The game above the window in front in the z-order; `None` when that cannot be compared.
    game_above_fg: Option<bool>,
    /// The share of the game the window in front covers, when it lies above the game.
    covered_by_fg: Option<f64>,
    /// ms since the last input anywhere in the session (`GetLastInputInfo`).
    idle_ms: Option<u32>,
}

impl State {
    fn not_ready(&self) -> Option<NotReady> {
        not_ready(
            self.fg,
            self.fg_is_game,
            self.fg_is_ours,
            self.game_minimized,
            self.game_above_fg,
        )
    }

    fn to_json(&self) -> Value {
        json!({
            "t_ms": self.t_ms,
            "foreground": self.fg_label,
            "foreground_is_game": self.fg_is_game,
            "foreground_is_ours": self.fg_is_ours,
            "game_alive": self.game_alive,
            "game_minimized": self.game_minimized,
            "game_above_foreground": self.game_above_fg,
            "game_covered_by_foreground": self.covered_by_fg,
            "idle_ms": self.idle_ms,
        })
    }
}

/// One shell message.
#[derive(Clone, Debug, Serialize)]
struct ShellMsg {
    t_ms: f64,
    code: u32,
    name: &'static str,
    /// The window it names (exe, class; the title only for the game's), when it names one.
    window: Value,
    /// About a window of the game's process.
    game: bool,
    /// A flash or an activation, or about the game: printed and always kept.
    loud: bool,
}

/// What one method did, or why it was not tried.
struct MethodRecord {
    method: Method,
    outcome: Option<Outcome>,
    verdict: String,
    record: Value,
}

thread_local! {
    /// The `SHELLHOOK` message's number while the hidden window is registered; 0 otherwise.
    static SHELL_MESSAGE: Cell<u32> = const { Cell::new(0) };
    /// Shell messages as the window procedure received them: when, the code, the `lParam`.
    static SHELL_INBOX: RefCell<Vec<(Instant, u32, isize)>> = const { RefCell::new(Vec::new()) };
    /// Shell messages the window procedure could not keep (the inbox was borrowed; never expected).
    static SHELL_LOST: Cell<usize> = const { Cell::new(0) };
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let shell = SHELL_MESSAGE.with(Cell::get);
    if shell != 0 && msg == shell {
        let at = Instant::now();
        let kept = SHELL_INBOX.with(|inbox| match inbox.try_borrow_mut() {
            Ok(mut inbox) => {
                inbox.push((at, wparam.0 as u32, lparam.0));
                true
            }
            Err(_) => false,
        });
        if !kept {
            SHELL_LOST.with(|lost| lost.set(lost.get() + 1));
        }
        return LRESULT(0);
    }
    // SAFETY: the default handling of any other message of this window, with its own arguments.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// The hidden window that receives the shell's messages; unregistered and destroyed on drop, on the
/// thread that created it.
struct ShellHook {
    hwnd: HWND,
    instance: HINSTANCE,
    registered: bool,
}

impl ShellHook {
    /// The window and its registration, with what to record; what failed otherwise.
    fn create() -> std::result::Result<(Self, Value), String> {
        // SAFETY: the module handle of this executable; nothing is freed.
        let module = unsafe { GetModuleHandleW(PCWSTR::null()) }
            .map_err(|e| format!("GetModuleHandleW: {}", error_text(&e)))?;
        let instance = HINSTANCE::from(module);
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: HOOK_CLASS,
            ..Default::default()
        };
        // SAFETY: a filled class description whose strings are static.
        if unsafe { RegisterClassW(&class) } == 0 {
            return Err(format!(
                "RegisterClassW: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the class just registered; no parent, menu or creation data. Not visible (no
        // WS_VISIBLE), never activated (WS_EX_NOACTIVATE), not on the taskbar (WS_EX_TOOLWINDOW).
        let created = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                HOOK_CLASS,
                w!("AFKLink focus probe"),
                WS_POPUP,
                0,
                0,
                0,
                0,
                None,
                None,
                Some(instance),
                None,
            )
        };
        let hwnd = match created {
            Ok(hwnd) => hwnd,
            Err(error) => {
                // SAFETY: the class registered above; no window of it exists.
                if let Err(e) = unsafe { UnregisterClassW(HOOK_CLASS, Some(instance)) } {
                    println!("{WHO}: UnregisterClassW failed: {}", error_text(&e));
                }
                return Err(format!("CreateWindowExW: {}", error_text(&error)));
            }
        };
        let mut hook = Self {
            hwnd,
            instance,
            registered: false,
        };
        // SAFETY: a static name; the number is the same in every process of the session.
        let message = unsafe { RegisterWindowMessageW(w!("SHELLHOOK")) };
        if message == 0 {
            return Err(format!(
                "RegisterWindowMessageW(SHELLHOOK): {}",
                std::io::Error::last_os_error()
            ));
        }
        SHELL_MESSAGE.with(|m| m.set(message));
        // SAFETY: our own window, created on this thread.
        hook.registered = unsafe { RegisterShellHookWindow(hwnd) }.as_bool();
        if !hook.registered {
            return Err(format!(
                "RegisterShellHookWindow: {}",
                std::io::Error::last_os_error()
            ));
        }
        let state = json!({
            "hwnd": format!("{:#x}", hwnd.0 as usize),
            "message": format!("{message:#06x}"),
        });
        Ok((hook, state))
    }
}

impl Drop for ShellHook {
    fn drop(&mut self) {
        SHELL_MESSAGE.with(|m| m.set(0));
        if self.registered {
            // SAFETY: our own window, registered in `create`.
            if !unsafe { DeregisterShellHookWindow(self.hwnd) }.as_bool() {
                println!(
                    "{WHO}: DeregisterShellHookWindow failed: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        // SAFETY: our own window, created on this thread (the probe never leaves it).
        if let Err(error) = unsafe { DestroyWindow(self.hwnd) } {
            println!("{WHO}: DestroyWindow failed: {}", error_text(&error));
        }
        // SAFETY: the class registered in `create`; its only window is gone.
        if let Err(error) = unsafe { UnregisterClassW(HOOK_CLASS, Some(self.instance)) } {
            println!("{WHO}: UnregisterClassW failed: {}", error_text(&error));
        }
    }
}

/// `SystemParametersInfoW` for a setting that is one u32.
fn spi_u32(action: SYSTEM_PARAMETERS_INFO_ACTION) -> std::result::Result<u32, String> {
    let mut value = 0u32;
    // SAFETY: `value` is a live u32, which both actions asked here write.
    unsafe {
        SystemParametersInfoW(
            action,
            0,
            Some((&mut value as *mut u32).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    }
    .map(|()| value)
    .map_err(|e| error_text(&e))
}

/// ms since the last keyboard or mouse input in this session; a read, nothing is sent.
fn idle_ms() -> Option<u32> {
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: a live LASTINPUTINFO with `cbSize` set.
    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        return None;
    }
    // SAFETY: plain call.
    Some(idle_since(unsafe { GetTickCount() }, info.dwTime))
}

struct Probe {
    class: String,
    out: PathBuf,
    started_local: String,
    epoch: Instant,
    /// FILETIME at the start: the game's creation time is ms after it.
    epoch_ft: u64,
    environment: Value,
    names: ExeNames,
    /// This process and the processes that started it: their windows do not count as "another
    /// window in front".
    ours: HashSet<u32>,
    console: usize,
    hook: Option<ShellHook>,
    lock_timeout_ms: Option<u32>,
    game_hwnd: usize,
    game_pid: u32,
    game_thread: u32,
    game: Value,
    last_fg: Option<usize>,
    events: Vec<Value>,
    shell: Vec<ShellMsg>,
    shell_seen: usize,
    quiet_kept: usize,
    quiet_dropped: usize,
    shell_by_code: BTreeMap<&'static str, usize>,
    methods: Vec<MethodRecord>,
    enum_errors: usize,
    summary: Value,
    notes: Vec<String>,
}

impl Probe {
    fn new(class: String, out: PathBuf) -> Self {
        Self {
            class,
            out,
            started_local: local_time(),
            epoch: Instant::now(),
            epoch_ft: now_filetime(),
            environment: json!({}),
            names: ExeNames::new(),
            ours: HashSet::new(),
            console: 0,
            hook: None,
            lock_timeout_ms: None,
            game_hwnd: 0,
            game_pid: 0,
            game_thread: 0,
            game: Value::Null,
            last_fg: None,
            events: Vec::new(),
            shell: Vec::new(),
            shell_seen: 0,
            quiet_kept: 0,
            quiet_dropped: 0,
            shell_by_code: BTreeMap::new(),
            methods: Vec::new(),
            enum_errors: 0,
            summary: Value::Null,
            notes: Vec::new(),
        }
    }

    fn t_ms(&self) -> f64 {
        self.epoch.elapsed().as_micros() as f64 / 1000.0
    }

    fn event(&mut self, t_ms: f64, kind: &str, text: String, detail: Value) {
        println!("{WHO}: {:+9.3} s  {kind:<10} {text}", t_ms / 1000.0);
        self.events
            .push(json!({ "t_ms": t_ms, "kind": kind, "text": text, "detail": detail }));
    }

    fn run(&mut self) -> Result<()> {
        let dpi = make_dpi_aware(WHO, &mut self.notes);
        let process = own_process();
        self.environment["dpi"] = dpi;
        self.environment["os"] = os_version();
        self.environment["process"] = process.clone();
        println!(
            "{WHO}: Windows {} build {}.{}; this process {process}",
            self.environment["os"]["display_version"],
            self.environment["os"]["build"],
            self.environment["os"]["ubr"],
        );
        if process["elevated"].as_bool() == Some(true) {
            bail!(
                "this process is elevated: run the probe from an unelevated terminal. The agent runs \
                 unelevated, and an elevated caller passes focus checks it does not"
            );
        }
        self.settings();
        self.parents();
        self.hook();
        self.find_game()?;
        self.print_checklist();
        for (i, method) in Method::ALL.into_iter().enumerate() {
            let wait = if i == 0 { FIRST_WAIT } else { NEXT_WAIT };
            if let Err(why) = self.wait_ready(method, wait) {
                note(
                    WHO,
                    &mut self.notes,
                    format!("stopped before ({}): {why}", method.id()),
                );
                for rest in &Method::ALL[i..] {
                    self.methods.push(MethodRecord {
                        method: *rest,
                        outcome: None,
                        verdict: format!("({}) {}: not tried — {why}", rest.id(), rest.name()),
                        record: json!({
                            "id": rest.id(),
                            "name": rest.name(),
                            "not_tried": why,
                        }),
                    });
                }
                break;
            }
            let record = self.try_method(method);
            self.methods.push(record);
        }
        Ok(())
    }

    /// The foreground rules' settings (method (e): recorded only).
    fn settings(&mut self) {
        let lock = spi_u32(SPI_GETFOREGROUNDLOCKTIMEOUT);
        let flash = spi_u32(SPI_GETFOREGROUNDFLASHCOUNT);
        self.lock_timeout_ms = lock.as_ref().ok().copied();
        let text = |r: &std::result::Result<u32, String>| match r {
            Ok(v) => v.to_string(),
            Err(e) => format!("unread ({e})"),
        };
        println!(
            "{WHO}: foreground lock timeout {} ms (Windows' default {DEFAULT_LOCK_TIMEOUT_MS}); \
             flash count {}; idle {} ms",
            text(&lock),
            text(&flash),
            idle_ms().map_or_else(|| "?".to_owned(), |i| i.to_string())
        );
        if let Err(error) = &lock {
            note(
                WHO,
                &mut self.notes,
                format!("SPI_GETFOREGROUNDLOCKTIMEOUT: {error}"),
            );
        }
        if let Err(error) = &flash {
            note(
                WHO,
                &mut self.notes,
                format!("SPI_GETFOREGROUNDFLASHCOUNT: {error}"),
            );
        }
        let as_json = |r: std::result::Result<u32, String>| match r {
            Ok(v) => json!(v),
            Err(e) => json!({ "error": e }),
        };
        self.environment["foreground_lock_timeout_ms"] = as_json(lock);
        self.environment["foreground_flash_count"] = as_json(flash);
    }

    /// This process's parents and console window: windows that must not count as "another window in
    /// front".
    fn parents(&mut self) {
        // SAFETY: plain calls.
        let (own, console) = unsafe { (GetCurrentProcessId(), GetConsoleWindow()) };
        self.console = console.0 as usize;
        let list = match snapshot() {
            Ok(list) => list,
            Err(error) => {
                note(
                    WHO,
                    &mut self.notes,
                    format!(
                        "{error}: the probe's parents are unknown, their windows count as others"
                    ),
                );
                Vec::new()
            }
        };
        let by_pid: HashMap<u32, (u32, String)> = list
            .iter()
            .map(|p| (p.pid, (p.ppid, p.exe.clone())))
            .collect();
        let mut created: HashMap<u32, Option<u64>> = HashMap::new();
        let chain = ancestors(
            own,
            |pid| by_pid.get(&pid).map(|p| p.0),
            |pid| {
                *created.entry(pid).or_insert_with(|| {
                    open_limited(pid, false)
                        .and_then(|h| process_times(&h))
                        .ok()
                        .map(|(c, _)| c)
                })
            },
        );
        let exe = |pid: u32| by_pid.get(&pid).map_or("?", |p| p.1.as_str());
        let parents: Vec<Value> = chain
            .iter()
            .map(|pid| json!({ "pid": pid, "exe": exe(*pid) }))
            .collect();
        println!(
            "{WHO}: this process {own} {}, started by: {}; console window {:#x}. Their windows do not \
             count as another window in front",
            exe(own),
            if chain.is_empty() {
                "? (none found)".to_owned()
            } else {
                chain
                    .iter()
                    .map(|pid| format!("{} {pid}", exe(*pid)))
                    .collect::<Vec<_>>()
                    .join(" ← ")
            },
            self.console
        );
        self.ours = chain.iter().copied().chain([own]).collect();
        self.environment["parents"] = json!(parents);
        self.environment["console_window"] = json!(format!("{:#x}", self.console));
    }

    fn hook(&mut self) {
        match ShellHook::create() {
            Ok((hook, state)) => {
                println!(
                    "{WHO}: shell hook window {}: taskbar flashes and activations will be seen",
                    state["hwnd"]
                );
                self.environment["shell_hook"] = state;
                self.hook = Some(hook);
            }
            Err(error) => {
                note(
                    WHO,
                    &mut self.notes,
                    format!(
                        "the shell hook window failed ({error}): flashes cannot be seen; the methods \
                         run anyway"
                    ),
                );
                self.environment["shell_hook"] = json!({ "error": error });
            }
        }
    }

    /// Wait until a window of the class exists, and record it and its process.
    fn find_game(&mut self) -> Result<()> {
        let start = Instant::now();
        let mut printed: Option<Instant> = None;
        let facts = loop {
            self.pump();
            if let Some(facts) = self.look_for_game() {
                break facts;
            }
            if start.elapsed() >= WAIT_FOR_WINDOW {
                bail!(
                    "no visible top-level window of class \"{}\" in {} s: is the game running? \
                     (AFK_PROBE_WINDOW_CLASS sets the class)",
                    self.class,
                    WAIT_FOR_WINDOW.as_secs()
                );
            }
            if printed.is_none_or(|p| p.elapsed() >= PRINT_EVERY) {
                println!(
                    "{WHO}: waiting for a window of class \"{}\" ({} s left)",
                    self.class,
                    WAIT_FOR_WINDOW.saturating_sub(start.elapsed()).as_secs()
                );
                printed = Some(Instant::now());
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        self.game_hwnd = facts.hwnd;
        self.game_pid = facts.pid;
        self.game_thread = facts.thread;
        let process = process_facts(facts.pid, self.epoch_ft);
        let exe = self.names.get(facts.pid);
        let text = format!(
            "{:#x} class \"{}\" title \"{}\" pid {} {}: {} {}{}",
            facts.hwnd,
            facts.class,
            clip(&facts.title, 40),
            facts.pid,
            exe.as_deref().unwrap_or("?"),
            process
                .get("integrity")
                .or_else(|| process.get("integrity_error"))
                .or_else(|| process.get("token_error"))
                .or_else(|| process.get("open_error"))
                .unwrap_or(&Value::Null),
            match process["elevated"].as_bool() {
                Some(true) => "elevated",
                Some(false) => "not elevated",
                None => "elevation ?",
            },
            if facts.minimized { ", minimized" } else { "" }
        );
        if process["elevated"].as_bool() == Some(false) {
            note(
                WHO,
                &mut self.notes,
                "the game is not elevated: this run shows what works on a window of this \
                 process's own level, not on the elevated game"
                    .to_owned(),
            );
        }
        self.game = json!({
            "hwnd": format!("{:#x}", facts.hwnd),
            "pid": facts.pid,
            "thread": facts.thread,
            "exe": exe,
            "process": process,
            "window": facts,
        });
        let t = self.t_ms();
        self.event(t, "game", text, Value::Null);
        Ok(())
    }

    /// The visible top-level window of the class; the best of several (on screen, then the largest).
    fn look_for_game(&mut self) -> Option<WinFacts> {
        let list = self.windows();
        let found: Vec<WinFacts> = list
            .into_iter()
            .filter(|h| window_visible(*h))
            .map(window_facts)
            .filter(|f| class_is(&f.class, &self.class))
            .collect();
        let candidates: Vec<Candidate> = found
            .iter()
            .map(|f| Candidate {
                matched: Matched {
                    class: true,
                    ..Matched::default()
                },
                minimized: f.minimized,
                cloaked: f.cloaked.unwrap_or(0) != 0,
                area: f.bounds().map_or(0, area),
            })
            .collect();
        let pick = pick_candidate(&candidates)?;
        if found.len() > 1 {
            let all: Vec<String> = found.iter().map(|f| format!("{:#x}", f.hwnd)).collect();
            note(
                WHO,
                &mut self.notes,
                format!(
                    "{} windows of the class ({}): took {:#x}, on screen and the largest",
                    found.len(),
                    all.join(", "),
                    found[pick].hwnd
                ),
            );
        }
        found.into_iter().nth(pick)
    }

    /// Every top-level window, top first; an error is noted and reads as none.
    fn windows(&mut self) -> Vec<usize> {
        match top_level_windows() {
            Ok(list) => list,
            Err(error) => {
                self.enum_errors += 1;
                if self.enum_errors <= ERRORS_PRINTED {
                    let t = self.t_ms();
                    note(
                        WHO,
                        &mut self.notes,
                        format!("+{:.1} s: {error}", t / 1000.0),
                    );
                }
                Vec::new()
            }
        }
    }

    fn print_checklist(&self) {
        println!();
        println!("{WHO}: by hand, at the PC — the terminal says when:");
        println!(
            "{WHO}:   1. click Notepad so that it is in front of the game (not this terminal, and not \
             Explorer or the desktop if the terminal was started from them);"
        );
        println!(
            "{WHO}:   2. hands off the mouse and keyboard: after 2 s the probe tries one way to bring \
             the game back and prints what happened;"
        );
        println!(
            "{WHO}:   3. when the game came to the front (or above Notepad), click Notepad again; the \
             probe waits up to {} s for that before each next way.",
            NEXT_WAIT.as_secs()
        );
        println!(
            "{WHO}:   Before (b) you may minimize the game instead of covering it: (b) then also \
             restores it."
        );
        for m in Method::ALL {
            println!("{WHO}:   ({}) {}", m.id(), m.name());
        }
        println!("{WHO}: no keyboard or mouse input is sent, ever.");
        println!();
    }

    /// Pump the shell messages, and log a change of the foreground window.
    fn pump(&mut self) {
        let mut msg = MSG::default();
        // SAFETY: a live MSG; this thread's messages, which only the hidden window gets.
        while unsafe { PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE) }.as_bool() {
            // SAFETY: a message just retrieved on this thread.
            unsafe { DispatchMessageW(&msg) };
        }
        self.take_shell_messages();
        let fg = foreground();
        if self.last_fg != Some(fg) {
            self.last_fg = Some(fg);
            let t = self.t_ms();
            if fg == 0 {
                self.event(t, "foreground", "none".to_owned(), Value::Null);
            } else {
                let facts = window_facts(fg);
                let (label, text) = self.label(&facts);
                let whose = if self.game_pid != 0 && facts.pid == self.game_pid {
                    " [game]"
                } else if self.ours.contains(&facts.pid) || fg == self.console {
                    " [ours]"
                } else {
                    ""
                };
                self.event(t, "foreground", format!("{text}{whose}"), label);
            }
        }
    }

    /// Pump until `until`, every 10 ms.
    fn pump_until(&mut self, until: Instant) {
        loop {
            self.pump();
            let now = Instant::now();
            if now >= until {
                return;
            }
            std::thread::sleep(PUMP.min(until - now));
        }
    }

    fn take_shell_messages(&mut self) {
        let inbox: Vec<(Instant, u32, isize)> = SHELL_INBOX.with(|inbox| {
            inbox
                .try_borrow_mut()
                .map(|mut i| std::mem::take(&mut *i))
                .unwrap_or_default()
        });
        for (at, code, lparam) in inbox {
            let t_ms = at.saturating_duration_since(self.epoch).as_micros() as f64 / 1000.0;
            let name = shell_code_name(code);
            self.shell_seen += 1;
            *self.shell_by_code.entry(name).or_default() += 1;
            let hwnd = shell_names_window(code).then_some(lparam as usize);
            let facts = hwnd.filter(|h| *h != 0).map(window_facts);
            let game = self.game_hwnd != 0
                && (hwnd == Some(self.game_hwnd)
                    || facts
                        .as_ref()
                        .is_some_and(|f| f.pid != 0 && f.pid == self.game_pid));
            let (window, text) = match &facts {
                Some(f) => self.label(f),
                None => (
                    Value::Null,
                    hwnd.map_or_else(|| format!("lParam {lparam:#x}"), |h| format!("{h:#x}")),
                ),
            };
            let loud = game || shell_loud(code);
            if loud {
                self.event(
                    t_ms,
                    "shell",
                    format!("{name} {text}{}", if game { " [game]" } else { "" }),
                    json!({ "code": code }),
                );
            } else if self.quiet_kept >= QUIET_KEPT {
                self.quiet_dropped += 1;
                continue;
            } else {
                self.quiet_kept += 1;
            }
            self.shell.push(ShellMsg {
                t_ms,
                code,
                name,
                window,
                game,
                loud,
            });
        }
    }

    /// A window as the record shows it: the exe and class, and the title for the game's windows
    /// only (the user's other windows may show private things in theirs).
    fn label(&mut self, facts: &WinFacts) -> (Value, String) {
        let exe = self.names.get(facts.pid);
        let title = (self.game_pid != 0 && facts.pid == self.game_pid).then(|| facts.title.clone());
        let text = format!(
            "{} class \"{}\"{} {:#x}",
            exe.as_deref().unwrap_or("?"),
            clip(&facts.class, 40),
            title
                .as_ref()
                .map_or_else(String::new, |t| format!(" title \"{}\"", clip(t, 40))),
            facts.hwnd
        );
        let value = json!({
            "hwnd": format!("{:#x}", facts.hwnd),
            "pid": facts.pid,
            "exe": exe,
            "class": facts.class,
            "title": title,
        });
        (value, text)
    }

    /// The foreground window and the game's place relative to it, now.
    fn state(&mut self) -> State {
        let t_ms = self.t_ms();
        let fg = foreground();
        let order = self.windows();
        let game = window_facts(self.game_hwnd);
        let game_alive = window_alive(self.game_hwnd);
        let fg_facts = (fg != 0).then(|| window_facts(fg));
        let fg_is_game = fg != 0
            && (fg == self.game_hwnd
                || fg_facts
                    .as_ref()
                    .is_some_and(|f| f.pid != 0 && f.pid == self.game_pid));
        let fg_is_ours = fg != 0
            && (fg == self.console
                || fg_facts
                    .as_ref()
                    .is_some_and(|f| self.ours.contains(&f.pid)));
        // A topmost window is above every other one whatever happens: only like with like compares.
        let comparable = fg_facts
            .as_ref()
            .is_some_and(|f| f.topmost() == game.topmost());
        let game_above_fg = if comparable && !fg_is_game {
            above(&order, self.game_hwnd, fg)
        } else {
            None
        };
        let covered_by_fg = match (
            game_above_fg,
            game.bounds(),
            fg_facts.as_ref().and_then(WinFacts::bounds),
        ) {
            (Some(false), Some(g), Some(f)) => Some(round3(covered_fraction(g, f))),
            _ => None,
        };
        let (fg_label, fg_text) = match &fg_facts {
            Some(f) => self.label(f),
            None => (Value::Null, "none".to_owned()),
        };
        State {
            t_ms,
            fg,
            fg_label,
            fg_text,
            fg_is_game,
            fg_is_ours,
            game_alive,
            game_minimized: game.minimized,
            game_above_fg,
            covered_by_fg,
            idle_ms: idle_ms(),
        }
    }

    /// Wait until another window has been in front of the game for [`SETTLE`]; `timeout` bounds the
    /// wait for it to get there, not the settling.
    fn wait_ready(&mut self, method: Method, timeout: Duration) -> std::result::Result<(), String> {
        let start = Instant::now();
        let mut ready_since: Option<Instant> = None;
        let mut printed: Option<(Instant, NotReady)> = None;
        let t = self.t_ms();
        self.event(
            t,
            "wait",
            format!(
                "before ({}): another window in front of the game, {} s at most, then {} s hands off",
                method.id(),
                timeout.as_secs(),
                SETTLE.as_secs()
            ),
            Value::Null,
        );
        loop {
            self.pump();
            let s = self.state();
            if !s.game_alive {
                return Err("the game's window is gone".to_owned());
            }
            match s.not_ready() {
                None => {
                    let since = *ready_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= SETTLE {
                        let text = format!(
                            "({}) starts from: {} in front; the game {}{}",
                            method.id(),
                            s.fg_text,
                            if s.game_minimized {
                                "minimized"
                            } else if s.game_above_fg == Some(false) {
                                "below it"
                            } else {
                                "not comparable in the z-order (one of them topmost)"
                            },
                            s.covered_by_fg.map_or_else(String::new, |c| format!(
                                ", {:.0} % of it covered",
                                c * 100.0
                            ))
                        );
                        self.event(s.t_ms, "ready", text, s.to_json());
                        return Ok(());
                    }
                }
                Some(why) => {
                    ready_since = None;
                    if start.elapsed() >= timeout {
                        return Err(format!(
                            "{} after {} s ({} in front)",
                            why.text(),
                            timeout.as_secs(),
                            s.fg_text
                        ));
                    }
                    let due =
                        printed.is_none_or(|(at, last)| last != why || at.elapsed() >= PRINT_EVERY);
                    if due {
                        println!(
                            "{WHO}:   ({}) waiting: {}: {} ({} s left)",
                            method.id(),
                            why.text(),
                            why.ask(),
                            timeout.saturating_sub(start.elapsed()).as_secs()
                        );
                        printed = Some((Instant::now(), why));
                    }
                }
            }
            std::thread::sleep(PUMP);
        }
    }

    fn call(&mut self, method: Method, calls: &mut Vec<Call>, call: Call) {
        self.event(
            call.t_ms,
            "call",
            format!("({}) {}", method.id(), call.text()),
            call.to_json(),
        );
        calls.push(call);
    }

    fn set_foreground(&mut self, method: Method, calls: &mut Vec<Call>, game: HWND) {
        let t = self.t_ms();
        // SAFETY: plain call on a window handle; a gone window fails and says so.
        let r = traced(|| unsafe { SetForegroundWindow(game) });
        let call = Call::done(
            "SetForegroundWindow(game)",
            t,
            json!(r.value.as_bool()),
            r.last_error,
            None,
        );
        self.call(method, calls, call);
    }

    fn try_method(&mut self, method: Method) -> MethodRecord {
        let before = self.state();
        let game = hwnd_of(self.game_hwnd);
        let mut calls: Vec<Call> = Vec::new();
        let start = Instant::now();
        let t0 = self.t_ms();
        self.event(
            t0,
            "method",
            format!("({}) {}", method.id(), method.name()),
            Value::Null,
        );
        match method {
            Method::A => self.set_foreground(method, &mut calls, game),
            Method::B => {
                // SAFETY: plain call on a window handle.
                let minimized = unsafe { IsIconic(game) }.as_bool();
                let t = self.t_ms();
                if minimized {
                    // SAFETY: plain call on a window handle; the system restores the window.
                    let r = traced(|| unsafe { ShowWindow(game, SW_RESTORE) });
                    // SAFETY: plain call on a window handle.
                    let still = unsafe { IsIconic(game) }.as_bool();
                    let call = Call::done(
                        "ShowWindow(game, SW_RESTORE)",
                        t,
                        json!(r.value.as_bool()),
                        r.last_error,
                        Some(format!(
                            "returns whether the window was visible before, not success; \
                             minimized right after: {still}"
                        )),
                    );
                    self.call(method, &mut calls, call);
                } else {
                    let call = Call::skipped(
                        "ShowWindow(game, SW_RESTORE)",
                        t,
                        "the game is not minimized",
                    );
                    self.call(method, &mut calls, call);
                }
                self.set_foreground(method, &mut calls, game);
            }
            Method::C => {
                let fg = foreground();
                let fg_thread = if fg == 0 { 0 } else { window_facts(fg).thread };
                // SAFETY: plain call.
                let ours = unsafe { GetCurrentThreadId() };
                let attach = format!(
                    "AttachThreadInput(this thread {ours}, thread {fg_thread} of the window in \
                     front {fg:#x}, TRUE)"
                );
                let t = self.t_ms();
                let skip = if fg == 0 || fg_thread == 0 {
                    Some("no window in front")
                } else if fg_thread == ours {
                    Some("the window in front is this thread's")
                } else if fg_thread == self.game_thread {
                    Some("the window in front is the game's: never attach to its thread")
                } else {
                    None
                };
                let attached = match skip {
                    Some(why) => {
                        self.call(method, &mut calls, Call::skipped(attach, t, why));
                        false
                    }
                    None => {
                        // SAFETY: plain call with two thread ids; the other one is never the
                        // game's (checked above).
                        let r = traced(|| unsafe { AttachThreadInput(ours, fg_thread, true) });
                        let ok = r.value.as_bool();
                        let call = Call::done(attach, t, json!(ok), r.last_error, None);
                        self.call(method, &mut calls, call);
                        ok
                    }
                };
                self.set_foreground(method, &mut calls, game);
                let t = self.t_ms();
                // SAFETY: plain call on a window handle.
                let r = traced(|| unsafe { BringWindowToTop(game) });
                let call = Call::done(
                    "BringWindowToTop(game)",
                    t,
                    json!(r.value.is_ok()),
                    r.last_error,
                    r.value.as_ref().err().map(error_text),
                );
                self.call(method, &mut calls, call);
                if attached {
                    let t = self.t_ms();
                    // SAFETY: as the attach above.
                    let r = traced(|| unsafe { AttachThreadInput(ours, fg_thread, false) });
                    let ok = r.value.as_bool();
                    let call = Call::done(
                        format!("AttachThreadInput(this thread {ours}, thread {fg_thread}, FALSE)"),
                        t,
                        json!(ok),
                        r.last_error,
                        None,
                    );
                    self.call(method, &mut calls, call);
                    if !ok {
                        note(
                            WHO,
                            &mut self.notes,
                            format!(
                                "({}) detaching from thread {fg_thread} failed ({}); the attachment \
                                 ends when this process exits",
                                method.id(),
                                win32_text(r.last_error)
                            ),
                        );
                    }
                }
            }
            Method::D => {
                let t = self.t_ms();
                // SAFETY: plain call on a window handle; it returns nothing.
                let r = traced(|| unsafe { SwitchToThisWindow(game, true) });
                let call = Call::done(
                    "SwitchToThisWindow(game, TRUE)",
                    t,
                    Value::Null,
                    r.last_error,
                    Some("returns nothing".to_owned()),
                );
                self.call(method, &mut calls, call);
            }
        }
        self.pump_until(start + AFTER);
        let after = self.state();
        self.pump_until(start + LATE);
        let late = self.state();
        let end = self.t_ms();

        let shell: Vec<ShellMsg> = self
            .shell
            .iter()
            .filter(|s| s.loud && s.t_ms >= t0 && s.t_ms <= end)
            .cloned()
            .collect();
        let first_of = |codes: &[u32]| {
            shell
                .iter()
                .find(|s| s.game && codes.contains(&s.code))
                .map(|s| round1(s.t_ms - t0))
        };
        let flashed_ms = first_of(&[HSHELL_FLASH]);
        let activated_ms = first_of(&[HSHELL_WINDOWACTIVATED, HSHELL_RUDEAPPACTIVATED]);
        let raised = !after.fg_is_game && after.game_above_fg == Some(true);
        let restored = before.game_minimized && !after.game_minimized;
        let result = outcome(
            after.fg_is_game,
            late.fg_is_game,
            raised,
            flashed_ms.is_some(),
        );

        let mut verdict = format!("({}) {}: {}", method.id(), method.name(), result.text());
        if restored {
            verdict.push_str("; restored from minimized");
        }
        if !after.fg_is_game {
            verdict.push_str(&format!("; in front at +300 ms: {}", after.fg_text));
        }
        verdict.push_str(&match (flashed_ms, self.hook.is_some()) {
            (Some(ms), _) => format!("; its taskbar button flashed at {ms:+.0} ms"),
            (None, true) => "; no taskbar flash seen".to_owned(),
            (None, false) => "; flashes unknown (no shell hook)".to_owned(),
        });
        if let Some(ms) = activated_ms {
            verdict.push_str(&format!("; the shell saw it activated at {ms:+.0} ms"));
        }
        verdict.push_str(&format!(
            "; calls: {}",
            calls.iter().map(Call::text).collect::<Vec<_>>().join("; ")
        ));
        let expired = match (before.idle_ms, self.lock_timeout_ms) {
            (Some(idle), Some(lock)) => Some(lock_expired(idle, lock)),
            _ => None,
        };
        if expired == Some(true) {
            verdict.push_str(&format!(
                "; NB the foreground lock had expired (idle {:.1} s, timeout {:.1} s): any process \
                 may take the foreground then",
                f64::from(before.idle_ms.unwrap_or(0)) / 1000.0,
                f64::from(self.lock_timeout_ms.unwrap_or(0)) / 1000.0
            ));
        }
        // A click on the game right after the call would read as the call's success.
        let input_during = [&after, &late]
            .iter()
            .any(|s| input_after(s.idle_ms, s.t_ms - t0));
        if input_during {
            verdict.push_str(
                "; NB keyboard or mouse input during the method: the result may be the owner's, \
                 not the call's",
            );
        }
        let t = self.t_ms();
        self.event(t, "result", verdict.clone(), json!({ "outcome": result }));

        let record = json!({
            "id": method.id(),
            "name": method.name(),
            "outcome": result,
            "in_front": result.in_front(),
            "started_ms": t0,
            "before": before.to_json(),
            "calls": calls.iter().map(Call::to_json).collect::<Vec<_>>(),
            "after_300ms": after.to_json(),
            "after_1s": late.to_json(),
            "restored_from_minimized": restored,
            "game_flash_ms": flashed_ms,
            "game_activated_ms": activated_ms,
            "lock_expired_before": expired,
            "input_during_method": input_during,
            "shell": shell,
            "verdict": verdict,
        });
        MethodRecord {
            method,
            outcome: Some(result),
            verdict,
            record,
        }
    }

    fn summarize(&mut self) {
        let mut verdict: Vec<String> = self.methods.iter().map(|m| m.verdict.clone()).collect();
        let tried = self.methods.iter().filter(|m| m.outcome.is_some()).count();
        let front: Vec<String> = self
            .methods
            .iter()
            .filter(|m| m.outcome.is_some_and(Outcome::in_front))
            .map(|m| format!("({})", m.method.id()))
            .collect();
        if tried > 0 {
            verdict.push(if front.is_empty() {
                format!("none of the {tried} methods tried brought the game to the front")
            } else {
                format!(
                    "brought the game to the front: {} (of {tried} tried)",
                    front.join(", ")
                )
            });
        }
        verdict.push(match self.lock_timeout_ms {
            Some(0) => {
                "ForegroundLockTimeout is 0 on this PC: no foreground lock, any process may \
                        take the foreground; a success here may fail on a PC with the default \
                        (200 000 ms)"
                    .to_owned()
            }
            Some(ms) => {
                format!(
                    "ForegroundLockTimeout {ms} ms (Windows' default {DEFAULT_LOCK_TIMEOUT_MS})"
                )
            }
            None => "ForegroundLockTimeout unread".to_owned(),
        });
        let level = |facts: &Value| {
            format!(
                "{} {}",
                facts["integrity"].as_str().unwrap_or("integrity ?"),
                match facts["elevated"].as_bool() {
                    Some(true) => "elevated",
                    Some(false) => "not elevated",
                    None => "elevation ?",
                }
            )
        };
        if !self.game.is_null() {
            verdict.push(format!(
                "this process: {}; the game: {}",
                level(&self.environment["process"]),
                level(&self.game["process"])
            ));
        }
        let lost = SHELL_LOST.with(Cell::get);
        let by_code: Vec<String> = self
            .shell_by_code
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect();
        verdict.push(if self.hook.is_some() {
            format!(
                "shell hook: {} messages ({}){}",
                self.shell_seen,
                if by_code.is_empty() {
                    "none".to_owned()
                } else {
                    by_code.join(", ")
                },
                if lost > 0 {
                    format!("; {lost} lost")
                } else {
                    String::new()
                }
            )
        } else {
            "shell hook unavailable: flashes could not be seen".to_owned()
        });
        if self.enum_errors > 0 {
            verdict.push(format!(
                "EnumWindows failed {} times: z-order reads were missing there",
                self.enum_errors
            ));
        }

        println!();
        println!("{WHO}: summary");
        for line in &verdict {
            println!("{WHO}:   - {line}");
        }
        self.summary = json!({
            "verdict": verdict,
            "methods": self
                .methods
                .iter()
                .map(|m| json!({ "id": m.method.id(), "outcome": m.outcome }))
                .collect::<Vec<_>>(),
            "shell_messages": {
                "seen": self.shell_seen,
                "by_code": self.shell_by_code,
                "quiet_kept": self.quiet_kept,
                "quiet_dropped": self.quiet_dropped,
                "lost": lost,
            },
            "enum_windows_errors": self.enum_errors,
        });
    }

    fn finish(mut self, outcome: Result<()>) -> Result<()> {
        self.summarize();
        let record = json!({
            "probe": "afklink-capture probe::focus",
            "format": 1,
            "started_local": self.started_local,
            "outcome": match &outcome {
                Ok(()) => "complete".to_owned(),
                Err(error) => format!("{error:#}"),
            },
            "config": {
                "window_class": self.class,
                "out": self.out.display().to_string(),
                "first_wait_s": FIRST_WAIT.as_secs(),
                "next_wait_s": NEXT_WAIT.as_secs(),
                "settle_ms": SETTLE.as_millis() as u64,
                "after_ms": AFTER.as_millis() as u64,
                "late_ms": LATE.as_millis() as u64,
                "pump_ms": PUMP.as_millis() as u64,
                "t0": "t = 0 (every t_ms) is the probe's start; a method's game_flash_ms and \
                    game_activated_ms are ms after its first call",
            },
            "environment": self.environment,
            "game": self.game,
            "summary": self.summary,
            "methods": self.methods.iter().map(|m| m.record.clone()).collect::<Vec<_>>(),
            "events": self.events,
            "shell": self.shell,
            "notes": self.notes,
        });
        let written = write_json(&self.out, &record);
        match &written {
            Ok(()) => println!("{WHO}: written {}", self.out.display()),
            Err(error) => println!("{WHO}: the JSON was not written: {error:#}"),
        }
        match (outcome, written) {
            (Err(error), _) => Err(error),
            (Ok(()), written) => written,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_codes_are_named_and_only_window_codes_are_read_as_windows() {
        assert_eq!(HSHELL_FLASH, 0x8006);
        assert_eq!(HSHELL_RUDEAPPACTIVATED, 0x8004);
        assert_eq!(shell_code_name(0x8006), "FLASH");
        assert_eq!(shell_code_name(0x8004), "RUDEAPPACTIVATED");
        assert_eq!(shell_code_name(4), "WINDOWACTIVATED");
        assert_eq!(shell_code_name(6), "REDRAW");
        assert_eq!(shell_code_name(0x1234), "other");
        assert!(shell_names_window(HSHELL_FLASH));
        assert!(shell_names_window(HSHELL_WINDOWACTIVATED));
        assert!(shell_names_window(HSHELL_RUDEAPPACTIVATED));
        // lParam is a pointer (GETMINRECT) or a keyboard layout (LANGUAGE): never a window.
        assert!(!shell_names_window(HSHELL_GETMINRECT));
        assert!(!shell_names_window(HSHELL_LANGUAGE));
        assert!(!shell_names_window(HSHELL_APPCOMMAND));
        assert!(shell_loud(HSHELL_FLASH) && shell_loud(HSHELL_RUDEAPPACTIVATED));
        assert!(!shell_loud(HSHELL_REDRAW));
    }

    #[test]
    fn a_method_waits_for_another_window_above_the_game_or_the_game_minimized() {
        // Notepad in front, above the game: go.
        assert_eq!(not_ready(0x10, false, false, false, Some(false)), None);
        assert_eq!(
            not_ready(0, false, false, false, None),
            Some(NotReady::NoForeground)
        );
        assert_eq!(
            not_ready(0x10, true, false, false, None),
            Some(NotReady::GameInFront)
        );
        // This terminal in front: its process started the probe, and that passes the focus rules.
        assert_eq!(
            not_ready(0x10, false, true, false, Some(false)),
            Some(NotReady::OursInFront)
        );
        // The last method raised the game above Notepad without the focus: click Notepad again.
        assert_eq!(
            not_ready(0x10, false, false, false, Some(true)),
            Some(NotReady::GameAbove)
        );
        // A minimized game is behind everything, wherever the z-order puts it.
        assert_eq!(not_ready(0x10, false, false, true, Some(true)), None);
        // An unknown z-order does not hold a method back.
        assert_eq!(not_ready(0x10, false, false, false, None), None);
    }

    #[test]
    fn the_z_order_is_top_first() {
        let order = [0x30, 0x10, 0x20];
        assert_eq!(above(&order, 0x30, 0x20), Some(true));
        assert_eq!(above(&order, 0x20, 0x10), Some(false));
        assert_eq!(above(&order, 0x99, 0x10), None);
        assert_eq!(above(&order, 0x10, 0x99), None);
    }

    #[test]
    fn outcomes_rank_front_then_late_then_raised_then_flash() {
        assert_eq!(outcome(true, true, false, false), Outcome::InFront);
        // In front at 300 ms is what counts, whatever came after.
        assert_eq!(outcome(true, false, false, true), Outcome::InFront);
        assert_eq!(outcome(false, true, false, true), Outcome::InFrontLate);
        assert_eq!(
            outcome(false, false, true, true),
            Outcome::RaisedWithoutFocus
        );
        assert_eq!(outcome(false, false, false, true), Outcome::Flashed);
        assert_eq!(outcome(false, false, false, false), Outcome::Nothing);
        assert!(Outcome::InFront.in_front() && Outcome::InFrontLate.in_front());
        assert!(!Outcome::RaisedWithoutFocus.in_front() && !Outcome::Flashed.in_front());
    }

    #[test]
    fn the_lock_expires_after_the_timeout_or_never_locks_at_zero() {
        assert_eq!(idle_since(5_000, 2_000), 3_000);
        // GetTickCount wraps after 49.7 days.
        assert_eq!(idle_since(100, u32::MAX - 99), 200);
        assert!(!lock_expired(3_000, 200_000));
        assert!(lock_expired(200_000, 200_000));
        assert!(lock_expired(250_000, 200_000));
        assert!(lock_expired(0, 0));
        // Idle 120 ms at 300 ms after the call: someone touched something after it.
        assert!(input_after(Some(120), 300.0));
        assert!(!input_after(Some(2_400), 300.0));
        assert!(!input_after(None, 300.0));
    }

    #[test]
    fn parents_are_walked_until_a_reused_pid_or_an_unknown() {
        // test.exe 500 ← cargo.exe 400 ← pwsh 300 ← WindowsTerminal 200 ← explorer 100 ← 4 (System,
        // creation unreadable).
        let parent = |pid: u32| match pid {
            500 => Some(400),
            400 => Some(300),
            300 => Some(200),
            200 => Some(100),
            100 => Some(4),
            _ => None,
        };
        let created = |pid: u32| match pid {
            500 => Some(50),
            400 => Some(40),
            300 => Some(30),
            200 => Some(20),
            100 => Some(10),
            _ => None,
        };
        assert_eq!(ancestors(500, parent, created), vec![400, 300, 200, 100]);
        // pwsh 300 exited and its pid now names a process started after cargo: not a parent.
        let reused = |pid: u32| match pid {
            300 => Some(45),
            other => created(other),
        };
        assert_eq!(ancestors(500, parent, reused), vec![400]);
        // A loop, and pid 0, end the walk.
        assert_eq!(
            ancestors(1, |p| Some(if p == 1 { 2 } else { 1 }), |_| Some(0)),
            vec![2]
        );
        assert!(ancestors(7, |_| Some(0), |_| Some(0)).is_empty());
        assert!(ancestors(7, |_| None, |_| Some(0)).is_empty());
    }

    #[test]
    fn classes_match_whole_and_errors_read_with_their_code() {
        assert!(class_is(
            "ScrydeGameUnrealWWindowsViewportWindow",
            "scrydegameunrealwwindowsviewportwindow"
        ));
        assert!(!class_is(
            "ScrydeGameUnrealWWindowsViewportWindow",
            "ScrydeGame"
        ));
        assert_eq!(win32_text(0), "0");
        assert!(win32_text(5).starts_with("5 (0x5) "), "{}", win32_text(5));
    }

    #[test]
    fn methods_are_four_in_order_with_distinct_names() {
        let ids: Vec<&str> = Method::ALL.iter().map(|m| m.id()).collect();
        assert_eq!(ids, ["a", "b", "c", "d"]);
        let names: HashSet<&str> = Method::ALL.iter().map(|m| m.name()).collect();
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn a_call_reads_as_api_result_and_error() {
        let done = Call::done("SetForegroundWindow(game)", 1.0, json!(false), 0, None);
        assert_eq!(
            done.text(),
            "SetForegroundWindow(game) → false, last error 0"
        );
        let nothing = Call::done("SwitchToThisWindow(game, TRUE)", 1.0, Value::Null, 0, None);
        assert!(nothing.text().contains("(no value)"));
        let skipped = Call::skipped("ShowWindow(game, SW_RESTORE)", 1.0, "not minimized");
        assert_eq!(
            skipped.text(),
            "ShowWindow(game, SW_RESTORE) skipped (not minimized)"
        );
        assert_eq!(skipped.to_json()["skipped"], json!("not minimized"));
    }
}
