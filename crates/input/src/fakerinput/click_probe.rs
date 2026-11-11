//! A hand-run check: the viewer's absolute position (`m`) through the production router
//! ([`FakerInputInjector`], the real driver) goes as FakerInput's absolute report (report 4), the
//! buttons stay on the relative report's collection (report 3), and a button right after an `m`
//! waits for the `m` to show, so it cannot click where the cursor was.
//!
//! **It moves the cursor and presses the left mouse button** — over Notepad's text, nowhere else.
//! The foreground must be `notepad.exe` and every point it moves to, presses at or drags through
//! must be Notepad's text control (`Edit` or `RichEditD2DPT`) on the primary monitor, checked again
//! before every press and drag step; a failure stops the run with everything released. A click
//! moves the caret and a drag selects text: nothing is typed or deleted.
//!
//! Run it by hand from an **unelevated** terminal with no AFKLink session live and the hands off
//! the mouse: open Notepad big on the primary monitor with a few lines of text (for the
//! administrator case, `Start-Process notepad -Verb RunAs`), then from `agent\`:
//!
//! ```text
//! cargo test -p afklink-input --release click_probe -- --ignored --nocapture
//! ```
//!
//! and focus Notepad within two minutes; three seconds later it runs for about eight seconds.
//!
//! What it does, all through `FakerInputInjector::inject` except `click_raw`:
//!
//! * `position` — twelve `m` onto pixel centres over the text: each must land within
//!   [`LAND_TIMEOUT`];
//! * `click_after_move` — [`TRIALS`] taps as the tablet mode sends them (`m`, `d` at once, `u`
//!   [`HOLD`] later): a raw-input sink must hear the report-4 move before the button, and the
//!   button's `WM_INPUT` must carry the new point (`MSG.pt`). The router's waits are in its
//!   `cursor sync` line (`order_waits`, `order_wait_max_ms`, `order_timeouts`);
//! * `click_raw` — the same taps written straight to the device with no wait; informational only;
//! * `drag` — `m`, `d`, [`DRAG_STEPS`] moves [`DRAG_GAP`] apart, `u`: the press lands at the start,
//!   every move comes with the button down, the release lands at the end, and Notepad's selection
//!   (`EM_GETSEL`) is not empty.
//!
//! The record goes to `agent\target\click-probe-<yyyymmdd-hhmmss>.json` (`AFK_PROBE_OUT`
//! overrides) with every raw event; stdout has a summary and this crate's `debug` lines. The test
//! fails when `position`, `click_after_move` or `drag` does.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use afklink_core::sync::lock;
use afklink_core::traits::InputInjector;
use afklink_protocol::InputMessage;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use windows::Win32::Foundation::{HWND, LPARAM, POINT, RECT, WPARAM};
use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod, TIMERR_NOERROR};
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::Win32::UI::HiDpi::{
    GetAwarenessFromDpiAwarenessContext, GetThreadDpiAwarenessContext,
    SetProcessDpiAwarenessContext, SetThreadDpiAwarenessContext,
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, DPI_AWARENESS_PER_MONITOR_AWARE,
};
use windows::Win32::UI::Input::MOUSE_MOVE_ABSOLUTE;
use windows::Win32::UI::WindowsAndMessaging::{
    GetClassNameW, GetWindowRect, SendMessageTimeoutW, WindowFromPoint, RI_MOUSE_LEFT_BUTTON_DOWN,
    RI_MOUSE_LEFT_BUTTON_UP, SMTO_ABORTIFHUNG,
};

use super::mouse_probe::{
    cursor_pos, foreground, local_time, primary_monitor, process_exe, process_facts, rect,
    set_cursor, us_between, window_pid, Pt, RawEvent, RawSink,
};
use super::{platform, FakerInputInjector, Target};

/// How long the probe waits for Notepad to take the foreground.
const WAIT_FOR_NOTEPAD: Duration = Duration::from_secs(120);
const WAIT_PRINT_EVERY: Duration = Duration::from_secs(5);
const COUNTDOWN_S: u64 = 3;
/// The run, from the first move to the last, may not take longer.
const RUN_BUDGET: Duration = Duration::from_secs(40);
/// How long `position` waits for the cursor to reach the pixel.
const LAND_TIMEOUT: Duration = Duration::from_millis(100);
/// How long a tap holds the button: past the router's 30 ms minimum hold, so no tap deferral
/// muddles the release.
const HOLD: Duration = Duration::from_millis(40);
/// The pause after each move or tap. Successive taps are hundreds of pixels apart, so no two make a
/// double click.
const SETTLE: Duration = Duration::from_millis(120);
const GRID: (i32, i32) = (4, 3);
const TRIALS: usize = 16;
const DRAG_STEPS: i32 = 12;
/// The viewer's pace: one `m` per animation frame.
const DRAG_GAP: Duration = Duration::from_millis(16);
/// The router's queue must drain within this after a tap or the drag.
const DRAIN: Duration = Duration::from_millis(500);
/// The text area, after its margins and on the primary monitor, must be at least this big (px).
const MIN_AREA: (i32, i32) = (300, 120);
/// Notepad's text control: the classic `Edit`, or the new Notepad's rich edit.
const TEXT_CLASSES: [&str; 3] = ["Edit", "RichEditD2DPT", "RichEdit20W"];
/// `EM_GETSEL` (winuser.h): with both parameters 0 it answers the selection packed, start in the low
/// word and end in the high one, so no pointer crosses the process boundary.
const EM_GETSEL: u32 = 0x00B0;
/// The notepad the probe drives.
const NOTEPAD_EXE: &str = "notepad.exe";

#[test]
#[ignore = "moves the cursor and presses the left mouse button, over Notepad's text only; run by \
            hand with the owner, see the module docs"]
fn click_probe() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("afklink_input=debug"));
    let _log = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::io::stdout)
            .finish(),
    );
    let out = output_path()?;
    say(format!("output {}", out.display()));
    let mut probe = Probe::new();
    let outcome = probe.run();
    probe.finish(outcome, &out)
}

fn say(line: String) {
    println!("click_probe: {line}");
}

/// `AFK_PROBE_OUT`, else `agent\target\click-probe-<local time>.json`.
fn output_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("AFK_PROBE_OUT").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    // SAFETY: returns a value; no pointers.
    let now = unsafe { GetLocalTime() };
    let stamp = format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond
    );
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("the crate directory has no workspace two levels above it")?;
    Ok(workspace
        .join("target")
        .join(format!("click-probe-{stamp}.json")))
}

/// The Notepad window the probe drives.
#[derive(Clone, Debug, Serialize)]
struct Notepad {
    hwnd: usize,
    pid: u32,
    exe: String,
    /// Its text control under the middle of the area, and that control's class.
    text: usize,
    text_class: String,
}

/// One `m` of `position`.
#[derive(Serialize, Debug)]
struct Landing {
    point: Pt,
    /// Where `GetCursorPos` saw the cursor last, and how long after the `m` it got there.
    seen: Option<Pt>,
    after_us: Option<i64>,
    ok: bool,
}

/// One tap of `click_after_move` or `click_raw`, and what the raw-input sink heard of it.
#[derive(Serialize, Debug)]
struct Tap {
    point: Pt,
    /// The cursor before the tap.
    from: Option<Pt>,
    /// µs since the run began: the tap's first call, the move written, the press asked for (the
    /// router may send it a moment later), the end of the tap's window.
    start_us: i64,
    move_written_us: i64,
    press_called_us: i64,
    end_us: i64,
    /// The first absolute move (report 4) and the first left-button press and release heard in the
    /// window, µs since the run began, in the sink's order.
    move_heard_us: Option<i64>,
    press_heard_us: Option<i64>,
    release_heard_us: Option<i64>,
    /// Where the cursor was when Windows posted the press and the release (`MSG.pt`).
    press_at: Option<Pt>,
    release_at: Option<Pt>,
    /// The raw-input devices the move and the press came from (two collections: two mice).
    move_device: Option<String>,
    press_device: Option<String>,
    /// Windows processed the move before the press.
    move_first: Option<bool>,
    /// The press landed on the point.
    landed: bool,
    #[serde(skip)]
    start: Instant,
    #[serde(skip)]
    end: Instant,
}

/// The drag, and what the sink heard of it.
#[derive(Serialize, Debug)]
struct Drag {
    from: Pt,
    to: Pt,
    start_us: i64,
    end_us: i64,
    press_at: Option<Pt>,
    release_at: Option<Pt>,
    /// Absolute moves heard between the press and the release.
    moves_while_down: usize,
    /// Left-button presses and releases heard in the window: one of each, or report 4 released the
    /// button on its own.
    presses: usize,
    releases: usize,
    /// Notepad's selection afterwards (`EM_GETSEL`), or why it could not be read.
    selection: Value,
    ok: bool,
    #[serde(skip)]
    start: Instant,
    #[serde(skip)]
    end: Instant,
}

/// Everything one run records.
struct Probe {
    started_local: String,
    environment: Value,
    driver: Value,
    notepad: Value,
    area: Value,
    cursor: Value,
    notes: Vec<String>,
    position: Vec<Landing>,
    click_after_move: Vec<Tap>,
    click_raw: Vec<Tap>,
    drag: Option<Drag>,
    raw_events: Vec<Value>,
    summary: Value,
}

fn note(notes: &mut Vec<String>, line: String) {
    say(line.clone());
    notes.push(line);
}

/// `timeBeginPeriod(1)` for the run, as a live session has it (`afklink-transport`'s timer): the
/// router's waiting button and the probe's paced moves wake on time. Ended on drop.
struct Period(bool);

impl Drop for Period {
    fn drop(&mut self) {
        if self.0 {
            // SAFETY: balances the `timeBeginPeriod(1)` that set this.
            let ended = unsafe { timeEndPeriod(1) };
            if ended != TIMERR_NOERROR {
                say(format!("timeEndPeriod(1) returned {ended}"));
            }
        }
    }
}

/// What the run drives with, and the checks it makes before each move and press.
struct Run<'a> {
    injector: &'a FakerInputInjector,
    notepad: Notepad,
    primary: RECT,
    epoch: Instant,
    deadline: Instant,
}

impl Probe {
    fn new() -> Self {
        Self {
            started_local: local_time(),
            environment: Value::Null,
            driver: Value::Null,
            notepad: Value::Null,
            area: Value::Null,
            cursor: Value::Null,
            notes: Vec::new(),
            position: Vec::new(),
            click_after_move: Vec::new(),
            click_raw: Vec::new(),
            drag: None,
            raw_events: Vec::new(),
            summary: Value::Null,
        }
    }

    fn run(&mut self) -> Result<()> {
        // Physical pixels from here on, in this thread and the ones the injector and the sink start.
        self.environment = dpi_awareness(&mut self.notes);
        let (width, height) = platform::screen_size();
        self.environment["screen"] = json!([width, height]);
        // SAFETY: plain call.
        let own = process_facts(unsafe { GetCurrentProcessId() });
        if own["elevated"] == json!(true) {
            note(
                &mut self.notes,
                "this probe runs elevated; the agent does not — run it from an unelevated terminal \
                 for a faithful answer"
                    .to_owned(),
            );
        }
        self.environment["process"] = own;

        let desktop = platform::evaluate_target();
        self.driver =
            json!({ "hid_target": format!("{:?}", desktop.target), "reason": desktop.reason });
        ensure!(
            desktop.target == Target::Allowed,
            "HID may not drive this desktop ({:?}: {}); nothing was moved",
            desktop.target,
            desktop.reason
        );
        let injector = FakerInputInjector::connect()?
            .ok_or_else(|| anyhow!("FakerInput is not installed; nothing was moved"))?;
        self.driver["outcome"] = json!("opened: API v1");
        // The planner says the pointer settings it works with, on stdout.
        injector.fallback.cursor_sync_begin();

        let notepad_window = wait_for_notepad()?;
        let primary = primary_monitor(&mut self.notes);
        let (area, notepad) = text_area(notepad_window, primary)?;
        self.notepad = json!({
            "window": notepad,
            "process": process_facts(notepad.pid),
        });
        say(format!(
            "Notepad {} (pid {}), text control {:#x} ({}), area {:?}; process {}",
            notepad.exe,
            notepad.pid,
            notepad.text,
            notepad.text_class,
            rect(area),
            self.notepad["process"]
        ));
        self.area = json!({ "rect": rect(area), "primary": rect(primary) });

        let points = Points::over(area);
        for p in points.all() {
            check_point(p, &notepad).map_err(|why| {
                anyhow!(
                    "{why}; nothing was moved (make Notepad bigger and keep its text area under \
                     every point)"
                )
            })?;
        }
        for left in (1..=COUNTDOWN_S).rev() {
            say(format!("starting in {left} s — hands off the mouse"));
            std::thread::sleep(Duration::from_secs(1));
        }
        let before = cursor_pos().map_err(|e| anyhow!("reading the cursor: {e}"))?;
        self.cursor = json!({ "before": before });

        let sink =
            RawSink::start().map_err(|e| anyhow!("the raw-input sink did not start: {e}"))?;
        // SAFETY: plain call; balanced by `Period`'s drop.
        let period = unsafe { timeBeginPeriod(1) };
        let _period = Period(period == TIMERR_NOERROR);
        if period != TIMERR_NOERROR {
            note(
                &mut self.notes,
                format!("timeBeginPeriod(1) returned {period}: waits may run long"),
            );
        }

        let epoch = Instant::now();
        let run = Run {
            injector: &injector,
            notepad: notepad.clone(),
            primary,
            epoch,
            deadline: epoch + RUN_BUDGET,
        };
        let outcome = run.all(&points, self);

        // Whatever happened: nothing held, the cursor back, the planner's last line.
        injector.release_all();
        let restore = set_cursor(before);
        let restored_by = if restore.ok {
            "SetCursorPos".to_owned()
        } else {
            let (x, y) = run.fraction(before);
            match injector.inject(&InputMessage::Move { x, y }) {
                Ok(()) => format!("the router's m (SetCursorPos refused: {})", restore.result),
                Err(error) => format!("not restored: {error:#}"),
            }
        };
        std::thread::sleep(Duration::from_millis(50));
        let end = cursor_pos();
        say(format!(
            "cursor put back to {before:?} by {restored_by}; now at {end:?}"
        ));
        self.cursor["end"] = json!(end.as_ref().ok());
        self.cursor["restored_by"] = json!(restored_by);
        injector.fallback.cursor_sync_end();

        let (events, errors) = sink.stop();
        for error in errors {
            note(&mut self.notes, format!("raw input: {error}"));
        }
        self.analyse(&events, epoch);
        outcome
    }

    /// Match what the sink heard to each tap and to the drag, and sum it up.
    fn analyse(&mut self, events: &[RawEvent], epoch: Instant) {
        for tap in self.click_after_move.iter_mut().chain(&mut self.click_raw) {
            analyse_tap(tap, events, epoch);
        }
        if let Some(drag) = self.drag.as_mut() {
            analyse_drag(drag, events);
        }
        self.raw_events = events
            .iter()
            .map(|e| {
                json!({
                    "t_us": us_between(epoch, e.at),
                    "flags": e.flags,
                    "x": e.x,
                    "y": e.y,
                    "buttons": e.buttons,
                    "device": format!("{:#x}", e.device),
                    "pt": e.pt,
                })
            })
            .collect();
        let taps = |taps: &[Tap]| {
            json!({
                "taps": taps.len(),
                "landed": taps.iter().filter(|t| t.landed).count(),
                "move_first": taps.iter().filter(|t| t.move_first == Some(true)).count(),
                "press_first": taps.iter().filter(|t| t.move_first == Some(false)).count(),
                "unheard": taps.iter().filter(|t| t.move_first.is_none()).count(),
            })
        };
        self.summary = json!({
            "position": {
                "moves": self.position.len(),
                "landed": self.position.iter().filter(|l| l.ok).count(),
            },
            "click_after_move": taps(&self.click_after_move),
            "click_raw": taps(&self.click_raw),
            "drag": self.drag.as_ref().map(|d| json!({
                "ok": d.ok,
                "moves_while_down": d.moves_while_down,
                "presses": d.presses,
                "releases": d.releases,
                "selection": d.selection,
            })),
        });
    }

    /// Print the summary, write the JSON, and answer with the run's outcome and the checks'.
    fn finish(self, outcome: Result<()>, out: &Path) -> Result<()> {
        say(format!("summary {}", self.summary));
        for (name, taps) in [
            ("click_after_move", &self.click_after_move),
            ("click_raw", &self.click_raw),
        ] {
            for (i, t) in taps.iter().enumerate() {
                say(format!(
                    "{name} {i:>2}: {:?} -> press at {:?}, move first {:?}, move→press heard {} µs",
                    t.point,
                    t.press_at,
                    t.move_first,
                    t.press_heard_us
                        .zip(t.move_heard_us)
                        .map_or_else(|| "-".to_owned(), |(p, m)| (p - m).to_string())
                ));
            }
        }
        let failures = self.failures();
        let record = json!({
            "probe": "afklink-input fakerinput::click_probe",
            "format": 1,
            "started_local": self.started_local,
            "outcome": match &outcome {
                Ok(()) if failures.is_empty() => "complete".to_owned(),
                Ok(()) => format!("complete, failed: {}", failures.join("; ")),
                Err(error) => format!("{error:#}"),
            },
            "config": {
                "grid": GRID,
                "trials": TRIALS,
                "hold_ms": HOLD.as_millis() as u64,
                "settle_ms": SETTLE.as_millis() as u64,
                "drag_steps": DRAG_STEPS,
                "drag_gap_ms": DRAG_GAP.as_millis() as u64,
                "land_timeout_ms": LAND_TIMEOUT.as_millis() as u64,
                "run_budget_s": RUN_BUDGET.as_secs(),
                "text_classes": TEXT_CLASSES,
                "m": "InputMessage::Move onto the pixel's centre, (px + 0.5) / width, through FakerInputInjector::inject",
                "click_raw": "State::absolute then State::button(0, true) under one lock, no wait; the release HOLD later",
                "press_at": "the WM_INPUT's MSG.pt: where the cursor was when Windows posted the button",
            },
            "environment": self.environment,
            "driver": self.driver,
            "notepad": self.notepad,
            "area": self.area,
            "cursor": self.cursor,
            "notes": self.notes,
            "summary": self.summary,
            "position": self.position,
            "click_after_move": self.click_after_move,
            "click_raw": self.click_raw,
            "drag": self.drag,
            "raw_events": self.raw_events,
        });
        let written = serde_json::to_string_pretty(&record)
            .context("serializing the probe record")
            .and_then(|text| {
                if let Some(dir) = out.parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
                std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))
            });
        match &written {
            Ok(()) => say(format!("written {}", out.display())),
            Err(error) => say(format!("the JSON was not written: {error:#}")),
        }
        outcome?;
        written?;
        if !failures.is_empty() {
            bail!("failed: {}", failures.join("; "));
        }
        Ok(())
    }

    /// The checks that fail the run (`click_raw` is informational).
    fn failures(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let missed = self.position.iter().filter(|l| !l.ok).count();
        if missed > 0 {
            failures.push(format!(
                "position: {missed} of {} m did not land on their pixel",
                self.position.len()
            ));
        }
        let taps = self.click_after_move.len();
        let order = self
            .click_after_move
            .iter()
            .filter(|t| t.move_first != Some(true))
            .count();
        if order > 0 {
            failures.push(format!(
                "click_after_move: in {order} of {taps} taps the sink did not hear the move before \
                 the press (press first, or either unheard)"
            ));
        }
        let elsewhere = self.click_after_move.iter().filter(|t| !t.landed).count();
        if elsewhere > 0 {
            failures.push(format!(
                "click_after_move: in {elsewhere} of {taps} taps the press was posted with the \
                 cursor elsewhere (MSG.pt, see press_at against point)"
            ));
        }
        if self.drag.as_ref().is_some_and(|d| !d.ok) {
            failures.push("drag: see the record".to_owned());
        }
        failures
    }
}

impl Run<'_> {
    fn all(&self, points: &Points, probe: &mut Probe) -> Result<()> {
        say("position".to_owned());
        for &p in &points.grid {
            probe.position.push(self.land(p)?);
        }
        say("click_after_move".to_owned());
        for &p in &points.taps {
            probe.click_after_move.push(self.tap_router(p)?);
        }
        say("click_raw".to_owned());
        for &p in &points.taps {
            probe.click_raw.push(self.tap_raw(p)?);
        }
        say("drag".to_owned());
        probe.drag = Some(self.drag(&points.drag)?);
        Ok(())
    }

    /// What the viewer's `m` carries for a point: fractions of the primary monitor, onto the pixel's
    /// centre.
    fn fraction(&self, p: Pt) -> (f64, f64) {
        let (w, h) = platform::screen_size();
        (
            (f64::from(p[0] - self.primary.left) + 0.5) / f64::from(w.max(1)),
            (f64::from(p[1] - self.primary.top) + 0.5) / f64::from(h.max(1)),
        )
    }

    fn m(&self, p: Pt) -> Result<()> {
        let (x, y) = self.fraction(p);
        self.injector.inject(&InputMessage::Move { x, y })
    }

    fn button(&self, down: bool) -> Result<()> {
        self.injector.inject(&if down {
            InputMessage::Down { b: 0 }
        } else {
            InputMessage::Up { b: 0 }
        })
    }

    fn us(&self, at: Instant) -> i64 {
        us_between(self.epoch, at)
    }

    /// Before a move or a press: time left, Notepad in front, its text under the point. A failure
    /// releases everything before the run stops.
    fn check(&self, p: Pt) -> Result<()> {
        let result = self.still_safe(p);
        if result.is_err() {
            self.injector.release_all();
        }
        result
    }

    fn still_safe(&self, p: Pt) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "the run passed its {} s budget",
            RUN_BUDGET.as_secs()
        );
        let hwnd = foreground();
        let pid = window_pid(hwnd);
        ensure!(
            pid == self.notepad.pid,
            "the foreground left Notepad (now window {hwnd:#x}, pid {pid})"
        );
        check_point(p, &self.notepad)
    }

    /// Wait until the router's queue is empty (a waiting button has gone).
    fn drain(&self) -> Result<()> {
        let until = Instant::now() + DRAIN;
        loop {
            if !lock(&self.injector.shared.rt).typist.has_work() {
                return Ok(());
            }
            if Instant::now() >= until {
                self.injector.release_all();
                bail!(
                    "the router's queue did not drain within {} ms",
                    DRAIN.as_millis()
                );
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn land(&self, p: Pt) -> Result<Landing> {
        self.check(p)?;
        let t0 = Instant::now();
        self.m(p)?;
        let mut seen = None;
        let mut after_us = None;
        while t0.elapsed() < LAND_TIMEOUT {
            if let Ok(now) = cursor_pos() {
                seen = Some(now);
                if now == p {
                    after_us = Some(us_between(t0, Instant::now()));
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(SETTLE);
        let ok = seen == Some(p);
        if !ok {
            say(format!("position: {p:?} -> {seen:?}"));
        }
        Ok(Landing {
            point: p,
            seen,
            after_us,
            ok,
        })
    }

    fn tap(&self, p: Pt, start: Instant, from: Option<Pt>) -> Tap {
        Tap {
            point: p,
            from,
            start_us: self.us(start),
            move_written_us: 0,
            press_called_us: 0,
            end_us: 0,
            move_heard_us: None,
            press_heard_us: None,
            release_heard_us: None,
            press_at: None,
            release_at: None,
            move_device: None,
            press_device: None,
            move_first: None,
            landed: false,
            start,
            end: start,
        }
    }

    /// A tap of the tablet mode through the router: `m`, `d` at once, `u` a hold later.
    fn tap_router(&self, p: Pt) -> Result<Tap> {
        self.check(p)?;
        let start = Instant::now();
        let mut tap = self.tap(p, start, cursor_pos().ok());
        self.m(p)?;
        tap.move_written_us = self.us(Instant::now());
        self.button(true)?;
        tap.press_called_us = self.us(Instant::now());
        std::thread::sleep(HOLD);
        self.button(false)?;
        self.drain()?;
        std::thread::sleep(SETTLE);
        tap.end = Instant::now();
        tap.end_us = self.us(tap.end);
        Ok(tap)
    }

    /// The same tap written straight to the device: report 4, then report 3's press, back to back.
    fn tap_raw(&self, p: Pt) -> Result<Tap> {
        self.check(p)?;
        let start = Instant::now();
        let mut tap = self.tap(p, start, cursor_pos().ok());
        let (w, h) = platform::screen_size();
        {
            let mut rt = lock(&self.injector.shared.rt);
            rt.state
                .absolute(p[0] - self.primary.left, p[1] - self.primary.top, w, h)?;
            tap.move_written_us = self.us(Instant::now());
            rt.state.button(0, true)?;
            tap.press_called_us = self.us(Instant::now());
        }
        std::thread::sleep(HOLD);
        lock(&self.injector.shared.rt).state.button(0, false)?;
        std::thread::sleep(SETTLE);
        tap.end = Instant::now();
        tap.end_us = self.us(tap.end);
        Ok(tap)
    }

    /// A drag through the router: `m` onto the start, `d`, the moves a frame apart, `u` right after
    /// the last.
    fn drag(&self, path: &[Pt]) -> Result<Drag> {
        let (Some(&from), Some(&to)) = (path.first(), path.last()) else {
            bail!("no drag path");
        };
        self.check(from)?;
        let start = Instant::now();
        self.m(from)?;
        self.button(true)?;
        for &p in &path[1..] {
            std::thread::sleep(DRAG_GAP);
            self.check(p)?;
            self.m(p)?;
        }
        self.button(false)?;
        self.drain()?;
        std::thread::sleep(SETTLE);
        let end = Instant::now();
        Ok(Drag {
            from,
            to,
            start_us: self.us(start),
            end_us: self.us(end),
            press_at: None,
            release_at: None,
            moves_while_down: 0,
            presses: 0,
            releases: 0,
            selection: selection(self.notepad.text),
            ok: false,
            start,
            end,
        })
    }
}

/// The points: a grid for `position`, taps alternating between two columns far apart (rows
/// spread), and a line across the middle for the drag. All inside the text area.
struct Points {
    grid: Vec<Pt>,
    taps: Vec<Pt>,
    drag: Vec<Pt>,
}

impl Points {
    fn over(area: RECT) -> Self {
        let (w, h) = (area.right - area.left, area.bottom - area.top);
        let grid = (0..GRID.1)
            .flat_map(|row| {
                (0..GRID.0).map(move |col| {
                    [
                        area.left + (2 * col + 1) * w / (2 * GRID.0),
                        area.top + (2 * row + 1) * h / (2 * GRID.1),
                    ]
                })
            })
            .collect();
        let (left, right) = (area.left + w / 10, area.right - 1 - w / 10);
        let taps = (0..TRIALS)
            .map(|i| {
                let row = i32::try_from((i / 2) % 4).unwrap_or(0);
                [
                    if i % 2 == 0 { left } else { right },
                    area.top + (2 * row + 1) * h / 8,
                ]
            })
            .collect();
        let y = area.top + h / 2;
        let drag = (0..=DRAG_STEPS)
            .map(|i| [left + (right - left) * i / DRAG_STEPS, y])
            .collect();
        Self { grid, taps, drag }
    }

    fn all(&self) -> impl Iterator<Item = Pt> + '_ {
        self.grid
            .iter()
            .chain(&self.taps)
            .chain(&self.drag)
            .copied()
    }
}

/// Per-monitor DPI awareness for the process (so the threads the injector and the sink start have
/// it too) and this thread; what it was before and after.
fn dpi_awareness(notes: &mut Vec<String>) -> Value {
    let awareness = || {
        // SAFETY: plain calls on the thread's own context.
        unsafe { GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext()) }.0
    };
    let before = awareness();
    // SAFETY: plain call with a predefined context.
    let set = unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    if awareness() != DPI_AWARENESS_PER_MONITOR_AWARE.0 {
        // SAFETY: plain call with a predefined context.
        let previous =
            unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        if previous.0.is_null() {
            note(
                notes,
                format!(
                    "SetThreadDpiAwarenessContext failed: {}",
                    std::io::Error::last_os_error()
                ),
            );
        }
    }
    let after = awareness();
    if after != DPI_AWARENESS_PER_MONITOR_AWARE.0 {
        note(
            notes,
            format!("not per-monitor DPI aware ({after}): coordinates may be scaled"),
        );
    }
    json!({
        "awareness_before": before,
        "set_process_dpi_awareness_context": set.as_ref().map_or_else(ToString::to_string, |_| "ok".to_owned()),
        "awareness": after,
    })
}

/// Wait (up to [`WAIT_FOR_NOTEPAD`]) for Notepad to be the foreground window: its window, pid and
/// exe. Any other foreground is waited out, never driven.
fn wait_for_notepad() -> Result<(usize, u32, String)> {
    say(format!(
        "waiting up to {} s for Notepad ({NOTEPAD_EXE}) in the foreground — focus it now. \
         Switching away during the run stops it.",
        WAIT_FOR_NOTEPAD.as_secs()
    ));
    let begun = Instant::now();
    let mut printed = begun;
    loop {
        let hwnd = foreground();
        let pid = window_pid(hwnd);
        let exe = process_exe(pid);
        if hwnd != 0
            && exe
                .name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(NOTEPAD_EXE))
        {
            return Ok((hwnd, pid, exe.label()));
        }
        if begun.elapsed() >= WAIT_FOR_NOTEPAD {
            bail!(
                "Notepad was not in the foreground within {} s (the last: {} pid {pid}); nothing \
                 was moved",
                WAIT_FOR_NOTEPAD.as_secs(),
                exe.label()
            );
        }
        if printed.elapsed() >= WAIT_PRINT_EVERY {
            printed = Instant::now();
            say(format!(
                "still waiting; in the foreground: {} (pid {pid}{})",
                exe.label(),
                exe.error
                    .as_deref()
                    .map_or(String::new(), |e| format!("; {e}"))
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The class of a window.
fn class_name(hwnd: HWND) -> String {
    let mut class = [0u16; 256];
    // SAFETY: a live buffer; the call writes at most its length.
    let n = unsafe { GetClassNameW(hwnd, &mut class) };
    String::from_utf16_lossy(&class[..usize::try_from(n).unwrap_or(0)])
}

/// Notepad's text control under a point, if that is what is there: the window `WindowFromPoint`
/// gives, of Notepad's process and of a text class.
fn text_control_at(p: Pt, pid: u32) -> std::result::Result<(usize, String), String> {
    // SAFETY: plain call.
    let hwnd = unsafe { WindowFromPoint(POINT { x: p[0], y: p[1] }) };
    if hwnd.0.is_null() {
        return Err(format!("no window under {p:?}"));
    }
    let owner = window_pid(hwnd.0 as usize);
    let class = class_name(hwnd);
    if owner != pid {
        return Err(format!(
            "the window under {p:?} is not Notepad's ({class}, pid {owner})"
        ));
    }
    if !TEXT_CLASSES.contains(&class.as_str()) {
        return Err(format!(
            "the window under {p:?} is Notepad's {class}, not its text"
        ));
    }
    Ok((hwnd.0 as usize, class))
}

/// Before any press: the point is over Notepad's text.
fn check_point(p: Pt, notepad: &Notepad) -> Result<()> {
    text_control_at(p, notepad.pid)
        .map(|_| ())
        .map_err(|why| anyhow!("refused: {why}"))
}

/// The text control under the middle of Notepad's window, and the part of it the probe uses: its
/// rectangle less 15 % (at least 24 px) on every side — clear of scroll bars and edges — on the
/// primary monitor (report 4 maps onto that one alone).
fn text_area((hwnd, pid, exe): (usize, u32, String), primary: RECT) -> Result<(RECT, Notepad)> {
    let mut window = RECT::default();
    // SAFETY: a live RECT.
    unsafe { GetWindowRect(HWND(hwnd as *mut c_void), &mut window) }
        .context("GetWindowRect of Notepad")?;
    let centre = [
        (window.left + window.right) / 2,
        (window.top + window.bottom) / 2,
    ];
    let (text, text_class) = text_control_at(centre, pid).map_err(|why| {
        anyhow!("{why}: put Notepad's text under the middle of its window; nothing was moved")
    })?;
    let mut r = RECT::default();
    // SAFETY: a live RECT.
    unsafe { GetWindowRect(HWND(text as *mut c_void), &mut r) }
        .context("GetWindowRect of Notepad's text")?;
    let (w, h) = (r.right - r.left, r.bottom - r.top);
    let (ix, iy) = ((w * 15 / 100).max(24), (h * 15 / 100).max(24));
    let area = RECT {
        left: (r.left + ix).max(primary.left + 8),
        top: (r.top + iy).max(primary.top + 8),
        right: (r.right - ix).min(primary.right - 8),
        bottom: (r.bottom - iy).min(primary.bottom - 8),
    };
    ensure!(
        area.right - area.left >= MIN_AREA.0 && area.bottom - area.top >= MIN_AREA.1,
        "Notepad's text on the primary monitor is too small ({:?}, at least {MIN_AREA:?} needed): \
         make the window bigger; nothing was moved",
        rect(area)
    );
    Ok((
        area,
        Notepad {
            hwnd,
            pid,
            exe,
            text,
            text_class,
        },
    ))
}

/// Notepad's selection (`EM_GETSEL`, answered packed: nothing crosses the process boundary but the
/// number), or why it could not be read.
fn selection(text: usize) -> Value {
    let mut answer = 0usize;
    // SAFETY: a plain message with no pointer parameters; `answer` is a live usize.
    let sent = unsafe {
        SendMessageTimeoutW(
            HWND(text as *mut c_void),
            EM_GETSEL,
            WPARAM(0),
            LPARAM(0),
            SMTO_ABORTIFHUNG,
            200,
            Some(&mut answer),
        )
    };
    if sent.0 == 0 {
        return json!({
            "error": format!("SendMessageTimeoutW(EM_GETSEL): {}", std::io::Error::last_os_error())
        });
    }
    let packed = answer as u32;
    if packed == u32::MAX {
        return json!({ "note": "past 65535 characters: EM_GETSEL cannot say" });
    }
    let (start, end) = (packed & 0xffff, packed >> 16);
    json!({ "start": start, "end": end, "chars": end.saturating_sub(start) })
}

fn is_move(e: &RawEvent) -> bool {
    e.flags & MOUSE_MOVE_ABSOLUTE.0 != 0
}

fn is_press(e: &RawEvent) -> bool {
    u32::from(e.buttons) & RI_MOUSE_LEFT_BUTTON_DOWN != 0
}

fn is_release(e: &RawEvent) -> bool {
    u32::from(e.buttons) & RI_MOUSE_LEFT_BUTTON_UP != 0
}

/// A tap's events, in the order Windows processed them: the first absolute move, the first press
/// and the first release after it.
fn analyse_tap(tap: &mut Tap, events: &[RawEvent], epoch: Instant) {
    let window: Vec<(usize, &RawEvent)> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| e.at >= tap.start && e.at < tap.end)
        .collect();
    let first = |f: fn(&RawEvent) -> bool| window.iter().find(|(_, e)| f(e)).copied();
    let moved = first(is_move);
    let press = first(is_press);
    let release = press.and_then(|(i, _)| {
        window
            .iter()
            .find(|(j, e)| *j > i && is_release(e))
            .copied()
    });
    tap.move_heard_us = moved.map(|(_, e)| us_between(epoch, e.at));
    tap.press_heard_us = press.map(|(_, e)| us_between(epoch, e.at));
    tap.release_heard_us = release.map(|(_, e)| us_between(epoch, e.at));
    tap.move_device = moved.map(|(_, e)| format!("{:#x}", e.device));
    tap.press_device = press.map(|(_, e)| format!("{:#x}", e.device));
    tap.press_at = press.map(|(_, e)| e.pt);
    tap.release_at = release.map(|(_, e)| e.pt);
    tap.move_first = moved.zip(press).map(|((m, _), (p, _))| m < p);
    tap.landed = tap.press_at == Some(tap.point);
}

/// The drag's events: one press at the start, the moves while the button is down, one release at
/// the end — report 4 (button field 0) releasing nothing on its own.
fn analyse_drag(drag: &mut Drag, events: &[RawEvent]) {
    let window: Vec<&RawEvent> = events
        .iter()
        .filter(|e| e.at >= drag.start && e.at < drag.end)
        .collect();
    let press = window.iter().position(|e| is_press(e));
    let release = window.iter().rposition(|e| is_release(e));
    drag.presses = window.iter().filter(|e| is_press(e)).count();
    drag.releases = window.iter().filter(|e| is_release(e)).count();
    drag.press_at = press.map(|i| window[i].pt);
    drag.release_at = release.map(|i| window[i].pt);
    drag.moves_while_down = match (press, release) {
        (Some(p), Some(r)) if p < r => window[p..r].iter().filter(|e| is_move(e)).count(),
        _ => 0,
    };
    let steps = usize::try_from(DRAG_STEPS).unwrap_or(0);
    drag.ok = drag.presses == 1
        && drag.releases == 1
        && drag.press_at == Some(drag.from)
        && drag.release_at == Some(drag.to)
        && drag.moves_while_down >= steps;
}

// The pure parts, checked without moving anything.

#[test]
fn the_points_stay_inside_the_area_and_taps_alternate_far_apart() {
    let area = RECT {
        left: 100,
        top: 200,
        right: 1300,
        bottom: 900,
    };
    let points = Points::over(area);
    assert_eq!(points.grid.len(), 12);
    assert_eq!(points.taps.len(), TRIALS);
    assert_eq!(
        points.drag.len(),
        usize::try_from(DRAG_STEPS).unwrap_or(0) + 1
    );
    for p in points.all() {
        assert!(
            (area.left..area.right).contains(&p[0]) && (area.top..area.bottom).contains(&p[1]),
            "{p:?}"
        );
    }
    for pair in points.taps.windows(2) {
        assert!(
            (pair[0][0] - pair[1][0]).abs() >= 900,
            "no double click: {pair:?}"
        );
    }
    assert_eq!(points.drag.first(), Some(&[220, 550]));
    assert_eq!(points.drag.last(), Some(&[1179, 550]));
}

#[test]
fn a_tap_is_judged_by_the_sinks_order_and_the_press_point() {
    let t0 = Instant::now();
    let at = |ms: u64| t0 + Duration::from_millis(ms);
    let event = |ms: u64, flags: u16, buttons: u16, device: usize, pt: Pt| RawEvent {
        at: at(ms),
        flags,
        x: 0,
        y: 0,
        buttons,
        device,
        extra: 0,
        pt,
    };
    let abs = MOUSE_MOVE_ABSOLUTE.0;
    let (down, up) = (
        u16::try_from(RI_MOUSE_LEFT_BUTTON_DOWN).unwrap_or(0),
        u16::try_from(RI_MOUSE_LEFT_BUTTON_UP).unwrap_or(0),
    );
    let tap = |point: Pt| Tap {
        point,
        from: None,
        start_us: 0,
        move_written_us: 0,
        press_called_us: 0,
        end_us: 0,
        move_heard_us: None,
        press_heard_us: None,
        release_heard_us: None,
        press_at: None,
        release_at: None,
        move_device: None,
        press_device: None,
        move_first: None,
        landed: false,
        start: at(10),
        end: at(100),
    };
    // The move, then the press at the new point: right. An event outside the window is ignored.
    let good = [
        event(5, 0, down, 3, [1, 1]),
        event(11, abs, 0, 4, [500, 400]),
        event(13, 0, down, 3, [500, 400]),
        event(53, 0, up, 3, [500, 400]),
    ];
    let mut t = tap([500, 400]);
    analyse_tap(&mut t, &good, t0);
    assert_eq!(t.move_first, Some(true));
    assert!(t.landed);
    assert_eq!(t.press_device.as_deref(), Some("0x3"));
    assert_eq!(t.move_device.as_deref(), Some("0x4"));
    assert_eq!(t.release_at, Some([500, 400]));
    // The press overtook the move: it landed where the cursor was.
    let overtaken = [
        event(12, 0, down, 3, [100, 100]),
        event(13, abs, 0, 4, [500, 400]),
        event(53, 0, up, 3, [500, 400]),
    ];
    let mut t = tap([500, 400]);
    analyse_tap(&mut t, &overtaken, t0);
    assert_eq!(t.move_first, Some(false));
    assert!(!t.landed);

    // A drag: one press, moves while down, one release at the end.
    let mut drag = Drag {
        from: [100, 500],
        to: [700, 500],
        start_us: 0,
        end_us: 0,
        press_at: None,
        release_at: None,
        moves_while_down: 0,
        presses: 0,
        releases: 0,
        selection: Value::Null,
        ok: false,
        start: at(10),
        end: at(1000),
    };
    let mut events = vec![
        event(11, abs, 0, 4, [100, 500]),
        event(13, 0, down, 3, [100, 500]),
    ];
    for i in 1..=12u64 {
        let x = 100 + 50 * i32::try_from(i).unwrap_or(0);
        events.push(event(13 + 16 * i, abs, 0, 4, [x, 500]));
    }
    events.push(event(300, 0, up, 3, [700, 500]));
    analyse_drag(&mut drag, &events);
    assert!(drag.ok, "{drag:?}");
    assert_eq!(drag.moves_while_down, 12);
    // Report 4 letting the button go on its own would be a second release.
    events.insert(5, event(80, 0, up, 4, [250, 500]));
    analyse_drag(&mut drag, &events);
    assert!(!drag.ok);
    assert_eq!(drag.releases, 2);
}
