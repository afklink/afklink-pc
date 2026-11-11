//! Can this medium-integrity process capture the window of an elevated game with WGC
//! `CreateForWindow`, and what does that capture show while the game is covered, minimized and
//! restored?
//!
//! ## Run it
//!
//! From `agent\`, in an **unelevated** terminal (the agent runs unelevated, and what such a process
//! can capture is the question), with the game running:
//!
//! ```text
//! $env:AFK_PROBE_WINDOW = 'scrydegame'   # substring of the window's class, exe name or title
//! cargo test -p afklink-capture --release --lib window_capture_probe -- --ignored --nocapture
//! ```
//!
//! - `AFK_PROBE_WINDOW` (required): a case-insensitive substring matched against each visible
//!   top-level window's class, its process's exe name and its title. Lineage 2 (Scryde) has class
//!   `ScrydeGameUnrealWWindowsViewportWindow` and exe `ScrydeGame.bin`; `scrydegame` matches both.
//! - `AFK_PROBE_SECONDS`: how long to capture, default 45.
//! - `AFK_PROBE_SECONDARY=1`: also set `IncludeSecondaryWindows` (Windows 11 24H2+), which draws the
//!   game's own pop-ups that overlap its window into the capture. Run once without it and once with.
//! - `AFK_PROBE_OUT`: where the JSON goes (default `agent\target\window-probe-<yyyymmdd-hhmmss>.json`,
//!   local time); the pictures go to the folder of the same name without `.json`.
//!
//! ## What the person at the PC does
//!
//! Nothing at the terminal. The probe prints a numbered checklist and captures for 45 s while the
//! person, by hand: (1) leaves the game in front; (2) puts another window (Notepad) over part of
//! the game, then moves it away; (3) minimizes the game; (4) restores it; (5) opens some in-game
//! dialog, if the game has one, and notes whether a yellow frame showed around the game. The times
//! printed with the checklist are only a pace: every change is logged with its own time, and the
//! phases are mapped afterwards.
//!
//! ## What it does
//!
//! 1. `RoInitialize`, then per-monitor DPI awareness (every rectangle in physical pixels), the OS
//!    build, this process's integrity, any AFKLink process running, and which WGC properties this OS
//!    has (`ApiInformation`).
//! 2. The target: every visible top-level window whose class, exe name or title contains the needle.
//!    With several it lists them, takes the best — a class or exe match before a title-only one, a
//!    window on screen before a minimized or cloaked one, then the largest — and says so. It waits up
//!    to a minute for one. It records the target's hwnd, class, title, pid, parent, exe path
//!    (`QueryFullProcessImageNameW` through a `PROCESS_QUERY_LIMITED_INFORMATION` handle, or the
//!    error), integrity and elevation, window, frame and client rectangles, minimized, DPI, placement.
//! 3. The capture, through the raw WinRT API rather than `windows-capture`, so that each step keeps
//!    its own result: the crate folds a failing `CreateForWindow` into `ItemConvertFailed` and a
//!    refused property into a failed start. The steps and their order are the crate's
//!    (`windows-capture` 2.0.1, `GraphicsCaptureApi::new` and `start_capture`): the D3D11 device,
//!    `IGraphicsCaptureItemInterop::CreateForWindow(hwnd)`, a frame pool (B8G8R8A8, 2 buffers —
//!    free-threaded here, since the crate's `Create` needs a dispatcher queue; the item and the session
//!    are the same either way), `CreateCaptureSession`, the `Closed` and `FrameArrived` handlers,
//!    `IsCursorCaptureEnabled = true`, `IsBorderRequired = false`, `IncludeSecondaryWindows = true`
//!    when asked, `StartCapture`. Each property records whether the OS has it, what setting it
//!    answered and what it reads back. A failed item, pool, session, handler or start ends the run
//!    with that exact error; a refused property does not.
//! 4. While it captures: every frame's arrival time and content size; on a content-size change the
//!    pool is recreated for the new size, as the crate does. A picture — the first frame of every
//!    second, and the first after every size change — is copied off the GPU in the frame handler, then
//!    scaled (box filter, at most 1280 wide, alpha ignored) and written as PNG on a writer thread, with
//!    its mean luma and black share. Every 100 ms the main thread looks at the foreground window, the
//!    target (exists, visible, minimized, cloaked, rectangle) and every window **above** the target in
//!    the z-order that is on screen and overlaps it (exe, class, title, share of the target covered,
//!    whether it is the game's own window or a click-through overlay), and logs every change with its
//!    time. Once a second it records and prints a row: that look, plus the second's frames, sizes and
//!    pictures.
//! 5. At the end it closes the capture, flushes the pictures and writes a summary: did it start,
//!    frames and fps, sizes and size changes, stretches without frames, frames and pictures while the
//!    target was minimized or covered, black pictures, and the properties' outcomes.
//!
//! **It never** injects input, sends a message to the game, changes its focus, z-order or size, asks
//! `GraphicsCaptureAccess` for borderless access (that may prompt), or opens the game's process for
//! more than `PROCESS_QUERY_LIMITED_INFORMATION` (exe path, creation time, and its token for
//! `TOKEN_QUERY`: integrity and elevation). WGC is DWM composition; it does not read the game's memory.
//!
//! ## What to look at
//!
//! `summary.verdict` first (also printed). Then the pictures taken while another window covered the
//! target (`summary.pictures_while_covered`): a leak shows as that window's content inside the game's
//! picture. Black pictures (`mean_luma` near 0) while frames arrive mean WGC hands out frames but not
//! the window's pixels. `capture.steps` has each step's exact error; `seconds` is the timeline,
//! `transitions` every change at 100 ms resolution, `frames.list` every frame as `[t_ms, w, h]`.
//! Throughout, t = 0 is the `StartCapture` call.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use afklink_core::sync::lock;
use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use windows::core::{IInspectable, Interface, HSTRING};
use windows::Foundation::Metadata::ApiInformation;
use windows::Foundation::TypedEventHandler;
use windows::Graphics::Capture::{
    Direct3D11CaptureFrame, Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession,
};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Graphics::SizeInt32;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_10_1,
    D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_9_1, D3D_FEATURE_LEVEL_9_2,
    D3D_FEATURE_LEVEL_9_3,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ,
    D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::System::WinRT::Direct3D11::{
    CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess,
};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};

use super::win::{
    env_text, error_text, hex, hwnd_of, local_time, make_dpi_aware, note, now_filetime, os_version,
    output_path, own_process, process_facts, snapshot, top_level_windows, window_alive,
    window_extra, window_facts, window_visible, write_json, ExeNames, WinFacts,
};
use super::{
    clip, covered_fraction, downscale_bgra_to_rgb, fit_width, frame_gaps, intersect, match_window,
    ms, needle_of, parse_flag, parse_seconds, per_second_counts, pick_candidate, picture_stats,
    rect_text, Candidate, Matched, PictureStats, Rect,
};

const WHO: &str = "window_capture_probe";
const DEFAULT_SECONDS: u64 = 45;
/// How long the probe waits for a matching window to appear.
const WAIT_FOR_WINDOW: Duration = Duration::from_secs(60);
const WAIT_PRINT_EVERY: Duration = Duration::from_secs(5);
/// How often the main thread looks at the foreground, the target and what covers it.
const TICK: Duration = Duration::from_millis(100);
const PICTURE_MAX_WIDTH: u32 = 1280;
/// Frame pool buffers (the crate uses 1; 2 lets a frame arrive while the handler still holds one).
const POOL_BUFFERS: i32 = 2;
/// Stretches without a frame longer than this are listed.
const GAP_US: i64 = 250_000;
/// Frame-handler errors kept word for word; the rest are counted.
const ERRORS_KEPT: usize = 50;
/// Pictures waiting for the writer; one more is skipped (and says so) rather than stall the handler.
const PICTURE_QUEUE: usize = 4;
/// A picture this dark on average counts as black in the verdict.
const BLACK_LUMA: f64 = 4.0;
/// The checklist, and where each step's suggested stretch ends as a share of the run.
const CHECKLIST: [&str; 5] = [
    "leave the game in front",
    "put another window (Notepad) over part of the game, then move it away",
    "minimize the game",
    "restore it",
    "open some in-game dialog, if the game has one",
];
const PHASE_ENDS: [f64; 4] = [0.18, 0.40, 0.58, 0.71];

#[test]
#[ignore = "captures a window of this PC and saves pictures of it; run by hand with the owner, see the module docs"]
fn window_capture_probe() -> Result<()> {
    let Some(window) = env_text("AFK_PROBE_WINDOW")?.as_deref().and_then(needle_of) else {
        bail!(
            "AFK_PROBE_WINDOW is not set: set it to a substring of the window's class, exe name or \
             title, e.g. $env:AFK_PROBE_WINDOW = 'scrydegame', then run again"
        );
    };
    let seconds = parse_seconds(env_text("AFK_PROBE_SECONDS")?.as_deref(), DEFAULT_SECONDS)
        .map_err(anyhow::Error::msg)?;
    let secondary = parse_flag(
        "AFK_PROBE_SECONDARY",
        env_text("AFK_PROBE_SECONDARY")?.as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let out = output_path("window-probe")?;
    let pictures = out.with_extension("");
    println!(
        "{WHO}: window \"{window}\", {seconds} s, IncludeSecondaryWindows {}; output {}, pictures {}",
        if secondary { "requested" } else { "not requested" },
        out.display(),
        pictures.display()
    );
    let mut probe = Probe::new(Config {
        needle: window,
        seconds,
        secondary,
        out,
        pictures,
    });
    let outcome = probe.run();
    probe.finish(outcome)
}

struct Config {
    needle: String,
    seconds: u64,
    secondary: bool,
    out: PathBuf,
    pictures: PathBuf,
}

/// Everything one run records, in the order the JSON lays it out.
struct Probe {
    config: Config,
    started_local: String,
    /// FILETIME at the start: process creation times are recorded as ms after it.
    started_ft: u64,
    environment: Value,
    candidates: Value,
    target: Value,
    steps: Vec<Value>,
    started: bool,
    summary: Value,
    seconds: Vec<Value>,
    transitions: Vec<Value>,
    frames: Value,
    pictures: Value,
    /// Every error or oddity that did not stop the run, as it was printed.
    notes: Vec<String>,
}

impl Probe {
    fn new(config: Config) -> Self {
        Self {
            config,
            started_local: local_time(),
            started_ft: now_filetime(),
            environment: Value::Null,
            candidates: Value::Null,
            target: Value::Null,
            steps: Vec::new(),
            started: false,
            summary: Value::Null,
            seconds: Vec::new(),
            transitions: Vec::new(),
            frames: Value::Null,
            pictures: Value::Null,
            notes: Vec::new(),
        }
    }

    fn run(&mut self) -> Result<()> {
        // WinRT on this thread first: `ApiInformation` below is already a WinRT call.
        let ro = RoGuard::init(&mut self.steps);
        self.environment = environment(&mut self.notes);

        let found = find_target(&self.config.needle, &mut self.notes)?;
        self.candidates = found.candidates;
        let target = found.facts;
        self.target = target_record(
            &target,
            found.exe.as_deref(),
            found.matched,
            self.started_ft,
        );
        print_target(&self.target, &self.environment);
        if self.target["process"]["elevated"] == json!(true)
            && self.environment["process"]["elevated"] != json!(true)
        {
            note(
                WHO,
                &mut self.notes,
                "the target runs elevated and this probe does not, as the agent does not: this is \
                 the case the probe is for"
                    .to_owned(),
            );
        }

        let pictures_on = match std::fs::create_dir_all(&self.config.pictures) {
            Ok(()) => true,
            Err(error) => {
                note(
                    WHO,
                    &mut self.notes,
                    format!(
                        "creating {} failed ({error}): no pictures this run",
                        self.config.pictures.display()
                    ),
                );
                false
            }
        };

        print_checklist(self.config.seconds);
        let Some(mut capture) = Capture::start(
            target.hwnd,
            &self.config,
            pictures_on,
            &mut self.steps,
            &mut self.notes,
        ) else {
            let failed = self
                .steps
                .iter()
                .rev()
                .find(|s| s["ok"] == json!(false) && s["fatal"] == json!(true))
                .map_or_else(
                    || "no step failed, yet no capture".to_owned(),
                    |s| format!("{}: {}", s["step"], s["error"]),
                );
            self.summary = json!({
                "started": false,
                "verdict": [format!("WGC did not start a capture of the window: {failed}")],
            });
            drop(ro);
            bail!("the capture did not start: {failed}");
        };
        self.started = true;

        let watch = self.watch(&capture, &target);
        let stopped = capture.stop(&mut self.notes);
        drop(capture);
        drop(ro);
        self.summarize(&target, watch, stopped);
        Ok(())
    }

    /// The main thread's part while the capture runs: a look every [`TICK`], its changes logged, and
    /// a row every second.
    fn watch(&mut self, capture: &Capture, target: &WinFacts) -> Watch {
        let epoch = lock(&capture.shared).epoch;
        let seconds = self.config.seconds as i64;
        let mut names = ExeNames::new();
        let mut watch = Watch::default();
        let mut last: Option<Look> = None;
        let mut next_row = 1i64;
        let (mut frame_cursor, mut picture_cursor, mut errors_printed) = (0usize, 0usize, 0usize);
        println!();
        println!("{}", row_header());
        loop {
            let tick_start = Instant::now();
            let t_us = epoch.elapsed().as_micros() as i64;
            let seen = look(target, &mut names, t_us);
            if let Some(error) = &seen.enum_error {
                note(
                    WHO,
                    &mut self.notes,
                    format!("+{:.1} s: {error}", ms(t_us) / 1000.0),
                );
            }
            log_transitions(last.as_ref(), &seen, target, &mut self.transitions);
            watch.ticks.push(seen.state());
            {
                let handler = lock(&capture.shared);
                for error in handler.errors.iter().skip(errors_printed) {
                    println!("{WHO}: frame handler: {error}");
                }
                errors_printed = handler.errors.len();
            }
            while t_us >= next_row * 1_000_000 && next_row <= seconds {
                let (record, line) = row(
                    next_row,
                    &seen,
                    target,
                    capture,
                    &mut frame_cursor,
                    &mut picture_cursor,
                );
                println!("{line}");
                self.seconds.push(record);
                next_row += 1;
            }
            if next_row > seconds {
                break;
            }
            last = Some(seen);
            std::thread::sleep(TICK.saturating_sub(tick_start.elapsed()));
        }
        println!();
        watch
    }

    /// Frames, pictures and the verdict, from what the handler collected and what the main thread saw.
    fn summarize(&mut self, target: &WinFacts, watch: Watch, stopped: Stopped) {
        let times: Vec<i64> = stopped.frames.iter().map(|f| f.t_us).collect();
        let per_second = per_second_counts(&times, self.config.seconds as usize);
        let gaps = frame_gaps(&times, stopped.ended_us, GAP_US);
        let mut sizes: BTreeMap<(i32, i32), (usize, i64, i64)> = BTreeMap::new();
        for f in &stopped.frames {
            let e = sizes.entry(f.content).or_insert((0, f.t_us, f.t_us));
            e.0 += 1;
            e.2 = f.t_us;
        }
        let ticks = &watch.ticks;
        let while_state = |pred: &dyn Fn(&TickState) -> bool| -> (usize, BTreeMap<String, usize>) {
            let mut n = 0;
            let mut by_size = BTreeMap::new();
            for f in &stopped.frames {
                if state_at(ticks, f.t_us).is_some_and(pred) {
                    n += 1;
                    *by_size
                        .entry(format!("{}x{}", f.content.0, f.content.1))
                        .or_insert(0) += 1;
                }
            }
            (n, by_size)
        };
        let (frames_minimized, sizes_minimized) = while_state(&|s| s.minimized);
        let (frames_covered, _) = while_state(&|s| !s.covered_by.is_empty());
        let (frames_gone, _) = while_state(&|s| !s.exists);
        let minimized_us = time_where(ticks, stopped.ended_us, |s| s.minimized);
        let covered_us = time_where(ticks, stopped.ended_us, |s| !s.covered_by.is_empty());
        let own_over_us = time_where(ticks, stopped.ended_us, |s| !s.own_over.is_empty());
        let front_us = time_where(ticks, stopped.ended_us, |s| s.foreground_target);
        let covered_by: Vec<String> = unique(ticks.iter().flat_map(|s| s.covered_by.clone()));
        let own_over: Vec<String> = unique(ticks.iter().flat_map(|s| s.own_over.clone()));

        // Pictures: what was asked of the handler, what the writer made of it, and the state then.
        let done: BTreeMap<u32, &PictureDone> = stopped.done.iter().map(|d| (d.seq, d)).collect();
        let mut pictures = Vec::new();
        let (mut saved, mut black) = (Vec::new(), Vec::new());
        let (mut while_covered, mut while_own_over, mut while_minimized) =
            (Vec::new(), Vec::new(), Vec::new());
        for ask in &stopped.pictures {
            let result = done.get(&ask.seq);
            let state = state_at(ticks, ask.t_us);
            let written = result.filter(|d| d.error.is_none());
            if let Some(d) = written {
                saved.push(ask.file.clone());
                if d.stats.mean_luma < BLACK_LUMA {
                    black.push(ask.file.clone());
                }
            }
            // Only pictures that exist go into the lists to open.
            if let Some(s) = state.filter(|_| written.is_some()) {
                if !s.covered_by.is_empty() {
                    while_covered.push(format!("{} ({})", ask.file, s.covered_by.join(", ")));
                }
                if !s.own_over.is_empty() {
                    while_own_over.push(format!("{} ({})", ask.file, s.own_over.join(", ")));
                }
                if s.minimized {
                    while_minimized.push(ask.file.clone());
                }
            }
            pictures.push(json!({
                "seq": ask.seq,
                "t_ms": ms(ask.t_us),
                "reason": ask.reason,
                "file": ask.file,
                "source": ask.source,
                "status": ask.status,
                "saved": result.map(|d| d.saved),
                "stats": result.map(|d| d.stats),
                "write_error": result.and_then(|d| d.error.clone()),
                "target_minimized": state.map(|s| s.minimized),
                "covered_by": state.map(|s| s.covered_by.clone()),
                "own_windows_over": state.map(|s| s.own_over.clone()),
            }));
        }

        let property = |name: &str| {
            self.steps
                .iter()
                .find(|s| s["property"] == json!(name))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let (cursor, border, secondary) = (
            property("IsCursorCaptureEnabled"),
            property("IsBorderRequired"),
            property("IncludeSecondaryWindows"),
        );

        let mut verdict = vec![format!(
            "WGC started a capture of window {:#x} (class \"{}\", pid {}, {} integrity) from this \
             {} process",
            target.hwnd,
            target.class,
            target.pid,
            self.target["process"]["integrity"]
                .as_str()
                .unwrap_or("unknown"),
            self.environment["process"]["integrity"]
                .as_str()
                .unwrap_or("unknown"),
        )];
        let n = stopped.frames.len();
        if n == 0 {
            verdict.push(format!(
                "no frame arrived in {} s: the capture started but delivered nothing",
                self.config.seconds
            ));
        } else {
            let mut sorted = per_second.clone();
            sorted.sort_unstable();
            verdict.push(format!(
                "{n} frames in {:.1} s, the first {:.0} ms after StartCapture; frames per second: \
                 min {}, median {}, max {}",
                stopped.ended_us as f64 / 1e6,
                ms(times[0]),
                sorted.first().copied().unwrap_or(0),
                sorted.get(sorted.len() / 2).copied().unwrap_or(0),
                sorted.last().copied().unwrap_or(0),
            ));
        }
        if !saved.is_empty() && black.len() == saved.len() {
            verdict.push(format!(
                "every one of the {} pictures is black (mean luma < {BLACK_LUMA}): frames arrive \
                 but carry no picture of the window",
                saved.len()
            ));
        } else if !black.is_empty() {
            verdict.push(format!(
                "{} of {} pictures are black: {}",
                black.len(),
                saved.len(),
                black.join(", ")
            ));
        }
        if minimized_us > 0 {
            verdict.push(format!(
                "the target was minimized for about {:.1} s; {frames_minimized} frames arrived \
                 meanwhile{}",
                minimized_us as f64 / 1e6,
                if sizes_minimized.is_empty() {
                    String::new()
                } else {
                    format!(" (sizes {sizes_minimized:?})")
                }
            ));
        } else {
            verdict.push("the target was never seen minimized (step 3 not done?)".to_owned());
        }
        if covered_us > 0 {
            verdict.push(format!(
                "other windows covered part of the target for about {:.1} s ({}); {frames_covered} \
                 frames and {} pictures meanwhile — open them: a leak shows as that window's \
                 content inside the game's picture",
                covered_us as f64 / 1e6,
                covered_by.join(", "),
                while_covered.len()
            ));
        } else {
            verdict.push("no other window was seen over the target (step 2 not done?)".to_owned());
        }
        if own_over_us > 0 {
            verdict.push(format!(
                "the game's own windows were over it for about {:.1} s ({}); \
                 IncludeSecondaryWindows {} — see whether they show in {} pictures",
                own_over_us as f64 / 1e6,
                own_over.join(", "),
                if self.config.secondary {
                    "was requested"
                } else {
                    "was not requested"
                },
                while_own_over.len()
            ));
        }
        if frames_gone > 0 || !ticks.iter().all(|s| s.exists) {
            verdict.push(format!(
                "the target window was gone for part of the run; {frames_gone} frames arrived then"
            ));
        }
        verdict.push(format!(
            "the target was in front for about {:.1} of {:.1} s",
            front_us as f64 / 1e6,
            stopped.ended_us as f64 / 1e6
        ));
        verdict.push(format!(
            "IsBorderRequired = false: {}; whether a yellow frame showed is for the owner to say",
            property_outcome(&border)
        ));
        verdict.push(format!(
            "IncludeSecondaryWindows: {}",
            property_outcome(&secondary)
        ));
        verdict.push(format!(
            "IsCursorCaptureEnabled = true: {}",
            property_outcome(&cursor)
        ));
        if let Some(t) = stopped.closed_at_us {
            verdict.push(format!(
                "the capture item closed at {:.1} s (the window was destroyed?)",
                t as f64 / 1e6
            ));
        }
        if !stopped.size_changes.is_empty() {
            verdict.push(format!(
                "{} content-size changes: {}",
                stopped.size_changes.len(),
                stopped
                    .size_changes
                    .iter()
                    .map(|c| format!("{:.1} s → {}", c.t_us as f64 / 1e6, size_text(c.to)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if stopped.error_count > 0 {
            verdict.push(format!(
                "{} errors in the frame handler (see frames.errors)",
                stopped.error_count
            ));
        }

        println!("{WHO}: summary");
        for line in &verdict {
            println!("{WHO}:   - {line}");
        }
        if !while_covered.is_empty() {
            println!("{WHO}: pictures taken while another window covered the target — check them:");
            for p in &while_covered {
                println!("{WHO}:     {p}");
            }
        }

        self.summary = json!({
            "started": true,
            "verdict": verdict,
            "frames": n,
            "first_frame_ms": times.first().map(|t| ms(*t)),
            "ended_ms": ms(stopped.ended_us),
            "per_second": per_second,
            "minimized_s": minimized_us as f64 / 1e6,
            "frames_while_minimized": frames_minimized,
            "sizes_while_minimized": sizes_minimized,
            "covered_s": covered_us as f64 / 1e6,
            "covered_by": covered_by,
            "frames_while_covered": frames_covered,
            "pictures_while_covered": while_covered,
            "own_windows_over_s": own_over_us as f64 / 1e6,
            "own_windows_over": own_over,
            "pictures_while_own_windows_over": while_own_over,
            "pictures_while_minimized": while_minimized,
            "target_in_front_s": front_us as f64 / 1e6,
            "pictures_saved": saved.len(),
            "pictures_black": black,
            "item_closed_ms": stopped.closed_at_us.map(ms),
            "cursor": cursor,
            "border": border,
            "secondary_windows": secondary,
        });
        self.frames = json!({
            "count": n,
            "per_second": self.summary["per_second"].clone(),
            "sizes": sizes.iter().map(|((w, h), (count, first, last))| json!({
                "size": [w, h], "frames": count, "first_ms": ms(*first), "last_ms": ms(*last),
            })).collect::<Vec<_>>(),
            "size_changes": stopped.size_changes.iter().map(|c| json!({
                "t_ms": ms(c.t_us), "from": [c.from.0, c.from.1], "to": [c.to.0, c.to.1],
                "pool_recreated": c.recreated,
            })).collect::<Vec<_>>(),
            "gaps_over_ms": ms(GAP_US),
            "gaps": gaps.iter().map(|(from, to)| json!({
                "from_ms": ms(*from), "to_ms": ms(*to), "ms": ms(to - from),
            })).collect::<Vec<_>>(),
            "error_count": stopped.error_count,
            "errors": stopped.errors,
            "list_format": "[t_ms, content width, content height]",
            "list": stopped.frames.iter().map(|f| json!([ms(f.t_us), f.content.0, f.content.1])).collect::<Vec<_>>(),
        });
        self.pictures = json!(pictures);
    }

    /// Write the JSON and answer with the run's outcome (or the write's failure).
    fn finish(self, outcome: Result<()>) -> Result<()> {
        let record = json!({
            "probe": "afklink-capture probe::window_capture",
            "format": 1,
            "started_local": self.started_local,
            "outcome": match &outcome {
                Ok(()) => "complete".to_owned(),
                Err(error) => format!("{error:#}"),
            },
            "config": {
                "window": self.config.needle,
                "seconds": self.config.seconds,
                "secondary_windows_requested": self.config.secondary,
                "out": self.config.out.display().to_string(),
                "pictures_dir": self.config.pictures.display().to_string(),
                "tick_ms": TICK.as_millis() as u64,
                "picture_max_width": PICTURE_MAX_WIDTH,
                "pool_buffers": POOL_BUFFERS,
                "pixel_format": "B8G8R8A8UIntNormalized",
                "checklist": checklist(self.config.seconds),
                "t0": "t = 0 is the StartCapture call; every t_ms and t_s counts from it",
                "pictures": "the first frame of every second and the first after every content-size \
                    change; box-filtered to at most 1280 wide, alpha ignored (shown opaque), RGB PNG",
                "over": "windows above the target in the z-order (EnumWindows order), on screen \
                    (visible, not minimized, not cloaked) and overlapping its DWM frame; \
                    same_process: the game's own window; click_through: layered + transparent \
                    (an overlay)",
            },
            "environment": self.environment,
            "candidates": self.candidates,
            "target": self.target,
            "capture": { "started": self.started, "steps": self.steps },
            "summary": self.summary,
            "seconds": self.seconds,
            "transitions": self.transitions,
            "frames": self.frames,
            "pictures": self.pictures,
            "notes": self.notes,
        });
        let written = write_json(&self.config.out, &record);
        match &written {
            Ok(()) => println!(
                "{WHO}: written {} (pictures in {})",
                self.config.out.display(),
                self.config.pictures.display()
            ),
            Err(error) => println!("{WHO}: the JSON was not written: {error:#}"),
        }
        match (outcome, written) {
            (Err(error), _) => Err(error),
            (Ok(()), written) => written,
        }
    }
}

/// `RoInitialize(MTA)` for this thread, balanced when dropped (after every WinRT object of the run).
struct RoGuard(bool);

impl RoGuard {
    fn init(steps: &mut Vec<Value>) -> Self {
        // SAFETY: plain call; balanced in `drop` when it succeeded.
        let result = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        let ok = result.is_ok();
        step(
            steps,
            "RoInitialize(RO_INIT_MULTITHREADED)",
            false,
            result.map(|()| Value::Null).map_err(|e| error_text(&e)),
        );
        Self(ok)
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

/// Record one capture step and print it. `fatal`: its failure means no capture.
fn step(steps: &mut Vec<Value>, name: &str, fatal: bool, result: Result<Value, String>) -> bool {
    match result {
        Ok(detail) => {
            if detail.is_null() {
                println!("{WHO}: {name}: ok");
            } else {
                println!("{WHO}: {name}: ok {detail}");
            }
            steps.push(json!({ "step": name, "ok": true, "detail": detail }));
            true
        }
        Err(error) => {
            println!("{WHO}: {name}: FAILED {error}");
            steps.push(json!({ "step": name, "ok": false, "fatal": fatal, "error": error }));
            false
        }
    }
}

/// DPI awareness (first: every rectangle after it is in physical pixels), the OS, this process, any
/// AFKLink process, and which WGC properties this OS has.
fn environment(notes: &mut Vec<String>) -> Value {
    let dpi = make_dpi_aware(WHO, notes);
    let os = os_version();
    let process = own_process();
    let own_pid = process["pid"].as_u64().unwrap_or(0);
    let afklink = match snapshot() {
        Ok(list) => json!(list
            .into_iter()
            .filter(|p| {
                let exe = p.exe.to_lowercase();
                u64::from(p.pid) != own_pid
                    && exe.starts_with("afklink")
                    && !exe.starts_with("afklink_capture")
            })
            .map(|p| json!({ "pid": p.pid, "exe": p.exe }))
            .collect::<Vec<_>>()),
        Err(error) => {
            note(WHO, notes, format!("listing processes failed: {error}"));
            json!({ "error": error })
        }
    };
    let wgc = wgc_api();
    println!(
        "{WHO}: Windows {} build {}.{}; this process {}; AFKLink running: {afklink}",
        os["display_version"], os["build"], os["ubr"], process
    );
    println!("{WHO}: WGC on this OS: {wgc}");
    json!({
        "dpi": dpi,
        "os": os,
        "process": process,
        "afklink_processes": afklink,
        "wgc": wgc,
    })
}

fn property_present(name: &str) -> Result<bool, String> {
    ApiInformation::IsPropertyPresent(
        &HSTRING::from("Windows.Graphics.Capture.GraphicsCaptureSession"),
        &HSTRING::from(name),
    )
    .map_err(|e| format!("ApiInformation::IsPropertyPresent: {}", error_text(&e)))
}

/// What of WGC this OS has, the way `windows-capture` checks it.
fn wgc_api() -> Value {
    let answer = |r: Result<bool, String>| r.map_or_else(|e| json!({ "error": e }), |b| json!(b));
    let contract = ApiInformation::IsApiContractPresentByMajor(
        &HSTRING::from("Windows.Foundation.UniversalApiContract"),
        8,
    )
    .map_err(|e| error_text(&e));
    let supported = GraphicsCaptureSession::IsSupported().map_err(|e| error_text(&e));
    let access = ApiInformation::IsTypePresent(&HSTRING::from(
        "Windows.Graphics.Capture.GraphicsCaptureAccess",
    ))
    .map_err(|e| error_text(&e));
    let mut properties = serde_json::Map::new();
    for name in [
        "IsCursorCaptureEnabled",
        "IsBorderRequired",
        "IncludeSecondaryWindows",
        "MinUpdateInterval",
        "DirtyRegionMode",
    ] {
        properties.insert(name.into(), answer(property_present(name)));
    }
    json!({
        "universal_api_contract_8": answer(contract),
        "session_is_supported": answer(supported),
        "session_properties": properties,
        "graphics_capture_access_type": answer(access),
    })
}

/// The chosen window and the list it was chosen from.
struct Found {
    facts: WinFacts,
    exe: Option<String>,
    matched: Matched,
    candidates: Value,
}

/// Wait (up to [`WAIT_FOR_WINDOW`]) for a visible top-level window matching `needle`, and choose.
fn find_target(needle: &str, notes: &mut Vec<String>) -> Result<Found> {
    println!(
        "{WHO}: looking for a visible top-level window whose class, exe name or title contains \
         \"{needle}\""
    );
    let begun = Instant::now();
    let mut printed = begun;
    let mut names = ExeNames::new();
    loop {
        let list = top_level_windows().map_err(anyhow::Error::msg)?;
        let mut found: Vec<(WinFacts, Option<String>, Matched)> = Vec::new();
        for hwnd in list {
            if !window_visible(hwnd) {
                continue;
            }
            let facts = window_facts(hwnd);
            let exe = names.get(facts.pid);
            let matched = match_window(needle, &facts.class, exe.as_deref(), &facts.title);
            if matched.any() {
                found.push((facts, exe, matched));
            }
        }
        let candidates: Vec<Candidate> = found
            .iter()
            .map(|(f, _, m)| Candidate {
                matched: *m,
                minimized: f.minimized,
                cloaked: f.cloaked.unwrap_or(0) != 0,
                area: f.bounds().map_or(0, super::area),
            })
            .collect();
        if let Some(best) = pick_candidate(&candidates) {
            let listed: Vec<Value> = found
                .iter()
                .enumerate()
                .map(|(i, (f, exe, m))| {
                    json!({
                        "chosen": i == best,
                        "matched": m.fields(),
                        "exe": exe,
                        "window": f,
                    })
                })
                .collect();
            if found.len() > 1 {
                note(
                    WHO,
                    notes,
                    format!(
                        "{} visible windows match \"{needle}\"; taking {:#x} (a class or exe match \
                         first, then on screen, then the largest):",
                        found.len(),
                        found[best].0.hwnd
                    ),
                );
                for (i, (f, exe, m)) in found.iter().enumerate() {
                    println!(
                        "{WHO}:   {} {:#x} class \"{}\" title \"{}\" {} pid {} matched {}{} {}",
                        if i == best { "*" } else { " " },
                        f.hwnd,
                        f.class,
                        clip(&f.title, 40),
                        exe.as_deref().unwrap_or("?"),
                        f.pid,
                        m.fields(),
                        if f.minimized { " minimized" } else { "" },
                        rect_text(f.bounds())
                    );
                }
            }
            let (facts, exe, matched) = found.swap_remove(best);
            return Ok(Found {
                facts,
                exe,
                matched,
                candidates: json!(listed),
            });
        }
        if begun.elapsed() >= WAIT_FOR_WINDOW {
            bail!(
                "no visible top-level window's class, exe name or title contains \"{needle}\" \
                 within {} s; nothing was captured",
                WAIT_FOR_WINDOW.as_secs()
            );
        }
        if printed.elapsed() >= WAIT_PRINT_EVERY {
            printed = Instant::now();
            println!(
                "{WHO}: no matching window yet ({} s left)",
                WAIT_FOR_WINDOW.saturating_sub(begun.elapsed()).as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The target as recorded once, before the capture: its window, its process and parent (the snapshot
/// gives the parent without opening anything), and what the limited handle reads.
fn target_record(facts: &WinFacts, exe: Option<&str>, matched: Matched, epoch: u64) -> Value {
    let parent = snapshot().ok().and_then(|list| {
        let ppid = list.iter().find(|p| p.pid == facts.pid)?.ppid;
        let parent_exe = list.iter().find(|p| p.pid == ppid).map(|p| p.exe.clone());
        Some(json!({ "pid": ppid, "exe": parent_exe }))
    });
    json!({
        "matched": matched.fields(),
        "exe": exe,
        "window": facts,
        "extra": window_extra(facts.hwnd),
        "parent": parent,
        "process": process_facts(facts.pid, epoch),
        "process_note": "opened for PROCESS_QUERY_LIMITED_INFORMATION only, closed at once; \
            created_ms is ms after the probe started (negative: before)",
    })
}

fn print_target(target: &Value, environment: &Value) {
    let w = &target["window"];
    let p = &target["process"];
    println!(
        "{WHO}: target {}: class {} title {} — {} pid {} (parent {})",
        w["hwnd"], w["class"], w["title"], target["exe"], w["pid"], target["parent"]
    );
    println!(
        "{WHO}:   path {}; integrity {}, elevated {}; this probe: integrity {}, elevated {}",
        p.get("path").unwrap_or(&p["path_error"]),
        p.get("integrity").unwrap_or(&p["integrity_error"]),
        p["elevated"],
        environment["process"]["integrity"],
        environment["process"]["elevated"],
    );
    println!(
        "{WHO}:   window {}, frame {}, client {}; minimized {}; dpi {} ({})",
        w["rect"],
        w["frame"],
        target["extra"]["client_rect_screen"],
        w["minimized"],
        target["extra"]["dpi"],
        target["extra"]["dpi_awareness"],
    );
}

/// The checklist with a suggested pace for a run of `seconds`.
fn checklist(seconds: u64) -> Vec<String> {
    let s = seconds as f64;
    let mut bounds = vec![0u64];
    bounds.extend(PHASE_ENDS.iter().map(|f| (s * f).round() as u64));
    bounds.push(seconds);
    CHECKLIST
        .iter()
        .enumerate()
        .map(|(i, what)| {
            format!(
                "{}. {what} (about {}-{} s)",
                i + 1,
                bounds[i],
                bounds[i + 1]
            )
        })
        .collect()
}

fn print_checklist(seconds: u64) {
    println!();
    println!(
        "{WHO}: capturing for {seconds} s from the moment StartCapture succeeds — nothing to do at \
         this terminal. By hand, at the PC:"
    );
    for line in checklist(seconds) {
        println!("{WHO}:   {line}");
    }
    println!("{WHO}:   and say afterwards whether a yellow frame showed around the game.");
    println!(
        "{WHO}: the pace is only a guide: every change is logged with its time. Starting the \
         capture:"
    );
    println!();
}

/// The WinRT Direct3D device, used from the frame handler on the system's thread pool. It is agile —
/// `CreateDirect3D11DeviceFromDXGIDevice` over a free-threaded D3D11 device — which windows-rs cannot
/// know, so the type is not `Send`; `windows-capture` wraps it the same way (`SendDirectX`).
struct AgileDevice(IDirect3DDevice);

// SAFETY: see above; the handler only passes it to `Recreate`, under the handler's mutex.
unsafe impl Send for AgileDevice {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameRec {
    t_us: i64,
    content: (i32, i32),
}

#[derive(Clone, Copy, Debug)]
struct SizeChange {
    t_us: i64,
    from: (i32, i32),
    to: (i32, i32),
    recreated: bool,
}

/// A picture the handler asked for.
#[derive(Clone, Debug)]
struct PictureAsk {
    seq: u32,
    t_us: i64,
    reason: String,
    file: String,
    source: [u32; 2],
    /// `queued`, or why not.
    status: String,
}

struct PictureJob {
    seq: u32,
    path: PathBuf,
    width: u32,
    height: u32,
    bgra: Vec<u8>,
}

/// What the writer made of a picture.
#[derive(Clone, Debug)]
struct PictureDone {
    seq: u32,
    saved: [u32; 2],
    stats: PictureStats,
    error: Option<String>,
}

/// The frame handler's state, behind one mutex: the `FrameArrived` callback runs on the system's
/// thread pool, the D3D11 immediate context is not thread-safe, and the main thread reads the counts.
struct Handler {
    /// t = 0: reset just before `StartCapture`.
    epoch: Instant,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    d3d: AgileDevice,
    pool_size: (i32, i32),
    /// The last frame's content size.
    last_content: Option<(i32, i32)>,
    staging: Option<((u32, u32), ID3D11Texture2D)>,
    frames: Vec<FrameRec>,
    size_changes: Vec<SizeChange>,
    errors: Vec<String>,
    error_count: usize,
    pictures: Vec<PictureAsk>,
    last_picture_second: Option<i64>,
    /// A content-size change whose first properly sized frame is still to be pictured.
    pending_size: Option<(i32, i32)>,
    writer: Option<SyncSender<PictureJob>>,
    pictures_dir: PathBuf,
    closed_at_us: Option<i64>,
}

impl Handler {
    fn now_us(&self) -> i64 {
        self.epoch.elapsed().as_micros() as i64
    }

    fn error(&mut self, t_us: i64, what: String) {
        self.error_count += 1;
        if self.errors.len() < ERRORS_KEPT {
            self.errors
                .push(format!("+{:.3} s: {what}", t_us as f64 / 1e6));
        }
    }

    fn on_frame(&mut self, pool: &Direct3D11CaptureFramePool) {
        let t_us = self.now_us();
        let frame = match pool.TryGetNextFrame() {
            Ok(frame) => frame,
            Err(error) => {
                self.error(t_us, format!("TryGetNextFrame: {}", error_text(&error)));
                return;
            }
        };
        let content = match frame.ContentSize() {
            Ok(size) => (size.Width, size.Height),
            Err(error) => {
                self.error(t_us, format!("ContentSize: {}", error_text(&error)));
                self.close_frame(&frame, t_us);
                return;
            }
        };
        self.frames.push(FrameRec { t_us, content });
        let previous = self.last_content.replace(content);

        if content != self.pool_size {
            // As `windows-capture` does: this frame's surface still has the old pool's size, so it is
            // released, the pool recreated for the new size, and the next frame is the first of it.
            self.close_frame(&frame, t_us);
            drop(frame);
            let empty = content.0 <= 0 || content.1 <= 0;
            if empty && previous == Some(content) {
                // The same empty size as the last frame: said once, counted in `frames` still.
                return;
            }
            let recreated = if !empty {
                match pool.Recreate(
                    &self.d3d.0,
                    DirectXPixelFormat::B8G8R8A8UIntNormalized,
                    POOL_BUFFERS,
                    SizeInt32 {
                        Width: content.0,
                        Height: content.1,
                    },
                ) {
                    Ok(()) => true,
                    Err(error) => {
                        self.error(
                            t_us,
                            format!(
                                "recreating the pool for {}: {}",
                                size_text(content),
                                error_text(&error)
                            ),
                        );
                        false
                    }
                }
            } else {
                self.error(
                    t_us,
                    format!(
                        "content size {} is empty; the pool is kept",
                        size_text(content)
                    ),
                );
                false
            };
            self.size_changes.push(SizeChange {
                t_us,
                from: self.pool_size,
                to: content,
                recreated,
            });
            if recreated {
                self.pool_size = content;
                self.pending_size = Some(content);
            }
            return;
        }

        let second = t_us / 1_000_000;
        let reason = if let Some(size) = self.pending_size.take() {
            Some(format!("size-{}", size_text(size)))
        } else if self.last_picture_second != Some(second) {
            Some(if self.pictures.is_empty() {
                "first".to_owned()
            } else {
                "second".to_owned()
            })
        } else {
            None
        };
        if let Some(reason) = reason {
            self.last_picture_second = Some(second);
            if self.writer.is_some() {
                self.take_picture(&frame, t_us, reason, content);
            }
        }
        self.close_frame(&frame, t_us);
    }

    fn close_frame(&mut self, frame: &Direct3D11CaptureFrame, t_us: i64) {
        if let Err(error) = frame.Close() {
            self.error(t_us, format!("closing a frame: {}", error_text(&error)));
        }
    }

    fn take_picture(
        &mut self,
        frame: &Direct3D11CaptureFrame,
        t_us: i64,
        reason: String,
        content: (i32, i32),
    ) {
        let seq = self.pictures.len() as u32 + 1;
        let file = format!("{seq:03}_t{:05.1}s_{reason}.png", t_us as f64 / 1e6);
        let mut ask = PictureAsk {
            seq,
            t_us,
            reason,
            file: file.clone(),
            source: [0, 0],
            status: String::new(),
        };
        match self.read_pixels(frame, content) {
            Ok((width, height, bgra)) => {
                ask.source = [width, height];
                let job = PictureJob {
                    seq,
                    path: self.pictures_dir.join(&file),
                    width,
                    height,
                    bgra,
                };
                ask.status = match self.writer.as_ref().map(|tx| tx.try_send(job)) {
                    Some(Ok(())) => "queued".to_owned(),
                    Some(Err(TrySendError::Full(_))) => "skipped: the writer is behind".to_owned(),
                    Some(Err(TrySendError::Disconnected(_))) => {
                        "skipped: the writer stopped".to_owned()
                    }
                    None => "skipped: pictures are off".to_owned(),
                };
                if ask.status != "queued" {
                    self.error(t_us, format!("picture {file}: {}", ask.status));
                }
            }
            Err(error) => {
                self.error(t_us, format!("picture {file}: {error}"));
                ask.status = format!("not read: {error}");
            }
        }
        self.pictures.push(ask);
    }

    /// The frame's pixels, tightly packed BGRA: copied to a staging texture, mapped and read row by
    /// row. The content may be smaller than the surface; only the content is read.
    fn read_pixels(
        &mut self,
        frame: &Direct3D11CaptureFrame,
        content: (i32, i32),
    ) -> std::result::Result<(u32, u32, Vec<u8>), String> {
        let texture: ID3D11Texture2D = frame
            .Surface()
            .and_then(|surface| surface.cast::<IDirect3DDxgiInterfaceAccess>())
            // SAFETY: a live surface's DXGI access interface.
            .and_then(|access| unsafe { access.GetInterface::<ID3D11Texture2D>() })
            .map_err(|e| format!("the frame's texture: {}", error_text(&e)))?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        // SAFETY: a live texture and a live description.
        unsafe { texture.GetDesc(&mut desc) };
        if desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(format!("unexpected texture format {}", desc.Format.0));
        }
        let width = desc.Width.min(content.0.max(0) as u32);
        let height = desc.Height.min(content.1.max(0) as u32);
        if width == 0 || height == 0 {
            return Err(format!("an empty frame ({})", size_text(content)));
        }
        let staging = self.staging_for(&desc)?;
        // SAFETY: two live textures of the same size and format.
        unsafe { self.context.CopyResource(&staging, &texture) };
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        // SAFETY: a live staging texture with CPU read access, and a live output.
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(|e| format!("mapping the staging texture: {}", error_text(&e)))?;
        let row = width as usize * 4;
        let pitch = mapped.RowPitch as usize;
        let read = if mapped.pData.is_null() || pitch < row {
            Err(format!(
                "the mapped texture is unusable (data null {}, row pitch {pitch} < {row})",
                mapped.pData.is_null()
            ))
        } else {
            let mut bgra = Vec::with_capacity(row * height as usize);
            for y in 0..height as usize {
                // SAFETY: the mapping holds `desc.Height` rows of `RowPitch` bytes; `y < height <=
                // desc.Height` and `row <= pitch`, so this line lies inside it.
                let line = unsafe {
                    std::slice::from_raw_parts(mapped.pData.cast::<u8>().add(y * pitch), row)
                };
                bgra.extend_from_slice(line);
            }
            Ok((width, height, bgra))
        };
        // SAFETY: balances the successful `Map` above.
        unsafe { self.context.Unmap(&staging, 0) };
        read
    }

    /// A CPU-readable copy target of the surface's size, kept while the size holds.
    fn staging_for(
        &mut self,
        desc: &D3D11_TEXTURE2D_DESC,
    ) -> std::result::Result<ID3D11Texture2D, String> {
        if let Some(((w, h), texture)) = &self.staging {
            if *w == desc.Width && *h == desc.Height {
                return Ok(texture.clone());
            }
        }
        let staging = D3D11_TEXTURE2D_DESC {
            Width: desc.Width,
            Height: desc.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: desc.Format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut texture = None;
        // SAFETY: a live description and output.
        unsafe {
            self.device
                .CreateTexture2D(&staging, None, Some(&mut texture))
        }
        .map_err(|e| format!("creating a staging texture: {}", error_text(&e)))?;
        let texture = texture.ok_or("creating a staging texture returned none")?;
        self.staging = Some(((desc.Width, desc.Height), texture.clone()));
        Ok(texture)
    }
}

fn size_text(size: (i32, i32)) -> String {
    format!("{}x{}", size.0, size.1)
}

/// The pictures' writer: scale, measure and write each as PNG, off the frame handler's thread.
fn write_pictures(jobs: &Receiver<PictureJob>) -> Vec<PictureDone> {
    let mut done = Vec::new();
    for job in jobs {
        let (w, h) = fit_width(job.width, job.height, PICTURE_MAX_WIDTH);
        let rgb = downscale_bgra_to_rgb(&job.bgra, job.width, job.height, w, h);
        let stats = picture_stats(&rgb);
        let error = write_png(&job.path, w, h, &rgb).err();
        if let Some(error) = &error {
            println!("{WHO}: picture {} not written: {error}", job.path.display());
        }
        done.push(PictureDone {
            seq: job.seq,
            saved: [w, h],
            stats,
            error,
        });
    }
    done
}

/// An RGB picture as a PNG file (also the cursor probe's, `super::cursor_capture`).
pub(super) fn write_png(
    path: &std::path::Path,
    w: u32,
    h: u32,
    rgb: &[u8],
) -> std::result::Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| format!("creating the file: {e}"))?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), w, h);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::Fast);
    let mut writer = encoder
        .write_header()
        .map_err(|e| format!("PNG header: {e}"))?;
    writer
        .write_image_data(rgb)
        .map_err(|e| format!("PNG data: {e}"))?;
    writer.finish().map_err(|e| format!("PNG end: {e}"))
}

/// One window session property and how it went.
#[derive(Clone, Copy)]
enum Property {
    Cursor,
    Border,
    Secondary,
}

impl Property {
    fn name(self) -> &'static str {
        match self {
            Self::Cursor => "IsCursorCaptureEnabled",
            Self::Border => "IsBorderRequired",
            Self::Secondary => "IncludeSecondaryWindows",
        }
    }

    fn set(self, session: &GraphicsCaptureSession, value: bool) -> windows::core::Result<()> {
        match self {
            Self::Cursor => session.SetIsCursorCaptureEnabled(value),
            Self::Border => session.SetIsBorderRequired(value),
            Self::Secondary => session.SetIncludeSecondaryWindows(value),
        }
    }

    fn get(self, session: &GraphicsCaptureSession) -> windows::core::Result<bool> {
        match self {
            Self::Cursor => session.IsCursorCaptureEnabled(),
            Self::Border => session.IsBorderRequired(),
            Self::Secondary => session.IncludeSecondaryWindows(),
        }
    }
}

/// Set a session property (when `want` is `Some`) and read it back, recording whether the OS has it,
/// what the setter answered, what it reads, and whether that is what was asked. Never fatal.
fn session_property(
    steps: &mut Vec<Value>,
    session: &GraphicsCaptureSession,
    property: Property,
    want: Option<bool>,
) {
    let name = property.name();
    let present = property_present(name);
    let mut record = json!({
        "step": match want {
            Some(v) => format!("{name} = {v}"),
            None => format!("{name} (read only)"),
        },
        "property": name,
        "present": present.clone().map_or_else(|e| json!({ "error": e }), |b| json!(b)),
        "requested": want,
    });
    // Absent (or unknown): nothing is called, as `windows-capture` calls nothing either.
    if present != Ok(true) {
        record["ok"] = json!(false);
        record["set"] = json!("skipped: not present on this OS");
        println!("{WHO}: {name}: not present on this OS ({present:?}); not set");
        steps.push(record);
        return;
    }
    let set = want.map(|v| property.set(session, v).map_err(|e| error_text(&e)));
    let reads = property.get(session).map_err(|e| error_text(&e));
    let accepted = match (want, &set, &reads) {
        (Some(v), Some(Ok(())), Ok(r)) => *r == v,
        (None, None, Ok(_)) => true,
        _ => false,
    };
    record["set"] = match &set {
        None => json!("not requested"),
        Some(Ok(())) => json!("ok"),
        Some(Err(e)) => json!(e),
    };
    record["reads"] = reads
        .clone()
        .map_or_else(|e| json!({ "error": e }), |b| json!(b));
    record["accepted"] = json!(accepted);
    record["ok"] = json!(accepted);
    println!(
        "{WHO}: {}: set {}, reads {}{}",
        record["step"].as_str().unwrap_or(name),
        record["set"],
        record["reads"],
        if accepted { "" } else { " — NOT as asked" }
    );
    steps.push(record);
}

/// A property step as one phrase for the verdict.
fn property_outcome(record: &Value) -> String {
    if record.is_null() {
        return "not tried".to_owned();
    }
    if record["set"] == json!("skipped: not present on this OS") {
        return format!("not present on this OS ({})", record["present"]);
    }
    format!(
        "set {}, reads back {}{}",
        record["set"],
        record["reads"],
        if record["accepted"] == json!(true) {
            ""
        } else if record["requested"].is_null() {
            " (not requested)"
        } else {
            " — not as asked"
        }
    )
}

/// What `Capture::stop` hands back.
struct Stopped {
    ended_us: i64,
    frames: Vec<FrameRec>,
    size_changes: Vec<SizeChange>,
    errors: Vec<String>,
    error_count: usize,
    pictures: Vec<PictureAsk>,
    done: Vec<PictureDone>,
    closed_at_us: Option<i64>,
}

/// A running WGC capture of one window.
struct Capture {
    item: GraphicsCaptureItem,
    pool: Direct3D11CaptureFramePool,
    session: GraphicsCaptureSession,
    frame_token: Option<i64>,
    closed_token: Option<i64>,
    shared: Arc<Mutex<Handler>>,
    writer: Option<JoinHandle<Vec<PictureDone>>>,
    stopped: bool,
}

impl Capture {
    /// The capture steps in `windows-capture`'s order, each recorded; `None` when one that a capture
    /// cannot do without failed (everything made so far is closed again).
    fn start(
        hwnd: usize,
        config: &Config,
        pictures_on: bool,
        steps: &mut Vec<Value>,
        notes: &mut Vec<String>,
    ) -> Option<Self> {
        let supported = match (
            ApiInformation::IsApiContractPresentByMajor(
                &HSTRING::from("Windows.Foundation.UniversalApiContract"),
                8,
            ),
            GraphicsCaptureSession::IsSupported(),
        ) {
            (Ok(true), Ok(true)) => Ok(Value::Null),
            (contract, supported) => Err(format!(
                "UniversalApiContract 8: {:?}; GraphicsCaptureSession::IsSupported: {:?}",
                contract.map_err(|e| error_text(&e)),
                supported.map_err(|e| error_text(&e))
            )),
        };
        if !step(steps, "WGC supported", true, supported) {
            return None;
        }

        let (device, context, level) = match create_device() {
            Ok(made) => made,
            Err(error) => {
                step(
                    steps,
                    "D3D11CreateDevice (hardware, BGRA)",
                    true,
                    Err(error),
                );
                return None;
            }
        };
        step(
            steps,
            "D3D11CreateDevice (hardware, BGRA)",
            true,
            Ok(json!({ "feature_level": format!("{:#x}", level.0) })),
        );
        let d3d = match winrt_device(&device) {
            Ok(d3d) => d3d,
            Err(error) => {
                step(
                    steps,
                    "CreateDirect3D11DeviceFromDXGIDevice",
                    true,
                    Err(error),
                );
                return None;
            }
        };
        step(
            steps,
            "CreateDirect3D11DeviceFromDXGIDevice",
            true,
            Ok(Value::Null),
        );

        // The question itself.
        let item = match create_item(hwnd) {
            Ok(item) => item,
            Err(error) => {
                step(
                    steps,
                    "IGraphicsCaptureItemInterop::CreateForWindow",
                    true,
                    Err(error),
                );
                return None;
            }
        };
        let size = match item.Size() {
            Ok(size) => size,
            Err(error) => {
                step(
                    steps,
                    "IGraphicsCaptureItemInterop::CreateForWindow",
                    true,
                    Err(format!(
                        "the item was made but its Size failed: {}",
                        error_text(&error)
                    )),
                );
                return None;
            }
        };
        let display_name = item
            .DisplayName()
            .map_or_else(|e| format!("? ({})", error_text(&e)), |n| n.to_string());
        step(
            steps,
            "IGraphicsCaptureItemInterop::CreateForWindow",
            true,
            Ok(json!({ "display_name": display_name, "size": [size.Width, size.Height] })),
        );

        let pool = match Direct3D11CaptureFramePool::CreateFreeThreaded(
            &d3d,
            DirectXPixelFormat::B8G8R8A8UIntNormalized,
            POOL_BUFFERS,
            size,
        ) {
            Ok(pool) => pool,
            Err(error) => {
                step(
                    steps,
                    "Direct3D11CaptureFramePool::CreateFreeThreaded",
                    true,
                    Err(error_text(&error)),
                );
                return None;
            }
        };
        step(
            steps,
            "Direct3D11CaptureFramePool::CreateFreeThreaded",
            true,
            Ok(Value::Null),
        );
        let session = match pool.CreateCaptureSession(&item) {
            Ok(session) => session,
            Err(error) => {
                step(steps, "CreateCaptureSession", true, Err(error_text(&error)));
                if let Err(error) = pool.Close() {
                    note(
                        WHO,
                        notes,
                        format!("closing the frame pool: {}", error_text(&error)),
                    );
                }
                return None;
            }
        };
        step(steps, "CreateCaptureSession", true, Ok(Value::Null));

        let (sender, writer) = if pictures_on {
            let (tx, rx) = sync_channel::<PictureJob>(PICTURE_QUEUE);
            match std::thread::Builder::new()
                .name("window-probe-pictures".into())
                .spawn(move || write_pictures(&rx))
            {
                Ok(handle) => (Some(tx), Some(handle)),
                Err(error) => {
                    note(
                        WHO,
                        notes,
                        format!("the picture writer did not start ({error}): no pictures"),
                    );
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
        let shared = Arc::new(Mutex::new(Handler {
            epoch: Instant::now(),
            device,
            context,
            d3d: AgileDevice(d3d),
            pool_size: (size.Width, size.Height),
            last_content: None,
            staging: None,
            frames: Vec::new(),
            size_changes: Vec::new(),
            errors: Vec::new(),
            error_count: 0,
            pictures: Vec::new(),
            last_picture_second: None,
            pending_size: None,
            writer: sender,
            pictures_dir: config.pictures.clone(),
            closed_at_us: None,
        }));
        let mut capture = Capture {
            item,
            pool,
            session,
            frame_token: None,
            closed_token: None,
            shared,
            writer,
            stopped: false,
        };

        let for_closed = Arc::clone(&capture.shared);
        let closed = capture.item.Closed(
            &TypedEventHandler::<GraphicsCaptureItem, IInspectable>::new(move |_, _| {
                let mut handler = lock(&for_closed);
                let t = handler.now_us();
                handler.closed_at_us.get_or_insert(t);
                Ok(())
            }),
        );
        match closed {
            Ok(token) => {
                capture.closed_token = Some(token);
                step(
                    steps,
                    "GraphicsCaptureItem::Closed handler",
                    false,
                    Ok(Value::Null),
                );
            }
            Err(error) => {
                step(
                    steps,
                    "GraphicsCaptureItem::Closed handler",
                    false,
                    Err(error_text(&error)),
                );
            }
        }
        let for_frames = Arc::clone(&capture.shared);
        let arrived = capture.pool.FrameArrived(&TypedEventHandler::<
            Direct3D11CaptureFramePool,
            IInspectable,
        >::new(move |pool, _| {
            if let Some(pool) = pool.as_ref() {
                lock(&for_frames).on_frame(pool);
            }
            Ok(())
        }));
        match arrived {
            Ok(token) => {
                capture.frame_token = Some(token);
                step(steps, "FrameArrived handler", true, Ok(Value::Null));
            }
            Err(error) => {
                step(steps, "FrameArrived handler", true, Err(error_text(&error)));
                capture.stop(notes);
                return None;
            }
        }

        session_property(steps, &capture.session, Property::Cursor, Some(true));
        session_property(steps, &capture.session, Property::Border, Some(false));
        session_property(
            steps,
            &capture.session,
            Property::Secondary,
            config.secondary.then_some(true),
        );

        lock(&capture.shared).epoch = Instant::now();
        match capture.session.StartCapture() {
            Ok(()) => {
                step(steps, "StartCapture", true, Ok(Value::Null));
                Some(capture)
            }
            Err(error) => {
                step(steps, "StartCapture", true, Err(error_text(&error)));
                capture.stop(notes);
                None
            }
        }
    }

    /// Close the session, the handlers and the pool, then flush the pictures; hands back what the
    /// handler collected. Every close that fails is noted.
    fn stop(&mut self, notes: &mut Vec<String>) -> Stopped {
        self.stopped = true;
        let mut closing = |what: &str, result: windows::core::Result<()>| {
            if let Err(error) = result {
                note(WHO, notes, format!("{what}: {}", error_text(&error)));
            }
        };
        closing("GraphicsCaptureSession::Close", self.session.Close());
        if let Some(token) = self.frame_token.take() {
            closing(
                "Direct3D11CaptureFramePool::RemoveFrameArrived",
                self.pool.RemoveFrameArrived(token),
            );
        }
        closing("Direct3D11CaptureFramePool::Close", self.pool.Close());
        if let Some(token) = self.closed_token.take() {
            closing(
                "GraphicsCaptureItem::RemoveClosed",
                self.item.RemoveClosed(token),
            );
        }
        let mut stopped = {
            let mut handler = lock(&self.shared);
            // Dropping the sender ends the writer once it has written what is queued.
            handler.writer = None;
            Stopped {
                ended_us: handler.now_us(),
                frames: std::mem::take(&mut handler.frames),
                size_changes: std::mem::take(&mut handler.size_changes),
                errors: std::mem::take(&mut handler.errors),
                error_count: handler.error_count,
                pictures: std::mem::take(&mut handler.pictures),
                done: Vec::new(),
                closed_at_us: handler.closed_at_us,
            }
        };
        if let Some(writer) = self.writer.take() {
            match writer.join() {
                Ok(done) => stopped.done = done,
                Err(_) => note(
                    WHO,
                    notes,
                    "the picture writer panicked; the pictures' results are lost".to_owned(),
                ),
            }
        }
        stopped
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if !self.stopped {
            // Only on an abnormal way out: the normal path stops with a record. Its notes are printed.
            let mut notes = Vec::new();
            let _ = self.stop(&mut notes);
        }
    }
}

/// The hardware D3D11 device with BGRA support a capture needs (also the cursor probe's).
pub(super) fn create_device(
) -> std::result::Result<(ID3D11Device, ID3D11DeviceContext, D3D_FEATURE_LEVEL), String> {
    // The levels `windows-capture` asks for.
    let levels = [
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
        D3D_FEATURE_LEVEL_9_3,
        D3D_FEATURE_LEVEL_9_2,
        D3D_FEATURE_LEVEL_9_1,
    ];
    let (mut device, mut level, mut context) = (None, D3D_FEATURE_LEVEL::default(), None);
    // SAFETY: live outputs; the level list outlives the call.
    unsafe {
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            Some(&levels),
            D3D11_SDK_VERSION,
            Some(&mut device),
            Some(&mut level),
            Some(&mut context),
        )
    }
    .map_err(|e| error_text(&e))?;
    match (device, context) {
        (Some(device), Some(context)) => Ok((device, context, level)),
        _ => Err("D3D11CreateDevice succeeded without a device or context".to_owned()),
    }
}

/// The WinRT device over a D3D11 one, which frame pools are made with (also the cursor probe's).
pub(super) fn winrt_device(device: &ID3D11Device) -> std::result::Result<IDirect3DDevice, String> {
    let dxgi: IDXGIDevice = device
        .cast()
        .map_err(|e| format!("IDXGIDevice: {}", error_text(&e)))?;
    // SAFETY: a live DXGI device.
    let inspectable =
        unsafe { CreateDirect3D11DeviceFromDXGIDevice(&dxgi) }.map_err(|e| error_text(&e))?;
    inspectable
        .cast()
        .map_err(|e| format!("IDirect3DDevice: {}", error_text(&e)))
}

/// `IGraphicsCaptureItemInterop::CreateForWindow` (also the cursor probe's).
pub(super) fn create_item(hwnd: usize) -> std::result::Result<GraphicsCaptureItem, String> {
    let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()
        .map_err(|e| format!("the interop factory: {}", error_text(&e)))?;
    // SAFETY: a window handle; the call validates it.
    unsafe { interop.CreateForWindow::<GraphicsCaptureItem>(hwnd_of(hwnd)) }
        .map_err(|e| error_text(&e))
}

/// A window above the target in the z-order, on screen, overlapping it.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct Over {
    #[serde(serialize_with = "hex")]
    hwnd: usize,
    pid: u32,
    exe: Option<String>,
    class: String,
    title: String,
    bounds: Rect,
    /// The part of the target it covers.
    covered: Rect,
    /// That part as a share of the target, 0..=1.
    fraction: f64,
    /// The game's own window (a dialog, a pop-up): `IncludeSecondaryWindows` may draw it in.
    same_process: bool,
    /// Layered and transparent to input: an overlay, usually invisible where it has nothing to draw.
    click_through: bool,
    topmost: bool,
}

impl Over {
    fn label(&self) -> String {
        let name = self.exe.clone().unwrap_or_else(|| self.class.clone());
        format!("{name} {:.0}%", self.fraction * 100.0)
    }
}

/// The windows among `above` (those above the target in the z-order) that are on screen and overlap
/// the target's drawn bounds.
fn windows_over(target: &WinFacts, above: &[WinFacts]) -> Vec<Over> {
    let Some(tb) = target.bounds() else {
        return Vec::new();
    };
    above
        .iter()
        .filter(|w| w.shown())
        .filter_map(|w| {
            let bounds = w.bounds()?;
            let covered = intersect(tb, bounds)?;
            Some(Over {
                hwnd: w.hwnd,
                pid: w.pid,
                exe: None,
                class: w.class.clone(),
                title: w.title.clone(),
                bounds,
                covered,
                fraction: (covered_fraction(tb, bounds) * 1000.0).round() / 1000.0,
                same_process: w.pid == target.pid,
                click_through: w.click_through(),
                topmost: w.topmost(),
            })
        })
        .collect()
}

/// One look by the main thread.
struct Look {
    t_us: i64,
    foreground: WinFacts,
    foreground_exe: Option<String>,
    /// `None`: the target window is gone.
    target: Option<WinFacts>,
    over: Vec<Over>,
    enum_error: Option<String>,
}

impl Look {
    fn covered_by(&self) -> Vec<String> {
        self.over
            .iter()
            .filter(|o| !o.same_process && !o.click_through)
            .map(Over::label)
            .collect()
    }

    fn own_over(&self) -> Vec<String> {
        self.over
            .iter()
            .filter(|o| o.same_process)
            .map(|o| format!("{} {:.0}%", o.class, o.fraction * 100.0))
            .collect()
    }

    fn state(&self) -> TickState {
        TickState {
            t_us: self.t_us,
            exists: self.target.is_some(),
            minimized: self.target.as_ref().is_some_and(|t| t.minimized),
            foreground_target: self
                .target
                .as_ref()
                .is_some_and(|t| t.hwnd == self.foreground.hwnd),
            covered_by: self.covered_by(),
            own_over: self.own_over(),
        }
    }
}

fn look(target: &WinFacts, names: &mut ExeNames, t_us: i64) -> Look {
    let fg = super::win::foreground();
    let foreground = if fg == 0 {
        WinFacts::default()
    } else {
        window_facts(fg)
    };
    let foreground_exe = if foreground.pid == 0 {
        None
    } else {
        names.get(foreground.pid)
    };
    let now = window_alive(target.hwnd).then(|| window_facts(target.hwnd));
    let (over, enum_error) = match &now {
        None => (Vec::new(), None),
        Some(t) => match top_level_windows() {
            Ok(list) => {
                let above: Vec<WinFacts> = list
                    .iter()
                    .take_while(|&&h| h != target.hwnd)
                    .map(|&h| window_facts(h))
                    .collect();
                let mut over = windows_over(t, &above);
                for o in &mut over {
                    o.exe = names.get(o.pid);
                }
                (over, None)
            }
            Err(error) => (Vec::new(), Some(error)),
        },
    };
    Look {
        t_us,
        foreground,
        foreground_exe,
        target: now,
        over,
        enum_error,
    }
}

/// What the summary needs of each look.
#[derive(Clone, Debug, Default, PartialEq)]
struct TickState {
    t_us: i64,
    exists: bool,
    minimized: bool,
    foreground_target: bool,
    /// Other processes' windows over the target (not click-through overlays), as labels.
    covered_by: Vec<String>,
    /// The game's own windows over it.
    own_over: Vec<String>,
}

#[derive(Default)]
struct Watch {
    ticks: Vec<TickState>,
}

/// The state at `t_us`: the last look at or before it (the first look for anything earlier).
fn state_at(ticks: &[TickState], t_us: i64) -> Option<&TickState> {
    let i = ticks.partition_point(|s| s.t_us <= t_us);
    ticks.get(i.saturating_sub(1))
}

/// How long `pred` held, each look standing for the time until the next (the last until `end_us`).
fn time_where(ticks: &[TickState], end_us: i64, pred: impl Fn(&TickState) -> bool) -> i64 {
    ticks
        .iter()
        .enumerate()
        .filter(|(_, s)| pred(s))
        .map(|(i, s)| {
            let next = ticks.get(i + 1).map_or(end_us, |n| n.t_us);
            (next - s.t_us).max(0)
        })
        .sum()
}

fn unique(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        // Labels carry a share ("notepad.exe 22%"); the name is what is unique.
        let name = item
            .rsplit_once(' ')
            .map_or(item.as_str(), |(n, _)| n)
            .to_owned();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn target_label(target: Option<&WinFacts>) -> String {
    match target {
        None => "gone".to_owned(),
        Some(t) if t.minimized => "minimized".to_owned(),
        Some(t) if !t.visible => "hidden".to_owned(),
        Some(t) if t.cloaked.unwrap_or(0) != 0 => "cloaked".to_owned(),
        Some(t) => format!("shown {}", rect_text(t.bounds())),
    }
}

fn foreground_label(look: &Look, target: &WinFacts) -> String {
    let f = &look.foreground;
    if f.hwnd == 0 {
        return "(none)".to_owned();
    }
    let name = look
        .foreground_exe
        .clone()
        .unwrap_or_else(|| f.class.clone());
    if f.hwnd == target.hwnd {
        format!("{name} *")
    } else if f.pid == target.pid {
        format!("{name} + \"{}\"", clip(&f.class, 16))
    } else {
        name
    }
}

fn over_label(look: &Look) -> String {
    let mut parts: Vec<String> = look
        .over
        .iter()
        .filter(|o| !o.click_through)
        .map(|o| {
            if o.same_process {
                format!("own {} {:.0}%", o.class, o.fraction * 100.0)
            } else {
                o.label()
            }
        })
        .collect();
    let overlays = look.over.iter().filter(|o| o.click_through).count();
    if overlays > 0 {
        parts.push(format!("+{overlays} overlay"));
    }
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join(", ")
    }
}

/// Log (and print) what changed since the last look: the foreground, the target's state, what covers
/// it.
fn log_transitions(last: Option<&Look>, now: &Look, target: &WinFacts, out: &mut Vec<Value>) {
    let t = format!("{:+7.1} s", now.t_us as f64 / 1e6);
    if last.is_none_or(|l| l.foreground.hwnd != now.foreground.hwnd) {
        let f = &now.foreground;
        println!(
            "{WHO}: {t}  foreground → {} {:#x} class \"{}\" title \"{}\"",
            foreground_label(now, target),
            f.hwnd,
            clip(&f.class, 40),
            clip(&f.title, 40)
        );
        out.push(json!({
            "t_ms": ms(now.t_us),
            "what": "foreground",
            "hwnd": format!("{:#x}", f.hwnd),
            "pid": f.pid,
            "exe": now.foreground_exe,
            "class": f.class,
            "title": f.title,
            "is_target": f.hwnd == target.hwnd,
            "target_process": f.pid == target.pid,
        }));
    }
    let key = |l: &Look| {
        l.target
            .as_ref()
            .map(|t| (t.visible, t.minimized, t.cloaked, t.bounds()))
    };
    if last.is_none_or(|l| key(l) != key(now)) {
        println!("{WHO}: {t}  target {}", target_label(now.target.as_ref()));
        out.push(json!({
            "t_ms": ms(now.t_us),
            "what": "target",
            "exists": now.target.is_some(),
            "window": now.target,
        }));
    }
    let over_key = |l: &Look| {
        l.over
            .iter()
            .map(|o| (o.hwnd, (o.fraction * 100.0).round() as i64))
            .collect::<Vec<_>>()
    };
    if last.is_none_or(|l| over_key(l) != over_key(now)) {
        println!("{WHO}: {t}  over the target: {}", over_label(now));
        out.push(json!({
            "t_ms": ms(now.t_us),
            "what": "over",
            "windows": now.over,
        }));
    }
}

fn row_header() -> String {
    format!(
        "{:>4}  {:<28} {:<24} {:<34} {:>6}  {:<16} picture",
        "t s", "foreground (* the target)", "target", "over the target", "frames", "size"
    )
}

/// Row `k`: the look at (or just after) `k` s, and the frames and pictures of `[k - 1, k)` s.
/// `target` is the window as chosen at the start, for telling it apart in the foreground column.
fn row(
    k: i64,
    look: &Look,
    target: &WinFacts,
    capture: &Capture,
    frame_cursor: &mut usize,
    picture_cursor: &mut usize,
) -> (Value, String) {
    let end_us = k * 1_000_000;
    let (frames, pictures) = {
        let handler = lock(&capture.shared);
        let frames: Vec<FrameRec> = handler
            .frames
            .iter()
            .skip(*frame_cursor)
            .take_while(|f| f.t_us < end_us)
            .copied()
            .collect();
        let pictures: Vec<String> = handler
            .pictures
            .iter()
            .skip(*picture_cursor)
            .take_while(|p| p.t_us < end_us)
            .map(|p| p.file.clone())
            .collect();
        (frames, pictures)
    };
    *frame_cursor += frames.len();
    *picture_cursor += pictures.len();
    let mut sizes: Vec<((i32, i32), usize)> = Vec::new();
    for f in &frames {
        match sizes.iter_mut().find(|(s, _)| *s == f.content) {
            Some((_, n)) => *n += 1,
            None => sizes.push((f.content, 1)),
        }
    }
    let now = look.target.as_ref();
    let record = json!({
        "t_s": k,
        "look_ms": ms(look.t_us),
        "foreground": {
            "hwnd": format!("{:#x}", look.foreground.hwnd),
            "pid": look.foreground.pid,
            "exe": look.foreground_exe,
            "class": look.foreground.class,
            "title": look.foreground.title,
            "is_target": look.foreground.hwnd == target.hwnd,
            "target_process": look.foreground.pid == target.pid,
        },
        "target": {
            "exists": now.is_some(),
            "visible": now.map(|t| t.visible),
            "minimized": now.map(|t| t.minimized),
            "cloaked": now.and_then(|t| t.cloaked),
            "rect": now.and_then(|t| t.rect),
            "frame": now.and_then(|t| t.frame),
        },
        "over": look.over,
        "frames": frames.len(),
        "sizes": sizes.iter().map(|((w, h), n)| json!({ "size": [w, h], "frames": n })).collect::<Vec<_>>(),
        "pictures": pictures,
    });
    let line = format!(
        "{:>4}  {:<28} {:<24} {:<34} {:>6}  {:<16} {}",
        k,
        clip(&foreground_label(look, target), 28),
        clip(&target_label(now), 24),
        clip(&over_label(look), 34),
        frames.len(),
        clip(
            &sizes
                .iter()
                .map(|(s, _)| size_text(*s))
                .collect::<Vec<_>>()
                .join(","),
            16
        ),
        if pictures.is_empty() {
            "-".to_owned()
        } else {
            pictures.join(" ")
        }
    );
    (record, line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(hwnd: usize, pid: u32, frame: Rect) -> WinFacts {
        WinFacts {
            hwnd,
            pid,
            class: format!("class{hwnd}"),
            visible: true,
            cloaked: Some(0),
            rect: Some(frame),
            frame: Some(frame),
            ..WinFacts::default()
        }
    }

    #[test]
    fn only_shown_windows_that_overlap_the_target_count_as_over_it() {
        let game = window(1, 100, [0, 0, 3600, 2328]);
        let notepad = window(2, 200, [1000, 500, 2800, 1664]);
        let mut hidden = window(3, 300, [0, 0, 500, 500]);
        hidden.visible = false;
        let mut minimized = window(4, 400, [0, 0, 500, 500]);
        minimized.minimized = true;
        let mut other_desktop = window(5, 500, [0, 0, 500, 500]);
        other_desktop.cloaked = Some(2);
        let taskbar = window(6, 600, [0, 2328, 3600, 2400]);
        let mut dialog = window(7, 100, [1500, 900, 2100, 1400]);
        dialog.owner = 1;
        let mut overlay = window(8, 800, [0, 0, 3600, 2400]);
        overlay.ex_style = 0x0008_0000 | 0x0000_0020 | 0x0000_0008;
        let over = windows_over(
            &game,
            &[
                notepad,
                hidden,
                minimized,
                other_desktop,
                taskbar,
                dialog,
                overlay,
            ],
        );
        let ids: Vec<usize> = over.iter().map(|o| o.hwnd).collect();
        assert_eq!(ids, vec![2, 7, 8]);
        let notepad = &over[0];
        assert_eq!(notepad.covered, [1000, 500, 2800, 1664]);
        let share = (1800.0 * 1164.0) / (3600.0 * 2328.0);
        assert!((notepad.fraction - (share * 1000.0f64).round() / 1000.0).abs() < 1e-9);
        assert!(!notepad.same_process && !notepad.click_through);
        assert!(over[1].same_process);
        assert!(over[2].click_through && over[2].topmost);
        assert!((over[2].fraction - 1.0).abs() < 1e-9);
        // A minimized target covers nothing, so nothing is over it.
        let mut hidden_game = window(1, 100, [-32000, -32000, -31840, -31972]);
        hidden_game.minimized = true;
        assert!(windows_over(&hidden_game, &[window(2, 200, [0, 0, 100, 100])]).is_empty());
    }

    #[test]
    fn a_look_splits_other_windows_from_the_games_own_and_overlays() {
        let game = window(1, 100, [0, 0, 1000, 1000]);
        let mut over = windows_over(
            &game,
            &[
                window(2, 200, [0, 0, 500, 1000]),
                window(3, 100, [0, 0, 100, 100]),
            ],
        );
        over[0].exe = Some("notepad.exe".to_owned());
        let look = Look {
            t_us: 5,
            foreground: window(2, 200, [0, 0, 500, 1000]),
            foreground_exe: Some("notepad.exe".to_owned()),
            target: Some(game),
            over,
            enum_error: None,
        };
        let state = look.state();
        assert_eq!(state.covered_by, vec!["notepad.exe 50%".to_owned()]);
        assert_eq!(state.own_over, vec!["class3 1%".to_owned()]);
        assert!(state.exists && !state.minimized && !state.foreground_target);
        assert_eq!(
            unique(["notepad.exe 50%".to_owned(), "notepad.exe 20%".to_owned()].into_iter()),
            vec!["notepad.exe".to_owned()]
        );
    }

    #[test]
    fn frames_take_the_state_of_the_last_look_before_them() {
        let tick = |t_us, minimized| TickState {
            t_us,
            exists: true,
            minimized,
            ..TickState::default()
        };
        let ticks = [tick(0, false), tick(100_000, true), tick(200_000, false)];
        assert!(!state_at(&ticks, 50_000).unwrap().minimized);
        assert!(state_at(&ticks, 100_000).unwrap().minimized);
        assert!(state_at(&ticks, 199_999).unwrap().minimized);
        assert!(!state_at(&ticks, 900_000).unwrap().minimized);
        // Before the first look: the first look.
        assert_eq!(state_at(&ticks, -5).unwrap().t_us, 0);
        assert!(state_at(&[], 0).is_none());
        // Minimized from 0.1 to 0.2 s; the last look stands until the end.
        assert_eq!(time_where(&ticks, 1_000_000, |s| s.minimized), 100_000);
        assert_eq!(time_where(&ticks, 1_000_000, |s| !s.minimized), 900_000);
    }

    #[test]
    fn the_checklist_paces_a_45_second_run() {
        assert_eq!(
            checklist(45),
            vec![
                "1. leave the game in front (about 0-8 s)".to_owned(),
                "2. put another window (Notepad) over part of the game, then move it away (about \
                 8-18 s)"
                    .to_owned(),
                "3. minimize the game (about 18-26 s)".to_owned(),
                "4. restore it (about 26-32 s)".to_owned(),
                "5. open some in-game dialog, if the game has one (about 32-45 s)".to_owned(),
            ]
        );
    }

    #[test]
    fn a_property_outcome_reads_as_one_phrase() {
        assert_eq!(property_outcome(&Value::Null), "not tried");
        let accepted = json!({
            "set": "ok", "reads": false, "accepted": true, "requested": false,
        });
        assert_eq!(property_outcome(&accepted), "set \"ok\", reads back false");
        let ignored = json!({
            "set": "ok", "reads": true, "accepted": false, "requested": false,
        });
        assert_eq!(
            property_outcome(&ignored),
            "set \"ok\", reads back true — not as asked"
        );
        let absent = json!({ "set": "skipped: not present on this OS", "present": false });
        assert_eq!(property_outcome(&absent), "not present on this OS (false)");
    }
}
