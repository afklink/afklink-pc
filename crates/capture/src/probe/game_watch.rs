//! The passive launch probe: what the process tree and the game's windows do while the game is
//! closed and started again through its launcher. It answers what to bind to (the loader
//! `ScrydeGame.exe` starts `ScrydeGame.bin` and exits; which window appears, when, with what class)
//! and how to tell a crash from a close (WerFault, exit codes). It starts nothing itself.
//!
//! ## Run it
//!
//! From `agent\`, in an **unelevated** terminal, with the game running:
//!
//! ```text
//! $env:AFK_PROBE_PROCESS = 'scrydegame'   # substring of the exe names to watch
//! cargo test -p afklink-capture --release --lib game_watch_probe -- --ignored --nocapture
//! ```
//!
//! - `AFK_PROBE_PROCESS` (required): a case-insensitive substring of the exe names to watch. For
//!   Lineage 2 (Scryde): `scrydegame` matches the loader `ScrydeGame.exe` and the game
//!   `ScrydeGame.bin` (not the updater `Scryde.exe`).
//! - `AFK_PROBE_SECONDS`: how long to watch, default 120.
//! - `AFK_PROBE_EXITCODE=1`: also open each watched process (the needle's and their children) with
//!   `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` and hold that handle until it exits, to read its
//!   exit code and exact exit time. **Off by default** because of the game's kernel anti-cheat: a
//!   handle held on the game for its whole life is more than it gets from AFKLink otherwise. Turn it on
//!   only for a run where telling a crash from a close by the exit code is worth that.
//! - `AFK_PROBE_OUT`: where the JSON goes (default `agent\target\game-watch-<yyyymmdd-hhmmss>.json`,
//!   local time).
//!
//! ## What the person at the PC does
//!
//! Nothing at the terminal. With the game running: (1) close it the normal way (the in-game exit)
//! and wait until its window is gone; (2) start it again by hand through `ScrydeGame.exe`,
//! answering UAC; (3) wait until the game's window is up (logging in is fine). A crash during the
//! run is recorded like anything else; nobody crashes the game on purpose.
//!
//! ## What it does
//!
//! Every 100 ms: a toolhelp process snapshot (pid, parent pid, exe name — no process is opened for
//! it) and `EnumWindows`. It watches every process whose exe name contains the needle, every child of
//! one (the loader's children, an anti-cheat helper), every `WerFault*.exe` (a crash report — of
//! anything; its command line's `-p <pid>` says whose), and `consent.exe` (the UAC prompt the loader
//! raises). For each watched process that appears — or is there at the start — it logs the pid, the
//! parent pid and exe (from the snapshot; "gone" when the parent has exited) and, through one handle
//! opened for `PROCESS_QUERY_LIMITED_INFORMATION` and closed at once, the full path (or the error),
//! the exact creation time, integrity and elevation (the token, for `TOKEN_QUERY`), and for WerFault
//! the command line. Every exit is logged at the first poll without it. Every top-level window of
//! a watched process is logged when it appears, when its class, title, visibility, minimized or cloaked
//! state, rectangle or owner changes, and when it goes; a `#32770` dialog of a watched process and any
//! WerFault window are listed as crash signs.
//!
//! **It never** injects input, sends a message to any window, starts, stops or signals a process, or
//! opens one for more than `PROCESS_QUERY_LIMITED_INFORMATION` — plus `SYNCHRONIZE` with
//! `AFK_PROBE_EXITCODE=1`, and then only for the needle's processes and their children.
//!
//! ## What to look at
//!
//! `summary.verdict` (also printed): the loader → game chain with its times (the game created how long
//! after the loader, its first window on screen how long after that, when the loader exited), each exit
//! (with the exit code when asked for), WerFault and dialogs, and whether the paths were readable with
//! limited rights. `events` is the full timeline, `processes` one record per process.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde::Serialize;
use serde_json::{json, Value};
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

use super::win::{
    command_line, env_text, error_text, filetime_ms_after, local_time, make_dpi_aware, note,
    now_filetime, open_limited, os_version, output_path, own_process, process_facts,
    process_facts_on, process_times, snapshot, top_level_windows, window_facts, window_pid,
    write_json, Owned, ProcEntry, WinFacts,
};
use super::{clip, needle_of, parse_flag, parse_seconds, rect_text};

const WHO: &str = "game_watch_probe";
const DEFAULT_SECONDS: u64 = 120;
const POLL: Duration = Duration::from_millis(100);
/// Errors of the same kind printed word for word; the rest are counted.
const ERRORS_PRINTED: usize = 5;

#[test]
#[ignore = "watches processes and windows for 2 minutes while the owner restarts the game; run by hand, see the module docs"]
fn game_watch_probe() -> Result<()> {
    let Some(process) = env_text("AFK_PROBE_PROCESS")?
        .as_deref()
        .and_then(needle_of)
    else {
        bail!(
            "AFK_PROBE_PROCESS is not set: set it to a substring of the exe names to watch, e.g. \
             $env:AFK_PROBE_PROCESS = 'scrydegame', then run again"
        );
    };
    let seconds = parse_seconds(env_text("AFK_PROBE_SECONDS")?.as_deref(), DEFAULT_SECONDS)
        .map_err(anyhow::Error::msg)?;
    let exit_codes = parse_flag(
        "AFK_PROBE_EXITCODE",
        env_text("AFK_PROBE_EXITCODE")?.as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let out = output_path("game-watch")?;
    println!(
        "{WHO}: process \"{process}\", {seconds} s, exit codes {}; output {}",
        if exit_codes { "on" } else { "off" },
        out.display()
    );
    let mut watcher = Watcher::new(Config {
        needle: process,
        seconds,
        exit_codes,
        out,
    });
    let outcome = watcher.run();
    watcher.finish(outcome)
}

struct Config {
    needle: String,
    seconds: u64,
    exit_codes: bool,
    out: PathBuf,
}

/// Why a process is watched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    /// Its exe name contains the needle.
    Name,
    /// Its parent is watched for its name, or is such a child.
    Child,
    /// A crash report.
    WerFault,
    /// The UAC prompt.
    Consent,
}

impl Why {
    fn name(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Child => "child",
            Self::WerFault => "werfault",
            Self::Consent => "consent",
        }
    }

    /// The game's own processes: what the chains, the windows' first-shown times and the exit codes
    /// are about.
    fn game(self) -> bool {
        matches!(self, Self::Name | Self::Child)
    }
}

/// Why a process with this exe name is watched, given why its parent is (`None`: not watched).
fn watch_reason(exe: &str, needle: &str, parent: Option<Why>) -> Option<Why> {
    let lower = exe.to_lowercase();
    if lower.contains(needle) {
        Some(Why::Name)
    } else if lower.starts_with("werfault") {
        Some(Why::WerFault)
    } else if lower == "consent.exe" {
        Some(Why::Consent)
    } else if parent.is_some_and(Why::game) {
        Some(Why::Child)
    } else {
        None
    }
}

/// Processes that appeared and exited between two snapshots, by pid, ascending. A pid that now names
/// another exe exited and appeared again (reused).
fn diff(before: &HashMap<u32, String>, after: &HashMap<u32, String>) -> (Vec<u32>, Vec<u32>) {
    let mut appeared: Vec<u32> = after
        .iter()
        .filter(|(pid, exe)| before.get(pid) != Some(exe))
        .map(|(pid, _)| *pid)
        .collect();
    let mut exited: Vec<u32> = before
        .iter()
        .filter(|(pid, exe)| after.get(pid) != Some(exe))
        .map(|(pid, _)| *pid)
        .collect();
    appeared.sort_unstable();
    exited.sort_unstable();
    (appeared, exited)
}

/// `pids` reordered so that a process comes after its parent when both are in it: the watch decision
/// for a child needs its parent's.
fn parents_first(pids: &[u32], parent_of: impl Fn(u32) -> u32) -> Vec<u32> {
    let all: HashSet<u32> = pids.iter().copied().collect();
    let mut done: HashSet<u32> = HashSet::new();
    let mut order = Vec::with_capacity(pids.len());
    for _ in 0..pids.len() {
        for &pid in pids {
            if done.contains(&pid) {
                continue;
            }
            let ppid = parent_of(pid);
            if ppid == pid || !all.contains(&ppid) || done.contains(&ppid) {
                order.push(pid);
                done.insert(pid);
            }
        }
        if order.len() == pids.len() {
            return order;
        }
    }
    // A parent loop cannot happen with live pids; if the snapshot ever shows one, keep the rest as is.
    order.extend(pids.iter().filter(|p| !done.contains(p)));
    order
}

/// The pid a WerFault command line reports on (`WerFault.exe -u -p 1234 -s 567`).
fn werfault_target_pid(command_line: &str) -> Option<u32> {
    let words: Vec<&str> = command_line.split_whitespace().collect();
    words
        .windows(2)
        .find(|w| w[0].eq_ignore_ascii_case("-p") || w[0].eq_ignore_ascii_case("/p"))
        .and_then(|w| w[1].parse().ok())
}

/// An exit code with its usual meaning, and whether it reads like a crash.
fn exit_code_label(code: u32) -> String {
    let name = match code {
        0 => Some("success"),
        1 => Some("generic failure, or TerminateProcess(…, 1)"),
        259 => Some("STILL_ACTIVE"),
        0x4001_0004 => Some("DBG_TERMINATE_PROCESS"),
        0x8000_0003 => Some("STATUS_BREAKPOINT"),
        0xC000_0005 => Some("STATUS_ACCESS_VIOLATION"),
        0xC000_001D => Some("STATUS_ILLEGAL_INSTRUCTION"),
        0xC000_0094 => Some("STATUS_INTEGER_DIVIDE_BY_ZERO"),
        0xC000_00FD => Some("STATUS_STACK_OVERFLOW"),
        0xC000_013A => Some("STATUS_CONTROL_C_EXIT"),
        0xC000_0374 => Some("STATUS_HEAP_CORRUPTION"),
        0xC000_0409 => Some("STATUS_STACK_BUFFER_OVERRUN (fail-fast)"),
        0xE06D_7363 => Some("unhandled C++ exception"),
        _ => None,
    };
    format!(
        "{code} ({code:#010x}){}{}",
        name.map_or_else(String::new, |n| format!(" {n}")),
        if looks_like_crash(code) {
            ", a crash"
        } else {
            ""
        }
    )
}

fn looks_like_crash(code: u32) -> bool {
    ((code & 0xC000_0000) == 0xC000_0000 && code != 0xC000_013A)
        || code == 0x8000_0003
        || code == 0xE06D_7363
}

/// What changed between two looks at one window.
fn changed_fields(a: &WinFacts, b: &WinFacts) -> Vec<&'static str> {
    let mut out = Vec::new();
    if a.class != b.class {
        out.push("class");
    }
    if a.title != b.title {
        out.push("title");
    }
    if a.visible != b.visible {
        out.push("visible");
    }
    if a.minimized != b.minimized {
        out.push("minimized");
    }
    if a.cloaked != b.cloaked {
        out.push("cloaked");
    }
    if a.rect != b.rect {
        out.push("rect");
    }
    if a.owner != b.owner {
        out.push("owner");
    }
    out
}

/// A process's times, for the chains.
#[derive(Clone, Debug, PartialEq)]
struct ProcTimes {
    pid: u32,
    ppid: u32,
    exe: String,
    why: Why,
    /// Its creation (exact) when read, else when first seen, ms after the probe started.
    start_ms: f64,
    exited_ms: Option<f64>,
    first_shown_ms: Option<f64>,
    first_shown: Option<String>,
}

/// A parent → child step of the game's own processes, in seconds.
#[derive(Clone, Debug, PartialEq, Serialize)]
struct Chain {
    parent: String,
    child: String,
    child_after_parent_s: f64,
    child_window: Option<String>,
    child_window_after_child_s: Option<f64>,
    child_window_after_parent_s: Option<f64>,
    parent_exited_after_parent_s: Option<f64>,
}

/// ms as s, rounded to the ms.
fn secs(ms: f64) -> f64 {
    ms.round() / 1000.0
}

/// Every child of the game's processes whose parent was seen too — the parent being the process with
/// that pid that started last before the child (pids are reused).
fn chains(procs: &[ProcTimes]) -> Vec<Chain> {
    procs
        .iter()
        .filter(|c| c.why.game())
        .filter_map(|c| {
            let p = procs
                .iter()
                .filter(|p| p.pid == c.ppid && p.why.game() && p.start_ms <= c.start_ms)
                .max_by(|a, b| a.start_ms.total_cmp(&b.start_ms))?;
            Some(Chain {
                parent: format!("{} pid {}", p.exe, p.pid),
                child: format!("{} pid {}", c.exe, c.pid),
                child_after_parent_s: secs(c.start_ms - p.start_ms),
                child_window: c.first_shown.clone(),
                child_window_after_child_s: c.first_shown_ms.map(|w| secs(w - c.start_ms)),
                child_window_after_parent_s: c.first_shown_ms.map(|w| secs(w - p.start_ms)),
                parent_exited_after_parent_s: p.exited_ms.map(|e| secs(e - p.start_ms)),
            })
        })
        .collect()
}

/// One watched process.
struct Proc {
    pid: u32,
    ppid: u32,
    exe: String,
    why: Why,
    parent_exe: Option<String>,
    parent_alive: bool,
    at_start: bool,
    seen_ms: f64,
    /// Path, creation time, integrity, elevation (or why not), through a limited handle.
    facts: Value,
    command_line: Option<std::result::Result<String, String>>,
    reports_on: Option<(u32, Option<String>)>,
    /// Held only with `AFK_PROBE_EXITCODE=1`, until the exit is read.
    handle: Option<Owned>,
    handle_note: Option<String>,
    exited_ms: Option<f64>,
    exit_code: Option<std::result::Result<u32, String>>,
    exit_time_ms: Option<f64>,
    first_window_ms: Option<f64>,
    first_shown_ms: Option<f64>,
    first_shown: Option<String>,
    windows_seen: usize,
}

impl Proc {
    fn created_ms(&self) -> Option<f64> {
        self.facts["created_ms"].as_f64()
    }

    fn times(&self) -> ProcTimes {
        ProcTimes {
            pid: self.pid,
            ppid: self.ppid,
            exe: self.exe.clone(),
            why: self.why,
            start_ms: self.created_ms().unwrap_or(self.seen_ms),
            exited_ms: self.exit_time_ms.or(self.exited_ms),
            first_shown_ms: self.first_shown_ms,
            first_shown: self.first_shown.clone(),
        }
    }

    fn label(&self) -> String {
        format!("{} pid {}", self.exe, self.pid)
    }

    fn to_json(&self) -> Value {
        json!({
            "pid": self.pid,
            "ppid": self.ppid,
            "exe": self.exe,
            "why": self.why.name(),
            "parent_exe": self.parent_exe,
            "parent_alive_when_seen": self.parent_alive,
            "present_at_start": self.at_start,
            "seen_ms": self.seen_ms,
            "facts": self.facts,
            "command_line": self.command_line.as_ref().map(|c| match c {
                Ok(text) => json!(text),
                Err(error) => json!({ "error": error }),
            }),
            "reports_on_pid": self.reports_on.as_ref().map(|r| r.0),
            "reports_on_exe": self.reports_on.as_ref().and_then(|r| r.1.clone()),
            "exit_code_handle": self.handle_note,
            "exited_ms": self.exited_ms,
            "exit_code": self.exit_code.as_ref().map(|c| match c {
                Ok(code) => json!({ "code": code, "label": exit_code_label(*code) }),
                Err(error) => json!({ "error": error }),
            }),
            "exit_time_ms": self.exit_time_ms,
            "first_window_ms": self.first_window_ms,
            "first_shown_ms": self.first_shown_ms,
            "first_shown": self.first_shown,
            "windows_seen": self.windows_seen,
        })
    }
}

struct Watcher {
    config: Config,
    started_local: String,
    environment: Value,
    epoch: Instant,
    /// FILETIME at the start: creation and exit times are ms after it.
    epoch_ft: u64,
    procs: Vec<Proc>,
    /// Watched processes still alive: pid → index into `procs`.
    live: HashMap<u32, usize>,
    /// Every exe name ever seen by pid, for a parent that has exited.
    ever: HashMap<u32, String>,
    previous: HashMap<u32, String>,
    tracked: HashMap<usize, WinFacts>,
    events: Vec<Value>,
    crash_signs: Vec<Value>,
    polls: usize,
    poll_max_ms: f64,
    polls_late: usize,
    snapshot_errors: usize,
    enum_errors: usize,
    summary: Value,
    notes: Vec<String>,
}

impl Watcher {
    fn new(config: Config) -> Self {
        Self {
            config,
            started_local: local_time(),
            environment: Value::Null,
            epoch: Instant::now(),
            epoch_ft: now_filetime(),
            procs: Vec::new(),
            live: HashMap::new(),
            ever: HashMap::new(),
            previous: HashMap::new(),
            tracked: HashMap::new(),
            events: Vec::new(),
            crash_signs: Vec::new(),
            polls: 0,
            poll_max_ms: 0.0,
            polls_late: 0,
            snapshot_errors: 0,
            enum_errors: 0,
            summary: Value::Null,
            notes: Vec::new(),
        }
    }

    fn t_ms(&self) -> f64 {
        self.epoch.elapsed().as_micros() as f64 / 1000.0
    }

    fn event(&mut self, t_ms: f64, kind: &str, text: String, detail: Value) {
        println!("{WHO}: {:+9.3} s  {kind:<14} {text}", t_ms / 1000.0);
        self.events
            .push(json!({ "t_ms": t_ms, "kind": kind, "text": text, "detail": detail }));
    }

    fn run(&mut self) -> Result<()> {
        let dpi = make_dpi_aware(WHO, &mut self.notes);
        self.environment = json!({ "dpi": dpi, "os": os_version(), "process": own_process() });
        println!(
            "{WHO}: Windows {} build {}.{}; this process {}",
            self.environment["os"]["display_version"],
            self.environment["os"]["build"],
            self.environment["os"]["ubr"],
            self.environment["process"]
        );
        self.print_checklist();

        self.epoch = Instant::now();
        self.epoch_ft = now_filetime();
        let deadline = self.epoch + Duration::from_secs(self.config.seconds);
        let mut first = true;
        loop {
            let poll_start = Instant::now();
            let t_ms = self.t_ms();
            match snapshot() {
                Ok(list) => self.processes(&list, first, t_ms),
                Err(error) => {
                    self.snapshot_errors += 1;
                    if self.snapshot_errors <= ERRORS_PRINTED {
                        note(
                            WHO,
                            &mut self.notes,
                            format!("+{:.1} s: {error}", t_ms / 1000.0),
                        );
                    }
                }
            }
            if self.config.exit_codes {
                self.read_exits(t_ms);
            }
            self.windows(first, t_ms);
            first = false;

            self.polls += 1;
            let took = poll_start.elapsed();
            self.poll_max_ms = self.poll_max_ms.max(took.as_secs_f64() * 1000.0);
            if took > POLL {
                self.polls_late += 1;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(POLL.saturating_sub(took));
        }
        // Exits that landed between the last poll and now; then every handle goes.
        if self.config.exit_codes {
            let t_ms = self.t_ms();
            self.read_exits(t_ms);
        }
        let held = self.procs.iter().filter(|p| p.handle.is_some()).count();
        for p in &mut self.procs {
            p.handle = None;
        }
        if held > 0 {
            println!("{WHO}: closed {held} exit-code handles of processes still running");
        }
        self.summarize();
        Ok(())
    }

    fn print_checklist(&self) {
        println!();
        println!(
            "{WHO}: watching for {} s: processes whose exe name contains \"{}\", their children, \
             WerFault and consent.exe (UAC), and every top-level window of theirs. Nothing to do at \
             this terminal. By hand, at the PC:",
            self.config.seconds, self.config.needle
        );
        println!(
            "{WHO}:   1. close the game the normal way (the in-game exit) and wait until its window \
             is gone;"
        );
        println!(
            "{WHO}:   2. start it again through its launcher (ScrydeGame.exe for the owner's L2); \
             answer UAC if it asks;"
        );
        println!("{WHO}:   3. wait until the game's window is up (logging in is fine).");
        if self.config.exit_codes {
            println!(
                "{WHO}: exit codes ON: each of the game's processes is opened with \
                 QUERY_LIMITED_INFORMATION | SYNCHRONIZE and held until it exits."
            );
        } else {
            println!(
                "{WHO}: exit codes off (AFK_PROBE_EXITCODE=1 would hold a SYNCHRONIZE handle on each \
                 of the game's processes; off by default because of its anti-cheat)."
            );
        }
        println!();
    }

    /// One snapshot: exits first (a reused pid exits and appears again), then appearances, parents
    /// before children.
    fn processes(&mut self, list: &[ProcEntry], first: bool, t_ms: f64) {
        let next: HashMap<u32, String> = list.iter().map(|p| (p.pid, p.exe.clone())).collect();
        let by_pid: HashMap<u32, &ProcEntry> = list.iter().map(|p| (p.pid, p)).collect();
        for p in list {
            self.ever.insert(p.pid, p.exe.clone());
        }
        let (appeared, exited) = diff(&self.previous, &next);
        for pid in exited {
            self.exited(pid, t_ms);
        }
        let order = parents_first(&appeared, |pid| by_pid.get(&pid).map_or(0, |p| p.ppid));
        for pid in order {
            let Some(entry) = by_pid.get(&pid) else {
                continue;
            };
            let parent = self.live.get(&entry.ppid).map(|&i| self.procs[i].why);
            if let Some(why) = watch_reason(&entry.exe, &self.config.needle, parent) {
                self.add(entry, why, first, t_ms, &next);
            }
        }
        self.previous = next;
    }

    fn add(
        &mut self,
        entry: &ProcEntry,
        why: Why,
        at_start: bool,
        t_ms: f64,
        alive: &HashMap<u32, String>,
    ) {
        let parent_alive = alive.contains_key(&entry.ppid);
        let parent_exe = alive
            .get(&entry.ppid)
            .or_else(|| self.ever.get(&entry.ppid))
            .cloned();
        // One handle for the facts: limited, closed at once — unless exit codes are wanted for the
        // game's processes, when it also has SYNCHRONIZE and is kept until the exit is read.
        let hold = self.config.exit_codes && why.game();
        let (facts, handle, handle_note, command) = if hold {
            match open_limited(entry.pid, true) {
                Ok(handle) => (
                    process_facts_on(&handle, self.epoch_ft),
                    Some(handle),
                    Some("held (QUERY_LIMITED_INFORMATION | SYNCHRONIZE)".to_owned()),
                    None,
                ),
                Err(error) => (
                    process_facts(entry.pid, self.epoch_ft),
                    None,
                    Some(format!("refused: {error}")),
                    None,
                ),
            }
        } else {
            match open_limited(entry.pid, false) {
                Ok(handle) => {
                    let facts = process_facts_on(&handle, self.epoch_ft);
                    let command = (why == Why::WerFault).then(|| command_line(&handle));
                    (facts, None, None, command)
                }
                Err(error) => (json!({ "open_error": error }), None, None, None),
            }
        };
        let reports_on = command
            .as_ref()
            .and_then(|c| c.as_ref().ok())
            .and_then(|c| werfault_target_pid(c))
            .map(|pid| (pid, self.ever.get(&pid).cloned()));
        let proc = Proc {
            pid: entry.pid,
            ppid: entry.ppid,
            exe: entry.exe.clone(),
            why,
            parent_exe,
            parent_alive,
            at_start,
            seen_ms: t_ms,
            facts,
            command_line: command,
            reports_on,
            handle,
            handle_note,
            exited_ms: None,
            exit_code: None,
            exit_time_ms: None,
            first_window_ms: None,
            first_shown_ms: None,
            first_shown: None,
            windows_seen: 0,
        };
        let f = &proc.facts;
        let mut text = format!(
            "{} pid {} ({}; parent {} {}{})",
            proc.exe,
            proc.pid,
            why.name(),
            proc.ppid,
            proc.parent_exe.as_deref().unwrap_or("?"),
            if parent_alive { "" } else { ", gone" }
        );
        match f["created_ms"].as_f64() {
            Some(c) => text.push_str(&format!(" created {:+.3} s", c / 1000.0)),
            None => text.push_str(&format!(
                " created ? ({})",
                f.get("created_error")
                    .or_else(|| f.get("open_error"))
                    .unwrap_or(&Value::Null)
            )),
        }
        text.push_str(&format!(
            "; {}; {} {}",
            f.get("path")
                .or_else(|| f.get("path_error"))
                .or_else(|| f.get("open_error"))
                .unwrap_or(&Value::Null),
            f.get("integrity")
                .or_else(|| f.get("integrity_error"))
                .or_else(|| f.get("token_error"))
                .unwrap_or(&Value::Null),
            match f["elevated"].as_bool() {
                Some(true) => "elevated",
                Some(false) => "not elevated",
                None => "elevation ?",
            }
        ));
        if let Some(command) = &proc.command_line {
            text.push_str(&format!("; command line {command:?}"));
        }
        if let Some((pid, exe)) = &proc.reports_on {
            text.push_str(&format!(
                "; reports on pid {pid} ({})",
                exe.as_deref().unwrap_or("?")
            ));
        }
        if let Some(handle) = &proc.handle_note {
            text.push_str(&format!("; exit-code handle {handle}"));
        }
        let detail = proc.to_json();
        if why == Why::WerFault {
            self.crash_signs.push(
                json!({ "t_ms": t_ms, "kind": "werfault process", "process": detail.clone() }),
            );
        }
        let kind = if at_start { "present" } else { "start" };
        self.live.insert(proc.pid, self.procs.len());
        self.procs.push(proc);
        self.event(t_ms, kind, text, detail);
    }

    fn exited(&mut self, pid: u32, t_ms: f64) {
        let Some(i) = self.live.remove(&pid) else {
            return;
        };
        let p = &mut self.procs[i];
        p.exited_ms = Some(t_ms);
        let start = p.created_ms().unwrap_or(p.seen_ms);
        let text = format!(
            "{} ({}) — {} {:.3} s",
            p.label(),
            p.why.name(),
            if p.created_ms().is_some() {
                "lived"
            } else {
                "seen for"
            },
            (t_ms - start) / 1000.0
        );
        self.event(t_ms, "exit", text, json!({ "pid": pid }));
    }

    /// With exit codes on: every held handle whose process has ended gives its code and exit time.
    fn read_exits(&mut self, t_ms: f64) {
        let mut done = Vec::new();
        for (i, p) in self.procs.iter_mut().enumerate() {
            let Some(handle) = &p.handle else {
                continue;
            };
            // SAFETY: a live process handle with SYNCHRONIZE; a zero wait only polls.
            if unsafe { WaitForSingleObject(handle.0, 0) } != WAIT_OBJECT_0 {
                continue;
            }
            let mut code = 0u32;
            // SAFETY: a live handle and output.
            p.exit_code = Some(
                unsafe { GetExitCodeProcess(handle.0, &mut code) }
                    .map(|()| code)
                    .map_err(|e| format!("GetExitCodeProcess: {}", error_text(&e))),
            );
            p.exit_time_ms = process_times(handle)
                .ok()
                .map(|(_, exit)| filetime_ms_after(exit, self.epoch_ft));
            p.handle = None;
            done.push(i);
        }
        for i in done {
            let p = &self.procs[i];
            let text = format!(
                "{}: {}{}",
                p.label(),
                match &p.exit_code {
                    Some(Ok(code)) => exit_code_label(*code),
                    Some(Err(error)) => error.clone(),
                    None => "?".to_owned(),
                },
                p.exit_time_ms
                    .map_or_else(String::new, |e| format!("; exited at {:+.3} s", e / 1000.0))
            );
            let detail = json!({ "pid": p.pid, "exit": p.to_json()["exit_code"] });
            self.event(t_ms, "exit code", text, detail);
        }
    }

    /// Every top-level window of a watched, living process: new, changed, gone.
    fn windows(&mut self, first: bool, t_ms: f64) {
        let list = match top_level_windows() {
            Ok(list) => list,
            Err(error) => {
                self.enum_errors += 1;
                if self.enum_errors <= ERRORS_PRINTED {
                    note(
                        WHO,
                        &mut self.notes,
                        format!("+{:.1} s: {error}", t_ms / 1000.0),
                    );
                }
                return;
            }
        };
        let mut seen = HashSet::new();
        for hwnd in list {
            let pid = window_pid(hwnd);
            let Some(&i) = self.live.get(&pid) else {
                continue;
            };
            let facts = window_facts(hwnd);
            seen.insert(hwnd);
            let why = self.procs[i].why;
            let shown = facts.shown();
            let crash_sign = why == Why::WerFault || facts.class == "#32770";
            let old = self.tracked.insert(hwnd, facts.clone());
            let p = &mut self.procs[i];
            let label = p.label();
            match old {
                None => {
                    p.windows_seen += 1;
                    p.first_window_ms.get_or_insert(t_ms);
                    if shown && p.first_shown_ms.is_none() {
                        p.first_shown_ms = Some(t_ms);
                        p.first_shown = Some(window_label(&facts));
                    }
                    let text = format!(
                        "{label}: {:#x} {}{}",
                        hwnd,
                        window_text(&facts),
                        if crash_sign { " [crash sign]" } else { "" }
                    );
                    if crash_sign {
                        self.crash_signs.push(json!({
                            "t_ms": t_ms, "kind": "window", "process": label, "window": facts,
                        }));
                    }
                    let kind = if first {
                        "window present"
                    } else {
                        "window new"
                    };
                    self.event(t_ms, kind, text, json!(facts));
                }
                Some(old) => {
                    if shown && p.first_shown_ms.is_none() {
                        p.first_shown_ms = Some(t_ms);
                        p.first_shown = Some(window_label(&facts));
                    }
                    let changed = changed_fields(&old, &facts);
                    if !changed.is_empty() {
                        let text = format!(
                            "{label}: {:#x} {} → {}",
                            hwnd,
                            changed.join(", "),
                            window_text(&facts)
                        );
                        self.event(
                            t_ms,
                            "window change",
                            text,
                            json!({ "changed": changed, "window": facts }),
                        );
                    }
                }
            }
        }
        let gone: Vec<usize> = self
            .tracked
            .keys()
            .filter(|h| !seen.contains(*h))
            .copied()
            .collect();
        for hwnd in gone {
            if let Some(old) = self.tracked.remove(&hwnd) {
                let text = format!(
                    "pid {}: {:#x} class \"{}\" title \"{}\"",
                    old.pid,
                    hwnd,
                    clip(&old.class, 40),
                    clip(&old.title, 40)
                );
                self.event(t_ms, "window gone", text, json!(old));
            }
        }
    }

    fn summarize(&mut self) {
        let times: Vec<ProcTimes> = self.procs.iter().map(Proc::times).collect();
        let chains = chains(&times);
        let mut verdict = Vec::new();
        for c in &chains {
            verdict.push(format!(
                "{} → {}: created {:.3} s after it; the child's first window on screen {}; the \
                 parent exited {}",
                c.parent,
                c.child,
                c.child_after_parent_s,
                match (
                    &c.child_window,
                    c.child_window_after_child_s,
                    c.child_window_after_parent_s
                ) {
                    (Some(w), Some(a), Some(b)) =>
                        format!("{a:.3} s after the child ({b:.3} s after the parent): {w}"),
                    _ => "not seen".to_owned(),
                },
                c.parent_exited_after_parent_s.map_or_else(
                    || "not seen".to_owned(),
                    |e| format!("{e:.3} s after its start")
                ),
            ));
        }
        for p in self.procs.iter().filter(|p| p.why.game()) {
            let start = p.created_ms().unwrap_or(p.seen_ms);
            let window = match (&p.first_shown, p.first_shown_ms) {
                (Some(w), Some(t)) if !p.at_start => {
                    format!(
                        "first window on screen {:.3} s after its start: {w}",
                        (t - start) / 1000.0
                    )
                }
                (Some(w), Some(_)) => format!("had a window on screen at the start: {w}"),
                _ => "no window on screen seen".to_owned(),
            };
            let exit = match (p.exited_ms, &p.exit_code) {
                (None, _) => "still running at the end".to_owned(),
                (Some(t), Some(Ok(code))) => format!(
                    "exited at {:+.3} s, exit code {}",
                    p.exit_time_ms.unwrap_or(t) / 1000.0,
                    exit_code_label(*code)
                ),
                (Some(t), Some(Err(error))) => {
                    format!("exited at {:+.3} s, exit code unread: {error}", t / 1000.0)
                }
                (Some(t), None) => format!(
                    "exited at {:+.3} s ({})",
                    t / 1000.0,
                    if self.config.exit_codes {
                        "no exit code: no handle"
                    } else {
                        "exit codes off"
                    }
                ),
            };
            verdict.push(format!(
                "{} ({}{}): {window}; {exit}",
                p.label(),
                if p.at_start {
                    "present at the start"
                } else {
                    "started "
                },
                if p.at_start {
                    String::new()
                } else {
                    format!("{:+.3} s", start / 1000.0)
                },
            ));
        }
        let werfault: Vec<&Proc> = self
            .procs
            .iter()
            .filter(|p| p.why == Why::WerFault)
            .collect();
        if werfault.is_empty() {
            verdict.push("no WerFault process appeared".to_owned());
        } else {
            for w in werfault {
                verdict.push(format!(
                    "WerFault: {} at {:+.3} s, reports on {}",
                    w.label(),
                    w.seen_ms / 1000.0,
                    w.reports_on.as_ref().map_or_else(
                        || "? (no command line)".to_owned(),
                        |(pid, exe)| format!("pid {pid} ({})", exe.as_deref().unwrap_or("?"))
                    )
                ));
            }
        }
        let dialogs = self
            .crash_signs
            .iter()
            .filter(|s| s["kind"] == json!("window"))
            .count();
        if dialogs > 0 {
            verdict.push(format!(
                "{dialogs} crash-sign windows (a #32770 dialog of a watched process, or a WerFault \
                 window): see summary.crash_signs"
            ));
        }
        for c in self.procs.iter().filter(|p| p.why == Why::Consent) {
            verdict.push(format!(
                "UAC prompt: {} from {:+.3} s{}",
                c.label(),
                c.seen_ms / 1000.0,
                c.exited_ms
                    .map_or_else(String::new, |e| format!(" to {:+.3} s", e / 1000.0))
            ));
        }
        let game: Vec<&Proc> = self.procs.iter().filter(|p| p.why.game()).collect();
        let refused: Vec<String> = game
            .iter()
            .filter(|p| p.facts.get("path").is_none())
            .map(|p| {
                format!(
                    "{} ({})",
                    p.label(),
                    p.facts
                        .get("path_error")
                        .or_else(|| p.facts.get("open_error"))
                        .unwrap_or(&Value::Null)
                )
            })
            .collect();
        verdict.push(if refused.is_empty() {
            format!(
                "the full path was read with limited rights for all {} of the game's processes",
                game.len()
            )
        } else {
            format!("the full path was refused for: {}", refused.join("; "))
        });
        if self.polls_late > 0 {
            verdict.push(format!(
                "{} of {} polls took longer than {} ms (longest {:.0} ms): times are that coarse there",
                self.polls_late,
                self.polls,
                POLL.as_millis(),
                self.poll_max_ms
            ));
        }

        println!();
        println!("{WHO}: processes");
        println!(
            "{WHO}:   {:<28} {:<8} {:>10} {:>10} {:>10}  {:<24} integrity",
            "process", "why", "start s", "window s", "exit s", "parent"
        );
        for p in &self.procs {
            let start = p.created_ms().unwrap_or(p.seen_ms);
            println!(
                "{WHO}:   {:<28} {:<8} {:>10} {:>10} {:>10}  {:<24} {}",
                clip(&p.label(), 28),
                p.why.name(),
                format!("{:+.3}", start / 1000.0),
                p.first_shown_ms
                    .map_or_else(|| "-".to_owned(), |t| format!("{:+.3}", t / 1000.0)),
                p.exit_time_ms
                    .or(p.exited_ms)
                    .map_or_else(|| "-".to_owned(), |t| format!("{:+.3}", t / 1000.0)),
                clip(
                    &format!(
                        "{} {}{}",
                        p.ppid,
                        p.parent_exe.as_deref().unwrap_or("?"),
                        if p.parent_alive { "" } else { " (gone)" }
                    ),
                    24
                ),
                p.facts
                    .get("integrity")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
            );
        }
        println!("{WHO}: summary");
        for line in &verdict {
            println!("{WHO}:   - {line}");
        }

        self.summary = json!({
            "verdict": verdict,
            "chains": chains,
            "crash_signs": self.crash_signs,
            "polls": {
                "count": self.polls,
                "every_ms": POLL.as_millis() as u64,
                "longest_ms": self.poll_max_ms,
                "late": self.polls_late,
                "snapshot_errors": self.snapshot_errors,
                "enum_windows_errors": self.enum_errors,
            },
        });
    }

    fn finish(self, outcome: Result<()>) -> Result<()> {
        let record = json!({
            "probe": "afklink-capture probe::game_watch",
            "format": 1,
            "started_local": self.started_local,
            "outcome": match &outcome {
                Ok(()) => "complete".to_owned(),
                Err(error) => format!("{error:#}"),
            },
            "config": {
                "process": self.config.needle,
                "seconds": self.config.seconds,
                "exit_codes": self.config.exit_codes,
                "out": self.config.out.display().to_string(),
                "poll_ms": POLL.as_millis() as u64,
                "t0": "t = 0 (t_ms, created_ms, exit_time_ms) is the first poll; created_ms and \
                    exit_time_ms are exact (GetProcessTimes), the rest are poll times (±100 ms)",
                "watched": "exe name contains the needle (name); a child of such a process (child); \
                    WerFault*.exe (werfault); consent.exe (consent)",
            },
            "environment": self.environment,
            "summary": self.summary,
            "processes": self.procs.iter().map(Proc::to_json).collect::<Vec<_>>(),
            "windows_at_end": self.tracked.values().collect::<Vec<_>>(),
            "events": self.events,
            "notes": self.notes,
        });
        let written = write_json(&self.config.out, &record);
        match &written {
            Ok(()) => println!("{WHO}: written {}", self.config.out.display()),
            Err(error) => println!("{WHO}: the JSON was not written: {error:#}"),
        }
        match (outcome, written) {
            (Err(error), _) => Err(error),
            (Ok(()), written) => written,
        }
    }
}

/// A window's class and title, for the chains ("the first window on screen").
fn window_label(w: &WinFacts) -> String {
    format!(
        "class \"{}\" title \"{}\" {}",
        w.class,
        clip(&w.title, 40),
        rect_text(w.rect)
    )
}

fn window_text(w: &WinFacts) -> String {
    format!(
        "class \"{}\" title \"{}\" {}{}{}{} rect {}{}",
        clip(&w.class, 48),
        clip(&w.title, 40),
        if w.visible { "visible" } else { "hidden" },
        if w.minimized { ", minimized" } else { "" },
        match w.cloaked {
            Some(0) | None => String::new(),
            Some(c) => format!(", cloaked {c}"),
        },
        if w.shown() { ", on screen" } else { "" },
        rect_text(w.rect),
        if w.owner == 0 {
            String::new()
        } else {
            format!(" owner {:#x}", w.owner)
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processes_are_watched_by_name_crash_report_uac_or_parent() {
        let n = "scrydegame";
        assert_eq!(watch_reason("ScrydeGame.exe", n, None), Some(Why::Name));
        assert_eq!(watch_reason("ScrydeGame.bin", n, None), Some(Why::Name));
        // The updater is another program.
        assert_eq!(watch_reason("Scryde.exe", n, None), None);
        assert_eq!(watch_reason("WerFault.exe", n, None), Some(Why::WerFault));
        assert_eq!(
            watch_reason("WerFaultSecure.exe", n, None),
            Some(Why::WerFault)
        );
        assert_eq!(watch_reason("consent.exe", n, None), Some(Why::Consent));
        // A child of the game's processes, however deep; not of WerFault's or UAC's.
        assert_eq!(
            watch_reason("aaerrport.exe", n, Some(Why::Name)),
            Some(Why::Child)
        );
        assert_eq!(
            watch_reason("helper.exe", n, Some(Why::Child)),
            Some(Why::Child)
        );
        assert_eq!(watch_reason("conhost.exe", n, Some(Why::WerFault)), None);
        assert_eq!(watch_reason("notepad.exe", n, None), None);
    }

    #[test]
    fn a_snapshot_diff_sees_starts_exits_and_reused_pids() {
        let map = |items: &[(u32, &str)]| -> HashMap<u32, String> {
            items.iter().map(|(p, e)| (*p, (*e).to_owned())).collect()
        };
        let before = map(&[(4, "System"), (100, "ScrydeGame.exe"), (200, "a.exe")]);
        let after = map(&[(4, "System"), (200, "b.exe"), (300, "ScrydeGame.bin")]);
        assert_eq!(diff(&before, &after), (vec![200, 300], vec![100, 200]));
        assert_eq!(diff(&after, &after), (vec![], vec![]));
    }

    #[test]
    fn parents_are_decided_before_their_children() {
        // 30's parent is 20, whose parent is 10; 40's parent is not in the list.
        let parent = |pid: u32| match pid {
            30 => 20,
            20 => 10,
            10 => 1,
            40 => 999,
            _ => 0,
        };
        let order = parents_first(&[30, 40, 20, 10], parent);
        let at = |pid| order.iter().position(|p| *p == pid).unwrap();
        assert_eq!(order.len(), 4);
        assert!(at(10) < at(20) && at(20) < at(30));
        // A process that names itself its parent (pid 0 does) is not waited for.
        assert_eq!(parents_first(&[0], |_| 0), vec![0]);
        // A loop does not hang or drop anything.
        let mut looped = parents_first(&[1, 2], |p| if p == 1 { 2 } else { 1 });
        looped.sort_unstable();
        assert_eq!(looped, vec![1, 2]);
    }

    #[test]
    fn werfault_says_whose_crash_it_reports() {
        assert_eq!(
            werfault_target_pid(r"C:\Windows\system32\WerFault.exe -u -p 5678 -s 1234"),
            Some(5678)
        );
        assert_eq!(werfault_target_pid("WerFault.exe /P 42"), Some(42));
        assert_eq!(werfault_target_pid("WerFault.exe -u -p"), None);
        assert_eq!(werfault_target_pid("WerFault.exe -s 12"), None);
    }

    #[test]
    fn exit_codes_read_as_close_or_crash() {
        assert_eq!(exit_code_label(0), "0 (0x00000000) success");
        assert_eq!(
            exit_code_label(0xC000_0005),
            "3221225477 (0xc0000005) STATUS_ACCESS_VIOLATION, a crash"
        );
        assert!(looks_like_crash(0xC000_0409));
        assert!(looks_like_crash(0xE06D_7363));
        assert!(!looks_like_crash(0xC000_013A));
        assert!(!looks_like_crash(1));
        assert_eq!(exit_code_label(7), "7 (0x00000007)");
    }

    #[test]
    fn window_changes_name_the_fields_that_moved() {
        let a = WinFacts {
            hwnd: 1,
            class: "ScrydeGameUnrealWWindowsViewportWindow".to_owned(),
            title: "Lineage II".to_owned(),
            visible: false,
            rect: Some([0, 0, 800, 600]),
            ..WinFacts::default()
        };
        let mut b = a.clone();
        assert!(changed_fields(&a, &b).is_empty());
        b.title = "ТАНОР".to_owned();
        b.visible = true;
        b.rect = Some([0, 0, 3600, 2328]);
        assert_eq!(changed_fields(&a, &b), vec!["title", "visible", "rect"]);
    }

    #[test]
    fn a_chain_times_the_loader_the_game_and_its_window() {
        let t = |pid, ppid, exe: &str, start_ms, exited_ms, shown_ms: Option<f64>| ProcTimes {
            pid,
            ppid,
            exe: exe.to_owned(),
            why: Why::Name,
            start_ms,
            exited_ms,
            first_shown_ms: shown_ms,
            first_shown: shown_ms.map(|_| "class \"X\"".to_owned()),
        };
        let procs = [
            t(100, 7, "ScrydeGame.exe", 10_000.0, Some(12_500.0), None),
            // An older process that had pid 100 once, long gone: not the parent, though listed later.
            t(100, 1, "ScrydeGame.bin", -50_000.0, Some(-40_000.0), None),
            t(200, 100, "ScrydeGame.bin", 11_000.0, None, Some(19_250.0)),
        ];
        let chains = chains(&procs);
        assert_eq!(chains.len(), 1);
        let c = &chains[0];
        assert_eq!(c.parent, "ScrydeGame.exe pid 100");
        assert_eq!(c.child, "ScrydeGame.bin pid 200");
        assert!((c.child_after_parent_s - 1.0).abs() < 1e-9);
        assert!((c.child_window_after_child_s.unwrap() - 8.25).abs() < 1e-9);
        assert!((c.child_window_after_parent_s.unwrap() - 9.25).abs() < 1e-9);
        assert!((c.parent_exited_after_parent_s.unwrap() - 2.5).abs() < 1e-9);
    }
}
