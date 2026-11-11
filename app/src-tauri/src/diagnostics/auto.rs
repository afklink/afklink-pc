//! The automatic report («автоотчёт»): when something went wrong the agent sends a short tail of
//! its own log by itself, so nobody has to ask the person for it.
//!
//! # Triggers (`auto.trigger` in the signed metadata)
//!
//! - `crash`: at start, the previous run ended in a crash or a panic ([`crash_fired`]); its tail
//!   ends where that process stopped writing ([`note_log_at_start`]). Packed at once, so a run that
//!   dies again half a minute in still reports it.
//! - `offline`: the link came back after [`limits::AGENT_AUTO_OUTAGE_MS`] or more of awake time
//!   down ([`Outage`]; not the first connection, not sleep, not a refusal by the server).
//! - `session_failed`: a session ended on the agent's side with an error reason
//!   ([`FAILED_REASONS`]); its own file's tail goes in, its id first in `session_ids`.
//! - `stall`: the stall watch logged an error (`stall_watch`); it only posts a note
//!   ([`stall_seen`], never waits).
//!
//! # Flow
//!
//! A trigger opens a report and waits [`MERGE_WINDOW_MS`] so the lines after the event are in the
//! tail; triggers in that window merge into it. Then only the tails are packed
//! (`package::build_tail`: the last half hour at most, no line that names a key, the account's
//! folder masked, at most 200 000 bytes) and sent while connected, oldest first; at most
//! [`PENDING_MAX`] wait, for at most [`PENDING_TTL_MS`].
//!
//! # Limits (promised in the privacy policy)
//!
//! [`Limiter`], persisted in `diag_auto.json`: at most [`limits::AGENT_AUTO_PER_WINDOW`] reports in
//! any rolling 24 h, [`PER_TRIGGER`] of one trigger, [`limits::AGENT_AUTO_MIN_GAP_MS`] between two;
//! a clock set back does not unlock it. A blocked trigger is not queued, only counted and named in
//! the next report (`skipped`). Upload attempts are capped too ([`ATTEMPTS_PER_WINDOW`]); a report
//! whose whole body went without an answer counts as sent and is never sent again. A record that
//! cannot be read or written closes the reports for the run (fail closed). With the log off (the
//! stored choice, whatever `RUST_LOG` says) nothing is recorded or sent, and turning it off drops
//! what was opened ([`Auto::observe_log`]).
//!
//! # Threads
//!
//! One task on Tauri's async runtime owns it all ([`Auto`]), with no lock of its own. It copies
//! from the config's, agent state's and log choice's locks (never across an await), packs and
//! touches `diag_auto.json` on blocking threads (`spawn_blocking`, with a timeout), and uploads on
//! a task whose outcome always comes back on a channel, panic or drop included ([`OutcomeGuard`]).

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use afklink_core::build_info::BuildInfo;
use afklink_core::logging::LogLevel;
use afklink_core::{AgentControl, AgentEvent};
use afklink_protocol::diagnostics::{
    is_auto_detail, limits, AgentAutoReport, AgentAutoTrigger as Trigger, AgentDiagnosticsMeta,
};
use afklink_protocol::end_reason;
use afklink_protocol::metrics::{AgentExitKind, AgentLastExit};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::{AppHandle, Manager};
use tokio::sync::{broadcast, mpsc};

use super::package::{self, LogStart};
use super::upload;
use super::Diagnostics;

/// After the first trigger, how long a report waits for the lines after it (and for more triggers
/// to merge) before it is packed. Not after a crash: that event is in the past.
pub(crate) const MERGE_WINDOW_MS: u64 = 30_000;

/// Reports packed and waiting to be sent, at most: the oldest goes past it.
pub(crate) const PENDING_MAX: usize = 3;

/// A report not sent this long after it was packed is dropped.
pub(crate) const PENDING_TTL_MS: u64 = 6 * 60 * 60_000;

/// Reports of one trigger in any rolling window.
pub(crate) const PER_TRIGGER: usize = 2;

/// Upload attempts of one report.
pub(crate) const MAX_ATTEMPTS: u32 = 3;

/// After a network failure, the next attempt at the next reconnect or after this long.
pub(crate) const RETRY_AFTER_FAILURE_MS: u64 = 5 * 60_000;

/// A `429`'s `Retry-After` past this: the report is dropped, not retried.
pub(crate) const RETRY_AFTER_MAX_S: u64 = 3600;

/// Upload attempts in any rolling window, whatever came of them.
pub(crate) const ATTEMPTS_PER_WINDOW: usize = limits::AGENT_AUTO_PER_WINDOW * MAX_ATTEMPTS as usize;

/// An outage whose wall time passes its awake time by this much was slept through, in part.
pub(crate) const SLEEP_TOLERANCE_MS: u64 = 2_000;

/// The end reasons that make a session `session_failed`: errors on the agent's side. Not
/// `agent_disconnected` (that is `offline`), and no normal end.
pub(crate) const FAILED_REASONS: [&str; 8] = [
    end_reason::PEER_ERROR,
    end_reason::ICE_TIMEOUT,
    end_reason::ICE_RESTART_FAILED,
    end_reason::CAPTURE_LOST,
    end_reason::CAPTURE_ERROR,
    end_reason::ENCODER_ERROR,
    end_reason::INTERNAL_ERROR,
    end_reason::NO_SESSION_REQUEST,
];

/// Triggers merged into one report, at most; more are only counted.
const MERGED_MAX: usize = 16;

/// The limiter's file, beside `run_state.json`.
pub(crate) const FILE_NAME: &str = "diag_auto.json";

/// A limiter file larger than this is not ours: the reports close for the run.
const FILE_MAX_BYTES: u64 = 64 * 1024;

/// Stall notes waiting for the task, at most; more are dropped (the hang is reported already).
const STALL_QUEUE: usize = 16;

/// How long packing may take before the report is given up.
const PACK_WAIT: Duration = Duration::from_secs(120);

/// How long reading or writing the limiter's file may take.
const FILE_WAIT: Duration = Duration::from_secs(30);

/// With anything waiting, the task looks again at least this often (expiry, a gap that ends) — and
/// no oftener while what waits cannot go (not connected, out of attempts).
pub(crate) const BUSY_WAKE_MS: u64 = 60_000;

/// With nothing waiting, it sleeps until an event, or this long.
pub(crate) const IDLE_WAKE_MS: u64 = 60 * 60_000;

/// With an upload on its way, how often the task looks whether the log was turned off (to stop it).
/// Each look is a few cheap reads (the log choice's lock only to copy it) and logs nothing.
pub(crate) const UPLOAD_WATCH_MS: u64 = 1_000;

/// Whether the log lets automatic reports record and send: it writes (`recording`: the flight
/// recorder is on), the stored choice is not «Выключены» (`RUST_LOG` may keep the log on while it
/// is), and the level in effect is not `off`.
pub(crate) fn log_lets_auto(
    recording: bool,
    choice: Option<LogLevel>,
    effective: LogLevel,
) -> bool {
    recording && choice != Some(LogLevel::Off) && effective != LogLevel::Off
}

// ---------- Triggers ----------

/// One trigger, as the task saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Fired {
    pub(crate) trigger: Trigger,
    /// When it happened, Unix ms on the PC's clock (`auto.at`).
    pub(crate) at_ms: u64,
    /// `auto.detail`: a short machine word, or none.
    pub(crate) detail: Option<String>,
    /// `session_failed`: the session.
    pub(crate) session_id: Option<String>,
}

impl Fired {
    /// A trigger; a `detail` the contract would refuse is left out (said at `debug`).
    pub(crate) fn new(
        trigger: Trigger,
        at_ms: u64,
        detail: &str,
        session_id: Option<String>,
    ) -> Self {
        let detail = if is_auto_detail(detail) {
            Some(detail.to_string())
        } else {
            tracing::debug!(
                trigger = trigger.as_str(),
                detail_len = detail.len(),
                "diagnostics: auto: a detail the contract would refuse; left out"
            );
            None
        };
        Self {
            trigger,
            at_ms: at_ms.max(1),
            detail,
            session_id,
        }
    }

    /// The metadata's `auto`.
    pub(crate) fn marker(&self) -> AgentAutoReport {
        AgentAutoReport {
            trigger: self.trigger,
            at: self.at_ms,
            detail: self.detail.clone(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "trigger": self.trigger.as_str(),
            "at": self.at_ms,
            "detail": self.detail,
            "session_id": self.session_id,
        })
    }
}

/// The `crash` trigger for how the previous run ended (`run_state`'s `last_exit`), if it is one: a
/// panic or a crash, never a clean exit, an update, Windows' shutdown, or nothing known (`unknown`,
/// `app_exit`, `update_exit`, `os_shutdown`). `now_ms` stands in for a missing time.
pub(crate) fn crash_fired(last: AgentLastExit, now_ms: u64) -> Option<Fired> {
    let detail = match last.kind {
        AgentExitKind::Panic => "panic",
        AgentExitKind::Crash => "crash",
        AgentExitKind::AppExit
        | AgentExitKind::UpdateExit
        | AgentExitKind::OsShutdown
        | AgentExitKind::Unknown => return None,
    };
    let at = last.at.filter(|&at| at > 0).unwrap_or(now_ms);
    Some(Fired::new(Trigger::Crash, at, detail, None))
}

/// Whether a session that ended with `reason` failed on the agent's side.
pub(crate) fn session_failed(reason: &str) -> bool {
    FAILED_REASONS.contains(&reason)
}

// ---------- Clocks and outages ----------

/// Two monotonic clocks, ms: `tick_ms` counts the time the PC slept, `awake_ms` does not
/// (`GetTickCount64`, `QueryUnbiasedInterruptTime`). What they disagree by over an outage is the
/// sleep in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Clocks {
    pub(crate) tick_ms: u64,
    pub(crate) awake_ms: u64,
}

/// The clocks now.
pub(crate) fn clocks() -> Clocks {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetTickCount64;
        use windows::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;
        // SAFETY: no arguments; reads the system's tick count.
        let tick_ms = unsafe { GetTickCount64() };
        let mut unbiased: u64 = 0;
        // SAFETY: a valid pointer to a u64 that lives across the call.
        let ok = unsafe { QueryUnbiasedInterruptTime(&mut unbiased) }.as_bool();
        // In 100 ns units. Never refused on Windows 7 and later; refused, the sleep goes unseen.
        let awake_ms = if ok { unbiased / 10_000 } else { tick_ms };
        Clocks { tick_ms, awake_ms }
    }
    #[cfg(not(windows))]
    {
        static START: OnceLock<Instant> = OnceLock::new();
        let ms = START.get_or_init(Instant::now).elapsed().as_millis() as u64;
        Clocks {
            tick_ms: ms,
            awake_ms: ms,
        }
    }
}

/// What a connection that comes back says of the time the link was down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outage {
    /// The process's first connection: no outage.
    FirstConnect,
    /// Connected without a drop seen (events missed, or a refusal only).
    NoneSeen,
    /// Down less than [`limits::AGENT_AUTO_OUTAGE_MS`] of awake time (`ms`).
    Short { ms: u64 },
    /// Down long on the wall clock, but its sleep explains it: under a minute awake.
    Slept { ms: u64, slept_ms: u64 },
    /// Down long, but the server refused the agent meanwhile (a block, an old version): its
    /// decision, not a fault of the link. `ms`: awake time down.
    Refused { ms: u64 },
    /// Down this long while awake (sleep, if any, not counted): `offline`.
    Long { ms: u64 },
}

/// The link's outages, timed from the agent's events.
#[derive(Debug, Default)]
pub(crate) struct OutageWatch {
    connected_once: bool,
    down_since: Option<Clocks>,
    /// The server refused the agent during the outage now running.
    refused: bool,
}

impl OutageWatch {
    /// The link went down at `at` (the first drop of an outage counts; a repeat keeps it).
    pub(crate) fn disconnected(&mut self, at: Clocks) {
        if self.connected_once && self.down_since.is_none() {
            self.down_since = Some(at);
        }
    }

    /// The server refused the agent at `at`: the link is down, and this outage is not `offline`.
    pub(crate) fn refused(&mut self, at: Clocks) {
        self.disconnected(at);
        self.refused = true;
    }

    /// The link is up at `at`.
    pub(crate) fn connected(&mut self, at: Clocks) -> Outage {
        let refused = std::mem::take(&mut self.refused);
        if !std::mem::replace(&mut self.connected_once, true) {
            self.down_since = None;
            return Outage::FirstConnect;
        }
        let Some(down) = self.down_since.take() else {
            return Outage::NoneSeen;
        };
        let ms = at.tick_ms.saturating_sub(down.tick_ms);
        let awake = at.awake_ms.saturating_sub(down.awake_ms).min(ms);
        let slept_ms = ms.saturating_sub(awake);
        if refused {
            Outage::Refused { ms: awake }
        } else if awake >= limits::AGENT_AUTO_OUTAGE_MS {
            Outage::Long { ms: awake }
        } else if slept_ms >= SLEEP_TOLERANCE_MS {
            Outage::Slept { ms, slept_ms }
        } else {
            Outage::Short { ms: awake }
        }
    }

    /// Events were missed: the outage now running, if any, is not timed.
    pub(crate) fn forget(&mut self) {
        self.down_since = None;
        self.refused = false;
    }
}

// ---------- The limiter ----------

/// One report sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Mark {
    /// Unix ms on the PC's clock.
    pub(crate) at: u64,
    pub(crate) trigger: String,
}

/// `diag_auto.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LimiterRecord {
    #[serde(default)]
    pub(crate) format: u32,
    /// The reports sent in the window, oldest first.
    #[serde(default)]
    pub(crate) sent: Vec<Mark>,
    /// Every upload attempt in the window, Unix ms.
    #[serde(default)]
    pub(crate) attempts: Vec<u64>,
    /// Triggers a limit blocked since the last report sent, by name.
    #[serde(default)]
    pub(crate) skipped: BTreeMap<String, u32>,
}

/// Whether a new report may be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allow,
    /// Blocked: `per_window`, `per_trigger` or `min_gap`.
    Block(&'static str),
}

/// Whether a packed report may go now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendVerdict {
    Go,
    /// Not before this many ms (the gap since the last one sent).
    Wait {
        ms: u64,
    },
    /// Never: `per_window` or `per_trigger`, reached since it was opened.
    Block(&'static str),
}

/// The hard limits on automatic reports, over a rolling window on the PC's clock.
#[derive(Debug, Clone, Default)]
pub(crate) struct Limiter {
    pub(crate) record: LimiterRecord,
}

impl Limiter {
    pub(crate) fn new(record: LimiterRecord) -> Self {
        Self { record }
    }

    /// Times in the future (the clock was set back) become `now` — so a clock set back never
    /// unlocks a limit — and what has left the window goes.
    fn prune(&mut self, now: u64) {
        let window = limits::AGENT_AUTO_WINDOW_MS;
        for mark in &mut self.record.sent {
            mark.at = mark.at.min(now);
        }
        self.record
            .sent
            .retain(|m| m.at.saturating_add(window) > now);
        for at in &mut self.record.attempts {
            *at = (*at).min(now);
        }
        self.record
            .attempts
            .retain(|at| at.saturating_add(window) > now);
    }

    fn sent_of(&self, trigger: Trigger) -> usize {
        self.record
            .sent
            .iter()
            .filter(|m| m.trigger == trigger.as_str())
            .count()
    }

    /// May a new report for `trigger` be opened at `now`, with `reserved` (the trigger and when it
    /// was seen of each report opened and not yet sent) counted as if sent?
    pub(crate) fn check_new(
        &mut self,
        trigger: Trigger,
        now: u64,
        reserved: &[(Trigger, u64)],
    ) -> Verdict {
        self.prune(now);
        let total = self.record.sent.len() + reserved.len();
        let of_trigger =
            self.sent_of(trigger) + reserved.iter().filter(|(t, _)| *t == trigger).count();
        let last = self
            .record
            .sent
            .iter()
            .map(|m| m.at)
            .chain(reserved.iter().map(|(_, at)| (*at).min(now)))
            .max();
        let verdict = if total >= limits::AGENT_AUTO_PER_WINDOW {
            Verdict::Block("per_window")
        } else if of_trigger >= PER_TRIGGER {
            Verdict::Block("per_trigger")
        } else if last.is_some_and(|last| now.saturating_sub(last) < limits::AGENT_AUTO_MIN_GAP_MS)
        {
            Verdict::Block("min_gap")
        } else {
            Verdict::Allow
        };
        tracing::debug!(
            trigger = trigger.as_str(),
            sent = self.record.sent.len(),
            reserved = reserved.len(),
            of_trigger,
            since_last_ms = ?last.map(|last| now.saturating_sub(last)),
            verdict = ?verdict,
            per_window = limits::AGENT_AUTO_PER_WINDOW,
            per_trigger = PER_TRIGGER,
            min_gap_ms = limits::AGENT_AUTO_MIN_GAP_MS,
            "diagnostics: auto: the limits' verdict on a new report"
        );
        verdict
    }

    /// May a packed report for `trigger` go at `now`?
    pub(crate) fn check_send(&mut self, trigger: Trigger, now: u64) -> SendVerdict {
        self.prune(now);
        if self.record.sent.len() >= limits::AGENT_AUTO_PER_WINDOW {
            return SendVerdict::Block("per_window");
        }
        if self.sent_of(trigger) >= PER_TRIGGER {
            return SendVerdict::Block("per_trigger");
        }
        match self.record.sent.iter().map(|m| m.at).max() {
            Some(last) if now.saturating_sub(last) < limits::AGENT_AUTO_MIN_GAP_MS => {
                SendVerdict::Wait {
                    ms: limits::AGENT_AUTO_MIN_GAP_MS - now.saturating_sub(last),
                }
            }
            _ => SendVerdict::Go,
        }
    }

    /// Whether another upload attempt fits the window.
    pub(crate) fn attempt_allowed(&mut self, now: u64) -> bool {
        self.prune(now);
        self.record.attempts.len() < ATTEMPTS_PER_WINDOW
    }

    pub(crate) fn record_attempt(&mut self, now: u64) {
        self.record.attempts.push(now);
    }

    pub(crate) fn record_sent(&mut self, trigger: Trigger, now: u64) {
        self.record.sent.push(Mark {
            at: now,
            trigger: trigger.as_str().to_string(),
        });
    }

    /// A trigger a limit blocked: counted for the next report.
    pub(crate) fn skip(&mut self, trigger: Trigger) {
        let count = self
            .record
            .skipped
            .entry(trigger.as_str().to_string())
            .or_insert(0);
        *count = count.saturating_add(1);
    }

    pub(crate) fn skipped(&self) -> BTreeMap<String, u32> {
        self.record.skipped.clone()
    }

    /// A report that named `told` was sent: those counts are told.
    pub(crate) fn told(&mut self, told: &BTreeMap<String, u32>) {
        for (name, n) in told {
            if let Some(count) = self.record.skipped.get_mut(name) {
                *count = count.saturating_sub(*n);
            }
        }
        self.record.skipped.retain(|_, n| *n > 0);
    }
}

/// The limiter's record from `path`: none yet is an empty one; anything else that cannot be read
/// — a folder in its place, a lock, too large, garbled — is an error, and the reports close for
/// the run (fail closed: the limits cannot be held without it). Blocking: on a blocking thread.
pub(crate) fn load_record(path: &Path) -> Result<LimiterRecord, String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!("diagnostics: auto: no limits' record yet; starting empty");
            return Ok(LimiterRecord::default());
        }
        Err(e) => return Err(format!("not read: {e}")),
    };
    if !meta.is_file() {
        return Err("not a file".to_string());
    }
    if meta.len() > FILE_MAX_BYTES {
        return Err(format!("{} bytes, over {FILE_MAX_BYTES}", meta.len()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("not read: {e}"))?;
    let record =
        serde_json::from_slice::<LimiterRecord>(&bytes).map_err(|e| format!("garbled: {e}"))?;
    tracing::debug!(
        sent = record.sent.len(),
        attempts = record.attempts.len(),
        skipped = ?record.skipped,
        "diagnostics: auto: the limits' record read"
    );
    Ok(record)
}

/// Write the limiter's record to `path`: a `.tmp` beside it, then a rename. Blocking.
pub(crate) fn save_record(path: &Path, record: &LimiterRecord) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let mut tmp = path.to_path_buf().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path))
}

// ---------- The reports' state ----------

/// A report open for triggers: the first, and those merged into it.
#[derive(Debug, Clone)]
pub(crate) struct Collecting {
    pub(crate) id: u64,
    pub(crate) first: Fired,
    pub(crate) merged: Vec<Fired>,
    pub(crate) merged_dropped: u32,
    /// When it is packed, on the tick clock: [`MERGE_WINDOW_MS`] after the first trigger, at once
    /// after a crash.
    due_ms: u64,
    /// When the first was seen, on the PC's clock (for the limits).
    seen_unix_ms: u64,
    /// The log's off-generation it was opened under ([`Auto::observe_log`]).
    generation: u64,
}

impl Collecting {
    /// Every trigger in it, the first first.
    pub(crate) fn all(&self) -> impl Iterator<Item = &Fired> {
        std::iter::once(&self.first).chain(self.merged.iter())
    }

    /// Whether a crash is among them: the tail ends where the previous run stopped.
    pub(crate) fn has_crash(&self) -> bool {
        self.all().any(|f| f.trigger == Trigger::Crash)
    }

    /// The first failed session's id, whose file goes in and leads `session_ids`.
    pub(crate) fn failed_session(&self) -> Option<&str> {
        self.all()
            .filter(|f| f.trigger == Trigger::SessionFailed)
            .find_map(|f| f.session_id.as_deref())
    }

    /// The newest of its events: the log's lines go back [`package::AUTO_LOOKBACK_MS`] from it.
    pub(crate) fn event_ms(&self) -> u64 {
        self.all()
            .map(|f| f.at_ms)
            .max()
            .unwrap_or(self.first.at_ms)
    }

    /// `report.json`'s `auto`.
    pub(crate) fn about(&self, skipped: &BTreeMap<String, u32>) -> Value {
        json!({
            "trigger": self.first.trigger.as_str(),
            "at": self.first.at_ms,
            "detail": self.first.detail,
            "session_id": self.first.session_id,
            "merged": self.merged.iter().map(Fired::to_json).collect::<Vec<_>>(),
            "merged_dropped": self.merged_dropped,
            "skipped": skipped,
            "window_s": MERGE_WINDOW_MS / 1000,
        })
    }
}

/// A report packed and signed-to-be: what goes, and the skipped counts its `report.json` names.
#[derive(Debug, Clone)]
pub(crate) struct Ready {
    pub(crate) prepared: upload::Prepared,
    pub(crate) skipped: BTreeMap<String, u32>,
}

#[derive(Debug)]
struct Pending {
    id: u64,
    first: Fired,
    seen_unix_ms: u64,
    generation: u64,
    ready: Ready,
    made_ms: u64,
    attempts: u32,
    /// Not before this (tick clock); `None`: now.
    not_before_ms: Option<u64>,
    /// A network failure: the next reconnect may try at once.
    retry_on_connect: bool,
    too_often_retried: bool,
}

/// One upload to make.
#[derive(Debug, Clone)]
pub(crate) struct Upload {
    pub(crate) id: u64,
    pub(crate) trigger: Trigger,
    pub(crate) attempt: u32,
    pub(crate) prepared: upload::Prepared,
}

/// What became of a trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fire {
    /// Not recorded: the log is off.
    Ignored,
    /// Not recorded: the reports are closed for the run (their record cannot be kept).
    Closed,
    /// A new report is open.
    Opened,
    /// Merged into the open one.
    Merged,
    /// A limit blocked it: counted for the next report.
    Skipped(&'static str),
}

/// Every automatic report of this run, and the limits. Owned by one task; times in ms, `mono` on
/// the tick clock ([`Clocks::tick_ms`]), `now` on the PC's clock.
#[derive(Debug)]
pub(crate) struct Auto {
    pub(crate) limiter: Limiter,
    dirty: bool,
    outage: OutageWatch,
    connected: bool,
    collecting: Option<Collecting>,
    pending: VecDeque<Pending>,
    /// The upload on its way: the report's id and trigger (counted as sent even when the report was
    /// dropped meanwhile, should it get through).
    inflight: Option<u64>,
    inflight_trigger: Option<Trigger>,
    next_id: u64,
    /// The log's off-generation everything held was opened under.
    generation: u64,
    /// Why the reports are closed for the run, once they are.
    closed: Option<String>,
    /// Why what waits does not go now, as last said (said once per change).
    waiting: Option<&'static str>,
}

impl Auto {
    pub(crate) fn new(limiter: Limiter) -> Self {
        Self {
            limiter,
            dirty: false,
            outage: OutageWatch::default(),
            connected: false,
            collecting: None,
            pending: VecDeque::new(),
            inflight: None,
            inflight_trigger: None,
            next_id: 1,
            generation: 0,
            closed: None,
            waiting: None,
        }
    }

    /// Whether the limiter's record changed since the last call: to be written.
    pub(crate) fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Why what waits does not go now, if anything waits and cannot (for the tests; the log says
    /// it as it changes).
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> Option<&'static str> {
        self.waiting
    }

    /// Close the reports for the run (`why`, said once): nothing more is opened or sent.
    pub(crate) fn close(&mut self, why: &str) {
        if self.closed.is_none() {
            tracing::warn!(
                why,
                pending = self.pending.len(),
                "diagnostics: auto: automatic reports are off for this run (their limits cannot be \
                 kept); nothing is sent"
            );
            self.closed = Some(why.to_string());
        }
        self.collecting = None;
        self.pending.clear();
        // An upload that was to start does not: nothing waits for it.
        self.inflight = None;
        self.inflight_trigger = None;
    }

    /// The log's off-generation now (bumped each time «Выключены» is chosen): anything opened or
    /// packed under an older one is dropped — the one on its way too. Its id, when there is one: the
    /// caller aborts that upload, and its outcome (a failure, `OutcomeGuard`) finds nothing kept.
    pub(crate) fn observe_log(&mut self, generation: u64) -> Option<u64> {
        if generation == self.generation {
            return None;
        }
        tracing::info!(
            from = self.generation,
            to = generation,
            open = self.collecting.is_some(),
            pending = self.pending.len(),
            inflight = ?self.inflight,
            "diagnostics: auto: the log was turned off; every report opened before it is dropped, \
             and an upload on its way is stopped"
        );
        self.generation = generation;
        if self
            .collecting
            .as_ref()
            .is_some_and(|c| c.generation != generation)
        {
            self.collecting = None;
        }
        self.pending.retain(|p| p.generation == generation);
        self.inflight
    }

    /// A trigger.
    pub(crate) fn fire(&mut self, fired: Fired, mono: u64, now: u64, log_on: bool) -> Fire {
        if !log_on {
            tracing::debug!(
                trigger = fired.trigger.as_str(),
                "diagnostics: auto: a trigger while the log is off; nothing recorded"
            );
            return Fire::Ignored;
        }
        if let Some(why) = &self.closed {
            tracing::debug!(
                trigger = fired.trigger.as_str(),
                why = %why,
                "diagnostics: auto: a trigger while the reports are off for this run; nothing recorded"
            );
            return Fire::Closed;
        }
        if let Some(open) = self.collecting.as_mut() {
            if open.merged.len() < MERGED_MAX {
                open.merged.push(fired.clone());
            } else {
                open.merged_dropped = open.merged_dropped.saturating_add(1);
            }
            tracing::debug!(
                trigger = fired.trigger.as_str(),
                detail = fired.detail.as_deref().unwrap_or("-"),
                into = open.first.trigger.as_str(),
                merged = open.merged.len(),
                merged_dropped = open.merged_dropped,
                "diagnostics: auto: a trigger merged into the report waiting for its lines"
            );
            return Fire::Merged;
        }
        let reserved: Vec<(Trigger, u64)> = self
            .pending
            .iter()
            .map(|p| (p.first.trigger, p.seen_unix_ms))
            .collect();
        match self.limiter.check_new(fired.trigger, now, &reserved) {
            Verdict::Block(why) => {
                self.limiter.skip(fired.trigger);
                self.dirty = true;
                tracing::info!(
                    trigger = fired.trigger.as_str(),
                    detail = fired.detail.as_deref().unwrap_or("-"),
                    why,
                    skipped = ?self.limiter.record.skipped,
                    "diagnostics: auto: a trigger not reported (a limit); counted for the next report"
                );
                Fire::Skipped(why)
            }
            Verdict::Allow => {
                let id = self.next_id;
                self.next_id += 1;
                // A crash is in the past: packed at once, so a run that dies again soon still
                // reports it.
                let due_ms = if fired.trigger == Trigger::Crash {
                    mono
                } else {
                    mono.saturating_add(MERGE_WINDOW_MS)
                };
                tracing::info!(
                    id,
                    trigger = fired.trigger.as_str(),
                    detail = fired.detail.as_deref().unwrap_or("-"),
                    at = fired.at_ms,
                    session = fired.session_id.as_deref().unwrap_or("-"),
                    wait_ms = due_ms - mono,
                    "diagnostics: auto: a report opened; packed once the lines after the event are in"
                );
                self.collecting = Some(Collecting {
                    id,
                    first: fired,
                    merged: Vec::new(),
                    merged_dropped: 0,
                    due_ms,
                    seen_unix_ms: now,
                    generation: self.generation,
                });
                Fire::Opened
            }
        }
    }

    /// A session ended with `reason`.
    pub(crate) fn session_ended(
        &mut self,
        session_id: &str,
        reason: &str,
        mono: u64,
        now: u64,
        log_on: bool,
    ) -> Option<Fire> {
        if !session_failed(reason) {
            tracing::debug!(
                session = session_id,
                reason,
                "diagnostics: auto: a session ended, not a failure on this side; no report"
            );
            return None;
        }
        let fired = Fired::new(
            Trigger::SessionFailed,
            now,
            reason,
            Some(session_id.to_string()),
        );
        Some(self.fire(fired, mono, now, log_on))
    }

    /// The link to the server is up.
    pub(crate) fn connected(&mut self, at: Clocks, now: u64, log_on: bool) -> Option<Fire> {
        self.connected = true;
        for p in &mut self.pending {
            if std::mem::take(&mut p.retry_on_connect) {
                p.not_before_ms = None;
                tracing::debug!(
                    id = p.id,
                    "diagnostics: auto: connected again; a report that failed on the network goes now"
                );
            }
        }
        let outage = self.outage.connected(at);
        tracing::debug!(
            outage = ?outage,
            outage_min_ms = limits::AGENT_AUTO_OUTAGE_MS,
            sleep_tolerance_ms = SLEEP_TOLERANCE_MS,
            pending = self.pending.len(),
            "diagnostics: auto: connected to the server; the outage judged on its awake time"
        );
        match outage {
            Outage::Long { ms } => {
                let detail = format!("outage_s={}", ms / 1000);
                Some(self.fire(
                    Fired::new(Trigger::Offline, now, &detail, None),
                    at.tick_ms,
                    now,
                    log_on,
                ))
            }
            _ => None,
        }
    }

    /// The link to the server is down.
    pub(crate) fn disconnected(&mut self, at: Clocks) {
        self.connected = false;
        self.outage.disconnected(at);
    }

    /// The server refused the agent: down, and the outage it is in is not `offline`.
    pub(crate) fn refused(&mut self, at: Clocks) {
        self.connected = false;
        self.outage.refused(at);
    }

    /// Events were missed: the outage now running is not timed.
    pub(crate) fn lagged(&mut self) {
        self.outage.forget();
    }

    /// The open report, once it is due.
    pub(crate) fn take_due(&mut self, mono: u64) -> Option<Collecting> {
        let due = self.collecting.as_ref().is_some_and(|c| mono >= c.due_ms);
        if due {
            self.collecting.take()
        } else {
            None
        }
    }

    /// A report packed: it waits to be sent — unless the log was turned off while it was packed.
    pub(crate) fn add_ready(&mut self, c: Collecting, ready: Ready, mono: u64) {
        if c.generation != self.generation {
            tracing::info!(
                id = c.id,
                "diagnostics: auto: the log was turned off while the report was packed; dropped"
            );
            return;
        }
        if self.closed.is_some() {
            tracing::debug!(
                id = c.id,
                "diagnostics: auto: packed after the reports closed; dropped"
            );
            return;
        }
        if self.pending.len() >= PENDING_MAX {
            if let Some(oldest) = self.pending.pop_front() {
                tracing::warn!(
                    id = oldest.id,
                    trigger = oldest.first.trigger.as_str(),
                    max = PENDING_MAX,
                    "diagnostics: auto: too many reports waiting; the oldest dropped"
                );
            }
        }
        tracing::debug!(
            id = c.id,
            trigger = c.first.trigger.as_str(),
            zip_bytes = ready.prepared.body.len(),
            pending = self.pending.len() + 1,
            connected = self.connected,
            "diagnostics: auto: a report packed; it goes while connected to the server"
        );
        self.pending.push_back(Pending {
            id: c.id,
            first: c.first,
            seen_unix_ms: c.seen_unix_ms,
            generation: c.generation,
            ready,
            made_ms: mono,
            attempts: 0,
            not_before_ms: None,
            retry_on_connect: false,
            too_often_retried: false,
        });
    }

    /// Note why what waits does not go now; said once per change.
    fn wait_for(&mut self, why: Option<&'static str>) {
        if self.waiting != why {
            tracing::debug!(
                was = self.waiting.unwrap_or("-"),
                now = why.unwrap_or("-"),
                pending = self.pending.len(),
                attempts_in_window = self.limiter.record.attempts.len(),
                "diagnostics: auto: what holds the reports waiting changed"
            );
            self.waiting = why;
        }
    }

    /// The next upload to make now, if any: the oldest report, when connected, inside every limit.
    /// Drops what has expired, what a limit now blocks, an oversize one, and everything when the log
    /// is off or the reports are closed.
    pub(crate) fn next_upload(&mut self, mono: u64, now: u64, log_on: bool) -> Option<Upload> {
        if self.inflight.is_some() {
            self.wait_for(Some("upload_on_its_way"));
            return None;
        }
        if !log_on || self.closed.is_some() {
            if !self.pending.is_empty() || self.collecting.is_some() {
                tracing::debug!(
                    pending = self.pending.len(),
                    open = self.collecting.is_some(),
                    log_on,
                    closed = self.closed.is_some(),
                    "diagnostics: auto: the log is off (or the reports closed); what waits is dropped"
                );
                self.pending.clear();
                self.collecting = None;
            }
            self.wait_for(None);
            return None;
        }
        self.pending.retain(|p| {
            let keep = mono.saturating_sub(p.made_ms) < PENDING_TTL_MS;
            if !keep {
                tracing::warn!(
                    id = p.id,
                    trigger = p.first.trigger.as_str(),
                    attempts = p.attempts,
                    ttl_h = PENDING_TTL_MS / 3_600_000,
                    "diagnostics: auto: a report not sent in time; dropped"
                );
            }
            keep
        });
        while let Some(p) = self.pending.front_mut() {
            if p.ready.prepared.body.len() as u64 > limits::AGENT_AUTO_BODY_BYTES {
                tracing::warn!(
                    id = p.id,
                    zip_bytes = p.ready.prepared.body.len(),
                    cap = limits::AGENT_AUTO_BODY_BYTES,
                    "diagnostics: auto: a report over its cap; dropped, never sent"
                );
                self.pending.pop_front();
                continue;
            }
            if !self.connected {
                self.wait_for(Some("not_connected"));
                return None;
            }
            if p.not_before_ms.is_some_and(|t| mono < t) {
                self.wait_for(Some("retry_or_gap_wait"));
                return None;
            }
            let trigger = p.first.trigger;
            match self.limiter.check_send(trigger, now) {
                SendVerdict::Block(why) => {
                    tracing::info!(
                        id = p.id,
                        trigger = trigger.as_str(),
                        why,
                        "diagnostics: auto: a limit was reached while the report waited; dropped \
                         and counted for the next"
                    );
                    self.pending.pop_front();
                    self.limiter.skip(trigger);
                    self.dirty = true;
                    continue;
                }
                SendVerdict::Wait { ms } => {
                    p.not_before_ms = Some(mono.saturating_add(ms));
                    tracing::debug!(
                        id = p.id,
                        wait_ms = ms,
                        "diagnostics: auto: the gap since the last report has not passed; waiting"
                    );
                    self.wait_for(Some("retry_or_gap_wait"));
                    return None;
                }
                SendVerdict::Go => {}
            }
            if !self.limiter.attempt_allowed(now) {
                self.wait_for(Some("out_of_attempts"));
                return None;
            }
            p.attempts += 1;
            self.limiter.record_attempt(now);
            self.dirty = true;
            self.inflight = Some(p.id);
            self.inflight_trigger = Some(trigger);
            tracing::debug!(
                id = p.id,
                trigger = trigger.as_str(),
                attempt = p.attempts,
                max_attempts = MAX_ATTEMPTS,
                zip_bytes = p.ready.prepared.body.len(),
                "diagnostics: auto: uploading a report"
            );
            let upload = Upload {
                id: p.id,
                trigger,
                attempt: p.attempts,
                prepared: p.ready.prepared.clone(),
            };
            self.wait_for(Some("upload_on_its_way"));
            return Some(upload);
        }
        self.wait_for(None);
        None
    }

    /// What became of an upload.
    pub(crate) fn upload_done(&mut self, id: u64, outcome: &upload::Outcome, mono: u64, now: u64) {
        let trigger = if self.inflight == Some(id) {
            self.inflight = None;
            self.inflight_trigger.take()
        } else {
            None
        };
        let Some(index) = self.pending.iter().position(|p| p.id == id) else {
            // Dropped while on its way (the log turned off): what got through still counts.
            let through = matches!(
                outcome,
                upload::Outcome::Sent { .. }
                    | upload::Outcome::Failed(upload::Failure::Unanswered(_))
            );
            if let Some(trigger) = trigger.filter(|_| through) {
                self.limiter.record_sent(trigger, now);
                self.dirty = true;
            }
            tracing::debug!(
                id,
                counted = through,
                "diagnostics: auto: an upload's outcome for a report no longer kept"
            );
            return;
        };
        let remove = match outcome {
            upload::Outcome::Sent { receipt } => {
                let p = &self.pending[index];
                self.limiter.record_sent(p.first.trigger, now);
                self.limiter.told(&p.ready.skipped);
                self.dirty = true;
                tracing::info!(
                    id,
                    trigger = p.first.trigger.as_str(),
                    report_id = receipt.as_ref().map_or("-", |r| r.report_id.as_str()),
                    zip_bytes = p.ready.prepared.body.len(),
                    attempt = p.attempts,
                    sent_in_window = self.limiter.record.sent.len(),
                    "diagnostics: auto: report sent"
                );
                true
            }
            upload::Outcome::Failed(upload::Failure::Unanswered(why)) => {
                // The server may have stored it: counted as sent, never sent again.
                let p = &self.pending[index];
                self.limiter.record_sent(p.first.trigger, now);
                self.limiter.told(&p.ready.skipped);
                self.dirty = true;
                tracing::info!(
                    id,
                    trigger = p.first.trigger.as_str(),
                    attempt = p.attempts,
                    sent_in_window = self.limiter.record.sent.len(),
                    "diagnostics: auto: the whole report went but no answer came; counted as sent, \
                     not sent again: {why}"
                );
                true
            }
            upload::Outcome::TooOften { retry_after_s } => {
                let p = &mut self.pending[index];
                match retry_after_s {
                    Some(s)
                        if *s <= RETRY_AFTER_MAX_S
                            && !p.too_often_retried
                            && p.attempts < MAX_ATTEMPTS =>
                    {
                        p.too_often_retried = true;
                        p.not_before_ms = Some(mono.saturating_add(s.saturating_mul(1000)));
                        tracing::info!(
                            id,
                            retry_after_s = s,
                            "diagnostics: auto: over the server's budget; tried once more after its \
                             wait"
                        );
                        false
                    }
                    _ => {
                        tracing::info!(
                            id,
                            retry_after_s = ?retry_after_s,
                            retried = p.too_often_retried,
                            "diagnostics: auto: over the server's budget; dropped"
                        );
                        true
                    }
                }
            }
            upload::Outcome::Failed(upload::Failure::Network(why)) => {
                let p = &mut self.pending[index];
                if p.attempts >= MAX_ATTEMPTS {
                    tracing::warn!(
                        id,
                        attempts = p.attempts,
                        "diagnostics: auto: no answer from the server, the last attempt; dropped: \
                         {why}"
                    );
                    true
                } else {
                    p.not_before_ms = Some(mono.saturating_add(RETRY_AFTER_FAILURE_MS));
                    p.retry_on_connect = true;
                    tracing::info!(
                        id,
                        attempts = p.attempts,
                        retry_in_s = RETRY_AFTER_FAILURE_MS / 1000,
                        "diagnostics: auto: no answer from the server before the report went; tried \
                         again at the next reconnect or later: {why}"
                    );
                    false
                }
            }
            upload::Outcome::Failed(other) => {
                tracing::warn!(
                    id,
                    failure = other.kind(),
                    "diagnostics: auto: the server refused the report; dropped"
                );
                true
            }
        };
        if remove {
            self.pending.remove(index);
        }
    }

    /// How long the task may sleep before something here is due, ms. A report that cannot go now
    /// for a reason no time passing ends soon (not connected, out of attempts, reports closed)
    /// counts only towards the busy wake: never a spin.
    pub(crate) fn next_wake(&mut self, mono: u64, now: u64) -> u64 {
        let mut wake = if self.pending.is_empty() {
            IDLE_WAKE_MS
        } else {
            BUSY_WAKE_MS
        };
        if let Some(c) = &self.collecting {
            wake = wake.min(c.due_ms.saturating_sub(mono));
        }
        // An upload on its way: looked at every second, so the log turned off stops it soon.
        if self.inflight.is_some() {
            wake = wake.min(UPLOAD_WATCH_MS);
        }
        let could_go = self.inflight.is_none() && self.connected && self.closed.is_none();
        if could_go && self.limiter.attempt_allowed(now) {
            if let Some(t) = self
                .pending
                .front()
                .and_then(|p| p.not_before_ms)
                .filter(|&t| t > mono)
            {
                wake = wake.min(t - mono);
            }
        }
        wake
    }
}

// ---------- Hooks for the rest of the app ----------

/// The system log as this process found it, before its first line (`init_logging`).
static LOG_AT_START: OnceLock<Result<LogStart, String>> = OnceLock::new();

/// Note where the system log stands before this process writes to it: the previous process's last
/// byte, where a `crash` report's tail ends. Called once, on the main thread at start, before the log
/// files open; said later (the file is not open yet), by [`start`].
pub(crate) fn note_log_at_start(logs_dir: Option<&Path>) {
    let noted = match logs_dir {
        Some(dir) => {
            LogStart::read(&dir.join(crate::log_retention::SYSTEM_LOG)).map_err(|e| e.to_string())
        }
        None => Err("no logs folder".to_string()),
    };
    let _first = LOG_AT_START.set(noted);
}

/// A note from the stall watch: a side hung.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StallNote {
    pub(crate) side: &'static str,
    pub(crate) at_ms: u64,
}

static STALL_NOTES: OnceLock<mpsc::Sender<StallNote>> = OnceLock::new();

/// The stall watch logged an error about `side` (`main_thread` or `async_runtime`). Posts a note
/// and returns: never waits, takes no lock (a full queue drops the note, said at `debug`).
pub(crate) fn stall_seen(side: &'static str) {
    let Some(notes) = STALL_NOTES.get() else {
        tracing::trace!(
            side,
            "diagnostics: auto: a stall before the reports started; not noted"
        );
        return;
    };
    let note = StallNote {
        side,
        at_ms: upload::now_ms(),
    };
    if let Err(e) = notes.try_send(note) {
        tracing::debug!(side, "diagnostics: auto: a stall note not queued: {e}");
    }
}

/// An upload's outcome on its way back to the task: sent once, by [`Self::send`] — or, when the
/// upload's task panics or is dropped first, by `Drop`, as a network failure. The task never waits
/// for an outcome that does not come.
pub(crate) struct OutcomeGuard {
    id: u64,
    done: mpsc::Sender<(u64, upload::Outcome)>,
    sent: bool,
}

impl OutcomeGuard {
    pub(crate) fn new(id: u64, done: mpsc::Sender<(u64, upload::Outcome)>) -> Self {
        Self {
            id,
            done,
            sent: false,
        }
    }

    pub(crate) fn send(mut self, outcome: upload::Outcome) {
        self.sent = true;
        if let Err(e) = self.done.try_send((self.id, outcome)) {
            tracing::debug!(
                id = self.id,
                "diagnostics: auto: an upload's outcome not delivered: {e}"
            );
        }
    }
}

impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        if self.sent {
            return;
        }
        tracing::warn!(
            id = self.id,
            "diagnostics: auto: the upload's task ended without an outcome (a panic, or dropped); \
             taken as no answer"
        );
        let failed = upload::Outcome::Failed(upload::Failure::Network(
            "the upload's task ended without an outcome".into(),
        ));
        if let Err(e) = self.done.try_send((self.id, failed)) {
            tracing::debug!(
                id = self.id,
                "diagnostics: auto: the failure not delivered: {e}"
            );
        }
    }
}

/// Start the automatic reports: one task on Tauri's runtime. `events` is subscribed before the agent
/// runs; `last_exit` is how the previous run ended (`None`: no run state).
pub(crate) fn start(
    app: AppHandle,
    events: broadcast::Receiver<AgentEvent>,
    last_exit: Option<AgentLastExit>,
) {
    let (notes_tx, notes_rx) = mpsc::channel(STALL_QUEUE);
    if STALL_NOTES.set(notes_tx).is_err() {
        tracing::debug!(
            "diagnostics: auto: started before in this process; the first one's notes stand"
        );
        return;
    }
    tauri::async_runtime::spawn(run(app, events, notes_rx, last_exit));
}

/// Whether the log lets automatic reports record and send now ([`log_lets_auto`]).
fn log_on(app: &AppHandle) -> bool {
    app.state::<crate::Logging>().auto_reports_on()
}

/// How many times the log was turned off this run.
fn log_generation(app: &AppHandle) -> u64 {
    app.state::<crate::Logging>().off_generation()
}

/// The log's off-generation into `auto`; when the log was turned off with an upload on its way,
/// that upload is stopped (its `OutcomeGuard` reports it as a failure, for a report not kept).
fn observe_log(
    auto: &mut Auto,
    app: &AppHandle,
    uploading: &Option<(u64, tauri::async_runtime::JoinHandle<()>)>,
) {
    let Some(id) = auto.observe_log(log_generation(app)) else {
        return;
    };
    match uploading {
        Some((task_id, task)) if *task_id == id => {
            task.abort();
            tracing::info!(
                id,
                "diagnostics: auto: the log was turned off; the upload on its way is stopped"
            );
        }
        _ => tracing::debug!(
            id,
            "diagnostics: auto: no task for the upload on its way to stop"
        ),
    }
}

/// Write the limits' record if it changed. `false` when it could not be written: the reports close
/// for the run (said there).
pub(crate) async fn persist(auto: &mut Auto, path: Option<&Path>) -> bool {
    if !auto.take_dirty() {
        return true;
    }
    let Some(path) = path.map(Path::to_path_buf) else {
        auto.close("no place for the limits' record");
        return false;
    };
    let record = auto.limiter.record.clone();
    match blocking(FILE_WAIT, "the limits' record", move || {
        save_record(&path, &record).map_err(|e| e.to_string())
    })
    .await
    .and_then(|saved| saved)
    {
        Ok(()) => {
            tracing::trace!("diagnostics: auto: the limits' record written");
            true
        }
        Err(e) => {
            auto.close(&format!("the limits' record not written: {e}"));
            false
        }
    }
}

/// The next upload to start, once its attempt is on disk: `None` when nothing goes now, or when
/// the record could not be written — then the reports close and the upload never starts, so a
/// record that cannot be replaced (read-only, denied) never lets a body out.
pub(crate) async fn next_upload_persisted(
    auto: &mut Auto,
    path: Option<&Path>,
    mono: u64,
    now: u64,
    log_on: bool,
) -> Option<Upload> {
    let up = auto.next_upload(mono, now, log_on)?;
    if persist(auto, path).await {
        Some(up)
    } else {
        tracing::warn!(
            id = up.id,
            "diagnostics: auto: the upload's attempt could not be recorded; it does not start"
        );
        None
    }
}

/// The task: every trigger, every report, every upload's outcome, in one place.
async fn run(
    app: AppHandle,
    mut events: broadcast::Receiver<AgentEvent>,
    mut notes: mpsc::Receiver<StallNote>,
    last_exit: Option<AgentLastExit>,
) {
    let mut auto = Auto::new(Limiter::default());
    auto.observe_log(log_generation(&app));
    let path = blocking(FILE_WAIT, "the limits' file path", || {
        afklink_core::paths::afklink_dir().map(|dir| dir.join(FILE_NAME))
    })
    .await
    .and_then(|found| found.map_err(|e| format!("{e:#}")));
    let path = match path {
        Ok(path) => Some(path),
        Err(e) => {
            auto.close(&format!("no data folder for the limits' record: {e}"));
            None
        }
    };
    if let Some(path) = path.clone() {
        match blocking(FILE_WAIT, "the limits' record", move || load_record(&path))
            .await
            .and_then(|read| read)
        {
            Ok(record) => auto.limiter = Limiter::new(record),
            Err(e) => auto.close(&format!("the limits' record: {e}")),
        }
    }
    match LOG_AT_START.get() {
        Some(Ok(start)) => tracing::debug!(
            system_log_bytes = start.len,
            "diagnostics: auto: where the system log stood at start (a crash's tail ends there)"
        ),
        Some(Err(e)) => tracing::debug!("diagnostics: auto: the system log at start not read: {e}"),
        None => tracing::debug!("diagnostics: auto: the system log at start not noted"),
    }
    let (done_tx, mut done_rx) = mpsc::channel::<(u64, upload::Outcome)>(4);
    tracing::debug!(
        per_window = limits::AGENT_AUTO_PER_WINDOW,
        window_h = limits::AGENT_AUTO_WINDOW_MS / 3_600_000,
        per_trigger = PER_TRIGGER,
        min_gap_s = limits::AGENT_AUTO_MIN_GAP_MS / 1000,
        cap_bytes = limits::AGENT_AUTO_BODY_BYTES,
        outage_s = limits::AGENT_AUTO_OUTAGE_MS / 1000,
        lookback_s = package::AUTO_LOOKBACK_MS / 1000,
        last_exit = ?last_exit.map(|l| l.kind),
        "diagnostics: auto: automatic reports on"
    );
    match last_exit.and_then(|last| crash_fired(last, upload::now_ms())) {
        Some(fired) => {
            auto.fire(fired, clocks().tick_ms, upload::now_ms(), log_on(&app));
        }
        None => tracing::debug!(
            last_exit = ?last_exit.map(|l| l.kind),
            "diagnostics: auto: the previous run did not crash; no crash report"
        ),
    }
    // The upload on its way, to stop when the log is turned off.
    let mut uploading: Option<(u64, tauri::async_runtime::JoinHandle<()>)> = None;
    loop {
        observe_log(&mut auto, &app, &uploading);
        if let Some(c) = auto.take_due(clocks().tick_ms) {
            if log_on(&app) {
                let skipped = auto.limiter.skipped();
                let packed = pack(&app, &c, skipped).await;
                // The log may have been turned off while it was packed: then it is dropped.
                observe_log(&mut auto, &app, &uploading);
                match packed {
                    Ok(ready) => auto.add_ready(c, ready, clocks().tick_ms),
                    Err(e) => tracing::warn!(
                        id = c.id,
                        trigger = c.first.trigger.as_str(),
                        "diagnostics: auto: the report not packed ({e}); dropped"
                    ),
                }
            } else {
                tracing::debug!(
                    id = c.id,
                    "diagnostics: auto: the log went off; the report dropped"
                );
            }
        }
        // The attempt is on disk before its upload starts: a record that cannot be written sends
        // nothing.
        if let Some(up) = next_upload_persisted(
            &mut auto,
            path.as_deref(),
            clocks().tick_ms,
            upload::now_ms(),
            log_on(&app),
        )
        .await
        {
            let app = app.clone();
            let id = up.id;
            let guard = OutcomeGuard::new(id, done_tx.clone());
            let task = tauri::async_runtime::spawn(async move {
                let outcome = upload_one(&app, &up).await;
                guard.send(outcome);
            });
            uploading = Some((id, task));
        }
        persist(&mut auto, path.as_deref()).await;
        let wait =
            Duration::from_millis(auto.next_wake(clocks().tick_ms, upload::now_ms()).max(10));
        tokio::select! {
            event = events.recv() => match event {
                Ok(AgentEvent::SignalingConnected { .. }) => {
                    auto.connected(clocks(), upload::now_ms(), log_on(&app));
                }
                Ok(AgentEvent::SignalingDisconnected) => {
                    auto.disconnected(clocks());
                    tracing::debug!(
                        pending = auto.pending_len(),
                        "diagnostics: auto: the link to the server is down; reports wait, the outage \
                         is timed"
                    );
                }
                Ok(AgentEvent::SignalingRefused(_)) => {
                    auto.refused(clocks());
                    tracing::debug!(
                        pending = auto.pending_len(),
                        "diagnostics: auto: the server refused the agent; reports wait, and this \
                         outage is not reported as offline"
                    );
                }
                Ok(AgentEvent::SessionEnded { session_id, reason }) => {
                    auto.session_ended(
                        &session_id,
                        &reason,
                        clocks().tick_ms,
                        upload::now_ms(),
                        log_on(&app),
                    );
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    auto.lagged();
                    tracing::debug!(
                        missed,
                        "diagnostics: auto: agent events missed; the outage now running (if any) \
                         is not timed, and a failed session may go unreported"
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::debug!("diagnostics: auto: the agent's events ended; no more reports");
                    break;
                }
            },
            Some(note) = notes.recv() => {
                let fired = Fired::new(
                    Trigger::Stall,
                    note.at_ms,
                    &format!("side={}", note.side),
                    None,
                );
                auto.fire(fired, clocks().tick_ms, upload::now_ms(), log_on(&app));
            }
            Some((id, outcome)) = done_rx.recv() => {
                auto.upload_done(id, &outcome, clocks().tick_ms, upload::now_ms());
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// `work` on a blocking thread, waited for at most `wait`; `what` names it for the error.
async fn blocking<T: Send + 'static>(
    wait: Duration,
    what: &str,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    match tokio::time::timeout(wait, tauri::async_runtime::spawn_blocking(work)).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(format!("{what}: the blocking task failed: {e}")),
        Err(_) => Err(format!(
            "{what}: not done in {} s (left to finish on its own)",
            wait.as_secs()
        )),
    }
}

/// Pack the report `c`: what the app knows copied now (each lock only to copy), the zip made on a
/// blocking thread, the metadata with `auto`.
async fn pack(
    app: &AppHandle,
    c: &Collecting,
    skipped: BTreeMap<String, u32>,
) -> Result<Ready, String> {
    let started = Instant::now();
    let diagnostics = app.state::<Diagnostics>();
    let control = app.state::<AgentControl>();
    let config = super::config_snapshot(&control);
    let live = super::live_sessions(&control);
    let focus = c.failed_session().map(str::to_string);
    let session_ids = super::session_ids(
        focus.as_deref(),
        &live,
        &afklink_core::lock(&diagnostics.recent_sessions),
    );
    let endpoint = upload::endpoint(&config.server_url)?;
    let build = app.state::<BuildInfo>().inner().clone();
    let files = Arc::clone(app.state::<crate::Logging>().files());
    let previous_end = if c.has_crash() {
        match LOG_AT_START.get() {
            Some(Ok(start)) => Some(start.clone()),
            _ => {
                tracing::debug!(
                    "diagnostics: auto: a crash, but where the system log stood at start is not \
                     known; its plain tail goes in"
                );
                None
            }
        }
    } else {
        None
    };
    let mut about = Map::new();
    about.insert("auto".into(), c.about(&skipped));
    about.insert("session_ids".into(), json!(session_ids));
    about.insert(
        "app_uptime_s".into(),
        json!(diagnostics.started.elapsed().as_secs()),
    );
    about.insert("entry".into(), super::entry_json(&diagnostics.entry));
    let now_ms = upload::now_ms();
    let event_ms = c.event_ms();
    let endpoint_text = endpoint.to_string();
    let build_for_pack = build.clone();
    let app_for_pack = app.clone();
    let (package, os) = blocking(PACK_WAIT, "packing", move || {
        let flushed = files.flush(super::FLUSH_WAIT);
        let os = super::system::os_label();
        let log = app_for_pack.state::<crate::Logging>().dto();
        let mut about = about;
        about.insert(
            "log".into(),
            json!({
                "level": log.level,
                "choice": log.choice,
                "default_level": log.default_level,
                "env_override": log.env_override,
                "flushed": flushed,
            }),
        );
        package::build_tail(package::TailInputs {
            logs_dir: crate::logs_dir()
                .inspect_err(|e| tracing::warn!("diagnostics: auto: no logs folder: {e}"))
                .ok(),
            config: package::ConfigSource {
                path: config.path,
                in_memory: config.in_memory,
            },
            generated: vec![(
                "build.json".to_string(),
                super::pretty(&super::build_json(&build_for_pack, &endpoint_text)),
            )],
            about,
            now_unix_ms: now_ms,
            event_unix_ms: event_ms,
            cap: package::AUTO_CAP,
            system_raw: package::AUTO_SYSTEM_RAW,
            session: focus,
            session_raw: package::AUTO_SESSION_RAW,
            previous_end,
            this_run_raw: package::AUTO_THIS_RUN_RAW,
        })
        .map(|package| (package, os))
    })
    .await?
    .map_err(|e| e.to_string())?;
    let ready = ready(
        &build,
        &config.device_id,
        endpoint,
        c,
        package,
        Meta {
            session_ids,
            os,
            now_ms,
        },
        skipped,
    )?;
    tracing::debug!(
        id = c.id,
        zip_bytes = ready.prepared.body.len(),
        meta_chars = ready.prepared.meta_header.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "diagnostics: auto: report ready"
    );
    Ok(ready)
}

/// What the metadata says beside the files and `auto`.
pub(crate) struct Meta {
    pub(crate) session_ids: Vec<String>,
    /// Windows, e.g. «Windows 11 Pro 24H2 (26100)».
    pub(crate) os: Option<String>,
    /// When it was packed (`client_time`).
    pub(crate) now_ms: u64,
}

/// The packed report with its metadata (`auto` the first trigger), ready to sign and send. The size
/// is checked here once more: past the cap, it is not made.
pub(crate) fn ready(
    build: &BuildInfo,
    device_id: &str,
    endpoint: reqwest::Url,
    c: &Collecting,
    package: package::Package,
    meta: Meta,
    skipped: BTreeMap<String, u32>,
) -> Result<Ready, String> {
    let Meta {
        session_ids,
        os,
        now_ms,
    } = meta;
    if package.zip.len() as u64 > limits::AGENT_AUTO_BODY_BYTES {
        return Err(format!(
            "the zip is {} bytes, over the cap of {}",
            package.zip.len(),
            limits::AGENT_AUTO_BODY_BYTES
        ));
    }
    let meta = AgentDiagnosticsMeta {
        build: super::agent_build(build),
        client_time: now_ms,
        comment: None,
        files: package.files,
        session_ids: (!session_ids.is_empty()).then_some(session_ids),
        os,
        auto: Some(c.first.marker()),
    };
    let meta_header = upload::meta_header(&meta)?;
    Ok(Ready {
        prepared: upload::Prepared {
            endpoint,
            device: device_id.to_string(),
            content_sha256: upload::sha256_hex(&package.zip),
            body: Bytes::from(package.zip),
            meta_header,
        },
        skipped,
    })
}

/// One upload, the way the signaling socket goes first. A report whose whole body went without an
/// answer is not tried again nor the other way ([`upload::AfterBody::Stop`]).
async fn upload_one(app: &AppHandle, up: &Upload) -> upload::Outcome {
    let diagnostics = app.state::<Diagnostics>();
    let build = app.state::<BuildInfo>();
    let client = match upload::client(&build.user_agent()) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(id = up.id, "diagnostics: auto: {e}");
            return upload::Outcome::Failed(upload::Failure::Network(e));
        }
    };
    let endpoints = super::endpoints_in_order(&diagnostics.entry, &up.prepared.endpoint);
    tracing::debug!(
        id = up.id,
        trigger = up.trigger.as_str(),
        attempt = up.attempt,
        "diagnostics: auto: sending"
    );
    upload::send_any(
        &client,
        &up.prepared,
        &endpoints,
        &diagnostics.identity,
        upload::now_ms,
        upload::random_nonce,
        upload::STALL,
        upload::AfterBody::Stop,
    )
    .await
}

#[cfg(test)]
#[path = "auto_tests.rs"]
mod tests;
