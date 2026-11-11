//! What happened on the PC outside any session, for the server: `agent_event` (a process started,
//! the last one crashed, an update ended, the input driver's installer ended, the owner changed a
//! setting). Kept in a queue on disk until a connection took them.
//!
//! The queue is `agent_events.json` in the data directory ([`crate::paths::afklink_dir`]:
//! `%APPDATA%\AFKLink`, or the CLI's `--data-dir`), beside `run_state.json`, rewritten whole on
//! every change (a temporary file, then a rename) so a reader finds the old queue or the new, never
//! half of either. Opening writes nothing; the desktop app writes only once it is the one instance
//! ([`EventQueue::claim`]).
//!
//! Every change is written at once, synchronously, under the queue's own mutex: a few hundred bytes
//! to a local file, so [`record`] may block its caller for that long. Callers record after they let
//! go of their own locks (the config's, above all), never while holding one.
//!
//! # Delivery
//!
//! - **Only after `agent_ready`.** The orchestrator sends the queue on a connection whose handshake
//!   is done ([`crate::Agent`], `connect_and_serve`), again when something is queued while it is
//!   up, and on its tick for what the budget held back. A server older than the message answers
//!   `error bad_message` and keeps the socket; the event is then lost to it, nothing worse.
//! - **No acknowledgement.** The server answers nothing, so delivery is inferred from the link
//!   staying healthy after the send ([`EventQueue::confirm`]); a resend is free.
//! - **The relay does not hold events** (`crate::relay::class`): while no connection is up, this
//!   queue is what carries them to the next.
//! - **Bounded.** At most [`SEND_BUDGET`] sends an hour and [`QUEUE_CAP`] waiting events; each fact
//!   is queued once and only what the contract takes ([`EventQueue::record`]).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use afklink_protocol::metrics::{AgentEvent, AgentEventKind, PcSettingKey, PcSettingValue};

use crate::sync::lock;

/// The file's name in the data directory.
pub const FILE_NAME: &str = "agent_events.json";

/// The file's format; a later one may add fields (an older reader ignores them).
const VERSION: u32 = 1;

/// Events that wait, at most. A healthy PC has one or two at a time; this is a bound on a PC that
/// stays offline through a crash loop, not a budget. Past it the oldest goes (counted in the file's
/// `dropped`, warned once a process).
pub const QUEUE_CAP: usize = 64;

/// Sends an hour, resends included: a fifth of what the server takes from a device (300), so the
/// agent never comes near its limit. The times of the sends are kept in the file, so a crash loop
/// or a flapping link cannot spend more by restarting. What the budget holds back waits.
pub const SEND_BUDGET: usize = 60;

/// The window [`SEND_BUDGET`] counts in.
pub const BUDGET_WINDOW: Duration = Duration::from_secs(3_600);

/// How long past its silence limit an event's connection must stay up after the send before the
/// event counts as delivered ([`EventQueue::confirm`]).
pub const CONFIRM_MARGIN: Duration = Duration::from_secs(5);

/// How long after an event's send the backend must have been heard from (any frame, its heartbeat
/// ping included) before the event counts as delivered: the path still carried something both ways
/// well after the event was written.
pub const HEARD_AFTER: Duration = Duration::from_secs(5);

/// Events delivered by this process that a new one is compared with, at most.
const RECENT_KEPT: usize = 64;

/// One waiting event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Stored {
    /// Unique in the file; one missing or repeated is given a new one on reading.
    #[serde(default)]
    id: u64,
    /// How often it went out (for the log).
    #[serde(default)]
    sends: u32,
    event: AgentEvent,
}

/// The file's content, one small JSON object:
///
/// ```json
/// {"v":1,"next_id":4,"events":[{"id":3,"sends":1,"event":{"at":1789600300000,
///  "kind":"pc_setting_changed","key":"game_only","value":true}}],"sends":[1789600301000],"dropped":0}
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct QueueFile {
    v: u32,
    #[serde(default)]
    next_id: u64,
    #[serde(default)]
    events: Vec<Stored>,
    /// Unix ms of the sends in the last [`BUDGET_WINDOW`].
    #[serde(default)]
    sends: Vec<u64>,
    /// Events dropped over the cap, ever.
    #[serde(default)]
    dropped: u64,
}

/// A waiting event sent on a connection.
#[derive(Debug, Clone, Copy)]
struct Flight {
    link: u64,
    sent: Instant,
    /// The connection's silence limit at the send.
    limit: Duration,
}

/// What a connection says of itself when its events are confirmed
/// (`afklink_transport::LinkHealth`).
#[derive(Debug, Clone, Copy)]
pub struct LinkSeen {
    /// Its pump still runs.
    pub up: bool,
    /// When the backend was last heard from on it.
    pub last_heard: Instant,
    /// The silence limit in force for it now.
    pub silence_limit: Duration,
}

/// Why an event on its way stays in the queue, or that it was delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Delivered,
    /// Its connection's pump has ended (its `link_down` follows).
    Down,
    /// Not yet [`CONFIRM_MARGIN`] past the silence limit since the send.
    TooSoon,
    /// The backend not heard from [`HEARD_AFTER`] after the send.
    Unheard,
}

fn verdict(f: &Flight, now: Instant, seen: &LinkSeen) -> Verdict {
    if !seen.up {
        return Verdict::Down;
    }
    let limit = f.limit.max(seen.silence_limit);
    if now.saturating_duration_since(f.sent) < limit.saturating_add(CONFIRM_MARGIN) {
        return Verdict::TooSoon;
    }
    if seen.last_heard < f.sent + HEARD_AFTER {
        return Verdict::Unheard;
    }
    Verdict::Delivered
}

#[derive(Debug, Default)]
struct Inner {
    file: QueueFile,
    /// Waiting events sent on a connection, by id.
    in_flight: HashMap<u64, Flight>,
    /// Delivered by this process: a fact recorded again is not queued twice.
    recent: VecDeque<AgentEvent>,
    budget_warned: bool,
    cap_warned: bool,
    write_failed: bool,
    /// Writing is allowed: the process owns the queue (the desktop app's single-instance lock).
    claimed: bool,
}

/// What [`EventQueue::record`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// Queued, at `at` (moved on from the event's own when another fact of its kind had it).
    Queued { at: u64, pending: usize },
    /// The same fact waits already, or was delivered by this process.
    Duplicate,
    /// The contract would refuse it: this field.
    Refused(&'static str),
}

/// The queue. One per process ([`install`]), shared by the orchestrator, which sends it, and every
/// place that records an event.
#[derive(Debug)]
pub struct EventQueue {
    path: Option<PathBuf>,
    inner: Mutex<Inner>,
    wake: tokio::sync::Notify,
}

/// Unix ms now, on this PC's clock; 0 before 1970.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The queue file's text, each part read on its own: an event this build cannot read (a kind a
/// later build added, a field gone wrong) or one the contract's checks refuse now is skipped with a
/// warning, and the rest stay; fields this build does not know are ignored; past [`QUEUE_CAP`] the
/// oldest go, counted in `dropped`. Only a text that is not a JSON object at all is unreadable.
fn read_file(text: &str) -> Result<QueueFile, serde_json::Error> {
    use serde_json::Value;
    let raw: serde_json::Map<String, Value> = serde_json::from_str(text)?;
    let number = |key: &str| raw.get(key).and_then(Value::as_u64);
    if let Some(v) = number("v").filter(|&v| v > u64::from(VERSION)) {
        tracing::debug!(
            v,
            ours = VERSION,
            "agent events: the queue on disk was written by a later build; read as far as this \
             one knows"
        );
    }
    let mut file = QueueFile {
        v: VERSION,
        next_id: number("next_id").unwrap_or(0),
        events: Vec::new(),
        sends: raw
            .get("sends")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default(),
        dropped: number("dropped").unwrap_or(0),
    };
    let listed: &[Value] = match raw.get("events") {
        Some(Value::Array(a)) => a,
        Some(_) => {
            tracing::warn!(
                "agent events: the queue on disk has no list of events where one belongs; none read"
            );
            &[]
        }
        None => &[],
    };
    let mut skipped = 0usize;
    for value in listed {
        let stored = match Stored::deserialize(value) {
            Ok(stored) => stored,
            Err(e) => {
                // The kind only when it is a short id: what a broken file holds is not echoed.
                let kind = value
                    .pointer("/event/kind")
                    .and_then(Value::as_str)
                    .filter(|k| afklink_protocol::metrics::is_short_id(k))
                    .unwrap_or("-");
                tracing::warn!(
                    kind,
                    "agent events: an event in the queue on disk is unreadable ({e}); skipped, the \
                     rest kept"
                );
                skipped += 1;
                continue;
            }
        };
        if let Err(e) = stored.event.check() {
            tracing::warn!(
                kind = stored.event.event.kind(),
                field = e.field,
                "agent events: an event in the queue on disk fails the contract's checks; skipped, \
                 the rest kept"
            );
            skipped += 1;
            continue;
        }
        file.events.push(stored);
    }
    // Ids unique and below `next_id`: they key the sends on their way, in this process only.
    let mut seen = std::collections::HashSet::new();
    let mut renumbered = 0usize;
    for i in 0..file.events.len() {
        let id = file.events[i].id;
        if id >= file.next_id || !seen.insert(id) {
            let fresh = file.next_id;
            file.next_id = fresh.saturating_add(1);
            file.events[i].id = fresh;
            seen.insert(fresh);
            renumbered += 1;
        }
    }
    if renumbered > 0 {
        tracing::debug!(
            renumbered,
            "agent events: ids in the queue on disk repeated or ran past its next id; given new ones"
        );
    }
    if file.events.len() > QUEUE_CAP {
        let over = file.events.len() - QUEUE_CAP;
        file.events.drain(..over);
        file.dropped = file.dropped.saturating_add(over as u64);
        tracing::warn!(
            cap = QUEUE_CAP,
            dropped = over,
            dropped_ever = file.dropped,
            "agent events: the queue on disk holds more than the cap; the oldest are dropped"
        );
    }
    if skipped > 0 {
        tracing::info!(
            skipped,
            kept = file.events.len(),
            "agent events: the queue on disk read in part; the events skipped are lost"
        );
    }
    Ok(file)
}

impl EventQueue {
    /// Read the queue in `dir` (`read_file`). Writes nothing until [`Self::claim`]: the desktop
    /// app opens it before Tauri and claims once the single-instance lock made it the one instance
    /// (as `crate::run_state` does), so a second launch, ended by the lock at once, never touches
    /// the running one's queue.
    pub fn open(dir: &Path) -> Self {
        let path = dir.join(FILE_NAME);
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => match read_file(&text) {
                Ok(file) => {
                    tracing::debug!(
                        file = %path.display(),
                        waiting = file.events.len(),
                        sends_kept = file.sends.len(),
                        dropped = file.dropped,
                        "agent events: the queue the last run left read"
                    );
                    file
                }
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        "agent events: the queue on disk is unreadable ({e}); starting empty — \
                         what it held is lost"
                    );
                    QueueFile::default()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(file = %path.display(), "agent events: no queue on disk yet");
                QueueFile::default()
            }
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    "agent events: the queue on disk could not be read ({e}); starting empty"
                );
                QueueFile::default()
            }
        };
        Self::with(Some(path), file)
    }

    /// [`Self::open`] in the data directory; `None` when there is none to be had.
    pub fn open_default() -> Option<Self> {
        match crate::paths::afklink_dir() {
            Ok(dir) => Some(Self::open(&dir)),
            Err(e) => {
                tracing::warn!("agent events: no data directory ({e:#}); none will be kept");
                None
            }
        }
    }

    /// A queue that keeps nothing on disk (tests).
    pub fn in_memory() -> Self {
        let q = Self::with(None, QueueFile::default());
        lock(&q.inner).claimed = true;
        q
    }

    fn with(path: Option<PathBuf>, mut file: QueueFile) -> Self {
        file.v = VERSION;
        Self {
            path,
            inner: Mutex::new(Inner {
                file,
                ..Inner::default()
            }),
            wake: tokio::sync::Notify::new(),
        }
    }

    /// This process owns the queue from here: it may write. The desktop app claims once its
    /// single-instance lock is past, the CLI at once.
    pub fn claim(&self) {
        let mut inner = lock(&self.inner);
        if std::mem::replace(&mut inner.claimed, true) {
            return;
        }
        tracing::debug!(
            waiting = inner.file.events.len(),
            "agent events: the queue is this process's; sent once a connection is up"
        );
        if !inner.file.events.is_empty() {
            self.wake.notify_one();
        }
    }

    /// Events waiting.
    pub fn pending(&self) -> usize {
        lock(&self.inner).file.events.len()
    }

    /// The events waiting, oldest first (a copy: for a look, not for sending).
    pub fn waiting(&self) -> Vec<AgentEvent> {
        lock(&self.inner)
            .file
            .events
            .iter()
            .map(|s| s.event.clone())
            .collect()
    }

    /// Queue `event` and wake the sender.
    ///
    /// - Only what the contract takes: an event that fails [`AgentEvent::check`] would cost its
    ///   whole frame, so it is refused here, with a warning, and never queued.
    /// - Each fact once: an event identical to one waiting, or to one delivered by this process, is
    ///   not queued again. One of the same kind at the same `at` with other props is moved a
    ///   millisecond on, so the server's kind-and-`at` rule cannot merge two facts.
    /// - Bounded by [`QUEUE_CAP`]: past it the oldest goes.
    pub fn record(&self, mut event: AgentEvent) -> Recorded {
        let kind = event.event.kind();
        if let Err(e) = event.check() {
            tracing::warn!(
                kind,
                field = e.field,
                "agent event refused: the contract would not take it; not queued"
            );
            return Recorded::Refused(e.field);
        }
        let mut inner = lock(&self.inner);
        if !inner.claimed {
            tracing::debug!(
                kind,
                "agent events: the queue is not claimed by this process; not queued"
            );
            return Recorded::Refused("unclaimed");
        }
        let same = |e: &AgentEvent| *e == event;
        if inner.file.events.iter().any(|s| same(&s.event)) || inner.recent.iter().any(same) {
            tracing::debug!(
                kind,
                at = event.at,
                "agent event: the same fact is queued or delivered already"
            );
            return Recorded::Duplicate;
        }
        // Another fact of this kind at this `at`: a millisecond on, until it has its own.
        let taken = |inner: &Inner, at: u64| {
            inner
                .file
                .events
                .iter()
                .map(|s| &s.event)
                .chain(inner.recent.iter())
                .any(|e| e.at == at && e.event.kind() == kind)
        };
        let asked = event.at;
        while taken(&inner, event.at) {
            event.at = event.at.saturating_add(1);
        }
        if event.at != asked {
            tracing::debug!(
                kind,
                asked,
                at = event.at,
                "agent event moved on: its `at` was another fact's"
            );
        }
        if inner.file.events.len() >= QUEUE_CAP {
            let gone = inner.file.events.remove(0);
            inner.in_flight.remove(&gone.id);
            inner.file.dropped = inner.file.dropped.saturating_add(1);
            if std::mem::replace(&mut inner.cap_warned, true) {
                tracing::debug!(
                    dropped = gone.event.event.kind(),
                    "agent events: queue full; the oldest dropped"
                );
            } else {
                tracing::warn!(
                    cap = QUEUE_CAP,
                    dropped = gone.event.event.kind(),
                    dropped_at = gone.event.at,
                    dropped_ever = inner.file.dropped,
                    "agent events: the queue is full (offline for long?); the oldest is dropped"
                );
            }
        }
        let id = inner.file.next_id;
        inner.file.next_id = id.saturating_add(1);
        let at = event.at;
        tracing::info!(
            kind,
            at,
            props = %props_line(&event.event),
            pending = inner.file.events.len() + 1,
            "agent event queued"
        );
        inner.file.events.push(Stored {
            id,
            sends: 0,
            event,
        });
        let pending = inner.file.events.len();
        self.write(&mut inner, "queued");
        drop(inner);
        self.wake.notify_one();
        Recorded::Queued { at, pending }
    }

    /// Wait until something is queued (or was queued since the last wait).
    pub fn queued(&self) -> impl Future<Output = ()> + '_ {
        self.wake.notified()
    }

    /// The events to send now on connection `link`: every waiting one not already on its way on
    /// that connection, as far as the budget allows, marked as sent at `now` on a connection held
    /// to `silence_limit` (`afklink_transport::LinkHealth::silence_limit`).
    pub fn due(
        &self,
        link: u64,
        now: Instant,
        now_ms: u64,
        silence_limit: Duration,
    ) -> Vec<AgentEvent> {
        let mut inner = lock(&self.inner);
        let window_ms = u64::try_from(BUDGET_WINDOW.as_millis()).unwrap_or(u64::MAX);
        inner.file.sends.retain(|&at| {
            now_ms.saturating_sub(at) < window_ms && at <= now_ms.saturating_add(window_ms)
        });
        let room = SEND_BUDGET.saturating_sub(inner.file.sends.len());
        let Inner {
            file, in_flight, ..
        } = &mut *inner;
        let waiting: Vec<usize> = file
            .events
            .iter()
            .enumerate()
            .filter(|(_, s)| in_flight.get(&s.id).map(|f| f.link) != Some(link))
            .map(|(i, _)| i)
            .collect();
        let held = waiting.len().saturating_sub(room);
        let mut out = Vec::new();
        for &i in waiting.iter().take(room) {
            if let Some(s) = file.events.get_mut(i) {
                s.sends = s.sends.saturating_add(1);
                in_flight.insert(
                    s.id,
                    Flight {
                        link,
                        sent: now,
                        limit: silence_limit,
                    },
                );
                file.sends.push(now_ms);
                out.push(s.event.clone());
            }
        }
        if held > 0 {
            if std::mem::replace(&mut inner.budget_warned, true) {
                tracing::debug!(
                    held,
                    link,
                    "agent events: the hour's budget holds some back"
                );
            } else {
                tracing::warn!(
                    held,
                    budget = SEND_BUDGET,
                    window_s = BUDGET_WINDOW.as_secs(),
                    link,
                    "agent events: the hour's send budget is spent; the rest wait for it"
                );
            }
        } else {
            inner.budget_warned = false;
        }
        if !out.is_empty() {
            tracing::debug!(
                link,
                sent = out.len(),
                kinds = %out.iter().map(|e| e.event.kind()).collect::<Vec<_>>().join(","),
                waiting = inner.file.events.len(),
                budget_left = SEND_BUDGET.saturating_sub(inner.file.sends.len()),
                silence_limit_ms = silence_limit.as_millis() as u64,
                "agent events sent on the connection (delivered once it stays up {} s past its \
                 silence limit and the backend is heard from {} s after them)",
                CONFIRM_MARGIN.as_secs(),
                HEARD_AFTER.as_secs()
            );
            self.write(&mut inner, "sent");
        }
        out
    }

    /// Connection `link`, as it says of itself at `now` (`seen`): what went out on it and is now
    /// known to be taken leaves the queue — the connection still up [`CONFIRM_MARGIN`] past the
    /// longer of its silence limit at the send and now, and the backend heard from [`HEARD_AFTER`]
    /// after the send. Anything less stays. Returns how many left.
    ///
    /// The server answers nothing, so an event leaves the queue only when both hold: its connection
    /// is still up [`CONFIRM_MARGIN`] past the silence limit in force for it
    /// (`afklink_transport::LinkHealth`: 45 s until the backend's pings are seen to come every few
    /// seconds, then 20 s; the longer of the limit at the send and the one now), and the backend
    /// was heard from (any frame) at least [`HEARD_AFTER`] after the send. A connection that died
    /// after the send would have been given up by then, and the server reaps one it does not hear
    /// from in 20 s. Anything less keeps the event: one whose connection ended goes again on the
    /// next, and with every restart until then, with the same `at`. The server counts the same
    /// device, kind and `at` within an hour once, so a resend is free and erring on resending loses
    /// nothing.
    pub fn confirm(&self, link: u64, now: Instant, seen: LinkSeen) -> usize {
        let mut inner = lock(&self.inner);
        let mut delivered: Vec<u64> = Vec::new();
        let (mut down, mut too_soon, mut unheard) = (0usize, 0usize, 0usize);
        for (id, f) in inner.in_flight.iter().filter(|(_, f)| f.link == link) {
            match verdict(f, now, &seen) {
                Verdict::Delivered => delivered.push(*id),
                Verdict::Down => down += 1,
                Verdict::TooSoon => too_soon += 1,
                Verdict::Unheard => unheard += 1,
            }
        }
        let heard_ago_ms = now.saturating_duration_since(seen.last_heard).as_millis() as u64;
        if down + too_soon + unheard > 0 {
            tracing::debug!(
                link,
                kept = down + too_soon + unheard,
                down,
                too_soon,
                unheard,
                up = seen.up,
                silence_limit_ms = seen.silence_limit.as_millis() as u64,
                heard_ago_ms,
                "agent events on their way kept in the queue: not yet known taken (down: the \
                 connection ended, sent again on the next; too_soon: not yet past its silence limit \
                 and the margin; unheard: the backend not heard from since the send)"
            );
        }
        if delivered.is_empty() {
            return 0;
        }
        for id in &delivered {
            inner.in_flight.remove(id);
            if let Some(i) = inner.file.events.iter().position(|s| s.id == *id) {
                let s = inner.file.events.remove(i);
                inner.recent.push_back(s.event);
                if inner.recent.len() > RECENT_KEPT {
                    inner.recent.pop_front();
                }
            }
        }
        tracing::debug!(
            link,
            delivered = delivered.len(),
            waiting = inner.file.events.len(),
            silence_limit_ms = seen.silence_limit.as_millis() as u64,
            heard_ago_ms,
            "agent events delivered: their connection stayed up past its silence limit after them \
             and the backend was heard from since"
        );
        self.write(&mut inner, "delivered");
        delivered.len()
    }

    /// Connection `link` ended: what was on its way on it goes again on the next. How many.
    pub fn link_down(&self, link: u64) -> usize {
        let mut inner = lock(&self.inner);
        let before = inner.in_flight.len();
        inner.in_flight.retain(|_, f| f.link != link);
        let back = before - inner.in_flight.len();
        if back > 0 {
            tracing::debug!(
                link,
                back,
                "agent events sent on a connection that ended too soon: they go again on the next \
                 (the server counts a repeat once)"
            );
        }
        back
    }

    /// Write the queue whole: a temporary file beside it, then a rename over it. Nothing without a
    /// path (tests).
    fn write(&self, inner: &mut Inner, what: &str) {
        let Some(path) = &self.path else {
            return;
        };
        let result = serde_json::to_vec(&inner.file)
            .map_err(std::io::Error::other)
            .and_then(|bytes| {
                let mut tmp = path.clone().into_os_string();
                tmp.push(".tmp");
                let tmp = PathBuf::from(tmp);
                std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path))
            });
        match result {
            Ok(()) => {
                if std::mem::replace(&mut inner.write_failed, false) {
                    tracing::info!(what, "agent events: the queue is written again");
                } else {
                    tracing::trace!(what, "agent events: queue written");
                }
            }
            Err(e) => {
                if std::mem::replace(&mut inner.write_failed, true) {
                    tracing::debug!(what, "agent events: queue still not written: {e}");
                } else {
                    tracing::warn!(
                        file = %path.display(),
                        what,
                        "agent events: the queue was not written ({e}); held in memory, lost if \
                         the process ends before a connection takes it"
                    );
                }
            }
        }
    }
}

/// An event's props for the log line: counters, codes, versions and verdicts — what goes on the
/// wire, nothing more.
fn props_line(e: &AgentEventKind) -> String {
    match e {
        AgentEventKind::AgentStarted {
            boot_id,
            first_run,
            build,
            last_exit,
            autostart,
            previous_record,
            pc_restarted,
        } => format!(
            "boot_id={boot_id} first_run={first_run} version={} last_exit={} autostart={autostart} \
             previous_record={} pc_restarted={}",
            build.version,
            last_exit.kind.as_str(),
            previous_record.map_or("-", |r| r.as_str()),
            pc_restarted.map_or_else(|| "-".to_string(), |r| r.to_string())
        ),
        AgentEventKind::AgentCrashed {
            version,
            place_hash,
            thread,
            uptime_s,
            ..
        } => {
            format!("version={version} place_hash={place_hash} thread={thread} uptime_s={uptime_s}")
        }
        AgentEventKind::UpdateFinished {
            from,
            to,
            outcome,
            reason,
        } => format!(
            "from={from} to={to} outcome={} reason={}",
            outcome.as_str(),
            reason.as_deref().unwrap_or("-")
        ),
        AgentEventKind::DriverInstallFinished {
            outcome,
            step,
            code,
            ms,
        } => format!(
            "outcome={} step={step} code={} ms={ms}",
            outcome.as_str(),
            code.map_or_else(|| "-".to_string(), |c| c.to_string())
        ),
        AgentEventKind::PcSettingChanged { key, value } => {
            format!("key={} value={value}", key.as_str())
        }
    }
}

/// The queue this process records into ([`install`]).
static INSTALLED: OnceLock<Arc<EventQueue>> = OnceLock::new();

/// Make `queue` the one [`record`] writes to, and claim it ([`EventQueue::claim`]). Whether it is
/// the first: a second is ignored (said at warn).
pub fn install(queue: Arc<EventQueue>) -> bool {
    queue.claim();
    if INSTALLED.set(queue).is_err() {
        tracing::warn!("agent events: a queue was installed already; that one stays");
        return false;
    }
    true
}

/// The installed queue.
pub fn installed() -> Option<&'static Arc<EventQueue>> {
    INSTALLED.get()
}

/// Record `event` as of now into the installed queue.
pub fn record(event: AgentEventKind) -> Option<Recorded> {
    record_at(now_ms(), event)
}

#[cfg(test)]
thread_local! {
    /// Tests: this thread's events go here rather than into the installed queue, so a test that
    /// looks at what it recorded is not disturbed by tests on other threads recording into the
    /// process's one ([`record_on_this_thread`]).
    static THREAD_QUEUE: std::cell::RefCell<Option<Arc<EventQueue>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests: record this thread's events into `queue` (`None`: the installed one again).
#[cfg(test)]
pub(crate) fn record_on_this_thread(queue: Option<Arc<EventQueue>>) {
    THREAD_QUEUE.with(|t| *t.borrow_mut() = queue);
}

/// Record `event` at `at` (Unix ms on this PC's clock) — the fact's own time, which a resend keeps.
/// With no queue installed (a process that keeps none) it is said at debug and dropped.
pub fn record_at(at: u64, event: AgentEventKind) -> Option<Recorded> {
    #[cfg(test)]
    if let Some(queue) = THREAD_QUEUE.with(|t| t.borrow().clone()) {
        return Some(queue.record(AgentEvent { at, event }));
    }
    match INSTALLED.get() {
        Some(queue) => Some(queue.record(AgentEvent { at, event })),
        None => {
            tracing::debug!(
                kind = event.kind(),
                "agent events: no queue in this process; not recorded"
            );
            None
        }
    }
}

/// The owner changed a setting on the PC (`pc_setting_changed`, the closed list of keys).
pub fn setting_changed(key: PcSettingKey, value: PcSettingValue) -> Option<Recorded> {
    record(AgentEventKind::PcSettingChanged { key, value })
}

/// This process started: `agent_crashed` first when the previous one panicked
/// ([`crate::run_state::RunState::previous_crash`]), then `agent_started` — each at its own time,
/// the panic's and this start's, so a resend after another restart is the same fact. `first_run`:
/// the identity was made now; `autostart`: Windows started it at sign-in.
pub fn record_start(
    state: &crate::run_state::RunState,
    build: &crate::build_info::BuildInfo,
    first_run: bool,
    autostart: bool,
) {
    for event in start_events(state, build, first_run, autostart) {
        record_at(event.at, event.event);
    }
}

/// The events of [`record_start`], in the order they are recorded.
pub fn start_events(
    state: &crate::run_state::RunState,
    build: &crate::build_info::BuildInfo,
    first_run: bool,
    autostart: bool,
) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    if let Some(crash) = state.previous_crash() {
        out.push(AgentEvent {
            at: crash.at,
            event: AgentEventKind::AgentCrashed {
                version: crash.version,
                place_hash: crash.place_hash,
                thread: crash.thread,
                uptime_s: crash.uptime_s,
                boot_id: crash.boot_id,
            },
        });
    }
    match build.wire() {
        Some(wire) => out.push(AgentEvent {
            at: state.started_at(),
            event: AgentEventKind::AgentStarted {
                boot_id: state.boot_id().to_string(),
                first_run,
                build: wire,
                last_exit: state.last_exit(),
                autostart,
                previous_record: Some(state.previous_record()),
                pc_restarted: state.pc_restarted(),
            },
        }),
        None => tracing::warn!(
            version = %build.version,
            "agent_started not recorded: this build's version does not fit the contract"
        ),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_protocol::metrics::{DriverInstallOutcome, UpdateOutcome};

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "afklink-agent-events-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    /// The pump's two silence limits (`afklink_transport::signaling`).
    const SHORT: Duration = Duration::from_secs(20);
    const LONG: Duration = Duration::from_secs(45);

    /// A connection still up, last heard from at `heard`, held to `limit`.
    fn up(heard: Instant, limit: Duration) -> LinkSeen {
        LinkSeen {
            up: true,
            last_heard: heard,
            silence_limit: limit,
        }
    }

    /// The test's numbers are the transport's.
    #[test]
    fn the_limits_are_the_transports() {
        assert_eq!(SHORT, afklink_transport::signaling::BACKEND_SILENCE_LIMIT);
        assert_eq!(LONG, afklink_transport::signaling::LEGACY_SILENCE_LIMIT);
    }

    fn setting(at: u64, on: bool) -> AgentEvent {
        AgentEvent {
            at,
            event: AgentEventKind::PcSettingChanged {
                key: PcSettingKey::GameOnly,
                value: PcSettingValue::Flag(on),
            },
        }
    }

    fn driver(at: u64) -> AgentEvent {
        AgentEvent {
            at,
            event: AgentEventKind::DriverInstallFinished {
                outcome: DriverInstallOutcome::Failed,
                step: "msiexec".into(),
                code: Some(1603),
                ms: 41_250,
            },
        }
    }

    /// Queued on disk, still there for the next process, sent on its connection with the `at` it
    /// was recorded at, and gone once the connection stayed up past the confirmation.
    #[test]
    fn the_queue_survives_a_restart_and_keeps_its_at() {
        let d = dir("restart");
        let q = EventQueue::open(&d);
        q.claim();
        assert!(matches!(
            q.record(setting(1_789_600_300_000, true)),
            Recorded::Queued {
                at: 1_789_600_300_000,
                pending: 1
            }
        ));
        assert!(matches!(
            q.record(driver(1_789_600_200_000)),
            Recorded::Queued { pending: 2, .. }
        ));
        // Sent on a connection that ends at once: still waiting.
        let t0 = Instant::now();
        assert_eq!(q.due(1, t0, 1_789_600_301_000, SHORT).len(), 2);
        assert_eq!(q.link_down(1), 2);
        drop(q);

        // The next process.
        let q = EventQueue::open(&d);
        assert_eq!(q.pending(), 2);
        q.claim();
        let sent = q.due(1, t0, 1_789_600_400_000, SHORT);
        let ats: Vec<u64> = sent.iter().map(|e| e.at).collect();
        assert_eq!(
            ats,
            [1_789_600_300_000, 1_789_600_200_000],
            "the same `at`, in order"
        );
        assert!(
            q.due(1, t0, 1_789_600_400_000, SHORT).is_empty(),
            "not twice on one connection"
        );
        let soon = t0 + Duration::from_secs(5);
        assert_eq!(q.confirm(1, soon, up(soon, SHORT)), 0, "too soon");
        let later = t0 + SHORT + CONFIRM_MARGIN;
        assert_eq!(q.confirm(1, later, up(later, SHORT)), 2);
        assert_eq!(q.pending(), 0);
        drop(q);
        assert_eq!(EventQueue::open(&d).pending(), 0, "and gone from disk");
        // Its sends are remembered for the budget across the restart.
        let text = std::fs::read_to_string(d.join(FILE_NAME)).expect("the file");
        let file: QueueFile = serde_json::from_str(&text).expect("a queue");
        assert_eq!(file.sends.len(), 4);
    }

    /// Nothing is written before the claim: a second instance, ended by the lock, leaves the
    /// running one's queue alone.
    #[test]
    fn nothing_is_written_before_the_claim() {
        let d = dir("unclaimed");
        let q = EventQueue::open(&d);
        assert_eq!(q.record(setting(1, true)), Recorded::Refused("unclaimed"));
        assert!(!d.join(FILE_NAME).exists());
    }

    /// The same fact twice is one; another fact of the kind at the same `at` moves a millisecond
    /// on.
    #[test]
    fn each_fact_once_and_never_merged_with_another() {
        let q = EventQueue::in_memory();
        assert!(matches!(
            q.record(setting(1_000, true)),
            Recorded::Queued { at: 1_000, .. }
        ));
        assert_eq!(q.record(setting(1_000, true)), Recorded::Duplicate);
        assert!(matches!(
            q.record(setting(1_000, false)),
            Recorded::Queued { at: 1_001, .. }
        ));
        // Delivered, then recorded again by the same process: still once.
        let t0 = Instant::now();
        q.due(7, t0, 2_000, SHORT);
        q.confirm(
            7,
            t0 + SHORT + CONFIRM_MARGIN,
            up(t0 + Duration::from_secs(10), SHORT),
        );
        assert_eq!(q.pending(), 0);
        assert_eq!(q.record(setting(1_000, true)), Recorded::Duplicate);
    }

    /// What the contract would refuse is never queued.
    #[test]
    fn an_event_off_the_contract_is_refused() {
        let q = EventQueue::in_memory();
        let bad = AgentEvent {
            at: 1,
            event: AgentEventKind::UpdateFinished {
                from: "0.5".into(),
                to: "0.6.0".into(),
                outcome: UpdateOutcome::Confirmed,
                reason: None,
            },
        };
        assert_eq!(q.record(bad), Recorded::Refused("from"));
        let bad_code = AgentEvent {
            at: 1,
            event: AgentEventKind::PcSettingChanged {
                key: PcSettingKey::LogLevel,
                value: PcSettingValue::Id("Debug Mode".into()),
            },
        };
        assert_eq!(q.record(bad_code), Recorded::Refused("value"));
        assert_eq!(q.pending(), 0);
    }

    /// The hour's budget: no more than [`SEND_BUDGET`] sends, resends included; the rest wait.
    #[test]
    fn the_budget_holds_the_rest_back() {
        let q = EventQueue::in_memory();
        for i in 0..40u64 {
            q.record(setting(10_000 + i, true));
        }
        let t0 = Instant::now();
        let now_ms = 1_789_600_000_000;
        assert_eq!(q.due(1, t0, now_ms, SHORT).len(), 40);
        q.link_down(1);
        // The same forty again on the next connection: only twenty fit the hour.
        assert_eq!(q.due(2, t0, now_ms + 1_000, SHORT).len(), SEND_BUDGET - 40);
        // An hour on, room again.
        q.link_down(2);
        assert_eq!(q.due(3, t0, now_ms + 3_601_000, SHORT).len(), 40);
    }

    /// Events go out the moment a connection is up, and its path dies a second later. The pump
    /// holds a fresh connection to the long limit (45 s) until it has judged the backend's pings,
    /// so the connection still looks up at 30 s and long after — but nothing was heard after the
    /// send, so nothing is taken for delivered; the connection's end then sends them again on the
    /// next.
    #[test]
    fn events_sent_on_a_connection_that_dies_right_after_are_not_confirmed() {
        let q = EventQueue::in_memory();
        q.record(setting(1_000, true));
        q.record(driver(2_000));
        let t0 = Instant::now();
        assert_eq!(q.due(1, t0, 1_789_600_000_000, LONG).len(), 2);
        // The path dies a second after the send: the last word heard.
        let dead = up(t0 + Duration::from_secs(1), LONG);
        for after in [5u64, 30, 45, 49, 60, 120] {
            assert_eq!(
                q.confirm(1, t0 + Duration::from_secs(after), dead),
                0,
                "{after} s after the send"
            );
        }
        // The pump gives up on the silence: down, kept.
        let gone = LinkSeen { up: false, ..dead };
        assert_eq!(q.confirm(1, t0 + Duration::from_secs(47), gone), 0);
        assert_eq!(q.link_down(1), 2);
        assert_eq!(q.pending(), 2);

        // The next connection is healthy: its pings are judged fast ten seconds in (the limit
        // drops to 20 s) and keep coming. The limit at the send (45 s) still governs.
        let t1 = t0 + Duration::from_secs(60);
        assert_eq!(q.due(2, t1, 1_789_600_060_000, LONG).len(), 2);
        let pinging = |at: u64| up(t1 + Duration::from_secs(at), SHORT);
        assert_eq!(q.confirm(2, t1 + Duration::from_secs(25), pinging(24)), 0);
        assert_eq!(q.confirm(2, t1 + Duration::from_secs(49), pinging(48)), 0);
        assert_eq!(
            q.confirm(2, t1 + LONG + CONFIRM_MARGIN, pinging(49)),
            2,
            "up past the limit at the send and the margin, heard from since"
        );
        assert_eq!(q.pending(), 0);
    }

    /// Up long enough is not enough: the backend must have been heard from after the send.
    #[test]
    fn an_event_is_not_confirmed_without_a_word_from_the_backend_after_it() {
        let q = EventQueue::in_memory();
        q.record(setting(1_000, true));
        let t0 = Instant::now();
        q.due(1, t0, 1_789_600_000_000, SHORT);
        let late = t0 + SHORT + CONFIRM_MARGIN;
        let just_before = t0 + HEARD_AFTER - Duration::from_millis(1);
        assert_eq!(q.confirm(1, late, up(just_before, SHORT)), 0);
        // Another connection's view never confirms this one's events.
        assert_eq!(q.confirm(2, late, up(late, SHORT)), 0);
        assert_eq!(q.confirm(1, late, up(t0 + HEARD_AFTER, SHORT)), 1);
    }

    /// Past the cap the oldest goes, counted.
    #[test]
    fn the_queue_is_bounded() {
        let q = EventQueue::in_memory();
        for i in 0..(QUEUE_CAP as u64 + 5) {
            q.record(setting(100 + i, true));
        }
        assert_eq!(q.pending(), QUEUE_CAP);
        let inner = lock(&q.inner);
        assert_eq!(inner.file.dropped, 5);
        assert_eq!(inner.file.events[0].event.at, 105, "the oldest went");
    }

    /// A start after a panic: `agent_crashed` at the panic's time, then `agent_started` at this
    /// start's — the wire shapes the contract's fixtures have, each passing its checks.
    #[test]
    fn a_start_after_a_panic_is_two_events_in_the_contracts_shapes() {
        let d = dir("start_after_panic");
        std::fs::write(
            d.join(crate::run_state::FILE_NAME),
            r#"{"v":1,"boot_id":"0d9c8b7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d","pid":7,"version":"0.5.1",
               "started_at":1789594560000,"alive_at":1789599960000,
               "exit":{"kind":"panic","at":1789599960000},
               "panic":{"place_hash":"9f86d081884c7d65","thread":"main","uptime_s":5400}}"#,
        )
        .expect("write");
        // Windows booted 30 s after the panic, and this start came a minute later.
        let state =
            crate::run_state::RunState::read_at(&d, 1_789_600_050_000, Some(1_789_599_990_000));
        let build = crate::build_info::BuildInfo::from_stamp(
            "0.5.1",
            "3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9",
            "0",
            "",
            "release",
        );
        let events = start_events(&state, &build, false, true);
        assert_eq!(events.len(), 2);
        for e in &events {
            assert_eq!(e.check(), Ok(()), "{e:?}");
        }
        let crashed = serde_json::to_value(afklink_transport::AgentToServer::AgentEvent(
            events[0].clone(),
        ))
        .expect("serialises");
        assert_eq!(
            crashed,
            serde_json::json!({
                "type": "agent_event",
                "kind": "agent_crashed",
                "at": 1_789_599_960_000u64,
                "version": "0.5.1",
                "place_hash": "9f86d081884c7d65",
                "thread": "main",
                "uptime_s": 5_400,
                "boot_id": "0d9c8b7a-6e5f-4a3b-9c2d-1e0f9a8b7c6d"
            })
        );
        let started = serde_json::to_value(afklink_transport::AgentToServer::AgentEvent(
            events[1].clone(),
        ))
        .expect("serialises");
        assert_eq!(started["kind"], "agent_started");
        assert_eq!(started["at"], state.started_at());
        assert_eq!(started["boot_id"], state.boot_id());
        assert_eq!(started["first_run"], false);
        assert_eq!(started["autostart"], true);
        assert_eq!(
            started["build"],
            serde_json::json!({
                "version": "0.5.1",
                "commit": "3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9",
                "channel": "release",
                "dirty": false
            })
        );
        assert_eq!(
            started["last_exit"],
            serde_json::json!({ "kind": "panic", "at": 1_789_599_960_000u64 })
        );
        assert_eq!(started["previous_record"], "found");
        assert_eq!(started["pc_restarted"], true, "a boot 30 s after the panic");

        // Without a boot time the field is left out, not null.
        let state = crate::run_state::RunState::read_at(&d, 1_789_600_050_000, None);
        let events = start_events(&state, &build, false, true);
        let started = serde_json::to_value(&events[1]).expect("serialises");
        assert_eq!(started["previous_record"], "found");
        assert!(started.get("pc_restarted").is_none(), "{started}");
    }

    /// A queue a later build wrote: a kind this build does not know among known ones, fields it
    /// does not know, an event the checks refuse now, a stray value — each costs only itself; the
    /// known events stay, in order, and the rest of the file is read.
    #[test]
    fn an_unknown_kind_in_the_file_costs_only_itself() {
        let d = dir("unknown_kind");
        std::fs::write(
            d.join(FILE_NAME),
            r#"{"v":2,"next_id":9,"later":{"x":1},"events":[
                {"id":3,"sends":1,"event":{"at":1789600300000,"kind":"pc_setting_changed",
                 "key":"game_only","value":true,"later_field":7}},
                {"id":4,"sends":0,"event":{"at":1789600300500,"kind":"gpu_changed","vendor":"x"}},
                {"id":5,"sends":0,"event":{"at":1789600301000,"kind":"update_finished",
                 "from":"0.5","to":"0.6.0","outcome":"confirmed"}},
                "not an event",
                {"id":6,"sends":2,"event":{"at":1789600302000,"kind":"driver_install_finished",
                 "outcome":"failed","step":"msiexec","code":1603,"ms":41250}}
               ],"sends":[1789600301000,"x"],"dropped":1}"#,
        )
        .expect("write");
        let q = EventQueue::open(&d);
        assert_eq!(
            q.waiting(),
            [setting(1_789_600_300_000, true), driver(1_789_600_302_000)],
            "the known kinds, in order; the unknown kind, the refused event and the stray skipped"
        );
        {
            let inner = lock(&q.inner);
            assert_eq!(inner.file.sends, [1_789_600_301_000]);
            assert_eq!(inner.file.dropped, 1);
            assert_eq!(inner.file.next_id, 9);
            assert_eq!(
                inner.file.events.iter().map(|s| s.id).collect::<Vec<_>>(),
                [3, 6]
            );
        }
        // Written again by this build: what it read, and nothing it could not.
        q.claim();
        q.record(setting(1_789_600_303_000, false));
        assert_eq!(EventQueue::open(&d).pending(), 3);
    }

    /// The cap holds from the start: a file with more than it keeps the newest, the rest counted.
    #[test]
    fn the_cap_holds_on_reading() {
        let d = dir("cap_on_read");
        let events: Vec<serde_json::Value> = (0..(QUEUE_CAP as u64 + 3))
            .map(|i| {
                serde_json::json!({
                    "id": i,
                    "event": serde_json::to_value(setting(1_000 + i, true)).expect("event")
                })
            })
            .collect();
        let text = serde_json::json!({ "v": 1, "next_id": 1_000, "events": events, "dropped": 2 });
        std::fs::write(d.join(FILE_NAME), text.to_string()).expect("write");
        let q = EventQueue::open(&d);
        assert_eq!(q.pending(), QUEUE_CAP);
        let inner = lock(&q.inner);
        assert_eq!(inner.file.dropped, 5);
        assert_eq!(inner.file.events[0].event.at, 1_003, "the oldest went");
    }

    /// A broken file is an empty queue, replaced by the next write.
    #[test]
    fn a_broken_file_starts_empty() {
        let d = dir("broken");
        std::fs::write(d.join(FILE_NAME), "{ not json").expect("write");
        let q = EventQueue::open(&d);
        assert_eq!(q.pending(), 0);
        q.claim();
        q.record(setting(5, true));
        assert_eq!(EventQueue::open(&d).pending(), 1);
    }
}
