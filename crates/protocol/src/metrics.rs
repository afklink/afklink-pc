//! Contract v2 of the telemetry, the agent's side: who the
//! agent is as software and how its previous process ended (`agent_hello`), how a session's peer saw
//! its path at the end (`session_end.detail`), the agent's summary of a session
//! (`session_stats.stats.summary`) and its events outside sessions (`agent_event`).
//!
//! Mirrors the contract's `metrics.ts` (the vocabularies and bounds) and `metrics-wire.ts` (the
//! shapes). Held to it by `tests/fixtures.rs` — every golden fixture of the `agent-to-server` group
//! parses into these types and round-trips — and by `tests/metrics.rs`, which checks the hand-written
//! checks here against the emitted JSON Schema and the vocabularies against `metrics.ts`.
//!
//! **Additive only.** Every field here is optional on the wire: an older server drops the ones it
//! does not know (a plain zod object strips unknown keys), and an older agent sends none of them.
//! What the agent sends by itself is counters, codes, versions and verdicts — never an address, a
//! window title, a typed text or a log.
//!
//! A value the contract would refuse costs the whole frame (`error bad_message`) — for `agent_hello`
//! the whole handshake, again and again — so the agent checks every field before it goes out and
//! leaves out one that does not fit ([`AgentBuildInfo::check`], [`SessionEndDetail::keep_valid`],
//! [`AgentSessionSummary::check`], [`AgentEvent::check`]).
//!
//! The summary goes in every `session_stats` (phase C2, `afklink_core::summary`) and the events from
//! the agent's queue on disk (`afklink_core::agent_events`); both are checked here before they go.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::start_failure::{is_commit, is_version, BuildChannel};

/* --- bounds -------------------------------------------------------------------------------- */

/// Unix milliseconds the contract takes (`epochMsSchema`): from 1970 to the start of 2100.
pub const EPOCH_MS_MAX: u64 = 4_102_444_800_000;

/// Milliseconds within a session (`TELEMETRY_LIMITS.sessionMs`): 30 days.
pub const SESSION_MS_MAX: u64 = 2_592_000_000;

/// How long the server takes a session's reports after the session ended: its tombstone
/// (`SESSION_TOMBSTONE_MS` in the backend's `signaling/sessions.ts`). A final report
/// held while signaling was down is worth sending only within it; past it the server answers
/// `session_end unknown_session` and stores nothing.
pub const SESSION_TOMBSTONE_MS: u64 = 60_000;

/// The agent's first report on a session comes this soon after it starts, then every `TELEMETRY_INTERVAL_MS`: a session that dies in its first quarter minute —
/// most failed ones — still leaves a report.
pub const TELEMETRY_FIRST_REPORT_MS: u64 = 5_000;

/// Episodes in one summary (`TELEMETRY_LIMITS.episodes`); past it the agent counts the rest in
/// `episodes_dropped`.
pub const SUMMARY_EPISODES_MAX: usize = 100;

/// Rungs in `summary.rung_s` (`TELEMETRY_LIMITS.rungs`).
pub const SUMMARY_RUNGS_MAX: usize = 16;

/// Seconds a summary counts (`TELEMETRY_LIMITS.sessionSeconds`): 30 days.
pub const SESSION_SECONDS_MAX: f64 = 2_592_000.0;

/// The largest `encode_ms_p95` the contract takes, ms.
pub const ENCODE_MS_P95_MAX: f64 = 60_000.0;

/// Seconds a process may have run (`TELEMETRY_LIMITS.uptimeSeconds`, `agent_crashed.uptime_s`): a
/// year.
pub const UPTIME_SECONDS_MAX: u64 = 31_536_000;

/// The longest short id (`SHORT_ID_PATTERN`): an episode's `code`, a step, a reason.
pub const SHORT_ID_MAX: usize = 32;

/// `driver_install_finished.code`: `msiexec`'s exit code or an HRESULT, from `i32::MIN` to
/// `u32::MAX` (the contract's bounds).
pub const DRIVER_CODE_MIN: i64 = -2_147_483_648;
/// See [`DRIVER_CODE_MIN`].
pub const DRIVER_CODE_MAX: i64 = 4_294_967_295;

/// A short id (`SHORT_ID_PATTERN`): `^[a-z0-9_]{1,32}$` — never a sentence, a path or a name.
pub fn is_short_id(s: &str) -> bool {
    (1..=SHORT_ID_MAX).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// One of the agent's own words as a short id: lowercased, `-`, `:`, `.` and spaces turned into `_`
/// (`no-feedback` → `no_feedback`, `startup-thin` → `startup_thin`). `None` when what is left is not
/// a short id (empty, too long, another character): the field is then left out, never sent wrong.
pub fn short_id(word: &str) -> Option<String> {
    let id: String = word
        .chars()
        .map(|c| match c {
            '-' | ':' | '.' | ' ' => '_',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    is_short_id(&id).then_some(id)
}

/// A panic's place, hashed (`PLACE_HASH_PATTERN`): 8 to 64 lowercase hex digits.
pub fn is_place_hash(s: &str) -> bool {
    (8..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A thread's name (`THREAD_NAME_PATTERN`): 1 to 32 of `A-Z a-z 0-9 _ . : -`.
pub fn is_thread_name(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// A key of `summary.rung_s` (`RUNG_KEY_PATTERN`): a rung's encoded height, 2 to 5 digits.
pub fn is_rung_key(s: &str) -> bool {
    (2..=5).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/* --- builds -------------------------------------------------------------------------------- */

/// A field the contract would refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidField {
    /// The field's wire name.
    pub field: &'static str,
}

impl fmt::Display for InvalidField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not the contract's shape", self.field)
    }
}

impl std::error::Error for InvalidField {}

/// The agent's build (`agent_hello.build`, `agentBuildInfoSchema`): what
/// `afklink_core::build_info::BuildInfo` stamps, without the label and the time. The server stores
/// it on every session this PC serves (`sessions.agent_build`); without it it knows the PC's version
/// only from its last `User-Agent`, without the commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBuildInfo {
    /// `CARGO_PKG_VERSION`: `0.5.0`, or `0.6.0-beta.1` ([`is_version`]).
    pub version: String,
    /// The stamped commit, 7 to 40 lowercase hex digits ([`is_commit`]); absent for an unstamped
    /// build (the contract also takes `null`, which this agent never sends).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub channel: BuildChannel,
    /// Built from a tree with uncommitted changes; absent when the build did not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
}

impl AgentBuildInfo {
    /// Every field against the contract's rules; the first that fails is named.
    pub fn check(&self) -> Result<(), InvalidField> {
        if !is_version(&self.version) {
            return Err(InvalidField {
                field: "build.version",
            });
        }
        if !self.commit.as_deref().is_none_or(is_commit) {
            return Err(InvalidField {
                field: "build.commit",
            });
        }
        Ok(())
    }
}

/// How the agent's previous process ended (`AGENT_EXIT_KINDS`), as the next one finds it on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentExitKind {
    /// The owner closed the app (the tray's «Выход»), or the CLI was stopped.
    AppExit,
    /// It restarted itself to install an update.
    UpdateExit,
    /// A Rust panic: it was recorded before the process went.
    Panic,
    /// It died without a word (killed, a native fault): it said it was running and recorded no exit.
    Crash,
    /// Windows shut down, restarted or logged the user off.
    OsShutdown,
    /// Nothing to go by: no record (a first run, or a build that kept none) or one unreadable.
    Unknown,
}

impl AgentExitKind {
    /// Every kind, in the contract's order.
    pub const ALL: [Self; 6] = [
        Self::AppExit,
        Self::UpdateExit,
        Self::Panic,
        Self::Crash,
        Self::OsShutdown,
        Self::Unknown,
    ];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppExit => "app_exit",
            Self::UpdateExit => "update_exit",
            Self::Panic => "panic",
            Self::Crash => "crash",
            Self::OsShutdown => "os_shutdown",
            Self::Unknown => "unknown",
        }
    }

    /// The previous process died (`AGENT_CRASH_EXITS`): what lets the server tell the sessions it
    /// left behind ended by a crash, not by the network.
    pub const fn is_crash(self) -> bool {
        matches!(self, Self::Panic | Self::Crash)
    }
}

impl fmt::Display for AgentExitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `agent_hello.last_exit` (`agentLastExitSchema`): how the previous process ended, and when on this
/// PC's clock. `at` matters for `panic`/`crash`: without it the server cannot tell which already
/// closed sessions that process left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLastExit {
    pub kind: AgentExitKind,
    /// Unix ms, at most [`EPOCH_MS_MAX`]; absent when not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<u64>,
}

/* --- how an end saw its peer (`session_end.detail`) ---------------------------------------- */

/// Longest code in `session_end.detail` (`END_DETAIL_CODE_PATTERN`).
pub const END_DETAIL_CODE_MAX: usize = 32;

/// A code in `session_end.detail`: `^[a-z0-9_:]{1,32}$` (`END_DETAIL_CODE_PATTERN`). The server holds
/// each to its own list and drops one it does not know; the shape is what the frame needs to parse.
pub fn is_end_detail_code(s: &str) -> bool {
    (1..=END_DETAIL_CODE_MAX).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b':')
}

/// `ended_detail` for the reason `peer_closed` (`SESSION_END_DETAILS.peer_closed`).
pub mod ended_detail {
    /// The viewer said goodbye on the data channel (its DTLS `close_notify` or SCTP abort).
    pub const VIEWER: &str = "viewer";
    /// str0m closed the peer by itself: ICE, DTLS, SDP — no goodbye from the viewer.
    pub const RTC: &str = "rtc";
    /// Both, in the contract's order.
    pub const PEER_CLOSED: [&str; 2] = [VIEWER, RTC];
}

/// How far the end's peer got when the session ended (`PEER_STAGES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStage {
    /// Nothing yet: no candidate pair was checked.
    #[default]
    New,
    /// ICE checking, never connected.
    Ice,
    /// ICE connected, DTLS not (the stall of «Установка застряла»).
    Dtls,
    /// DTLS done: the media path was up.
    Connected,
}

impl PeerStage {
    /// Every stage, in the contract's order.
    pub const ALL: [Self; 4] = [Self::New, Self::Ice, Self::Dtls, Self::Connected];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Ice => "ice",
            Self::Dtls => "dtls",
            Self::Connected => "connected",
        }
    }
}

impl fmt::Display for PeerStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The agent's DTLS verdicts (`DTLS_VERDICTS`): `Verdict::as_str` in
/// `afklink_transport`'s `paths.rs`, word for word (held to it by a test there).
pub const DTLS_VERDICTS: [&str; 8] = [
    "nothing_from_viewer",
    "no_reply_sent",
    "viewer_resends_hello",
    "viewer_silent_after_hello",
    "second_flight_stuck",
    "nominated_path_silent",
    "no_hello_sent",
    "unclear",
];

/// A selected pair's candidate types (`CANDIDATE_KINDS`).
pub const CANDIDATE_KINDS: [&str; 4] = ["host", "srflx", "prflx", "relay"];

/// How the viewer reaches its TURN relay (`RELAY_TRANSPORTS`).
pub const RELAY_TRANSPORTS: [&str; 3] = ["udp", "tcp", "tls"];

/// `session_end.detail` (`sessionEndDetailSchema`): the reason split (`ended_detail`) and how the
/// peer saw the media path — how far it got, the DTLS verdict, how long DTLS took after ICE, the
/// selected pair's candidate types and the relay's transport. Kinds and verdicts only: no address,
/// no candidate. Every field optional; an empty detail is not sent at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEndDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// Milliseconds from ICE `connected` to DTLS done, at most [`SESSION_MS_MAX`]; absent when DTLS
    /// never came.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtls_after_ice_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_local_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair_remote_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_transport: Option<String>,
}

impl SessionEndDetail {
    /// Nothing in it: sent as no `detail` at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The detail with every field the contract would refuse left out, and the names of those left
    /// out (for the log): a code not of the wire's shape, a duration past [`SESSION_MS_MAX`]. One bad
    /// field must cost that field, not the whole `session_end`.
    pub fn keep_valid(mut self) -> (Self, Vec<&'static str>) {
        let mut dropped = Vec::new();
        for (name, slot) in [
            ("ended_detail", &mut self.ended_detail),
            ("stage", &mut self.stage),
            ("verdict", &mut self.verdict),
            ("pair_local_kind", &mut self.pair_local_kind),
            ("pair_remote_kind", &mut self.pair_remote_kind),
            ("relay_transport", &mut self.relay_transport),
        ] {
            if slot.as_deref().is_some_and(|c| !is_end_detail_code(c)) {
                *slot = None;
                dropped.push(name);
            }
        }
        if self.dtls_after_ice_ms.is_some_and(|ms| ms > SESSION_MS_MAX) {
            self.dtls_after_ice_ms = None;
            dropped.push("dtls_after_ice_ms");
        }
        (self, dropped)
    }
}

/* --- the agent's summary of a session ------------------------------------------------------ */

/// What happened during a session (`SESSION_EPISODE_KINDS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEpisodeKind {
    Freeze,
    Brake,
    Drain,
    PathChange,
    IceRestart,
    CaptureRestart,
    RungChange,
}

impl SessionEpisodeKind {
    /// Every kind, in the contract's order.
    pub const ALL: [Self; 7] = [
        Self::Freeze,
        Self::Brake,
        Self::Drain,
        Self::PathChange,
        Self::IceRestart,
        Self::CaptureRestart,
        Self::RungChange,
    ];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Freeze => "freeze",
            Self::Brake => "brake",
            Self::Drain => "drain",
            Self::PathChange => "path_change",
            Self::IceRestart => "ice_restart",
            Self::CaptureRestart => "capture_restart",
            Self::RungChange => "rung_change",
        }
    }
}

/// One episode (`sessionEpisodeSchema`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEpisode {
    pub kind: SessionEpisodeKind,
    /// When it began, ms since the session's pipeline started.
    pub at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<u64>,
    /// Why, as a short id (`SHORT_ID_PATTERN`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Input applied, by kind (`inputCountsSchema`): counts only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputCounts {
    pub abs: u64,
    pub rel: u64,
    pub buttons: u64,
    pub keys: u64,
    pub text: u64,
}

/// How input was applied (`INPUT_PATHS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputPath {
    Sendinput,
    Hid,
}

impl InputPath {
    /// Every path, in the contract's order.
    pub const ALL: [Self; 2] = [Self::Sendinput, Self::Hid];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sendinput => "sendinput",
            Self::Hid => "hid",
        }
    }
}

/// What the PC captured (`CAPTURE_MODES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    Screen,
    GameOnly,
}

impl CaptureMode {
    /// Every mode, in the contract's order.
    pub const ALL: [Self; 2] = [Self::Screen, Self::GameOnly];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Screen => "screen",
            Self::GameOnly => "game_only",
        }
    }
}

/// The input driver on the PC (`DRIVER_STATES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverState {
    Installed,
    Absent,
    Unknown,
}

impl DriverState {
    /// Every state, in the contract's order.
    pub const ALL: [Self; 3] = [Self::Installed, Self::Absent, Self::Unknown];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

/// The agent's summary of a session (`agentSessionSummarySchema`), cumulative like the rest of the
/// report; every field optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionSummary {
    /// Seconds on each rung, keyed by its encoded height (`"1080"`), at most 16 rungs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rung_s: Option<BTreeMap<String, f64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freeze_s: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episodes: Option<Vec<SessionEpisode>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub episodes_dropped: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encode_ms_p95: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<InputCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_path: Option<InputPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_blocked_n: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_mode: Option<CaptureMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub driver: Option<DriverState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped_rate: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_socket: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_relay: Option<u64>,
    /// The quality profile the session ran on, `"<id>.v<v>"`; at most 48 characters on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_profile: Option<String>,
    /// Where that profile came from (`QUALITY_PROFILE_SOURCES`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_profile_source: Option<QualityProfileSource>,
}

/// Where a session's quality profile came from (`QUALITY_PROFILE_SOURCES`): the server's
/// `quality_profile`, or the agent's compiled one — because the server sent none, or what it sent
/// did not validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityProfileSource {
    Server,
    Fallback,
}

impl QualityProfileSource {
    /// Every source, in the contract's order.
    pub const ALL: [Self; 2] = [Self::Server, Self::Fallback];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Fallback => "fallback",
        }
    }
}

/// The longest `quality_profile` label the summary takes.
pub const QUALITY_PROFILE_LABEL_MAX: usize = 48;

/// The largest counter the contract takes (`Number.MAX_SAFE_INTEGER`).
pub const COUNT_MAX: u64 = 9_007_199_254_740_991;

impl AgentSessionSummary {
    /// Every field against the contract's bounds (`agentSessionSummarySchema`); the first that fails
    /// is named. The agent builds the summary to fit (`afklink_core::summary`), so a failure here is
    /// a defect — the report then goes without its summary rather than not at all.
    pub fn check(&self) -> Result<(), InvalidField> {
        let seconds = |v: f64| v.is_finite() && (0.0..=SESSION_SECONDS_MAX).contains(&v);
        let err = |field| Err(InvalidField { field });
        if let Some(rungs) = &self.rung_s {
            if rungs.len() > SUMMARY_RUNGS_MAX {
                return err("summary.rung_s");
            }
            if rungs.iter().any(|(k, v)| !is_rung_key(k) || !seconds(*v)) {
                return err("summary.rung_s");
            }
        }
        if self.freeze_s.is_some_and(|v| !seconds(v)) {
            return err("summary.freeze_s");
        }
        if let Some(episodes) = &self.episodes {
            if episodes.len() > SUMMARY_EPISODES_MAX {
                return err("summary.episodes");
            }
            for e in episodes {
                if e.at_ms > SESSION_MS_MAX || e.dur_ms.is_some_and(|d| d > SESSION_MS_MAX) {
                    return err("summary.episodes.at_ms");
                }
                if e.code.as_deref().is_some_and(|c| !is_short_id(c)) {
                    return err("summary.episodes.code");
                }
            }
        }
        if self
            .encode_ms_p95
            .is_some_and(|v| !(v.is_finite() && (0.0..=ENCODE_MS_P95_MAX).contains(&v)))
        {
            return err("summary.encode_ms_p95");
        }
        let counts = [
            self.episodes_dropped,
            self.input_blocked_n,
            self.dropped_rate,
            self.bytes_socket,
            self.bytes_relay,
        ];
        if counts.iter().flatten().any(|&n| n > COUNT_MAX) {
            return err("summary.count");
        }
        if let Some(i) = self.input {
            if [i.abs, i.rel, i.buttons, i.keys, i.text]
                .iter()
                .any(|&n| n > COUNT_MAX)
            {
                return err("summary.input");
            }
        }
        if self
            .quality_profile
            .as_deref()
            .is_some_and(|l| l.chars().count() > QUALITY_PROFILE_LABEL_MAX)
        {
            return err("summary.quality_profile");
        }
        Ok(())
    }
}

/* --- the agent's events -------------------------------------------------------------------- */

/// `agent_event` (`AGENT_EVENT_KINDS`): something that happened on the PC outside any session, `at`
/// on the PC's clock, the kind's props flat beside it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    /// Unix ms on the PC's clock.
    pub at: u64,
    #[serde(flatten)]
    pub event: AgentEventKind,
}

/// An agent event's kind and props (`AGENT_EVENT_PROPS`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentEventKind {
    AgentStarted {
        boot_id: String,
        first_run: bool,
        build: AgentBuildInfo,
        last_exit: AgentLastExit,
        autostart: bool,
        /// What this start found of the previous process's record. Absent from builds before it
        /// (and from a queue they wrote).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous_record: Option<PreviousRecord>,
        /// Whether the previous process went down with the PC: Windows booted within three minutes
        /// of its last sign of life (`true`), or was running before it ran (`false`). Absent when
        /// that cannot be told, a boot later than those three minutes included.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pc_restarted: Option<bool>,
    },
    AgentCrashed {
        version: String,
        place_hash: String,
        thread: String,
        uptime_s: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boot_id: Option<String>,
    },
    UpdateFinished {
        from: String,
        to: String,
        outcome: UpdateOutcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    DriverInstallFinished {
        outcome: DriverInstallOutcome,
        step: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i64>,
        ms: u64,
    },
    PcSettingChanged {
        key: PcSettingKey,
        value: PcSettingValue,
    },
}

impl AgentEventKind {
    /// Every kind's wire word, in the contract's order (`AGENT_EVENT_KINDS`).
    pub const KINDS: [&'static str; 5] = [
        "agent_started",
        "agent_crashed",
        "update_finished",
        "driver_install_finished",
        "pc_setting_changed",
    ];

    /// This event's wire word (`kind`).
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::AgentStarted { .. } => "agent_started",
            Self::AgentCrashed { .. } => "agent_crashed",
            Self::UpdateFinished { .. } => "update_finished",
            Self::DriverInstallFinished { .. } => "driver_install_finished",
            Self::PcSettingChanged { .. } => "pc_setting_changed",
        }
    }
}

impl AgentEvent {
    /// Every field against the contract's rules (`AGENT_EVENT_PROPS`); the first that fails is
    /// named. A kind or a prop off the contract makes the whole frame `bad_message`, so an event
    /// that fails here is never queued (`afklink_core::agent_events`).
    pub fn check(&self) -> Result<(), InvalidField> {
        let err = |field| Err(InvalidField { field });
        if self.at > EPOCH_MS_MAX {
            return err("at");
        }
        match &self.event {
            AgentEventKind::AgentStarted {
                boot_id,
                build,
                last_exit,
                ..
            } => {
                if !crate::diagnostics::is_uuid(boot_id) {
                    return err("boot_id");
                }
                build.check()?;
                if last_exit.at.is_some_and(|at| at > EPOCH_MS_MAX) {
                    return err("last_exit.at");
                }
            }
            AgentEventKind::AgentCrashed {
                version,
                place_hash,
                thread,
                uptime_s,
                boot_id,
            } => {
                if !is_version(version) {
                    return err("version");
                }
                if !is_place_hash(place_hash) {
                    return err("place_hash");
                }
                if !is_thread_name(thread) {
                    return err("thread");
                }
                if *uptime_s > UPTIME_SECONDS_MAX {
                    return err("uptime_s");
                }
                if boot_id
                    .as_deref()
                    .is_some_and(|b| !crate::diagnostics::is_uuid(b))
                {
                    return err("boot_id");
                }
            }
            AgentEventKind::UpdateFinished {
                from, to, reason, ..
            } => {
                if !is_version(from) {
                    return err("from");
                }
                if !is_version(to) {
                    return err("to");
                }
                if reason.as_deref().is_some_and(|r| !is_short_id(r)) {
                    return err("reason");
                }
            }
            AgentEventKind::DriverInstallFinished { step, code, ms, .. } => {
                if !is_short_id(step) {
                    return err("step");
                }
                if code.is_some_and(|c| !(DRIVER_CODE_MIN..=DRIVER_CODE_MAX).contains(&c)) {
                    return err("code");
                }
                if *ms > SESSION_MS_MAX {
                    return err("ms");
                }
            }
            AgentEventKind::PcSettingChanged { value, .. } => {
                if let PcSettingValue::Id(id) = value {
                    if !is_short_id(id) {
                        return err("value");
                    }
                }
            }
        }
        Ok(())
    }
}

/// What a start found of the previous process's run state record (`PREVIOUS_RECORD_STATES`,
/// `agent_started.previous_record`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviousRecord {
    /// A record: `last_exit` is what it says.
    Found,
    /// No file: a first run, or a build that kept none.
    Missing,
    /// A torn file (empty, zeros, cut short), or one that could not be read or is not a record this
    /// build reads.
    Unreadable,
}

impl PreviousRecord {
    /// Every state, in the contract's order.
    pub const ALL: [Self; 3] = [Self::Found, Self::Missing, Self::Unreadable];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::Missing => "missing",
            Self::Unreadable => "unreadable",
        }
    }
}

/// How an update ended (`UPDATE_OUTCOMES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateOutcome {
    Confirmed,
    RolledBack,
}

impl UpdateOutcome {
    /// Every outcome, in the contract's order.
    pub const ALL: [Self; 2] = [Self::Confirmed, Self::RolledBack];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// How the driver's installer ended (`DRIVER_INSTALL_OUTCOMES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverInstallOutcome {
    Ok,
    Failed,
    Cancelled,
}

impl DriverInstallOutcome {
    /// Every outcome, in the contract's order.
    pub const ALL: [Self; 3] = [Self::Ok, Self::Failed, Self::Cancelled];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The settings whose changes are counted (`PC_SETTING_KEYS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcSettingKey {
    GameOnly,
    GameOnlyForGuests,
    GameHelper,
    Autostart,
    AutoUpdate,
    LogLevel,
}

impl PcSettingKey {
    /// Every key, in the contract's order.
    pub const ALL: [Self; 6] = [
        Self::GameOnly,
        Self::GameOnlyForGuests,
        Self::GameHelper,
        Self::Autostart,
        Self::AutoUpdate,
        Self::LogLevel,
    ];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GameOnly => "game_only",
            Self::GameOnlyForGuests => "game_only_for_guests",
            Self::GameHelper => "game_helper",
            Self::Autostart => "autostart",
            Self::AutoUpdate => "auto_update",
            Self::LogLevel => "log_level",
        }
    }
}

/// A setting's new value: a switch's state, or a short id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PcSettingValue {
    Flag(bool),
    Id(String),
}

impl fmt::Display for PcSettingValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flag(b) => write!(f, "{b}"),
            Self::Id(id) => f.write_str(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_kinds_have_their_wire_words() {
        for kind in AgentExitKind::ALL {
            let v = serde_json::to_value(kind).expect("serialises");
            assert_eq!(v, kind.as_str());
            assert_eq!(
                serde_json::from_value::<AgentExitKind>(v).expect("parses"),
                kind
            );
        }
        assert!(AgentExitKind::Panic.is_crash() && AgentExitKind::Crash.is_crash());
        assert!(!AgentExitKind::AppExit.is_crash() && !AgentExitKind::Unknown.is_crash());
        assert!(serde_json::from_str::<AgentExitKind>(r#""killed""#).is_err());
    }

    /// `at` is absent, not null, when not known.
    #[test]
    fn a_last_exit_without_a_time_has_no_at_key() {
        let v = serde_json::to_value(AgentLastExit {
            kind: AgentExitKind::Unknown,
            at: None,
        })
        .expect("serialises");
        assert_eq!(v, serde_json::json!({ "kind": "unknown" }));
    }

    #[test]
    fn a_build_is_checked_field_by_field() {
        let good = AgentBuildInfo {
            version: "0.5.1".into(),
            commit: Some("1d38642".into()),
            channel: BuildChannel::Dev,
            dirty: Some(true),
        };
        assert_eq!(good.check(), Ok(()));
        let unstamped = AgentBuildInfo {
            commit: None,
            dirty: None,
            ..good.clone()
        };
        assert_eq!(unstamped.check(), Ok(()));
        let v = serde_json::to_value(&unstamped).expect("serialises");
        assert_eq!(
            v,
            serde_json::json!({ "version": "0.5.1", "channel": "dev" }),
            "absent, not null"
        );
        let bad_version = AgentBuildInfo {
            version: "0.5".into(),
            ..good.clone()
        };
        assert_eq!(
            bad_version.check().map_err(|e| e.field),
            Err("build.version")
        );
        let bad_commit = AgentBuildInfo {
            commit: Some("1D38642".into()),
            ..good
        };
        assert_eq!(bad_commit.check().map_err(|e| e.field), Err("build.commit"));
    }

    #[test]
    fn end_detail_codes_are_short_lowercase_ids() {
        let longest = "x".repeat(END_DETAIL_CODE_MAX);
        let too_long = "x".repeat(END_DETAIL_CODE_MAX + 1);
        for ok in [
            "rtc",
            "nothing_from_viewer",
            "goodbye:quit",
            "a",
            longest.as_str(),
        ] {
            assert!(is_end_detail_code(ok), "{ok}");
        }
        for bad in [
            "",
            "RTC",
            "relay/tcp",
            "with space",
            too_long.as_str(),
            "10.0.0.1",
        ] {
            assert!(!is_end_detail_code(bad), "{bad}");
        }
        for word in DTLS_VERDICTS
            .iter()
            .chain(&CANDIDATE_KINDS)
            .chain(&RELAY_TRANSPORTS)
            .chain(&ended_detail::PEER_CLOSED)
        {
            assert!(is_end_detail_code(word), "{word}");
        }
        for stage in PeerStage::ALL {
            assert!(is_end_detail_code(stage.as_str()), "{stage}");
        }
    }

    /// The agent's own words become short ids; what cannot be one is refused, never sent wrong.
    #[test]
    fn short_ids_are_made_from_the_agents_words() {
        assert_eq!(short_id("no-feedback").as_deref(), Some("no_feedback"));
        assert_eq!(short_id("startup-thin").as_deref(), Some("startup_thin"));
        assert_eq!(short_id("capture_lost").as_deref(), Some("capture_lost"));
        assert_eq!(short_id("Relay").as_deref(), Some("relay"));
        assert_eq!(short_id(""), None);
        assert_eq!(short_id("capture lost?"), None);
        assert_eq!(short_id(&"x".repeat(SHORT_ID_MAX + 1)), None);
        assert!(is_short_id("a") && !is_short_id("a-b") && !is_short_id("A"));
        assert!(
            is_place_hash("9f86d081884c7d65")
                && !is_place_hash("9F86D081")
                && !is_place_hash("abc")
        );
        assert!(
            is_thread_name("tokio-runtime-worker") && !is_thread_name("a b") && !is_thread_name("")
        );
        assert!(
            is_rung_key("1080") && is_rung_key("72") && !is_rung_key("7") && !is_rung_key("1080p")
        );
    }

    /// The summary's checks: the shape the agent builds passes; each bound the contract keeps fails.
    #[test]
    fn a_summary_is_checked_against_the_contracts_bounds() {
        let good = AgentSessionSummary {
            rung_s: Some([("1080".to_string(), 31.5)].into_iter().collect()),
            freeze_s: Some(2.0),
            episodes: Some(vec![SessionEpisode {
                kind: SessionEpisodeKind::Brake,
                at_ms: 30_200,
                dur_ms: Some(1_800),
                code: Some("loss".into()),
            }]),
            episodes_dropped: Some(0),
            encode_ms_p95: Some(14.2),
            quality_profile: Some("default.v1".into()),
            quality_profile_source: Some(QualityProfileSource::Server),
            ..AgentSessionSummary::default()
        };
        assert_eq!(good.check(), Ok(()));
        let field = |s: AgentSessionSummary| s.check().map_err(|e| e.field);
        assert_eq!(
            field(AgentSessionSummary {
                quality_profile: Some("a".repeat(QUALITY_PROFILE_LABEL_MAX + 1)),
                ..good.clone()
            }),
            Err("summary.quality_profile")
        );
        assert_eq!(
            field(AgentSessionSummary {
                rung_s: Some([("1080p".to_string(), 1.0)].into_iter().collect()),
                ..good.clone()
            }),
            Err("summary.rung_s")
        );
        assert_eq!(
            field(AgentSessionSummary {
                freeze_s: Some(f64::NAN),
                ..good.clone()
            }),
            Err("summary.freeze_s")
        );
        assert_eq!(
            field(AgentSessionSummary {
                episodes: Some(vec![SessionEpisode {
                    kind: SessionEpisodeKind::RungChange,
                    at_ms: 1,
                    dur_ms: None,
                    code: Some("startup-thin".into()),
                }]),
                ..good.clone()
            }),
            Err("summary.episodes.code")
        );
        assert_eq!(
            field(AgentSessionSummary {
                encode_ms_p95: Some(60_001.0),
                ..good
            }),
            Err("summary.encode_ms_p95")
        );
    }

    /// The events' checks name the field the contract would refuse.
    #[test]
    fn an_event_is_checked_field_by_field() {
        let crashed = |thread: &str, hash: &str| AgentEvent {
            at: 1_789_599_960_000,
            event: AgentEventKind::AgentCrashed {
                version: "0.6.0".into(),
                place_hash: hash.into(),
                thread: thread.into(),
                uptime_s: 5_400,
                boot_id: None,
            },
        };
        assert_eq!(crashed("main", "9f86d081884c7d65").check(), Ok(()));
        assert_eq!(
            crashed("main thread", "9f86d081884c7d65")
                .check()
                .map_err(|e| e.field),
            Err("thread")
        );
        assert_eq!(
            crashed("main", "src/agent.rs:12")
                .check()
                .map_err(|e| e.field),
            Err("place_hash")
        );
        let late = AgentEvent {
            at: EPOCH_MS_MAX + 1,
            ..crashed("main", "9f86d081884c7d65")
        };
        assert_eq!(late.check().map_err(|e| e.field), Err("at"));
        let driver = AgentEvent {
            at: 1,
            event: AgentEventKind::DriverInstallFinished {
                outcome: DriverInstallOutcome::Failed,
                step: "msiexec".into(),
                code: Some(DRIVER_CODE_MAX + 1),
                ms: 10,
            },
        };
        assert_eq!(driver.check().map_err(|e| e.field), Err("code"));
        assert_eq!(driver.event.kind(), "driver_install_finished");
    }

    /// One field the contract would refuse costs that field: the rest of the detail goes.
    #[test]
    fn an_invalid_detail_field_is_left_out_alone() {
        let detail = SessionEndDetail {
            ended_detail: Some("rtc".into()),
            stage: Some("dtls".into()),
            verdict: Some("Nothing From Viewer".into()),
            dtls_after_ice_ms: Some(SESSION_MS_MAX + 1),
            pair_local_kind: Some("host".into()),
            pair_remote_kind: Some("relay".into()),
            relay_transport: Some("tls".into()),
        };
        let (kept, dropped) = detail.keep_valid();
        assert_eq!(dropped, ["verdict", "dtls_after_ice_ms"]);
        assert_eq!(kept.verdict, None);
        assert_eq!(kept.dtls_after_ice_ms, None);
        assert_eq!(kept.stage.as_deref(), Some("dtls"));
        assert_eq!(kept.relay_transport.as_deref(), Some("tls"));
        assert!(!kept.is_empty());
        assert!(SessionEndDetail::default().is_empty());
        assert_eq!(
            serde_json::to_value(SessionEndDetail::default()).expect("serialises"),
            serde_json::json!({})
        );
    }
}
