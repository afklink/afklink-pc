//! The agent's summary of a session: `session_stats.stats.summary`. Cumulative, like the rest of
//! the report: every report carries the whole session so far, the final one the whole session.
//!
//! Every field comes from a value one of the session's existing log lines prints, at the place it
//! prints it, so the summary and the log cannot disagree. The field-by-field sources are on
//! [`SessionSummary`]; what counts as a motion second is on [`SecondKind`], and a freeze on
//! [`FREEZE_EPISODE_MIN`].
//!
//! # The hot path
//!
//! Two things are counted per frame or per message, one atomic add each: the encode time's bucket
//! ([`EncodeHistogram`], in the encode loop beside `encode_us_total`) and the input's kind
//! ([`InputTotals`], in the event task beside the `input` line's tally). Everything else is the
//! control task's (its 200 ms tick for episodes, its once-a-second `pipeline` line for rung time
//! and freeze) and the heartbeat's, once a second (the driver, blocked input). Nothing here logs
//! per frame or per tick at debug: a freeze's start and end, each episode, the cap, and each kind
//! of second the first time are logged once each, and a tally of the seconds' kinds once a minute.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_protocol::metrics::{
    self as m, AgentSessionSummary, CaptureMode, DriverState, InputCounts, InputPath,
    SessionEpisode, SessionEpisodeKind,
};
use afklink_protocol::InputMessage;
use afklink_transport::SocketBytes;

use crate::sync::lock;
use crate::traits::{DriverPresence, InputReach};

/// Frames a second the PC must send for the second to count as motion.
pub const MOTION_FRAMES: u64 = 5;

/// The shortest run of freeze seconds that is a `freeze` episode.
///
/// A freeze second is a motion second in which the viewer presented nothing, by its own `vv`
/// report. Not one: any second that is not motion, a second the viewer did not report (unknown, so
/// neither a freeze nor its end; it still counts on its rung), and the seconds before its first
/// presented frame (that is the time to the first picture, not a freeze). A run of freeze seconds
/// of [`FREEZE_EPISODE_MIN`] or more is a `freeze` episode, dated from the run's first second.
pub const FREEZE_EPISODE_MIN: Duration = Duration::from_secs(2);

/// The most one `pipeline` second counts ([`SecondClock`]): twice its nominal length. A line a
/// starved runtime wrote late counts the time its counters covered, up to this; a longer gap is a
/// stall of the whole process (or the PC asleep), whose length says nothing of the picture.
pub const SECOND_COUNTED_MAX: Duration = Duration::from_secs(2);

/// How often at most the clamp of [`SECOND_COUNTED_MAX`] is said again after the first time.
const CLAMP_LOG_EVERY: Duration = Duration::from_secs(30);

/// How many `pipeline` seconds the debug tally of their kinds covers ([`SecondKind`]).
const KIND_TALLY_EVERY: u32 = 60;

/// The `pipeline` line's clock for the summary: each line's second counts the time since the line
/// before, measured — what the line's counters actually covered, not its nominal second (five 200
/// ms ticks), which a runtime starved of CPU stretches — at most [`SECOND_COUNTED_MAX`]. The same
/// time goes to the rung (`rung_s`) and to the freeze rule (`freeze_s`), so the two count motion
/// seconds alike. When the cap bites it is said at debug: the first time in the session, then at
/// most every [`CLAMP_LOG_EVERY`] with what was cut since, and what is left at [`Self::finish`].
///
/// Only the summary's: the line's own rates keep their nominal second, and the quality controller
/// its fixed `dt` (a stall must not count as evidence watched).
#[derive(Debug)]
pub struct SecondClock {
    last: Instant,
    /// Clamped seconds, and the time cut off them, since the last line about them.
    clamped: u32,
    cut_ms: u64,
    logged_at: Option<Instant>,
}

impl SecondClock {
    /// Seconds counted from `start` on.
    pub fn new(start: Instant) -> Self {
        Self {
            last: start,
            clamped: 0,
            cut_ms: 0,
            logged_at: None,
        }
    }

    /// The `pipeline` line at `now`: the time its second counts.
    pub fn step(&mut self, now: Instant, session: &str) -> Duration {
        let elapsed = now.saturating_duration_since(self.last);
        self.last = now;
        if elapsed <= SECOND_COUNTED_MAX {
            return elapsed;
        }
        let cut = elapsed.saturating_sub(SECOND_COUNTED_MAX);
        self.clamped = self.clamped.saturating_add(1);
        self.cut_ms = self
            .cut_ms
            .saturating_add(u64::try_from(cut.as_millis()).unwrap_or(u64::MAX));
        let due = self
            .logged_at
            .is_none_or(|at| now.saturating_duration_since(at) >= CLAMP_LOG_EVERY);
        if due {
            self.say(session, elapsed, "a pipeline line came late");
            self.logged_at = Some(now);
        }
        SECOND_COUNTED_MAX
    }

    /// The session ends: what was cut since the last line, if anything.
    pub fn finish(&mut self, session: &str) {
        if self.clamped > 0 {
            self.say(session, Duration::ZERO, "the session ends");
        }
    }

    fn say(&mut self, session: &str, last_gap: Duration, why: &'static str) {
        tracing::debug!(
            session,
            clamped = self.clamped,
            cut_ms = self.cut_ms,
            last_gap_ms = last_gap.as_millis() as u64,
            max_ms = SECOND_COUNTED_MAX.as_millis() as u64,
            why,
            "summary: pipeline lines further apart than the most one second counts (a stalled \
             process): each counts at most that, for the rung time and the freeze rule alike"
        );
        self.clamped = 0;
        self.cut_ms = 0;
    }
}

/// What a `pipeline` second is to the summary: the one test `rung_s` and the freeze rule share.
///
/// A motion second is a `pipeline` second in which the PC sent ≥ [`MOTION_FRAMES`] frames (encoded,
/// less discarded) to a viewer whose page is visible and not held in the background. Only these
/// count: `rung_s` is their time on each rung (the rung in force at the line), so `sum(rung_s)` is
/// the motion seconds, the denominator of «Заморозки» (`freeze_s`) and of «Качество картинки» (the
/// share on the top rung). A still screen, a hidden page and a background hold count nowhere. Each
/// second counts the time its counters covered, measured since the line before, at most
/// [`SECOND_COUNTED_MAX`] ([`SecondClock`]), for the rung and the freeze rule alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondKind {
    /// The PC sent ≥ [`MOTION_FRAMES`] frames, the viewer's page visible and not held: counted on
    /// the rung in force, and judged by the freeze rule.
    Motion,
    /// Fewer frames: a still screen. Not counted.
    Still,
    /// The viewer's page is hidden (the background hold's grace): nobody sees the picture. Not
    /// counted.
    Hidden,
    /// A background hold is in force: no video on purpose. Not counted.
    Held,
}

impl SecondKind {
    /// The kind of `sec`.
    pub fn of(sec: &Second) -> Self {
        if sec.held {
            Self::Held
        } else if sec.page_hidden {
            Self::Hidden
        } else if sec.sent_frames >= MOTION_FRAMES {
            Self::Motion
        } else {
            Self::Still
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Motion => 0,
            Self::Still => 1,
            Self::Hidden => 2,
            Self::Held => 3,
        }
    }

    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Motion => "motion",
            Self::Still => "still",
            Self::Hidden => "hidden",
            Self::Held => "held",
        }
    }

    /// Why it counts or not, for the log.
    fn why(self) -> &'static str {
        match self {
            Self::Motion => {
                "the PC sent frames at the motion rate to a visible page: counted on the rung in \
                 force, and judged by the freeze rule"
            }
            Self::Still => {
                "fewer frames than the motion rate (a still screen): not counted, not judged"
            }
            Self::Hidden => "the viewer's page is hidden: not counted, not judged",
            Self::Held => "a background hold is in force: not counted, not judged",
        }
    }
}

/// The encode time histogram's bucket edges, µs: a bucket holds the times up to its edge, the last
/// bucket everything past the last edge. Finer where encodes live (1 to 20 ms, a 30 and a 60 fps
/// budget), coarse past them.
const ENCODE_EDGES_US: [u64; 28] = [
    1_000, 2_000, 3_000, 4_000, 5_000, 6_000, 7_000, 8_000, 9_000, 10_000, 12_000, 14_000, 16_000,
    18_000, 20_000, 25_000, 30_000, 35_000, 40_000, 50_000, 60_000, 80_000, 100_000, 150_000,
    200_000, 500_000, 1_000_000, 5_000_000,
];

/// Buckets: one per edge, and one past the last.
const ENCODE_BUCKETS: usize = ENCODE_EDGES_US.len() + 1;

/// The time inside `encode()`, by bucket: one atomic add per encode, on the encode thread. Its
/// 95th percentile is the summary's `encode_ms_p95`.
#[derive(Debug)]
pub struct EncodeHistogram {
    buckets: [AtomicU64; ENCODE_BUCKETS],
}

impl Default for EncodeHistogram {
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl EncodeHistogram {
    /// One encode that took `us` microseconds.
    pub fn record(&self, us: u64) {
        let i = ENCODE_EDGES_US.partition_point(|&edge| edge < us);
        if let Some(bucket) = self.buckets.get(i) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Encodes recorded.
    pub fn count(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// The 95th percentile, ms to a tenth, interpolated within its bucket; `None` before the first
    /// encode.
    pub fn p95_ms(&self) -> Option<f64> {
        let counts: [u64; ENCODE_BUCKETS] =
            std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed));
        percentile_ms(&counts, 0.95)
    }
}

/// The `q` quantile of a histogram over [`ENCODE_EDGES_US`], ms to a tenth, at most the contract's
/// bound; `None` when it is empty. The overflow bucket reads as its lower edge.
fn percentile_ms(counts: &[u64; ENCODE_BUCKETS], q: f64) -> Option<f64> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let rank = q * total as f64;
    let mut below = 0u64;
    for (i, &n) in counts.iter().enumerate() {
        if n == 0 {
            continue;
        }
        if (below + n) as f64 >= rank {
            let lo = if i == 0 { 0 } else { ENCODE_EDGES_US[i - 1] };
            let hi = ENCODE_EDGES_US.get(i).copied().unwrap_or(lo);
            let into = ((rank - below as f64) / n as f64).clamp(0.0, 1.0);
            let us = lo as f64 + (hi - lo) as f64 * into;
            let ms = (us / 100.0).round() / 10.0;
            return Some(ms.min(m::ENCODE_MS_P95_MAX));
        }
        below += n;
    }
    None
}

/// What kind of input a message is, for the `input` line's tally and the summary's counts alike —
/// one mapping, so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputClass {
    /// `m`: absolute pointer positions.
    Abs,
    /// `r`: relative moves.
    Rel,
    /// `d` and `u`.
    Buttons,
    /// `w`: on the `input` line, not in the summary (the contract has no wheel count).
    Wheel,
    /// `k`.
    Keys,
    /// `text`.
    Text,
    /// `combo`, `ra` and anything else that reaches the injector: on the line only.
    Other,
}

impl InputClass {
    pub fn of(m: &InputMessage) -> Self {
        match m {
            InputMessage::Move { .. } => Self::Abs,
            InputMessage::Rel { .. } => Self::Rel,
            InputMessage::Down { .. } | InputMessage::Up { .. } => Self::Buttons,
            InputMessage::Wheel { .. } => Self::Wheel,
            InputMessage::Key { .. } => Self::Keys,
            InputMessage::Text { .. } => Self::Text,
            _ => Self::Other,
        }
    }
}

/// Input the session's injector took, by kind (`summary.input`): counts only — never a key, a
/// character or a position. One atomic add per injected message, beside the `input` line's tally.
#[derive(Debug, Default)]
pub struct InputTotals {
    abs: AtomicU64,
    rel: AtomicU64,
    buttons: AtomicU64,
    keys: AtomicU64,
    text: AtomicU64,
}

impl InputTotals {
    /// One injected message.
    pub fn count(&self, m: &InputMessage) {
        let slot = match InputClass::of(m) {
            InputClass::Abs => &self.abs,
            InputClass::Rel => &self.rel,
            InputClass::Buttons => &self.buttons,
            InputClass::Keys => &self.keys,
            InputClass::Text => &self.text,
            InputClass::Wheel | InputClass::Other => return,
        };
        slot.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> InputCounts {
        InputCounts {
            abs: self.abs.load(Ordering::Relaxed),
            rel: self.rel.load(Ordering::Relaxed),
            buttons: self.buttons.load(Ordering::Relaxed),
            keys: self.keys.load(Ordering::Relaxed),
            text: self.text.load(Ordering::Relaxed),
        }
    }
}

/// The ICE username fragment of an SDP (`a=ice-ufrag:`), to tell a re-answer from an ICE restart:
/// a restart's answer has new credentials, a repeated offer's the same.
pub fn ice_ufrag(sdp: &str) -> Option<&str> {
    sdp.lines()
        .find_map(|l| l.trim().strip_prefix("a=ice-ufrag:"))
        .map(str::trim)
}

/// One `pipeline` second, as the summary reads it: its kind ([`SecondKind`]) for the rung time and
/// the freeze rule alike.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Second {
    /// Frames the PC sent this second: encoded, less the ones the transport discarded.
    pub sent_frames: u64,
    /// Frames the viewer presented since the last line (`v_pres`); `None` without a report.
    pub presented: Option<u64>,
    /// The viewer's page is hidden (in the background hold's grace, or held).
    pub page_hidden: bool,
    /// A background hold is in force: no video on purpose.
    pub held: bool,
    /// The rung in force at the line (its encoded height, `rung=` on `pipeline`).
    pub height: u32,
    /// The time the line's second counts, seconds: measured since the line before, at most
    /// [`SECOND_COUNTED_MAX`] ([`SecondClock`]); about one.
    pub secs: f64,
}

/// Where an episode went: into the list, or past the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    At(usize),
    Dropped,
}

#[derive(Debug, Clone)]
struct Episode {
    kind: SessionEpisodeKind,
    at_ms: u64,
    dur_ms: Option<u64>,
    code: Option<String>,
    /// Still going on (a brake, a drain): a report gives its duration so far.
    open: bool,
}

/// A run of freeze seconds.
#[derive(Debug, Clone, Copy)]
struct FreezeRun {
    start_ms: u64,
    ms: u64,
    /// Its episode, once the run is [`FREEZE_EPISODE_MIN`] long.
    episode: Option<Slot>,
}

/// The `pipeline` seconds by kind since the last debug tally of them ([`KIND_TALLY_EVERY`]).
#[derive(Debug, Default)]
struct KindTally {
    /// Seconds of each kind, by [`SecondKind::index`].
    n: [u32; 4],
    /// Of the motion seconds, the time counted on a rung, ms.
    counted_ms: u64,
    lines: u32,
}

#[derive(Debug, Default)]
struct State {
    /// Motion seconds' time on each rung, ms, by encoded height: `rung_s`.
    rung_ms: BTreeMap<u32, u64>,
    /// Motion time on rungs past [`m::SUMMARY_RUNGS_MAX`]: not listed (said once).
    rung_overflow_ms: u64,
    rung_overflow_said: bool,
    /// The last second's kind: a change is said at trace.
    last_kind: Option<SecondKind>,
    /// Each kind's first second in the session is said at debug, with why it counts or not.
    kinds_said: [bool; 4],
    tally: KindTally,
    viewer_reported: bool,
    presented_seen: bool,
    freeze_ms: u64,
    freeze_run: Option<FreezeRun>,
    episodes: Vec<Episode>,
    dropped: u64,
    open_brake: Option<Slot>,
    open_drain: Option<Slot>,
    driver_open: bool,
    driver_missing: bool,
    reach_episodes: Option<u64>,
}

/// One session's summary. Shared by the control task (rung time, episodes, freeze), the heartbeat
/// (the driver, blocked input), the event task (ICE restarts) and the reports, which read it.
///
/// | field                       | from                                                               |
/// |-----------------------------|--------------------------------------------------------------------|
/// | `rung_s`                    | each motion second of the `pipeline` line ([`SecondKind::Motion`]: `encode_fps` less `discarded` ≥ [`MOTION_FRAMES`], the page visible, no hold), on the rung in force at the line (`rung=`), for the second's measured time ([`SecondClock`]) |
/// | `freeze_s`, `freeze`        | the same motion seconds, judged on `v_pres` (presented)            |
/// | `brake`                     | `brake engaged` … `brake released` (its `cause` is the code)        |
/// | `drain`                     | `drain mode entered` … `drain mode left` (`by_silence`: `silence`, else `rtt`) |
/// | `path_change`               | the transport's change count (`media path changed`, `ICE path restored`); the code is the new pair's kind |
/// | `ice_restart`               | the peer's answer to a re-offer with new ICE credentials (`ICE restart applied`) |
/// | `capture_restart`           | `capture restarted; the next frame will be a keyframe` (its `cause`) |
/// | `rung_change`               | `quality changed` (its `reason`), and `quality pinned` (`viewer`)   |
/// | `encode_ms_p95`             | the time inside `encode()` the encode loop adds to `encode_ms`      |
/// | `input`                     | the `input` line's counts by kind (no wheel, no `ra`/`combo`)       |
/// | `input_path`, `driver`, `input_blocked_n` | the heartbeat's reading of the injector (`heartbeat changed`: `driver`, `input_blocked`) |
/// | `capture_mode`              | the session's capture mode (`capture mode at session start`, `game-only setting changed`) |
/// | `dropped_rate`              | `dropped_rate` on `pipeline`                                        |
/// | `bytes_socket`, `bytes_relay` | the peer loop's sends the socket took ([`SocketBytes`])           |
///
/// Episodes: at most [`SUMMARY_EPISODES_MAX`](m::SUMMARY_EPISODES_MAX), in the order they began;
/// past it each is counted in `episodes_dropped` (logged once). `at_ms` is from the session's
/// start; an episode still going on at a report (a brake, a drain) carries its duration so far.
pub struct SessionSummary {
    /// For log lines.
    session: String,
    started: Instant,
    socket: Option<Arc<SocketBytes>>,
    capture: Option<Arc<crate::game::CaptureModeCell>>,
    /// The injector's blocked-input episodes at the session's start: `input_blocked_n` counts from
    /// here (`crate::input_reach`, the same baseline the session's end diffs against).
    reach_start_episodes: u64,
    /// The quality profile the session runs on (`"<id>.v<v>"`) and where it came from: fixed at the
    /// session's start ([`Self::with_quality_profile`]), so read without the lock.
    quality_profile: Option<(String, m::QualityProfileSource)>,
    state: Mutex<State>,
    /// A summary [`AgentSessionSummary::check`] refused has been warned about (once a session).
    refused_warned: AtomicBool,
}

impl SessionSummary {
    /// A session that started at `started`; its socket's counts, its capture mode and its input's
    /// reach at the start, when it has them.
    pub fn new(
        session: &str,
        started: Instant,
        socket: Option<Arc<SocketBytes>>,
        capture: Option<Arc<crate::game::CaptureModeCell>>,
        reach_start: InputReach,
    ) -> Self {
        Self {
            session: session.to_string(),
            started,
            socket,
            capture,
            reach_start_episodes: reach_start.episodes,
            quality_profile: None,
            state: Mutex::new(State::default()),
            refused_warned: AtomicBool::new(false),
        }
    }

    /// The quality profile the session runs on, `label` being `"<id>.v<v>"`, and its source — what
    /// the summary's `quality_profile` and `quality_profile_source` report.
    #[must_use]
    pub fn with_quality_profile(mut self, label: &str, source: m::QualityProfileSource) -> Self {
        self.quality_profile = Some((label.to_string(), source));
        self
    }

    /// When the session started: what every `at_ms` counts from.
    pub fn started(&self) -> Instant {
        self.started
    }

    fn ms_at(&self, now: Instant) -> u64 {
        let ms = now.saturating_duration_since(self.started).as_millis();
        u64::try_from(ms).unwrap_or(u64::MAX).min(m::SESSION_MS_MAX)
    }

    /// One `pipeline` second, ending at `now` (module docs): its kind ([`SecondKind`]) decides both
    /// what follows. A motion second's time goes to the rung in force (`rung_s`), whatever the
    /// viewer reported; then the freeze rule judges it on the viewer's report.
    pub fn second(&self, now: Instant, sec: Second) {
        let end_ms = self.ms_at(now);
        let secs_ms = if sec.secs.is_finite() && sec.secs > 0.0 {
            (sec.secs * 1000.0).round() as u64
        } else {
            0
        };
        let kind = SecondKind::of(&sec);
        let mut s = lock(&self.state);
        if kind == SecondKind::Motion {
            self.count_rung(&mut s, sec.height, secs_ms);
        }
        self.note_kind(&mut s, kind, &sec, secs_ms);
        let Some(presented) = sec.presented else {
            // No report this second: not a freeze, and not the end of one either.
            return;
        };
        s.viewer_reported = true;
        let freeze = kind == SecondKind::Motion && s.presented_seen && presented == 0;
        if presented > 0 {
            s.presented_seen = true;
        }
        if freeze {
            s.freeze_ms = s.freeze_ms.saturating_add(secs_ms);
            let mut run = s.freeze_run.unwrap_or_else(|| {
                let start_ms = end_ms.saturating_sub(secs_ms);
                tracing::debug!(
                    session = %self.session,
                    at_ms = start_ms,
                    sent_frames = sec.sent_frames,
                    "summary: freeze began: frames sent, none presented by the viewer"
                );
                FreezeRun {
                    start_ms,
                    ms: 0,
                    episode: None,
                }
            });
            run.ms = run.ms.saturating_add(secs_ms);
            let long = run.ms >= u64::try_from(FREEZE_EPISODE_MIN.as_millis()).unwrap_or(u64::MAX);
            match run.episode {
                None if long => {
                    let slot = self.push(
                        &mut s,
                        Episode {
                            kind: SessionEpisodeKind::Freeze,
                            at_ms: run.start_ms,
                            dur_ms: Some(run.ms),
                            code: None,
                            open: false,
                        },
                    );
                    run.episode = Some(slot);
                }
                Some(Slot::At(i)) => {
                    if let Some(e) = s.episodes.get_mut(i) {
                        e.dur_ms = Some(run.ms.min(m::SESSION_MS_MAX));
                    }
                }
                None | Some(Slot::Dropped) => {}
            }
            s.freeze_run = Some(run);
        } else if let Some(run) = s.freeze_run.take() {
            tracing::debug!(
                session = %self.session,
                at_ms = run.start_ms,
                dur_ms = run.ms,
                episode = run.episode.is_some(),
                why = match kind {
                    SecondKind::Hidden | SecondKind::Held => "the page is hidden or held",
                    SecondKind::Still => "the PC is sending fewer frames (a still screen)",
                    SecondKind::Motion => "the viewer presented frames again",
                },
                "summary: freeze ended"
            );
        }
    }

    /// A motion second's `ms` on the rung of encoded height `height`; past the contract's rungs,
    /// counted apart and not listed (said once).
    fn count_rung(&self, s: &mut State, height: u32, ms: u64) {
        if !s.rung_ms.contains_key(&height) && s.rung_ms.len() >= m::SUMMARY_RUNGS_MAX {
            if !std::mem::replace(&mut s.rung_overflow_said, true) {
                tracing::debug!(
                    session = %self.session,
                    height,
                    rungs = s.rung_ms.len(),
                    "summary: more rungs than the contract lists; the motion time on the rest is \
                     not listed"
                );
            }
            s.rung_overflow_ms = s.rung_overflow_ms.saturating_add(ms);
            return;
        }
        let slot = s.rung_ms.entry(height).or_insert(0);
        *slot = slot.saturating_add(ms);
        s.tally.counted_ms = s.tally.counted_ms.saturating_add(ms);
    }

    /// The log's side of a second's kind, nothing per second at debug: each kind's first second in
    /// the session at debug, with why it counts or not and the numbers it was judged on; every
    /// change of kind at trace; and every [`KIND_TALLY_EVERY`] seconds a debug tally of the kinds
    /// and of the motion time counted on rungs.
    fn note_kind(&self, s: &mut State, kind: SecondKind, sec: &Second, secs_ms: u64) {
        let i = kind.index();
        if !std::mem::replace(&mut s.kinds_said[i], true) {
            tracing::debug!(
                session = %self.session,
                kind = kind.as_str(),
                sent_frames = sec.sent_frames,
                motion_frames = MOTION_FRAMES,
                page_hidden = sec.page_hidden,
                held = sec.held,
                height = sec.height,
                secs_ms,
                why = kind.why(),
                "summary: the session's first second of this kind"
            );
        }
        if s.last_kind != Some(kind) {
            tracing::trace!(
                session = %self.session,
                kind = kind.as_str(),
                was = s.last_kind.map_or("-", SecondKind::as_str),
                sent_frames = sec.sent_frames,
                height = sec.height,
                "summary: the seconds changed kind"
            );
            s.last_kind = Some(kind);
        }
        s.tally.n[i] = s.tally.n[i].saturating_add(1);
        s.tally.lines = s.tally.lines.saturating_add(1);
        if s.tally.lines >= KIND_TALLY_EVERY {
            self.say_tally(s, "a minute of pipeline seconds");
        }
    }

    /// The seconds' kinds since the last tally, at debug, and a new tally from here.
    fn say_tally(&self, s: &mut State, why: &'static str) {
        let t = std::mem::take(&mut s.tally);
        tracing::debug!(
            session = %self.session,
            motion = t.n[SecondKind::Motion.index()],
            still = t.n[SecondKind::Still.index()],
            hidden = t.n[SecondKind::Hidden.index()],
            held = t.n[SecondKind::Held.index()],
            counted_ms = t.counted_ms,
            unlisted_ms = s.rung_overflow_ms,
            why,
            "summary: the last pipeline seconds by kind; only motion seconds count on a rung and \
             in the freeze rule"
        );
    }

    /// The session's control task stopped: the seconds since the last tally, if any (debug).
    pub fn seconds_ended(&self) {
        let mut s = lock(&self.state);
        if s.tally.lines > 0 {
            self.say_tally(&mut s, "the session ends");
        }
    }

    /// An episode with no duration: a path change, an ICE restart, a capture restart, a rung
    /// change. `code` is turned into a short id (`m::short_id`), or left out when it cannot be.
    pub fn instant(&self, now: Instant, kind: SessionEpisodeKind, code: Option<&str>) {
        let at_ms = self.ms_at(now);
        let code = self.code(kind, code);
        let mut s = lock(&self.state);
        self.push(
            &mut s,
            Episode {
                kind,
                at_ms,
                dur_ms: None,
                code,
                open: false,
            },
        );
    }

    /// An episode with a duration begins: a brake, a drain. One of a kind open at a time — a second
    /// beginning closes the first.
    pub fn begin(&self, now: Instant, kind: SessionEpisodeKind, code: Option<&str>) {
        let at_ms = self.ms_at(now);
        let code = self.code(kind, code);
        let mut s = lock(&self.state);
        if Self::open_slot(&mut s, kind).is_some() {
            tracing::debug!(
                session = %self.session,
                kind = kind.as_str(),
                "summary: an episode began while one of its kind was open; that one ends here"
            );
            self.close(&mut s, kind, at_ms);
        }
        let slot = self.push(
            &mut s,
            Episode {
                kind,
                at_ms,
                dur_ms: None,
                code,
                open: true,
            },
        );
        *Self::open_slot(&mut s, kind) = Some(slot);
    }

    /// The open episode of `kind` ends now.
    pub fn end(&self, now: Instant, kind: SessionEpisodeKind) {
        let at_ms = self.ms_at(now);
        let mut s = lock(&self.state);
        if Self::open_slot(&mut s, kind).is_none() {
            tracing::debug!(
                session = %self.session,
                kind = kind.as_str(),
                "summary: an end with no episode of its kind open (it began before the summary \
                 could see it): nothing to close"
            );
            return;
        }
        self.close(&mut s, kind, at_ms);
    }

    /// The heartbeat's reading of the injector: whether the driver was open for the session, and
    /// how often the viewer's presses were found blocked.
    pub fn note_reach(&self, reach: &InputReach) {
        let mut s = lock(&self.state);
        match reach.driver {
            DriverPresence::Open => s.driver_open = true,
            DriverPresence::Missing => s.driver_missing = true,
            DriverPresence::Unknown => {}
        }
        s.reach_episodes = Some(reach.episodes);
    }

    /// The summary as of `now`, from this session's state and its counters.
    pub fn snapshot(
        &self,
        now: Instant,
        counters: &crate::agent::SessionCounters,
    ) -> AgentSessionSummary {
        let now_ms = self.ms_at(now);
        let s = lock(&self.state);
        let rung_s: BTreeMap<String, f64> = s
            .rung_ms
            .iter()
            .map(|(h, ms)| (h.to_string(), seconds(*ms)))
            .filter(|(k, _)| m::is_rung_key(k))
            .collect();
        let episodes = s
            .episodes
            .iter()
            .map(|e| SessionEpisode {
                kind: e.kind,
                at_ms: e.at_ms,
                dur_ms: if e.open {
                    Some(now_ms.saturating_sub(e.at_ms))
                } else {
                    e.dur_ms
                },
                code: e.code.clone(),
            })
            .collect();
        // The driver the session had: open at any reading is the HID path (the injector switches a
        // live session to it the moment it opens); missing at every reading, SendInput alone.
        let (driver, input_path) = if s.driver_open {
            (DriverState::Installed, Some(InputPath::Hid))
        } else if s.driver_missing {
            (DriverState::Absent, Some(InputPath::Sendinput))
        } else {
            (DriverState::Unknown, None)
        };
        AgentSessionSummary {
            rung_s: (!rung_s.is_empty()).then_some(rung_s),
            // Without a single report from the viewer nothing is known of its screen.
            freeze_s: s.viewer_reported.then(|| seconds(s.freeze_ms)),
            episodes: Some(episodes),
            episodes_dropped: Some(s.dropped),
            encode_ms_p95: counters.encode_hist.p95_ms(),
            input: Some(counters.input.snapshot()),
            input_path,
            input_blocked_n: s
                .reach_episodes
                .map(|n| n.saturating_sub(self.reach_start_episodes)),
            capture_mode: self.capture.as_ref().map(|c| {
                if c.is_game() {
                    CaptureMode::GameOnly
                } else {
                    CaptureMode::Screen
                }
            }),
            driver: Some(driver),
            dropped_rate: Some(counters.frames_dropped_rate.load(Ordering::Relaxed)),
            bytes_socket: self.socket.as_ref().map(|b| b.total()),
            bytes_relay: self.socket.as_ref().map(|b| b.relay()),
            quality_profile: self.quality_profile.as_ref().map(|(l, _)| l.clone()),
            quality_profile_source: self.quality_profile.as_ref().map(|(_, s)| *s),
        }
    }

    /// [`Self::snapshot`] held to the contract: a summary that fails [`AgentSessionSummary::check`]
    /// (a defect — it is built to fit) is left out of the report, which then goes without it.
    pub fn checked(
        &self,
        now: Instant,
        counters: &crate::agent::SessionCounters,
    ) -> Option<AgentSessionSummary> {
        let summary = self.snapshot(now, counters);
        match summary.check() {
            Ok(()) => Some(summary),
            Err(e) => {
                if self.refused_warned.swap(true, Ordering::Relaxed) {
                    tracing::debug!(session = %self.session, "summary still refused: {e}");
                } else {
                    tracing::warn!(
                        session = %self.session,
                        "summary refused by the contract's checks ({e}): the report goes without it"
                    );
                }
                None
            }
        }
    }

    /// `code` as a short id, said when it cannot be one.
    fn code(&self, kind: SessionEpisodeKind, code: Option<&str>) -> Option<String> {
        let code = code?;
        let id = m::short_id(code);
        if id.is_none() {
            // not-a-key-name: an episode's short code
            tracing::debug!(
                session = %self.session,
                kind = kind.as_str(),
                code,
                "summary: an episode's code is not a short id; left out"
            );
        }
        id
    }

    fn open_slot(s: &mut State, kind: SessionEpisodeKind) -> &mut Option<Slot> {
        match kind {
            SessionEpisodeKind::Drain => &mut s.open_drain,
            _ => &mut s.open_brake,
        }
    }

    /// Close the open episode of `kind` at `at_ms`.
    fn close(&self, s: &mut State, kind: SessionEpisodeKind, at_ms: u64) {
        let Some(slot) = Self::open_slot(s, kind).take() else {
            return;
        };
        if let Slot::At(i) = slot {
            if let Some(e) = s.episodes.get_mut(i) {
                e.dur_ms = Some(at_ms.saturating_sub(e.at_ms));
                e.open = false;
                // not-a-key-name: an episode's short code
                tracing::debug!(
                    session = %self.session,
                    kind = kind.as_str(),
                    at_ms = e.at_ms,
                    dur_ms = e.dur_ms,
                    code = e.code.as_deref().unwrap_or("-"),
                    "summary: episode ended"
                );
            }
        }
    }

    /// Into the list, or past the cap: counted, and said once.
    fn push(&self, s: &mut State, e: Episode) -> Slot {
        if s.episodes.len() >= m::SUMMARY_EPISODES_MAX {
            s.dropped = s.dropped.saturating_add(1);
            if s.dropped == 1 {
                tracing::warn!(
                    session = %self.session,
                    cap = m::SUMMARY_EPISODES_MAX,
                    kind = e.kind.as_str(),
                    at_ms = e.at_ms,
                    "summary: the episode cap is reached; the rest are counted in \
                     episodes_dropped, not listed"
                );
            }
            return Slot::Dropped;
        }
        // not-a-key-name: an episode's short code
        tracing::debug!(
            session = %self.session,
            kind = e.kind.as_str(),
            at_ms = e.at_ms,
            dur_ms = ?e.dur_ms,
            code = e.code.as_deref().unwrap_or("-"),
            n = s.episodes.len() + 1,
            "summary: episode"
        );
        s.episodes.push(e);
        Slot::At(s.episodes.len() - 1)
    }
}

/// Milliseconds as seconds to a tenth, at most the contract's bound.
fn seconds(ms: u64) -> f64 {
    ((ms as f64 / 100.0).round() / 10.0).min(m::SESSION_SECONDS_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::SessionCounters;

    fn summary() -> (SessionSummary, Instant) {
        let t0 = Instant::now();
        (
            SessionSummary::new("s1", t0, None, None, InputReach::default()),
            t0,
        )
    }

    /// A second of `sent` frames at 1080p, `presented` by the viewer, one second long.
    fn sec(sent: u64, presented: Option<u64>) -> Second {
        Second {
            sent_frames: sent,
            presented,
            page_hidden: false,
            held: false,
            height: 1080,
            secs: 1.0,
        }
    }

    /// One test for both: motion is the motion rate to a visible page outside a hold, whatever the
    /// viewer reported.
    #[test]
    fn a_seconds_kind_is_the_one_test_of_rung_time_and_freeze() {
        assert_eq!(
            SecondKind::of(&sec(MOTION_FRAMES, None)),
            SecondKind::Motion
        );
        assert_eq!(SecondKind::of(&sec(30, Some(0))), SecondKind::Motion);
        assert_eq!(
            SecondKind::of(&sec(MOTION_FRAMES - 1, Some(30))),
            SecondKind::Still
        );
        let hidden = Second {
            page_hidden: true,
            ..sec(30, Some(0))
        };
        assert_eq!(SecondKind::of(&hidden), SecondKind::Hidden);
        let held = Second {
            held: true,
            ..hidden
        };
        assert_eq!(SecondKind::of(&held), SecondKind::Held, "a hold first");
    }

    /// The seconds' clock: each `pipeline` second counts the time since the line before — a late
    /// line (a starved runtime) what its counters covered — up to the cap; past it the cap, the
    /// rest counted for the log and said in one line, not per second.
    #[test]
    fn the_second_clock_counts_measured_time_up_to_the_cap() {
        let ms = Duration::from_millis;
        let t0 = Instant::now();
        let mut clock = SecondClock::new(t0);
        assert_eq!(clock.step(t0 + ms(1_000), "s1"), ms(1_000));
        assert_eq!(
            clock.step(t0 + ms(2_700), "s1"),
            ms(1_700),
            "a late line: what its counters covered, not one second"
        );
        // A ten-second stall: the cap; the first time it is said (and the tally starts again).
        let stalled = t0 + ms(2_700) + Duration::from_secs(10);
        assert_eq!(clock.step(stalled, "s1"), SECOND_COUNTED_MAX);
        assert_eq!((clock.clamped, clock.cut_ms), (0, 0), "said at once");
        // Another soon after: counted, not said yet.
        let again = stalled + Duration::from_secs(5);
        assert_eq!(clock.step(again, "s1"), SECOND_COUNTED_MAX);
        assert_eq!((clock.clamped, clock.cut_ms), (1, 3_000));
        assert_eq!(clock.step(again + ms(1_000), "s1"), ms(1_000));
        // The end says what is left.
        clock.finish("s1");
        assert_eq!((clock.clamped, clock.cut_ms), (0, 0));
        // Over late lines the rung time is the time their counters covered, not lines × 1 s.
        let (s, t0) = summary();
        let mut clock = SecondClock::new(t0);
        for i in 1..=10u64 {
            let now = t0 + ms(i * 1_450);
            let counted = clock.step(now, "s1");
            s.second(
                now,
                Second {
                    height: 720,
                    secs: counted.as_secs_f64(),
                    ..sec(30, None)
                },
            );
        }
        let out = s.snapshot(t0 + ms(14_500), &SessionCounters::default());
        assert_eq!(out.rung_s.map(|r| r["720"]), Some(14.5));
    }

    /// Only motion seconds count, on the rung in force at the line, keyed by height, in seconds to
    /// a tenth — with a viewer report or without one; a still screen, a hidden page and a
    /// background hold on no rung.
    #[test]
    fn rung_seconds_count_motion_seconds_only() {
        let (s, t0) = summary();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        let on = |height: u32, sent: u64| Second {
            height,
            ..sec(sent, Some(30))
        };
        for i in 1..=10u64 {
            s.second(at(i), on(1080, 30));
        }
        // 1.4 s of motion at 720p: a second the viewer did not report, and a short one.
        s.second(
            at(11),
            Second {
                presented: None,
                ..on(720, 30)
            },
        );
        s.second(
            at(12),
            Second {
                secs: 0.4,
                ..on(720, MOTION_FRAMES)
            },
        );
        // Not motion: a still screen, a hidden page, a background hold.
        s.second(at(13), on(720, MOTION_FRAMES - 1));
        s.second(
            at(14),
            Second {
                page_hidden: true,
                ..on(720, 30)
            },
        );
        s.second(
            at(15),
            Second {
                held: true,
                ..on(720, 30)
            },
        );
        let out = s.snapshot(at(15), &SessionCounters::default());
        let rungs = out.rung_s.clone().expect("rungs");
        assert_eq!(rungs.get("1080"), Some(&10.0));
        assert_eq!(rungs.get("720"), Some(&1.4), "no float dust: tenths");
        assert_eq!(rungs.len(), 2);
        assert_eq!(out.check(), Ok(()));
        // A session of still seconds only has no rung time at all.
        let (still, t0) = summary();
        still.second(t0 + Duration::from_secs(1), sec(1, Some(1)));
        assert_eq!(still.snapshot(t0, &SessionCounters::default()).rung_s, None);
    }

    /// No more than the contract's sixteen rungs; the motion time on the rest is not listed.
    #[test]
    fn rungs_past_the_cap_are_not_listed() {
        let (s, t0) = summary();
        for h in 0..20u32 {
            s.second(
                t0 + Duration::from_secs(u64::from(h) + 1),
                Second {
                    height: 100 + h,
                    ..sec(30, None)
                },
            );
        }
        let rungs = s
            .snapshot(t0, &SessionCounters::default())
            .rung_s
            .expect("rungs");
        assert_eq!(rungs.len(), m::SUMMARY_RUNGS_MAX);
    }

    /// The freeze rule: motion with nothing presented is a freeze second; a still screen is not; a
    /// second without a report neither counts nor ends a run; a hidden page is not; before the
    /// first presented frame is not. Two seconds or more is an episode, dated from its first.
    #[test]
    fn the_freeze_rule_counts_motion_without_a_presented_frame_only() {
        let (s, t0) = summary();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        // Before the first picture: 30 sent, 0 presented — the time to the first frame, no freeze.
        s.second(at(1), sec(30, Some(0)));
        s.second(at(2), sec(30, Some(25)));
        // A still screen: 2 sent, 0 presented.
        s.second(at(3), sec(2, Some(0)));
        // Motion, nothing presented: three seconds, one missing a report in the middle.
        s.second(at(4), sec(30, Some(0)));
        s.second(at(5), sec(30, None));
        s.second(at(6), sec(30, Some(0)));
        s.second(at(7), sec(30, Some(0)));
        // Back.
        s.second(at(8), sec(30, Some(30)));
        // One freeze second alone: counted, not an episode.
        s.second(at(9), sec(30, Some(0)));
        s.second(at(10), sec(30, Some(30)));
        // A hidden page: nothing presented, not a freeze.
        s.second(
            at(11),
            Second {
                page_hidden: true,
                ..sec(30, Some(0))
            },
        );
        let out = s.snapshot(at(12), &SessionCounters::default());
        assert_eq!(out.freeze_s, Some(4.0));
        // The same motion seconds on the rung: every second but the still one and the hidden one
        // (the unreported one too) — the freeze seconds are four of these nine.
        assert_eq!(out.rung_s.clone().map(|r| r["1080"]), Some(9.0));
        let episodes = out.episodes.clone().expect("episodes");
        assert_eq!(episodes.len(), 1, "{episodes:?}");
        let e = &episodes[0];
        assert_eq!(e.kind, SessionEpisodeKind::Freeze);
        assert_eq!(e.at_ms, 3_000, "from its first second");
        assert_eq!(e.dur_ms, Some(3_000), "the judged seconds");
        assert_eq!(out.check(), Ok(()));
    }

    /// A viewer that never reported (an old Mini App): nothing is known of its screen.
    #[test]
    fn without_a_viewer_report_the_freeze_is_unknown() {
        let (s, t0) = summary();
        s.second(t0 + Duration::from_secs(1), sec(30, None));
        assert_eq!(s.snapshot(t0, &SessionCounters::default()).freeze_s, None);
    }

    /// A brake and a drain with their durations, an open one with its duration so far; instants
    /// without one; the agent's words as short ids.
    #[test]
    fn episodes_carry_their_codes_and_durations() {
        let (s, t0) = summary();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        s.begin(at(30_200), SessionEpisodeKind::Brake, Some("loss"));
        s.instant(
            at(31_500),
            SessionEpisodeKind::RungChange,
            Some("startup-thin"),
        );
        s.end(at(32_000), SessionEpisodeKind::Brake);
        s.instant(at(34_100), SessionEpisodeKind::PathChange, Some("relay"));
        s.begin(at(40_000), SessionEpisodeKind::Brake, Some("no-feedback"));
        s.begin(at(41_000), SessionEpisodeKind::Drain, Some("rtt"));
        s.instant(
            at(41_500),
            SessionEpisodeKind::CaptureRestart,
            Some("capture lost?"),
        );
        s.end(at(41_700), SessionEpisodeKind::Drain);
        let out = s.snapshot(at(45_000), &SessionCounters::default());
        let e = out.episodes.clone().expect("episodes");
        let brief: Vec<_> = e
            .iter()
            .map(|e| (e.kind.as_str(), e.at_ms, e.dur_ms, e.code.as_deref()))
            .collect();
        assert_eq!(
            brief,
            [
                ("brake", 30_200, Some(1_800), Some("loss")),
                ("rung_change", 31_500, None, Some("startup_thin")),
                ("path_change", 34_100, None, Some("relay")),
                ("brake", 40_000, Some(5_000), Some("no_feedback")),
                ("drain", 41_000, Some(700), Some("rtt")),
                ("capture_restart", 41_500, None, None),
            ],
            "the open brake carries its time so far; a code that cannot be a short id is left out"
        );
        assert_eq!(out.check(), Ok(()));
        // An end with nothing open is nothing.
        s.end(at(46_000), SessionEpisodeKind::Drain);
    }

    /// At most a hundred episodes; the rest counted.
    #[test]
    fn the_episode_cap_counts_the_rest() {
        let (s, t0) = summary();
        for i in 0..130u64 {
            s.instant(
                t0 + Duration::from_millis(i),
                SessionEpisodeKind::RungChange,
                Some("down"),
            );
        }
        let out = s.snapshot(t0, &SessionCounters::default());
        assert_eq!(
            out.episodes.as_ref().map(Vec::len),
            Some(m::SUMMARY_EPISODES_MAX)
        );
        assert_eq!(out.episodes_dropped, Some(30));
        assert_eq!(out.check(), Ok(()));
    }

    /// The 95th percentile from the buckets: interpolated, in tenths, none before the first encode.
    #[test]
    fn the_encode_p95_comes_from_fixed_buckets() {
        let h = EncodeHistogram::default();
        assert_eq!(h.p95_ms(), None);
        // 90 encodes at 4.5 ms, 10 at 14.5 ms: the 95th is inside the 14-16 ms bucket.
        for _ in 0..90 {
            h.record(4_500);
        }
        for _ in 0..10 {
            h.record(14_500);
        }
        assert_eq!(h.count(), 100);
        let p95 = h.p95_ms().expect("a p95");
        assert!((14.0..=16.0).contains(&p95), "{p95}");
        // A pathological encode does not break the bound.
        let slow = EncodeHistogram::default();
        slow.record(90_000_000);
        assert_eq!(slow.p95_ms(), Some(5_000.0));
        // An edge value lands in its own bucket: 1000 µs is the first one's.
        let edge = EncodeHistogram::default();
        edge.record(1_000);
        assert_eq!(edge.p95_ms(), Some(1.0));
    }

    /// The input's kinds as the `input` line counts them, without the wheel and `ra`.
    #[test]
    fn input_counts_follow_the_input_lines_kinds() {
        let t = InputTotals::default();
        for m in [
            InputMessage::Move { x: 0.5, y: 0.5 },
            InputMessage::Rel {
                dx: 0.1,
                dy: 0.0,
                s: None,
                x: None,
                y: None,
            },
            InputMessage::Down { b: 0 },
            InputMessage::Up { b: 0 },
            InputMessage::ReleaseAll,
        ] {
            t.count(&m);
        }
        assert_eq!(
            t.snapshot(),
            InputCounts {
                abs: 1,
                rel: 1,
                buttons: 2,
                keys: 0,
                text: 0
            }
        );
    }

    /// The driver the session had, and the presses found blocked since its start.
    #[test]
    fn the_driver_and_blocked_input_come_from_the_heartbeats_readings() {
        let t0 = Instant::now();
        let s = SessionSummary::new(
            "s1",
            t0,
            None,
            None,
            InputReach {
                episodes: 4,
                ..InputReach::default()
            },
        );
        let out = s.snapshot(t0, &SessionCounters::default());
        assert_eq!(
            (out.driver, out.input_path, out.input_blocked_n),
            (Some(DriverState::Unknown), None, None)
        );
        s.note_reach(&InputReach {
            driver: DriverPresence::Missing,
            episodes: 6,
            ..InputReach::default()
        });
        let out = s.snapshot(t0, &SessionCounters::default());
        assert_eq!(
            (out.driver, out.input_path, out.input_blocked_n),
            (
                Some(DriverState::Absent),
                Some(InputPath::Sendinput),
                Some(2)
            )
        );
        // Installed mid-session: the session had it.
        s.note_reach(&InputReach {
            driver: DriverPresence::Open,
            episodes: 6,
            ..InputReach::default()
        });
        let out = s.snapshot(t0, &SessionCounters::default());
        assert_eq!(
            (out.driver, out.input_path),
            (Some(DriverState::Installed), Some(InputPath::Hid))
        );
    }

    /// A scripted session's summary as the wire carries it — every field the contract has — in the
    /// shape of the contract's golden fixture (`session_stats_final.json`), and its checks pass.
    #[test]
    fn a_scripted_sessions_summary_is_the_contracts_shape() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let socket = Arc::new(SocketBytes::default());
        socket.note(3_550_000, false);
        socket.note(2_100_000, true);
        let capture = Arc::new(crate::game::CaptureModeCell::new(
            crate::game::CaptureMode::GameWindow { binding: None },
        ));
        let s = SessionSummary::new("s1", t0, Some(socket), Some(capture), InputReach::default())
            .with_quality_profile("default.v1", m::QualityProfileSource::Server);
        // 31.5 motion seconds at 1080p, the picture shown all along.
        for i in 1..=31u64 {
            s.second(at(i * 1_000), sec(30, Some(30)));
        }
        s.second(
            at(31_500),
            Second {
                secs: 0.5,
                ..sec(30, Some(30))
            },
        );
        s.begin(at(30_200), SessionEpisodeKind::Brake, Some("loss"));
        s.instant(at(31_500), SessionEpisodeKind::RungChange, Some("brake"));
        // Then 13.5 at 720p; seconds 33 and 34 sent frames and the viewer presented none.
        let on720 = |presented: Option<u64>| Second {
            height: 720,
            ..sec(30, presented)
        };
        s.second(
            at(32_000),
            Second {
                secs: 0.5,
                ..on720(Some(30))
            },
        );
        s.end(at(32_000), SessionEpisodeKind::Brake);
        s.second(at(33_000), on720(Some(30)));
        s.second(at(34_000), on720(Some(0)));
        s.second(at(35_000), on720(Some(0)));
        s.second(at(36_000), on720(Some(28)));
        s.instant(at(34_100), SessionEpisodeKind::PathChange, Some("relay"));
        for i in 37..=45u64 {
            s.second(at(i * 1_000), on720(Some(30)));
        }
        // Not motion, so on no rung and judged by no freeze rule: a still screen with nothing
        // presented, a hidden page, a background hold.
        s.second(
            at(45_000),
            Second {
                sent_frames: 2,
                ..on720(Some(0))
            },
        );
        s.second(
            at(45_000),
            Second {
                page_hidden: true,
                ..on720(Some(0))
            },
        );
        s.second(
            at(45_000),
            Second {
                held: true,
                ..on720(None)
            },
        );
        s.note_reach(&InputReach {
            driver: DriverPresence::Open,
            ..InputReach::default()
        });
        let counters = SessionCounters::default();
        for us in [6_000, 8_000, 9_500, 14_200] {
            for _ in 0..25 {
                counters.encode_hist.record(us);
            }
        }
        counters.frames_dropped_rate.store(1_328, Ordering::Relaxed);
        for _ in 0..3 {
            counters.input.count(&InputMessage::Text {
                text: "секрет".into(),
                game: None,
            });
        }
        counters.input.count(&InputMessage::Move { x: 0.5, y: 0.5 });
        let out = s.snapshot(at(45_000), &counters);
        assert_eq!(out.check(), Ok(()));
        let wire = serde_json::to_value(&out).expect("serialises");
        assert_eq!(
            wire,
            serde_json::json!({
                "rung_s": { "1080": 31.5, "720": 13.5 },
                "freeze_s": 2.0,
                "episodes": [
                    { "kind": "brake", "at_ms": 30_200, "dur_ms": 1_800, "code": "loss" },
                    { "kind": "rung_change", "at_ms": 31_500, "code": "brake" },
                    { "kind": "freeze", "at_ms": 33_000, "dur_ms": 2_000 },
                    { "kind": "path_change", "at_ms": 34_100, "code": "relay" }
                ],
                "episodes_dropped": 0,
                // 75 of 100 encodes at or under 10 ms, 25 in the 14-16 ms bucket: the 95th is 80 %
                // into that bucket.
                "encode_ms_p95": 15.6,
                "input": { "abs": 1, "rel": 0, "buttons": 0, "keys": 0, "text": 3 },
                "input_path": "hid",
                "input_blocked_n": 0,
                "capture_mode": "game_only",
                "driver": "installed",
                "dropped_rate": 1_328,
                "bytes_socket": 5_650_000,
                "bytes_relay": 2_100_000,
                "quality_profile": "default.v1",
                "quality_profile_source": "server"
            })
        );
        assert!(
            !wire.to_string().contains("секрет"),
            "never what was typed: {wire}"
        );

        // The contract's golden fixture itself: the same fields, each the same kind of value, and
        // the same episodes with the same fields. Its numbers are its own (a freeze episode longer
        // than its freeze seconds, which this summary's one rule cannot make), so the values are
        // held above.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../contract/packages/protocol/fixtures/agent-to-server/session_stats_final.json",
        );
        let fixture: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path)
                .expect("the contract's fixture (the contract submodule checked out)"),
        )
        .expect("the fixture is JSON");
        let golden = &fixture["stats"]["summary"];
        let keys = |v: &serde_json::Value| {
            v.as_object()
                .map(|o| o.keys().cloned().collect::<std::collections::BTreeSet<_>>())
                .unwrap_or_default()
        };
        let kind = |v: &serde_json::Value| match v {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "bool",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        };
        assert_eq!(
            keys(&wire),
            keys(golden),
            "the fixture's fields, no more, no fewer"
        );
        for (field, value) in golden.as_object().expect("the fixture's summary") {
            assert_eq!(kind(&wire[field]), kind(value), "{field}");
        }
        let episodes = |v: &serde_json::Value| {
            v["episodes"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|e| (e["kind"].clone(), keys(e)))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        assert_eq!(episodes(&wire), episodes(golden));
        assert_eq!(keys(&wire["input"]), keys(&golden["input"]));
    }

    #[test]
    fn a_restart_is_told_by_its_new_credentials() {
        let a = "v=0\r\na=ice-ufrag:abcd\r\na=ice-pwd:x\r\n";
        let b = "v=0\r\na=ice-ufrag:efgh\r\n";
        assert_eq!(ice_ufrag(a), Some("abcd"));
        assert_eq!(ice_ufrag(b), Some("efgh"));
        assert_eq!(ice_ufrag("v=0\r\n"), None);
    }
}
