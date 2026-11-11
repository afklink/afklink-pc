//! The viewer's repeated keyframe requests, held against the keyframe already on its way to it.
//!
//! A viewer that lost its picture keeps asking for a keyframe until one arrives: Chrome's frame
//! buffer asks again every 200 ms (`max_wait_for_keyframe`; the simulator's viewer does the same,
//! `afklink_sim::viewer`). On a long round trip the repeat leaves before the first keyframe can have
//! arrived, so an IDR per request costs two keyframes or more per lost picture: in one measured
//! session (290 ms round trip, ~14 Mbps, burst loss) 294 of 380 recoveries cost two, and 464 of 971
//! keyframes went out less than half a second after the one before. A keyframe is the largest thing
//! the pipeline sends, and a queue spike into a link that has just lost packets.
//!
//! A keyframe handed to the transport opens a window of
//!
//! ```text
//! window = clamp(rtt + (ahead + bytes) / drain + WINDOW_MARGIN, WINDOW_MIN, WINDOW_MAX)
//! ```
//!
//! and a viewer's request that arrives inside it is not honoured: it was sent before the keyframe
//! could arrive, so that keyframe answers it. `rtt` is the last receiver report's round trip,
//! `ahead` the bytes queued in front of the keyframe, `drain` [`crate::quality::drain_kbps`] (the
//! larger of measured egress and str0m's pacing rate, because a window too long costs more than one
//! too short). [`WINDOW_MARGIN`] covers the jitter the request crosses, [`WINDOW_MIN`] a short path,
//! [`WINDOW_MAX`] a stale gauge. Before the first receiver report the window is [`WINDOW_MIN`] flat.
//!
//! Only the browser's RTCP PLI/FIR (`afklink_transport::KeyframeAsk::Viewer`) is held. Not the Mini
//! App's `kf`, which comes at most every 2 s and is WebKit's way back from a frozen picture; not the
//! agent's own requests (`ChainBroken`, `PathRestored`, `PairMoved`, a drain's end, a new capture or
//! encoder), which say something sent before is unusable. Every keyframe opens the window.
//!
//! The window assumes the keyframe arrives whole. Evidence of trouble distrusts it
//! ([`KeyframeWindow::note_path`], [`KeyframeWindow::judge_with`]) and every later request is
//! honoured: a NACK since the keyframe went out (the transport's live count) or reported loss; a
//! lossy path before it ([`LOSSY_PATH_WHOLE`]); a receiver silent for [`SILENT_INTERVALS`] that
//! reports again; drain mode. A false alarm costs one keyframe.
//!
//! Decided on the encode thread, the one place that both makes keyframes and takes requests; the
//! event task only notes each PLI ([`ViewerAsks`]), so PLIs that land together coalesce. Logs: one
//! debug line a second at most while requests are held or a held one is re-asked (`kind="reask"`,
//! `kind="new_episode"`), debug for a distrusted window and receiver silence, trace for the rest,
//! `kf_suppressed` on the `pipeline` line, and the session's totals at the end.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::quality::{drain_kbps, queue_ms};
use crate::sync::lock;

/// The shortest window: one and a half of Chrome's 200 ms repeats, and a round trip a report
/// under-reads by its jitter. Also the whole window before the first receiver report: the formula
/// on an unmeasured drain priced a 54 kB start keyframe at 3.6 s of send time and held start-up
/// requests for the full cap.
pub const WINDOW_MIN: Duration = Duration::from_millis(300);

/// The longest window, whatever the gauges say: a collapsed estimate behind a megabyte of queue
/// would hold every request for seconds, and a keyframe that cannot leave in two seconds is the
/// queue breaker's business (`QUEUE_HARD_LIMIT_MS`), which asks for a keyframe of its own.
pub const WINDOW_MAX: Duration = Duration::from_secs(2);

/// Added to every window for the path's jitter, which a round-trip sample does not show and the
/// viewer's last repeat crosses too. Without it a simulated 290 ms path with 15 ms of jitter each
/// way (`scenarios/pli-repeat-290ms.toml`) let a repeat sent 11 ms before the keyframe arrived reach
/// the agent 1.4 ms after a 367 ms window. 50 ms is twice the measured p99 interarrival jitter
/// (26 ms); it delays a lost keyframe's retry by one 200 ms repeat at most.
pub const WINDOW_MARGIN: Duration = Duration::from_millis(50);

/// Stats intervals in a row without a receiver report, while frames went out, that make the
/// receiver *silent* for [`KeyframeWindow::note_path`]: the loss/round-trip brake's own count
/// (`quality::BRAKE_STALE_REPORTS`, "the earliest the stats clock can tell an outage from Chrome's
/// jitter"). One empty interval is Chrome's report timing; see the module documentation.
pub const SILENT_INTERVALS: u32 = 2;

/// [`PathNow::loss_bp`] for a stats interval that carried no receiver report, as
/// `SessionCounters::loss_bp` stores it.
pub const NO_REPORT: u32 = u32::MAX;

/// How many of the receiver's latest reports the path's recent loss is averaged over, for
/// [`LOSSY_PATH_WHOLE`]: ten, about ten seconds, the playout hold's own memory of loss
/// (`afklink_transport`'s `LOSS_MEMORY`). See the module documentation.
pub const LOSSY_PATH_REPORTS: usize = 10;

/// The chance of arriving without a retransmission under which a keyframe's window opens
/// distrusted: more likely damaged than whole. See the module documentation.
pub const LOSSY_PATH_WHOLE: f64 = 0.5;

/// The packet a keyframe is cut into, for [`LOSSY_PATH_WHOLE`], in bytes: str0m's 1150-byte MTU
/// (`afklink_transport`).
pub const KEYFRAME_PACKET_BYTES: u32 = 1_150;

/// How soon after the last request a window held the next one must come to be the viewer asking
/// again — its keyframe did not make it — rather than a new loss. Chrome repeats every 200 ms while
/// it waits; 1.5 s is the gap the playout cushion splits keyframe-request episodes on
/// (`afklink_transport`'s `KEYFRAME_EPISODE_GAP`). On a lossy 3G bench run 14 of 27 «honoured after
/// the window» lines came 3-31 s after their keyframe, new losses rather than failed keyframes;
/// real re-asks came 0.6-1.9 s after, a repeat or two after a held one.
pub const REASK_WITHIN: Duration = Duration::from_millis(1_500);

/// At most one line a second for each of the aggregated decisions.
const LINE_EVERY: Duration = Duration::from_secs(1);

/// The viewer's keyframe requests (its PLIs and FIRs) since the encode thread last took them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asked {
    pub first_at: Instant,
    /// What the window judges: if the latest is answered by a keyframe, so is every earlier one.
    pub last_at: Instant,
    pub count: u32,
}

impl Asked {
    /// One request.
    #[must_use]
    pub fn once(at: Instant) -> Self {
        Self {
            first_at: at,
            last_at: at,
            count: 1,
        }
    }

    fn add(&mut self, at: Instant) {
        self.first_at = self.first_at.min(at);
        self.last_at = self.last_at.max(at);
        self.count = self.count.saturating_add(1);
    }
}

/// Where the event task leaves the viewer's requests for the encode thread.
///
/// A flag for the encode thread's every-frame look, and the requests themselves behind a lock that
/// is taken only when the flag says there is something to take: a few times a second in a PLI
/// storm, never otherwise.
#[derive(Debug, Default)]
pub struct ViewerAsks {
    pending: AtomicBool,
    asked: Mutex<Option<Asked>>,
}

impl ViewerAsks {
    /// A viewer's request arrived at `at`.
    pub fn note(&self, at: Instant) {
        {
            let mut asked = lock(&self.asked);
            match asked.as_mut() {
                Some(a) => a.add(at),
                None => *asked = Some(Asked::once(at)),
            }
        }
        // After the requests are in: a reader that sees the flag finds them.
        self.pending.store(true, Ordering::Release);
    }

    /// Everything noted since the last take, or `None`.
    ///
    /// A note that lands between the flag's swap and the lock is taken now and leaves the flag set
    /// behind it, so the next take finds nothing: harmless.
    pub fn take(&self) -> Option<Asked> {
        if !self.pending.swap(false, Ordering::Acquire) {
            return None;
        }
        lock(&self.asked).take()
    }
}

/// What a keyframe's window is made of, read as the keyframe is handed to the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkNow {
    /// The last receiver report's round trip; `None` when str0m has reported none yet.
    pub rtt_ms: Option<u32>,
    /// What the send queue drains at, kbps. See the module documentation.
    pub drain_kbps: u32,
    /// Bytes queued in front of the keyframe: str0m's send queue and the media channel.
    pub ahead_bytes: u32,
    /// The NACKs the transport has counted this session, live
    /// (`afklink_transport::Peer::nacks_received`), as the keyframe is handed over: the window's
    /// baseline for [`KeyframeWindow::judge_with`]. `None` where nobody counts them live (the
    /// simulator), and the stats interval's count stands in ([`KeyframeWindow::note_path`]).
    pub nacks: Option<u64>,
}

impl LinkNow {
    /// From the gauges the encode thread holds: the round trip as `SessionCounters::rtt_ms` keeps
    /// it (`u32::MAX` for none, and `0`, its value before the first report — no path has a round
    /// trip of zero), the drain rate as the control task published it (`0` before its first tick,
    /// when str0m's estimate, paced, stands in for it — `quality::drain_kbps`), the estimate, and
    /// the bytes ahead.
    #[must_use]
    pub fn from_gauges(
        rtt_ms: u32,
        published_drain_kbps: u32,
        estimate_kbps: u32,
        ahead_bytes: u32,
    ) -> Self {
        Self {
            rtt_ms: (rtt_ms != u32::MAX && rtt_ms != 0).then_some(rtt_ms),
            drain_kbps: if published_drain_kbps > 0 {
                published_drain_kbps
            } else {
                drain_kbps(0, estimate_kbps)
            },
            ahead_bytes,
            nacks: None,
        }
    }

    /// The same, with the transport's live NACK count as the keyframe is handed over.
    #[must_use]
    pub fn with_nacks(self, nacks: u64) -> Self {
        Self {
            nacks: Some(nacks),
            ..self
        }
    }
}

/// What the encode thread reads of the path at a frame, for [`KeyframeWindow::note_path`]: the
/// receiver-report gauges as the event task stored them from str0m's stats (`SessionCounters`, once
/// a stats interval), and the frames the encode thread has handed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathNow {
    /// Stats intervals so far (`SessionCounters::link_reports`): the rest is read only when it moves.
    pub reports: u64,
    /// The last interval's fraction lost, in hundredths of a percent; [`NO_REPORT`] when it carried
    /// no receiver report (`SessionCounters::loss_bp`).
    pub loss_bp: u32,
    /// str0m's NACK count this session, as of the last interval (`SessionCounters::nacks`): the
    /// evidence for a window opened without the transport's live count ([`LinkNow::nacks`]).
    pub nacks: u64,
    /// Frames the encode thread has handed to the transport this session: an interval without a
    /// report counts as silence only if frames went out in it.
    pub frames_sent: u64,
}

/// Why a window was distrusted: what the path showed that its keyframe may not reach the viewer
/// whole. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Distrust {
    /// The transport's live NACK count (`LinkNow::nacks`) had moved, by `new`, since the keyframe
    /// went out, as a request was judged against its window.
    NackLive { new: u64 },
    /// str0m's NACK counter moved, by `new`, since the keyframe went out, as a stats interval read
    /// it — for a window opened without the live count.
    Nack { new: u64 },
    /// A receiver report since the keyframe went out lost `bp` hundredths of a percent.
    Loss { bp: u32 },
    /// The receiver was silent for `intervals` intervals around the keyframe, and reports again.
    Silence { intervals: u32 },
    /// Drain mode began while the window was open.
    Drain,
    /// The path's recent loss, `bp` hundredths of a percent on average, made the keyframe's
    /// `packets` more likely damaged than whole ([`LOSSY_PATH_WHOLE`]): distrusted as it opened.
    LossyPath { bp: u32, packets: u32 },
}

impl Distrust {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NackLive { .. } => "nack_live",
            Self::Nack { .. } => "nack",
            Self::Loss { .. } => "loss",
            Self::Silence { .. } => "silence",
            Self::Drain => "drain",
            Self::LossyPath { .. } => "lossy_path",
        }
    }
}

/// When and why a window was distrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Distrusted {
    pub why: Distrust,
    pub at: Instant,
}

/// The path as [`KeyframeWindow::note_path`] last read it.
#[derive(Debug, Clone, Copy)]
struct PathSeen {
    reports: u64,
    nacks: u64,
    frames_sent: u64,
    /// Intervals in a row without a receiver report while frames went out.
    silent_run: u32,
}

/// Where a window's round trip came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RttFrom {
    /// The last receiver report.
    Report,
    /// None now; the last one this session had.
    Remembered,
    /// None ever: the window is the send time alone, or [`WINDOW_MIN`].
    Unknown,
}

impl RttFrom {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Remembered => "remembered",
            Self::Unknown => "unknown",
        }
    }
}

/// The window one keyframe opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// When the keyframe was handed to the transport.
    pub sent_at: Instant,
    pub len: Duration,
    pub bytes: u32,
    pub rtt_ms: u32,
    pub rtt_from: RttFrom,
    /// `(ahead + bytes) / drain`: when its last byte leaves, after `sent_at`.
    pub send_ms: u32,
    pub ahead_bytes: u32,
    pub drain_kbps: u32,
    /// Whether the keyframe was asked for (a request, the viewer's or the agent's) rather than the
    /// encoder's own (the GOP, a new size, a new encoder).
    pub forced: bool,
    /// Viewer requests held against it so far, and when the last of them arrived.
    pub suppressed: u32,
    pub last_suppressed_at: Option<Instant>,
    /// The receiver was silent ([`SILENT_INTERVALS`]) when the keyframe went out, or went silent
    /// while the window was open, after `silent_intervals` intervals: the window is distrusted when
    /// it reports again. `0`: not silent.
    pub silent_intervals: u32,
    /// The transport's live NACK count as the keyframe went out ([`LinkNow::nacks`]): a request
    /// judged once it has moved is honoured ([`KeyframeWindow::judge_with`]). `None`: no live
    /// count, and the stats interval's stands in.
    pub nacks_at_send: Option<u64>,
    /// Distrusted on the path's evidence: every request judged against it since is honoured.
    pub distrusted: Option<Distrusted>,
}

impl Window {
    /// The first instant a request is honoured again.
    #[must_use]
    pub fn until(&self) -> Instant {
        self.sent_at + self.len
    }
}

/// The window a keyframe of `bytes` opens, and its send time in ms: see the module documentation.
#[must_use]
pub fn window_len(bytes: u32, rtt_ms: u32, drain_kbps: u32, ahead_bytes: u32) -> (Duration, u32) {
    let send_ms = queue_ms(ahead_bytes.saturating_add(bytes), drain_kbps);
    let raw = Duration::from_millis(u64::from(rtt_ms) + u64::from(send_ms)) + WINDOW_MARGIN;
    (raw.clamp(WINDOW_MIN, WINDOW_MAX), send_ms)
}

/// What [`KeyframeWindow::judge`] decided for the requests it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No keyframe sent answers them: force one.
    Honour,
    /// The last keyframe answers them: nothing is forced for them.
    Suppressed,
    /// A keyframe is forced at this frame for another reason; they ride on it.
    Joined,
}

/// The session's count of requests by verdict, and of the windows they were judged against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Keyframes handed to the transport, each of which opened a window.
    pub keyframes: u64,
    pub honoured: u64,
    pub suppressed: u64,
    pub joined: u64,
    /// Of `honoured`: those that came after a window that had held some, within [`REASK_WITHIN`] of
    /// the last one held — the viewer kept asking, so that keyframe, or a packet of it, did not make
    /// it.
    pub after_window: u64,
    /// Of `honoured`: those after a window that had held some, but long after the last one held —
    /// a new loss, not that keyframe failing.
    pub new_episodes: u64,
    /// Windows distrusted on the path's evidence before they ran out ([`KeyframeWindow::note_path`],
    /// [`KeyframeWindow::judge_with`]).
    pub distrusted: u64,
    /// Of `distrusted`: those let go on the transport's live NACK count, as a request was judged
    /// ([`Distrust::NackLive`]).
    pub distrusted_live: u64,
    /// Of `honoured`: those inside a window, honoured because it was distrusted.
    pub distrusted_honoured: u64,
}

/// `Some(lines held back since the last one)` when a line may be written now; at most one a second.
#[derive(Debug, Default)]
struct LineGate {
    last: Option<Instant>,
    held: u32,
}

impl LineGate {
    fn ready(&mut self, now: Instant) -> Option<u32> {
        if self
            .last
            .is_none_or(|t| now.saturating_duration_since(t) >= LINE_EVERY)
        {
            self.last = Some(now);
            Some(std::mem::take(&mut self.held))
        } else {
            self.held = self.held.saturating_add(1);
            None
        }
    }
}

/// The encode thread's half: the window the last keyframe opened, and the verdicts against it. See
/// the module documentation.
#[derive(Debug, Default)]
pub struct KeyframeWindow {
    open: Option<Window>,
    last_rtt_ms: Option<u32>,
    /// The path as last read; `None` before the first read, which is the baseline.
    path: Option<PathSeen>,
    /// The fraction lost of the receiver's latest reports, at most [`LOSSY_PATH_REPORTS`], in
    /// hundredths of a percent.
    recent_loss: VecDeque<u32>,
    totals: Totals,
    suppressed_line: LineGate,
    after_window_line: LineGate,
    distrust_line: LineGate,
    distrusted_honoured_line: LineGate,
}

impl KeyframeWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A keyframe of `bytes` was handed to the transport at `now`: it opens the window, replacing
    /// the last one. `forced` — it was asked for (see [`Window::forced`]).
    pub fn keyframe_sent(
        &mut self,
        now: Instant,
        bytes: usize,
        link: LinkNow,
        forced: bool,
    ) -> Window {
        let (rtt_ms, rtt_from) = match (link.rtt_ms, self.last_rtt_ms) {
            (Some(r), _) => {
                self.last_rtt_ms = Some(r);
                (r, RttFrom::Report)
            }
            (None, Some(r)) => (r, RttFrom::Remembered),
            (None, None) => (0, RttFrom::Unknown),
        };
        let bytes = u32::try_from(bytes).unwrap_or(u32::MAX);
        let (formula_len, send_ms) = window_len(bytes, rtt_ms, link.drain_kbps, link.ahead_bytes);
        // No round trip measured yet: the floor, not a send time priced on a drain nothing has
        // measured either (module documentation; q5 3g-f-r3 held two start-up requests 2 s).
        let len = if rtt_from == RttFrom::Unknown {
            WINDOW_MIN
        } else {
            formula_len
        };
        // Sent into a silent receiver: distrusted when it reports again (module documentation).
        let silent_run = self.path.map_or(0, |p| p.silent_run);
        let silent_intervals = if silent_run >= SILENT_INTERVALS {
            silent_run
        } else {
            0
        };
        // Sent into a lossy path: more likely damaged than whole, so nothing is held against it.
        let (loss_bp, packets, whole) = self.chance_whole(bytes);
        let lossy = whole.is_some_and(|p| p < LOSSY_PATH_WHOLE);
        let distrusted = lossy.then_some(Distrusted {
            why: Distrust::LossyPath {
                bp: loss_bp.unwrap_or(0),
                packets,
            },
            at: now,
        });
        let w = Window {
            sent_at: now,
            len,
            bytes,
            rtt_ms,
            rtt_from,
            send_ms,
            ahead_bytes: link.ahead_bytes,
            drain_kbps: link.drain_kbps,
            forced,
            suppressed: 0,
            last_suppressed_at: None,
            silent_intervals,
            nacks_at_send: link.nacks,
            distrusted,
        };
        // A keyframe a second at most outside a storm, a few in one: the window's inputs are on
        // the debug lines of the requests it holds; here only for a trace.
        tracing::trace!(
            window_ms = len.as_millis() as u64,
            formula_ms = formula_len.as_millis() as u64,
            rtt_ms,
            rtt_from = rtt_from.as_str(),
            keyframe_bytes = bytes,
            ahead_bytes = link.ahead_bytes,
            drain_kbps = link.drain_kbps,
            send_ms,
            forced,
            sent_into_silence_intervals = silent_intervals,
            nacks_at_send = ?link.nacks,
            recent_loss_bp = ?loss_bp,
            packets,
            chance_whole = ?whole,
            replaced_suppressed = self.open.map_or(0, |o| o.suppressed),
            replaced_distrusted = ?self.open.and_then(|o| o.distrusted).map(|d| d.why.as_str()),
            "keyframe window opened: viewer keyframe requests arriving before its end are answered \
             by this keyframe"
        );
        self.open = Some(w);
        self.totals.keyframes += 1;
        if lossy {
            self.totals.distrusted += 1;
            if let Some(held_back) = self.distrust_line.ready(now) {
                tracing::debug!(
                    why = "lossy_path",
                    recent_loss_bp = ?loss_bp,
                    reports = self.recent_loss.len(),
                    packets,
                    chance_whole = ?whole,
                    needed = LOSSY_PATH_WHOLE,
                    window_ms = len.as_millis() as u64,
                    rtt_ms,
                    keyframe_bytes = bytes,
                    keyframe_forced = forced,
                    lines_held_back = held_back,
                    distrusted_total = self.totals.distrusted,
                    "keyframe window distrusted as it opens: the path's recent loss makes this \
                     keyframe more likely damaged than whole, so the viewer's requests are honoured \
                     until a keyframe opens a window on a cleaner path"
                );
            }
        }
        w
    }

    /// The path's recent loss — the mean fraction lost of the receiver's last
    /// [`LOSSY_PATH_REPORTS`] reports, in hundredths of a percent — the packets a keyframe of
    /// `bytes` is cut into, and the chance it arrives with none of them lost, `(1 - lost)^packets`.
    /// `None` for both before any report.
    fn chance_whole(&self, bytes: u32) -> (Option<u32>, u32, Option<f64>) {
        let packets = bytes.div_ceil(KEYFRAME_PACKET_BYTES).max(1);
        let n = self.recent_loss.len();
        if n == 0 {
            return (None, packets, None);
        }
        let sum: u64 = self.recent_loss.iter().map(|&bp| u64::from(bp)).sum();
        let mean_bp = u32::try_from(sum / n as u64).unwrap_or(u32::MAX);
        let lost = (f64::from(mean_bp) / 10_000.0).clamp(0.0, 1.0);
        let whole = (1.0 - lost).powi(i32::try_from(packets).unwrap_or(i32::MAX));
        (Some(mean_bp), packets, Some(whole))
    }

    /// Judge the viewer's requests the encode thread took at `now`, for a frame that is forced
    /// anyway (`forced_anyway`: the agent's own pending keyframe, or the Mini App's `kf`) or not,
    /// with no live NACK count: see [`Self::judge_with`].
    pub fn judge(&mut self, now: Instant, asked: Asked, forced_anyway: bool) -> Verdict {
        self.judge_with(now, asked, forced_anyway, None)
    }

    /// [`Self::judge`], with the transport's live NACK count (`live_nacks`, from
    /// `afklink_transport::Peer::nacks_received`) read as the requests are judged — after they were
    /// taken, so it holds every NACK that arrived before them. A request inside a window whose
    /// keyframe went out at a lower count is honoured: the window is distrusted
    /// ([`Distrust::NackLive`]) at once, not at the next stats interval (module documentation, "When
    /// the keyframe on its way cannot be trusted"). Every verdict is counted; see the module
    /// documentation for what is logged.
    pub fn judge_with(
        &mut self,
        now: Instant,
        asked: Asked,
        forced_anyway: bool,
        live_nacks: Option<u64>,
    ) -> Verdict {
        let n = asked.count;
        if forced_anyway {
            self.totals.joined += u64::from(n);
            tracing::trace!(
                requests = n,
                "viewer keyframe requests ride on a keyframe forced for another reason"
            );
            return Verdict::Joined;
        }
        let Some(w) = self.open.as_mut() else {
            self.totals.honoured += u64::from(n);
            tracing::trace!(
                requests = n,
                "viewer keyframe request honoured: no keyframe sent yet"
            );
            return Verdict::Honour;
        };
        let until = w.until();
        // Signed in effect: a request that arrived while the keyframe was being encoded reads 0
        // and `before_keyframe`.
        let since_ms = asked
            .last_at
            .saturating_duration_since(w.sent_at)
            .as_millis() as u64;
        // The NACKs since the keyframe went out, as the transport counted them up to now; `None`
        // without a live count on either side.
        let nacks_since = w
            .nacks_at_send
            .zip(live_nacks)
            .map(|(at_send, seen)| seen.saturating_sub(at_send));
        if asked.last_at < until {
            if let Some(new) = nacks_since.filter(|&new| new > 0 && w.distrusted.is_none()) {
                // Judged inside the window, whatever the clock says now: a request that waited
                // for a frame past the window's end is still one the window would hold.
                Self::mark_distrusted(
                    w,
                    &mut self.totals,
                    &mut self.distrust_line,
                    now,
                    Distrust::NackLive { new },
                );
            }
            if let Some(d) = w.distrusted {
                // The path said the keyframe may not make it: honoured, as every request was
                // before the window existed (module documentation).
                self.totals.honoured += u64::from(n);
                self.totals.distrusted_honoured += u64::from(n);
                if let Some(held_back) = self.distrusted_honoured_line.ready(now) {
                    tracing::debug!(
                        requests = n,
                        since_keyframe_ms = since_ms,
                        why = d.why.as_str(),
                        distrusted_ms_ago = now.saturating_duration_since(d.at).as_millis() as u64,
                        window_ms = w.len.as_millis() as u64,
                        rtt_ms = w.rtt_ms,
                        keyframe_bytes = w.bytes,
                        suppressed_in_window = w.suppressed,
                        nacks_since_keyframe = ?nacks_since,
                        lines_held_back = held_back,
                        distrusted_honoured_total = self.totals.distrusted_honoured,
                        "viewer keyframe request honoured inside the last keyframe's window: the \
                         window was distrusted on the path's evidence, so that keyframe cannot be \
                         counted on to answer it"
                    );
                }
                return Verdict::Honour;
            }
            w.suppressed = w.suppressed.saturating_add(n);
            w.last_suppressed_at = Some(
                w.last_suppressed_at
                    .map_or(asked.last_at, |at| at.max(asked.last_at)),
            );
            self.totals.suppressed += u64::from(n);
            if let Some(held_back) = self.suppressed_line.ready(now) {
                tracing::debug!(
                    requests = n,
                    since_keyframe_ms = since_ms,
                    before_keyframe = asked.last_at < w.sent_at,
                    window_ms = w.len.as_millis() as u64,
                    rtt_ms = w.rtt_ms,
                    rtt_from = w.rtt_from.as_str(),
                    keyframe_bytes = w.bytes,
                    ahead_bytes = w.ahead_bytes,
                    drain_kbps = w.drain_kbps,
                    send_ms = w.send_ms,
                    keyframe_forced = w.forced,
                    suppressed_in_window = w.suppressed,
                    nacks_since_keyframe = ?nacks_since,
                    lines_held_back = held_back,
                    suppressed_total = self.totals.suppressed,
                    "viewer keyframe request not honoured: it left the viewer before the last \
                     keyframe could reach it, so that keyframe answers it (window = round trip + \
                     the keyframe's send time)"
                );
            }
            return Verdict::Suppressed;
        }
        self.totals.honoured += u64::from(n);
        if let Some(held_at) = w.last_suppressed_at {
            // The viewer asking again — a repeat or two after one held — or a new loss long after.
            let since_held = asked.last_at.saturating_duration_since(held_at);
            let reask = since_held < REASK_WITHIN;
            if reask {
                self.totals.after_window += u64::from(n);
            } else {
                self.totals.new_episodes += u64::from(n);
            }
            if let Some(held_back) = self.after_window_line.ready(now) {
                tracing::debug!(
                    kind = if reask { "reask" } else { "new_episode" },
                    requests = n,
                    since_keyframe_ms = since_ms,
                    since_last_held_ms = since_held.as_millis() as u64,
                    reask_within_ms = REASK_WITHIN.as_millis() as u64,
                    window_ms = w.len.as_millis() as u64,
                    past_window_ms = since_ms.saturating_sub(w.len.as_millis() as u64),
                    rtt_ms = w.rtt_ms,
                    rtt_from = w.rtt_from.as_str(),
                    keyframe_bytes = w.bytes,
                    send_ms = w.send_ms,
                    suppressed_in_window = w.suppressed,
                    lines_held_back = held_back,
                    after_window_total = self.totals.after_window,
                    new_episodes_total = self.totals.new_episodes,
                    "viewer keyframe request honoured after the last keyframe's window: {}",
                    if reask {
                        "the viewer still asks a repeat or two after a request the window held, \
                         so that keyframe, or a packet of it, did not make it"
                    } else {
                        "long after the last request the window held, so a new loss rather than \
                         that keyframe failing"
                    }
                );
            }
        } else {
            tracing::trace!(
                requests = n,
                since_keyframe_ms = since_ms,
                window_ms = w.len.as_millis() as u64,
                "viewer keyframe request honoured: past the last keyframe's window"
            );
        }
        Verdict::Honour
    }

    /// The path at this frame (see [`PathNow`]), on every frame that may take requests: each new
    /// stats interval is read once and may distrust the open window — loss since its keyframe went
    /// out (NACKs only for a window opened without the live count, [`LinkNow::nacks`]), or a silent
    /// receiver that reports again (module documentation, "When the keyframe on its way cannot be
    /// trusted"). Every other frame costs a comparison. The first read is the baseline: nothing
    /// before it is evidence about any keyframe.
    pub fn note_path(&mut self, now: Instant, p: PathNow) {
        let Some(seen) = self.path else {
            tracing::trace!(
                reports = p.reports,
                nacks = p.nacks,
                "keyframe window: the path's gauges, first read, taken as the baseline"
            );
            self.path = Some(PathSeen {
                reports: p.reports,
                nacks: p.nacks,
                frames_sent: p.frames_sent,
                silent_run: 0,
            });
            return;
        };
        if p.reports == seen.reports {
            return;
        }
        let sent = p.frames_sent > seen.frames_sent;
        let silent = p.loss_bp == NO_REPORT;
        let new_nacks = p.nacks.saturating_sub(seen.nacks);
        // An interval without a report counts only while frames went out (a still screen gives the
        // receiver nothing to report on), as the brake counts it; anything else ends the run.
        let silent_run = if silent && sent {
            seen.silent_run.saturating_add(1)
        } else {
            0
        };
        self.path = Some(PathSeen {
            reports: p.reports,
            nacks: p.nacks,
            frames_sent: p.frames_sent,
            silent_run,
        });
        // Trace: once a stats interval.
        tracing::trace!(
            reports = p.reports,
            silent,
            sent,
            silent_run,
            loss_bp = ?(!silent).then_some(p.loss_bp),
            new_nacks,
            window_open = self.open.is_some(),
            window_counts_nacks_live = ?self.open.map(|w| w.nacks_at_send.is_some()),
            "keyframe window: a stats interval read"
        );
        if silent_run == SILENT_INTERVALS {
            // Once a silence: the line the distrust that follows refers back to.
            tracing::debug!(
                intervals = silent_run,
                needed = SILENT_INTERVALS,
                window_open = ?self.open.map(|w| now < w.until()),
                "keyframe window: the receiver has reported nothing for these intervals while frames \
                 went out (a stall, or an outage); a keyframe sent into it, or just before it, is \
                 not trusted to answer the viewer's requests once it reports again"
            );
        }
        if !silent {
            // The path's recent loss, for the windows the next keyframes open.
            self.recent_loss.push_back(p.loss_bp);
            while self.recent_loss.len() > LOSSY_PATH_REPORTS {
                self.recent_loss.pop_front();
            }
        }
        // A window opened with the transport's live count judges NACKs by it, as each request is
        // judged (`Self::judge_with`): the interval's count would add only the ones from before its
        // keyframe went out.
        let live = self.open.is_some_and(|w| w.nacks_at_send.is_some());
        if new_nacks > 0 && !live {
            self.distrust(now, Distrust::Nack { new: new_nacks });
        } else if !silent && p.loss_bp > 0 {
            self.distrust(now, Distrust::Loss { bp: p.loss_bp });
        }
        if silent_run >= SILENT_INTERVALS {
            if let Some(w) = self.open.as_mut() {
                if now < w.until() && w.silent_intervals == 0 {
                    w.silent_intervals = silent_run;
                }
            }
        } else if !silent {
            if seen.silent_run >= SILENT_INTERVALS {
                tracing::debug!(
                    silent_intervals = seen.silent_run,
                    loss_bp = p.loss_bp,
                    new_nacks,
                    "keyframe window: the receiver reports again after a silence"
                );
            }
            let silent_before = self.open.map_or(0, |w| w.silent_intervals);
            if silent_before > 0 {
                self.distrust(
                    now,
                    Distrust::Silence {
                        intervals: silent_before,
                    },
                );
            }
        }
    }

    /// Drain mode began, at the first frame the encode loop withheld for it: the open window, if
    /// any, is distrusted (module documentation).
    pub fn note_drain(&mut self, now: Instant) {
        self.distrust(now, Distrust::Drain);
    }

    /// The open window stops holding requests: its keyframe went into a path that showed `why`.
    /// Once a window, the first evidence named; nothing for a window already past.
    fn distrust(&mut self, now: Instant, why: Distrust) {
        let Some(w) = self.open.as_mut() else {
            tracing::trace!(
                why = why.as_str(),
                "keyframe window: path evidence with no keyframe sent yet"
            );
            return;
        };
        if let Some(d) = w.distrusted {
            tracing::trace!(
                why = why.as_str(),
                already = d.why.as_str(),
                "keyframe window: more path evidence against a window already distrusted"
            );
            return;
        }
        let until = w.until();
        if now >= until {
            tracing::trace!(
                why = why.as_str(),
                past_ms = now.saturating_duration_since(until).as_millis() as u64,
                "keyframe window: path evidence after the last keyframe's window ran out: nothing \
                 held to let go"
            );
            return;
        }
        Self::mark_distrusted(w, &mut self.totals, &mut self.distrust_line, now, why);
    }

    /// `w` stops holding requests, on `why`: counted, and a line at most a second. Its own
    /// function, on the fields it needs, so [`Self::judge_with`] can call it holding the window.
    fn mark_distrusted(
        w: &mut Window,
        totals: &mut Totals,
        line: &mut LineGate,
        now: Instant,
        why: Distrust,
    ) {
        w.distrusted = Some(Distrusted { why, at: now });
        totals.distrusted += 1;
        if matches!(why, Distrust::NackLive { .. }) {
            totals.distrusted_live += 1;
        }
        let (new_nacks, loss_bp, silent_intervals) = match why {
            Distrust::NackLive { new } | Distrust::Nack { new } => (Some(new), None, None),
            Distrust::Loss { bp } | Distrust::LossyPath { bp, .. } => (None, Some(bp), None),
            Distrust::Silence { intervals } => (None, None, Some(intervals)),
            Distrust::Drain => (None, None, None),
        };
        if let Some(held_back) = line.ready(now) {
            tracing::debug!(
                why = why.as_str(),
                new_nacks = ?new_nacks,
                nacks_at_send = ?w.nacks_at_send,
                loss_bp = ?loss_bp,
                silent_intervals = ?silent_intervals,
                keyframe_age_ms = now.saturating_duration_since(w.sent_at).as_millis() as u64,
                window_ms = w.len.as_millis() as u64,
                left_ms = w.until().saturating_duration_since(now).as_millis() as u64,
                rtt_ms = w.rtt_ms,
                rtt_from = w.rtt_from.as_str(),
                keyframe_bytes = w.bytes,
                keyframe_forced = w.forced,
                suppressed_in_window = w.suppressed,
                lines_held_back = held_back,
                distrusted_total = totals.distrusted,
                distrusted_live_total = totals.distrusted_live,
                "keyframe window distrusted: the path showed trouble around the last keyframe, so it \
                 may not reach the viewer whole; the viewer's requests are honoured until the next \
                 keyframe opens a window (nack_live: NACKs the transport counted since the keyframe \
                 went out, read as a request was judged)"
            );
        }
    }

    /// The window the last keyframe opened, if any keyframe was sent.
    #[must_use]
    pub fn open(&self) -> Option<Window> {
        self.open
    }

    #[must_use]
    pub fn totals(&self) -> Totals {
        self.totals
    }

    /// The session's totals, once, as the encode loop ends.
    pub fn finish(&self) {
        let t = self.totals;
        tracing::debug!(
            keyframes = t.keyframes,
            honoured = t.honoured,
            suppressed = t.suppressed,
            joined = t.joined,
            after_window = t.after_window,
            new_episodes = t.new_episodes,
            distrusted = t.distrusted,
            distrusted_live = t.distrusted_live,
            distrusted_honoured = t.distrusted_honoured,
            "viewer keyframe requests: session totals (suppressed: answered by a keyframe already \
             on its way; after_window: the viewer asking again once its window had passed; \
             new_episodes: a new loss after a window that had held some; distrusted: windows let go \
             on the path's evidence — distrusted_live of them on the NACKs the transport counted \
             live — and the requests honoured inside them)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    /// A measured session's path: 290 ms round trip, ~11 Mbps of egress, nothing queued ahead; no
    /// live NACK count (the stats interval's stands in).
    fn session_link() -> LinkNow {
        LinkNow {
            rtt_ms: Some(290),
            drain_kbps: 11_000,
            ahead_bytes: 0,
            nacks: None,
        }
    }

    /// The session's mean keyframe.
    const KF_BYTES: usize = 111_000;

    #[test]
    fn the_sessions_numbers_make_a_window_of_420_ms() {
        // 111 kB at 11 Mbps leave in 80 ms (`queue_ms` truncates 80.7); 290 + 80 + the margin.
        assert_eq!(window_len(111_000, 290, 11_000, 0), (ms(420), 80));
        // Bytes ahead of the keyframe leave first: 426 ms of the session's queue at 11 Mbps is
        // ~586 kB, and the window grows by its drain.
        assert_eq!(window_len(111_000, 290, 11_000, 586_000).1, 506);
        // Floored at WINDOW_MIN on a short path, capped at WINDOW_MAX however stale the gauges.
        assert_eq!(window_len(20_000, 6, 50_000, 0).0, WINDOW_MIN);
        assert_eq!(window_len(1_000_000, 290, 120, 0).0, WINDOW_MAX);
        // A drain of 0 (nothing known) is floored by `queue_ms`, not divided by.
        assert_eq!(window_len(111_000, 290, 0, 0).0, WINDOW_MAX);
    }

    #[test]
    fn chromes_repeat_at_200_ms_is_answered_by_the_keyframe_in_flight() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        // The first PLI finds no window: honoured, and its keyframe opens one.
        assert_eq!(w.judge(t0, Asked::once(t0), false), Verdict::Honour);
        let kf_at = t0 + ms(20);
        let opened = w.keyframe_sent(kf_at, KF_BYTES, session_link(), true);
        assert_eq!(opened.len, ms(420));
        assert_eq!(opened.until(), kf_at + ms(420));
        // Chrome's repeat, 200 ms after the first: it left before the keyframe could arrive.
        let repeat = kf_at + ms(200);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
        // And one that lands while that keyframe was still being encoded is answered by it too.
        let mut w2 = KeyframeWindow::new();
        w2.keyframe_sent(kf_at, KF_BYTES, session_link(), true);
        let early = kf_at - ms(5);
        assert_eq!(
            w2.judge(kf_at + ms(1), Asked::once(early), false),
            Verdict::Suppressed
        );
        let t = w.totals();
        assert_eq!((t.honoured, t.suppressed, t.keyframes), (1, 1, 1));
    }

    #[test]
    fn a_request_after_the_window_is_honoured_the_keyframe_may_be_lost() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        let repeat = t0 + ms(200);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
        // 700 ms on, past the 420 ms window: the viewer still asks, so the keyframe did not make it.
        let late = t0 + ms(700);
        assert_eq!(w.judge(late, Asked::once(late), false), Verdict::Honour);
        // The first instant past the window is already past it.
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        let edge = t0 + ms(420);
        assert_eq!(w.judge(edge, Asked::once(edge), false), Verdict::Honour);
        let t = w.totals();
        assert_eq!(
            (t.honoured, t.after_window),
            (1, 0),
            "nothing held before it"
        );
    }

    #[test]
    fn honoured_after_a_window_that_held_requests_is_counted_apart() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        for at in [t0 + ms(200), t0 + ms(250)] {
            assert_eq!(w.judge(at, Asked::once(at), false), Verdict::Suppressed);
        }
        assert_eq!(w.open().map(|o| o.suppressed), Some(2));
        let late = t0 + ms(450);
        assert_eq!(w.judge(late, Asked::once(late), false), Verdict::Honour);
        let t = w.totals();
        assert_eq!((t.suppressed, t.honoured, t.after_window), (2, 1, 1));
    }

    #[test]
    fn a_keyframe_forced_for_another_reason_opens_the_window_too() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        // A drain's end, a restarted capture, the transport's broken chain, the Mini App's `kf`:
        // a keyframe never held. A PLI that arrives just after it is answered by it.
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        let pli = t0 + ms(50);
        assert_eq!(w.judge(pli, Asked::once(pli), false), Verdict::Suppressed);
        // The GOP's keyframe, or a new size's, that nobody asked for: the same.
        let gop = t0 + ms(5_000);
        w.keyframe_sent(gop, KF_BYTES, session_link(), false);
        let pli = gop + ms(100);
        assert_eq!(w.judge(pli, Asked::once(pli), false), Verdict::Suppressed);
        assert_eq!(w.open().map(|o| o.forced), Some(false));
    }

    #[test]
    fn requests_taken_at_a_forced_frame_ride_on_it() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        // Inside a window or not, a frame that is forced anyway answers them: no second keyframe,
        // and they are not counted as held either.
        assert_eq!(w.judge(t0, Asked::once(t0), true), Verdict::Joined);
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        let at = t0 + ms(100);
        assert_eq!(w.judge(at, Asked::once(at), true), Verdict::Joined);
        let t = w.totals();
        assert_eq!((t.joined, t.suppressed, t.honoured), (2, 0, 0));
    }

    #[test]
    fn the_latest_of_coalesced_requests_decides() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        // Two requests waited for one frame (a still screen): one inside the window, one after.
        // The later says the keyframe did not make it, so a keyframe is forced for both.
        let asks = ViewerAsks::default();
        asks.note(t0 + ms(200));
        asks.note(t0 + ms(600));
        let asked = asks.take().expect("two requests");
        assert_eq!(asked.count, 2);
        assert_eq!(asked.first_at, t0 + ms(200));
        assert_eq!(asked.last_at, t0 + ms(600));
        assert!(asks.take().is_none(), "taken once");
        assert_eq!(w.judge(t0 + ms(610), asked, false), Verdict::Honour);
        assert_eq!(w.totals().honoured, 2);
    }

    #[test]
    fn a_round_trip_missing_now_is_the_last_one_known() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        let none = LinkNow {
            rtt_ms: None,
            ..session_link()
        };
        // None ever: the floor.
        let first = w.keyframe_sent(t0, KF_BYTES, none, true);
        assert_eq!((first.rtt_from, first.len), (RttFrom::Unknown, WINDOW_MIN));
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        let again = w.keyframe_sent(t0, KF_BYTES, none, true);
        assert_eq!(
            (again.rtt_from, again.rtt_ms, again.len),
            (RttFrom::Remembered, 290, ms(420))
        );
    }

    #[test]
    fn the_gauges_say_none_and_not_yet_as_the_agent_stores_them() {
        // `SessionCounters::rtt_ms` keeps `u32::MAX` for "no report"; before the control task's
        // first tick nothing is published, and str0m's estimate, paced, stands in.
        let l = LinkNow::from_gauges(u32::MAX, 0, 13_700, 5_000);
        assert_eq!(l.rtt_ms, None);
        assert_eq!(LinkNow::from_gauges(0, 0, 0, 0).rtt_ms, None, "the default");
        assert_eq!(l.drain_kbps, drain_kbps(0, 13_700));
        assert_eq!(l.drain_kbps, 15_070);
        assert_eq!(l.ahead_bytes, 5_000);
        // The live NACK count is the transport's, added where it is counted.
        assert_eq!(l.nacks, None);
        assert_eq!(
            l.with_nacks(7),
            LinkNow {
                nacks: Some(7),
                ..l
            }
        );
        let l = LinkNow::from_gauges(290, 11_000, 13_700, 0);
        assert_eq!((l.rtt_ms, l.drain_kbps), (Some(290), 11_000));
    }

    /// The path's gauges at a frame: `reports` stats intervals so far, the last one's loss
    /// (`None`: no receiver report in it), the NACKs so far, the frames sent so far.
    fn path(reports: u64, loss_bp: Option<u32>, nacks: u64, frames_sent: u64) -> PathNow {
        PathNow {
            reports,
            loss_bp: loss_bp.unwrap_or(NO_REPORT),
            nacks,
            frames_sent,
        }
    }

    /// A bench run with a stalled egress: it held everything for 2.3 s and the receiver reported
    /// nothing for three intervals while frames went out. A keyframe went out into that silence
    /// (58,640 bytes; the window on the round trip from before it, 299 ms, and 17.5 Mbps: 375 ms).
    /// The viewer's request 65 ms after it, sent before it could arrive, is held as before; the
    /// report that ends the silence distrusts the window, and the request the viewer sent once it
    /// had decoded that keyframe, which the window held (the picture then froze 2.17 s), is honoured.
    #[test]
    fn a_keyframe_sent_into_a_silent_receiver_is_not_trusted_once_it_reports_again() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(10, Some(0), 0, 600));
        // Three intervals without a report, frames going out in each.
        w.note_path(t0 + ms(1_000), path(11, None, 0, 660));
        w.note_path(t0 + ms(2_000), path(12, None, 0, 720));
        w.note_path(t0 + ms(3_000), path(13, None, 0, 780));
        let link = LinkNow {
            rtt_ms: Some(299),
            drain_kbps: 17_521,
            ahead_bytes: 0,
            nacks: None,
        };
        let kf = t0 + ms(3_200);
        let opened = w.keyframe_sent(kf, 58_640, link, false);
        assert_eq!(opened.len, ms(375));
        assert_eq!(opened.silent_intervals, 3, "sent into the silence");
        let early = kf + ms(65);
        assert_eq!(
            w.judge(early, Asked::once(early), false),
            Verdict::Suppressed,
            "sent before the keyframe could arrive, and the receiver still silent: held"
        );
        // The first report after the silence (its round trip 842 ms, the stall's).
        w.note_path(kf + ms(300), path(14, Some(0), 0, 800));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Silence { intervals: 3 })
        );
        let after = kf + ms(345);
        assert!(
            after < opened.until(),
            "inside the window, which held it before"
        );
        assert_eq!(w.judge(after, Asked::once(after), false), Verdict::Honour);
        let t = w.totals();
        assert_eq!(
            (
                t.suppressed,
                t.honoured,
                t.distrusted,
                t.distrusted_honoured
            ),
            (1, 1, 1, 1)
        );
        // The keyframe that answers it opens a window of its own, trusted: the receiver reports.
        let next = w.keyframe_sent(after + ms(5), 60_318, link, true);
        assert_eq!((next.silent_intervals, next.distrusted), (0, None));
        let repeat = after + ms(205);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
    }

    /// A bench run on a lossy path: a keyframe (75,729 bytes, 304 ms, 10.5 Mbps: a 411 ms window) went
    /// into a NACK burst whose retransmissions were lost too; its repeats were held and the viewer
    /// asked again 604 ms after it. For a window opened without the live NACK count, the stats
    /// interval that shows the NACKs distrusts it, so the repeat after it is honoured; the one before
    /// it is still held. A report that lost packets without a NACK in it does the same.
    #[test]
    fn loss_since_the_keyframe_went_out_distrusts_its_window() {
        let t0 = Instant::now();
        let link = LinkNow {
            rtt_ms: Some(304),
            drain_kbps: 10_487,
            ahead_bytes: 0,
            nacks: None,
        };
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(20, Some(0), 40, 1_200));
        let opened = w.keyframe_sent(t0 + ms(100), 75_729, link, true);
        assert_eq!(opened.len, ms(411));
        let held = t0 + ms(283);
        assert_eq!(w.judge(held, Asked::once(held), false), Verdict::Suppressed);
        // The next stats interval: 13 more NACKs.
        w.note_path(t0 + ms(400), path(21, Some(0), 53, 1_260));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Nack { new: 13 })
        );
        let repeat = t0 + ms(483);
        assert_eq!(w.judge(repeat, Asked::once(repeat), false), Verdict::Honour);

        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(20, Some(0), 40, 1_200));
        w.keyframe_sent(t0 + ms(100), 75_729, link, true);
        // 0.4% lost, the NACK count unchanged.
        w.note_path(t0 + ms(400), path(21, Some(40), 40, 1_260));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Loss { bp: 40 })
        );
        let repeat = t0 + ms(483);
        assert_eq!(w.judge(repeat, Asked::once(repeat), false), Verdict::Honour);
    }

    /// A bench run on 3G: a keyframe of ~7 kB on a 1303 ms round trip at ~300 kbps, a 1539 ms
    /// window; the viewer's repeat 289 ms on came in a second of 22 NACKs that the stats interval
    /// reported only 266 ms later. With the transport's live count the request that comes after a
    /// NACK is honoured at once, one with none since the keyframe went out is held, the NACKs from
    /// before it are not its evidence, and the stats interval's NACKs do not let such a window go
    /// (its fraction lost does).
    #[test]
    fn a_nack_counted_live_since_the_keyframe_lets_the_next_request_through() {
        let t0 = Instant::now();
        let link = LinkNow {
            rtt_ms: Some(1_303),
            drain_kbps: 300,
            ahead_bytes: 0,
            nacks: None,
        };
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(60, Some(0), 400, 3_000));
        // 400 NACKs before it went out: the loss that made the viewer ask.
        let opened = w.keyframe_sent(t0, 7_000, link.with_nacks(400), true);
        assert_eq!((opened.len, opened.nacks_at_send), (ms(1_539), Some(400)));
        // No NACK since: held, as the window was built for.
        let early = t0 + ms(150);
        assert_eq!(
            w.judge_with(early, Asked::once(early), false, Some(400)),
            Verdict::Suppressed
        );
        // Three since, by the request 289 ms on: honoured, no stats interval needed.
        let held_on_q6 = t0 + ms(289);
        assert_eq!(
            w.judge_with(held_on_q6, Asked::once(held_on_q6), false, Some(403)),
            Verdict::Honour
        );
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::NackLive { new: 3 })
        );
        let t = w.totals();
        assert_eq!(
            (
                t.suppressed,
                t.honoured,
                t.distrusted,
                t.distrusted_live,
                t.distrusted_honoured
            ),
            (1, 1, 1, 1, 1)
        );
        // A request that waited for a frame past the window's end, having arrived inside it, is
        // judged by the count too.
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, 7_000, link.with_nacks(400), true);
        let inside = t0 + ms(1_000);
        assert_eq!(
            w.judge_with(t0 + ms(2_000), Asked::once(inside), false, Some(401)),
            Verdict::Honour
        );
        // The stats interval's NACKs do not let a live window go; its fraction lost does.
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(60, Some(0), 400, 3_000));
        w.keyframe_sent(t0, 7_000, link.with_nacks(400), true);
        w.note_path(t0 + ms(100), path(61, Some(0), 422, 3_015));
        assert_eq!(w.open().and_then(|o| o.distrusted), None);
        assert_eq!(
            w.judge_with(early, Asked::once(early), false, Some(400)),
            Verdict::Suppressed
        );
        w.note_path(t0 + ms(1_100), path(62, Some(250), 422, 3_030));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Loss { bp: 250 })
        );
        // And a judge without a live count, or a window without one, is the stats' business.
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, 7_000, link, true);
        assert_eq!(
            w.judge_with(early, Asked::once(early), false, Some(9_999)),
            Verdict::Suppressed
        );
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, 7_000, link.with_nacks(400), true);
        assert_eq!(
            w.judge(early, Asked::once(early), false),
            Verdict::Suppressed
        );
    }

    /// The case the window is for keeps its hold: a clean path, reports arriving with nothing lost,
    /// Chrome's repeat 200 ms after its PLI. One interval without a report is Chrome's own report
    /// timing (bench rtt-290-clean: 24-28 in three minutes, never two in a row), and two without
    /// a frame sent in them are a still screen's: neither is silence.
    #[test]
    fn a_clean_path_keeps_the_hold_and_one_empty_interval_is_not_silence() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(5, Some(0), 7, 300));
        let kf = t0 + ms(100);
        w.keyframe_sent(kf, KF_BYTES, session_link(), true);
        w.note_path(kf + ms(150), path(6, Some(0), 7, 309));
        let repeat = kf + ms(200);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
        // One empty interval, then a report: no silence, nothing distrusted.
        w.note_path(kf + ms(250), path(7, None, 7, 312));
        w.note_path(kf + ms(350), path(8, Some(0), 7, 318));
        let again = kf + ms(400);
        assert_eq!(
            w.judge(again, Asked::once(again), false),
            Verdict::Suppressed
        );
        assert_eq!(w.totals().distrusted, 0);

        // Two empty intervals with nothing sent in them, a keyframe, and a report: no silence.
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(5, Some(0), 7, 300));
        w.note_path(t0 + ms(1_000), path(6, None, 7, 300));
        w.note_path(t0 + ms(2_000), path(7, None, 7, 300));
        let opened = w.keyframe_sent(t0 + ms(2_100), KF_BYTES, session_link(), true);
        assert_eq!(opened.silent_intervals, 0);
        w.note_path(t0 + ms(2_200), path(8, Some(0), 7, 301));
        let repeat = t0 + ms(2_300);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
        // And the first read is only a baseline, however many NACKs the session had before it.
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        w.note_path(t0 + ms(100), path(30, Some(0), 900, 2_000));
        assert_eq!(w.open().and_then(|o| o.distrusted), None);
    }

    /// A receiver that goes silent while the window is open distrusts it when it reports again, and
    /// drain mode distrusts it at once. Evidence that comes after the window ran out changes
    /// nothing: past it, requests are honoured anyway.
    #[test]
    fn silence_during_the_window_drain_and_late_evidence() {
        let t0 = Instant::now();
        // A long window: two seconds of queue in front of the keyframe.
        let slow = LinkNow {
            rtt_ms: Some(290),
            drain_kbps: 4_000,
            ahead_bytes: 1_000_000,
            nacks: None,
        };
        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(1, Some(0), 0, 100));
        let opened = w.keyframe_sent(t0 + ms(10), 20_000, slow, true);
        assert_eq!(opened.len, WINDOW_MAX);
        w.note_path(t0 + ms(500), path(2, None, 0, 130));
        w.note_path(t0 + ms(1_000), path(3, None, 0, 160));
        assert_eq!(w.open().map(|o| o.silent_intervals), Some(2));
        assert_eq!(
            w.open().and_then(|o| o.distrusted),
            None,
            "not while silent"
        );
        w.note_path(t0 + ms(1_500), path(4, Some(0), 0, 190));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Silence { intervals: 2 })
        );

        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        w.note_drain(t0 + ms(100));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Drain)
        );
        // The first evidence is the one named.
        w.note_path(t0 + ms(150), path(1, Some(0), 0, 10));
        w.note_path(t0 + ms(200), path(2, Some(0), 5, 20));
        assert_eq!(
            w.open().and_then(|o| o.distrusted).map(|d| d.why),
            Some(Distrust::Drain)
        );
        assert_eq!(w.totals().distrusted, 1);

        let mut w = KeyframeWindow::new();
        w.note_path(t0, path(1, Some(0), 0, 10));
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        w.note_path(t0 + ms(420), path(2, Some(0), 9, 40));
        assert_eq!(w.open().and_then(|o| o.distrusted), None);
        assert_eq!(w.totals().distrusted, 0);
    }

    /// A bench run on 3G: the 54 kB start keyframe before any receiver report or estimate. The
    /// formula would price its send time on the controller's floor and hold two start-up requests
    /// for the 2 s cap; with no round trip the window is the floor, so the one 495 ms after it is
    /// honoured.
    #[test]
    fn with_no_round_trip_yet_the_window_is_the_floor() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        let start = LinkNow::from_gauges(u32::MAX, 0, 0, 0);
        let (formula, send_ms) = window_len(54_118, 0, start.drain_kbps, 0);
        assert!(send_ms > 3_000, "{send_ms}");
        assert_eq!(formula, WINDOW_MAX);
        let opened = w.keyframe_sent(t0, 54_118, start, true);
        assert_eq!(
            (opened.rtt_from, opened.len),
            (RttFrom::Unknown, WINDOW_MIN)
        );
        let repeat = t0 + ms(200);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
        let later = t0 + ms(495);
        assert_eq!(w.judge(later, Asked::once(later), false), Verdict::Honour);
    }

    /// The path's recent loss: a keyframe more likely damaged than whole opens its window
    /// distrusted. Bench runs: on 3G at 34.4 s, 21,884 bytes (20 packets) after ten seconds at
    /// 6.5 % lost, a chance of 0.26 — held, and never answered; loss-0p5-f-r2 at 3.5 s, 55,813 bytes
    /// (49 packets) at 0.73 %, 0.70 — held, and answered: kept.
    #[test]
    fn a_lossy_path_opens_the_window_distrusted() {
        let t0 = Instant::now();
        let link = LinkNow {
            rtt_ms: Some(300),
            drain_kbps: 2_000,
            ahead_bytes: 0,
            nacks: None,
        };
        let reports = |w: &mut KeyframeWindow, bp: u32| {
            w.note_path(t0, path(0, Some(0), 0, 0));
            for i in 1..=10u64 {
                w.note_path(t0 + ms(i * 1_000), path(i, Some(bp), 0, i * 60));
            }
        };
        let mut w = KeyframeWindow::new();
        reports(&mut w, 654);
        let kf = t0 + ms(10_500);
        let opened = w.keyframe_sent(kf, 21_884, link, true);
        assert_eq!(
            opened.distrusted.map(|d| d.why),
            Some(Distrust::LossyPath {
                bp: 654,
                packets: 20
            })
        );
        let repeat = kf + ms(200);
        assert_eq!(w.judge(repeat, Asked::once(repeat), false), Verdict::Honour);
        assert_eq!(w.totals().distrusted, 1);

        let mut w = KeyframeWindow::new();
        reports(&mut w, 73);
        let opened = w.keyframe_sent(kf, 55_813, link, true);
        assert_eq!(opened.distrusted, None);
        assert_eq!(
            w.judge(repeat, Asked::once(repeat), false),
            Verdict::Suppressed
        );
        // Only the last ten reports count: ten clean ones after a lossy stretch make it clean.
        let mut w = KeyframeWindow::new();
        reports(&mut w, 2_000);
        for i in 11..=20u64 {
            w.note_path(t0 + ms(i * 1_000), path(i, Some(0), 0, i * 60));
        }
        let opened = w.keyframe_sent(t0 + ms(20_500), 21_884, link, true);
        assert_eq!(opened.distrusted, None);
    }

    /// «Honoured after the window» tells the viewer asking again — a repeat or two after one held —
    /// from a new loss long after (a 3G bench run: 14 of 27 such lines came 3-31 s after their keyframe).
    #[test]
    fn a_reask_is_told_from_a_new_loss() {
        let t0 = Instant::now();
        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        let held = t0 + ms(200);
        assert_eq!(w.judge(held, Asked::once(held), false), Verdict::Suppressed);
        let again = t0 + ms(604);
        assert_eq!(w.judge(again, Asked::once(again), false), Verdict::Honour);
        assert_eq!((w.totals().after_window, w.totals().new_episodes), (1, 0));

        let mut w = KeyframeWindow::new();
        w.keyframe_sent(t0, KF_BYTES, session_link(), true);
        assert_eq!(w.judge(held, Asked::once(held), false), Verdict::Suppressed);
        let new_loss = t0 + ms(31_000);
        assert_eq!(
            w.judge(new_loss, Asked::once(new_loss), false),
            Verdict::Honour
        );
        assert_eq!((w.totals().after_window, w.totals().new_episodes), (0, 1));
    }

    #[test]
    fn nothing_noted_is_nothing_taken() {
        let asks = ViewerAsks::default();
        assert!(asks.take().is_none());
        let t0 = Instant::now();
        asks.note(t0);
        assert_eq!(asks.take(), Some(Asked::once(t0)));
        assert!(asks.take().is_none());
    }
}
