//! The PC's cursor position for the viewer's cursor marker (`cp`, see `afklink_protocol::cursor`).
//!
//! The trackpad mode moves the cursor with relative moves only, and the phone's only picture of the
//! cursor is the one in the video — a few pixels tall and a round trip late. So the agent reports
//! where the cursor really is, and the viewer draws a large marker at that position plus the
//! relative moves it has sent since. The report's `ack` is how the viewer knows which moves a
//! report already includes: the highest `r.s` whose effect the sampled position shows.
//!
//! The `ack` never claims a move the sampled position does not show yet ([`Ack`]).
//!
//! One task per session polls the injector's [`InputInjector::cursor`] every
//! [`afklink_protocol::CURSOR_REPORT_MIN_INTERVAL_MS`] and sends a report when anything in it
//! changed, or [`afklink_protocol::CURSOR_REPORT_REFRESH_MS`] after the last one (the `cursor`
//! channel never retransmits, so a lost last report would otherwise stand).
//!
//! In «only the game window» mode the report is in the space `m` is in: fractions of the game's
//! client area (the picture the viewer sees), and `hidden` while the cursor is outside it or the
//! window is not shown (`crate::game_input::to_scope`).
//!
//! Logging is listed on [`cursor_report_task`]; each new cursor shape is said once ([`ShapeLog`]).

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// For hosts that pace their own cursor reports like [`CursorReporter`].
pub use afklink_protocol::CURSOR_REPORT_MIN_INTERVAL_MS;
use afklink_protocol::{AgentDataMessage, CursorPos};
use afklink_transport::PeerControl;
use tokio::sync::mpsc;

use crate::game_input::{describe_space, to_scope, InputScopeSource};
use crate::traits::{CursorSample, CursorShape, InputInjector, InputScope};

/// How often the report counts are logged while reports flow.
pub const SUMMARY_EVERY: Duration = Duration::from_secs(10);

/// The coordinate space's line at most this often (a window being dragged changes it every poll).
const SPACE_LOG_EVERY: Duration = Duration::from_secs(1);

/// Control-queue slots a cursor report leaves free for everything else on it (the heartbeat, the
/// bitrate, candidates): a report is the one message on that queue that can always wait for the
/// next.
const QUEUE_HEADROOM: usize = 4;

/// New cursor shapes described at debug per session; the rest are counted in the summary line (a
/// game that makes a new cursor every frame would otherwise write a line a poll).
pub const SHAPE_LINES: u32 = 32;

/// Shapes remembered per session. Past this nothing more is remembered, so no shape is new any
/// more.
const SHAPES_KEPT: usize = 256;

/// The highest relative-move number (`r.s`) handed to the injector this session — applied, queued
/// behind other input, or dropped by game-only mode's guard: whatever the injector did with it, it
/// has it. Which of those the cursor shows is the injector's to say ([`CursorSample::unshown`]).
///
/// Stored as `s + 1`, so zero can mean "none yet". A maximum rather than the latest: the `cursor`
/// channel is unordered, and an older move arriving after a newer one must not take the
/// acknowledgement backwards (the viewer would count the newer move twice).
#[derive(Debug, Default)]
pub struct RelAck(AtomicU64);

impl RelAck {
    pub fn new() -> Self {
        Self::default()
    }

    /// A numbered relative move was handed to the injector, and it took it.
    pub fn note(&self, s: u32) {
        self.0.fetch_max(u64::from(s) + 1, Ordering::Relaxed);
    }

    /// The highest number handed in, if any.
    pub fn get(&self) -> Option<u32> {
        match self.0.load(Ordering::Relaxed) {
            0 => None,
            v => u32::try_from(v - 1).ok(),
        }
    }
}

/// What a report's `ack` may say: from the highest move number handed to the injector before the
/// sample (`applied`, [`RelAck`]) and the lowest one the sampled position does not show yet
/// ([`CursorSample::unshown`]).
///
/// [`RelAck`] holds the highest number handed to the injector. That is not yet a move the position
/// shows: Windows shows a HID report about 2 ms after it is written (measured), and a move can wait
/// behind a click in the injector's queue. A report sampled in that window that claims the move
/// anyway makes the viewer take it off its marker: the marker steps back by one move until the next
/// report, about every eighth report while the finger moves. So the injector says, with each
/// sample, the lowest number the position does not show yet (its cursor-sync planner matches the
/// cursor's movement to the reports in flight, each taken as shown after 40 ms at most), and the
/// `ack` stays below it. A viewer that numbers no moves gets no `ack`; one that does gets an exact
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ack {
    /// Every move handed in shows (or none is numbered, or the injector cannot tell): `applied`, as
    /// it is — what every report said before the injector could tell.
    All(Option<u32>),
    /// A move is still on its way to the cursor: the highest number below it. The viewer keeps that
    /// move, and every later one, on its marker.
    Before(u32),
    /// Nothing handed in shows yet (move 0 of the session is on its way), so no number can be said
    /// — and none (`null`) would tell the viewer that nothing it sent is pending, which takes every
    /// move off its marker. The report waits for the next poll.
    Wait,
}

impl Ack {
    pub fn of(applied: Option<u32>, unshown: Option<u32>) -> Self {
        match (applied, unshown) {
            (applied, None) => Self::All(applied),
            // Handed in after `applied` was read: none of the moves `applied` names is waiting.
            (Some(a), Some(u)) if a < u => Self::All(Some(a)),
            (Some(_), Some(u)) => u.checked_sub(1).map_or(Self::Wait, Self::Before),
            // A move came in after `applied` was read and has not shown: there is nothing to say.
            (None, Some(_)) => Self::Wait,
        }
    }
}

/// Why the cursor is not drawn on the captured screen, for the transition lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Visibility {
    Shown,
    /// The OS says it is not drawn: an application hid it, or touch input suppressed it.
    HiddenByOs,
    /// It is on another monitor.
    OffScreen,
}

impl Visibility {
    fn of(s: &CursorSample) -> Self {
        if !s.on_screen() {
            Self::OffScreen
        } else if !s.visible {
            Self::HiddenByOs
        } else {
            Self::Shown
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Self::Shown => "visible on the captured screen",
            Self::HiddenByOs => "hidden by the PC (an application hid it, or touch suppressed it)",
            Self::OffScreen => {
                "outside the captured picture (on another monitor; in game-only mode, outside the \
                 game's client area, or the game's window is not shown)"
            }
        }
    }
}

/// What the last report said, to tell a change from a repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Said {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    visibility: Visibility,
    ack: Option<u32>,
}

/// What the reporter did about the `ack`, counted for the summary line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AckCounts {
    /// Reports whose `ack` stayed below a move the position did not show yet ([`Ack::Before`]).
    pub behind: u64,
    /// Polls that made no report because no move showed yet ([`Ack::Wait`]).
    pub waited: u64,
    /// Reports that stopped waiting after a whole refresh interval and said `applied` anyway.
    pub gave_up: u64,
}

/// Decides, sample by sample, whether a report goes out and what it says. No I/O: the task
/// below feeds it and sends what it returns.
#[derive(Debug, Default)]
pub struct CursorReporter {
    seq: u64,
    last: Option<(Said, Instant)>,
    /// Since when polls have waited for a move to show ([`Ack::Wait`]), and whether giving up on
    /// that wait was said.
    waiting_since: Option<Instant>,
    gave_up_said: bool,
    counts: AckCounts,
}

impl CursorReporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// The report to send for this sample, or `None` when it would repeat the last one within
    /// the refresh interval, when no move the injector was handed shows yet ([`Ack::Wait`], for at
    /// most a refresh interval) — or the screen size is unknown, so no position can be normalized.
    ///
    /// `applied` is the highest move number handed to the injector, read before the sample; the
    /// report's `ack` stays below the sample's [`CursorSample::unshown`] ([`Ack::of`]).
    ///
    /// Also returns the visibility change, if this sample made one, for the caller to log.
    pub fn decide(
        &mut self,
        now: Instant,
        sample: CursorSample,
        applied: Option<u32>,
    ) -> Option<(CursorPos, Option<&'static str>)> {
        let (x, y) = sample.normalized()?;
        let refresh = Duration::from_millis(afklink_protocol::CURSOR_REPORT_REFRESH_MS);
        let decided = Ack::of(applied, sample.unshown);
        let ack = match decided {
            Ack::All(ack) => ack,
            Ack::Before(ack) => Some(ack),
            Ack::Wait => {
                let since = *self.waiting_since.get_or_insert(now);
                let waited = now.saturating_duration_since(since);
                if waited < refresh {
                    self.counts.waited += 1;
                    tracing::trace!(
                        applied = ?applied,
                        unshown = ?sample.unshown,
                        waited_ms = waited.as_millis(),
                        "cursor report waits: no move handed in shows yet"
                    );
                    return None;
                }
                // The injector should never keep a move unshown this long (it takes one as shown
                // 40 ms after its report at most): say what the agent has, as before it could tell
                // — on every poll of the streak, said once.
                self.counts.gave_up += 1;
                if !self.gave_up_said {
                    self.gave_up_said = true;
                    tracing::debug!(
                        applied = ?applied,
                        unshown = ?sample.unshown,
                        waited_ms = waited.as_millis(),
                        "cursor report: no move has shown for a whole refresh interval; reporting \
                         without waiting for it until one shows"
                    );
                }
                applied
            }
        };
        if decided != Ack::Wait {
            self.waiting_since = None;
            self.gave_up_said = false;
        }
        let said = Said {
            x: sample.x,
            y: sample.y,
            width: sample.width,
            height: sample.height,
            visibility: Visibility::of(&sample),
            ack,
        };
        let changed_visibility = match self.last {
            Some((last, at)) => {
                if last == said && now.saturating_duration_since(at) < refresh {
                    return None;
                }
                (last.visibility != said.visibility).then(|| said.visibility.describe())
            }
            // The first report says where things stand, whatever that is.
            None => Some(said.visibility.describe()),
        };
        let report = CursorPos {
            seq: self.seq,
            x,
            y,
            ack,
            hidden: said.visibility != Visibility::Shown,
        };
        if matches!(decided, Ack::Before(_)) {
            self.counts.behind += 1;
        }
        self.seq += 1;
        self.last = Some((said, now));
        Some((report, changed_visibility))
    }

    /// Reports made so far.
    pub fn made(&self) -> u64 {
        self.seq
    }

    /// What was done about the `ack` since the last call, for the summary line.
    pub fn take_counts(&mut self) -> AckCounts {
        std::mem::take(&mut self.counts)
    }
}

/// Says each cursor shape the first time a session sees it: one debug line, with the picture and
/// the window under it ([`InputInjector::cursor_shape`]). A shape seen before is silent, and so is
/// a hidden cursor; past [`SHAPE_LINES`] new shapes are only counted.
///
/// Each new cursor shape of the session (a visible cursor whose `HCURSOR` was not seen before) gets
/// one debug line: the picture's size, its hotspot, the box it draws relative to the hotspot, and
/// the window under it with its DPI awareness. That is what tells a game's cursor drawn off its
/// click point from a marker drawn off it.
#[derive(Debug, Default)]
pub struct ShapeLog {
    seen: HashSet<usize>,
    said: u32,
    /// The lines saying that further shapes are only counted, or not told apart any more, were
    /// said.
    capped_said: bool,
    full_said: bool,
    /// New shapes since the last summary line, and those of them not described (past
    /// [`SHAPE_LINES`], or the injector could not).
    new: u64,
    unsaid: u64,
}

impl ShapeLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// A sample: if its shape is new this session, describe it (at most [`SHAPE_LINES`] lines).
    /// Returns whether a line was written.
    pub fn note(
        &mut self,
        sample: &CursorSample,
        injector: &dyn InputInjector,
        game_only: bool,
        sid: &str,
    ) -> bool {
        if sample.shape == 0 || !sample.visible || self.seen.contains(&sample.shape) {
            return false;
        }
        if self.seen.len() >= SHAPES_KEPT {
            // Nothing more is remembered, so nothing more is new: one line says so.
            if !self.full_said {
                self.full_said = true;
                tracing::debug!(
                    session = %sid,
                    kept = SHAPES_KEPT,
                    "cursor shapes: too many this session; new ones are no longer told apart"
                );
            }
            return false;
        }
        self.seen.insert(sample.shape);
        self.new += 1;
        if self.said >= SHAPE_LINES {
            self.unsaid += 1;
            if !self.capped_said {
                self.capped_said = true;
                tracing::debug!(
                    session = %sid,
                    lines = SHAPE_LINES,
                    "cursor shapes: further new shapes this session are counted, not described"
                );
            }
            tracing::trace!(
                session = %sid,
                shape = %format!("{:#x}", sample.shape),
                "cursor shape: new, not described"
            );
            return false;
        }
        // A few Win32 reads (the cursor's picture, the window under it): off the worker.
        let Some(shape) = crate::input_session::blocking(|| injector.cursor_shape(sample)) else {
            self.unsaid += 1;
            tracing::trace!(
                session = %sid,
                shape = %format!("{:#x}", sample.shape),
                "cursor shape: new; this injector cannot describe it"
            );
            return false;
        };
        self.said += 1;
        say_shape(sample, &shape, game_only, sid);
        true
    }

    /// New shapes since the last call, and how many of them were not described.
    fn take_new(&mut self) -> (u64, u64) {
        (
            std::mem::take(&mut self.new),
            std::mem::take(&mut self.unsaid),
        )
    }
}

/// The new shape's line.
fn say_shape(sample: &CursorSample, shape: &CursorShape, game_only: bool, sid: &str) {
    let (size, hotspot, drawn, color) = match &shape.image {
        Ok(image) => (
            format!("{}x{}", image.width, image.height),
            format!("{},{}", image.hotspot_x, image.hotspot_y),
            image.drawn.map_or_else(
                || "nothing (transparent or unreadable)".to_owned(),
                |(l, t, r, b)| format!("x {l:+}..{r:+}, y {t:+}..{b:+}"),
            ),
            if image.color { "colour" } else { "monochrome" },
        ),
        Err(error) => (
            format!("unreadable: {error}"),
            "-".to_owned(),
            "-".to_owned(),
            "-",
        ),
    };
    match &shape.under {
        Ok(window) => tracing::debug!(
            session = %sid,
            shape = %format!("{:#x}", sample.shape),
            at = %format!("{},{}", sample.x, sample.y),
            size = %size,
            hotspot = %hotspot,
            drawn_from_hotspot = %drawn,
            kind = color,
            window = %format!("{:#x}", window.hwnd),
            exe = %window.exe,
            class = %window.class,
            awareness = window.awareness,
            window_dpi = window.dpi,
            monitor_dpi = window.monitor_dpi,
            game_only,
            "cursor shape: new this session"
        ),
        Err(error) => tracing::debug!(
            session = %sid,
            shape = %format!("{:#x}", sample.shape),
            at = %format!("{},{}", sample.x, sample.y),
            size = %size,
            hotspot = %hotspot,
            drawn_from_hotspot = %drawn,
            kind = color,
            window = %format!("unknown: {error}"),
            game_only,
            "cursor shape: new this session"
        ),
    }
}

/// Counts for the summary line.
#[derive(Debug, Default)]
struct Counts {
    sent: u64,
    /// The peer's control queue had no room to spare.
    queue_full: u64,
    /// The injector could not read the cursor (another desktop has input).
    unavailable: u64,
}

/// Poll the cursor and report it to the viewer for as long as the session runs, in the space of
/// `scope` (the primary monitor, or in game-only mode the game's client area).
///
/// Ends when `stop` is set, when the peer is gone, or at once for an injector that never reads a
/// cursor and moves no pointer (the bench's `--no-input`): there is nothing to report there.
///
/// Logging: start and stop at debug with their reason; the coordinate space at start and on every
/// change (the game's window moved or resized, game-only mode turned on or off) at debug; every
/// change of visibility at debug with why; a new cursor shape at debug, at most [`SHAPE_LINES`] a
/// session; a report that waited a whole refresh for a move to show at debug; one debug line every
/// [`SUMMARY_EVERY`] counting what was sent and dropped while reports flow, the reports whose `ack`
/// stayed below a move not shown yet, the polls that waited for one, and the new shapes; each
/// report itself at trace with the numbers its `ack` came from (up to thirty a second).
pub async fn cursor_report_task(
    injector: Arc<dyn InputInjector>,
    control_tx: mpsc::Sender<PeerControl>,
    stop: Arc<AtomicBool>,
    ack: Arc<RelAck>,
    scope: Option<Arc<InputScopeSource>>,
    sid: String,
) {
    if !injector.moves_pointer() && crate::input_session::blocking(|| injector.cursor()).is_none() {
        tracing::debug!(
            session = %sid,
            "cursor reports off: this injector moves no pointer and reads no cursor"
        );
        return;
    }
    tracing::debug!(
        session = %sid,
        every_ms = afklink_protocol::CURSOR_REPORT_MIN_INTERVAL_MS,
        refresh_ms = afklink_protocol::CURSOR_REPORT_REFRESH_MS,
        "cursor reports start: sent when the cursor or the moves it shows change (ack: the \
         highest move the position shows)"
    );
    let mut tick = tokio::time::interval(Duration::from_millis(
        afklink_protocol::CURSOR_REPORT_MIN_INTERVAL_MS,
    ));
    // A late tick is skipped, not made up: a burst of reports of the same position says nothing.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut reporter = CursorReporter::new();
    let mut shapes = ShapeLog::new();
    let mut counts = Counts::default();
    let mut window_start = Instant::now();
    let mut was_unavailable = false;
    // The coordinate space the reports are in, said at start and whenever it changes.
    let mut space_said: Option<String> = None;
    let mut space_logged_at: Option<Instant> = None;
    let mut space_quiet = 0u32;
    loop {
        tick.tick().await;
        if stop.load(Ordering::SeqCst) {
            tracing::debug!(
                session = %sid,
                made = reporter.made(),
                "cursor reports stop: the session is ending"
            );
            break;
        }
        let now = Instant::now();
        if now.saturating_duration_since(window_start) >= SUMMARY_EVERY {
            let acks = reporter.take_counts();
            let (new_shapes, shapes_undescribed) = shapes.take_new();
            if counts.sent + counts.queue_full + counts.unavailable + acks.waited + new_shapes > 0 {
                tracing::debug!(
                    session = %sid,
                    window_s = now.saturating_duration_since(window_start).as_secs(),
                    sent = counts.sent,
                    queue_full = counts.queue_full,
                    unavailable_polls = counts.unavailable,
                    acks_behind = acks.behind,
                    waited_polls = acks.waited,
                    wait_gave_up = acks.gave_up,
                    new_shapes,
                    shapes_undescribed,
                    "cursor reports"
                );
            }
            counts = Counts::default();
            window_start = now;
        }
        // The highest move handed in is read before the cursor, and the injector says with the
        // sample which of them it does not show yet: the `ack` names only moves the position
        // includes. A move handed in between is in neither, and the next report names it.
        let applied = ack.get();
        // Off the worker (`block_in_place`): the read takes the injector's guard and planner locks,
        // which an injection or the game's focus watch hold across Win32 calls (`SendInput` among
        // them); a stuck holder must stall this task only, not the worker's timers and I/O.
        let Some(sample) = crate::input_session::blocking(|| injector.cursor()) else {
            counts.unavailable += 1;
            if !was_unavailable {
                was_unavailable = true;
                tracing::debug!(session = %sid, "cursor reports paused: the cursor cannot be read");
            }
            continue;
        };
        if was_unavailable {
            was_unavailable = false;
            tracing::debug!(session = %sid, "cursor reports resume: the cursor can be read again");
        }
        // In the space `m` is in: the game's client area in game-only mode.
        let space = scope
            .as_ref()
            .map_or(InputScope::Desktop, |scope| scope.scope());
        let described = describe_space(&space);
        if space_said.as_deref() != Some(described.as_str()) {
            // A window being dragged changes it every poll: one line a second, the rest at trace.
            if space_logged_at.is_none_or(|at| now.saturating_duration_since(at) >= SPACE_LOG_EVERY)
            {
                tracing::debug!(
                    session = %sid,
                    from = space_said.as_deref().unwrap_or("-"),
                    changes_since_last_line = space_quiet,
                    "cursor reports: coordinate space: {described}"
                );
                space_logged_at = Some(now);
                space_quiet = 0;
            } else {
                space_quiet += 1;
                tracing::trace!(session = %sid, "cursor reports: coordinate space: {described}");
            }
            space_said = Some(described);
        }
        // On the screen's own sample: the window under the cursor is found by its screen position.
        shapes.note(
            &sample,
            injector.as_ref(),
            matches!(space, InputScope::Game(_)),
            &sid,
        );
        let sample = to_scope(sample, &space);
        let Some((report, visibility)) = reporter.decide(now, sample, applied) else {
            continue;
        };
        if let Some(why) = visibility {
            tracing::debug!(
                session = %sid,
                x = sample.x,
                y = sample.y,
                screen = %format!("{}x{}", sample.width, sample.height),
                "cursor now {why}"
            );
        }
        tracing::trace!(
            seq = report.seq,
            x = report.x,
            y = report.y,
            ack = ?report.ack,
            applied = ?applied,
            unshown = ?sample.unshown,
            hidden = report.hidden,
            "cursor report"
        );
        if control_tx.capacity() <= QUEUE_HEADROOM {
            counts.queue_full += 1;
            continue;
        }
        let json = match AgentDataMessage::Cursor(report).to_json() {
            Ok(json) => json,
            Err(e) => {
                tracing::warn!(session = %sid, "cursor report could not be serialised: {e}");
                continue;
            }
        };
        match control_tx.try_send(PeerControl::SendCursor(json)) {
            Ok(()) => counts.sent += 1,
            Err(mpsc::error::TrySendError::Full(_)) => counts.queue_full += 1,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(
                    session = %sid,
                    made = reporter.made(),
                    "cursor reports stop: the peer is gone"
                );
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{CursorImage, CursorWindow};
    use afklink_protocol::InputMessage;
    use std::sync::Mutex;

    fn sample(x: i32, y: i32) -> CursorSample {
        CursorSample {
            x,
            y,
            width: 1920,
            height: 1080,
            visible: true,
            shape: 0,
            unshown: None,
        }
    }

    #[test]
    fn the_first_sample_is_reported_and_says_where_things_stand() {
        let mut r = CursorReporter::new();
        let (cp, vis) = r.decide(Instant::now(), sample(960, 270), None).unwrap();
        assert_eq!(cp.seq, 0);
        assert!((cp.x - 0.5).abs() < 1e-9 && (cp.y - 0.25).abs() < 1e-9);
        assert_eq!(cp.ack, None);
        assert!(!cp.hidden);
        assert!(
            vis.is_some(),
            "the first report logs the visibility it starts with"
        );
    }

    #[test]
    fn an_unchanged_cursor_waits_for_the_refresh() {
        let mut r = CursorReporter::new();
        let t0 = Instant::now();
        assert!(r.decide(t0, sample(10, 10), None).is_some());
        assert!(r
            .decide(t0 + Duration::from_millis(33), sample(10, 10), None)
            .is_none());
        assert!(r
            .decide(t0 + Duration::from_millis(999), sample(10, 10), None)
            .is_none());
        let (cp, vis) = r
            .decide(t0 + Duration::from_millis(1000), sample(10, 10), None)
            .unwrap();
        assert_eq!(cp.seq, 1, "the refresh is a new report with its own number");
        assert!(vis.is_none(), "nothing changed, so nothing to log");
    }

    #[test]
    fn a_move_or_a_newer_ack_is_reported_at_once() {
        let mut r = CursorReporter::new();
        let t0 = Instant::now();
        r.decide(t0, sample(10, 10), None);
        assert!(
            r.decide(t0, sample(11, 10), None).is_some(),
            "moved one pixel"
        );
        let (cp, _) = r.decide(t0, sample(11, 10), Some(4)).unwrap();
        assert_eq!(
            cp.ack,
            Some(4),
            "a newer applied move is news even when nothing moved"
        );
    }

    #[test]
    fn hidden_and_off_screen_cursors_are_reported_hidden_with_the_reason_logged() {
        let mut r = CursorReporter::new();
        let t0 = Instant::now();
        r.decide(t0, sample(10, 10), None);
        let hidden = CursorSample {
            visible: false,
            ..sample(10, 10)
        };
        let (cp, vis) = r.decide(t0, hidden, None).unwrap();
        assert!(cp.hidden);
        assert!(vis.unwrap().contains("hidden by the PC"));

        let (cp, vis) = r.decide(t0, sample(2500, 300), None).unwrap();
        assert!(cp.hidden, "a cursor on another monitor is not drawn");
        assert!(
            (cp.x - 1.0).abs() < 1e-9,
            "its position is clamped to the edge"
        );
        assert!(vis.unwrap().contains("another monitor"));

        let (cp, vis) = r.decide(t0, sample(100, 100), None).unwrap();
        assert!(!cp.hidden);
        assert!(vis.unwrap().contains("visible"));
    }

    #[test]
    fn an_unknown_screen_size_reports_nothing() {
        let mut r = CursorReporter::new();
        let unknown = CursorSample {
            width: 0,
            ..sample(10, 10)
        };
        assert!(r.decide(Instant::now(), unknown, None).is_none());
        assert_eq!(r.made(), 0);
    }

    #[test]
    fn the_ack_is_the_highest_number_applied_never_an_older_one() {
        let ack = RelAck::new();
        assert_eq!(ack.get(), None);
        ack.note(0);
        assert_eq!(ack.get(), Some(0), "zero is a number, not 'none'");
        ack.note(7);
        ack.note(5); // an older move the unordered channel delivered late
        assert_eq!(ack.get(), Some(7));
        ack.note(u32::MAX);
        assert_eq!(ack.get(), Some(u32::MAX));
    }

    /// The `ack` names only moves the position shows: below the first one still on its way, and
    /// nothing at all while move 0 is — `null` would take every move off the viewer's marker.
    #[test]
    fn the_ack_stays_below_a_move_the_position_does_not_show_yet() {
        // Nothing on its way (or an injector that cannot tell): what was handed in, as before.
        assert_eq!(Ack::of(None, None), Ack::All(None));
        assert_eq!(Ack::of(Some(4), None), Ack::All(Some(4)));
        // The last move on its way, or an older one with newer ones behind it.
        assert_eq!(Ack::of(Some(9), Some(9)), Ack::Before(8));
        assert_eq!(Ack::of(Some(12), Some(9)), Ack::Before(8));
        // Handed in after `applied` was read: everything `applied` names shows.
        assert_eq!(Ack::of(Some(8), Some(9)), Ack::All(Some(8)));
        // Move 0 on its way: no number can be said.
        assert_eq!(Ack::of(Some(5), Some(0)), Ack::Wait);
        assert_eq!(Ack::of(None, Some(3)), Ack::Wait);
    }

    /// A stroke: one move of 10 px every 16 ms, each showing on the PC's cursor 2 ms after it is
    /// handed to the injector (a HID report), polled every 33 ms. The viewer's marker is the report
    /// plus the moves after its `ack` (`miniapp/src/cursorReport.ts`). With the injector saying
    /// which moves are still on their way, every report puts the marker exactly where the moves
    /// sent so far take the cursor; without it the polls that land in a move's 2 ms (two in sixteen
    /// here) take that move off the marker, which steps back by it.
    #[test]
    fn a_move_on_its_way_stays_on_the_viewers_marker() {
        const STEP: i32 = 10;
        const START: i32 = 100;
        let run = |injector_tells: bool| -> (u32, u32, AckCounts) {
            let t0 = Instant::now();
            let mut r = CursorReporter::new();
            let (mut exact, mut behind) = (0u32, 0u32);
            for k in 0..64u32 {
                let t = 1 + 33 * u64::from(k);
                // Move `s` is handed in at 16·s ms and shows 2 ms later.
                let handed = u32::try_from(t / 16 + 1).unwrap();
                let shown = u32::try_from((t.saturating_sub(2)) / 16 + 1).unwrap();
                let shown = if t >= 2 { shown } else { 0 };
                let applied = handed.checked_sub(1);
                let unshown = (injector_tells && shown < handed).then_some(shown);
                let position = START + STEP * i32::try_from(shown).unwrap();
                let s = CursorSample {
                    unshown,
                    ..sample(position, 500)
                };
                let Some((cp, _)) = r.decide(t0 + Duration::from_millis(t), s, applied) else {
                    continue;
                };
                // The viewer: the report, plus every move it sent after the one acknowledged.
                let pending = match cp.ack {
                    None => 0,
                    Some(ack) => handed.saturating_sub(ack + 1),
                };
                let marker = cp.x * 1920.0 + f64::from(STEP) * f64::from(pending);
                let goal = f64::from(START + STEP * i32::try_from(handed).unwrap());
                if (marker - goal).abs() < 1e-6 {
                    exact += 1;
                } else {
                    assert!(marker < goal, "never ahead: {marker} vs {goal} at {t} ms");
                    behind += 1;
                }
            }
            (exact, behind, r.take_counts())
        };
        let (exact, behind, counts) = run(true);
        assert_eq!(behind, 0, "the marker never steps back");
        assert!(exact >= 60, "{exact} reports");
        assert_eq!(counts.behind, 7, "{counts:?}");
        assert_eq!(
            counts.waited, 1,
            "move 0 on its way at the first poll: {counts:?}"
        );
        assert_eq!(counts.gave_up, 0);

        let (_, behind, counts) = run(false);
        assert_eq!(
            behind, 8,
            "before: a step back in about every eighth report"
        );
        assert_eq!(counts, AckCounts::default());
    }

    /// An injector that keeps saying a move is on its way (it never should: it takes one as shown
    /// after 40 ms) does not stop the reports for longer than the refresh interval.
    #[test]
    fn waiting_for_a_move_to_show_stops_reports_for_a_refresh_at_most() {
        let mut r = CursorReporter::new();
        let t0 = Instant::now();
        let stuck = CursorSample {
            unshown: Some(0),
            ..sample(10, 10)
        };
        for ms in [0, 33, 500, 999] {
            assert!(r
                .decide(t0 + Duration::from_millis(ms), stuck, Some(0))
                .is_none());
        }
        let (cp, _) = r
            .decide(t0 + Duration::from_millis(1000), stuck, Some(0))
            .unwrap();
        assert_eq!(
            cp.ack,
            Some(0),
            "after the refresh: what was handed in, as before"
        );
        let counts = r.take_counts();
        assert_eq!((counts.waited, counts.gave_up), (4, 1), "{counts:?}");
        // Once move 0 shows, the wait is over and starts afresh next time.
        let (cp, _) = r
            .decide(t0 + Duration::from_millis(1033), sample(11, 10), Some(0))
            .unwrap();
        assert_eq!(cp.ack, Some(0));
        let again = CursorSample {
            unshown: Some(0),
            ..sample(12, 10)
        };
        assert!(r
            .decide(t0 + Duration::from_millis(1066), again, Some(0))
            .is_none());
    }

    /// A viewer that numbers no moves (`r` without `s`), and an injector that cannot tell which
    /// moves show: the reports are what they always were.
    #[test]
    fn old_viewers_and_injectors_that_cannot_tell_get_the_reports_as_before() {
        let mut r = CursorReporter::new();
        let t0 = Instant::now();
        for (i, x) in (10..20).enumerate() {
            let t = t0 + Duration::from_millis(33 * i as u64);
            let (cp, _) = r.decide(t, sample(x, 10), None).unwrap();
            assert_eq!(cp.ack, None, "no numbers, no ack");
        }
        let (cp, _) = r
            .decide(t0 + Duration::from_millis(400), sample(30, 10), Some(41))
            .unwrap();
        assert_eq!(cp.ack, Some(41), "the highest number handed in");
        assert_eq!(r.take_counts(), AckCounts::default());
    }

    /// An injector that describes every shape it is asked about, and counts the questions.
    #[derive(Default)]
    struct ShapeInjector {
        asked: Mutex<Vec<usize>>,
    }

    impl InputInjector for ShapeInjector {
        fn inject(&self, _: &InputMessage) -> anyhow::Result<()> {
            Ok(())
        }

        fn release_all(&self) {}

        fn cursor_shape(&self, sample: &CursorSample) -> Option<CursorShape> {
            self.asked.lock().unwrap().push(sample.shape);
            Some(CursorShape {
                image: Ok(CursorImage {
                    width: 32,
                    height: 32,
                    hotspot_x: 6,
                    hotspot_y: 5,
                    color: true,
                    drawn: Some((-1, -1, 21, 22)),
                }),
                under: Ok(CursorWindow {
                    hwnd: 0x5104c,
                    exe: "ScrydeGame.bin".to_owned(),
                    class: "ScrydeGameUnrealWWindowsViewportWindow".to_owned(),
                    awareness: "unaware",
                    dpi: 96,
                    monitor_dpi: 144,
                }),
            })
        }
    }

    /// What `f` logs at `level` and above, on this thread.
    fn logged(level: tracing::Level, f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let capture = Capture::default();
        let writer = capture.clone();
        let ours = tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(level)
                .with_ansi(false)
                .without_time()
                .with_writer(move || writer.clone())
                .finish(),
        );
        // A second live dispatcher makes tracing ask every one of them rather than cache "off" for
        // a call site another test's subscriber saw first.
        let _second = tracing::Dispatch::new(tracing_subscriber::registry());
        tracing::dispatcher::with_default(&ours, f);
        let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        log
    }

    /// One debug line per shape a session sees, with the picture and the window under it; a shape
    /// seen before is silent, and so are a hidden cursor and one with no shape.
    #[test]
    fn each_new_cursor_shape_is_said_once_a_session() {
        let injector = ShapeInjector::default();
        let arrow = CursorSample {
            shape: 0x10003,
            ..sample(2003, 1137)
        };
        let hand = CursorSample {
            shape: 0x10011,
            ..sample(2010, 1140)
        };
        let log = logged(tracing::Level::DEBUG, || {
            let mut shapes = ShapeLog::new();
            assert!(shapes.note(&arrow, &injector, true, "s1"));
            assert!(!shapes.note(&arrow, &injector, true, "s1"), "seen: silent");
            assert!(shapes.note(&hand, &injector, true, "s1"));
            assert!(
                !shapes.note(&arrow, &injector, true, "s1"),
                "back to the arrow"
            );
            let hidden = CursorSample {
                visible: false,
                shape: 0x10021,
                ..sample(5, 5)
            };
            assert!(!shapes.note(&hidden, &injector, true, "s1"));
            assert!(
                !shapes.note(&sample(5, 5), &injector, true, "s1"),
                "no shape"
            );
            assert_eq!(shapes.take_new(), (2, 0));
            // A new session starts afresh.
            let mut next = ShapeLog::new();
            assert!(next.note(&arrow, &injector, false, "s2"));
        });
        assert_eq!(
            *injector.asked.lock().unwrap(),
            [0x10003, 0x10011, 0x10003],
            "asked once per new shape a session"
        );
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| l.contains("cursor shape: new this session"))
            .collect();
        assert_eq!(lines.len(), 3, "{log}");
        for field in [
            "shape=0x10003",
            "at=2003,1137",
            "size=32x32",
            "hotspot=6,5",
            "drawn_from_hotspot=x -1..+21, y -1..+22",
            "exe=ScrydeGame.bin",
            "awareness=\"unaware\"",
            "window_dpi=96",
            "monitor_dpi=144",
            "game_only=true",
        ] {
            assert!(lines[0].contains(field), "{field}: {}", lines[0]);
        }
    }

    /// A game that makes a cursor per frame: past [`SHAPE_LINES`] new shapes are only counted, with
    /// one line saying so.
    #[test]
    fn new_shapes_past_the_cap_are_counted_not_described() {
        let injector = ShapeInjector::default();
        let log = logged(tracing::Level::DEBUG, || {
            let mut shapes = ShapeLog::new();
            for i in 0..100usize {
                let s = CursorSample {
                    shape: 0x20000 + i,
                    ..sample(10, 10)
                };
                shapes.note(&s, &injector, false, "s1");
            }
            assert_eq!(shapes.take_new(), (100, 100 - u64::from(SHAPE_LINES)));
        });
        assert_eq!(injector.asked.lock().unwrap().len(), SHAPE_LINES as usize);
        assert_eq!(
            log.lines()
                .filter(|l| l.contains("cursor shape: new this session"))
                .count(),
            SHAPE_LINES as usize
        );
        assert_eq!(
            log.lines()
                .filter(|l| l.contains("counted, not described"))
                .count(),
            1,
            "{log}"
        );
    }
}
