//! Pipeline supervision: whether capture -> encode is alive, bringing it back when it is not, and
//! the heartbeat that tells the viewer which.
//!
//! ## The blind spot this closes
//!
//! The agent captures on change. A desktop nobody touches produces no frames, so it sends no video,
//! and that is by design. A capture thread that has died produces no frames either — and so does an
//! encoder that fails every frame — while the WebRTC link stays perfectly healthy. The viewer, which
//! can only see what arrives, got the same frozen picture in all three cases and no message in any
//! of them; the agent went on logging `capture_fps=0.0` as if the screen were merely still.
//!
//! ## What can actually be observed here, and what is done about each
//!
//! | observation | meaning | action |
//! |---|---|---|
//! | [`Capturer::check`] fails | the capture ended on its own: the WGC thread exits when its frame handler fails, when the captured monitor closes, or when its message loop fails | restart at once (`capture_lost`); back off on repeated failure; end the session after [`MAX_CAPTURE_FAILURES`] in a row with no frame between them |
//! | creating or starting a capturer fails | no capture to be had right now (a display being reconfigured, a GPU reset) | the same backoff and the same limit |
//! | pointer moved, no frame | WGC composites the cursor, so an absolute move on the captured screen is a change it must deliver — silence then is not a still screen | one restart (`capture_stalled`), rate-limited, never session-ending: a cursor can also fail to move for reasons no restart fixes (input blocked by an elevated window, the secure desktop) |
//! | [`ENCODE_ERRORS_BEFORE_RESTART`] encode errors in a row, or one panic | the encoder is broken | recreate it (`encoder_error`); end the session after [`MAX_ENCODER_FAILURES`] |
//! | an encode or a restart has not returned for [`BUSY_STALL_AFTER`] | stuck in a call nothing here can interrupt | report `stalled`; end the session at [`BUSY_FATAL_AFTER`] |
//! | no frames and no input | a still screen | nothing |
//! | the session's background hold is published (`crate::bg_hold`) | the viewer's page is hidden past its grace: no video on purpose | stop the capture (the game capturer, which can hold, keeps watching its window), and no check, no stall evidence, no mode change while it lasts; on its end start the capture again in the mode in force then, the next frame a keyframe — `ok` throughout, not a restart |
//!
//! After every recovery the next frame is a keyframe, because the viewer's decoder has no reference
//! to predict the first frame of a new capture from.
//!
//! ## Who runs what
//!
//! [`Supervisor`] lives on the encode thread (`crate::agent::encode_loop`), which already owns the
//! encoder and wakes at least every [`SUPERVISE_EVERY`] even with no frame to encode. It is the only
//! writer of the pipeline's state. [`PipelineHealth`] is what it shares: timestamps and the state,
//! read once a second by the heartbeat task, which is also the one place that can notice the encode
//! thread itself being stuck — the thread cannot report on itself from inside a call that never
//! returns.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_protocol::{Heartbeat, InputMessage, PipelineCause, PipelineState};
use tokio::sync::Notify;

use crate::game::SessionCapture;
use crate::quality::QualityTarget;
use crate::sync::lock;
use crate::traits::{Capturer, Encoder};
use crate::types::Frame;

/// The longest the encode thread waits for a frame before supervising anyway.
///
/// A tenth of a second: the dead-capture check runs every [`CAPTURE_CHECK_EVERY`] and a stop
/// request is noticed within this, while an idle thread waking ten times a second costs nothing
/// measurable.
pub const SUPERVISE_EVERY: Duration = Duration::from_millis(100);

/// How often the capturer is asked whether it is still running. See [`Capturer::check`].
const CAPTURE_CHECK_EVERY: Duration = Duration::from_millis(250);

/// Hard capture failures in a row — dead, or refusing to start — with no frame in between, after
/// which the session is ended rather than retried.
///
/// Six, with [`capture_retry_delay`] between them: attempts at 0, 1, 2, 4 and 8 seconds, so about
/// fifteen seconds of trying. Long enough to ride out a display reconfiguration or a driver reset,
/// short enough that the viewer's own deadline (`PIPELINE_RECOVERY_TIMEOUT_MS`, 20 s) is the
/// backstop and not the rule.
pub const MAX_CAPTURE_FAILURES: u32 = 6;

/// How long after a restart the pipeline reports `restarting` while waiting for a frame to prove
/// the new capture works.
///
/// A first frame normally follows within tens of milliseconds, and it ends the wait. Its absence is
/// not proof of failure — a still screen may send nothing — so when this runs out the capture is
/// taken as running, and only a new observation can condemn it again.
pub const RESTART_SETTLE: Duration = Duration::from_secs(2);

/// Pointer moves unanswered by any frame for this long are a stalled capture...
pub const INPUT_STALL_AFTER: Duration = Duration::from_secs(3);

/// ...provided the moves themselves kept coming for at least this long.
///
/// So a single move, or one burst, cannot condemn a capture: the capturer's pacing gate
/// legitimately discards a frame that arrives before its slot, and a burst of moves inside one
/// frame interval can produce one frame that is then discarded. Half a second is four intervals at
/// the slowest rung (8 fps); a move that late always finds its slot open.
pub const INPUT_STALL_SPREAD: Duration = Duration::from_millis(500);

/// Two pointer positions closer than this, in normalised screen units, may be the same pixel, and
/// a move to where the cursor already is changes nothing on screen.
const POINTER_EPSILON: f64 = 0.001;

/// The least time between two stall-triggered restarts, doubling on each one up to
/// [`STALL_GAP_MAX`], and back to this after [`STALL_GAP_RESET`] without one.
///
/// Rate-limited because the evidence is ambiguous in one direction: a cursor that does not move
/// (input refused by an elevated window, the secure desktop, a game that pins it) produces no frame
/// either, and no number of restarts fixes that. Each restart costs a keyframe, so this bounds what
/// a misread can cost to one keyframe every minute.
const STALL_GAP_MIN: Duration = Duration::from_secs(10);
const STALL_GAP_MAX: Duration = Duration::from_secs(60);
const STALL_GAP_RESET: Duration = Duration::from_secs(300);

/// Encode errors in a row that condemn an encoder. One could be a bad frame; three is the encoder.
pub const ENCODE_ERRORS_BEFORE_RESTART: u32 = 3;

/// Encoder failures in a row — condemned, or refusing to be created — with no successful encode in
/// between, after which the session is ended. Recreations at 0, 1 and 2 seconds.
pub const MAX_ENCODER_FAILURES: u32 = 4;

/// A pipeline call — an encode, or a restart — that has not returned for this long is reported as
/// `stalled`. An encode takes milliseconds and a restart well under a second.
pub const BUSY_STALL_AFTER: Duration = Duration::from_secs(5);

/// And for this long, the session is ended. Nothing in this process can interrupt the call.
pub const BUSY_FATAL_AFTER: Duration = Duration::from_secs(15);

/// Nothing captured for this long, with the pipeline healthy, is reported as a still screen.
pub const STILL_AFTER_MS: u64 = 1_000;

/// How long after a background hold's end the capture started again has to deliver its first
/// frame before that is worth a warning.
///
/// A fresh WGC capture delivers the screen as it is on start — 31 ms after it in measured logs,
/// the start itself 83-430 ms for the monitor and about 10 ms for a game's window — and a
/// game capture with no window to show sends a black frame at once. A second is several times
/// either. Not a failure on its own (the capture is then taken as running, as after a restart's
/// settle), but the viewer is looking at the picture from before the hold until a frame comes.
pub const HOLD_FIRST_FRAME_WITHIN: Duration = Duration::from_secs(1);

/// The delay before the next capture attempt after `failures` hard failures in a row.
fn capture_retry_delay(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::ZERO,
        n => Duration::from_secs(1u64 << (n - 2).min(3)),
    }
}

/// The delay before the next encoder attempt after `failures` failures in a row.
fn encoder_retry_delay(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::ZERO,
        n => Duration::from_secs(u64::from(n - 1).min(2)),
    }
}

/// The `session_end` reason for a pipeline that could not be brought back.
///
/// Agreed values from `SESSION_END_REASONS` in the contract (`afklink_protocol::end_reason`), which
/// the viewer maps to a sentence.
pub fn end_reason(cause: PipelineCause) -> &'static str {
    use afklink_protocol::end_reason;
    match cause {
        PipelineCause::CaptureLost | PipelineCause::CaptureStalled => end_reason::CAPTURE_LOST,
        PipelineCause::EncoderError | PipelineCause::EncoderStalled => end_reason::ENCODER_ERROR,
    }
}

/// A call the encode thread is inside of, for the stuck-call check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Busy {
    Encode,
    CaptureRestart,
    EncoderRestart,
}

impl Busy {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::CaptureRestart,
            2 => Self::EncoderRestart,
            _ => Self::Encode,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            Self::Encode => 0,
            Self::CaptureRestart => 1,
            Self::EncoderRestart => 2,
        }
    }

    /// What a call stuck here is, in the heartbeat's terms.
    pub fn cause(self) -> PipelineCause {
        match self {
            Self::Encode | Self::EncoderRestart => PipelineCause::EncoderStalled,
            Self::CaptureRestart => PipelineCause::CaptureStalled,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encode => "encode",
            Self::CaptureRestart => "capture restart",
            Self::EncoderRestart => "encoder restart",
        }
    }
}

/// What the heartbeat task concludes about a call the encode thread is stuck in.
///
/// `episode` identifies the call (it is when the call began), so a reader can tell the same stuck
/// call seen twice from two different calls. The heartbeat task acts on `Fatal` only when it has
/// seen the same episode on an earlier tick too: after the machine sleeps, a call that was in
/// flight when it went down reads as ancient for the moment before the thread gets to finish it,
/// and that moment must not end a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyVerdict {
    /// Not inside a call, or not for long.
    Clear,
    /// Past [`BUSY_STALL_AFTER`]: reported as `stalled`.
    Stalled {
        what: Busy,
        for_ms: u64,
        episode: u64,
    },
    /// Past [`BUSY_FATAL_AFTER`]: the session has to end.
    Fatal {
        what: Busy,
        for_ms: u64,
        episode: u64,
    },
}

fn state_to_u8(s: PipelineState) -> u8 {
    match s {
        PipelineState::Ok => 0,
        PipelineState::Restarting => 1,
        PipelineState::Stalled => 2,
        PipelineState::Failed => 3,
    }
}

fn state_from_u8(v: u8) -> PipelineState {
    match v {
        1 => PipelineState::Restarting,
        2 => PipelineState::Stalled,
        3 => PipelineState::Failed,
        _ => PipelineState::Ok,
    }
}

fn cause_to_u8(c: Option<PipelineCause>) -> u8 {
    match c {
        None => 0,
        Some(PipelineCause::CaptureLost) => 1,
        Some(PipelineCause::CaptureStalled) => 2,
        Some(PipelineCause::EncoderError) => 3,
        Some(PipelineCause::EncoderStalled) => 4,
    }
}

fn cause_from_u8(v: u8) -> Option<PipelineCause> {
    match v {
        1 => Some(PipelineCause::CaptureLost),
        2 => Some(PipelineCause::CaptureStalled),
        3 => Some(PipelineCause::EncoderError),
        4 => Some(PipelineCause::EncoderStalled),
        _ => None,
    }
}

/// `-` for no cause, the wire spelling otherwise. For log fields.
pub fn cause_str(c: Option<PipelineCause>) -> &'static str {
    c.map_or("-", PipelineCause::as_str)
}

/// The pipeline's state as the heartbeat task sees it: written by the encode thread (and by the
/// event task, for pointer moves), read once a second.
///
/// Atomics, because the writer is on the per-frame path. Instants are stored as milliseconds since
/// [`Self::new`] plus one, so that zero can mean "never" without a sentinel that could also be a
/// time.
#[derive(Debug)]
pub struct PipelineHealth {
    epoch: Instant,
    last_capture: AtomicU64,
    last_encode: AtomicU64,
    busy_since: AtomicU64,
    busy_what: AtomicU8,
    state: AtomicU8,
    cause: AtomicU8,
    restarts: AtomicU32,
    /// Capture restarts that brought the capture back (the `capture restarted` line), and the cause
    /// of the last one: the session summary's `capture_restart` episodes (`crate::summary`), read by
    /// the control task on its tick.
    capture_restarts: AtomicU32,
    capture_restart_cause: AtomicU8,
    pointer_moves: AtomicU64,
    /// Wakes the heartbeat task on a state change, so a failure or a recovery reaches the viewer
    /// at once rather than on the next one-second tick.
    changed: Notify,
}

impl PipelineHealth {
    pub fn new(now: Instant) -> Self {
        Self {
            epoch: now,
            last_capture: AtomicU64::new(0),
            last_encode: AtomicU64::new(0),
            busy_since: AtomicU64::new(0),
            busy_what: AtomicU8::new(0),
            state: AtomicU8::new(state_to_u8(PipelineState::Ok)),
            cause: AtomicU8::new(cause_to_u8(None)),
            restarts: AtomicU32::new(0),
            capture_restarts: AtomicU32::new(0),
            capture_restart_cause: AtomicU8::new(cause_to_u8(None)),
            pointer_moves: AtomicU64::new(0),
            changed: Notify::new(),
        }
    }

    /// The capture was restarted and is running again, after `cause`. The cause goes first, and the
    /// count after it with release ordering, so a reader that sees the count move sees its cause.
    fn note_capture_restart(&self, cause: PipelineCause) {
        self.capture_restart_cause
            .store(cause_to_u8(Some(cause)), Ordering::Relaxed);
        self.capture_restarts.fetch_add(1, Ordering::Release);
    }

    /// Capture restarts that brought the capture back, and the last one's cause.
    pub fn capture_restarts(&self) -> (u32, Option<PipelineCause>) {
        let n = self.capture_restarts.load(Ordering::Acquire);
        (
            n,
            cause_from_u8(self.capture_restart_cause.load(Ordering::Relaxed)),
        )
    }

    fn stamp(&self, now: Instant) -> u64 {
        let ms = now.saturating_duration_since(self.epoch).as_millis();
        u64::try_from(ms).unwrap_or(u64::MAX - 1) + 1
    }

    /// Milliseconds from a stored stamp to `now`, or `None` for "never".
    fn age(&self, stamp: u64, now: Instant) -> Option<u64> {
        (stamp != 0).then(|| self.stamp(now).saturating_sub(stamp))
    }

    pub fn note_capture(&self, now: Instant) {
        self.last_capture.store(self.stamp(now), Ordering::Relaxed);
    }

    pub fn note_encode(&self, now: Instant) {
        self.last_encode.store(self.stamp(now), Ordering::Relaxed);
    }

    /// Milliseconds since the capturer last delivered a frame, `None` before the first.
    pub fn since_capture_ms(&self, now: Instant) -> Option<u64> {
        self.age(self.last_capture.load(Ordering::Relaxed), now)
    }

    /// Milliseconds since the encoder last produced a frame, `None` before the first.
    pub fn since_encode_ms(&self, now: Instant) -> Option<u64> {
        self.age(self.last_encode.load(Ordering::Relaxed), now)
    }

    /// The encode thread is about to make a call that could, in principle, never return.
    pub fn enter(&self, what: Busy, now: Instant) {
        self.busy_what.store(what.as_u8(), Ordering::Relaxed);
        // Release, so a reader that sees the new stamp also sees which call it belongs to.
        self.busy_since.store(self.stamp(now), Ordering::Release);
    }

    /// ...and it did.
    pub fn leave(&self) {
        self.busy_since.store(0, Ordering::Release);
    }

    /// The call the encode thread is inside of, and for how long.
    pub fn busy(&self, now: Instant) -> Option<(Busy, Duration)> {
        let since = self.busy_since.load(Ordering::Acquire);
        let for_ms = self.age(since, now)?;
        let what = Busy::from_u8(self.busy_what.load(Ordering::Relaxed));
        Some((what, Duration::from_millis(for_ms)))
    }

    /// An absolute pointer move to a new position was injected. Written by the event task.
    pub fn note_pointer_move(&self) {
        self.pointer_moves.fetch_add(1, Ordering::Relaxed);
    }

    pub fn pointer_moves(&self) -> u64 {
        self.pointer_moves.load(Ordering::Relaxed)
    }

    pub fn restarts(&self) -> u32 {
        self.restarts.load(Ordering::Relaxed)
    }

    fn note_restart(&self) {
        self.restarts.fetch_add(1, Ordering::Relaxed);
    }

    /// The state as the encode thread last published it.
    pub fn state(&self) -> (PipelineState, Option<PipelineCause>) {
        (
            state_from_u8(self.state.load(Ordering::Relaxed)),
            cause_from_u8(self.cause.load(Ordering::Relaxed)),
        )
    }

    /// Publish a state. True if it changed, in which case the heartbeat task is woken.
    ///
    /// The supervisor is the only writer in production; crate-visible for the heartbeat task's
    /// tests.
    pub(crate) fn publish(&self, state: PipelineState, cause: Option<PipelineCause>) -> bool {
        let s = state_to_u8(state);
        let c = cause_to_u8(cause);
        let changed = self.state.swap(s, Ordering::Relaxed) != s;
        let changed = self.cause.swap(c, Ordering::Relaxed) != c || changed;
        if changed {
            self.changed.notify_one();
        }
        changed
    }

    /// Resolves on the next state change. For the heartbeat task's `select!`.
    pub fn changed(&self) -> &Notify {
        &self.changed
    }

    /// Whether the encode thread is stuck, and how badly. See [`BUSY_STALL_AFTER`].
    pub fn busy_verdict(&self, now: Instant) -> BusyVerdict {
        // One load: the stamp is both the episode and the start, and must not change in between.
        let episode = self.busy_since.load(Ordering::Acquire);
        let Some(for_ms) = self.age(episode, now) else {
            return BusyVerdict::Clear;
        };
        let what = Busy::from_u8(self.busy_what.load(Ordering::Relaxed));
        let d = Duration::from_millis(for_ms);
        if d >= BUSY_FATAL_AFTER {
            BusyVerdict::Fatal {
                what,
                for_ms,
                episode,
            }
        } else if d >= BUSY_STALL_AFTER {
            BusyVerdict::Stalled {
                what,
                for_ms,
                episode,
            }
        } else {
            BusyVerdict::Clear
        }
    }

    /// The heartbeat to send now, and the stuck-call verdict it was built on.
    ///
    /// The published state, overlaid with what only this reader can see: an encode thread stuck
    /// inside a call reports nothing about itself, so a stuck call turns the heartbeat `stalled`
    /// here. `failed` stays the supervisor's word alone — it means the session is being ended —
    /// and the heartbeat task says it by ending the session, not by predicting it.
    pub fn heartbeat(&self, now: Instant, seq: u64, h: u32, fps: u32) -> (Heartbeat, BusyVerdict) {
        let (mut state, mut cause) = self.state();
        let verdict = self.busy_verdict(now);
        match verdict {
            BusyVerdict::Clear => {}
            BusyVerdict::Stalled { what, .. } | BusyVerdict::Fatal { what, .. } => {
                if state != PipelineState::Failed {
                    state = PipelineState::Stalled;
                    cause = Some(what.cause());
                }
            }
        }
        let since_capture_ms = self.since_capture_ms(now);
        let since_encode_ms = self.since_encode_ms(now);
        let still =
            state == PipelineState::Ok && since_capture_ms.is_none_or(|ms| ms >= STILL_AFTER_MS);
        (
            Heartbeat {
                seq,
                state,
                cause,
                since_capture_ms,
                since_encode_ms,
                still,
                h,
                fps,
                restarts: self.restarts(),
                // The pipeline's own state says nothing about the network; the heartbeat task sets
                // it from the controller's drain mode.
                net_stall: false,
                // This build's input moves a visible cursor by exactly the `r` fraction and honours
                // `r.x`/`r.y` (`afklink_input`'s cursor sync): the viewer steers it 1:1.
                rel_exact: true,
                // The pipeline knows nothing of the game window; the heartbeat task sets it from
                // the session's `crate::game::GameStatus`.
                game: None,
                // Nor of the input driver: the heartbeat task sets both from the injector
                // (`crate::input_reach`).
                no_driver: false,
                input_blocked: false,
                // This build honours the viewer's `vis` (`crate::bg_hold`): the viewer sends one
                // only after seeing this.
                vis_ok: true,
                // The pipeline does not decide the hold; the heartbeat task sets it from the
                // session's published flag. `still` above is true through a hold — healthy, and
                // nothing captured for longer than a still screen's second — and this says why.
                bg_hold: false,
            },
            verdict,
        )
    }
}

/// Counts the pointer moves that should have changed the captured screen. Owned by the event task.
///
/// Only absolute moves (`m`), and only to a new position: WGC composites the cursor, so moving it
/// on the captured monitor is a change the capture must deliver. Relative moves are not counted —
/// in a game the cursor is often hidden and pinned, and a camera that does not turn is not a
/// capture failure — and neither are clicks, keys or the wheel, which may change nothing visible.
pub struct PointerProbe {
    health: Arc<PipelineHealth>,
    last: Option<(f64, f64)>,
}

impl PointerProbe {
    pub fn new(health: Arc<PipelineHealth>) -> Self {
        Self { health, last: None }
    }

    /// Look at one input message on its way to the injector.
    pub fn observe(&mut self, msg: &InputMessage) {
        if let InputMessage::Move { x, y } = *msg {
            let moved = self.last.is_none_or(|(lx, ly)| {
                (x - lx).abs() > POINTER_EPSILON || (y - ly).abs() > POINTER_EPSILON
            });
            self.last = Some((x, y));
            if moved {
                self.health.note_pointer_move();
            }
        }
    }
}

/// Where the capture stands.
#[derive(Debug, Clone, Copy)]
enum Capture {
    /// Running, as far as anything shows.
    Running,
    /// Restarted at `since`; waiting for a first frame to prove the new capture works.
    Settling {
        since: Instant,
        cause: PipelineCause,
    },
    /// Not running. The next attempt is due at `retry_at`.
    Down {
        cause: PipelineCause,
        retry_at: Instant,
    },
    /// The background hold (`crate::bg_hold`): stopped on purpose since `since` — or, when the
    /// capturer can hold (`watching`, the game capturer), alive and delivering nothing. Not a
    /// failure: no check, no stall evidence, no mode change until it ends; reported `ok`.
    Held { since: Instant, watching: bool },
    /// Started again at `since` after a hold, waiting for its first frame. Reported `ok` and not
    /// counted as a restart; checked like a running capture.
    Resuming { since: Instant },
}

/// Watches the capture and the encoder from the encode thread, and puts them back when they fail.
///
/// See the module documentation for what counts as a failure and what is done about each. The
/// encode loop calls [`Self::poll`] every time round, with or without a frame, and reports every
/// frame and every encode through the other methods; everything this decides is published to
/// [`PipelineHealth`] and logged, transitions at info and each decision at debug.
pub struct Supervisor {
    health: Arc<PipelineHealth>,
    /// How this session makes capturers — the monitor, or the bound game's window only — and the
    /// encoder factory beside them. The only way a capturer is made here (`crate::game`).
    capture_source: SessionCapture,
    /// Shared with the session so that ending it can stop the capture even while this thread is
    /// stuck in an encode. Held here only across a check or a restart, never across an encode.
    capturer: Arc<Mutex<Box<dyn Capturer>>>,
    /// A sender into the encode thread's own channel, for each new capturer.
    frame_tx: Sender<Frame>,
    target: Arc<QualityTarget>,
    /// The same flag a viewer's PLI sets: the next encoded frame is a keyframe.
    pending_kf: Arc<AtomicBool>,
    capture: Capture,
    capture_failures: u32,
    next_check: Instant,
    /// The pointer-move count as last seen, and as it stood at the last frame.
    moves_seen: u64,
    moves_at_frame: u64,
    /// The first and the latest time moves were seen with no frame after them.
    unanswered: Option<(Instant, Instant)>,
    /// When a stall may next restart the capture, and the gap after that one.
    stall_restart_after: Option<Instant>,
    stall_gap: Duration,
    last_stall_restart: Option<Instant>,
    /// Some while the encoder is condemned: when to try making a new one.
    encoder_retry_at: Option<Instant>,
    encoder_failures: u32,
    encode_errors_in_row: u32,
    /// Set once the pipeline has been given up on. The session ends with this cause's reason.
    fatal: Option<PipelineCause>,
    /// Frames refused since the capture mode changed under the running capture (see
    /// [`Self::admits_frame`]): counted for one line when the capture is replaced.
    refused_frames: u64,
}

impl Supervisor {
    /// For a capture already started (made by `capture_source`) and an encoder already made — the
    /// session's first ones.
    pub fn new(
        health: Arc<PipelineHealth>,
        capture_source: SessionCapture,
        capturer: Arc<Mutex<Box<dyn Capturer>>>,
        frame_tx: Sender<Frame>,
        target: Arc<QualityTarget>,
        pending_kf: Arc<AtomicBool>,
        now: Instant,
    ) -> Self {
        let moves = health.pointer_moves();
        tracing::debug!(
            capture = %capture_source.mode().describe(),
            pointer_stall_evidence = capture_source.answers_pointer_moves(),
            "pipeline supervisor started"
        );
        Self {
            health,
            capture_source,
            capturer,
            frame_tx,
            target,
            pending_kf,
            capture: Capture::Running,
            capture_failures: 0,
            next_check: now + CAPTURE_CHECK_EVERY,
            moves_seen: moves,
            moves_at_frame: moves,
            unanswered: None,
            stall_restart_after: None,
            stall_gap: STALL_GAP_MIN,
            last_stall_restart: None,
            encoder_retry_at: None,
            encoder_failures: 0,
            encode_errors_in_row: 0,
            fatal: None,
            refused_frames: 0,
        }
    }

    /// Whether a frame just received may go on to the encoder: only while the capture mode it was
    /// captured in is still the one in force (`SessionCapture::admits_frames`). The owner who turns
    /// «only the game window» on mid-session has the monitor's frames stopped here at once — not
    /// only once the next [`Self::poll`] has replaced the capture — so none of the desktop reaches
    /// the viewer after the setting flipped. The first refusal is said at `debug`, the rest counted
    /// into the replacement's line.
    pub fn admits_frame(&mut self) -> bool {
        if self.capture_source.admits_frames() {
            if self.refused_frames > 0 {
                // Flipped back before the capture was replaced: its frames are right again.
                tracing::debug!(
                    refused = std::mem::take(&mut self.refused_frames),
                    "frames admitted again: the capture mode is back to this capture's"
                );
            }
            return true;
        }
        self.refused_frames += 1;
        if self.refused_frames == 1 {
            tracing::debug!(
                capture = %self.capture_source.mode().describe(),
                "frame refused: the capture mode changed and this capture was made for the old \
                 one; it is replaced at the supervisor's next look"
            );
        } else {
            tracing::trace!(
                refused = self.refused_frames,
                "frame refused: the capture mode changed"
            );
        }
        false
    }

    /// The shared state, for the encode loop's busy markers.
    pub fn health(&self) -> &PipelineHealth {
        &self.health
    }

    /// The flag that makes the next encoded frame a keyframe — the same one a viewer's PLI sets,
    /// and the one this supervisor sets after a capture restart.
    pub fn keyframe_flag(&self) -> Arc<AtomicBool> {
        self.pending_kf.clone()
    }

    /// Why the session has to end, once the pipeline has been given up on.
    pub fn fatal_reason(&self) -> Option<&'static str> {
        self.fatal.map(end_reason)
    }

    /// Supervise: check the capture, weigh the pointer evidence, and make any restart that is due.
    ///
    /// `frames` is the encode thread's channel, emptied during a capture restart: what the old
    /// capture left in it shows the screen before the failure, and must not be taken as proof that
    /// the new one works.
    pub fn poll(&mut self, now: Instant, frames: &Receiver<Frame>) {
        if self.fatal.is_some() {
            return;
        }
        // The background hold, before anything else here: while it lasts the capture is stopped on
        // purpose, and nothing below may read that as a failure, a stall or a moment to replace it.
        if self.target.bg_hold() {
            if !matches!(self.capture, Capture::Held { .. }) {
                self.begin_hold(now, frames);
            }
            self.publish();
            return;
        }
        if let Capture::Held { since, watching } = self.capture {
            self.end_hold(now, since, watching, frames);
        }
        self.gather_pointer_evidence(now);

        // The owner switched «only the game window» on or off (or bound another game) while this
        // session runs: the capture is replaced at once, before anything else here can make one of
        // the old kind. Not a failure: the count of those starts over.
        if let Some(from) = self.capture_source.take_change() {
            tracing::info!(
                from = %from.describe(),
                to = %self.capture_source.mode().describe(),
                frames_refused = std::mem::take(&mut self.refused_frames),
                "capture mode changed during the session; replacing the capture"
            );
            self.capture_failures = 0;
            self.forget_input_evidence();
            self.restart_capture(
                now,
                PipelineCause::CaptureLost,
                "capture mode changed",
                frames,
            );
        }

        // Is the capture still running?
        if matches!(
            self.capture,
            Capture::Running | Capture::Settling { .. } | Capture::Resuming { .. }
        ) && now >= self.next_check
        {
            self.next_check = now + CAPTURE_CHECK_EVERY;
            let checked = lock(&self.capturer).check();
            if let Err(e) = checked {
                self.capture_failed(now, PipelineCause::CaptureLost, &format!("{e:#}"));
            }
        }

        // A restart that is due, including one just scheduled with no delay.
        if let Capture::Down { cause, retry_at } = self.capture {
            if now >= retry_at {
                self.restart_capture(now, cause, "the capture failed", frames);
            }
        }

        // A restart that has had long enough to show a frame, and has not.
        if let Capture::Settling { since, cause } = self.capture {
            if now.saturating_duration_since(since) >= RESTART_SETTLE {
                tracing::debug!(
                    cause = cause.as_str(),
                    settle_ms = RESTART_SETTLE.as_millis() as u64,
                    "no frame since capture was restarted; nothing says it failed (a still screen \
                     sends none either), so it is taken as running"
                );
                self.capture = Capture::Running;
            }
        }

        // A capture started again after a hold that has not shown its first frame in the time a
        // fresh capture takes several times over. Not a failure — nothing says it failed — but the
        // viewer is still looking at the picture from before the hold.
        if let Capture::Resuming { since } = self.capture {
            let waited = now.saturating_duration_since(since);
            if waited >= HOLD_FIRST_FRAME_WITHIN {
                tracing::warn!(
                    waited_ms = waited.as_millis() as u64,
                    within_ms = HOLD_FIRST_FRAME_WITHIN.as_millis() as u64,
                    game_only = self.capture_source.mode().is_game(),
                    "background hold over, but the capture started again has delivered no frame; \
                     taken as running (a check or a stall restart answers it if it is not)"
                );
                self.capture = Capture::Running;
            }
        }

        if matches!(self.capture, Capture::Running) {
            if self.capture_source.answers_pointer_moves() {
                self.check_input_stall(now, frames);
            } else if self.unanswered.is_some() {
                // The game's window capture: the cursor may be outside the window, and the game
                // capturer answers for its own silence (black frames). Not evidence of anything.
                tracing::trace!("pointer moves without a frame ignored in game mode");
                self.forget_input_evidence();
            }
        }
        self.publish();
    }

    /// A frame arrived from the capturer.
    pub fn frame_captured(&mut self, now: Instant) {
        self.health.note_capture(now);
        self.forget_input_evidence();
        match self.capture {
            Capture::Settling { since, cause } => {
                tracing::info!(
                    cause = cause.as_str(),
                    after_ms = now.saturating_duration_since(since).as_millis() as u64,
                    restarts = self.health.restarts(),
                    "capture restored: first frame since the restart"
                );
                self.capture = Capture::Running;
                self.capture_failures = 0;
                self.publish();
            }
            Capture::Running => {
                if self.capture_failures > 0 {
                    tracing::debug!(
                        failures = self.capture_failures,
                        "a frame arrived: the capture failure count is cleared"
                    );
                    self.capture_failures = 0;
                }
            }
            // Left in the channel by the capture that failed; the restart is still due.
            Capture::Down { cause, .. } => tracing::trace!(
                cause = cause.as_str(),
                "frame from before the capture failed; restart still pending"
            ),
            Capture::Resuming { since } => {
                tracing::debug!(
                    first_frame_ms = now.saturating_duration_since(since).as_millis() as u64,
                    game_only = self.capture_source.mode().is_game(),
                    "background hold over: the capture started again delivered its first frame \
                     (the keyframe the viewer resumes on)"
                );
                self.capture = Capture::Running;
                self.capture_failures = 0;
            }
            // The encode loop takes no frame while held; one here is the stopped capture's last.
            Capture::Held { .. } => {
                tracing::trace!("frame during the background hold: from the capture just stopped");
            }
        }
    }

    /// The background hold began: stop the capture — or, for a capturer that can hold, leave it
    /// watching and delivering nothing — and empty the channel of what it left. Inside the stuck-call
    /// marker, as a restart is: a stop that never returns is the same fault.
    fn begin_hold(&mut self, now: Instant, frames: &Receiver<Frame>) {
        let was = match self.capture {
            Capture::Running => "running",
            Capture::Settling { .. } => "settling",
            Capture::Down { .. } => "down",
            Capture::Resuming { .. } => "resuming",
            Capture::Held { .. } => "held",
        };
        let began = Instant::now();
        self.health.enter(Busy::CaptureRestart, now);
        let (watching, stale) = {
            let mut current = lock(&self.capturer);
            // A capture that is down has nothing to hold; it is collected, and started afresh after.
            let watching = !matches!(self.capture, Capture::Down { .. }) && current.hold(true);
            if !watching {
                current.stop();
            }
            (watching, frames.try_iter().count())
        };
        self.health.leave();
        let took = began.elapsed();
        if self.refused_frames > 0 {
            tracing::debug!(
                refused = std::mem::take(&mut self.refused_frames),
                "frames refused for a mode change before the hold; the capture is replaced after it"
            );
        }
        self.forget_input_evidence();
        self.capture = Capture::Held {
            since: now + took,
            watching,
        };
        tracing::debug!(
            was,
            watching,
            stop_ms = took.as_millis() as u64,
            stale_frames_discarded = stale,
            game_only = self.capture_source.mode().is_game(),
            failures = self.capture_failures,
            since_capture_ms = self
                .health
                .since_capture_ms(now)
                .map_or_else(|| "-".to_string(), |v| v.to_string()),
            "background hold: {}",
            if watching {
                "the game capture stops its window capture and black frames and keeps watching \
                 the window; no check, no stall evidence and no mode change until the hold ends"
            } else {
                "capture stopped; no check, no stall evidence and no mode change until the hold \
                 ends"
            }
        );
    }

    /// The background hold ended: start the capture again — in the mode in force now, taken first
    /// so «Только игра» stays fail-closed through a hold — with the next frame a keyframe. Not a
    /// restart: not counted, and reported `ok` while its first frame comes. A start that fails is
    /// a capture failure like any other, and the restart path takes over.
    fn end_hold(&mut self, now: Instant, since: Instant, watching: bool, frames: &Receiver<Frame>) {
        let changed = self.capture_source.take_change();
        if let Some(from) = &changed {
            tracing::info!(
                from = %from.describe(),
                to = %self.capture_source.mode().describe(),
                "capture mode changed during the background hold; the capture resumes in the new \
                 mode"
            );
            self.capture_failures = 0;
        }
        let began = Instant::now();
        self.health.enter(Busy::CaptureRestart, now);
        let (result, how, stale) = {
            let mut current = lock(&self.capturer);
            if watching && changed.is_none() && current.hold(false) {
                (Ok(()), "released", 0)
            } else {
                current.stop();
                let stale = frames.try_iter().count();
                let result = match self.capture_source.make() {
                    Ok(mut fresh) => {
                        match fresh.start(self.frame_tx.clone(), self.target.clone()) {
                            Ok(()) => {
                                *current = fresh;
                                Ok(())
                            }
                            Err(e) => Err(format!("start: {e:#}")),
                        }
                    }
                    Err(e) => Err(format!("create: {e:#}")),
                };
                (result, "started", stale)
            }
        };
        self.health.leave();
        let took = began.elapsed();
        let done = now + took;
        let held_ms = now.saturating_duration_since(since).as_millis() as u64;
        match result {
            Ok(()) => {
                // The viewer's decoder last saw the screen as it was before the hold.
                self.pending_kf.store(true, Ordering::SeqCst);
                self.capture = Capture::Resuming { since: done };
                self.next_check = done + CAPTURE_CHECK_EVERY;
                self.forget_input_evidence();
                tracing::debug!(
                    how,
                    start_ms = took.as_millis() as u64,
                    held_ms,
                    stale_frames_discarded = stale,
                    game_only = self.capture_source.mode().is_game(),
                    "background hold over: capture started again; the next frame is a keyframe"
                );
            }
            Err(why) => {
                tracing::warn!(
                    start_ms = took.as_millis() as u64,
                    held_ms,
                    "background hold over, but the capture could not start again ({why}); the \
                     restart path takes over"
                );
                self.capture_failed(done, PipelineCause::CaptureLost, &why);
            }
        }
    }

    /// The encoder returned without an error. `produced` if it made a frame rather than skipping.
    pub fn encode_ok(&mut self, now: Instant, produced: bool) {
        if produced {
            self.health.note_encode(now);
        }
        self.encode_errors_in_row = 0;
        if self.encoder_failures > 0 {
            tracing::info!(
                failures = self.encoder_failures,
                "encoder restored: the new encoder is encoding"
            );
            self.encoder_failures = 0;
        }
    }

    /// The encoder returned an error, or panicked. True if it is condemned: the caller drops it,
    /// and a new one is made once [`Self::encoder_due`] says so.
    pub fn encode_failed(&mut self, now: Instant, panicked: bool, why: &str) -> bool {
        self.encode_errors_in_row += 1;
        if !panicked && self.encode_errors_in_row < ENCODE_ERRORS_BEFORE_RESTART {
            tracing::debug!(
                in_row = self.encode_errors_in_row,
                limit = ENCODE_ERRORS_BEFORE_RESTART,
                "encode error tolerated: one bad frame is not a broken encoder"
            );
            return false;
        }
        let errors = self.encode_errors_in_row;
        self.encode_errors_in_row = 0;
        self.encoder_failed(
            now,
            &format!("{why} ({errors} in a row, panicked={panicked})"),
        );
        true
    }

    /// The encoder is down and a new one is due.
    pub fn encoder_due(&self, now: Instant) -> bool {
        self.fatal.is_none() && self.encoder_retry_at.is_some_and(|t| now >= t)
    }

    /// Make a new encoder. `None` if that failed, in which case the next attempt is scheduled, or
    /// the pipeline given up on.
    pub fn recreate_encoder(&mut self, now: Instant) -> Option<Box<dyn Encoder>> {
        tracing::debug!(failures = self.encoder_failures, "recreating the encoder");
        self.health.enter(Busy::EncoderRestart, now);
        let made = (self.capture_source.backends().make_encoder)();
        self.health.leave();
        match made {
            Ok(mut encoder) => {
                // A fresh encoder opens with an IDR anyway. Asked for explicitly so that stays true
                // of a backend that does not.
                encoder.request_keyframe();
                self.encoder_retry_at = None;
                self.health.note_restart();
                tracing::info!(
                    failures = self.encoder_failures,
                    restarts = self.health.restarts(),
                    "encoder recreated; its first frame will be a keyframe"
                );
                self.publish();
                Some(encoder)
            }
            Err(e) => {
                self.encoder_failed(now, &format!("could not create one: {e:#}"));
                None
            }
        }
    }

    fn encoder_failed(&mut self, now: Instant, why: &str) {
        self.encoder_failures += 1;
        if self.encoder_failures >= MAX_ENCODER_FAILURES {
            tracing::error!(
                failures = self.encoder_failures,
                "the encoder could not be brought back ({why}); ending the session"
            );
            self.fatal = Some(PipelineCause::EncoderError);
        } else {
            let delay = encoder_retry_delay(self.encoder_failures);
            tracing::warn!(
                failures = self.encoder_failures,
                retry_in_ms = delay.as_millis() as u64,
                "encoder failed: {why}; making a new one"
            );
            self.encoder_retry_at = Some(now + delay);
        }
        self.publish();
    }

    fn capture_failed(&mut self, now: Instant, cause: PipelineCause, why: &str) {
        self.capture_failures += 1;
        if self.capture_failures >= MAX_CAPTURE_FAILURES {
            tracing::error!(
                failures = self.capture_failures,
                cause = cause.as_str(),
                "capture could not be brought back ({why}); ending the session"
            );
            self.fatal = Some(cause);
        } else {
            let delay = capture_retry_delay(self.capture_failures);
            tracing::warn!(
                failures = self.capture_failures,
                cause = cause.as_str(),
                retry_in_ms = delay.as_millis() as u64,
                "capture failed: {why}"
            );
            self.capture = Capture::Down {
                cause,
                retry_at: now + delay,
            };
        }
        self.publish();
    }

    fn restart_capture(
        &mut self,
        now: Instant,
        cause: PipelineCause,
        why: &'static str,
        frames: &Receiver<Frame>,
    ) {
        tracing::info!(
            cause = cause.as_str(),
            why,
            game_only = self.capture_source.mode().is_game(),
            failures = self.capture_failures,
            since_capture_ms = self
                .health
                .since_capture_ms(now)
                .map_or_else(|| "-".to_string(), |v| v.to_string()),
            "restarting capture"
        );
        // Timed on the real clock, and carried forward from `now` rather than read afresh, so every
        // instant this supervisor holds is on the caller's clock.
        let began = Instant::now();
        self.health.enter(Busy::CaptureRestart, now);
        let (result, stale) = {
            let mut current = lock(&self.capturer);
            // Stopped first even when it already died: that is what collects its thread.
            current.stop();
            // What the old capture left in the channel shows the screen before the failure. Emptied
            // here — after its thread is gone, before the new one can add anything — so none of it
            // passes for the new capture's first frame, and none of the new capture's is discarded.
            let stale = frames.try_iter().count();
            // The session's mode decides the factory: in game mode this is the game capturer, after
            // any failure — never the monitor.
            let result = match self.capture_source.make() {
                Ok(mut fresh) => match fresh.start(self.frame_tx.clone(), self.target.clone()) {
                    Ok(()) => {
                        *current = fresh;
                        Ok(())
                    }
                    Err(e) => Err(format!("start: {e:#}")),
                },
                Err(e) => Err(format!("create: {e:#}")),
            };
            (result, stale)
        };
        self.health.leave();
        let took = began.elapsed();
        let took_ms = took.as_millis() as u64;
        let done = now + took;
        match result {
            Ok(()) => {
                self.health.note_restart();
                self.health.note_capture_restart(cause);
                // The viewer's decoder has nothing to predict the new capture's first frame from.
                self.pending_kf.store(true, Ordering::SeqCst);
                self.capture = Capture::Settling { since: done, cause };
                self.next_check = done + CAPTURE_CHECK_EVERY;
                self.forget_input_evidence();
                tracing::info!(
                    cause = cause.as_str(),
                    took_ms,
                    stale_frames_discarded = stale,
                    restarts = self.health.restarts(),
                    "capture restarted; the next frame will be a keyframe"
                );
            }
            Err(why) => {
                tracing::debug!(
                    took_ms,
                    stale_frames_discarded = stale,
                    "capture restart attempt failed"
                );
                self.capture_failed(done, cause, &why);
            }
        }
    }

    fn gather_pointer_evidence(&mut self, now: Instant) {
        let moves = self.health.pointer_moves();
        if moves == self.moves_seen {
            return;
        }
        self.moves_seen = moves;
        if moves > self.moves_at_frame {
            match &mut self.unanswered {
                Some((_, last)) => *last = now,
                None => self.unanswered = Some((now, now)),
            }
        }
    }

    fn forget_input_evidence(&mut self) {
        let moves = self.health.pointer_moves();
        self.moves_seen = moves;
        self.moves_at_frame = moves;
        self.unanswered = None;
    }

    fn check_input_stall(&mut self, now: Instant, frames: &Receiver<Frame>) {
        let Some((first, last)) = self.unanswered else {
            return;
        };
        let waited = now.saturating_duration_since(first);
        let spread = last.saturating_duration_since(first);
        if waited < INPUT_STALL_AFTER || spread < INPUT_STALL_SPREAD {
            return;
        }
        let moves = self.moves_seen.saturating_sub(self.moves_at_frame);
        let since_capture = self
            .health
            .since_capture_ms(now)
            .map_or_else(|| "-".to_string(), |v| v.to_string());
        if let Some(after) = self.stall_restart_after {
            if now < after {
                tracing::debug!(
                    moves,
                    waited_ms = waited.as_millis() as u64,
                    since_capture_ms = %since_capture,
                    next_restart_in_ms = after.saturating_duration_since(now).as_millis() as u64,
                    "capture looks stalled again, but it was restarted for that recently; the \
                     cursor may simply not be moving (input refused, secure desktop), so waiting"
                );
                self.forget_input_evidence();
                return;
            }
        }
        if self
            .last_stall_restart
            .is_some_and(|t| now.saturating_duration_since(t) >= STALL_GAP_RESET)
        {
            tracing::debug!("no stall restart for a long while; the gap between them is reset");
            self.stall_gap = STALL_GAP_MIN;
        }
        tracing::warn!(
            moves,
            waited_ms = waited.as_millis() as u64,
            spread_ms = spread.as_millis() as u64,
            since_capture_ms = %since_capture,
            next_gap_s = self.stall_gap.as_secs(),
            "capture stalled: the pointer moved on the captured screen and no frame followed; \
             restarting capture"
        );
        self.last_stall_restart = Some(now);
        self.stall_restart_after = Some(now + self.stall_gap);
        self.stall_gap = (self.stall_gap * 2).min(STALL_GAP_MAX);
        self.restart_capture(
            now,
            PipelineCause::CaptureStalled,
            "pointer moves with no frame",
            frames,
        );
    }

    /// The state this supervisor's knowledge amounts to.
    fn status(&self) -> (PipelineState, Option<PipelineCause>) {
        if let Some(cause) = self.fatal {
            return (PipelineState::Failed, Some(cause));
        }
        match self.capture {
            Capture::Down { cause, .. } | Capture::Settling { cause, .. } => {
                (PipelineState::Restarting, Some(cause))
            }
            Capture::Running | Capture::Held { .. } | Capture::Resuming { .. }
                if self.encoder_retry_at.is_some() =>
            {
                (PipelineState::Restarting, Some(PipelineCause::EncoderError))
            }
            // A hold is on purpose, and the capture started after it is no restart.
            Capture::Running | Capture::Held { .. } | Capture::Resuming { .. } => {
                (PipelineState::Ok, None)
            }
        }
    }

    fn publish(&self) {
        let (state, cause) = self.status();
        let (was, was_cause) = self.health.state();
        if self.health.publish(state, cause) {
            tracing::info!(
                from = was.as_str(),
                from_cause = cause_str(was_cause),
                to = state.as_str(),
                cause = cause_str(cause),
                restarts = self.health.restarts(),
                "pipeline state changed"
            );
        }
    }
}

impl Drop for Supervisor {
    /// The capture must not outlive the pipeline that consumes it: every exit from the encode
    /// thread — the session ending, the pipeline given up on, a panic unwinding — passes here.
    ///
    /// `try_lock`, not a wait: the only other holder of the capturer is the session's capture-stop
    /// thread (`agent::stop_capture`), which holds it exactly while it stops this capture — and a
    /// stop can join a capture thread without a bound. Waiting here would keep this thread, the
    /// encoder and the media sender alive behind it for nothing: the capture is being stopped.
    fn drop(&mut self) {
        match self.capturer.try_lock() {
            Ok(mut c) => {
                c.stop();
                tracing::debug!("pipeline supervisor finished; capture stopped");
            }
            Err(std::sync::TryLockError::Poisoned(p)) => {
                p.into_inner().stop();
                tracing::debug!(
                    "pipeline supervisor finished; capture stopped (its lock was poisoned by a panic)"
                );
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                tracing::debug!(
                    "pipeline supervisor finished; the capture is being stopped by the session's \
                     capture-stop thread (it holds the capturer), not waited for here"
                );
            }
        }
    }
}

/// Scriptable capturers and encoders, for tests here and in `crate::agent` that drive the real
/// supervision and encode loop through the failures it exists for.
#[cfg(test)]
pub(crate) mod fakes {
    use super::*;
    use crate::agent::Backends;
    use crate::game::{CaptureMode, CaptureModeCell, GameStatus};
    use crate::traits::InputInjector;
    use crate::types::EncodedFrame;

    /// How a session over `backends` makes capturers in `mode`, with the cell a test flips to
    /// change the mode mid-session.
    pub(crate) fn session_capture(
        backends: Arc<Backends>,
        mode: CaptureMode,
    ) -> (SessionCapture, Arc<CaptureModeCell>, Arc<GameStatus>) {
        let modes = Arc::new(CaptureModeCell::new(mode));
        let status = Arc::new(GameStatus::new());
        (
            SessionCapture::new(backends, modes.clone(), status.clone()),
            modes,
            status,
        )
    }

    struct NoopInjector;
    impl InputInjector for NoopInjector {
        fn inject(&self, _event: &InputMessage) -> anyhow::Result<()> {
            Ok(())
        }
        fn release_all(&self) {}
    }

    /// Everything the fake capturers do, shared with the test that scripts them.
    #[derive(Default)]
    pub(crate) struct CaptureWorld {
        /// Monitor capturers made.
        pub created: u32,
        /// Game-window capturers made.
        pub game_created: u32,
        pub starts: u32,
        pub stops: u32,
        /// What each successful start was: `"monitor"` or `"game"`, in order.
        pub started_kinds: Vec<&'static str>,
        /// The sink of the capture currently running.
        pub sink: Option<Sender<Frame>>,
        /// The running capture's thread has "exited".
        pub dead: bool,
        /// This many upcoming `start`s fail.
        pub fail_starts: u32,
        /// Background holds asked of a running game capture (`true` to hold, `false` to release),
        /// in order. Monitor captures cannot hold, as the WGC one cannot.
        pub held_calls: Vec<bool>,
    }

    pub(crate) struct FakeCapturer {
        world: Arc<Mutex<CaptureWorld>>,
        running: bool,
        kind: &'static str,
    }

    impl Capturer for FakeCapturer {
        fn start(
            &mut self,
            sink: Sender<Frame>,
            _target: Arc<QualityTarget>,
        ) -> anyhow::Result<()> {
            let mut w = lock(&self.world);
            if w.fail_starts > 0 {
                w.fail_starts -= 1;
                anyhow::bail!("no {} to capture right now", self.kind);
            }
            w.starts += 1;
            w.started_kinds.push(self.kind);
            w.sink = Some(sink);
            w.dead = false;
            self.running = true;
            Ok(())
        }
        fn stop(&mut self) {
            if self.running {
                let mut w = lock(&self.world);
                w.stops += 1;
                w.sink = None;
                self.running = false;
            }
        }
        fn check(&mut self) -> anyhow::Result<()> {
            if !self.running {
                anyhow::bail!("not running");
            }
            if lock(&self.world).dead {
                anyhow::bail!("capture thread exited: frame buffer: device removed");
            }
            Ok(())
        }
        fn hold(&mut self, held: bool) -> bool {
            if self.kind != "game" || !self.running {
                return false;
            }
            lock(&self.world).held_calls.push(held);
            true
        }
    }

    /// Everything the fake encoders do.
    #[derive(Default)]
    pub(crate) struct EncoderWorld {
        pub created: u32,
        /// This many upcoming creations fail.
        pub fail_creates: u32,
        /// This many upcoming encodes return an error.
        pub errors: u32,
        /// This many upcoming encodes panic.
        pub panics: u32,
        pub keyframes_requested: u32,
        pub encoded: u32,
    }

    pub(crate) struct FakeEncoder {
        world: Arc<Mutex<EncoderWorld>>,
        force_key: bool,
    }

    impl Encoder for FakeEncoder {
        fn encode(&mut self, frame: &Frame) -> anyhow::Result<Option<EncodedFrame>> {
            let panic_now = {
                let mut w = lock(&self.world);
                if w.panics > 0 {
                    w.panics -= 1;
                    true
                } else {
                    false
                }
            };
            if panic_now {
                panic!("fake encoder: index out of bounds");
            }
            let mut w = lock(&self.world);
            if w.errors > 0 {
                w.errors -= 1;
                anyhow::bail!("openh264 encode: rc=-1");
            }
            w.encoded += 1;
            let is_keyframe = std::mem::take(&mut self.force_key) || w.encoded == 1;
            Ok(Some(EncodedFrame {
                data: vec![0, 0, 0, 1, if is_keyframe { 0x65 } else { 0x41 }],
                is_keyframe,
                timestamp_ms: frame.timestamp_ms,
            }))
        }
        fn request_keyframe(&mut self) {
            self.force_key = true;
            lock(&self.world).keyframes_requested += 1;
        }
    }

    pub(crate) fn fake_backends(
        capture: &Arc<Mutex<CaptureWorld>>,
        encode: &Arc<Mutex<EncoderWorld>>,
    ) -> Arc<Backends> {
        let cw = capture.clone();
        let gw = capture.clone();
        let ew = encode.clone();
        Arc::new(Backends {
            make_capturer: Box::new(move || {
                lock(&cw).created += 1;
                Ok(Box::new(FakeCapturer {
                    world: cw.clone(),
                    running: false,
                    kind: "monitor",
                }) as Box<dyn Capturer>)
            }),
            make_game_capturer: Box::new(move |_request| {
                lock(&gw).game_created += 1;
                Ok(Box::new(FakeCapturer {
                    world: gw.clone(),
                    running: false,
                    kind: "game",
                }) as Box<dyn Capturer>)
            }),
            make_encoder: Box::new(move || {
                let mut w = lock(&ew);
                if w.fail_creates > 0 {
                    w.fail_creates -= 1;
                    anyhow::bail!("OpenH264 would not initialise");
                }
                w.created += 1;
                Ok(Box::new(FakeEncoder {
                    world: ew.clone(),
                    force_key: false,
                }) as Box<dyn Encoder>)
            }),
            injector: Arc::new(NoopInjector),
        })
    }

    pub(crate) fn test_frame() -> Frame {
        Frame {
            data: vec![0; 16],
            width: 2,
            height: 2,
            timestamp_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fakes::*;
    use super::*;
    use std::sync::mpsc;

    struct Rig {
        t0: Instant,
        sup: Supervisor,
        health: Arc<PipelineHealth>,
        rx: Receiver<Frame>,
        capture: Arc<Mutex<CaptureWorld>>,
        encode: Arc<Mutex<EncoderWorld>>,
        kf: Arc<AtomicBool>,
        /// The owner's mode, flipped by a test to change it mid-session.
        modes: Arc<crate::game::CaptureModeCell>,
        game: Arc<crate::game::GameStatus>,
        /// Where the background hold is published, as the session's hold cell does.
        target: Arc<QualityTarget>,
    }

    impl Rig {
        fn at(&self, ms: u64) -> Instant {
            self.t0 + Duration::from_millis(ms)
        }
        fn poll(&mut self, ms: u64) {
            let now = self.at(ms);
            self.sup.poll(now, &self.rx);
        }
        /// The running fake capture delivers a frame, and the encode thread receives it.
        fn frame(&mut self, ms: u64) {
            let sink = lock(&self.capture)
                .sink
                .clone()
                .expect("a capture is running");
            sink.send(test_frame()).expect("channel open");
            while self.rx.try_recv().is_ok() {}
            let now = self.at(ms);
            self.sup.frame_captured(now);
        }
        fn state(&self) -> (PipelineState, Option<PipelineCause>) {
            self.health.state()
        }
    }

    fn rig() -> Rig {
        rig_in(crate::game::CaptureMode::Monitor)
    }

    /// A session whose capture the owner set to `mode`; its first capturer made the way
    /// `start_session` makes it.
    fn rig_in(mode: crate::game::CaptureMode) -> Rig {
        let t0 = Instant::now();
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let backends = fake_backends(&capture, &encode);
        let (tx, rx) = mpsc::channel();
        let target = Arc::new(QualityTarget::default());
        let (source, modes, game) = session_capture(backends, mode);
        let mut first = source.make().expect("first capturer");
        first
            .start(tx.clone(), target.clone())
            .expect("first start");
        let health = Arc::new(PipelineHealth::new(t0));
        let kf = Arc::new(AtomicBool::new(false));
        let sup = Supervisor::new(
            health.clone(),
            source,
            Arc::new(Mutex::new(first)),
            tx,
            target.clone(),
            kf.clone(),
            t0,
        );
        Rig {
            t0,
            sup,
            health,
            rx,
            capture,
            encode,
            kf,
            modes,
            game,
            target,
        }
    }

    /// The supervisor ends (the encode thread leaves) while the session's capture-stop thread holds
    /// the capturer inside a stop that waits on the capture's thread: it does not wait for it, the
    /// stop thread's stop is the only one, and nothing is left running.
    #[test]
    fn the_supervisor_leaves_a_capture_being_stopped_to_its_stopper() {
        use crate::offload::tests::Gate;
        struct GatedStop {
            gate: Arc<Gate>,
            stops: Arc<AtomicU32>,
            running: Arc<AtomicBool>,
        }
        impl Capturer for GatedStop {
            fn start(
                &mut self,
                _sink: Sender<Frame>,
                _target: Arc<QualityTarget>,
            ) -> anyhow::Result<()> {
                self.running.store(true, Ordering::SeqCst);
                Ok(())
            }
            fn stop(&mut self) {
                self.gate.wait();
                if self.running.swap(false, Ordering::SeqCst) {
                    self.stops.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let t0 = Instant::now();
        let capture = Arc::new(Mutex::new(CaptureWorld::default()));
        let encode = Arc::new(Mutex::new(EncoderWorld::default()));
        let (source, _modes, _game) = session_capture(
            fake_backends(&capture, &encode),
            crate::game::CaptureMode::Monitor,
        );
        let (tx, _rx) = mpsc::channel();
        let (gate, stops, running) = (
            Arc::new(Gate::default()),
            Arc::new(AtomicU32::new(0)),
            Arc::new(AtomicBool::new(true)),
        );
        let capturer: Arc<Mutex<Box<dyn Capturer>>> = Arc::new(Mutex::new(Box::new(GatedStop {
            gate: gate.clone(),
            stops: stops.clone(),
            running: running.clone(),
        })));
        let sup = Supervisor::new(
            Arc::new(PipelineHealth::new(t0)),
            source,
            capturer.clone(),
            tx,
            Arc::new(QualityTarget::default()),
            Arc::new(AtomicBool::new(false)),
            t0,
        );
        // The session's capture-stop thread, inside its stop.
        let held = capturer.clone();
        let stopper = std::thread::spawn(move || lock(&held).stop());
        let deadline = Instant::now() + Duration::from_secs(5);
        while gate.waiting.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "the stop thread is inside its stop"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let dropped_at = Instant::now();
        drop(sup);
        assert!(
            dropped_at.elapsed() < Duration::from_secs(1),
            "the supervisor did not wait for the stop"
        );
        assert_eq!(stops.load(Ordering::SeqCst), 0);
        gate.open();
        stopper.join().expect("the stop thread");
        assert_eq!(
            stops.load(Ordering::SeqCst),
            1,
            "stopped once, by the stop thread"
        );
        assert!(!running.load(Ordering::SeqCst), "nothing left running");
    }

    fn game_mode() -> crate::game::CaptureMode {
        crate::game::CaptureMode::GameWindow {
            binding: Some(crate::game::GameBinding::new(
                r"D:\Games\Scryde\Scryde\ScrydeGame.bin",
                "ScrydeGameUnrealWWindowsViewportWindow",
            )),
        }
    }

    /// Fail closed: in game mode the monitor capturer is never made — not at the start, not on a
    /// capture that died, not on starts that keep failing, not when the pipeline is finally given up
    /// on. The session ends (`capture_lost`) rather than fall back to the desktop.
    #[test]
    fn in_game_mode_the_monitor_is_never_captured_whatever_fails() {
        let mut r = rig_in(game_mode());
        assert_eq!(lock(&r.capture).game_created, 1);
        assert!(r.game.snapshot().active, "the heartbeat carries `game`");
        r.frame(100);

        // The game capture dies; its restart works.
        lock(&r.capture).dead = true;
        r.poll(300);
        r.frame(400);
        // Pointer moves with no frame: evidence of nothing in game mode, no restart for it.
        for (i, ms) in (500..=5_000).step_by(200).enumerate() {
            let mut probe = PointerProbe::new(r.health.clone());
            probe.observe(&InputMessage::Move {
                x: 0.1 + i as f64 * 0.01,
                y: 0.5,
            });
            r.poll(ms);
        }
        assert_eq!(
            lock(&r.capture).game_created,
            2,
            "no stall restart in game mode"
        );

        // Then it dies and cannot be started again, until the pipeline gives up.
        {
            let mut w = lock(&r.capture);
            w.fail_starts = u32::MAX;
            w.dead = true;
        }
        let mut ms = 5_100;
        while r.sup.fatal_reason().is_none() && ms < 60_000 {
            ms += 100;
            r.poll(ms);
        }
        assert_eq!(r.sup.fatal_reason(), Some("capture_lost"));
        let w = lock(&r.capture);
        assert_eq!(w.created, 0, "the monitor capturer was never made");
        assert!(w.game_created > 2);
        assert!(
            w.started_kinds.iter().all(|k| *k == "game"),
            "{:?}",
            w.started_kinds
        );
    }

    /// The owner turns the mode on during a session: the monitor capture is stopped and replaced by
    /// the game's at the next poll, with a keyframe; from then on every restart is the game's. Off
    /// again, the monitor is back.
    #[test]
    fn a_mode_change_mid_session_replaces_the_capture_at_once() {
        let mut r = rig();
        r.frame(50);
        assert_eq!(lock(&r.capture).started_kinds, vec!["monitor"]);
        assert!(!r.game.snapshot().active);

        r.modes.set(game_mode(), "test: on");
        r.poll(100);
        {
            let w = lock(&r.capture);
            assert_eq!(w.started_kinds, vec!["monitor", "game"]);
            assert!(w.stops >= 1, "the monitor capture was stopped first");
        }
        assert!(
            r.kf.load(Ordering::SeqCst),
            "the new capture opens with a keyframe"
        );
        assert!(r.game.snapshot().active);
        r.frame(150);
        assert_eq!(r.state(), (PipelineState::Ok, None));

        // A failure now brings back the game's capture, not the monitor's.
        lock(&r.capture).dead = true;
        r.poll(400);
        assert_eq!(
            lock(&r.capture).started_kinds,
            vec!["monitor", "game", "game"]
        );
        assert_eq!(lock(&r.capture).created, 1);

        // Unchanged mode: nothing happens.
        assert!(!r.modes.set(game_mode(), "test: again"));
        r.poll(700);
        assert_eq!(lock(&r.capture).started_kinds.len(), 3);

        r.modes.set(crate::game::CaptureMode::Monitor, "test: off");
        r.poll(1_000);
        assert_eq!(
            lock(&r.capture).started_kinds.last().copied(),
            Some("monitor")
        );
        assert!(
            !r.game.snapshot().active,
            "no `game` in the heartbeat any more"
        );
    }

    /// The owner turns the mode on: from that moment no frame of the monitor's capture is admitted
    /// — before the next poll replaces the capture, not after it. The game's capture's frames are.
    #[test]
    fn no_monitor_frame_is_admitted_once_game_only_is_turned_on() {
        let mut r = rig();
        r.frame(50);
        assert!(
            r.sup.admits_frame(),
            "the monitor's frames, in monitor mode"
        );
        let monitor_sink = lock(&r.capture).sink.clone().expect("running");

        r.modes.set(game_mode(), "test: on");
        // A frame the monitor captured just before (or after) the flip, not yet polled for.
        monitor_sink.send(test_frame()).expect("channel open");
        assert!(
            !r.sup.admits_frame(),
            "refused at once, before the supervisor has looked"
        );
        assert!(!r.sup.admits_frame(), "and every one after it");
        r.poll(100);
        assert_eq!(
            lock(&r.capture).started_kinds,
            vec!["monitor", "game"],
            "replaced at the poll"
        );
        assert_eq!(
            r.rx.try_iter().count(),
            0,
            "what the monitor left in the channel was discarded with it"
        );
        assert!(r.sup.admits_frame(), "the game's capture's frames pass");

        // And off again: the game's frames stop at once too.
        r.modes.set(crate::game::CaptureMode::Monitor, "test: off");
        assert!(!r.sup.admits_frame());
        r.poll(200);
        assert!(r.sup.admits_frame());
    }

    /// The case the whole module exists for: the capture thread exits on its own and the channel it
    /// fed stays open. The next check sees it, a fresh capture is started at once, the viewer is told
    /// `restarting` meanwhile, and the next frame is a keyframe.
    #[test]
    fn a_capture_that_dies_is_restarted_at_once_and_forces_a_keyframe() {
        let mut r = rig();
        r.frame(100);
        r.poll(300);
        assert_eq!(r.state(), (PipelineState::Ok, None));

        lock(&r.capture).dead = true;
        r.poll(600);
        {
            let w = lock(&r.capture);
            assert_eq!(
                w.created, 2,
                "a fresh capturer is made at once, not after a delay"
            );
            assert_eq!(w.starts, 2);
            assert!(
                w.stops >= 1,
                "the dead one is stopped, which collects its thread"
            );
        }
        assert_eq!(
            r.state(),
            (PipelineState::Restarting, Some(PipelineCause::CaptureLost)),
            "restarting until a frame proves the new capture works"
        );
        assert!(
            r.kf.load(Ordering::SeqCst),
            "the next encoded frame must be a keyframe"
        );
        assert_eq!(r.health.restarts(), 1);
        assert_eq!(
            r.health.capture_restarts(),
            (1, Some(PipelineCause::CaptureLost)),
            "the summary's capture_restart episode, with its cause"
        );

        r.frame(700);
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(r.sup.fatal_reason(), None);
    }

    /// No frame after a restart is not proof of failure — a still screen sends none — so the
    /// restart is taken as good once it has had its chance, rather than retried forever.
    #[test]
    fn a_restart_followed_by_silence_settles_as_running() {
        let mut r = rig();
        lock(&r.capture).dead = true;
        r.poll(300);
        assert_eq!(r.state().0, PipelineState::Restarting);
        let settled = 300 + RESTART_SETTLE.as_millis() as u64 + 100;
        r.poll(settled);
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(lock(&r.capture).created, 2, "and it is not restarted again");
    }

    /// A capture that cannot be started is retried with growing delays, and after
    /// MAX_CAPTURE_FAILURES in a row the session is ended with an agreed reason.
    #[test]
    fn a_capture_that_cannot_be_restarted_ends_the_session_as_capture_lost() {
        let mut r = rig();
        lock(&r.capture).fail_starts = 100;
        lock(&r.capture).dead = true;
        let mut ms = 300;
        r.poll(ms);
        assert_eq!(r.state().0, PipelineState::Restarting);
        // Walk the clock in 100 ms steps; the backoff decides when attempts happen.
        while r.sup.fatal_reason().is_none() && ms < 60_000 {
            ms += 100;
            r.poll(ms);
        }
        assert_eq!(r.sup.fatal_reason(), Some("capture_lost"));
        assert_eq!(
            r.state(),
            (PipelineState::Failed, Some(PipelineCause::CaptureLost))
        );
        // Attempts at +0, +1, +2, +4, +8 s after the first failure.
        assert!(
            (14_000..=17_000).contains(&ms),
            "gave up after {ms} ms; expected about fifteen seconds of trying"
        );
        assert_eq!(
            lock(&r.capture).created,
            1 + MAX_CAPTURE_FAILURES - 1,
            "one creation per retry"
        );
    }

    /// A start that fails once and then works is a restart, not an ending, and a frame clears the
    /// failure count so a later failure starts the backoff from the beginning.
    #[test]
    fn a_transient_start_failure_is_retried_and_recovers() {
        let mut r = rig();
        lock(&r.capture).fail_starts = 1;
        lock(&r.capture).dead = true;
        r.poll(300);
        assert_eq!(lock(&r.capture).starts, 1, "the first retry's start failed");
        r.poll(1_200);
        assert_eq!(
            lock(&r.capture).starts,
            1,
            "not before the one-second backoff"
        );
        // The backoff counts from when the failed attempt finished, a hair after 300 ms.
        r.poll(1_400);
        assert_eq!(lock(&r.capture).starts, 2, "retried after the backoff");
        r.frame(1_500);
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(r.sup.capture_failures, 0);
    }

    /// A desktop nobody touches: no frames for a minute, no input. Nothing is wrong, nothing is
    /// restarted, and the heartbeat says the screen is still rather than that anything failed.
    #[test]
    fn a_still_screen_is_never_restarted() {
        let mut r = rig();
        r.frame(50);
        for s in 1..=60 {
            r.poll(s * 1_000);
        }
        assert_eq!(lock(&r.capture).created, 1);
        assert_eq!(r.state(), (PipelineState::Ok, None));
        let (hb, verdict) = r.health.heartbeat(r.at(60_000), 0, 1080, 30);
        assert_eq!(verdict, BusyVerdict::Clear);
        assert_eq!(hb.state, PipelineState::Ok);
        assert!(
            hb.still,
            "no frames on a healthy pipeline is a still screen"
        );
        assert_eq!(hb.since_capture_ms, Some(59_950));
        assert_eq!(hb.since_encode_ms, None);
    }

    fn move_to(r: &Rig, x: f64) {
        let mut probe = PointerProbe::new(r.health.clone());
        probe.observe(&InputMessage::Move { x, y: 0.5 });
    }

    /// The pointer moved on the captured screen for seconds and not one frame followed — a change
    /// WGC must deliver, so the capture is stalled although its thread is running. One restart.
    #[test]
    fn pointer_moves_with_no_frame_restart_the_capture_once() {
        let mut r = rig();
        r.frame(0);
        for (i, ms) in (200..=3_600).step_by(200).enumerate() {
            move_to(&r, 0.1 + i as f64 * 0.01);
            r.poll(ms);
        }
        assert_eq!(lock(&r.capture).created, 2, "restarted for the stall");
        assert_eq!(
            r.state(),
            (
                PipelineState::Restarting,
                Some(PipelineCause::CaptureStalled)
            )
        );
        assert!(r.kf.load(Ordering::SeqCst));

        // It happens again at once — say the cursor is over an elevated window and cannot move.
        // The gap holds: no second restart inside it, and the state settles back to ok.
        for (i, ms) in (3_800..=9_000).step_by(200).enumerate() {
            move_to(&r, 0.5 + i as f64 * 0.01);
            r.poll(ms);
        }
        assert_eq!(
            lock(&r.capture).created,
            2,
            "not restarted again inside the gap"
        );
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(
            r.sup.fatal_reason(),
            None,
            "a stall never ends the session by itself"
        );
    }

    /// Moves that frames did answer, and a single burst of moves, are not evidence.
    #[test]
    fn answered_moves_and_a_single_burst_are_not_a_stall() {
        let mut r = rig();
        r.frame(0);
        // Every move answered by a frame, for ten seconds.
        for (i, ms) in (200..=10_000).step_by(200).enumerate() {
            move_to(&r, 0.1 + i as f64 * 0.001 * 2.0);
            r.poll(ms);
            r.frame(ms + 50);
        }
        // One burst: moves within 100 ms, then nothing, for five seconds with no frame.
        for (i, ms) in (10_100..=10_200).step_by(50).enumerate() {
            move_to(&r, 0.9 - i as f64 * 0.01);
            r.poll(ms);
        }
        for ms in (10_300..=15_300).step_by(100) {
            r.poll(ms);
        }
        assert_eq!(lock(&r.capture).created, 1);
        assert_eq!(r.state(), (PipelineState::Ok, None));
    }

    #[test]
    fn a_move_to_the_same_spot_is_not_counted() {
        let r = rig();
        let mut probe = PointerProbe::new(r.health.clone());
        probe.observe(&InputMessage::Move { x: 0.5, y: 0.5 });
        probe.observe(&InputMessage::Move { x: 0.5, y: 0.5 });
        probe.observe(&InputMessage::Move { x: 0.5004, y: 0.5 });
        probe.observe(&InputMessage::Rel {
            dx: 0.1,
            dy: 0.1,
            s: None,
            x: None,
            y: None,
        });
        probe.observe(&InputMessage::Down { b: 0 });
        assert_eq!(r.health.pointer_moves(), 1);
        probe.observe(&InputMessage::Move { x: 0.6, y: 0.5 });
        assert_eq!(r.health.pointer_moves(), 2);
    }

    /// One bad frame is tolerated; three in a row condemn the encoder, which is recreated at once
    /// with a keyframe asked for, and the state says so until it encodes again.
    #[test]
    fn repeated_encode_errors_recreate_the_encoder() {
        let mut r = rig();
        let now = r.at(100);
        assert!(!r.sup.encode_failed(now, false, "rc=-1"));
        r.sup.encode_ok(now, true);
        assert!(!r.sup.encode_failed(now, false, "rc=-1"));
        assert!(!r.sup.encode_failed(now, false, "rc=-1"));
        assert!(
            r.sup.encode_failed(now, false, "rc=-1"),
            "the third in a row condemns it"
        );
        assert_eq!(
            r.state(),
            (PipelineState::Restarting, Some(PipelineCause::EncoderError))
        );
        assert!(r.sup.encoder_due(now), "the first recreation is immediate");
        let mut fresh = r.sup.recreate_encoder(now).expect("a new encoder");
        assert_eq!(lock(&r.encode).keyframes_requested, 1);
        let out = fresh
            .encode(&test_frame())
            .expect("encodes")
            .expect("a frame");
        assert!(out.is_keyframe);
        r.sup.encode_ok(r.at(150), true);
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(r.health.restarts(), 1);
        assert_eq!(r.health.since_encode_ms(r.at(1_150)), Some(1_000));
    }

    #[test]
    fn a_panic_condemns_the_encoder_at_once() {
        let mut r = rig();
        assert!(r
            .sup
            .encode_failed(r.at(10), true, "panicked: index out of bounds"));
        assert!(r.sup.encoder_due(r.at(10)));
    }

    /// An encoder that cannot be made again ends the session, with the agreed reason.
    #[test]
    fn an_encoder_that_cannot_be_recreated_ends_the_session_as_encoder_error() {
        let mut r = rig();
        lock(&r.encode).fail_creates = 100;
        let mut ms = 0;
        assert!(r.sup.encode_failed(r.at(ms), true, "panicked"));
        while r.sup.fatal_reason().is_none() && ms < 30_000 {
            if r.sup.encoder_due(r.at(ms)) {
                assert!(r.sup.recreate_encoder(r.at(ms)).is_none());
            }
            ms += 100;
        }
        assert_eq!(r.sup.fatal_reason(), Some("encoder_error"));
        assert_eq!(
            r.state(),
            (PipelineState::Failed, Some(PipelineCause::EncoderError))
        );
        assert!(
            ms < 5_000,
            "gave up after {ms} ms; attempts are 0, 1 and 2 s apart"
        );
    }

    /// Only the heartbeat task can see the encode thread stuck inside a call; it overlays `stalled`
    /// and then `failed` on whatever the thread last published.
    #[test]
    fn a_call_that_never_returns_is_stalled_then_fatal() {
        let t0 = Instant::now();
        let health = PipelineHealth::new(t0);
        health.enter(Busy::Encode, t0);
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        assert_eq!(health.busy_verdict(at(4_000)), BusyVerdict::Clear);
        let (hb, v) = health.heartbeat(at(6_000), 3, 720, 30);
        assert!(matches!(
            v,
            BusyVerdict::Stalled {
                what: Busy::Encode,
                ..
            }
        ));
        assert_eq!(hb.state, PipelineState::Stalled);
        assert_eq!(hb.cause, Some(PipelineCause::EncoderStalled));
        assert!(!hb.still);
        let (hb, v) = health.heartbeat(at(16_000), 4, 720, 30);
        let BusyVerdict::Fatal {
            what: Busy::Encode,
            episode,
            ..
        } = v
        else {
            panic!("expected a fatal verdict, got {v:?}");
        };
        assert_eq!(
            hb.state,
            PipelineState::Stalled,
            "failed is the supervisor's word"
        );
        // The same call seen again is the same episode — what the heartbeat task waits for.
        assert!(matches!(
            health.busy_verdict(at(17_000)),
            BusyVerdict::Fatal { episode: e, .. } if e == episode
        ));
        health.leave();
        assert_eq!(health.busy_verdict(at(20_000)), BusyVerdict::Clear);
        // A new call is a new episode.
        health.enter(Busy::Encode, at(20_000));
        assert!(matches!(
            health.busy_verdict(at(40_000)),
            BusyVerdict::Fatal { episode: e, .. } if e != episode
        ));
    }

    #[test]
    fn the_session_end_reasons_are_the_agreed_ones() {
        assert_eq!(end_reason(PipelineCause::CaptureLost), "capture_lost");
        assert_eq!(end_reason(PipelineCause::CaptureStalled), "capture_lost");
        assert_eq!(end_reason(PipelineCause::EncoderError), "encoder_error");
        assert_eq!(end_reason(PipelineCause::EncoderStalled), "encoder_error");
    }

    /// The background hold: the capture is stopped, and through a minute of it — a dead capture, the
    /// pointer moving with no frame — nothing restarts it and the state stays `ok`. On its end the
    /// capture starts again with a keyframe, `ok` throughout, and is not counted as a restart.
    #[test]
    fn a_hold_stops_the_capture_and_its_end_is_not_a_restart() {
        let mut r = rig();
        r.frame(50);
        r.poll(100);
        r.target.set_bg_hold(true);
        r.poll(200);
        {
            let w = lock(&r.capture);
            assert_eq!(w.stops, 1, "stopped for the hold");
            assert!(w.sink.is_none());
        }
        assert_eq!(
            r.state(),
            (PipelineState::Ok, None),
            "a hold is not a failure"
        );
        assert!(!r.kf.load(Ordering::SeqCst));
        // A minute held: pointer moves with no frame, and the stopped capture "dead" — evidence
        // the supervisor must not read while held.
        lock(&r.capture).dead = true;
        for (i, ms) in (300..=60_000).step_by(200).enumerate() {
            move_to(&r, 0.1 + (i % 50) as f64 * 0.01);
            r.poll(ms);
        }
        assert_eq!(lock(&r.capture).created, 1, "no restart while held");
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(r.health.restarts(), 0);
        let (hb, _) = r.health.heartbeat(r.at(60_000), 0, 1080, 60);
        assert!(hb.still && hb.vis_ok && !hb.bg_hold, "{hb:?}");

        r.target.set_bg_hold(false);
        r.poll(60_100);
        {
            let w = lock(&r.capture);
            assert_eq!(w.created, 2, "a fresh capture for the resume");
            assert_eq!(w.starts, 2);
            assert!(w.sink.is_some());
        }
        assert!(
            r.kf.load(Ordering::SeqCst),
            "the resume opens with a keyframe"
        );
        assert_eq!(r.state(), (PipelineState::Ok, None), "not `restarting`");
        assert_eq!(r.health.restarts(), 0, "a resume is not a restart");
        r.frame(60_130);
        assert_eq!(r.state(), (PipelineState::Ok, None));
        // And the pointer evidence of the hold is forgotten: no stall restart from it.
        for ms in (60_200..=64_000).step_by(200) {
            r.poll(ms);
        }
        assert_eq!(lock(&r.capture).created, 2);
    }

    /// No first frame after the resume within its second: a warning, and the capture taken as
    /// running — never a restart on that alone.
    #[test]
    fn a_resume_with_no_frame_is_taken_as_running() {
        let mut r = rig();
        r.frame(50);
        r.target.set_bg_hold(true);
        r.poll(100);
        r.target.set_bg_hold(false);
        r.poll(20_000);
        assert!(matches!(r.sup.capture, Capture::Resuming { .. }));
        r.poll(20_000 + HOLD_FIRST_FRAME_WITHIN.as_millis() as u64 + 50);
        assert!(matches!(r.sup.capture, Capture::Running));
        assert_eq!(r.state(), (PipelineState::Ok, None));
        assert_eq!(lock(&r.capture).created, 2);
    }

    /// «Только игра» turned on during a hold: nothing is replaced while held, and the capture that
    /// resumes is the game's — the monitor's is never started again.
    #[test]
    fn game_only_turned_on_during_a_hold_resumes_in_game_mode() {
        let mut r = rig();
        r.frame(50);
        r.target.set_bg_hold(true);
        r.poll(100);
        r.modes.set(game_mode(), "test: on during the hold");
        r.poll(300);
        r.poll(5_000);
        assert_eq!(
            lock(&r.capture).started_kinds,
            vec!["monitor"],
            "no mode change while held"
        );
        r.target.set_bg_hold(false);
        r.poll(5_100);
        let w = lock(&r.capture);
        assert_eq!(w.started_kinds, vec!["monitor", "game"]);
        assert_eq!(
            w.created, 1,
            "the monitor capturer was made once, at the start"
        );
        drop(w);
        assert!(r.game.snapshot().active);
        assert!(r.kf.load(Ordering::SeqCst));
        assert!(r.sup.admits_frame());
    }

    /// The game capture can hold: it is held and released, not stopped and made again — its thread
    /// keeps watching the window. Unless the mode changed meanwhile: then it is replaced.
    #[test]
    fn a_game_capture_is_held_and_released_not_replaced() {
        let mut r = rig_in(game_mode());
        r.frame(50);
        r.target.set_bg_hold(true);
        r.poll(100);
        {
            let w = lock(&r.capture);
            assert_eq!(w.held_calls, vec![true]);
            assert_eq!(w.stops, 0, "kept alive to watch the window");
        }
        r.poll(30_000);
        r.target.set_bg_hold(false);
        r.poll(30_100);
        {
            let w = lock(&r.capture);
            assert_eq!(w.held_calls, vec![true, false]);
            assert_eq!(w.game_created, 1);
            assert_eq!(w.stops, 0);
        }
        assert!(r.kf.load(Ordering::SeqCst));
        assert_eq!(r.state(), (PipelineState::Ok, None));

        // Held again, and the owner turns game-only off meanwhile: the game capture is stopped and
        // the monitor's started — the mode in force at the resume.
        r.kf.store(false, Ordering::SeqCst);
        r.target.set_bg_hold(true);
        r.poll(40_000);
        r.modes.set(
            crate::game::CaptureMode::Monitor,
            "test: off during the hold",
        );
        r.target.set_bg_hold(false);
        r.poll(50_000);
        let w = lock(&r.capture);
        assert_eq!(w.held_calls, vec![true, false, true]);
        assert_eq!(w.started_kinds, vec!["game", "monitor"]);
        assert!(w.stops >= 1);
        drop(w);
        assert!(r.kf.load(Ordering::SeqCst));
    }

    /// A capture that cannot start after the hold is a capture failure like any other: the restart
    /// path, with its backoff, takes over.
    #[test]
    fn a_failed_start_after_a_hold_takes_the_restart_path() {
        let mut r = rig();
        r.frame(50);
        r.target.set_bg_hold(true);
        r.poll(100);
        lock(&r.capture).fail_starts = 1;
        r.target.set_bg_hold(false);
        r.poll(10_000);
        assert_eq!(
            r.state(),
            (PipelineState::Restarting, Some(PipelineCause::CaptureLost))
        );
        r.poll(11_200);
        assert_eq!(lock(&r.capture).starts, 2, "retried after the backoff");
        r.frame(11_300);
        assert_eq!(r.state(), (PipelineState::Ok, None));
    }

    #[test]
    fn the_supervisor_stops_the_capture_when_it_goes() {
        let r = rig();
        let capture = r.capture.clone();
        drop(r);
        assert!(lock(&capture).stops >= 1);
        assert!(lock(&capture).sink.is_none());
    }
}
