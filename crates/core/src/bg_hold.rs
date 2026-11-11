//! The background hold: while the viewer's page is hidden, the session sends no video.
//!
//! Never "pause": on the PC that word is the owner's access pause (the journal's `paused`, the kill
//! switch). Nothing of the hold is on screen anywhere.
//!
//! A hidden page shows nothing: the viewer has no sound and no picture-in-picture. Without the hold
//! the agent captures, encodes and sends into it at full rate: a Safari tab hidden for 19 s had the
//! PC encoding about 58 frames a second and sending 100-650 kbit/s, through a relay paid by the
//! gigabyte, on the PC's CPU.
//!
//! ## The states, per session
//!
//! ```text
//! Visible --vis hidden--> Grace --BG_HOLD_GRACE, or asleep (BG_HOLD_ASLEEP_AFTER)--> Held --resume--> Visible
//!                           \--resume (cancel, no effect)--> Visible
//! ```
//!
//! [`BgHold`] is the session's cell (what resumes a hold is listed there); [`HoldControl`] is the
//! control task's side, which freezes the quality controller and quiets str0m for the hold.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_protocol::InputMessage;
use tokio::sync::Notify;

use crate::quality::{QualityController, QualityTarget, Rung};
use crate::sync::lock;

/// How long the page must stay hidden before the hold begins. A shorter hide —
/// a glance at another chat, a notification — changes nothing. Unless the page is asleep: see
/// [`BG_HOLD_ASLEEP_AFTER`].
pub const BG_HOLD_GRACE: Duration = Duration::from_secs(10);

/// A hidden page whose receiver has been silent this long — counted from its last receiver report,
/// while we are sending — is asleep, and the hold begins at once instead of after the rest of
/// [`BG_HOLD_GRACE`].
///
/// ## Why
///
/// On an iPhone, Telegram's WebView stops every receiver report, transport-wide feedback and ICE
/// consent answer about a second after its page is hidden; without this, the grace goes on sending
/// the video into it — 2-6 Mbit/s for eight more seconds in a measured session, over a relay paid
/// by the gigabyte, to a page that can show nothing and, over UDP, will never get it. A page that
/// stays awake while hidden — a background browser tab, macOS's full-screen flicker, Telegram on a
/// Mac — keeps reporting through its grace (an empty interval at most) and keeps the whole grace,
/// so a glance away still changes nothing.
///
/// ## The evidence, and when it counts
///
/// The controller's own definition of a silent receiver ([`QualityController::receiver_silence`]):
/// two stats intervals in a row without a fresh receiver report while we are sending enough for one
/// to be due — the silence brake's count (`BRAKE_STALE_REPORTS` in `crate::quality`) — and two
/// seconds since the last one. Chrome's reports come every 0.5-1.5 s, so one empty interval is its
/// cadence and two are a cadence no awake receiver produces; requiring both keeps a single late
/// report, read a tick late, from passing for two seconds of silence. Only in the grace — after the
/// page's own `vis hidden`, never before and never without it: a silent receiver on a visible page
/// is the path's business (the silence brake's), and a viewer that predates `vis` is never held.
/// The silence may have begun before the `vis`; it counts from the last report all the same.
///
/// A receiver that falls silent while its page is hidden for a reason of the network's is held
/// early too, and that is fine: nobody is watching either way, the hold stops sending into the
/// silence, and its resume restarts str0m on what the receiver says then. A still screen, which
/// sends too little for silence to count, keeps the whole grace.
pub const BG_HOLD_ASLEEP_AFTER: Duration = Duration::from_secs(2);

/// The desired bitrate str0m is told while a session is held, in kbps.
///
/// str0m queues no probe under 5 kbps and caps every probe at twice the desired bitrate
/// (`str0m-0.23.1/src/bwe/probe/control.rs`, `queue_probe`), so at 1 kbps every ALR probe — every 5
/// s, up to twice the desired rate, into a page nobody looks at — is skipped. It moves nothing
/// else: the pacer's padding does not read it (`session.rs`, `configure_pacer`).
pub const BG_HOLD_DESIRED_KBPS: u32 = 1;

/// The phase as [`BgHold`]'s lock-free look sees it.
const VISIBLE: u8 = 0;
const GRACE: u8 = 1;
const HELD: u8 = 2;

/// What, besides `vis hidden: false`, ends a hold or cancels a grace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Real input from the viewer, named by its wire `t`.
    Input(&'static str),
    /// The viewer asked for a keyframe (`kf`).
    Keyframe,
    /// The viewer's `vv` report says its page is visible.
    ViewerVisible,
}

impl Trigger {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Trigger::Input(t) => t,
            Trigger::Keyframe => "kf",
            Trigger::ViewerVisible => "vv",
        }
    }

    /// The trigger a viewer's input message is, if it is one: real input — pointer, buttons, keys,
    /// text, combos, the wheel. Not `ra`: the viewer releases everything exactly when it hides.
    #[must_use]
    pub fn of_input(m: &InputMessage) -> Option<Trigger> {
        let t = match m {
            InputMessage::Move { .. } => "m",
            InputMessage::Rel { .. } => "r",
            InputMessage::Wheel { .. } => "w",
            InputMessage::Down { .. } => "d",
            InputMessage::Up { .. } => "u",
            InputMessage::Key { .. } => "k",
            InputMessage::Text { .. } => "text",
            InputMessage::Combo { .. } => "combo",
            _ => return None,
        };
        Some(Trigger::Input(t))
    }
}

/// Why a hold began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldStart {
    /// The page stayed hidden for [`BG_HOLD_GRACE`].
    Grace,
    /// The page is hidden and its receiver has been silent for [`BG_HOLD_ASLEEP_AFTER`]: asleep.
    Asleep,
}

impl HoldStart {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            HoldStart::Grace => "grace",
            HoldStart::Asleep => "asleep",
        }
    }
}

/// A hold that began: how long the page had been hidden, the `why` of the `vis` that hid it, what
/// began it, and the receiver's silence as the control task saw it then (`None`: reporting).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldStarted {
    pub hidden: Duration,
    pub why: String,
    pub by: HoldStart,
    pub silent: Option<Duration>,
}

/// A hold that ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldEnded {
    /// How long video was held back.
    pub held: Duration,
    /// How long the page had been hidden, the grace included.
    pub hidden: Duration,
    /// What ended it: `vis`, or a [`Trigger`]'s name.
    pub by: String,
    /// The `why` of the `vis` that ended it; `-` for anything else.
    pub why: String,
    /// The `why` of the `vis` that began it.
    pub hidden_why: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Visible,
    Grace {
        since: Instant,
        why: String,
    },
    Held {
        since: Instant,
        hidden_since: Instant,
        why: String,
    },
}

impl Phase {
    fn name(&self) -> &'static str {
        match self {
            Phase::Visible => "visible",
            Phase::Grace { .. } => "grace",
            Phase::Held { .. } => "held",
        }
    }

    fn code(&self) -> u8 {
        match self {
            Phase::Visible => VISIBLE,
            Phase::Grace { .. } => GRACE,
            Phase::Held { .. } => HELD,
        }
    }
}

struct Inner {
    phase: Phase,
    holds: u64,
    /// Held time of the holds that ended.
    held_total: Duration,
    /// The last hold that ended, until the control task takes it.
    ended: Option<HoldEnded>,
    /// `vis` messages received, for the session's last line.
    vis_received: u64,
}

/// The session's background hold.
///
/// The event task feeds it the viewer's messages; the control task polls it on its tick (the grace
/// runs out there); it publishes the hold into the session's [`QualityTarget`] (drain mode's
/// shape), where the hot paths read it: the pipeline supervisor stops the capture and starts it
/// again (`crate::pipeline`), the encode loop takes no frame, the heartbeat says `bg_hold`. A
/// resume is published the moment its message arrives, so the capture starts again without waiting
/// for a tick.
///
/// What resumes (or cancels a grace): `vis hidden: false`; any real input (`d`, `u`, `k`, `text`,
/// `combo`, `m`, `r`, `w`; never `ra`, which the viewer sends exactly when it hides); a `kf`; a
/// `vv` whose `visibility` is `visible` (only that way: `vv` is advisory and never starts a hold).
/// A `vis hidden: true` while in grace or held changes nothing. A viewer that predates `vis` never
/// sends one, and its sessions are never held. Every session starts visible on both sides.
pub struct BgHold {
    sid: String,
    target: Arc<QualityTarget>,
    inner: Mutex<Inner>,
    /// [`Phase::code`], for the input path's look without the lock: a moving pointer is sixty
    /// messages a second, and while the page is visible each of them asks only this.
    phase: AtomicU8,
    /// Wakes the heartbeat on a hold's start and end, so `bg_hold` reaches the viewer at once.
    changed: Notify,
}

impl std::fmt::Debug for BgHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BgHold")
            .field("sid", &self.sid)
            .field("phase", &self.phase.load(Ordering::Relaxed))
            .finish()
    }
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl BgHold {
    /// The cell of session `sid`, publishing into its `target`.
    pub fn new(sid: impl Into<String>, target: Arc<QualityTarget>) -> Self {
        Self {
            sid: sid.into(),
            target,
            inner: Mutex::new(Inner {
                phase: Phase::Visible,
                holds: 0,
                held_total: Duration::ZERO,
                ended: None,
                vis_received: 0,
            }),
            phase: AtomicU8::new(VISIBLE),
            changed: Notify::new(),
        }
    }

    /// The viewer's `vis`: its page is `hidden` now, or visible. One debug line each, with the
    /// state before and after.
    pub fn on_vis(&self, hidden: bool, why: Option<&str>, now: Instant) {
        let why = why.unwrap_or("-");
        let mut inner = lock(&self.inner);
        inner.vis_received += 1;
        let from = inner.phase.name();
        let (what, detail_ms) = match (inner.phase.clone(), hidden) {
            (Phase::Visible, true) => {
                inner.phase = Phase::Grace {
                    since: now,
                    why: why.to_string(),
                };
                (
                    "the grace begins; the hold follows unless the page comes back",
                    0,
                )
            }
            (Phase::Visible, false) => ("already visible: nothing to do", 0),
            (Phase::Grace { since, .. }, true) => (
                "hidden again during the grace: changes nothing",
                ms(now.saturating_duration_since(since)),
            ),
            (Phase::Grace { since, .. }, false) => {
                inner.phase = Phase::Visible;
                (
                    "grace cancelled: the page came back before the hold began",
                    ms(now.saturating_duration_since(since)),
                )
            }
            (Phase::Held { since, .. }, true) => (
                "hidden again during the hold: changes nothing",
                ms(now.saturating_duration_since(since)),
            ),
            (
                Phase::Held {
                    since,
                    hidden_since,
                    why: hidden_why,
                },
                false,
            ) => {
                self.end_hold(&mut inner, now, since, hidden_since, hidden_why, "vis", why);
                (
                    "the hold ends: video resumes with a keyframe of the current screen",
                    ms(now.saturating_duration_since(since)),
                )
            }
        };
        let to = inner.phase.name();
        self.phase.store(inner.phase.code(), Ordering::SeqCst);
        drop(inner);
        tracing::debug!(
            session = %self.sid,
            hidden,
            why,
            from,
            to,
            in_state_ms = detail_ms,
            "viewer vis: {what}"
        );
    }

    /// Something that resumes a hold or cancels a grace (see [`Trigger`]). While visible, nothing:
    /// said at trace, because input is the hot path.
    pub fn on_trigger(&self, trigger: Trigger, now: Instant) {
        if self.phase.load(Ordering::SeqCst) == VISIBLE {
            tracing::trace!(
                trigger = trigger.as_str(),
                "hold trigger while visible: nothing to resume"
            );
            return;
        }
        let mut inner = lock(&self.inner);
        match inner.phase.clone() {
            Phase::Visible => {
                tracing::trace!(
                    trigger = trigger.as_str(),
                    "hold trigger while visible: nothing to resume"
                );
            }
            Phase::Grace { since, why } => {
                inner.phase = Phase::Visible;
                tracing::debug!(
                    session = %self.sid,
                    trigger = trigger.as_str(),
                    grace_ms = ms(now.saturating_duration_since(since)),
                    hidden_why = %why,
                    "background hold: grace cancelled — the viewer is active again (no hold began)"
                );
            }
            Phase::Held {
                since,
                hidden_since,
                why,
            } => {
                self.end_hold(
                    &mut inner,
                    now,
                    since,
                    hidden_since,
                    why,
                    trigger.as_str(),
                    "-",
                );
                tracing::debug!(
                    session = %self.sid,
                    trigger = trigger.as_str(),
                    held_ms = ms(now.saturating_duration_since(since)),
                    "background hold: ended by the viewer's activity, not by a vis"
                );
            }
        }
        self.phase.store(inner.phase.code(), Ordering::SeqCst);
    }

    /// The control task's look, once a tick: a grace that has run out begins the hold, and so does
    /// a grace whose receiver has been silent for [`BG_HOLD_ASLEEP_AFTER`] — `receiver_silent`, the
    /// control task's [`QualityController::receiver_silence`]. `Some` on the tick it began.
    pub fn poll(&self, now: Instant, receiver_silent: Option<Duration>) -> Option<HoldStarted> {
        if self.phase.load(Ordering::SeqCst) != GRACE {
            return None;
        }
        let mut inner = lock(&self.inner);
        let Phase::Grace { since, why } = inner.phase.clone() else {
            return None;
        };
        let hidden = now.saturating_duration_since(since);
        let by = if hidden >= BG_HOLD_GRACE {
            HoldStart::Grace
        } else if receiver_silent.is_some_and(|s| s >= BG_HOLD_ASLEEP_AFTER) {
            HoldStart::Asleep
        } else {
            // Per control tick while the receiver is silent in the grace, so trace; the controller
            // says the silence once at debug ("receiver silent while the viewer's page is hidden").
            if let Some(silent) = receiver_silent {
                tracing::trace!(
                    hidden_ms = ms(hidden),
                    silent_ms = ms(silent),
                    asleep_after_ms = ms(BG_HOLD_ASLEEP_AFTER),
                    "background hold: the hidden page's receiver is silent, not yet long enough \
                     to call it asleep"
                );
            }
            return None;
        };
        inner.phase = Phase::Held {
            since: now,
            hidden_since: since,
            why: why.clone(),
        };
        inner.holds += 1;
        let holds = inner.holds;
        self.phase.store(HELD, Ordering::SeqCst);
        drop(inner);
        self.target.set_bg_hold(true);
        self.changed.notify_one();
        tracing::debug!(
            session = %self.sid,
            by = by.as_str(),
            hidden_ms = ms(hidden),
            silent_ms = %receiver_silent.map_or_else(|| "-".to_string(), |s| ms(s).to_string()),
            grace_ms = ms(BG_HOLD_GRACE),
            asleep_after_ms = ms(BG_HOLD_ASLEEP_AFTER),
            hidden_why = %why,
            holds,
            "background hold: {}; published to the supervisor, the encode loop and the heartbeat",
            match by {
                HoldStart::Grace => "the grace ran out",
                HoldStart::Asleep =>
                    "the hidden page's receiver has been silent past the asleep mark, so the page \
                     is asleep and the rest of the grace is not waited for",
            }
        );
        Some(HoldStarted {
            hidden,
            why,
            by,
            silent: receiver_silent,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the held phase taken apart, and what ended it"
    )]
    fn end_hold(
        &self,
        inner: &mut Inner,
        now: Instant,
        since: Instant,
        hidden_since: Instant,
        hidden_why: String,
        by: &str,
        why: &str,
    ) {
        let held = now.saturating_duration_since(since);
        inner.held_total = inner.held_total.saturating_add(held);
        inner.ended = Some(HoldEnded {
            held,
            hidden: now.saturating_duration_since(hidden_since),
            by: by.to_string(),
            why: why.to_string(),
            hidden_why,
        });
        inner.phase = Phase::Visible;
        // Published at once, from the message's own task: the supervisor starts the capture again
        // on its next look (a tenth of a second at most), not on the control task's next tick.
        self.target.set_bg_hold(false);
        self.changed.notify_one();
    }

    /// The hold that ended since the last call, if any. The control task's, on its next tick.
    pub fn take_ended(&self) -> Option<HoldEnded> {
        lock(&self.inner).ended.take()
    }

    /// Whether video is being held back now.
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.target.bg_hold()
    }

    /// Whether the viewer's page is hidden: in the grace or held. For the controller, which reads a
    /// silent receiver then as the page asleep (`QualityController::set_page_hidden`).
    #[must_use]
    pub fn page_hidden(&self) -> bool {
        self.phase.load(Ordering::SeqCst) != VISIBLE
    }

    /// How long the hold in progress has lasted; `None` outside one. For the `pipeline` line.
    #[must_use]
    pub fn current(&self, now: Instant) -> Option<Duration> {
        match &lock(&self.inner).phase {
            Phase::Held { since, .. } => Some(now.saturating_duration_since(*since)),
            _ => None,
        }
    }

    /// The session's totals for its stats: milliseconds held, the hold in progress counted up to
    /// `now`, and how many holds began.
    #[must_use]
    pub fn totals(&self, now: Instant) -> (u64, u64) {
        let inner = lock(&self.inner);
        let open = match &inner.phase {
            Phase::Held { since, .. } => now.saturating_duration_since(*since),
            _ => Duration::ZERO,
        };
        (ms(inner.held_total.saturating_add(open)), inner.holds)
    }

    /// Resolves on a hold's start or end. For the heartbeat task's `select!`.
    pub fn changed(&self) -> &Notify {
        &self.changed
    }

    /// The session ended: one line with its totals, and what it ended in.
    pub fn finish(&self, now: Instant) {
        let (held_ms, holds) = self.totals(now);
        let inner = lock(&self.inner);
        tracing::debug!(
            session = %self.sid,
            phase = inner.phase.name(),
            holds,
            held_ms,
            vis_received = inner.vis_received,
            "background hold: session totals{}",
            if matches!(inner.phase, Phase::Held { .. }) {
                " (the session ended during a hold; the open hold is counted to now)"
            } else {
                ""
            }
        );
    }
}

/// What a tick of the control task is, as far as the hold goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldStep {
    /// No hold: the controller ticks as usual.
    Live,
    /// A hold began on this tick: the controller is frozen from it on.
    Started,
    /// Held: the controller is not ticked.
    Frozen,
    /// A hold ended since the last tick; the controller has been resumed and ticks from here.
    Resumed { held: Duration },
}

impl HoldStep {
    /// Whether the controller is frozen on this tick.
    #[must_use]
    pub fn frozen(self) -> bool {
        matches!(self, HoldStep::Started | HoldStep::Frozen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Quiet {
    /// No hold: str0m's desired bitrate is the controller's.
    Off,
    /// Held, and the hold's desired bitrate not yet taken by the peer.
    Pending,
    /// Held, and the peer took it.
    Sent,
}

#[derive(Debug, Clone, Copy)]
struct Frozen {
    since: Instant,
    /// What str0m was told to probe towards before the hold: put back on the resume.
    desired_kbps: u32,
    /// str0m's estimate as the hold began, for the resume's line.
    estimate_kbps: u32,
    rung: Rung,
    /// What began it. See [`HoldControl::started_by`].
    by: HoldStart,
}

/// The control task's side of the hold.
///
/// The agent's, and the simulator's restatement of it. The quality controller is frozen (not
/// ticked, so no evidence decays and no dwell grows) while str0m is told a desired bitrate under
/// its probing minimum ([`BG_HOLD_DESIRED_KBPS`]), so its ALR probes stop; its padding (~50 kbit/s)
/// has no switch and stays, since str0m is not patched for it.
///
/// On the resume the desired bitrate goes back and the controller resumes at the same rung
/// ([`QualityController::resume_after_hold`]). str0m's estimator is restarted at the path's
/// evidence from before the hold or its own estimate, whichever is larger
/// ([`QualityController::reanchor_after_hold`]), decided on that tick and applied by the transport
/// right before the resumed video's first frame: the hold leaves str0m's acknowledged-rate history
/// at the padding rate, and the first overuse after the resume would otherwise cut the estimate to
/// 0.85 times that.
///
/// From the grace on, the controller is told the page is hidden
/// ([`QualityController::set_page_hidden`]). A hidden page may sleep (an iPhone's WebView stops
/// every receiver report, transport-wide feedback and ICE consent answer the moment it is hidden),
/// and its silence is then the page's, not the network's: no silence brake, no outage, no evidence
/// decay. After the hold the woken page's first reports, which read its sleep as round trip or
/// loss, say only that it is back (`HOLD_WAKE_WINDOW` in `crate::quality`).
#[derive(Debug)]
pub struct HoldControl {
    frozen: Option<Frozen>,
    quiet: Quiet,
    /// The desired bitrate to put back, until the peer takes it — or another one supersedes it.
    restore: Option<u32>,
    /// Whether a refused desired bitrate has been said in the current run of refusals.
    refused_logged: bool,
}

impl Default for HoldControl {
    fn default() -> Self {
        Self::new()
    }
}

impl HoldControl {
    #[must_use]
    pub fn new() -> Self {
        Self {
            frozen: None,
            quiet: Quiet::Off,
            restore: None,
            refused_logged: false,
        }
    }

    /// Once a tick, before the controller: let a grace run out, freeze the controller on a hold's
    /// start, and resume it once the hold is over, deciding str0m's restart for the resumed video.
    /// `estimate_kbps` is str0m's estimate now, `desired_kbps` what str0m was last told to probe
    /// towards.
    pub fn tick(
        &mut self,
        bg: &BgHold,
        quality: &mut QualityController,
        now: Instant,
        estimate_kbps: u32,
        desired_kbps: u32,
    ) -> HoldStep {
        let mut step = HoldStep::Live;
        // First, so this tick's grace already counts: a hidden page's silent receiver is the page
        // asleep, not the path.
        quality.set_page_hidden(bg.page_hidden());
        // The receiver's silence as the controller last read it: in the grace, past
        // [`BG_HOLD_ASLEEP_AFTER`], the page is asleep and the hold begins without the rest of it.
        if let Some(started) = bg.poll(now, quality.receiver_silence()) {
            let rung = quality.current();
            tracing::info!(
                session = %bg.sid,
                by = started.by.as_str(),
                hidden_ms = ms(started.hidden),
                silent_ms = %started.silent.map_or_else(|| "-".to_string(), |s| ms(s).to_string()),
                why = %started.why,
                rung = %format!("{}p@{}", rung.max_h, rung.fps),
                estimate_kbps,
                capacity_kbps = quality.capacity_kbps(),
                desired_kbps,
                draining = quality.draining(),
                "background hold started: {}, so this session's capture, encoding and sending \
                 stop; the peer, the heartbeat and input stay",
                match started.by {
                    HoldStart::Grace => "the viewer's page has been hidden past its grace",
                    HoldStart::Asleep =>
                        "the viewer's page is hidden and its receiver silent — the page is asleep, \
                         and the rest of the grace is not waited for",
                }
            );
            tracing::debug!(
                session = %bg.sid,
                capacity_kbps = quality.capacity_kbps(),
                budget_kbps = quality.encoder_target_kbps(),
                brake = quality.brake_state(),
                brake_kbps = ?quality.brake_kbps(),
                collapse = quality.collapse_state(),
                rtt_base_ms = ?quality.rtt_base_ms(),
                report_age_ms = ?quality.report_age().map(ms),
                drain_ms = ?quality.drain_held().map(ms),
                hold_desired_kbps = BG_HOLD_DESIRED_KBPS,
                "background hold: the controller is frozen as it stands (not ticked: no evidence \
                 decays, no dwell grows, no receiver report is read), and str0m is told a desired \
                 bitrate under its probing minimum so its ALR probes stop; its padding stays"
            );
            self.frozen = Some(Frozen {
                since: now,
                desired_kbps,
                estimate_kbps,
                rung,
                by: started.by,
            });
            self.quiet = Quiet::Pending;
            self.restore = None;
            self.refused_logged = false;
            step = HoldStep::Started;
        }
        if bg.is_held() {
            if self.frozen.is_none() {
                // The cell begins holds only in `poll` above, so this is a hold published without
                // its start being seen here. Frozen from now all the same.
                tracing::warn!(
                    session = %bg.sid,
                    "background hold in force without its start being seen by the control task; \
                     the controller is frozen from now"
                );
                self.frozen = Some(Frozen {
                    since: now,
                    desired_kbps,
                    estimate_kbps,
                    rung: quality.current(),
                    by: HoldStart::Grace,
                });
                self.quiet = Quiet::Pending;
                self.restore = None;
            }
            return if step == HoldStep::Started {
                step
            } else {
                HoldStep::Frozen
            };
        }
        let Some(f) = self.frozen.take() else {
            return step;
        };
        let ended = bg.take_ended();
        let held = ended
            .as_ref()
            .map_or_else(|| now.saturating_duration_since(f.since), |e| e.held);
        if self.quiet == Quiet::Sent {
            self.restore = Some(f.desired_kbps);
        }
        let quiet_was = self.quiet;
        self.quiet = Quiet::Off;
        self.refused_logged = false;
        let r = quality.resume_after_hold(held, estimate_kbps);
        // The drain's own resume, when one ended here, stands for the hold's re-anchor.
        let restart = r
            .reanchor_due
            .then(|| quality.reanchor_after_hold(estimate_kbps));
        let reanchor = r.reanchor.or(restart.and_then(|h| h.reanchor));
        let rung = quality.current();
        tracing::info!(
            session = %bg.sid,
            held_ms = ms(held),
            hidden_ms = ended.as_ref().map_or(0, |e| ms(e.hidden)),
            started_by = f.by.as_str(),
            by = ended.as_ref().map_or("-", |e| e.by.as_str()),
            why = ended.as_ref().map_or("-", |e| e.why.as_str()),
            keyframe = true,
            estimate_at_start_kbps = f.estimate_kbps,
            estimate_kbps,
            capacity_kbps = r.capacity_kbps,
            rung = %format!("{}p@{}", rung.max_h, rung.fps),
            rung_at_start = %format!("{}p@{}", f.rung.max_h, f.rung.fps),
            drain_ended = r.drain_ended,
            reanchor = reanchor.map_or("-", |a| a.trigger.as_str()),
            reanchor_kbps = %reanchor.map_or_else(|| "-".to_string(), |a| a.kbps.to_string()),
            raises = restart.is_some_and(|h| h.raises),
            refused = restart.and_then(|h| h.refused).unwrap_or("-"),
            desired_restore_kbps = %self.restore.map_or_else(|| "-".to_string(), |k| k.to_string()),
            "background hold ended: capture starts again and the next frame is a keyframe; the \
             controller resumes at the same rung, and str0m is restarted right before that keyframe \
             at the evidence from before the hold or its estimate, whichever is larger"
        );
        if quiet_was == Quiet::Pending {
            tracing::debug!(
                session = %bg.sid,
                "background hold: the hold's desired bitrate never reached the peer, so there is \
                 nothing to put back"
            );
        }
        HoldStep::Resumed { held }
    }

    /// The desired bitrate to hand str0m now, if any: the hold's own while held, the one from
    /// before it once it is over. Offered on every tick until [`Self::desired_sent`].
    #[must_use]
    pub fn desired_to_send(&self) -> Option<u32> {
        match self.quiet {
            Quiet::Pending => Some(BG_HOLD_DESIRED_KBPS),
            Quiet::Sent => None,
            Quiet::Off => self.restore,
        }
    }

    /// The peer took `kbps` as its desired bitrate — the one [`Self::desired_to_send`] offered, or
    /// any other the control task sent, which supersedes a restore still waiting.
    pub fn desired_sent(&mut self, kbps: u32) {
        self.refused_logged = false;
        if self.quiet == Quiet::Pending && kbps == BG_HOLD_DESIRED_KBPS {
            self.quiet = Quiet::Sent;
            tracing::debug!(
                desired_kbps = kbps,
                "background hold: str0m's desired bitrate is under its probing minimum — no ALR \
                 probes while held"
            );
            return;
        }
        if let Some(back) = self.restore.take() {
            tracing::debug!(
                desired_kbps = kbps,
                restored_from_hold_kbps = back,
                superseded = kbps != back,
                "background hold over: str0m's desired bitrate is back, and its probes with it"
            );
        }
    }

    /// The peer refused a desired bitrate (its control queue was full). Said once per run; offered
    /// again on the next tick.
    pub fn desired_refused(&mut self, kbps: u32, error: &str) {
        if !self.refused_logged {
            self.refused_logged = true;
            tracing::debug!(
                desired_kbps = kbps,
                error,
                "background hold: the peer refused the desired bitrate; offered again every tick"
            );
        }
    }

    /// Whether a re-anchor may go to the peer now. Not while the desired bitrate from before the
    /// hold is still waiting to go back: a re-anchor restores the ceiling it finds
    /// (`afklink_transport::reanchor_bwe`), and it would find the hold's.
    #[must_use]
    pub fn reanchor_may_go(&self) -> bool {
        self.restore.is_none() && self.quiet == Quiet::Off
    }

    /// Whether the controller is frozen.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen.is_some()
    }

    /// What began the hold in force, if one is.
    #[must_use]
    pub fn started_by(&self) -> Option<HoldStart> {
        self.frozen.map(|f| f.by)
    }

    /// The session ended. Said when it ended during a hold: nothing is resumed.
    pub fn finish(&self, now: Instant) {
        if let Some(f) = self.frozen {
            tracing::debug!(
                held_ms = ms(now.saturating_duration_since(f.since)),
                "the session ends during a background hold: nothing to resume"
            );
        }
    }
}

/// What the peer was last told of the viewer's page (`PeerControl::ViewerHidden`), for the control
/// task: the page hidden ([`BgHold::page_hidden`]: in the grace or held) or visible.
///
/// The transport's `cursor` channel may hold heartbeats and cursor reports only while the viewer is
/// out of reach — ICE lost the path, or this — and its own acknowledgements say the page is silent
/// (`afklink_transport`, `cursor_lane`). A hidden page is told from its `vis hidden` on, not from
/// the hold's "asleep" two seconds of receiver silence later: by then sctp-proto's window can be
/// full, and the transport measures the silence itself, on the channel.
#[derive(Debug, Default)]
pub struct HiddenTold {
    /// What the peer took last; every session starts visible on both sides.
    told: bool,
    /// Whether a refusal was said in the current run of refusals.
    refused_logged: bool,
}

impl HiddenTold {
    /// The state to offer the peer now, if it differs from what the peer has. Offered on every tick
    /// until it is taken.
    #[must_use]
    pub fn to_send(&self, page_hidden: bool) -> Option<bool> {
        (page_hidden != self.told).then_some(page_hidden)
    }

    /// What became of the offer of `hidden`: taken (`Ok`), or refused because the peer's control
    /// queue was full (said once per run of refusals; offered again on the next tick). `held` and
    /// `receiver_silent` (the controller's) are for the line.
    pub fn outcome(
        &mut self,
        session: &str,
        hidden: bool,
        held: bool,
        receiver_silent: Option<Duration>,
        sent: Result<(), String>,
    ) {
        match sent {
            Ok(()) => {
                self.told = hidden;
                self.refused_logged = false;
                tracing::debug!(
                    session,
                    hidden,
                    held,
                    receiver_silent_ms = %receiver_silent
                        .map_or_else(|| "-".to_string(), |s| ms(s).to_string()),
                    "viewer page {} told to the transport: its cursor channel {}",
                    if hidden { "hidden" } else { "visible" },
                    if hidden {
                        "may hold heartbeats and cursor reports once the viewer's SCTP stops \
                         acknowledging (the page asleep), and kicks when it is back"
                    } else {
                        "holds nothing on its account: what it held is written now"
                    }
                );
            }
            Err(error) => {
                if !self.refused_logged {
                    self.refused_logged = true;
                    tracing::debug!(
                        session,
                        hidden,
                        error,
                        "viewer page state refused by the peer (its control queue is full); \
                         offered again every tick"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::Quality;

    fn cell() -> (BgHold, Arc<QualityTarget>, Instant) {
        let target = Arc::new(QualityTarget::default());
        (BgHold::new("s", target.clone()), target, Instant::now())
    }

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    /// Hidden, ten seconds of grace, held; and back on `vis hidden: false`, the hold's length and
    /// what ended it recorded, the flag published both ways.
    #[test]
    fn hidden_past_the_grace_holds_and_visible_resumes() {
        let (bg, target, t0) = cell();
        bg.on_vis(true, Some("visibilitychange"), t0);
        assert!(!bg.is_held(), "the grace first");
        assert_eq!(bg.poll(at(t0, 9_999), None), None);
        assert!(!target.bg_hold());
        let started = bg.poll(at(t0, 10_000), None).expect("the grace ran out");
        assert_eq!(started.hidden, BG_HOLD_GRACE);
        assert_eq!(started.why, "visibilitychange");
        assert_eq!(started.by, HoldStart::Grace);
        assert_eq!(started.silent, None);
        assert!(target.bg_hold() && bg.is_held());
        assert_eq!(bg.poll(at(t0, 10_200), None), None, "a hold begins once");
        assert_eq!(bg.current(at(t0, 70_000)), Some(Duration::from_secs(60)));
        assert_eq!(
            bg.totals(at(t0, 70_000)),
            (60_000, 1),
            "an open hold counts"
        );

        bg.on_vis(false, Some("visibilitychange"), at(t0, 610_000));
        assert!(!target.bg_hold(), "published at once, not on a tick");
        let ended = bg.take_ended().expect("ended");
        assert_eq!(ended.held, Duration::from_secs(600));
        assert_eq!(ended.hidden, Duration::from_secs(610));
        assert_eq!(ended.by, "vis");
        assert_eq!(ended.hidden_why, "visibilitychange");
        assert_eq!(bg.take_ended(), None);
        assert_eq!(bg.totals(at(t0, 700_000)), (600_000, 1));
        assert_eq!(bg.current(at(t0, 700_000)), None);
    }

    /// A shorter hide changes nothing: the page back within the grace, or the viewer active in it,
    /// cancels it without a trace in the totals.
    #[test]
    fn the_grace_is_cancelled_by_a_resume_without_effect() {
        let (bg, target, t0) = cell();
        bg.on_vis(true, None, t0);
        bg.on_vis(false, Some("visibilitychange"), at(t0, 9_000));
        assert_eq!(bg.poll(at(t0, 20_000), None), None);
        assert!(!target.bg_hold());

        for trigger in [
            Trigger::Input("m"),
            Trigger::Keyframe,
            Trigger::ViewerVisible,
        ] {
            bg.on_vis(true, None, at(t0, 30_000));
            bg.on_trigger(trigger, at(t0, 31_000));
            assert_eq!(
                bg.poll(at(t0, 45_000), None),
                None,
                "{trigger:?} cancels the grace"
            );
        }
        assert_eq!(bg.totals(at(t0, 50_000)), (0, 0));
        assert_eq!(bg.take_ended(), None, "a cancelled grace is not a hold");
    }

    /// Each trigger ends a hold, as `vis hidden: false` does; `ra` and the other messages that are
    /// not input are no trigger at all.
    #[test]
    fn every_trigger_resumes_and_release_all_is_none() {
        for trigger in [
            Trigger::Input("d"),
            Trigger::Input("k"),
            Trigger::Input("w"),
            Trigger::Keyframe,
            Trigger::ViewerVisible,
        ] {
            let (bg, target, t0) = cell();
            bg.on_vis(true, None, t0);
            bg.poll(at(t0, 10_000), None).expect("held");
            bg.on_trigger(trigger, at(t0, 15_000));
            assert!(!target.bg_hold(), "{trigger:?} resumes");
            let ended = bg.take_ended().expect("ended");
            assert_eq!(ended.by, trigger.as_str());
            assert_eq!(ended.held, Duration::from_secs(5));
        }
        use afklink_protocol::Mods;
        let input = [
            (InputMessage::Move { x: 0.5, y: 0.5 }, Some("m")),
            (
                InputMessage::Rel {
                    dx: 0.1,
                    dy: 0.0,
                    s: None,
                    x: None,
                    y: None,
                },
                Some("r"),
            ),
            (
                InputMessage::Wheel {
                    dx: 0.0,
                    dy: 1.0,
                    mode: None,
                    game: None,
                },
                Some("w"),
            ),
            (InputMessage::Down { b: 0 }, Some("d")),
            (InputMessage::Up { b: 0 }, Some("u")),
            (
                InputMessage::Key {
                    d: 1,
                    code: "KeyA".into(),
                    key: None,
                    mods: Some(Mods::default()),
                    src: None,
                },
                Some("k"),
            ),
            (
                InputMessage::Text {
                    text: "x".into(),
                    game: None,
                },
                Some("text"),
            ),
            (
                InputMessage::Combo {
                    name: "ctrl_alt_del".into(),
                },
                Some("combo"),
            ),
            (InputMessage::ReleaseAll, None),
            (InputMessage::Quality { q: "auto".into() }, None),
            (
                InputMessage::Visibility {
                    hidden: false,
                    why: None,
                },
                None,
            ),
            (InputMessage::KeyframeRequest { reason: None }, None),
        ];
        for (m, want) in input {
            assert_eq!(Trigger::of_input(&m).map(Trigger::as_str), want, "{m:?}");
        }
    }

    /// `vis hidden: true` again — in the grace, or held — changes nothing: the grace does not
    /// restart, the hold does not end. And visible again while visible is nothing either.
    #[test]
    fn repeats_change_nothing() {
        let (bg, target, t0) = cell();
        bg.on_vis(false, Some("first_picture"), t0);
        bg.on_vis(true, Some("visibilitychange"), at(t0, 1_000));
        bg.on_vis(true, Some("input_open"), at(t0, 8_000));
        let started = bg
            .poll(at(t0, 11_000), None)
            .expect("the grace counts from the first");
        assert_eq!(started.why, "visibilitychange");
        bg.on_vis(true, Some("path_up"), at(t0, 20_000));
        assert!(target.bg_hold(), "still held");
        assert_eq!(bg.take_ended(), None);
        bg.on_vis(false, Some("reconcile"), at(t0, 30_000));
        bg.on_vis(false, Some("reconcile"), at(t0, 31_000));
        let ended = bg.take_ended().expect("ended once");
        assert_eq!(ended.why, "reconcile");
        assert_eq!(ended.held, Duration::from_secs(19));
        assert_eq!(bg.take_ended(), None);
        assert_eq!(bg.totals(at(t0, 40_000)), (19_000, 1));
    }

    /// A viewer that never sends `vis` — every viewer before it, and any viewer of an agent that
    /// never said `vis_ok` — is never held, whatever else it sends, and however long its receiver
    /// is silent: without the page's own word a silence is the path's (the silence brake's).
    #[test]
    fn a_session_without_vis_is_never_held() {
        let (bg, target, t0) = cell();
        for s in 0..100u64 {
            bg.on_trigger(Trigger::Input("m"), at(t0, s * 1_000));
            assert_eq!(bg.poll(at(t0, s * 1_000), None), None);
            assert_eq!(
                bg.poll(at(t0, s * 1_000), Some(Duration::from_secs(s))),
                None,
                "silent {s} s"
            );
        }
        assert!(!target.bg_hold());
        assert_eq!(bg.totals(at(t0, 100_000)), (0, 0));
    }

    /// The page hidden and its receiver silent for [`BG_HOLD_ASLEEP_AFTER`]: asleep, held at once —
    /// an iPhone's WebView, whose grace would send the video into a page that can show nothing.
    /// Silent for less, not yet.
    #[test]
    fn a_hidden_page_silent_past_the_asleep_mark_is_held_at_once() {
        let (bg, target, t0) = cell();
        bg.on_vis(true, Some("visibilitychange"), t0);
        let short = BG_HOLD_ASLEEP_AFTER - Duration::from_millis(1);
        assert_eq!(
            bg.poll(at(t0, 1_000), Some(Duration::from_millis(800))),
            None
        );
        assert_eq!(bg.poll(at(t0, 2_000), Some(short)), None, "not yet asleep");
        assert!(!target.bg_hold());
        let started = bg
            .poll(at(t0, 2_200), Some(BG_HOLD_ASLEEP_AFTER))
            .expect("asleep");
        assert_eq!(started.by, HoldStart::Asleep);
        assert_eq!(started.hidden, Duration::from_millis(2_200));
        assert_eq!(started.silent, Some(BG_HOLD_ASLEEP_AFTER));
        assert_eq!(started.why, "visibilitychange");
        assert!(target.bg_hold() && bg.is_held(), "the same hold");
        assert_eq!(
            bg.poll(at(t0, 2_400), Some(Duration::from_secs(3))),
            None,
            "a hold begins once"
        );
        bg.on_vis(false, Some("visibilitychange"), at(t0, 30_000));
        let ended = bg.take_ended().expect("ended as any hold");
        assert_eq!(ended.held, Duration::from_millis(27_800));
        assert_eq!(ended.hidden, Duration::from_secs(30));

        // The silence began before the page was hidden: it counts from the last report, but only
        // once the page's own `vis hidden` is in.
        let (bg, target, t0) = cell();
        assert_eq!(bg.poll(t0, Some(Duration::from_secs(5))), None, "visible");
        bg.on_vis(true, None, at(t0, 100));
        let started = bg
            .poll(at(t0, 200), Some(Duration::from_millis(5_200)))
            .expect("asleep on the first tick of the grace");
        assert_eq!(started.by, HoldStart::Asleep);
        assert!(target.bg_hold());
    }

    /// A receiver that goes quiet for a moment and reports again — an awake page, or Chrome's own
    /// cadence — leaves the whole grace to run: held at ten seconds, by the grace.
    #[test]
    fn feedback_back_within_the_asleep_mark_keeps_the_grace() {
        let (bg, target, t0) = cell();
        bg.on_vis(true, None, t0);
        assert_eq!(
            bg.poll(at(t0, 1_500), Some(Duration::from_millis(1_500))),
            None
        );
        assert_eq!(
            bg.poll(at(t0, 1_700), Some(Duration::from_millis(1_700))),
            None
        );
        for ms in (1_900..10_000).step_by(200) {
            assert_eq!(
                bg.poll(at(t0, ms), None),
                None,
                "reporting again at {ms} ms"
            );
        }
        assert!(!target.bg_hold());
        let started = bg.poll(at(t0, 10_000), None).expect("the grace ran out");
        assert_eq!(started.by, HoldStart::Grace);
    }

    /// Through the control side, with the controller's own evidence: a warm session whose receiver
    /// stops reporting when its page is hidden is held once two seconds pass without a report, not
    /// after ten; the same session reporting on through its grace is held at ten.
    #[test]
    fn the_control_side_holds_a_sleeping_page_on_the_controllers_silence() {
        use crate::quality::{Feedback, ReceiverReport, TICK};
        // Five ticks a second, a stats event on the first: a last fresh report as the page is
        // hidden, then fresh while `reporting`, empty otherwise.
        let run = |reporting: bool| -> (Duration, Option<HoldStart>) {
            let (bg, _target, t0) = cell();
            let mut quality = warm_controller();
            let mut hold = HoldControl::new();
            bg.on_vis(true, Some("visibilitychange"), t0);
            for i in 0..80u64 {
                let now = at(t0, i * 200);
                let step = hold.tick(&bg, &mut quality, now, 5_000, 8_000);
                if step == HoldStep::Started {
                    return (now.duration_since(t0), hold.started_by());
                }
                let fb = Feedback {
                    estimate_kbps: 5_000,
                    drain_kbps: 5_500,
                    produced_kbps: 4_400,
                    egress_kbps: 4_500,
                    qp_samples: 6,
                    queue_age_ms: 0,
                    avg_qp: Some(28.0),
                    encode_ms: 4.0,
                    spend_ratio: 1.0,
                    rung_fps_hint: quality.current().fps as f32,
                    qp_ceiling: Some(46.0),
                    drop_ratio: 0.0,
                    report: (i % 5 == 0).then_some(ReceiverReport {
                        rtt_ms: Some(40),
                        loss: (reporting || i == 0).then_some(0.0),
                        nacks: 0,
                    }),
                };
                quality.tick(fb, TICK);
            }
            (Duration::MAX, None)
        };
        let (asleep_at, by) = run(false);
        assert_eq!(by, Some(HoldStart::Asleep));
        assert!(
            asleep_at >= BG_HOLD_ASLEEP_AFTER && asleep_at <= Duration::from_millis(3_200),
            "held {asleep_at:?} after the hide"
        );
        let (grace_at, by) = run(true);
        assert_eq!(by, Some(HoldStart::Grace));
        assert_eq!(grace_at, BG_HOLD_GRACE);
    }

    /// The control task's side: frozen from the tick the grace runs out, the hold's desired bitrate
    /// offered until the peer takes it, the old one put back after, and no re-anchor before it is.
    #[test]
    fn the_control_side_freezes_quiets_and_restores() {
        let (bg, _target, t0) = cell();
        let mut quality = QualityController::new(1620, 1080, Quality::Balanced);
        let mut hold = HoldControl::new();
        assert_eq!(
            hold.tick(&bg, &mut quality, t0, 5_000, 8_000),
            HoldStep::Live
        );
        assert_eq!(hold.desired_to_send(), None);
        bg.on_vis(true, None, t0);
        assert!(!quality.page_hidden());
        assert_eq!(
            hold.tick(&bg, &mut quality, at(t0, 5_000), 5_000, 8_000),
            HoldStep::Live,
            "in the grace the controller ticks"
        );
        assert!(
            quality.page_hidden(),
            "from the grace on, a silent receiver is the page asleep"
        );
        let step = hold.tick(&bg, &mut quality, at(t0, 10_000), 5_000, 8_000);
        assert_eq!(step, HoldStep::Started);
        assert!(step.frozen());
        assert_eq!(hold.desired_to_send(), Some(BG_HOLD_DESIRED_KBPS));
        hold.desired_refused(BG_HOLD_DESIRED_KBPS, "full");
        assert_eq!(
            hold.desired_to_send(),
            Some(BG_HOLD_DESIRED_KBPS),
            "offered again"
        );
        hold.desired_sent(BG_HOLD_DESIRED_KBPS);
        assert_eq!(hold.desired_to_send(), None);
        assert!(!hold.reanchor_may_go());
        assert_eq!(
            hold.tick(&bg, &mut quality, at(t0, 70_000), 60, 1),
            HoldStep::Frozen
        );

        bg.on_vis(false, None, at(t0, 130_000));
        let step = hold.tick(&bg, &mut quality, at(t0, 130_100), 60, 1);
        assert_eq!(
            step,
            HoldStep::Resumed {
                held: Duration::from_secs(120)
            }
        );
        assert!(!step.frozen());
        assert!(!quality.page_hidden(), "visible again on the resume tick");
        assert_eq!(
            hold.desired_to_send(),
            Some(8_000),
            "the ceiling from before"
        );
        assert!(!hold.reanchor_may_go(), "not before the ceiling is back");
        hold.desired_sent(8_000);
        assert_eq!(hold.desired_to_send(), None);
        assert!(hold.reanchor_may_go());
        assert_eq!(
            hold.tick(&bg, &mut quality, at(t0, 130_300), 3_000, 8_000),
            HoldStep::Live
        );
        // A controller that has seen no media decides no re-anchor of its own.
        assert_eq!(quality.take_bwe_reanchor(), None);
    }

    /// A controller that has carried a loaded path: 4.5 Mbps leaving against an estimate of 5000,
    /// the receiver reporting a clean 40 ms round trip once a second.
    fn warm_controller() -> QualityController {
        use crate::quality::{Feedback, ReceiverReport, TICK};
        let mut q = QualityController::new(1620, 1080, Quality::Balanced);
        for i in 0..100 {
            let fb = Feedback {
                estimate_kbps: 5_000,
                drain_kbps: 5_500,
                produced_kbps: 4_400,
                egress_kbps: 4_500,
                qp_samples: 6,
                queue_age_ms: 0,
                avg_qp: Some(28.0),
                encode_ms: 4.0,
                spend_ratio: 1.0,
                rung_fps_hint: q.current().fps as f32,
                qp_ceiling: Some(46.0),
                drop_ratio: 0.0,
                report: (i % 5 == 0).then_some(ReceiverReport {
                    rtt_ms: Some(40),
                    loss: Some(0.0),
                    nacks: 0,
                }),
            };
            q.tick(fb, TICK);
            let _ = q.take_bwe_reanchor();
            let _ = q.take_probe_target();
            let _ = q.take_brake_event();
        }
        assert!(q.capacity_kbps() >= 4_000, "{}", q.capacity_kbps());
        q
    }

    /// Hold and resume through the control side: the restart is decided on the resume tick, with
    /// the hold's trigger — the one the transport applies right before the next frame — at the
    /// estimate as the hold left it standing above the evidence (never lower), and once per hold.
    #[test]
    fn the_hold_reanchor_is_decided_on_the_resume_tick_and_never_lowers() {
        use crate::quality::ReanchorTrigger;
        let (bg, _target, t0) = cell();
        let mut quality = warm_controller();
        let mut hold = HoldControl::new();
        bg.on_vis(true, None, t0);
        assert_eq!(
            hold.tick(&bg, &mut quality, at(t0, 10_000), 7_000, 8_000),
            HoldStep::Started
        );
        hold.desired_sent(BG_HOLD_DESIRED_KBPS);
        hold.tick(&bg, &mut quality, at(t0, 20_000), 7_000, 1);
        assert_eq!(quality.take_bwe_reanchor(), None, "none while held");
        bg.on_vis(false, None, at(t0, 30_000));
        assert!(matches!(
            hold.tick(&bg, &mut quality, at(t0, 30_100), 7_000, 1),
            HoldStep::Resumed { .. }
        ));
        let r = quality.last_reanchor().expect("decided on the resume tick");
        assert_eq!(r.trigger, ReanchorTrigger::HoldResume);
        assert!(r.trigger.at_next_frame());
        assert!(!hold.reanchor_may_go(), "not before the ceiling is back");
        hold.desired_sent(8_000);
        assert!(hold.reanchor_may_go());
        assert_eq!(
            quality.take_bwe_reanchor(),
            Some(7_000),
            "the estimate held above the evidence: restarted at the estimate itself, not lower"
        );
        hold.tick(&bg, &mut quality, at(t0, 30_300), 7_000, 8_000);
        assert_eq!(quality.take_bwe_reanchor(), None, "once per hold");
    }

    /// A hold whose silence walked the estimate down: raised to the evidence on the resume tick.
    #[test]
    fn a_collapsed_estimate_is_raised_to_the_evidence_on_the_resume_tick() {
        let (bg, _target, t0) = cell();
        let mut quality = warm_controller();
        let capacity = quality.capacity_kbps();
        let mut hold = HoldControl::new();
        bg.on_vis(true, None, t0);
        hold.tick(&bg, &mut quality, at(t0, 10_000), 5_000, 8_000);
        hold.desired_sent(BG_HOLD_DESIRED_KBPS);
        bg.on_trigger(Trigger::Input("k"), at(t0, 40_000));
        hold.tick(&bg, &mut quality, at(t0, 40_150), 60, 1);
        let kbps = quality.take_bwe_reanchor().expect("on the resume tick");
        assert!(kbps > 60 && kbps <= capacity, "{kbps} against {capacity}");
    }

    /// A hold over before the peer ever took the hold's desired bitrate leaves nothing to put back.
    #[test]
    fn a_quiet_never_sent_is_not_restored() {
        let (bg, _target, t0) = cell();
        let mut quality = QualityController::new(1620, 1080, Quality::Balanced);
        let mut hold = HoldControl::new();
        bg.on_vis(true, None, t0);
        assert_eq!(
            hold.tick(&bg, &mut quality, at(t0, 10_000), 5_000, 8_000),
            HoldStep::Started
        );
        bg.on_trigger(Trigger::Keyframe, at(t0, 10_100));
        assert!(matches!(
            hold.tick(&bg, &mut quality, at(t0, 10_200), 5_000, 8_000),
            HoldStep::Resumed { .. }
        ));
        assert_eq!(hold.desired_to_send(), None);
        assert!(hold.reanchor_may_go());
    }

    /// The transport hears of the page from its `vis hidden` on — the grace, not the hold — and of
    /// its return; a refusal is offered again until taken, and nothing is offered twice.
    #[test]
    fn the_transport_is_told_the_page_hidden_from_the_grace_and_visible_again() {
        let (bg, _, t0) = cell();
        let mut told = HiddenTold::default();
        assert_eq!(
            told.to_send(bg.page_hidden()),
            None,
            "visible on both sides"
        );
        bg.on_vis(true, Some("visibilitychange"), t0);
        assert!(!bg.is_held(), "in the grace");
        assert_eq!(told.to_send(bg.page_hidden()), Some(true));
        told.outcome("s", true, false, None, Err("full".into()));
        assert_eq!(told.to_send(bg.page_hidden()), Some(true), "offered again");
        told.outcome("s", true, false, None, Ok(()));
        assert_eq!(told.to_send(bg.page_hidden()), None, "taken");
        bg.poll(at(t0, 10_000), None).expect("held");
        assert_eq!(told.to_send(bg.page_hidden()), None, "held is still hidden");
        bg.on_trigger(Trigger::Input("r"), at(t0, 12_000));
        assert_eq!(told.to_send(bg.page_hidden()), Some(false));
        told.outcome("s", false, false, None, Ok(()));
        assert_eq!(told.to_send(bg.page_hidden()), None);
    }
}
