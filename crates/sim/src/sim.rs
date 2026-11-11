//! The event loop: two str0m peers, two links, a frame source, the encode loop and the control
//! task, all on one virtual clock.
//!
//! ## How time moves
//!
//! Every component says when it next needs to run — str0m through `poll_output`'s timeout (the
//! agent's through its run loop's timer, quantised to the platform tick), each link through its
//! next delivery, the source through its next frame, the encoder through the end of the encode in
//! progress, the controller through its 200 ms tick, the viewer through a keyframe re-request.
//! The loop takes the earliest, moves the clock there and runs it. Ties go in a fixed order
//! (deliveries, the agent's timer, the viewer's timer, the encoder, the source, the controller, the
//! viewer's re-request), so a run is a function of its scenario and seed.
//!
//! ## Phases
//!
//! 1. Handshake: SDP offer (viewer) and answer (agent) exchanged directly, then ICE and DTLS over
//!    links in ideal mode (see `crate::link`).
//! 2. The session, from the moment the agent's str0m reports `Connected`: the links switch to their
//!    model, the capture/encode pipeline and the controller start, and the scenario's duration
//!    counts from here. (The agent starts capturing at the answer and discards frames until
//!    `Connected`; starting the pipeline at `Connected` drops those discarded frames and nothing
//!    else.)
//!
//! ## The background hold
//!
//! A scenario's `[viewer] hidden` windows are the viewer's `vis`, delivered on the control task's
//! clock to the agent's own hold cell (`afklink_core::bg_hold::BgHold`): its grace, its hold, its
//! resume, and the control task's freeze and resume (`HoldControl`) are the production ones. The
//! supervisor's part is restated: while the hold is published the capture is stopped — the source's
//! frames are not captured, only remembered as the screen as it is — and on its end the capture
//! starts again [`CAPTURE_RESUME`] later with that screen as its first frame, a keyframe, as a
//! fresh WGC start delivers. The summary's `holds` measure each: what went on the wire while held,
//! the rung either side, the re-anchor, the first frame after.
//!
//! A scenario's viewer may also sleep while hidden ([`crate::scenario::AsleepViewer`]): from its
//! `vis hidden: true` it is not run at all — no receiver report, no transport-wide feedback, no ICE
//! consent answer — and what reaches it waits for it or is lost; it wakes a little before its
//! `vis hidden: false`, takes in what waited, and its first receiver report reads the time it slept
//! as round trip.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_core::bg_hold::{BgHold, HoldStep};
use afklink_core::quality::{Quality, QualityPolicy, QualityTarget, Rung, TICK};
use afklink_core::traits::Encoder;
use afklink_encode::{OpenH264Encoder, DEFAULT_BITRATE_BPS, DEFAULT_FPS, DEFAULT_GOP_FRAMES};
use anyhow::{Context, Result};

use crate::clock::{clear_log_time, log_timestamp, VirtualClock};
use crate::control::{Command, ControlTask, Gauges, Line};
use crate::datachannel::ViewerReports;
use crate::encode_loop::{Capturer, EncodeJob, EncodeLoop};
use crate::link::{describe_capacity, Datagram, Link};
use crate::metrics::{summarize, viewer_seconds, HoldMark, Metrics, SentFrame, Summary};
use crate::rng::{stream, SimRng};
use crate::scenario::Scenario;
use crate::source::{FrameSource, TimedFrame};
use crate::transport::{MediaSample, SenderPeer, WriteOutcome};
use crate::viewer::Viewer;

/// `encode/src/lib.rs:81` (`SLICE_BYTES`, private there): the slice cap the production encoder is
/// built with, restated for a scenario that overrides the thread count.
const SLICE_BYTES: u32 = 4 * 1024;

/// How long a handshake may take, in virtual time, before the run is declared broken.
const CONNECT_DEADLINE: Duration = Duration::from_secs(30);

/// A guard against a loop that stops advancing time: this many events at one instant is a bug.
const MAX_EVENTS_AT_ONE_INSTANT: u64 = 200_000;

/// From a background hold's end to the first frame of the capture started again: the supervisor's
/// next look (up to `pipeline::SUPERVISE_EVERY`, 100 ms) plus a WGC monitor start and its first
/// frame — 83-430 ms and ~31 ms in agent logs (a game window's start is ~10 ms). The middle
/// of that, not its tail.
pub const CAPTURE_RESUME: Duration = Duration::from_millis(250);

fn agent_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], 5000))
}

fn viewer_addr() -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 2], 6000))
}

/// What a run produced.
#[derive(Debug)]
pub struct RunOutput {
    pub summary: Summary,
    /// The session log: the agent's `pipeline`, `egress`, `quality changed`, re-anchor and brake
    /// lines, plus a per-second `viewer` line, in the agent's own format with virtual timestamps.
    pub log: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ev {
    ToAgent,
    ToViewer,
    AgentTimer,
    ViewerTimer,
    EncodeDone,
    Frame,
    Tick,
    Pli,
    CaptureStart,
    /// The viewer's page falls asleep or wakes. See [`crate::scenario::AsleepViewer`].
    Sleep,
    /// The viewer's `vv` report: made, arriving, or its acknowledgement arriving. See
    /// [`crate::datachannel`].
    Reports,
}

/// Whether the control task hands the controller the viewer's reports of the frames it received
/// (`QualityController::note_viewer_frames`): on unless `AFKLINK_SIM_VIEWER_DELIVERY` is `off`, which
/// replays the controller as it was before it read them — the same packets, the same run, until the
/// first decision they would have changed (see [`crate::datachannel`]).
fn viewer_delivery_on() -> bool {
    !std::env::var("AFKLINK_SIM_VIEWER_DELIVERY").is_ok_and(|v| v.eq_ignore_ascii_case("off"))
}

/// One simulated session. See the module documentation.
pub struct Simulation {
    scenario: Scenario,
    clock: VirtualClock,
    sender: SenderPeer,
    viewer: Viewer,
    up: Link,
    down: Link,
    source: Box<dyn FrameSource>,
    source_peek: Option<TimedFrame>,
    capturer: Capturer,
    encoder: Option<Box<dyn Encoder>>,
    encode: Option<EncodeLoop>,
    job: Option<EncodeJob>,
    pending: Option<(Duration, afklink_core::types::Frame)>,
    pending_offered: u32,
    control: ControlTask,
    target: Arc<QualityTarget>,
    /// The scenario's viewer keyframe requests not yet made, earliest first, as offsets from the
    /// start of the session. See [`Scenario::keyframe_requests`].
    keyframe_requests: std::collections::VecDeque<Duration>,
    /// The scenario's delay steps not yet applied, per direction, earliest first. See
    /// [`Scenario::up_delay_steps`].
    up_delay_steps: std::collections::VecDeque<(Duration, Duration)>,
    down_delay_steps: std::collections::VecDeque<(Duration, Duration)>,
    /// The session's background-hold cell, the agent's own, publishing into `target`.
    bg: Arc<BgHold>,
    /// The viewer's `vis` not yet sent: (offset from the session's start, hidden), in order.
    vis_events: std::collections::VecDeque<(Duration, bool)>,
    /// The supervisor's view of the hold: the capture stopped, and when it starts again.
    capture_held: bool,
    capture_start_at: Option<Duration>,
    /// The screen as it is, kept while a scenario has hidden windows: what a fresh capture
    /// delivers first after a hold.
    last_screen: Option<afklink_core::types::Frame>,
    keep_screen: bool,
    /// When the viewer's page falls asleep (`true`) and wakes (`false`), as offsets from the start of
    /// the session, in order. Empty unless the scenario's viewer sleeps while hidden.
    sleep_events: std::collections::VecDeque<(Duration, bool)>,
    /// Asleep now: the viewer is not run, and what reaches it is `backlog` (or lost).
    viewer_asleep: bool,
    asleep_since: Duration,
    backlog: Vec<Datagram>,
    /// Datagrams that reached the sleeping viewer and were lost, for the wake's line.
    backlog_dropped: u64,
    /// The viewer's `vv` reports on their way to the agent, and whether the control task hands
    /// them to the controller. See [`crate::datachannel`] and [`viewer_delivery_on`].
    reports: ViewerReports,
    delivery_on: bool,
    pipeline_start: Option<Duration>,
    next_tick: Option<Duration>,
    end: Option<Duration>,
    metrics: Metrics,
    lines: Vec<(Duration, u64, String)>,
    line_seq: u64,
    to_viewer: Vec<Datagram>,
    to_agent: Vec<Datagram>,
}

impl std::fmt::Debug for Simulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Simulation")
            .field("scenario", &self.scenario.name)
            .field("now", &self.clock.now())
            .field("pipeline_start", &self.pipeline_start)
            .finish()
    }
}

fn build_encoder(threads: u16) -> Result<Box<dyn Encoder>> {
    let enc = if threads == 0 {
        OpenH264Encoder::with_defaults()?
    } else {
        OpenH264Encoder::new_tuned(
            DEFAULT_BITRATE_BPS,
            DEFAULT_FPS,
            DEFAULT_GOP_FRAMES,
            threads,
            Some(SLICE_BYTES),
        )?
    };
    Ok(Box::new(enc))
}

impl Simulation {
    /// A simulation of `scenario` with the content its file describes, on the reference profile
    /// ([`crate::reference_policy`]).
    pub fn new(scenario: Scenario) -> Result<Self> {
        Self::with_policy(scenario, crate::reference_policy()?)
    }

    /// [`Self::new`] on `policy` — the agent's compiled fallback, a server profile, the reference.
    pub fn with_policy(scenario: Scenario, policy: QualityPolicy) -> Result<Self> {
        let source = scenario
            .content
            .build(SimRng::derive(scenario.seed, stream::CONTENT).next_u64())?;
        Self::with_source_and_policy(scenario, source, policy)
    }

    /// A simulation of `scenario` with frames from anywhere — the corpus reader's adapter point.
    /// The scenario's own `content` is ignored. On the reference profile.
    pub fn with_source(scenario: Scenario, source: Box<dyn FrameSource>) -> Result<Self> {
        Self::with_source_and_policy(scenario, source, crate::reference_policy()?)
    }

    /// [`Self::with_source`] on `policy`.
    pub fn with_source_and_policy(
        scenario: Scenario,
        source: Box<dyn FrameSource>,
        policy: QualityPolicy,
    ) -> Result<Self> {
        let clock = VirtualClock::new();
        // str0m's ids, SSRCs and sequence starts come from fastrand's thread-local generator; seed
        // it here, on the thread that will run every str0m call of this simulation.
        fastrand::seed(SimRng::derive(scenario.seed, stream::STR0M).next_u64());

        let mut viewer = Viewer::new(&clock, viewer_addr(), scenario.viewer)?;
        let mut sender = SenderPeer::new(&clock, agent_addr(), scenario.sender)?;
        let offer = viewer.create_offer()?;
        let answer = sender.accept_offer(&offer)?;
        viewer.accept_answer(&answer)?;

        let encoder = build_encoder(scenario.encoder_threads).context("build the encoder")?;
        let start = policy.start_rung();
        let ladder = policy.ladder.clone();
        // agent.rs:781: the opening budget is the top rung priced on a guessed 1080p screen.
        let opening_kbps = start.required_kbps_with(&policy, 1920, 1080, Quality::default());
        let (mut control, first) = ControlTask::new(encoder.max_qp().map(|q| q as f32), policy);
        let target = Arc::new(QualityTarget::new(start));
        target.set_target_kbps(opening_kbps);
        if let Some(h) = scenario.pin_height {
            control.pin(h, &target);
        }
        // What the run opens on, after the pin: the summary's `top%` and `lowest` are about it.
        let opening = Rung {
            max_h: target.max_h(),
            fps: target.fps(),
        };

        let up = Link::new(
            "up",
            scenario.up.clone(),
            SimRng::derive(scenario.seed, stream::LINK_UP),
        );
        let down = Link::new(
            "down",
            scenario.down.clone(),
            SimRng::derive(scenario.seed, stream::LINK_DOWN),
        );
        tracing::info!(
            scenario = %scenario.name,
            seed = scenario.seed,
            duration_s = scenario.duration.as_secs_f64(),
            up = %describe_capacity(&scenario.up.capacity),
            down = %describe_capacity(&scenario.down.capacity),
            rtt_ms = (scenario.up.delay + scenario.down.delay).as_secs_f64() * 1e3,
            viewer_str0m = %scenario.viewer.str0m,
            opening_rung = ?opening,
            profile_start_rung = ?start,
            "simulation built"
        );

        let keyframe_requests = scenario.keyframe_requests.iter().copied().collect();
        let up_delay_steps = scenario.up_delay_steps.iter().copied().collect();
        let down_delay_steps = scenario.down_delay_steps.iter().copied().collect();
        let vis_events = scenario
            .hidden
            .iter()
            .flat_map(|&(from, to)| [(from, true), (to, false)])
            .collect();
        let keep_screen = !scenario.hidden.is_empty();
        // Asleep from the hide, awake `wake_before_visible` before the page is visible again (never
        // before it fell asleep).
        let sleep_events = scenario.asleep.map_or_else(Default::default, |a| {
            scenario
                .hidden
                .iter()
                .flat_map(|&(from, to)| {
                    [
                        (from, true),
                        (to.saturating_sub(a.wake_before_visible).max(from), false),
                    ]
                })
                .collect()
        });
        let bg = Arc::new(BgHold::new(
            format!("sim-{}", scenario.name),
            target.clone(),
        ));
        let mut sim = Self {
            scenario,
            clock,
            sender,
            viewer,
            up,
            down,
            source,
            source_peek: None,
            capturer: Capturer::new(),
            encoder: Some(encoder),
            encode: None,
            job: None,
            pending: None,
            pending_offered: 0,
            control,
            target,
            keyframe_requests,
            up_delay_steps,
            down_delay_steps,
            bg,
            vis_events,
            capture_held: false,
            capture_start_at: None,
            last_screen: None,
            keep_screen,
            sleep_events,
            viewer_asleep: false,
            asleep_since: Duration::ZERO,
            backlog: Vec::new(),
            backlog_dropped: 0,
            reports: ViewerReports::default(),
            delivery_on: viewer_delivery_on(),
            pipeline_start: None,
            next_tick: None,
            end: None,
            metrics: Metrics {
                ladder,
                opening: Some(opening),
                ..Metrics::default()
            },
            lines: Vec::new(),
            line_seq: 0,
            to_viewer: Vec::new(),
            to_agent: Vec::new(),
        };
        // agent.rs:815-818: the ceiling for the guessed screen, sent right after the peer exists.
        if let Command::SetDesiredBitrate(kbps) = first {
            sim.sender
                .set_desired_bitrate(&sim.clock, kbps, &mut sim.to_viewer)?;
        }
        sim.viewer.timer(&sim.clock, &mut sim.to_agent)?;
        sim.route();
        Ok(sim)
    }

    fn log(&mut self, at: Duration, level: &str, target: &str, text: &str) {
        self.line_seq += 1;
        self.lines.push((
            at,
            self.line_seq,
            format!("{} {level:>5} {target}: {text}", log_timestamp(at)),
        ));
    }

    fn log_line(&mut self, at: Duration, l: &Line) {
        self.log(at, l.level, l.target, &l.text);
    }

    /// Hand everything the peers emitted to the links.
    fn route(&mut self) {
        let now = self.clock.now();
        let mut out = std::mem::take(&mut self.to_viewer);
        for d in out.drain(..) {
            self.metrics.note_egress(now, d.contents.len() as u64);
            self.up.send(now, d);
        }
        self.to_viewer = out;
        let mut out = std::mem::take(&mut self.to_agent);
        for d in out.drain(..) {
            self.down.send(now, d);
        }
        self.to_agent = out;
    }

    fn next_event(&self) -> Option<(Duration, Ev)> {
        let frame = match (self.pipeline_start, &self.source_peek) {
            (Some(start), Some((t, _))) => Some(start + *t),
            _ => None,
        };
        // A sleeping viewer runs nothing of its own: no timer, no keyframe re-request.
        let (viewer_wake, viewer_pli) = if self.viewer_asleep {
            (None, None)
        } else {
            (self.viewer.next_wake, self.viewer.pli_due())
        };
        let sleep = match (self.pipeline_start, self.sleep_events.front()) {
            (Some(start), Some((at, _))) => Some(start + *at),
            _ => None,
        };
        let candidates = [
            (self.down.next_delivery(), Ev::ToAgent),
            (self.up.next_delivery(), Ev::ToViewer),
            (self.sender.next_wake, Ev::AgentTimer),
            (viewer_wake, Ev::ViewerTimer),
            (self.job.as_ref().map(|j| j.done_at), Ev::EncodeDone),
            (frame, Ev::Frame),
            (self.next_tick, Ev::Tick),
            (viewer_pli, Ev::Pli),
            (self.capture_start_at, Ev::CaptureStart),
            (sleep, Ev::Sleep),
            (self.reports.next_event(), Ev::Reports),
        ];
        let mut best: Option<(Duration, Ev)> = None;
        for (t, ev) in candidates {
            if let Some(t) = t {
                if best.is_none_or(|(b, _)| t < b) {
                    best = Some((t, ev));
                }
            }
        }
        best
    }

    /// Run to the end of the scenario.
    pub fn run(mut self) -> Result<RunOutput> {
        let wall = Instant::now();
        let mut at_instant = 0u64;
        let mut last_t = Duration::MAX;
        let mut events = 0u64;
        loop {
            let deadline = self.end.unwrap_or(CONNECT_DEADLINE);
            let Some((t, ev)) = self.next_event() else {
                tracing::debug!("nothing left to happen; ending early");
                break;
            };
            if t >= deadline {
                anyhow::ensure!(
                    self.end.is_some(),
                    "no connection within {} s of virtual time",
                    CONNECT_DEADLINE.as_secs()
                );
                self.clock.advance_to(deadline);
                break;
            }
            if t == last_t {
                at_instant += 1;
                anyhow::ensure!(
                    at_instant < MAX_EVENTS_AT_ONE_INSTANT,
                    "the event loop stopped advancing time at {t:?} (last event {ev:?})"
                );
            } else {
                at_instant = 0;
                last_t = t;
            }
            events += 1;
            self.clock.advance_to(t);
            self.step(ev)?;
            self.route();
            if self.pipeline_start.is_none() {
                if let Some(at) = self.sender.connected_at() {
                    self.start_pipeline(at);
                }
            }
        }
        let end = self.clock.now();
        tracing::debug!(events, virtual_s = end.as_secs_f64(), "event loop finished");
        let out = self.finish(end, wall.elapsed().as_secs_f64());
        clear_log_time();
        out
    }

    fn step(&mut self, ev: Ev) -> Result<()> {
        let now = self.clock.now();
        match ev {
            Ev::ToAgent => {
                while let Some(d) = self.down.pop_due(now) {
                    self.sender.receive(&self.clock, &d, &mut self.to_viewer)?;
                }
            }
            Ev::ToViewer => {
                while let Some(d) = self.up.pop_due(now) {
                    if self.viewer_asleep {
                        match self.scenario.asleep.map(|a| a.backlog) {
                            Some(crate::scenario::Backlog::Drop) => self.backlog_dropped += 1,
                            _ => self.backlog.push(d),
                        }
                    } else {
                        self.viewer.receive(&self.clock, &d, &mut self.to_agent)?;
                    }
                }
            }
            Ev::AgentTimer => self.sender.timer(&self.clock, &mut self.to_viewer)?,
            Ev::ViewerTimer => self.viewer.timer(&self.clock, &mut self.to_agent)?,
            Ev::EncodeDone => self.finish_encode()?,
            Ev::Frame => self.on_source_frame()?,
            Ev::Tick => self.control_tick()?,
            Ev::Pli => self.viewer.pli_timer(&self.clock, &mut self.to_agent)?,
            Ev::CaptureStart => self.capture_start()?,
            Ev::Sleep => self.viewer_sleep()?,
            Ev::Reports => {
                let start = self.pipeline_start.unwrap_or_default();
                let viewer_ms =
                    u64::try_from(now.saturating_sub(start).as_millis()).unwrap_or(u64::MAX);
                self.reports.step(
                    now,
                    self.viewer.frames.len() as u64,
                    viewer_ms,
                    !self.viewer_asleep,
                    &self.up,
                    &self.down,
                );
            }
        }
        Ok(())
    }

    /// The viewer's page falls asleep, or wakes. See [`crate::scenario::AsleepViewer`].
    fn viewer_sleep(&mut self) -> Result<()> {
        let now = self.clock.now();
        let Some((at, asleep)) = self.sleep_events.pop_front() else {
            return Ok(());
        };
        if asleep {
            self.viewer_asleep = true;
            self.asleep_since = now;
            let text = format!(
                "viewer page asleep (scenario): no receiver report, no transport-wide feedback, no \
                 ICE consent answer until it wakes; what reaches it {} at_s=\"{:.1}\"",
                match self.scenario.asleep.map(|a| a.backlog) {
                    Some(crate::scenario::Backlog::Drop) => "is lost",
                    _ => "waits for it",
                },
                at.as_secs_f64()
            );
            tracing::debug!("{text}");
            self.log(now, "INFO", "afklink_sim", &text);
            return Ok(());
        }
        self.viewer_asleep = false;
        let backlog = std::mem::take(&mut self.backlog);
        let waited = backlog.len();
        let dropped = std::mem::take(&mut self.backlog_dropped);
        // Its clock did not run: everything that waited arrives now, and its first report reads the
        // sleep as round trip.
        for d in &backlog {
            self.viewer.receive(&self.clock, d, &mut self.to_agent)?;
        }
        self.viewer.timer(&self.clock, &mut self.to_agent)?;
        self.sender.stale_rtt_ms = self.scenario.asleep.and_then(|a| a.stale_rtt_ms);
        let text = format!(
            "viewer page awake (scenario): asleep_ms={} backlog_delivered={waited} \
             backlog_lost={dropped} stale_rtt_ms=\"{}\" at_s=\"{:.1}\"",
            now.saturating_sub(self.asleep_since).as_millis(),
            self.sender
                .stale_rtt_ms
                .map_or_else(|| "-".to_string(), |r| r.to_string()),
            at.as_secs_f64()
        );
        tracing::debug!("{text}");
        self.log(now, "INFO", "afklink_sim", &text);
        Ok(())
    }

    fn start_pipeline(&mut self, at: Duration) {
        let now = self.clock.now();
        tracing::info!(
            connect_ms = at.as_secs_f64() * 1e3,
            "connected: links modelled from here, pipeline and controller started"
        );
        self.pipeline_start = Some(now);
        self.metrics.pipeline_start = now;
        self.up.set_ideal(false, now);
        self.down.set_ideal(false, now);
        self.sender.begin_session(now);
        if let Some(enc) = self.encoder.take() {
            self.encode = Some(EncodeLoop::new(enc, self.scenario.encode_cost, now));
        }
        self.next_tick = Some(now + TICK);
        self.end = Some(now + self.scenario.duration);
        self.reports.start(now);
        self.source_peek = self.source.next();
        let (name, seed) = (self.scenario.name.clone(), self.scenario.seed);
        self.log(
            now,
            "INFO",
            "afklink_core::agent",
            &format!("session_request sim-{name} from user 0"),
        );
        self.log(
            now,
            "INFO",
            "afklink_sim",
            &format!(
                "simulated session, not a recording: scenario=\"{name}\" seed={seed} \
                 up=\"{}\" down=\"{}\" rtt_ms={:.1} connect_ms={:.1}",
                describe_capacity(&self.scenario.up.capacity),
                describe_capacity(&self.scenario.down.capacity),
                (self.scenario.up.delay + self.scenario.down.delay).as_secs_f64() * 1e3,
                at.as_secs_f64() * 1e3,
            ),
        );
    }

    fn on_source_frame(&mut self) -> Result<()> {
        let now = self.clock.now();
        let Some((_, frame)) = self.source_peek.take() else {
            return Ok(());
        };
        self.source_peek = self.source.next();
        // The capture is stopped for a background hold, or starting again: the screen changes, and
        // nothing captures it — it is only what the capture started again will show first.
        if self.capture_held || self.capture_start_at.is_some() {
            self.last_screen = Some(frame);
            return Ok(());
        }
        if self.keep_screen {
            self.last_screen = Some(frame.clone());
        }
        if let Some(scaled) = self.capturer.on_frame(now, frame, &self.target)? {
            self.metrics.note_capture(now);
            if self.job.is_none() {
                self.begin_encode(now, scaled, now, 1);
            } else {
                // The encoder is busy: the frame waits in the channel, newest wins.
                self.pending = Some((now, scaled));
                self.pending_offered += 1;
            }
        }
        Ok(())
    }

    fn begin_encode(
        &mut self,
        now: Duration,
        frame: afklink_core::types::Frame,
        captured_at: Duration,
        offered: u32,
    ) {
        let Some(enc) = self.encode.as_mut() else {
            return;
        };
        // agent.rs: the breaker, a drain's end or the viewer's `kf` set the flag the encode loop
        // consumes; the viewer's PLIs wait in `viewer_asks` for the encode loop to judge.
        if std::mem::take(&mut self.sender.keyframe_requested) {
            enc.keyframe_requested = true;
        }
        let at = self.clock.at(now);
        if let Ok(job) = enc.begin(
            now,
            at,
            frame,
            captured_at,
            offered,
            &self.target,
            &self.sender.viewer_asks,
        ) {
            self.job = Some(job);
        }
    }

    fn finish_encode(&mut self) -> Result<()> {
        let Some(job) = self.job.take() else {
            return Ok(());
        };
        let (captured_at, started) = (job.captured_at, job.started);
        // agent.rs: what a keyframe's window is made of as it is handed to the transport — the
        // round trip and the estimate the event task stored, the drain rate the control task
        // published, the bytes already in str0m's queue.
        let link = afklink_core::keyframe_window::LinkNow::from_gauges(
            self.sender.rtt_ms,
            self.target.drain_kbps(),
            self.sender.estimate_kbps,
            self.sender.outstanding_bytes,
        );
        let at = self.clock.instant();
        let done = self
            .encode
            .as_mut()
            .and_then(|enc| enc.complete(job, at, link));
        if let Some((ef, qp)) = done {
            let rtp = (ef.timestamp_ms.wrapping_mul(90) & 0xffff_ffff) as u32;
            let sent = SentFrame {
                captured_at,
                encode_start: started,
                bytes: ef.data.len(),
                keyframe: ef.is_keyframe,
                qp,
            };
            let outcome = self.sender.write_media(
                &self.clock,
                MediaSample {
                    data: ef.data,
                    is_keyframe: ef.is_keyframe,
                    timestamp_ms: ef.timestamp_ms,
                },
                &mut self.to_viewer,
            )?;
            match outcome {
                WriteOutcome::Discarded => self.metrics.discarded_writes += 1,
                // A delta held for a keyframe is an encoded frame not sent, as a discard is; the
                // held frame that asked for the keyframe is the resync.
                WriteOutcome::Held { asked } => {
                    self.metrics.discarded_writes += 1;
                    if asked {
                        self.metrics.resyncs += 1;
                    }
                }
                _ => {}
            }
            // Only what reached str0m can reach the viewer; a frame the breaker threw away is
            // accounted as a discard, not as a frame lost in the network.
            if matches!(
                outcome,
                WriteOutcome::Written | WriteOutcome::Resumed { .. }
            ) {
                self.metrics.note_sent(rtp, sent);
            }
            if self.sender.reference_broken
                && matches!(
                    outcome,
                    WriteOutcome::Written | WriteOutcome::Resumed { .. }
                )
            {
                self.metrics.broken_reference_frames += 1;
            }
        }
        let now = self.clock.now();
        if let Some((captured_at, frame)) = self.pending.take() {
            let offered = std::mem::take(&mut self.pending_offered);
            self.begin_encode(now, frame, captured_at, offered);
        }
        Ok(())
    }

    fn control_tick(&mut self) -> Result<()> {
        let now = self.clock.now();
        self.viewer_keyframe_requests(now);
        self.viewer_visibility(now);
        self.delay_steps(now);
        let Some(enc) = self.encode.as_ref() else {
            return Ok(());
        };
        let rung_before = Rung {
            max_h: self.target.max_h(),
            fps: self.target.fps(),
        };
        let g = Gauges {
            drain_kbps: self.sender.drain_kbps,
            queue_age_ms: self.sender.queue_age_ms,
            egress_kbps: self.sender.egress_kbps,
            egress_bytes_total: self.sender.egress_bytes_total,
            discarded_frames: self.sender.discarded_frames,
            estimate_kbps: self.sender.estimate_kbps,
            rtt_ms: self.sender.rtt_ms,
            loss_bp: self.sender.loss_bp,
            plis: self.sender.plis,
            nacks: self.sender.nacks,
            link_reports: self.sender.link_reports,
            outstanding_bytes: self.sender.outstanding_bytes,
        };
        // The viewer's latest `vv` report since the last tick, as the agent's control task reads its
        // gauges once a tick (the latest of a burst; the others are overwritten there too).
        if let Some((arrived, r)) = self.reports.take() {
            if self.delivery_on {
                self.control
                    .note_viewer(afklink_core::quality::ViewerFrames {
                        received: r.received,
                        viewer_ms: Some(r.viewer_ms),
                        age: now.saturating_sub(arrived),
                    });
            }
        }
        let out = self.control.tick(
            now,
            self.clock.instant(),
            &enc.counters,
            &g,
            &self.target,
            &self.bg,
        );
        self.metrics.note_tick(rung_before, TICK);
        // The hold's marks: the controller frozen and resumed, and what the first ticks after it
        // fed the controller — the counters must not hand it the hold's padding in one window.
        match out.hold {
            HoldStep::Started => {
                if let Some(m) = self.metrics.hold_marks.last_mut() {
                    m.held_from = Some(now);
                    m.rung_before = Some(rung_before);
                }
            }
            HoldStep::Resumed { .. } => {
                if let Some(m) = self.metrics.hold_marks.last_mut() {
                    m.resumed_tick = Some(now);
                    m.estimate_at_resume = g.estimate_kbps;
                    m.capacity_at_resume = out.reanchor.and_then(|(_, r)| r).map_or_else(
                        || self.control.controller().capacity_kbps(),
                        |r| r.capacity_kbps,
                    );
                    m.skipped_queue_at_resume = enc.counters.frames_skipped_queue;
                    m.brake_at_resume = self.control.controller().brake_state();
                }
            }
            HoldStep::Live | HoldStep::Frozen => {}
        }
        if let Some(m) = self.metrics.hold_marks.last_mut() {
            let since = m.resumed_tick.map(|t| now.saturating_sub(t));
            if since.is_some_and(|s| s <= Duration::from_secs(2)) {
                m.max_feedback_egress_after_kbps = m
                    .max_feedback_egress_after_kbps
                    .max(out.feedback.egress_kbps);
            }
            if since.is_some_and(|s| s <= Duration::from_secs(10)) {
                let est = out.feedback.estimate_kbps;
                m.estimate_min_after_kbps =
                    Some(m.estimate_min_after_kbps.map_or(est, |e| e.min(est)));
                m.queue_max_after_ms = m.queue_max_after_ms.max(out.feedback.queue_age_ms);
                m.skipped_queue_after = enc.counters.frames_skipped_queue;
            }
            if since.is_some_and(|s| s >= Duration::from_secs(1) && s <= Duration::from_secs(10)) {
                let budget = self.target.target_kbps().unwrap_or(0);
                m.budget_min_after_kbps =
                    Some(m.budget_min_after_kbps.map_or(budget, |b| b.min(budget)));
                m.budget_sum_after += u64::from(budget);
                m.budget_ticks_after += 1;
            }
        }
        for c in &out.commands {
            match *c {
                Command::SetDesiredBitrate(kbps) => {
                    self.sender
                        .set_desired_bitrate(&self.clock, kbps, &mut self.to_viewer)?;
                }
                Command::ResetBwe(kbps) => {
                    self.sender
                        .reset_bwe(&self.clock, kbps, &mut self.to_viewer)?;
                }
                Command::ResetBweAtNextFrame(kbps) => {
                    self.sender
                        .arm_reset_bwe(&self.clock, kbps, &mut self.to_viewer)?;
                }
                Command::ResetBweProbing {
                    kbps,
                    probe_cap_kbps,
                } => {
                    self.sender.reset_bwe_probing(
                        &self.clock,
                        kbps,
                        probe_cap_kbps,
                        &mut self.to_viewer,
                    )?;
                }
            }
        }
        if let Some((rung, why)) = out.moved {
            self.metrics.rung_changes.push((now, rung, why));
        }
        // agent.rs: a drain's end sets `pending_kf`, consumed by the next frame the encode loop
        // takes — the flag a PLI sets here too.
        if out.resume_keyframe {
            self.sender.keyframe_requested = true;
        }
        if let Some((kbps, r)) = out.reanchor {
            self.metrics
                .reanchors
                .push((now, kbps, r, out.feedback.estimate_kbps));
        }
        if let Some(b) = out.brake {
            self.metrics.brakes.push((now, b));
        }
        if let Some(s) = out.second {
            self.metrics.seconds.push((now, s));
            *self.metrics.collapse_seconds.entry(s.collapse).or_default() += 1;
            let w = self.up.take_window();
            self.metrics.link_up_seconds.push((now, w));
        }
        for l in &out.lines {
            self.log_line(now, l);
        }
        self.supervise_hold(now);
        self.next_tick = self.next_tick.map(|t| t + TICK);
        Ok(())
    }

    /// The scenario's `vis` that are due, on the control task's clock, into the agent's hold cell:
    /// the viewer's page hidden, and visible again. See [`Scenario::hidden`].
    fn viewer_visibility(&mut self, now: Duration) {
        let Some(start) = self.pipeline_start else {
            return;
        };
        while self
            .vis_events
            .front()
            .is_some_and(|(at, _)| start + *at <= now)
        {
            let Some((at, hidden)) = self.vis_events.pop_front() else {
                break;
            };
            self.bg
                .on_vis(hidden, Some("visibilitychange"), self.clock.instant());
            if hidden {
                self.metrics.hold_marks.push(HoldMark {
                    hidden_at: now,
                    budget_at_hide_kbps: self.target.target_kbps().unwrap_or(0),
                    ..HoldMark::default()
                });
            } else if let Some(m) = self.metrics.hold_marks.last_mut() {
                m.visible_at = Some(now);
            }
            let text = format!(
                "viewer page {} (scenario vis) at_s=\"{:.1}\"",
                if hidden { "hidden" } else { "visible" },
                at.as_secs_f64()
            );
            tracing::debug!("{text}");
            self.log(now, "INFO", "afklink_sim", &text);
        }
    }

    /// The supervisor's part of the hold (`pipeline::Supervisor`, restated): the capture stopped
    /// while it is published — what was waiting for the encoder dropped — and started again
    /// [`CAPTURE_RESUME`] after it ends.
    fn supervise_hold(&mut self, now: Duration) {
        let held = self.target.bg_hold();
        if held && !self.capture_held {
            self.capture_held = true;
            self.capture_start_at = None;
            let dropped = self.pending.take().is_some();
            self.pending_offered = 0;
            tracing::debug!(
                dropped_pending = dropped,
                "background hold: capture stopped (simulated supervisor)"
            );
            self.log(
                now,
                "INFO",
                "afklink_sim",
                "capture stopped for the background hold",
            );
        } else if !held && self.capture_held {
            self.capture_held = false;
            self.capture_start_at = Some(now + CAPTURE_RESUME);
            tracing::debug!(
                resume_ms = CAPTURE_RESUME.as_millis() as u64,
                "background hold over: capture starts again (simulated supervisor)"
            );
        }
    }

    /// A capture started again after a hold delivers the screen as it is, and the encode loop
    /// makes it a keyframe (`pending_kf`).
    fn capture_start(&mut self) -> Result<()> {
        let now = self.clock.now();
        self.capture_start_at = None;
        self.sender.keyframe_requested = true;
        if let Some(m) = self.metrics.hold_marks.last_mut() {
            m.capture_at = Some(now);
        }
        let Some(frame) = self.last_screen.clone() else {
            tracing::debug!("capture started again with no screen known yet; nothing to deliver");
            return Ok(());
        };
        self.log(
            now,
            "INFO",
            "afklink_sim",
            "capture started again after the background hold; its first frame is the screen as it is",
        );
        if let Some(scaled) = self.capturer.on_frame(now, frame, &self.target)? {
            self.metrics.note_capture(now);
            if self.job.is_none() {
                self.begin_encode(now, scaled, now, 1);
            } else {
                self.pending = Some((now, scaled));
                self.pending_offered += 1;
            }
        }
        Ok(())
    }

    /// The scenario's viewer keyframe requests that are due, made on the control task's clock (a
    /// data-channel message lands on the agent's event task, which sets the pending-keyframe flag the
    /// encode loop takes with its next frame — not held against the keyframe window, which is for
    /// PLIs; 200 ms of resolution is finer than the viewer's own spacing of one a second). As the
    /// agent honours one: `viewer_report.rs`, `keyframe_request`.
    fn viewer_keyframe_requests(&mut self, now: Duration) {
        let Some(start) = self.pipeline_start else {
            return;
        };
        while self
            .keyframe_requests
            .front()
            .is_some_and(|at| start + *at <= now)
        {
            let at = self.keyframe_requests.pop_front().unwrap_or_default();
            self.sender.keyframe_requested = true;
            tracing::debug!(
                at_s = at.as_secs_f64(),
                "viewer asked for a keyframe over the data channel (scenario); forcing one"
            );
            self.log(
                now,
                "INFO",
                "afklink_sim",
                &format!(
                    "viewer asked for a keyframe over the data channel (scenario) at_s=\"{:.1}\"",
                    at.as_secs_f64()
                ),
            );
        }
    }

    /// The scenario's delay steps that are due, applied on the control task's clock (200 ms is finer
    /// than any route change a scenario models). See [`Scenario::up_delay_steps`].
    fn delay_steps(&mut self, now: Duration) {
        let Some(start) = self.pipeline_start else {
            return;
        };
        for up in [true, false] {
            loop {
                let steps = if up {
                    &mut self.up_delay_steps
                } else {
                    &mut self.down_delay_steps
                };
                let Some(&(at, delay)) = steps.front() else {
                    break;
                };
                if start + at > now {
                    break;
                }
                steps.pop_front();
                let link = if up { &mut self.up } else { &mut self.down };
                let was = link.config().delay;
                let mut cfg = link.config().clone();
                cfg.delay = delay;
                link.reconfigure(cfg, now);
                let text = format!(
                    "link delay changed (scenario) direction={} from_ms={:.1} to_ms={:.1} at_s=\"{:.1}\"",
                    link.name(),
                    was.as_secs_f64() * 1e3,
                    delay.as_secs_f64() * 1e3,
                    at.as_secs_f64()
                );
                tracing::debug!("{text}");
                self.log(now, "INFO", "afklink_sim", &text);
            }
        }
    }

    fn finish(mut self, end: Duration, wall_secs: f64) -> Result<RunOutput> {
        let counters = self
            .encode
            .as_ref()
            .map(|e| e.counters.clone())
            .unwrap_or_default();
        let mut summary = summarize(
            &self.scenario.name,
            &self.metrics,
            &self.viewer.frames,
            &self.sender.estimates,
            &counters,
            self.sender.egress_bytes_total,
            self.sender.nacks,
            self.viewer.plis_sent,
            self.up.stats(),
            self.down.stats(),
            end,
            wall_secs,
        );
        summary.viewer_str0m = self.scenario.viewer.str0m.version();
        summary.recoveries = crate::metrics::recoveries(&self.metrics, &self.viewer.pli_times);
        for (t, text) in viewer_seconds(&self.metrics, &self.viewer.frames, end) {
            self.log(t, "INFO", "afklink_sim", &text);
        }
        let reports = format!(
            "viewer reports (simulated data channel) made={} delivered={} max_transit_ms={} \
             read_by_controller={}",
            self.reports.made,
            self.reports.delivered,
            self.reports.max_transit.as_millis(),
            self.delivery_on
        );
        tracing::info!("{reports}");
        self.log(end, "INFO", "afklink_sim", &reports);
        let egress: Vec<_> = self
            .sender
            .egress_reports
            .iter()
            .filter(|r| self.pipeline_start.is_some_and(|s| r.at >= s))
            .cloned()
            .collect();
        for r in egress {
            self.log(
                r.at,
                "INFO",
                "afklink_transport::webrtc",
                &format!(
                    "egress turns_per_s=\"{:.0}\" packets_per_s=\"{:.0}\" egress_kbps=\"{:.0}\" \
                     woke=t{} s{} m{}",
                    r.turns_per_s, r.packets_per_s, r.egress_kbps, r.woke.0, r.woke.1, r.woke.2
                ),
            );
        }
        self.lines.sort_by_key(|(t, seq, _)| (*t, *seq));
        let log = self.lines.into_iter().map(|(_, _, l)| l).collect();
        tracing::info!(
            scenario = %summary.name,
            sim_s = summary.sim_secs,
            wall_s = summary.wall_secs,
            speed = summary.speed(),
            "simulation finished"
        );
        Ok(RunOutput { summary, log })
    }
}
