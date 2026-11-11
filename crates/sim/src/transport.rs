//! The agent's end of the WebRTC session: str0m configured as `spawn_peer` configures it, and the
//! run loop's accounting around it, driven in virtual time.
//!
//! ## Copied from `transport/src/webrtc.rs`, to be deduplicated later
//!
//! Nothing is factored out of `webrtc.rs` yet. What is restated here, and where it comes from:
//!
//! | here | from `webrtc.rs` |
//! |---|---|
//! | [`sender_config`]: H.264 only, `enable_bwe(600 kbps)`, 1 s stats interval, playout-delay (id 5) and video-content-type (id 6) extensions, rust-crypto | `:865-905` |
//! | desired bitrate 2500 kbps at construction | `:918-919`, constant `:638` |
//! | [`INITIAL_BITRATE_KBPS`], [`DEFAULT_DESIRED_BITRATE_KBPS`] | `:622`, `:638` |
//! | [`Breaker`] (its thresholds are imported: `afklink_transport::QUEUE_HARD_LIMIT_MS`, `QUEUE_RESUME_MS`), and the `RefChain` gate — hold deltas after any lost encoded frame, ask for a keyframe, again after [`KEYFRAME_RETRY`] — restated in `write_media` | `Breaker`, `RefChain`, `PeerLoop::write_media` |
//! | [`QUEUE_SAMPLE_FRESH_MS`], `queue_age_ms`, `sample_send_queue` | `:607`, `:2148-2223` |
//! | [`EgressMeter`] (1 s window, 10%/s decaying peak for `drain_kbps`) | `:1272-1357` |
//! | the turn: drain, `BURST_PER_TURN` immediate re-polls, `IDLE_TURN` floor | `:1389-1512`, `:577`, `:821` |
//! | `write_media`: breaker, playout-delay cap, H.264 PT lookup, 90 kHz media time, wallclock | `:2427-2504` |
//! | [`playout_cap_ms`] and its constants, loss memory | `:658-798`, `:2334-2359` |
//! | event handling: `Connected`, `MediaAdded`, `KeyframeRequest` (the viewer's PLI, noted for the encode loop's keyframe window — `afklink_core::keyframe_window`, the production type — or, with [`SenderConfig::keyframe_window`] off, the pending flag), `EgressBitrateEstimate`, `MediaEgressStats` | `:2248-2362`; `agent.rs`, `PeerEvent::KeyframeRequest` |
//! | what the orchestrator stores from them (`estimate_kbps` 0 until the first estimate; `rtt_ms`/`loss_bp` with `u32::MAX` for "none"; cumulative PLIs/NACKs; `link_reports`) | `core/src/agent.rs:1080-1127` |
//!
//! RTX/NACK are not configured separately in the agent either: `enable_h264` brings str0m's RTX
//! payload types, and whether the viewer's offer accepted them decides whether str0m can pad
//! (`webrtc.rs:2046-2088`). The simulated viewer offers them, as Chrome does.
//!
//! Not modelled: the data channels (the viewer's input channel and the heartbeat, a few hundred
//! bytes a second over SCTP, not paced and not in the estimate), ICE restarts, the srflx/STUN
//! machinery and the ICE grace window.
//!
//! ## The platform timer, and why it matters more than it should
//!
//! The run loop sleeps on tokio's timer, whose wheel has millisecond granularity, and on Windows a
//! wait can be rounded further to the system tick (15.625 ms by default; `webrtc.rs:1441-1449`
//! measured 16.4 ms between timer wakes when the loop went through a zero-length sleep).
//! [`SenderConfig::timer_resolution`] models it: a timer wake is rounded up to the next multiple
//! (0 for an ideal timer), while packet arrivals and encoded frames still wake the loop at once, as
//! the socket and media arms do.
//!
//! The default is 1 ms, tokio's own granularity, and not the Windows tick, because the recordings
//! rule the tick out: str0m emits a probe as bursts of `target x 2 ms` spaced at least
//! `min_probe_delta` = 2 ms apart (`bwe/probe/cluster.rs:244-292`), and a burst is only released
//! when the loop wakes, so the probe rate the agent can reach is bounded by how often it wakes.
//! Simulated on the `wifi-0924` path, probes measure ~0.6 Mbps at a 15.625 ms tick, ~1.8 Mbps at
//! 4 ms, 6-8 Mbps at 1 ms and ~10 Mbps with an ideal timer — and a recorded WiFi session's
//! estimate reached 16 Mbps. If the agent ever does run at the default tick (a background process
//! under Windows 11's timer throttling), its estimate cannot leave the acknowledged rate by
//! probing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use str0m::bwe::{Bitrate, BweKind};
use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::media::{MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::Extension;
use str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};

use crate::clock::VirtualClock;
use crate::link::Datagram;

/// `webrtc.rs:622`.
pub const INITIAL_BITRATE_KBPS: u64 = 600;
/// `webrtc.rs:638`.
pub const DEFAULT_DESIRED_BITRATE_KBPS: u64 = 2_500;
/// `webrtc.rs:806`.
pub const EXT_ID_PLAYOUT_DELAY: u8 = 5;
/// `webrtc.rs:810`.
pub const EXT_ID_VIDEO_CONTENT_TYPE: u8 = 6;
// The breaker's two thresholds: the transport's own, public because the encode loop's hard hold
// mirrors them.
use afklink_transport::{QUEUE_HARD_LIMIT_MS, QUEUE_RESUME_MS};
/// `webrtc.rs:577`.
const BURST_PER_TURN: u32 = 32;
/// `webrtc.rs`, `KEYFRAME_RETRY`: how long delta frames are held for a keyframe before it is
/// asked for again.
const KEYFRAME_RETRY: Duration = Duration::from_millis(500);
/// `webrtc.rs:607`.
pub const QUEUE_SAMPLE_FRESH_MS: u64 = 200;
/// `webrtc.rs:821`.
const IDLE_TURN: Duration = Duration::from_millis(1);
/// `webrtc.rs:658`.
const PLAYOUT_DELAY_MIN_MS: u64 = 0;
/// `webrtc.rs:684`.
const PLAYOUT_DELAY_MAX_MS: u64 = 50;
/// `webrtc.rs:703`.
const PLAYOUT_DELAY_TICK_MS: u64 = 10;
/// `webrtc.rs:712`.
const PLAYOUT_DELAY_MAX_LOSSY_MS: u64 = 250;
/// `webrtc.rs:721`.
const LOSS_HEADROOM_MS: u64 = 30;
/// `webrtc.rs:731`.
const LOSS_MEMORY: Duration = Duration::from_secs(10);
/// `webrtc.rs:740`.
const PLAYOUT_DELAY_UNKNOWN_RTT_MS: u64 = 150;

/// `webrtc.rs:788-798`.
#[must_use]
pub fn playout_cap_ms(rtt: Option<Duration>, loss_recent: bool) -> u64 {
    if !loss_recent {
        return PLAYOUT_DELAY_MAX_MS;
    }
    let target = match rtt {
        Some(rtt) => (rtt.as_millis() as u64).saturating_add(LOSS_HEADROOM_MS),
        None => PLAYOUT_DELAY_UNKNOWN_RTT_MS,
    };
    let capped = target.clamp(PLAYOUT_DELAY_MAX_MS, PLAYOUT_DELAY_MAX_LOSSY_MS);
    capped - capped % PLAYOUT_DELAY_TICK_MS
}

/// The agent's `RtcConfig`, `webrtc.rs:865-905` (the ICE timing override is test-only there).
#[must_use]
pub fn sender_config() -> RtcConfig {
    Rtc::builder()
        .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
        .clear_codecs()
        .enable_h264(true)
        .enable_bwe(Some(Bitrate::kbps(INITIAL_BITRATE_KBPS)))
        .set_stats_interval(Some(Duration::from_secs(1)))
        .set_extension(EXT_ID_PLAYOUT_DELAY, Extension::PlayoutDelay)
        .set_extension(EXT_ID_VIDEO_CONTENT_TYPE, Extension::VideoContentType)
}

/// `webrtc.rs`, `Shed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shed {
    Send,
    Discard,
    /// Every resume breaks the viewer's reference chain, however few were discarded: see the
    /// gate in [`SenderPeer::write_media`] (`webrtc.rs`, `RefChain`).
    Resumed {
        discarded: u32,
    },
}

/// `webrtc.rs`, `Breaker`.
#[derive(Debug, Default)]
pub struct Breaker {
    shedding: bool,
    discarded: u32,
}

impl Breaker {
    pub fn admit(&mut self, queue_ms: u32) -> Shed {
        if self.shedding {
            if queue_ms > QUEUE_RESUME_MS {
                self.discarded = self.discarded.saturating_add(1);
                return Shed::Discard;
            }
            self.shedding = false;
            let discarded = std::mem::take(&mut self.discarded);
            return Shed::Resumed { discarded };
        }
        if queue_ms > QUEUE_HARD_LIMIT_MS {
            self.shedding = true;
            self.discarded = 1;
            return Shed::Discard;
        }
        Shed::Send
    }
}

/// `webrtc.rs:1272-1357`: a one-second window of what the loop sent, and how it was woken.
#[derive(Debug, Clone)]
pub struct EgressMeter {
    window_start: Duration,
    pub turns: u64,
    pub bytes: u64,
    pub packets: u64,
    pub woke_timer: u64,
    pub woke_socket: u64,
    pub woke_media: u64,
}

impl EgressMeter {
    const WINDOW: Duration = Duration::from_secs(1);

    fn new(now: Duration) -> Self {
        Self {
            window_start: now,
            turns: 0,
            bytes: 0,
            packets: 0,
            woke_timer: 0,
            woke_socket: 0,
            woke_media: 0,
        }
    }
}

/// One window's `egress` line, `webrtc.rs:1345-1354`.
#[derive(Debug, Clone)]
pub struct EgressReport {
    pub at: Duration,
    pub turns_per_s: f64,
    pub packets_per_s: f64,
    pub egress_kbps: f64,
    pub woke: (u64, u64, u64),
}

/// Knobs of the simulated agent's transport that the production code does not have.
#[derive(Debug, Clone, Copy)]
pub struct SenderConfig {
    /// The granularity of the run loop's timer. See the module documentation.
    pub timer_resolution: Duration,
    /// How `ResetBwe` is applied. See [`ReanchorMode`].
    pub reanchor: ReanchorMode,
    /// Whether the viewer's PLIs are held against the keyframe already on its way
    /// (`afklink_core::keyframe_window`), as the agent does; `false` is the
    /// counterfactual — every PLI forces a keyframe.
    pub keyframe_window: bool,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            timer_resolution: Duration::from_millis(1),
            reanchor: ReanchorMode::Capped,
            keyframe_window: true,
        }
    }
}

/// How the simulated agent applies `PeerControl::ResetBwe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorMode {
    /// As the agent does: `afklink_transport::webrtc::reanchor_bwe`, the production function
    /// itself, which holds str0m's opening probes to the new estimate.
    Capped,
    /// The counterfactual: a bare `Rtc::bwe().reset`, whose opening probes go out at 3x and 6x the
    /// new estimate (capped at 2x the ceiling) — what the agent did before `reanchor_bwe`.
    BareReset,
}

/// Which `select!` arm woke the loop, for the `egress` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    Timer,
    Socket,
    Media,
    Control,
}

/// One encoded frame for the transport, `webrtc.rs:42-48`.
#[derive(Debug, Clone)]
pub struct MediaSample {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    pub timestamp_ms: u64,
}

/// What `write_media` did with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    Written,
    NotConnected,
    Discarded,
    /// Written after a breaker episode: a keyframe (which repairs the chain), since a delta would
    /// have been [`Self::Held`].
    Resumed {
        discarded: u32,
    },
    /// A delta frame withheld because the viewer's reference chain is broken (`webrtc.rs`,
    /// `RefChain`); `asked` when a keyframe was requested with it.
    Held {
        asked: bool,
    },
    Failed,
}

/// The agent's peer. See the module documentation.
pub struct SenderPeer {
    pub rtc: Rtc,
    pub local: SocketAddr,
    cfg: SenderConfig,
    /// `PeerLoop::start`: the wallclock base for `Writer::write`.
    start: Instant,
    video_mid: Option<Mid>,
    connected: bool,
    connected_at: Option<Duration>,
    breaker: Breaker,
    /// `Peer::discarded_frames`.
    pub discarded_frames: u32,
    /// `PeerLoop::estimate_kbps`: the last estimate, starting at the initial bitrate.
    peer_estimate_kbps: u32,
    last_rtt: Option<Duration>,
    loss_recent_until: Option<Duration>,
    last_nacks: u64,
    egress: EgressMeter,
    pub egress_reports: Vec<EgressReport>,
    /// `Peer::drain_kbps`: the decaying peak of measured egress.
    pub drain_kbps: u32,
    /// `Peer::egress_kbps`: the last window, unsmoothed.
    pub egress_kbps: u32,
    /// `Peer::egress_bytes_total`.
    pub egress_bytes_total: u64,
    /// `Peer::outstanding_bytes` (plus the channel, which the simulation does not have).
    pub outstanding_bytes: u32,
    /// `Peer::queue_age_ms`, as last sampled by the loop.
    pub queue_age_ms: u32,
    /// `SessionCounters::estimate_kbps`: 0 until the first estimate event.
    pub estimate_kbps: u32,
    /// `SessionCounters::rtt_ms`, `u32::MAX` for none.
    pub rtt_ms: u32,
    /// `SessionCounters::loss_bp`, `u32::MAX` for none.
    pub loss_bp: u32,
    pub plis: u64,
    pub nacks: u64,
    pub link_reports: u64,
    /// The keyframe request the encode loop always honours (`pending_kf`): the breaker resyncing,
    /// and — with [`SenderConfig::keyframe_window`] off — the viewer's PLI as well.
    pub keyframe_requested: bool,
    /// The viewer's PLIs and when they arrived, for the encode loop to judge against the keyframe
    /// already on its way: the agent's `ViewerAsks`, which its event task fills.
    pub viewer_asks: afklink_core::keyframe_window::ViewerAsks,
    /// Every estimate str0m emitted, `(when, kbps)`, for the summary's trajectory.
    pub estimates: Vec<(Duration, u32)>,
    /// When the loop's timer arm next fires.
    pub next_wake: Option<Duration>,
    /// `PeerLoop::desired_kbps`: the ceiling last set, which a re-anchor restores.
    desired_kbps: u32,
    /// `PeerLoop::str0m_desired_kbps`: the ceiling str0m has, unless `desired_kbps` is waiting for
    /// the next video frame (`afklink_transport::webrtc::ceiling_waits_for_video`).
    str0m_desired_kbps: u32,
    /// `PeerLoop::armed_reanchor`: a `ResetBweAtNextFrame` waiting for its frame, and when it came.
    armed_reanchor: Option<(u32, Duration)>,
    /// `PeerLoop::last_frame_written`.
    last_frame_written: Option<Duration>,
    /// Whether an encoded frame failed to reach str0m since the last keyframe written, so the
    /// receiver lacks a reference (`webrtc.rs`, `RefChain`). While it is set, delta frames are held
    /// rather than written; the keyframe that is written clears it. The simulator's
    /// `broken_reference_frames` counts frames written while it is set, which the gate makes zero.
    pub reference_broken: bool,
    /// When a keyframe was last asked for while the chain was broken. See [`KEYFRAME_RETRY`].
    keyframe_asked_at: Option<Duration>,
    /// A woken viewer's stale round trip, for its next receiver report: the scenario's model of a
    /// suspended page's clock (`crate::scenario::AsleepViewer`). Not the agent's: its transport
    /// reads what the viewer sends.
    pub stale_rtt_ms: Option<u32>,
}

impl std::fmt::Debug for SenderPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderPeer")
            .field("local", &self.local)
            .field("connected", &self.connected)
            .field("estimate_kbps", &self.estimate_kbps)
            .field("next_wake", &self.next_wake)
            .finish()
    }
}

impl SenderPeer {
    /// Build the agent's `Rtc` at the current virtual time, offering one host candidate.
    pub fn new(clock: &VirtualClock, local: SocketAddr, cfg: SenderConfig) -> Result<Self> {
        let mut rtc = sender_config().build(clock.instant());
        // `webrtc.rs:918-919`.
        rtc.bwe()
            .set_desired_bitrate(Bitrate::kbps(DEFAULT_DESIRED_BITRATE_KBPS));
        let cand = Candidate::host(local, "udp").context("sender host candidate")?;
        rtc.add_local_candidate(cand);
        tracing::debug!(
            %local,
            initial_kbps = INITIAL_BITRATE_KBPS,
            desired_kbps = DEFAULT_DESIRED_BITRATE_KBPS,
            timer_resolution_us = cfg.timer_resolution.as_micros() as u64,
            "sender peer built with the agent's configuration"
        );
        let now = clock.now();
        Ok(Self {
            rtc,
            local,
            cfg,
            start: clock.instant(),
            video_mid: None,
            connected: false,
            connected_at: None,
            breaker: Breaker::default(),
            discarded_frames: 0,
            peer_estimate_kbps: u32::try_from(INITIAL_BITRATE_KBPS).unwrap_or(600),
            last_rtt: None,
            loss_recent_until: None,
            last_nacks: 0,
            egress: EgressMeter::new(now),
            egress_reports: Vec::new(),
            drain_kbps: 0,
            egress_kbps: 0,
            egress_bytes_total: 0,
            outstanding_bytes: 0,
            queue_age_ms: 0,
            estimate_kbps: 0,
            rtt_ms: u32::MAX,
            loss_bp: u32::MAX,
            plis: 0,
            nacks: 0,
            link_reports: 0,
            keyframe_requested: false,
            viewer_asks: afklink_core::keyframe_window::ViewerAsks::default(),
            estimates: Vec::new(),
            next_wake: Some(now),
            desired_kbps: u32::try_from(DEFAULT_DESIRED_BITRATE_KBPS).unwrap_or(u32::MAX),
            str0m_desired_kbps: u32::try_from(DEFAULT_DESIRED_BITRATE_KBPS).unwrap_or(u32::MAX),
            armed_reanchor: None,
            last_frame_written: None,
            reference_broken: false,
            keyframe_asked_at: None,
            stale_rtt_ms: None,
        })
    }

    /// Accept the viewer's offer, as `spawn_peer_on` does: SDP text in, SDP text out
    /// (`webrtc.rs`, `SdpOffer::from_sdp_string` and `to_sdp_string`). Text, so that a viewer on
    /// another str0m version can make the offer (`crate::viewer`).
    pub fn accept_offer(&mut self, offer_sdp: &str) -> Result<String> {
        let offer = SdpOffer::from_sdp_string(offer_sdp).context("sender: parse the offer")?;
        let answer = self
            .rtc
            .sdp_api()
            .accept_offer(offer)
            .context("sender: accept offer")?;
        Ok(answer.to_sdp_string())
    }

    #[must_use]
    pub fn connected_at(&self) -> Option<Duration> {
        self.connected_at
    }

    /// Start the egress accounting over at the start of the session proper.
    ///
    /// A departure from the agent, whose counters include the ICE/DTLS handshake's few kilobytes:
    /// the DTLS part varies by a few bytes from run to run (OS-random keys and signatures), and
    /// through `egress_kbps` and the controller's conservation check it would make two runs of one
    /// seed diverge. What is dropped is the handshake and nothing else.
    pub fn begin_session(&mut self, now: Duration) {
        tracing::debug!(
            handshake_bytes = self.egress_bytes_total,
            "sender: egress accounting restarted at the session start"
        );
        self.egress = EgressMeter::new(now);
        self.egress_bytes_total = 0;
        self.drain_kbps = 0;
        self.egress_kbps = 0;
        self.egress_reports.clear();
    }

    /// The socket arm: a datagram from the viewer.
    pub fn receive(
        &mut self,
        clock: &VirtualClock,
        d: &Datagram,
        out: &mut Vec<Datagram>,
    ) -> Result<()> {
        self.egress.woke_socket += 1;
        match str0m::net::DatagramRecv::try_from(&d.contents[..]) {
            Ok(contents) => {
                let recv = Receive {
                    proto: Protocol::Udp,
                    source: d.source,
                    destination: self.local,
                    contents,
                };
                self.rtc
                    .handle_input(Input::Receive(clock.instant(), recv))
                    .context("sender: handle receive")?;
            }
            Err(e) => tracing::debug!("sender: undecodable datagram skipped: {e:?}"),
        }
        self.turn(clock, Wake::Socket, out)
    }

    /// The timer arm.
    pub fn timer(&mut self, clock: &VirtualClock, out: &mut Vec<Datagram>) -> Result<()> {
        self.egress.woke_timer += 1;
        self.rtc
            .handle_input(Input::Timeout(clock.instant()))
            .context("sender: handle timeout")?;
        self.turn(clock, Wake::Timer, out)
    }

    /// The control arm: `PeerControl::SetDesiredBitrate` (`PeerLoop::set_desired`): at once, unless
    /// it would end str0m's quiet while no video flows — then with the next frame
    /// (`afklink_transport::webrtc::ceiling_waits_for_video`).
    pub fn set_desired_bitrate(
        &mut self,
        clock: &VirtualClock,
        kbps: u32,
        out: &mut Vec<Datagram>,
    ) -> Result<()> {
        let now = clock.now();
        let since_frame = self.last_frame_written.map(|t| now.saturating_sub(t));
        let was = self.str0m_desired_kbps;
        self.desired_kbps = kbps;
        if afklink_transport::webrtc::ceiling_waits_for_video(was, kbps, since_frame) {
            tracing::debug!(
                kbps,
                str0m_kbps = was,
                since_frame_ms =
                    %since_frame.map_or_else(|| "never".to_string(), |d| d.as_millis().to_string()),
                armed_reanchor = self.armed_reanchor.is_some(),
                "bwe ceiling set, held for the video: str0m probes nothing now and no frame is \
                 flowing, and in its application-limited region a rising ceiling is a probe at \
                 once; it goes with the next frame (with the re-anchor armed for it, if any)"
            );
        } else {
            tracing::debug!(kbps, str0m_was_kbps = was, "bwe ceiling set");
            self.str0m_desired_kbps = kbps;
            self.rtc
                .bwe()
                .set_desired_bitrate(Bitrate::kbps(u64::from(kbps)));
        }
        self.turn(clock, Wake::Control, out)
    }

    /// `PeerLoop::release_waiting_desired`: a ceiling still waiting for the video goes to str0m.
    fn release_waiting_desired(&mut self, by: &'static str) {
        if self.str0m_desired_kbps == self.desired_kbps {
            return;
        }
        tracing::debug!(
            desired_kbps = self.desired_kbps,
            str0m_was_kbps = self.str0m_desired_kbps,
            by,
            "bwe ceiling that waited for the video handed to str0m"
        );
        self.str0m_desired_kbps = self.desired_kbps;
        self.rtc
            .bwe()
            .set_desired_bitrate(Bitrate::kbps(u64::from(self.desired_kbps)));
    }

    /// The control arm: `PeerControl::ResetBwe` (`webrtc.rs`, the `ResetBwe` arm of
    /// `PeerLoop::serve`), through the production `reanchor_bwe` unless the scenario asks for the
    /// bare reset it replaced.
    pub fn reset_bwe(
        &mut self,
        clock: &VirtualClock,
        kbps: u32,
        out: &mut Vec<Datagram>,
    ) -> Result<()> {
        self.apply_reanchor(clock, kbps, None, "on-arrival", None)?;
        self.turn(clock, Wake::Control, out)
    }

    /// The control arm: `PeerControl::ResetBweProbing` (`PeerLoop::serve`): [`Self::reset_bwe`]
    /// with the opening probes allowed to `probe_cap_kbps`, through the production
    /// `reanchor_bwe_probing`.
    pub fn reset_bwe_probing(
        &mut self,
        clock: &VirtualClock,
        kbps: u32,
        probe_cap_kbps: u32,
        out: &mut Vec<Datagram>,
    ) -> Result<()> {
        self.apply_reanchor(clock, kbps, Some(probe_cap_kbps), "on-arrival", None)?;
        self.turn(clock, Wake::Control, out)
    }

    /// The control arm: `PeerControl::ResetBweAtNextFrame` (`PeerLoop::arm_reanchor`): applied at
    /// once if a frame went out within `REANCHOR_FLOWING_WITHIN`, armed for the next one otherwise
    /// ([`Self::write_media`] applies it right before handing that frame to str0m).
    pub fn arm_reset_bwe(
        &mut self,
        clock: &VirtualClock,
        kbps: u32,
        out: &mut Vec<Datagram>,
    ) -> Result<()> {
        let now = clock.now();
        let since_frame = self.last_frame_written.map(|t| now.saturating_sub(t));
        let since_frame_ms =
            since_frame.map_or_else(|| "never".to_string(), |d| d.as_millis().to_string());
        if since_frame.is_some_and(|d| d <= afklink_transport::webrtc::REANCHOR_FLOWING_WITHIN) {
            tracing::debug!(
                kbps,
                since_frame_ms,
                "bwe re-anchor for the next frame applied at once: a frame went out just before it \
                 arrived, so the video it is for is already flowing"
            );
            self.apply_reanchor(clock, kbps, None, "at-once", Some(now))?;
        } else {
            if let Some((was, at)) = self.armed_reanchor.replace((kbps, now)) {
                tracing::debug!(
                    kbps,
                    replaced_kbps = was,
                    armed_ms = now.saturating_sub(at).as_millis() as u64,
                    "bwe re-anchor re-armed: a newer one replaces the one still waiting for its frame"
                );
            }
            tracing::debug!(
                kbps,
                since_frame_ms,
                estimate_kbps = self.peer_estimate_kbps,
                "bwe re-anchor armed: applied right before the next video frame is handed to str0m, \
                 so the restarted estimator measures that video and not the padding before it"
            );
        }
        self.turn(clock, Wake::Control, out)
    }

    /// `PeerLoop::apply_reanchor`, through the production `reanchor_bwe` unless the scenario asks
    /// for the bare reset it replaced.
    fn apply_reanchor(
        &mut self,
        clock: &VirtualClock,
        kbps: u32,
        probe_cap: Option<u32>,
        applied: &'static str,
        armed: Option<Duration>,
    ) -> Result<()> {
        let init = Bitrate::kbps(u64::from(kbps));
        let now = clock.now();
        let armed_ms = armed.map_or_else(
            || "-".to_string(),
            |a| now.saturating_sub(a).as_millis().to_string(),
        );
        let waited = self.str0m_desired_kbps != self.desired_kbps;
        match self.cfg.reanchor {
            ReanchorMode::Capped => {
                let r = afklink_transport::webrtc::reanchor_bwe_probing(
                    &mut self.rtc,
                    init,
                    Bitrate::kbps(u64::from(self.desired_kbps)),
                    Bitrate::kbps(u64::from(probe_cap.unwrap_or(kbps))),
                    clock.instant(),
                );
                // `reanchor_bwe_probing` puts the ceiling back whatever its timeout did.
                self.str0m_desired_kbps = self.desired_kbps;
                let r = r.context("sender: re-anchor")?;
                if waited {
                    tracing::debug!(
                        desired_kbps = self.desired_kbps,
                        applied,
                        "bwe ceiling that waited for the video handed to str0m with the re-anchor"
                    );
                }
                tracing::info!(
                    kbps,
                    asked_probe_cap_kbps = %probe_cap.map_or_else(|| "-".to_string(), |c| c.to_string()),
                    applied,
                    armed_ms,
                    estimate_was_kbps = self.peer_estimate_kbps,
                    at_s = now.as_secs_f64(),
                    probe_cap_kbps = r.probe_cap_kbps,
                    desired_kbps = self.desired_kbps,
                    bare_reset_probes_kbps = %format!(
                        "{}/{}",
                        r.bare_reset_probes_kbps.0, r.bare_reset_probes_kbps.1
                    ),
                    "bwe re-anchored: str0m's estimator is restarted at kbps — on arrival, at once, \
                     or right before the frame it was armed for (applied) — and its opening probes \
                     are held to probe_cap_kbps"
                );
            }
            ReanchorMode::BareReset => {
                tracing::info!(
                    kbps,
                    applied,
                    armed_ms,
                    at_s = now.as_secs_f64(),
                    "bwe re-anchored with a bare reset (scenario sender.reanchor = \"reset\"): \
                     str0m's opening probes go out at 3x and 6x"
                );
                self.rtc.bwe().reset(init);
                // The bare reset leaves str0m's ceiling as it was; one that waited goes with it.
                self.release_waiting_desired(applied);
            }
        }
        Ok(())
    }

    /// The media arm: one encoded frame (`webrtc.rs:1569-1578`, `:2427-2504`).
    pub fn write_media(
        &mut self,
        clock: &VirtualClock,
        sample: MediaSample,
        out: &mut Vec<Datagram>,
    ) -> Result<WriteOutcome> {
        self.egress.woke_media += 1;
        let outcome = self.write_media_inner(clock, sample);
        self.turn(clock, Wake::Media, out)?;
        Ok(outcome)
    }

    fn write_media_inner(&mut self, clock: &VirtualClock, sample: MediaSample) -> WriteOutcome {
        let now = clock.now();
        if !self.connected {
            tracing::trace!("frame not written: not connected yet");
            self.lose_frame("before_connect", now);
            return WriteOutcome::NotConnected;
        }
        let Some(mid) = self.video_mid else {
            tracing::trace!("frame not written: no video m-line yet");
            self.lose_frame("no_video", now);
            return WriteOutcome::NotConnected;
        };
        let queued = self.measure_queue_age(clock);
        let mut resumed = None;
        match self.breaker.admit(queued) {
            Shed::Send => {}
            Shed::Discard => {
                self.discarded_frames += 1;
                if self.breaker.discarded == 1 {
                    tracing::warn!(
                        queue_ms = queued,
                        in_flight = self.outstanding_bytes,
                        estimate_kbps = self.peer_estimate_kbps,
                        at_s = now.as_secs_f64(),
                        "send queue past its hard limit: discarding until it drains"
                    );
                }
                self.lose_frame("breaker", now);
                return WriteOutcome::Discarded;
            }
            Shed::Resumed { discarded } => {
                tracing::info!(
                    queue_ms = queued,
                    discarded,
                    keyframe = sample.is_keyframe,
                    "send queue drained; resuming — the discarded frames broke the viewer's \
                     reference chain, so delta frames are held until a keyframe"
                );
                resumed = Some(discarded);
            }
        }
        // `webrtc.rs`, `RefChain::admit`: a delta frame referencing a frame the viewer never got
        // is held, and a keyframe asked for with the first one and every `KEYFRAME_RETRY` after.
        if self.reference_broken && !sample.is_keyframe {
            self.discarded_frames += 1;
            let asked = self
                .keyframe_asked_at
                .is_none_or(|at| now.saturating_sub(at) >= KEYFRAME_RETRY);
            if asked {
                self.keyframe_asked_at = Some(now);
                self.keyframe_requested = true;
                tracing::debug!(
                    at_s = now.as_secs_f64(),
                    "keyframe requested: the viewer's reference chain is broken, so delta frames \
                     are held until one arrives"
                );
            } else {
                tracing::trace!("delta frame held: it references a frame the viewer never got");
            }
            return WriteOutcome::Held { asked };
        }

        // `PeerLoop::write_media`: a restart armed for this moment goes right before the frame.
        if let Some((kbps, armed)) = self.armed_reanchor.take() {
            if let Err(e) = self.apply_reanchor(clock, kbps, None, "before-frame", Some(armed)) {
                tracing::error!(
                    kbps,
                    error = %e,
                    "bwe re-anchor before the frame failed: str0m refused the timeout after the \
                     reset; the frame is written all the same"
                );
            }
        }
        // `PeerLoop::write_media`: a ceiling that waited for the video and had no re-anchor to ride
        // goes with the frame that ends the silence.
        self.release_waiting_desired("before-frame");
        let cap_ms = self.playout_cap(now);
        let wallclock = self.start + Duration::from_millis(sample.timestamp_ms);
        let Some(writer) = self.rtc.writer(mid) else {
            tracing::debug!(%mid, "frame not written: str0m has no writer for the video mid");
            self.lose_frame("no_video", now);
            return WriteOutcome::Failed;
        };
        let Some(params) = writer
            .payload_params()
            .find(|p| p.spec().codec == Codec::H264)
            .copied()
        else {
            tracing::warn!("no negotiated H.264 payload type: frame not written");
            self.lose_frame("no_video", now);
            return WriteOutcome::Failed;
        };
        let pt = params.pt();
        let freq = params.spec().clock_rate;
        let media_time = MediaTime::new(sample.timestamp_ms.saturating_mul(90), freq);
        let writer = writer.playout_delay(
            MediaTime::from_millis(PLAYOUT_DELAY_MIN_MS),
            MediaTime::from_millis(cap_ms),
        );
        let keyframe = sample.is_keyframe;
        if let Err(e) = writer.write(pt, wallclock, media_time, sample.data) {
            tracing::debug!("media write failed: {e}");
            self.lose_frame("write_error", now);
            return WriteOutcome::Failed;
        }
        self.last_frame_written = Some(now);
        if keyframe && self.reference_broken {
            self.reference_broken = false;
            self.keyframe_asked_at = None;
            tracing::debug!(
                at_s = now.as_secs_f64(),
                "keyframe written: the viewer's reference chain is whole again"
            );
        }
        match resumed {
            Some(discarded) => WriteOutcome::Resumed { discarded },
            None => WriteOutcome::Written,
        }
    }

    /// `webrtc.rs`, `PeerLoop::lose_frame`: an encoded frame did not reach str0m.
    fn lose_frame(&mut self, why: &'static str, now: Duration) {
        if !self.reference_broken {
            self.reference_broken = true;
            self.keyframe_asked_at = None;
            tracing::debug!(
                why,
                at_s = now.as_secs_f64(),
                "the viewer's reference chain is broken: delta frames are held until a keyframe"
            );
        }
    }

    /// `webrtc.rs:2374-2398`, without the log line.
    fn playout_cap(&self, now: Duration) -> u64 {
        let loss_recent = self.loss_recent_until.is_some_and(|until| now < until);
        playout_cap_ms(self.last_rtt, loss_recent)
    }

    /// `webrtc.rs:2148-2168`: the measured age of the oldest unsent packet, `0` when the snapshot
    /// is stale.
    pub fn measure_queue_age(&mut self, clock: &VirtualClock) -> u32 {
        let Some(mid) = self.video_mid else {
            return 0;
        };
        let now = clock.instant();
        let age = self
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .and_then(|s| s.queue_info())
            .filter(|q| {
                now.saturating_duration_since(q.created_at()).as_millis()
                    <= u128::from(QUEUE_SAMPLE_FRESH_MS)
            })
            .and_then(|q| q.first_unsent())
            .map_or(0, |t| now.saturating_duration_since(t).as_millis());
        u32::try_from(age).unwrap_or(u32::MAX)
    }

    /// `webrtc.rs:2184-2223`.
    fn sample_send_queue(&mut self, clock: &VirtualClock) {
        let Some(mid) = self.video_mid else {
            return;
        };
        let bytes = self
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .and_then(|s| s.queue_info().map(|q| q.byte_size()))
            .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));
        self.outstanding_bytes = bytes;
        self.queue_age_ms = self.measure_queue_age(clock);
    }

    /// `EgressMeter::report_if_due`, `webrtc.rs:1336-1357`.
    fn report_if_due(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.egress.window_start);
        if elapsed < EgressMeter::WINDOW {
            return;
        }
        let secs = elapsed.as_secs_f64();
        let egress_kbps = (self.egress.bytes as f64 * 8.0 / secs / 1000.0) as u32;
        let decayed = self.drain_kbps * 9 / 10;
        self.drain_kbps = decayed.max(egress_kbps);
        self.egress_kbps = egress_kbps;
        self.egress_reports.push(EgressReport {
            at: now,
            turns_per_s: self.egress.turns as f64 / secs,
            packets_per_s: self.egress.packets as f64 / secs,
            egress_kbps: self.egress.bytes as f64 * 8.0 / secs / 1000.0,
            woke: (
                self.egress.woke_timer,
                self.egress.woke_socket,
                self.egress.woke_media,
            ),
        });
        self.egress = EgressMeter::new(now);
    }

    /// The rest of one iteration of `PeerLoop::serve` after an arm fired: drain, the immediate
    /// re-poll burst, and the next timer wake. `webrtc.rs:1396-1512`.
    fn turn(&mut self, clock: &VirtualClock, _woke: Wake, out: &mut Vec<Datagram>) -> Result<()> {
        let now = clock.now();
        let now_i = clock.instant();
        loop {
            let sent_before = self.egress.packets;
            let timeout = self.drain(clock, out)?;
            let produced_work = self.egress.packets > sent_before;
            self.egress.turns += 1;
            self.sample_send_queue(clock);
            self.report_if_due(now);
            let wait = timeout.saturating_duration_since(now_i);

            let mut immediate = 0;
            while wait.is_zero() && produced_work && immediate < BURST_PER_TURN {
                immediate += 1;
                self.rtc
                    .handle_input(Input::Timeout(now_i))
                    .context("sender: immediate timeout")?;
                let before = self.egress.packets;
                let next = self.drain(clock, out)?;
                self.egress.turns += 1;
                if !self.rtc.is_alive() || self.egress.packets == before {
                    break;
                }
                if next > now_i {
                    break;
                }
            }
            if immediate > 0 {
                self.sample_send_queue(clock);
                continue;
            }
            let wait = if produced_work {
                wait
            } else {
                wait.max(IDLE_TURN)
            };
            // Far-future timeouts (str0m's `not_happening()`) mean no timer at all.
            self.next_wake = if wait > Duration::from_secs(3600) {
                None
            } else {
                Some(quantize(now + wait, self.cfg.timer_resolution))
            };
            return Ok(());
        }
    }

    /// `PeerLoop::drain`, `webrtc.rs:2227-2246`: poll until a timeout, sending and handling events.
    fn drain(&mut self, clock: &VirtualClock, out: &mut Vec<Datagram>) -> Result<Instant> {
        loop {
            match self.rtc.poll_output().context("sender: poll_output")? {
                Output::Timeout(t) => return Ok(t),
                Output::Transmit(t) => {
                    let len = t.contents.len() as u64;
                    self.egress.bytes += len;
                    self.egress.packets += 1;
                    self.egress_bytes_total += len;
                    out.push(Datagram {
                        source: t.source,
                        destination: t.destination,
                        contents: t.contents.to_vec(),
                    });
                }
                Output::Event(e) => self.handle_event(clock, e),
            }
        }
    }

    /// `PeerLoop::handle_event`, `webrtc.rs:2248-2362`, plus what the orchestrator does with the
    /// resulting `PeerEvent`s (`agent.rs:1080-1127`).
    fn handle_event(&mut self, clock: &VirtualClock, e: Event) {
        let now = clock.now();
        match e {
            Event::Connected => {
                self.connected = true;
                self.connected_at.get_or_insert(now);
                tracing::info!(at_s = now.as_secs_f64(), "sender: connected");
            }
            Event::IceConnectionStateChange(state) => {
                tracing::debug!(?state, at_s = now.as_secs_f64(), "sender: ICE state");
            }
            Event::MediaAdded(m) => {
                if m.kind == MediaKind::Video {
                    tracing::debug!(mid = %m.mid, "sender: video m-line added");
                    self.video_mid = Some(m.mid);
                    self.log_probe_capability(m.mid);
                }
            }
            // `agent.rs`, `PeerEvent::KeyframeRequest(KeyframeAsk::Viewer)`: noted with when it
            // arrived, for the encode loop's window — or, with the window off, the pending flag.
            Event::KeyframeRequest(_) => {
                tracing::debug!(
                    at_s = now.as_secs_f64(),
                    window = self.cfg.keyframe_window,
                    "sender: keyframe request from the viewer"
                );
                if self.cfg.keyframe_window {
                    self.viewer_asks.note(clock.instant());
                } else {
                    self.keyframe_requested = true;
                }
            }
            Event::EgressBitrateEstimate(kind) => {
                let estimate = match kind {
                    // str0m 0.24 sends `can_probe: false` once when its estimator loses probing,
                    // then holds the estimate (the agent logs the same; `webrtc.rs`).
                    BweKind::Twcc {
                        estimate,
                        can_probe,
                    } => {
                        if !can_probe {
                            tracing::warn!(
                                kbps = estimate.as_u64() / 1000,
                                at_s = now.as_secs_f64(),
                                "sender: bandwidth estimator cannot probe; str0m holds its estimate"
                            );
                        }
                        estimate
                    }
                    BweKind::Remb { estimate, .. } => estimate,
                    other => {
                        tracing::debug!("unhandled bandwidth estimate kind: {other:?}");
                        return;
                    }
                };
                let kbps = (estimate.as_u64() / 1000) as u32;
                self.peer_estimate_kbps = kbps;
                self.estimate_kbps = kbps;
                self.estimates.push((now, kbps));
            }
            Event::MediaEgressStats(s) => {
                if let Some(rtt) = s.rtt {
                    self.last_rtt = Some(rtt);
                }
                let losing = s.loss.is_some_and(|l| l > 0.0) || s.nacks > self.last_nacks;
                self.last_nacks = s.nacks;
                if losing {
                    self.loss_recent_until = Some(now + LOSS_MEMORY);
                }
                self.rtt_ms = s.rtt.map_or(u32::MAX, |d| d.as_millis() as u32);
                // A fresh report (str0m gives a loss only for one) from a viewer that has just woken:
                // its round trip is the time it slept. See `crate::scenario::AsleepViewer`.
                if s.loss.is_some() {
                    if let Some(stale) = self.stale_rtt_ms.take() {
                        tracing::debug!(
                            rtt_ms = stale,
                            measured_rtt_ms = self.rtt_ms,
                            at_s = now.as_secs_f64(),
                            "sim: the woken viewer's first receiver report carries the time it \
                             slept as its round trip (scenario stale_rtt_ms)"
                        );
                        self.rtt_ms = stale;
                    }
                }
                self.loss_bp = s
                    .loss
                    .map_or(u32::MAX, |l| (l * 10_000.0).clamp(0.0, 10_000.0) as u32);
                self.plis = s.plis;
                self.nacks = s.nacks;
                self.link_reports += 1;
                tracing::trace!(
                    rtt = ?s.rtt,
                    loss = ?s.loss,
                    plis = s.plis,
                    nacks = s.nacks,
                    "sender: egress stats"
                );
            }
            _ => {}
        }
    }

    /// `webrtc.rs` `log_probe_capability`, at debug: whether str0m can probe (transport-wide
    /// feedback negotiated, str0m 0.24) and pad on the video stream (RTX) on this session.
    fn log_probe_capability(&mut self, mid: Mid) {
        let params: Vec<_> = match self.rtc.writer(mid) {
            Some(w) => w.payload_params().copied().collect(),
            None => return,
        };
        let any_rtx_pt = params
            .iter()
            .any(|p| p.spec().codec == Codec::H264 && p.resend().is_some());
        let rtx_ssrc = self
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .and_then(|s| s.rtx());
        let twcc_ext_id = self
            .rtc
            .media(mid)
            .and_then(|m| m.remote_extmap().id_of(Extension::TransportSequenceNumber));
        let h264_transport_cc = params
            .iter()
            .any(|p| p.spec().codec == Codec::H264 && p.fb_transport_cc());
        tracing::debug!(
            h264_rtx_pt = any_rtx_pt,
            rtx_ssrc = ?rtx_ssrc,
            twcc_ext_id = ?twcc_ext_id,
            h264_transport_cc,
            probing = twcc_ext_id.is_some() && h264_transport_cc,
            rtx_padding = any_rtx_pt && rtx_ssrc.is_some(),
            "sender: probe capability"
        );
    }
}

/// The first multiple of `res` at or after `t`; `t` itself for an ideal timer.
#[must_use]
pub fn quantize(t: Duration, res: Duration) -> Duration {
    let r = res.as_nanos();
    if r == 0 {
        return t;
    }
    let n = t.as_nanos();
    let q = n.div_ceil(r) * r;
    Duration::from_nanos(u64::try_from(q).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::{playout_cap_ms, quantize, Breaker, Shed};
    use std::time::Duration;

    #[test]
    fn the_breaker_is_the_transports() {
        // `webrtc.rs`'s shape: trips past a second, holds until 150 ms, then resumes — and every
        // resume breaks the viewer's reference chain, two discarded frames as much as four.
        let mut b = Breaker::default();
        assert_eq!(b.admit(900), Shed::Send);
        assert_eq!(b.admit(1_100), Shed::Discard);
        assert_eq!(b.admit(400), Shed::Discard);
        assert_eq!(b.admit(100), Shed::Resumed { discarded: 2 });
        assert_eq!(b.admit(1_100), Shed::Discard);
        for _ in 0..3 {
            assert_eq!(b.admit(500), Shed::Discard);
        }
        assert_eq!(b.admit(100), Shed::Resumed { discarded: 4 });
    }

    #[test]
    fn the_playout_cap_is_the_transports() {
        assert_eq!(playout_cap_ms(None, false), 50);
        assert_eq!(playout_cap_ms(Some(Duration::from_millis(137)), true), 160);
        assert_eq!(playout_cap_ms(None, true), 150);
        assert_eq!(playout_cap_ms(Some(Duration::from_millis(900)), true), 250);
    }

    #[test]
    fn the_timer_wakes_on_the_system_tick() {
        let tick = Duration::from_micros(15_625);
        assert_eq!(quantize(Duration::from_millis(1), tick), tick);
        assert_eq!(quantize(tick, tick), tick);
        assert_eq!(quantize(tick + Duration::from_nanos(1), tick), tick * 2);
        assert_eq!(
            quantize(Duration::from_millis(7), Duration::ZERO),
            Duration::from_millis(7)
        );
    }
}
